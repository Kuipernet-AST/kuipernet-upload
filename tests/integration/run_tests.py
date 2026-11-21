#!/usr/bin/env python3
"""Integration tests for Kuipernet Upload on a real nginx.

Starts the test backends and nginx, sends requests over raw sockets and
decides each case from three independent records:

  client   : HTTP status seen by the client, SHA-256 of the body it sent
  backend  : backends.py log (requests, body bytes, SHA-256 received)
  shield   : the module's structured line in nginx's error log

Usage: run_tests.py NGINX_BINARY MODULE_SO OUTPUT_DIR [--big MB] [--soak N]
"""
import hashlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT1, PORT2, PORT3, HTTP_PORT, FCGI_PORT = 18080, 18081, 18082, 19081, 19082
B = b"----MgusTestBoundary7MA4YWxkTrZu0gW"
CT = "multipart/form-data; boundary=" + B.decode()

results = []
evidence = []


# ------------------------------------------------------------------ helpers

def rnd(n, seed):
    return random.Random(seed).randbytes(n)


def field(name, value=b"v"):
    return (b'Content-Disposition: form-data; name="' + name.encode() + b'"',
            value)


def upfile(name, filename, data, extra=b""):
    return (b'Content-Disposition: form-data; name="' + name.encode()
            + b'"; filename="' + filename.encode() + b'"\r\n'
            b"Content-Type: application/octet-stream" + extra, data)


def multipart(parts, close=True, tail=b"", eol=b"\r\n"):
    out = b""
    for hdr, data in parts:
        out += b"--" + B + b"\r\n" + hdr + b"\r\n\r\n" + data + eol
    if close:
        out += b"--" + B + b"--\r\n"
    return out + tail


class Env:
    def __init__(self, nginx, module, out):
        self.nginx, self.module, self.out = nginx, module, out
        self.run = os.path.join(out, "run")
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(self.run)
        self.conf = os.path.join(self.run, "nginx.conf")
        text = open(os.path.join(HERE, "nginx.conf.in")).read()
        for k, v in {"@MODULE@": module, "@RUN@": self.run,
                     "@PORT1@": PORT1, "@PORT2@": PORT2, "@PORT3@": PORT3,
                     "@HTTP@": HTTP_PORT, "@FCGI@": FCGI_PORT}.items():
            text = text.replace(k, str(v))
        open(self.conf, "w").write(text)
        self.backend_log = os.path.join(self.run, "backend.jsonl")
        self.error_log = os.path.join(self.run, "error.log")
        self.b_off = 0
        self.e_off = 0
        self.backends = None

    def config_test(self):
        p = subprocess.run([self.nginx, "-t", "-c", self.conf],
                           capture_output=True, text=True)
        open(os.path.join(self.out, "nginx-config-test.txt"), "w").write(
            p.stderr + p.stdout)
        return p.returncode, p.stderr

    def start(self):
        self.backends = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "backends.py"),
             str(HTTP_PORT), str(FCGI_PORT), self.backend_log])
        subprocess.run([self.nginx, "-c", self.conf], check=True)
        for port in (PORT1, PORT2, PORT3, HTTP_PORT, FCGI_PORT):
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
        time.sleep(0.3)
        self.mark()

    def restart_nginx(self):
        subprocess.run([self.nginx, "-c", self.conf, "-s", "quit"], check=True)
        for _ in range(100):
            if not os.path.exists(os.path.join(self.run, "nginx.pid")):
                break
            time.sleep(0.05)
        subprocess.run([self.nginx, "-c", self.conf], check=True)
        time.sleep(0.3)

    def stop(self):
        subprocess.run([self.nginx, "-c", self.conf, "-s", "quit"])
        time.sleep(0.5)
        self.backends.terminate()

    def worker_pid(self):
        master = int(open(os.path.join(self.run, "nginx.pid")).read())
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    stat = open("/proc/%s/stat" % pid).read()
                except OSError:
                    continue
                if int(stat.rsplit(")", 1)[1].split()[1]) == master:
                    return int(pid)
        return None

    def mark(self):
        self.b_off = os.path.getsize(self.backend_log) \
            if os.path.exists(self.backend_log) else 0
        self.e_off = os.path.getsize(self.error_log)

    def new_backend(self):
        with open(self.backend_log) as f:
            f.seek(self.b_off)
            return [json.loads(x) for x in f if x.strip()]

    def new_shield(self):
        out, raw = [], []
        with open(self.error_log, errors="replace") as f:
            f.seek(self.e_off)
            for line in f:
                m = re.search(r"upload_shield: (\{.*?\})", line)
                if m:
                    out.append(json.loads(m.group(1)))
                    raw.append(line.rstrip("\n"))
        return out, raw

    def _open_temp(self):
        """nginx unlinks a request body temp file right after creating it, so
        the data is visible only through the worker's open descriptors."""
        out = []
        pid = self.worker_pid()
        if pid is None:
            return out
        fd_dir = "/proc/%d/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            return out
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
                if "client_body_temp" in target:
                    out.append(os.stat(os.path.join(fd_dir, fd)).st_blocks * 512)
            except OSError:
                pass
        return out

    def temp_files(self):
        n = len(self._open_temp())
        for _, _, files in os.walk(os.path.join(self.run, "client_body_temp")):
            n += len(files)
        return n

    def temp_bytes(self):
        return sum(self._open_temp())


def send(port, path, body, tid, ctype=CT, chunked=False, piece=65536,
         delay=0.0, abort_at=None, declared=None, timeout=20):
    """Send one request. body is bytes or an iterable of bytes (then declared
    is the Content-Length). Returns (status or None, bytes of body sent)."""
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(timeout)
    head = "POST %s HTTP/1.1\r\nHost: test\r\nX-Test-Id: %s\r\n" % (path, tid)
    if ctype:
        head += "Content-Type: %s\r\n" % ctype
    if chunked:
        head += "Transfer-Encoding: chunked\r\n"
    else:
        head += "Content-Length: %d\r\n" % (
            declared if declared is not None else len(body))
    head += "Connection: close\r\n\r\n"

    sent = 0
    try:
        s.sendall(head.encode())
        pieces = (body[i:i + piece] for i in range(0, len(body), piece)) \
            if isinstance(body, (bytes, bytearray)) else body
        for p in pieces:
            if abort_at is not None and sent + len(p) > abort_at:
                p = p[:abort_at - sent]
                if p:
                    s.sendall(p)
                    sent += len(p)
                time.sleep(0.2)
                s.close()
                return None, sent
            if chunked:
                s.sendall(b"%x\r\n" % len(p) + p + b"\r\n")
            else:
                s.sendall(p)
            sent += len(p)
            if delay:
                time.sleep(delay)
        if chunked:
            s.sendall(b"0\r\n\r\n")
    except OSError:
        pass        # the server may answer and close before the body is sent

    resp = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            resp += d
    except OSError:
        pass
    s.close()
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp)
    return (int(m.group(1)) if m else None), sent


def case(env, name, port, path, body, expect_status, expect_backend,
         expect_action, expect_rule=None, **kw):
    """expect_backend: 'full' (1 request, identical bytes), 'none'
    (0 requests, 0 bytes) or 'any'."""
    tid = "T%03d" % (len(results) + 1)
    env.mark()
    sha = hashlib.sha256(body).hexdigest() if isinstance(body, bytes) else None
    settle = kw.pop("settle", 0.25)
    status, sent = send(port, path + tid, body, tid, **kw)
    time.sleep(settle)

    reqs = [r for r in env.new_backend() if r.get("test_id") == tid]
    shield, raw = env.new_shield()
    b_bytes = sum(r["body_bytes"] for r in reqs)
    sha_ok = (len(reqs) == 1 and reqs[0]["complete"]
              and reqs[0]["sha256"] == sha)

    ok = True
    why = []
    if isinstance(expect_status, tuple):
        if status not in expect_status:
            ok = False
            why.append("status %s" % status)
    elif status != expect_status:
        ok = False
        why.append("status %s" % status)
    if expect_backend == "full" and not sha_ok:
        ok = False
        why.append("backend sha/requests mismatch")
    if expect_backend == "none" and (reqs or b_bytes):
        ok = False
        why.append("backend received %d req %d bytes" % (len(reqs), b_bytes))
    if expect_action is None:
        if shield:
            ok = False
            why.append("unexpected shield log")
    else:
        if len(shield) != 1 or shield[0]["action"] != expect_action:
            ok = False
            why.append("shield log %s" % [s.get("action") for s in shield])
        elif expect_rule and shield[0]["rule"] != expect_rule:
            ok = False
            why.append("rule %s" % shield[0]["rule"])

    row = {
        "id": tid, "name": name, "path": path,
        "ok": ok, "why": "; ".join(why),
        "client_status": status,
        "client_body_bytes": len(body) if isinstance(body, bytes) else sent,
        "client_sha256": sha,
        "backend_requests": len(reqs), "backend_body_bytes": b_bytes,
        "backend_sha256": reqs[0]["sha256"] if reqs else None,
        "sha_match": sha_ok if reqs else None,
        "shield": shield[0] if len(shield) == 1 else shield,
    }
    results.append(row)
    evidence.append({"id": tid, "backend_log": reqs, "nginx_error_log": raw})
    sh = row["shield"] if isinstance(row["shield"], dict) else {}
    print("%s %-4s %-46s %-24s status=%-4s backend=%d req/%d B sha=%s "
          "shield=%s/%s %s" % (
              "PASS" if ok else "FAIL", tid, name[:46], path[:24], status,
              len(reqs), b_bytes,
              {True: "match", False: "DIFF", None: "-"}[row["sha_match"]],
              sh.get("action", "-"), sh.get("rule", "-") or "-",
              row["why"]), flush=True)
    return row


# -------------------------------------------------------------------- tests

def bodies():
    f400 = [rnd(400 * 1024, i) for i in range(3)]
    normal = multipart([
        field("title", b"quarterly report"),
        upfile("f[]", "a.tar.gz", f400[0]),
        upfile("f[]", "b.min.js", f400[1]),
        upfile("f[]", "c.v1.2.pdf", f400[2]),
        field("note", b""),
    ])
    small = multipart([field("a", b"1"), upfile("f", "x.txt", b"hello\r\n")])
    big_last = multipart([
        field("title", b"x"),
        upfile("f[]", "ok1.bin", f400[0]),
        upfile("f[]", "ok2.bin", f400[1]),
        upfile("f[]", "big.bin", rnd(1024 * 1024 + 1, 9)),
    ])
    v = {
        "normal": normal,
        "small": small,
        "file_size_last": big_last,
        "truncated": multipart([field("a"), upfile("f", "x", f400[0])],
                               close=False),
        "file_count_last": multipart(
            [upfile("f[]", "n%d" % i, f400[0][:50000]) for i in range(5)]),
        "epilogue": multipart([upfile("f", "x", f400[0])], tail=b"trailing"),
        "part_header_last": multipart([
            upfile("f", "x", f400[0]),
            upfile("g", "y", b"z", extra=b"\r\nX-Pad: " + b"p" * 600)]),
        "field_size_last": multipart([upfile("f", "x", f400[0]),
                                      field("big", b"v" * 1025)]),
        "bare_lf": multipart([upfile("f", "x", f400[0][:70000] + b"\n--" + B
                                     + b"\r\nContent-Disposition: form-data; "
                                     b'name="smuggled"\r\n\r\nv')]),
        "part_count_last": multipart([field("p%d" % i) for i in range(9)]),
    }
    return v


def run_matrix(env, bod):
    for kind in ("proxy", "fcgi"):
        mon, blk = "/%s/monitor/" % kind, "/%s/block/" % kind

        # normal traffic must arrive unchanged in both modes
        for mode_path in (mon, blk):
            case(env, "normal multi-file upload", PORT1, mode_path,
                 bod["normal"], 200, "full", "pass")
            case(env, "normal upload, chunked request", PORT1, mode_path,
                 bod["normal"], 200, "full", "pass", chunked=True, piece=7919)
            case(env, "normal small upload (memory buffer)", PORT1, mode_path,
                 bod["small"], 200, "full", "pass")
            case(env, "normal upload sent in 1-byte writes", PORT1,
                 mode_path, bod["small"], 200, "full", "pass", piece=1)
            case(env, "non-multipart POST (not inspected)", PORT1, mode_path,
                 rnd(100000, 77), 200, "full", None,
                 ctype="application/octet-stream")

        # the same violating request: delivered in MONITOR, refused in BLOCK
        table = [
            ("last part: file over size limit", "file_size_last", 413, "MGUS-202"),
            ("end of body: closing boundary missing", "truncated", 400, "MGUS-105"),
            ("last part: file count exceeded", "file_count_last", 403, "MGUS-203"),
            ("end of body: data after closing boundary", "epilogue", 400, "MGUS-106"),
            ("last part: part header too large", "part_header_last", 413, "MGUS-201"),
            ("last part: form field too large", "field_size_last", 413, "MGUS-205"),
            ("bare-LF delimiter (parser differential)", "bare_lf", 400, "MGUS-102"),
            ("last part: part count exceeded", "part_count_last", 403, "MGUS-204"),
        ]
        for name, key, status, rule in table:
            case(env, name, PORT1, mon, bod[key], 200, "full", "monitor", rule)
            case(env, name, PORT1, blk, bod[key], status, "none", "block", rule)

        case(env, "last-part violation, chunked request", PORT1, mon,
             bod["file_size_last"], 200, "full", "monitor", "MGUS-202",
             chunked=True, piece=30011)
        case(env, "last-part violation, chunked request", PORT1, blk,
             bod["file_size_last"], 413, "none", "block", "MGUS-202",
             chunked=True, piece=30011)
        case(env, "invalid boundary parameter", PORT1, blk, bod["small"], 400,
             "none", "block", "MGUS-100",
             ctype="multipart/form-data; xboundary=a; boundary=" + B.decode())

        # request buffering off
        case(env, "buffering off, MONITOR, violating upload", PORT1,
             "/nobuf/%s/monitor/" % kind, bod["file_size_last"], 200, "full",
             "monitor", "MGUS-202")
        case(env, "buffering off, MONITOR, normal upload", PORT1,
             "/nobuf/%s/monitor/" % kind, bod["normal"], 200, "full", "pass")
        case(env, "buffering off, BLOCK, normal upload refused", PORT1,
             "/nobuf/%s/block/" % kind, bod["normal"], 500, "none", "block",
             "MGUS-901")
        case(env, "buffering off, BLOCK, non-multipart POST", PORT1,
             "/nobuf/%s/block/" % kind, rnd(50000, 5), 200, "full", None,
             ctype="application/json")

        # client goes away in the middle of the upload
        for mode_path in (mon, blk):
            case(env, "client aborts mid-upload", PORT1, mode_path,
                 bod["normal"], None, "none", "aborted",
                 abort_at=len(bod["normal"]) // 2, settle=0.6)


def run_limits(env, bod):
    three_mb = multipart([upfile("f[]", "a", rnd(900 * 1024, 1)),
                          upfile("f[]", "b", rnd(900 * 1024, 2)),
                          upfile("f[]", "c", rnd(900 * 1024, 3)),
                          upfile("f[]", "d", rnd(900 * 1024, 4))])
    for kind in ("proxy", "fcgi"):
        p = "/size/%s/block/" % kind
        case(env, "shield body limit 2m: 1.2 MB upload", PORT1, p,
             bod["normal"], 200, "full", "pass")
        case(env, "shield body limit 2m: 3.5 MB (Content-Length)", PORT1, p,
             three_mb, 413, "none", "block", "MGUS-401")
        case(env, "shield body limit 2m: 3.5 MB (chunked)", PORT1, p,
             three_mb, 413, "none", "block", "MGUS-401", chunked=True)
    case(env, "shield body limit 2m, MONITOR: 3.5 MB", PORT1,
         "/size/proxy/monitor/", three_mb, 200, "full", "monitor", "MGUS-401")
    case(env, "no shield limit: 3.5 MB follows nginx 64m", PORT1,
         "/proxy/block/", three_mb, 200, "full", "pass")
    case(env, "shield 128m > nginx 64m: 3.5 MB upload", PORT1,
         "/size/conflict/", three_mb, 200, "full", "pass")
    # 70 MB declared: nginx's own client_max_body_size answers first
    case(env, "shield 128m > nginx 64m: 70 MB declared", PORT1,
         "/size/conflict/", bod["small"], 413, "none", None,
         declared=70 * 1024 * 1024)

    slow = multipart([upfile("f", "slow.bin", rnd(300000, 8))])
    for p in ("/time/proxy/block/", "/time/fcgi/block/"):
        case(env, "shield body timeout 2s: fast upload", PORT1, p,
             bod["normal"], 200, "full", "pass")
        case(env, "shield body timeout 2s: upload takes ~5s", PORT1, p,
             slow, (None, 408), "none", "block", "MGUS-402",
             piece=30000, delay=0.5)
    case(env, "shield body timeout 2s, MONITOR: ~5s upload", PORT1,
         "/time/proxy/monitor/", slow, 200, "full", "monitor", "MGUS-402",
         piece=30000, delay=0.5)
    case(env, "no shield timeout: ~5s upload follows nginx", PORT1,
         "/proxy/block/", slow, 200, "full", "pass", piece=30000, delay=0.5)


def run_vhost(env, bod):
    progress_last = multipart([
        field("title", b"x"),
        upfile("f", "a.txt", rnd(200000, 3)),
        field("PHP_SESSION_UPLOAD_PROGRESS", b"probe"),
    ])
    progress_only = multipart([field("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])
    deep = multipart([field("a" + "[x]" * 5, b"1")])
    long_name = multipart([field("n" * 200, b"1")])
    many_hdrs = multipart([(b'Content-Disposition: form-data; name="a"'
                            + b"".join(b"\r\nX-H%d: 1" % i for i in range(5)),
                            b"1")])
    form = b"a=1&PHP_SESSION_UPLOAD_PROGRESS=probe"

    for port, mode in ((PORT2, "block"), (PORT3, "monitor")):
        blk = mode == "block"
        for path, kind in (("/index.php/", "fcgi"), ("/any/other/page.php/",
                           "fcgi"), ("/api/v1/items/", "proxy")):
            case(env, "host-wide %s: normal upload (%s)" % (mode, kind), port,
                 path, bod["normal"], 200, "full", "pass")
            case(env, "host-wide %s: progress field, last part (%s)"
                 % (mode, kind), port, path, progress_last,
                 403 if blk else 200, "none" if blk else "full",
                 mode, "MGUS-301")
            case(env, "host-wide %s: progress field only (%s)" % (mode, kind),
                 port, path, progress_only, 403 if blk else 200,
                 "none" if blk else "full", mode, "MGUS-301")
        case(env, "host-wide %s: field name depth 5 > 4" % mode, port, "/a.php/",
             deep, 403 if blk else 200, "none" if blk else "full", mode,
             "MGUS-208")
        case(env, "host-wide %s: field name 200 B > 128" % mode, port,
             "/a.php/", long_name, 403 if blk else 200,
             "none" if blk else "full", mode, "MGUS-207")
        case(env, "host-wide %s: 6 headers in one part > 4" % mode, port,
             "/a.php/", many_hdrs, 403 if blk else 200,
             "none" if blk else "full", mode, "MGUS-206")
        case(env, "host-wide %s: no-upload path, any multipart" % mode, port,
             "/noupload/x.php/", bod["small"], 403 if blk else 200,
             "none" if blk else "full", mode, "MGUS-302")
        case(env, "host-wide %s: urlencoded POST (not inspected)" % mode, port,
             "/index.php/", form, 200, "full", None,
             ctype="application/x-www-form-urlencoded")
    case(env, "host-wide block: path exempted from progress rule", PORT2,
         "/progress/up.php/", progress_last, 200, "full", "pass")


def run_curl(env, bod):
    """Real client and HTTP/2 (cleartext, prior knowledge)."""
    d = os.path.join(env.run, "files")
    os.makedirs(d, exist_ok=True)
    names = ["a.tar.gz", "b.min.js", "c.txt"]
    for i, n in enumerate(names):
        open(os.path.join(d, n), "wb").write(rnd(150000, 40 + i))
    open(os.path.join(d, "viol.bin"), "wb").write(bod["file_size_last"])
    open(os.path.join(d, "norm.bin"), "wb").write(bod["normal"])

    def curl(name, args, path, expect_status, expect_backend, action, rule=None,
             sha=None):
        tid = "T%03d" % (len(results) + 1)
        env.mark()
        p = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{http_version}",
             "-H", "X-Test-Id: " + tid] + args
            + ["http://127.0.0.1:%d%s%s" % (PORT1, path, tid)],
            capture_output=True, text=True)
        time.sleep(0.25)
        status, ver = (p.stdout.split() + ["?", "?"])[:2]
        reqs = [r for r in env.new_backend() if r.get("test_id") == tid]
        shield, raw = env.new_shield()
        b_bytes = sum(r["body_bytes"] for r in reqs)
        ok = status == str(expect_status)
        if expect_backend == "none":
            ok = ok and not reqs
        else:
            ok = ok and len(reqs) == 1 and reqs[0]["complete"]
            if sha:
                ok = ok and reqs[0]["sha256"] == sha
        ok = ok and len(shield) == 1 and shield[0]["action"] == action \
            and (rule is None or shield[0]["rule"] == rule)
        results.append({
            "id": tid, "name": name + " [HTTP/%s]" % ver, "path": path,
            "ok": ok, "why": "", "client_status": int(status)
            if status.isdigit() else None, "client_sha256": sha,
            "client_body_bytes": None,
            "backend_requests": len(reqs), "backend_body_bytes": b_bytes,
            "backend_sha256": reqs[0]["sha256"] if reqs else None,
            "sha_match": (reqs[0]["sha256"] == sha) if (reqs and sha) else None,
            "shield": shield[0] if len(shield) == 1 else shield})
        evidence.append({"id": tid, "backend_log": reqs, "nginx_error_log": raw})
        sh = shield[0] if len(shield) == 1 else {}
        print("%s %-4s %-46s %-24s status=%-4s backend=%d req/%d B "
              "shield=%s/%s" % ("PASS" if ok else "FAIL", tid,
                                (name + " [HTTP/%s]" % ver)[:46], path[:24],
                                status, len(reqs), b_bytes,
                                sh.get("action", "-"), sh.get("rule", "-")),
              flush=True)

    forms = ["-F", "title=hello"]
    for n in names:
        forms += ["-F", "f[]=@" + os.path.join(d, n)]
    raw_hdr = ["-H", "Content-Type: " + CT, "--data-binary"]
    sha_n = hashlib.sha256(bod["normal"]).hexdigest()

    for kind in ("proxy", "fcgi"):
        blk = "/%s/block/" % kind
        curl("curl -F, three files", forms, blk, 200, "full", "pass")
        curl("curl -F, three files", ["--http2-prior-knowledge"] + forms, blk,
             200, "full", "pass")
        curl("normal upload", ["--http2-prior-knowledge"] + raw_hdr
             + ["@" + os.path.join(d, "norm.bin")], blk, 200, "full", "pass",
             sha=sha_n)
        curl("last-part violation", ["--http2-prior-knowledge"] + raw_hdr
             + ["@" + os.path.join(d, "viol.bin")], blk, 413, "none", "block",
             "MGUS-202")
        curl("last-part violation", ["--http2-prior-knowledge"] + raw_hdr
             + ["@" + os.path.join(d, "viol.bin")], "/%s/monitor/" % kind, 200,
             "full", "monitor", "MGUS-202")


def run_extra(env, bod):
    """Cases added after the first round; appended so earlier IDs stay put."""
    slow = multipart([upfile("f", "slow.bin", rnd(360000, 8))])
    # Shield whole-body timeout 4s, nginx between-reads timeout 2s
    case(env, "shield 4s > nginx 2s: upload trickles for ~6s", PORT1,
         "/time/longer/", slow, (None, 408), "none", "block", "MGUS-402",
         piece=30000, delay=0.5)
    case(env, "shield 4s > nginx 2s: fast upload", PORT1, "/time/longer/",
         bod["normal"], 200, "full", "pass")
    case(env, "shield 4s > nginx 2s: client stalls (nginx ends it)", PORT1,
         "/time/longer/", slow, None, "none", "aborted",
         abort_at=None, piece=30000, delay=0.0, declared=len(slow) + 50000,
         timeout=10)


# ------------------------------------------------------------- measurements

def proc_cpu(pid):
    f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def proc_mem(pid):
    out = {}
    for line in open("/proc/%d/status" % pid):
        if line.startswith(("VmHWM", "VmRSS")):
            out[line.split(":")[0]] = int(line.split()[1])
    return out


def big_upload(env, path, mb):
    env.restart_nginx()
    pid = env.worker_pid()
    block = rnd(1 << 20, 99)
    head = (b"--" + B + b'\r\nContent-Disposition: form-data; name="f"; '
            b'filename="big.bin"\r\nContent-Type: application/octet-stream'
            b"\r\n\r\n")
    tail = b"\r\n--" + B + b"--\r\n"
    total = len(head) + mb * len(block) + len(tail)
    sha = hashlib.sha256()

    def gen():
        for p in [head] + [block] * mb + [tail]:
            sha.update(p)
            yield p

    peak = [0]
    stop = threading.Event()

    def poll():
        while not stop.is_set():
            peak[0] = max(peak[0], env.temp_bytes())
            time.sleep(0.01)

    t = threading.Thread(target=poll)
    t.start()
    env.mark()
    cpu0 = proc_cpu(pid)
    t0 = time.time()
    tid = "BIG%d" % int(t0 * 1000 % 100000)
    status, sent = send(PORT1, path + tid, gen(), tid, declared=total,
                        timeout=300)
    wall = time.time() - t0
    stop.set()
    t.join()
    time.sleep(0.3)
    reqs = [r for r in env.new_backend() if r.get("test_id") == tid]
    mem = proc_mem(pid)
    row = {
        "path": path, "upload_mb": mb, "status": status,
        "wall_s": round(wall, 2),
        "worker_cpu_s": round(proc_cpu(pid) - cpu0, 2),
        "worker_peak_rss_kb": mem.get("VmHWM"),
        "temp_disk_peak_mb": round(peak[0] / 1048576, 1),
        "temp_files_after": env.temp_files(),
        "sha_match": bool(reqs) and reqs[0]["sha256"] == sha.hexdigest(),
        "backend_body_bytes": reqs[0]["body_bytes"] if reqs else 0,
    }
    print("BIG  %-14s %4d MB status=%s wall=%ss cpu=%ss peak_rss=%s kB "
          "temp_peak=%s MB temp_after=%d sha=%s" % (
              path, mb, status, row["wall_s"], row["worker_cpu_s"],
              row["worker_peak_rss_kb"], row["temp_disk_peak_mb"],
              row["temp_files_after"], row["sha_match"]), flush=True)
    return row


def soak(env, n, bod):
    env.restart_nginx()
    pid = env.worker_pid()
    body_ok = multipart([field("a"), upfile("f", "x.bin", rnd(60000, 6))])
    body_bad = multipart([upfile("f", "x.bin", rnd(60000, 6))], close=False)
    # warm up so that allocator pools reach steady state before sampling
    for i in range(50):
        send(PORT1, "/proxy/block/warm", body_ok, "warm")
    start = {"rss_kb": proc_mem(pid)["VmRSS"],
             "fds": len(os.listdir("/proc/%d/fd" % pid))}
    cpu0 = proc_cpu(pid)
    t0 = time.time()
    counts = {}
    for i in range(n):
        kind = ("proxy", "fcgi")[i % 2]
        sel = i % 5
        if sel in (0, 1, 2):
            st, _ = send(PORT1, "/%s/block/s" % kind, body_ok, "soak")
        elif sel == 3:
            st, _ = send(PORT1, "/%s/block/s" % kind, body_bad, "soak")
        else:
            st, _ = send(PORT1, "/%s/block/s" % kind, body_ok, "soak",
                         abort_at=30000)
        counts[st] = counts.get(st, 0) + 1
    time.sleep(1)
    row = {
        "requests": n, "seconds": round(time.time() - t0, 1),
        "status_counts": {str(k): v for k, v in counts.items()},
        "worker_rss_kb_start": start["rss_kb"],
        "worker_rss_kb_end": proc_mem(pid)["VmRSS"],
        "worker_fds_start": start["fds"],
        "worker_fds_end": len(os.listdir("/proc/%d/fd" % pid)),
        "worker_cpu_s": round(proc_cpu(pid) - cpu0, 2),
        "temp_files_after": env.temp_files(),
    }
    print("SOAK", json.dumps(row), flush=True)
    return row


def main():
    nginx, module, out = sys.argv[1:4]
    big_mb = int(sys.argv[sys.argv.index("--big") + 1]) \
        if "--big" in sys.argv else 0
    soak_n = int(sys.argv[sys.argv.index("--soak") + 1]) \
        if "--soak" in sys.argv else 0

    env = Env(nginx, module, out)
    rc, text = env.config_test()
    print("nginx -t rc=%d\n%s" % (rc, text), flush=True)
    if rc != 0:
        return 2
    env.start()
    bod = bodies()
    measurements = {}
    try:
        run_matrix(env, bod)
        run_limits(env, bod)
        run_vhost(env, bod)
        run_curl(env, bod)
        run_extra(env, bod)
        time.sleep(1)
        measurements["temp_files_after_functional_tests"] = env.temp_files()
        if big_mb:
            measurements["big_upload"] = [
                big_upload(env, p, big_mb)
                for p in ("/big/off/", "/big/monitor/", "/big/block/",
                          "/big/off/", "/big/monitor/", "/big/block/")]
        if soak_n:
            measurements["soak"] = soak(env, soak_n, bod)
    finally:
        env.stop()

    err = open(env.error_log, errors="replace").read()
    measurements["nginx_alerts"] = len(re.findall(r"\[(alert|emerg|crit)\]", err))
    measurements["worker_exits_on_signal"] = err.count("exited on signal")
    passed = sum(1 for r in results if r["ok"])
    summary = {"total": len(results), "passed": passed,
               "failed": len(results) - passed}
    print("SUMMARY", json.dumps(summary), json.dumps(measurements))
    json.dump({"summary": summary, "results": results,
               "measurements": measurements},
              open(os.path.join(out, "results.json"), "w"), indent=1)
    with open(os.path.join(out, "evidence.jsonl"), "w") as f:
        for e in evidence:
            f.write(json.dumps(e) + "\n")
    for name in ("error.log", "access.log", "backend.jsonl", "nginx.conf"):
        shutil.copy(os.path.join(env.run, name), os.path.join(out, name))
    healthy = (measurements["nginx_alerts"] == 0
               and measurements["worker_exits_on_signal"] == 0)
    return 0 if passed == len(results) and healthy else 1


if __name__ == "__main__":
    sys.exit(main())
