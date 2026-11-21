#!/usr/bin/env python3
"""Hours-long repetition test on a distribution nginx package + PHP-FPM
package inside a chroot (see run_legacy.py), with the deployment module file
/usr/lib/nginx/modules/ngx_http_upload_shield_module.so of that chroot.

  soak_legacy.py start CHROOT PHPV OUT
  soak_legacy.py run   CHROOT PHPV OUT --minutes N [--concurrency C]  (repeatable)
  soak_legacy.py stop  CHROOT PHPV OUT

Workload: normal uploads (HTTP/1.1, HTTP/2) mixed with HTTP/2 uploads that
stall until the Shield whole-body timeout fires. In the "shared connection"
kind one HTTP/2 connection carries the stalled stream, a normal upload that is
in flight while the timeout fires, and a normal upload opened after it.

Verdict: FAIL on any nginx alert/crit/emerg line, any worker that exits on a
signal, any change of the worker PID, any unexpected client outcome, any
blocked request that reached PHP-FPM, or any delivered upload whose files
differ. On the first alert or worker exit the logs are copied as they are to
OUT/failure-<seconds>/ and the segment ends. All requests are harmless.
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
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))
import run_e2e as e  # noqa: E402

P_BLK, P_H2 = 18411, 18412
T = "/mgus-soak"
SAMPLE_SECONDS = 10
BAD = re.compile(r"\[(alert|emerg|crit)\]|exited on signal")
MODULE = "/usr/lib/nginx/modules/ngx_http_upload_shield_module.so"


def ch(chroot, cmd, check=True):
    p = subprocess.run(["chroot", chroot, "sh", "-c", cmd], capture_output=True, text=True)
    if check and p.returncode:
        raise SystemExit("failed: %s\n%s" % (cmd, p.stderr))
    return (p.stdout + p.stderr).strip()


def children(master):
    res = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                stat = open("/proc/%s/stat" % pid).read()
                if int(stat.rsplit(")", 1)[1].split()[1]) == master:
                    res.append(int(pid))
            except OSError:
                pass
    return sorted(res)


def rss(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmRSS"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


class Env:
    def __init__(self, chroot, phpv, out):
        self.chroot, self.phpv, self.out = chroot, phpv, out
        self.base = chroot + T
        self.run = self.base + "/run"
        self.err = self.run + "/nginx-error.log"

    def master(self):
        return int(open(self.run + "/nginx.pid").read())

    def workers(self):
        return children(self.master())

    def snapshot(self):
        w = self.workers()
        fds = temp = 0
        for pid in w:
            try:
                for fd in os.listdir("/proc/%d/fd" % pid):
                    fds += 1
                    try:
                        if "client_body_temp" in os.readlink("/proc/%d/fd/%s" % (pid, fd)):
                            temp += 1
                    except OSError:
                        pass
            except OSError:
                pass
        return {"workers": w, "worker_rss_kb": [rss(p) for p in w], "worker_fds": fds,
                "temp_open": temp,
                "temp_dir_entries": sum(len(f) for _, _, f in os.walk(self.run + "/client_body_temp")),
                "php_upload_tmp": len(os.listdir(self.run + "/php-upload-tmp")),
                "php_fpm_rss_kb": sum(rss(int(p)) for p in os.listdir("/proc") if p.isdigit()
                                      and self._is_fpm(p))}

    def _is_fpm(self, pid):
        try:
            return T + "/php-fpm.conf" in open("/proc/%s/cmdline" % pid).read() or \
                (open("/proc/%s/cmdline" % pid).read().startswith("php-fpm: pool")
                 and os.readlink("/proc/%s/root" % pid) == self.chroot)
        except OSError:
            return False

    def bad_lines(self):
        with open(self.err, errors="replace") as f:
            return [x.rstrip("\n") for x in f if BAD.search(x)]

    def preserve(self, label):
        """Copies the logs exactly as they are at this moment."""
        d = os.path.join(self.out, label)
        os.makedirs(d, exist_ok=True)
        for n in ("nginx-error.log", "nginx-access.log", "php-fpm-error.log",
                  "php-fpm-access.log"):
            try:
                shutil.copy(os.path.join(self.run, n), d)
            except OSError:
                pass
        subprocess.run("dmesg | tail -50 > %s/dmesg-tail.txt 2>&1" % d, shell=True)
        json.dump({"time": time.strftime("%Y-%m-%d %H:%M:%S %z"), "workers_now": self.workers(),
                   "bad_lines": self.bad_lines()}, open(d + "/what.json", "w"), indent=1)
        return d


def start(env):
    c, base = env.chroot, env.base
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(env.out, ignore_errors=True)
    os.makedirs(env.run + "/php-upload-tmp")
    os.makedirs(env.out)
    shutil.copytree(os.path.join(HERE, "..", "e2e", "php"), base + "/php")
    fcgi = """fastcgi_pass unix:%s/run/php-fpm.sock;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;""" % T
    up = "fastcgi_param SCRIPT_FILENAME $document_root/upload.php;"
    open(base + "/nginx.conf", "w").write("""# repetition test: distribution nginx package + deployment module
load_module %(mod)s;
user www-data;
worker_processes 1;
error_log %(t)s/run/nginx-error.log info;
pid %(t)s/run/nginx.pid;
events { worker_connections 512; }
http {
    access_log %(t)s/run/nginx-access.log;
    client_body_temp_path %(t)s/run/client_body_temp;
    fastcgi_temp_path     %(t)s/run/fastcgi_temp;
    client_max_body_size  8m;
    client_body_timeout   8s;
    server {
        listen 127.0.0.1:%(blk)d;
        listen 127.0.0.1:%(h2)d http2;
        root %(t)s/php;
        upload_shield                        block;
        upload_shield_deny_session_progress  on;
        upload_shield_max_file_size          1m;
        upload_shield_max_files              4;
        upload_shield_filename_check         on;
        location = /upload.php { %(up)s %(fcgi)s }
        location = /small.php  { upload_shield_max_body_size 2m; upload_shield_body_timeout 2s; %(up)s %(fcgi)s }
        location = /page.php   { upload_shield_deny_multipart on; fastcgi_param SCRIPT_FILENAME $document_root/page.php; %(fcgi)s }
    }
}
""" % {"mod": MODULE, "t": T, "blk": P_BLK, "h2": P_H2, "up": up, "fcgi": fcgi})
    open(base + "/php-fpm.conf", "w").write("""[global]
pid = %(t)s/run/php-fpm.pid
error_log = %(t)s/run/php-fpm-error.log
daemonize = yes

[www]
user = www-data
group = www-data
listen = %(t)s/run/php-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = static
pm.max_children = 6
access.log = %(t)s/run/php-fpm-access.log
access.format = "%%{%%s}T %%m %%r %%s len=%%l tid=%%{HTTP_X_TEST_ID}e"
env[MGUS_LOG] = %(t)s/run/php-app.jsonl
php_admin_value[upload_tmp_dir] = %(t)s/run/php-upload-tmp
""" % {"t": T})
    ch(c, "chown -R www-data:www-data %s/run" % T)
    meta = {
        "os": ch(c, ". /etc/os-release; echo $PRETTY_NAME"),
        "packages": ch(c, "dpkg-query -W -f '${Package} ${Version} ${Architecture}\\n' nginx nginx-core "
                          "nginx-common php%s-fpm php%s-common php%s-cli libssl1.1 libpcre3 zlib1g libc6"
                          % (env.phpv, env.phpv, env.phpv), check=False).splitlines(),
        "apt_sources": [x for x in open(c + "/etc/apt/sources.list").read().splitlines() if x.strip()],
        "esm_sources_configured": os.path.exists(c + "/etc/apt/sources.list.d/ubuntu-esm-infra.list")
        or "esm.ubuntu.com" in open(c + "/etc/apt/sources.list").read(),
        "nginx_V": ch(c, "nginx -V"),
        "nginx_binary_sha256": hashlib.sha256(open(c + "/usr/sbin/nginx", "rb").read()).hexdigest(),
        "php_version": ch(c, "php-fpm%s -v | head -1" % env.phpv),
        "module_path": MODULE,
        "module_sha256": hashlib.sha256(open(c + MODULE, "rb").read()).hexdigest(),
        "module_size": os.path.getsize(c + MODULE),
        "host_kernel": os.uname().release,
        "nginx_config_test": ch(c, "nginx -t -c %s/nginx.conf" % T, check=False),
        "started": time.time(), "started_text": time.strftime("%Y-%m-%d %H:%M:%S %z"),
    }
    if "successful" not in meta["nginx_config_test"]:
        raise SystemExit(meta["nginx_config_test"])
    ch(c, "php-fpm%s -y %s/php-fpm.conf" % (env.phpv, T))
    ch(c, "nginx -c %s/nginx.conf" % T)
    time.sleep(0.5)
    m = env.master()
    meta["nginx_master_pid"] = m
    meta["nginx_master_exe"] = os.readlink("/proc/%d/exe" % m)
    meta["workers"] = env.workers()
    mapped = [x.split()[-1] for x in open("/proc/%d/maps" % meta["workers"][0])
              if "ngx_http_upload_shield_module.so" in x]
    meta["module_mapped_in_worker"] = sorted(set(mapped))
    for port in (P_BLK, P_H2):
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
    for n in ("php-app.jsonl", "php-fpm-access.log"):
        open(env.run + "/" + n, "a").close()
    ch(c, "chown www-data:www-data %s/run/php-app.jsonl" % T)
    time.sleep(0.5)
    meta["idle_at_start"] = env.snapshot()
    json.dump(meta, open(env.out + "/soak-meta.json", "w"), indent=1)
    shutil.copy(base + "/nginx.conf", env.out)
    shutil.copy(base + "/php-fpm.conf", env.out)
    print("STARTED", json.dumps({k: meta[k] for k in ("os", "packages", "module_sha256",
                                                      "workers", "module_mapped_in_worker",
                                                      "nginx_master_exe")}))


def bodies():
    d = [e.rnd(300000 + 1000 * i, 100 + i) for i in range(3)]
    n0, x0 = e.build([e.F("title", b"quarterly report"), e.U("f[]", "archive.tar.gz", d[0]),
                      e.U("f[]", "jquery-3.7.1.min.js", d[1]), e.U("f[]", "c.v1.2.pdf", d[2]),
                      e.F("note", b"")])
    n1, x1 = e.build([e.F("a", b"1"), e.U("f", "x.bin", d[1][:120000])])
    return {
        "normal": [(n0, x0), (n1, x1)],
        "slow": e.build([e.U("f", "slow.bin", d[0])])[0],
        "progress": e.build([e.F("t", b"x"), e.U("f", "a.txt", d[0]),
                             e.F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0],
        "big_last": e.build([e.F("t", b"x"), e.U("f[]", "ok.bin", d[0]),
                             e.U("f[]", "big.bin", e.rnd(1024 * 1024 + 1, 9))])[0],
    }


def run(env, minutes, conc):
    b = bodies()
    meta = json.load(open(env.out + "/soak-meta.json"))
    w0 = meta["workers"]
    seg_path = env.out + "/soak-segments.jsonl"
    sample_path = env.out + "/soak-samples.jsonl"
    prior = 0.0
    if os.path.exists(sample_path):
        for line in open(sample_path):
            prior = json.loads(line)["t"]
    t_start = time.time()
    end = [t_start + minutes * 60]
    stop = threading.Event()
    lock = threading.Lock()
    kinds, unexpected, failure = {}, [], []
    shared = {"runs": 0, "stalled_cut": 0, "inflight_200": 0, "later_200": 0,
              "connection_kept": 0}

    def now():
        return round(prior + time.time() - t_start, 1)

    def sampler():
        with open(sample_path, "a") as f:
            while not stop.is_set():
                s = env.snapshot()
                s["t"] = now()
                with lock:
                    s["requests_this_segment"] = sum(v["n"] for v in kinds.values())
                bad = env.bad_lines()
                s["bad_log_lines"] = len(bad)
                f.write(json.dumps(s) + "\n")
                f.flush()
                if (bad or s["workers"] != w0) and not failure:
                    d = env.preserve("failure-%d" % s["t"])
                    failure.append({"t": s["t"], "workers_expected": w0,
                                    "workers_seen": s["workers"], "bad_lines": bad[:20],
                                    "logs_preserved_in": d})
                    print("FAILURE", json.dumps(failure[0]), flush=True)
                    end[0] = time.time()
                stop.wait(SAMPLE_SECONDS)

    def note(kind, ok, got):
        with lock:
            k = kinds.setdefault(kind, {"n": 0, "ok": 0})
            k["n"] += 1
            k["ok"] += bool(ok)
            if not ok and len(unexpected) < 100:
                unexpected.append({"kind": kind, "got": str(got)[:400], "t": now()})

    def client(seed):
        r = random.Random(seed)
        while time.time() < end[0]:
            x = r.random()
            i = r.randrange(2)
            body = b["normal"][i][0]
            try:
                if x < 0.30:
                    st, _ = e.h2c(P_H2, "/upload.php", body, "sk-n%d" % i, wait=60)
                    note("normal upload, HTTP/2", st == 200, st)
                elif x < 0.50:
                    ck = r.random() < 0.3
                    st, _ = e.h1(P_BLK, "/upload.php", body, "sk-n%d" % i, wait=60,
                                 chunked=ck, piece=7919 if ck else 65536)
                    note("normal upload, HTTP/1.1", st == 200, st)
                elif x < 0.72:
                    res, closed = e.h2_multi(P_H2, [
                        {"tid": "sk-timeout", "path": "/small.php", "body": b["slow"],
                         "stall_at": 90000},
                        {"tid": "sk-n0", "path": "/upload.php", "body": b["normal"][0][0],
                         "piece": 60000, "delay": 0.3},
                        {"tid": "sk-n1", "path": "/upload.php", "body": b["normal"][1][0],
                         "start": 3.0}], tls=False)
                    cut = (res[0]["status"] in (None, 408) and res[0]["done"]
                           and 1.8 <= res[0]["end"] <= 3.5)
                    a, c2 = res[1]["status"] == 200, res[2]["status"] == 200
                    with lock:
                        shared["runs"] += 1
                        shared["stalled_cut"] += cut
                        shared["inflight_200"] += a
                        shared["later_200"] += c2
                        shared["connection_kept"] += (not closed)
                    note("HTTP/2 shared connection: timeout stream + 2 normal streams",
                         cut and a and c2 and not closed, (res, closed))
                elif x < 0.84:
                    st, secs = e.h2c(P_H2, "/small.php", b["slow"], "sk-timeout", stall_at=90000)
                    note("HTTP/2 upload timeout, own connection",
                         st in (None, 408) and 1.8 <= secs <= 3.5, (st, secs))
                elif x < 0.88:
                    st, secs = e.h1(P_BLK, "/small.php", b["slow"], "sk-timeout", stall_at=90000)
                    note("HTTP/1.1 upload timeout", st in (None, 408) and 1.8 <= secs <= 3.5,
                         (st, secs))
                elif x < 0.92:
                    st, _ = e.h2c(P_H2, "/upload.php", b["progress"], "sk-violation")
                    note("progress field, HTTP/2 (403)", st == 403, st)
                elif x < 0.95:
                    st, _ = e.h1(P_BLK, "/upload.php", b["big_last"], "sk-violation")
                    note("last file over limit, HTTP/1.1 (413)", st == 413, st)
                elif x < 0.97:
                    st, _ = e.h1(P_BLK, "/page.php?q=1", b["normal"][1][0], "sk-violation")
                    note("multipart to no-upload path (403)", st == 403, st)
                else:
                    st, _ = e.h1(P_BLK, "/upload.php", b["normal"][0][0], "sk-abort",
                                 abort_at=r.randrange(1000, 250000))
                    note("client abort mid-upload", st is None, st)
            except Exception as ex:  # noqa: BLE001 - record and continue
                note("client exception", False, "%s: %s" % (type(ex).__name__, ex))

    threading.Thread(target=sampler, daemon=True).start()
    threads = [threading.Thread(target=client, args=(int(prior) * 100 + i,))
               for i in range(conc)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(5)
    stop.set()
    time.sleep(1)
    seg = {"from_t": prior, "minutes_requested": minutes,
           "seconds_run": round(time.time() - t_start), "concurrency": conc,
           "requests": sum(v["n"] for v in kinds.values()), "kinds": kinds,
           "unexpected_count": sum(v["n"] - v["ok"] for v in kinds.values()),
           "unexpected_examples": unexpected, "shared_connection": shared,
           "idle_after": env.snapshot(), "workers_at_start_of_run": w0,
           "bad_log_lines": len(env.bad_lines()), "failure": failure}
    with open(seg_path, "a") as f:
        f.write(json.dumps(seg) + "\n")
    print("SEGMENT", json.dumps({k: seg[k] for k in (
        "from_t", "seconds_run", "requests", "unexpected_count", "shared_connection",
        "idle_after", "bad_log_lines", "failure")}), flush=True)


def stop(env):
    meta = json.load(open(env.out + "/soak-meta.json"))
    b = bodies()
    meta["workers_at_end"] = env.workers()
    meta["idle_at_end"] = env.snapshot()
    meta["ended_text"] = time.strftime("%Y-%m-%d %H:%M:%S %z")
    meta["module_sha256_at_end"] = hashlib.sha256(open(env.chroot + MODULE, "rb").read()).hexdigest()
    ch(env.chroot, "nginx -c %s/nginx.conf -s quit" % T, check=False)
    ch(env.chroot, "kill $(cat %s/run/php-fpm.pid)" % T, check=False)
    time.sleep(2)
    bad = env.bad_lines()
    err = open(env.err, errors="replace").read()
    meta["nginx_alert_crit_emerg_lines"] = len(re.findall(r"\[(alert|emerg|crit)\]", err))
    meta["worker_exits_on_signal"] = err.count("exited on signal")
    meta["bad_lines"] = bad[:50]
    rules = {}
    for m in re.finditer(r'"action":"(\w+)","rule":"([\w-]+)"', err):
        rules["%s %s" % m.groups()] = rules.get("%s %s" % m.groups(), 0) + 1
    meta["shield_log_by_action_rule"] = rules
    # backend side: what PHP-FPM received, by test id
    acc = {}
    for line in open(env.run + "/php-fpm-access.log", errors="replace"):
        tid = line.rstrip("\n").rsplit("tid=", 1)[-1]
        acc[tid] = acc.get(tid, 0) + 1
    meta["php_fpm_access_lines_by_test_id"] = acc
    exp = {"sk-n%d" % i: (x["file_list"], x["fields"]) for i, (_, x) in enumerate(b["normal"])}
    app = {"records": 0, "normal_records": 0, "normal_sha256_match": 0, "other_test_ids": {}}
    for line in open(env.run + "/php-app.jsonl", errors="replace"):
        rec = json.loads(line)
        app["records"] += 1
        if rec["test_id"] in exp:
            app["normal_records"] += 1
            fl, fields = exp[rec["test_id"]]
            app["normal_sha256_match"] += (e.files_of(rec) == fl and rec["fields"] == fields)
        else:
            app["other_test_ids"][rec["test_id"]] = app["other_test_ids"].get(rec["test_id"], 0) + 1
    meta["php_app_records"] = app
    segs = [json.loads(x) for x in open(env.out + "/soak-segments.jsonl")]
    kinds = {}
    for s in segs:
        for k, v in s["kinds"].items():
            t = kinds.setdefault(k, {"n": 0, "ok": 0})
            t["n"] += v["n"]
            t["ok"] += v["ok"]
    shared = {k: sum(s["shared_connection"][k] for s in segs) for k in segs[0]["shared_connection"]}
    normal_200 = (kinds.get("normal upload, HTTP/2", {}).get("ok", 0)
                  + kinds.get("normal upload, HTTP/1.1", {}).get("ok", 0)
                  + shared["inflight_200"] + shared["later_200"])
    meta["totals"] = {"seconds": sum(s["seconds_run"] for s in segs),
                      "requests": sum(s["requests"] for s in segs), "kinds": kinds,
                      "shared_connection": shared, "normal_200_seen_by_clients": normal_200,
                      "unexpected": sum(s["unexpected_count"] for s in segs)}
    checks = {
        "no nginx alert/crit/emerg": meta["nginx_alert_crit_emerg_lines"] == 0,
        "no worker exited on signal": meta["worker_exits_on_signal"] == 0,
        "worker PID unchanged from start to end": meta["workers"] == meta["workers_at_end"],
        "no failure recorded during segments": not any(s["failure"] for s in segs),
        "no unexpected client outcome": meta["totals"]["unexpected"] == 0,
        "shared connection: every stalled stream cut, every other stream 200, connection kept":
            shared["runs"] > 0 and all(shared[k] == shared["runs"] for k in shared),
        "timeout/violation requests reaching PHP-FPM = 0":
            acc.get("sk-timeout", 0) == 0 and acc.get("sk-violation", 0) == 0
            and not app["other_test_ids"].get("sk-timeout") and not app["other_test_ids"].get("sk-violation"),
        "every normal upload delivered once with matching SHA-256":
            app["normal_records"] == normal_200 == app["normal_sha256_match"]
            and acc.get("sk-n0", 0) + acc.get("sk-n1", 0) == normal_200,
        "no temp file left": meta["idle_at_end"]["temp_dir_entries"] == 0
            and meta["idle_at_end"]["php_upload_tmp"] == 0,
        "module file unchanged during the run": meta["module_sha256"] == meta["module_sha256_at_end"],
    }
    meta["checks"] = checks
    meta["verdict"] = "PASS" if all(checks.values()) else "FAIL"
    if meta["verdict"] == "FAIL" and not any(s["failure"] for s in segs):
        env.preserve("failure-at-stop")
    json.dump(meta, open(env.out + "/soak-meta.json", "w"), indent=1)
    for n in ("nginx-error.log", "nginx-access.log", "php-fpm-access.log",
              "php-fpm-error.log", "php-app.jsonl"):
        shutil.copy(env.run + "/" + n, env.out)
    print("STOPPED", json.dumps({k: meta[k] for k in ("verdict", "checks", "totals", "workers",
                                                       "workers_at_end", "idle_at_end")}))
    return 0 if meta["verdict"] == "PASS" else 1


def main():
    cmd, chroot, phpv, out = sys.argv[1:5]
    env = Env(chroot, phpv, out)
    if cmd == "start":
        start(env)
    elif cmd == "run":
        conc = int(sys.argv[sys.argv.index("--concurrency") + 1]) if "--concurrency" in sys.argv else 6
        run(env, float(sys.argv[sys.argv.index("--minutes") + 1]), conc)
    elif cmd == "stop":
        return stop(env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
