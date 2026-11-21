#!/usr/bin/env python3
"""Second-round verification of Kuipernet Upload against real backends.

  nginx (+ module)  ->  PHP-FPM 8.3 (fastcgi_pass)
                    ->  Apache Tomcat 10.1 (proxy_pass)

Backend-side instrumentation used for every case:
  PHP-FPM : FPM's own access log, the PHP scripts' record (php/record.php)
  Tomcat  : AccessLogValve, the servlets' record
  both    : kernel packet counters (iptables) on the backend's listening port,
            so "0 packets" means nginx did not even open a connection

Usage: run_e2e.py NGINX_BINARY MODULE_SO OUTPUT_DIR [--rounds N] [--round-seconds S]
                  [--concurrency C]
"""
import hashlib
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "integration"))
from run_tests import B, CT, rnd  # noqa: E402

P_OFF, P_MON, P_BLK, P_CON = 18180, 18181, 18182, 18183
P_FN_MON, P_FN_BLK = 18184, 18185       # as P_MON / P_BLK plus the file name policy
P_TLS_CON, P_TLS_BLK = 18443, 18444     # TLS listeners of the contract / block server
P_FPM, P_TC = 19000, 19090
MODES = {P_OFF: "off", P_MON: "monitor", P_BLK: "block"}
LABEL = {P_OFF: "off", P_MON: "monitor", P_BLK: "block", P_CON: "contract",
         P_FN_MON: "monitor+filename", P_FN_BLK: "block+filename",
         P_TLS_CON: "contract", P_TLS_BLK: "block"}
PHP_FPM = "/usr/sbin/php-fpm8.3"
TOMCAT_HOME = "/usr/share/tomcat10"

cases = []          # one dict per test case


# ---------------------------------------------------------------- body specs

def F(name, value=b"v"):
    return ("field", name, value)


def U(name, filename, data):
    return ("file", name, filename, data)


def build(parts, close=True, tail=b"", boundary=B):
    """Returns (body, expectation) for well-formed part specs."""
    out = b""
    files = []
    fields = 0
    for p in parts:
        if p[0] == "field":
            hdr = b'Content-Disposition: form-data; name="' + p[1].encode() + b'"'
            data = p[2]
            fields += 1
        elif p[0] == "file":
            hdr = (b'Content-Disposition: form-data; name="' + p[1].encode()
                   + b'"; filename="' + p[2].encode() + b'"\r\n'
                   b"Content-Type: application/octet-stream")
            data = p[3]
            files.append((len(data), hashlib.sha256(data).hexdigest()))
        else:                       # ("raw", header bytes, data, kind)
            hdr, data = p[1], p[2]
            if p[3] == "file":
                files.append((len(data), hashlib.sha256(data).hexdigest()))
            else:
                fields += 1
        out += b"--" + boundary + b"\r\n" + hdr + b"\r\n\r\n" + data + b"\r\n"
    if close:
        out += b"--" + boundary + b"--\r\n"
    exp = {"files": len(files), "fields": fields,
           "max_file_bytes": max([f[0] for f in files] or [0]),
           "file_list": sorted(files)}
    return out + tail, exp


# -------------------------------------------------------------- environment

class Env:
    def __init__(self, nginx, module, out, quiet=False, attach=False):
        """quiet: keep only warnings and no per-request application records
        (long runs). attach: use an environment that is already running."""
        self.nginx, self.module, self.out = nginx, module, out
        self.quiet = quiet
        self.run = os.path.join(out, "run")
        if not attach:
            shutil.rmtree(out, ignore_errors=True)
            for d in ("", "php-upload-tmp", "tomcat/conf", "tomcat/logs",
                      "tomcat/temp", "tomcat/work",
                      "tomcat/webapps/ROOT/WEB-INF/classes"):
                os.makedirs(os.path.join(self.run, d))
        self.logs = {
            "shield": os.path.join(self.run, "nginx-error.log"),
            "php_access": os.path.join(self.run, "php-fpm-access.log"),
            "php_app": os.path.join(self.run, "php-app.jsonl"),
            "tc_access": os.path.join(self.run, "tomcat/logs/access.log"),
            "tc_app": os.path.join(self.run, "tomcat-app.jsonl"),
        }
        self.off = {}
        self.pk = {}
        self.nginx_conf = os.path.join(self.run, "nginx.conf")
        self.fpm_conf = os.path.join(self.run, "php-fpm.conf")
        if attach:
            return
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-days", "2", "-subj", "/CN=localhost",
                        "-keyout", os.path.join(self.run, "tls.key"),
                        "-out", os.path.join(self.run, "tls.crt")],
                       check=True, capture_output=True)
        self._write_nginx()
        self._write_fpm()
        self._write_tomcat()

    # -- configuration files

    def _write_nginx(self):
        policy = """
        upload_shield                        %s;
        upload_shield_max_file_size          4m;
        upload_shield_max_files              6;
        upload_shield_max_parts              20;
        upload_shield_max_field_size         64k;
        upload_shield_deny_session_progress  on;
"""
        php = """
        location ~ \\.php$ {
            fastcgi_pass 127.0.0.1:%d;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;
        }
        location /tc/ { proxy_pass http://127.0.0.1:%d/; }
""" % (P_FPM, P_TC)
        con = """
            fastcgi_pass 127.0.0.1:%d;
            fastcgi_param SCRIPT_FILENAME $document_root/upload.php;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;
""" % P_FPM
        servers = ""
        for port, mode in MODES.items():
            servers += """
    # ---- whole virtual host: upload_shield %s ----
    server {
        listen 127.0.0.1:%d;%s
        http2 on;
        root %s;
%s%s    }
""" % (mode, port,
       "\n        listen 127.0.0.1:%d ssl;" % P_TLS_BLK if mode == "block" else "",
       os.path.join(HERE, "php"),
       policy % mode if mode != "off" else "", php)
        for port, mode in ((P_FN_MON, "monitor"), (P_FN_BLK, "block")):
            servers += """
    # ---- whole virtual host: upload_shield %s + optional file name policy ----
    server {
        listen 127.0.0.1:%d;
        http2 on;
        root %s;
%s        upload_shield_filename_check         on;
%s
        # the built-in extension list replaced by the operator's own
        location = /custom.php { upload_shield_filename_deny_ext exe SVG; %s }
    }
""" % (mode, port, os.path.join(HERE, "php"), policy % mode, php, con)
        servers += """
    # ---- size / timeout contract: nginx limits are 8m and 8s here ----
    server {
        listen 127.0.0.1:%d;
        listen 127.0.0.1:%d ssl;
        http2 on;
        root %s;
        client_max_body_size 8m;
        client_body_timeout  8s;

        # Shield values not set: nginx's limits apply
        location = /c/unset    { upload_shield block; %s }
        # Shield values below nginx's: the Shield values are effective
        location = /c/small    { upload_shield block;   upload_shield_max_body_size 2m; upload_shield_body_timeout 2s; %s }
        location = /c/small-m  { upload_shield monitor; upload_shield_max_body_size 2m; upload_shield_body_timeout 2s; %s }
        # Shield values above nginx's: nginx applies first (config conflict)
        location = /c/conflict { upload_shield block;   upload_shield_max_body_size 32m; upload_shield_body_timeout 30s; %s }
    }
""" % (P_CON, P_TLS_CON, os.path.join(HERE, "php"), con, con, con, con)

        text = """# Generated by tests/e2e/run_e2e.py
load_module %s;
user root;
worker_processes 2;
error_log %s %s;
pid %s/nginx.pid;
events { worker_connections 512; }
http {
    log_format shield '$status $request_method $uri $server_protocol '
                      'shield=$upload_shield_action rule=$upload_shield_rule';
    access_log %s;
    ssl_certificate     %s/tls.crt;
    ssl_certificate_key %s/tls.key;
    client_body_temp_path %s/client_body_temp;
    proxy_temp_path       %s/proxy_temp;
    fastcgi_temp_path     %s/fastcgi_temp;
    client_max_body_size  64m;
%s}
""" % (self.module, self.logs["shield"], "warn" if self.quiet else "info",
            self.run,
            "off" if self.quiet else self.run + "/nginx-access.log shield",
            self.run, self.run, self.run, self.run, self.run, servers)
        open(self.nginx_conf, "w").write(text)

    def _write_fpm(self):
        open(self.fpm_conf, "w").write("""; Generated by tests/e2e/run_e2e.py
[global]
pid = %(run)s/php-fpm.pid
error_log = %(run)s/php-fpm-error.log
daemonize = yes

[www]
user = root
group = root
listen = 127.0.0.1:%(port)d
pm = static
pm.max_children = 8
pm.status_path = /fpm-status
access.log = %(run)s/php-fpm-access.log
access.format = "%%{%%s}T %%m %%r %%s len=%%l tid=%%{HTTP_X_TEST_ID}e"
env[MGUS_LOG] = %(applog)s
php_admin_value[upload_tmp_dir] = %(run)s/php-upload-tmp
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 128M
""" % {"run": self.run, "port": P_FPM,
       "applog": "/dev/null" if self.quiet else self.run + "/php-app.jsonl"})

    def _write_tomcat(self):
        base = os.path.join(self.run, "tomcat")
        text = open(os.path.join(HERE, "tomcat", "server.xml.in")).read()
        open(os.path.join(base, "conf", "server.xml"), "w").write(
            text.replace("@TOMCAT@", str(P_TC)))
        shutil.copy("/etc/tomcat10/web.xml", os.path.join(base, "conf"))
        src = [os.path.join(HERE, "tomcat", "src", "mgus", f)
               for f in os.listdir(os.path.join(HERE, "tomcat", "src", "mgus"))]
        subprocess.run(["javac", "-cp", TOMCAT_HOME + "/lib/servlet-api.jar",
                        "-d", os.path.join(base, "webapps/ROOT/WEB-INF/classes")]
                       + src, check=True, capture_output=True)

    # -- processes

    def start(self):
        p = subprocess.run([self.nginx, "-t", "-c", self.nginx_conf],
                           capture_output=True, text=True)
        open(os.path.join(self.out, "nginx-config-test.txt"), "w").write(p.stderr)
        print(p.stderr, flush=True)
        if p.returncode:
            raise SystemExit("nginx -t failed")

        subprocess.run([PHP_FPM, "-y", self.fpm_conf, "-R"], check=True,
                       capture_output=True)
        env = dict(os.environ, CATALINA_HOME=TOMCAT_HOME,
                   CATALINA_BASE=os.path.join(self.run, "tomcat"),
                   CATALINA_PID=os.path.join(self.run, "tomcat.pid"),
                   CATALINA_TMPDIR=os.path.join(self.run, "tomcat/temp"),
                   CATALINA_OPTS="-Dmgus.log="
                   + ("/dev/null" if self.quiet else self.logs["tc_app"])
                   + " -Xmx512m")
        subprocess.run([TOMCAT_HOME + "/bin/catalina.sh", "start"], env=env,
                       check=True, capture_output=True)
        subprocess.run([self.nginx, "-c", self.nginx_conf], check=True)
        for port in (P_FPM, P_TC, P_OFF, P_MON, P_BLK, P_CON, P_FN_MON,
                     P_FN_BLK, P_TLS_CON, P_TLS_BLK):
            for _ in range(600):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise SystemExit("port %d did not come up" % port)
        # wait until the web application answers
        for _ in range(100):
            if self.tomcat_stats() is not None:
                break
            time.sleep(0.2)

        for cmd in (["-N", "MGUS"], ["-I", "INPUT", "-j", "MGUS"],
                    ["-A", "MGUS", "-p", "tcp", "--dport", str(P_FPM)],
                    ["-A", "MGUS", "-p", "tcp", "--dport", str(P_TC)]):
            subprocess.run(["iptables"] + cmd, check=True)
        for v in self.logs.values():
            open(v, "a").close()
        time.sleep(0.5)

    def stop(self):
        for cmd in (["-D", "INPUT", "-j", "MGUS"], ["-F", "MGUS"],
                    ["-X", "MGUS"]):
            subprocess.run(["iptables"] + cmd, capture_output=True)
        subprocess.run([self.nginx, "-c", self.nginx_conf, "-s", "quit"])
        for name in ("php-fpm.pid", "tomcat.pid"):
            try:
                os.kill(int(open(os.path.join(self.run, name)).read()), 15)
            except (OSError, ValueError):
                pass
        time.sleep(2)

    def versions(self):
        def out(cmd, env=None):
            p = subprocess.run(cmd, capture_output=True, text=True, env=env)
            return (p.stdout + p.stderr).strip()
        v = {"nginx": out([self.nginx, "-v"]),
             "php_fpm": out([PHP_FPM, "-v"]).splitlines()[0],
             "kernel": os.uname().release}
        t = out([TOMCAT_HOME + "/bin/version.sh"],
                dict(os.environ, CATALINA_HOME=TOMCAT_HOME))
        v["tomcat"] = [x for x in t.splitlines() if "Server version" in x][0]
        v["jvm"] = [x for x in t.splitlines() if "JVM Version" in x][0]
        return v

    # -- backend-side observation

    def packets(self):
        p = subprocess.run(["iptables", "-L", "MGUS", "-v", "-n", "-x"],
                           capture_output=True, text=True).stdout
        res = {}
        for line in p.splitlines():
            m = re.match(r"\s*(\d+)\s+(\d+)\s.*dpt:(\d+)", line)
            if m:
                res[int(m.group(3))] = int(m.group(1))
        return res

    def mark(self):
        self.off = {k: os.path.getsize(v) for k, v in self.logs.items()}
        self.pk = self.packets()

    def _new(self, key):
        with open(self.logs[key], errors="replace") as f:
            f.seek(self.off[key])
            return [x.rstrip("\n") for x in f if x.strip()]

    def observe(self, tid):
        pk = self.packets()
        shield, raw = [], []
        for line in self._new("shield"):
            m = re.search(r"upload_shield: (\{.*?\})", line)
            if m:
                shield.append(json.loads(m.group(1)))
                raw.append(line)
        tag = "tid=" + tid
        return {
            "shield": shield, "shield_raw": raw,
            "php_access": [x for x in self._new("php_access") if x.endswith(tag)],
            "php_app": [json.loads(x) for x in self._new("php_app")
                        if json.loads(x)["test_id"] == tid],
            "tc_access": [x for x in self._new("tc_access") if x.endswith(tag)],
            "tc_app": [json.loads(x) for x in self._new("tc_app")
                       if json.loads(x)["test_id"] == tid],
            "pkts_php": pk[P_FPM] - self.pk[P_FPM],
            "pkts_tc": pk[P_TC] - self.pk[P_TC],
        }

    def tomcat_stats(self):
        try:
            s = socket.create_connection(("127.0.0.1", P_TC), 2)
            s.sendall(b"GET /stats HTTP/1.0\r\n\r\n")
            data = b""
            while True:
                d = s.recv(65536)
                if not d:
                    break
                data += d
            s.close()
            if b" 200 " not in data.split(b"\r\n", 1)[0]:
                return None
            return json.loads(data.split(b"\r\n\r\n", 1)[1])
        except (OSError, ValueError):
            return None

    # -- nginx worker resources

    def workers(self):
        try:
            master = int(open(os.path.join(self.run, "nginx.pid")).read())
        except (OSError, ValueError):
            return []
        res = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    stat = open("/proc/%s/stat" % pid).read()
                except OSError:
                    continue
                if int(stat.rsplit(")", 1)[1].split()[1]) == master:
                    res.append(int(pid))
        return sorted(res)

    def snapshot(self):
        rss = fds = tmp_open = tmp_bytes = 0
        for pid in self.workers():
            try:
                for line in open("/proc/%d/status" % pid):
                    if line.startswith("VmRSS"):
                        rss += int(line.split()[1])
                names = os.listdir("/proc/%d/fd" % pid)
                fds += len(names)
                for fd in names:
                    try:
                        path = "/proc/%d/fd/%s" % (pid, fd)
                        if "client_body_temp" in os.readlink(path):
                            tmp_open += 1
                            tmp_bytes += os.stat(path).st_blocks * 512
                    except OSError:
                        pass
            except OSError:
                pass
        tmp_dir = sum(len(f) for _, _, f in os.walk(
            os.path.join(self.run, "client_body_temp")))
        return {"rss_kb": rss, "fds": fds, "temp_open": tmp_open,
                "temp_open_mb": round(tmp_bytes / 1048576, 1),
                "temp_dir_entries": tmp_dir,
                "php_upload_tmp": len(os.listdir(
                    os.path.join(self.run, "php-upload-tmp")))}


# ------------------------------------------------------------------ clients

def h1(port, path, body, tid, ctype=CT, chunked=False, piece=65536, delay=0.0,
       stall_at=None, abort_at=None, declared=None, wait=40):
    """HTTP/1.1 request over a raw socket. Returns (status|None, seconds)."""
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(wait)
    head = "POST %s HTTP/1.1\r\nHost: test\r\nX-Test-Id: %s\r\n" % (path, tid)
    if ctype:
        head += "Content-Type: %s\r\n" % ctype
    head += "Transfer-Encoding: chunked\r\n" if chunked else \
        "Content-Length: %d\r\n" % (len(body) if declared is None else declared)
    head += "Connection: close\r\n\r\n"
    sent = 0
    try:
        s.sendall(head.encode())
        while sent < len(body):
            p = body[sent:sent + piece]
            if stall_at is not None and sent >= stall_at:
                break                       # keep the connection open, send nothing
            if abort_at is not None and sent >= abort_at:
                time.sleep(0.1)
                s.close()
                return None, time.time() - t0
            s.sendall((b"%x\r\n" % len(p) + p + b"\r\n") if chunked else p)
            sent += len(p)
            if delay:
                time.sleep(delay)
        if chunked and sent >= len(body):
            s.sendall(b"0\r\n\r\n")
    except OSError:
        pass
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
    return (int(m.group(1)) if m else None), time.time() - t0


def tls_h2(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE         # self-signed test certificate
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(sock, server_hostname="localhost")
    if s.selected_alpn_protocol() != "h2":
        raise OSError("ALPN did not select h2")
    return s


def h2c(port, path, body, tid, ctype=CT, with_length=True, piece=16384,
        delay=0.0, stall_at=None, wait=40, tls=False):
    """HTTP/2 request: cleartext with prior knowledge, or over TLS (ALPN h2).
    Returns (status|None, seconds)."""
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", port), 5)
    if tls:
        s = tls_h2(s)
    conn = h2.connection.H2Connection(
        h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    hdrs = [(":method", "POST"), (":path", path), (":scheme", "http"),
            (":authority", "test"), ("content-type", ctype), ("x-test-id", tid)]
    if tls:
        hdrs[2] = (":scheme", "https")
    if with_length:
        hdrs.append(("content-length", str(len(body))))
    conn.send_headers(1, hdrs)
    state = {"status": None, "done": False}

    def flush():
        data = conn.data_to_send()
        if data:
            s.sendall(data)

    def pump(timeout):
        s.settimeout(timeout if timeout > 0 else 0.0001)
        try:
            data = s.recv(65536)
        except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
            return
        except OSError:
            state["done"] = True
            return
        if not data:
            state["done"] = True
            return
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                state["status"] = int(dict(ev.headers)[":status"])
            elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset,
                                 h2.events.ConnectionTerminated)):
                state["done"] = True
        try:
            flush()
        except OSError:
            state["done"] = True

    try:
        flush()
        sent = 0
        while sent < len(body) and not state["done"]:
            if stall_at is not None and sent >= stall_at:
                break
            win = min(conn.local_flow_control_window(1),
                      conn.max_outbound_frame_size, piece, len(body) - sent)
            if win <= 0:
                pump(0.5)
                continue
            conn.send_data(1, body[sent:sent + win],
                           end_stream=(sent + win == len(body)))
            flush()
            sent += win
            pump(0)
            if delay:
                time.sleep(delay)
    except OSError:
        pass
    except h2.exceptions.ProtocolError:
        pass
    while not state["done"] and time.time() - t0 < wait:
        pump(0.5)
    s.close()
    return state["status"], time.time() - t0


# ---------------------------------------------------------------- recording

def run_case(env, group, name, proto, port, backend, path, body, client_kw=None,
             settle=0.35):
    tid = "E%03d" % (len(cases) + 1)
    env.mark()
    kw = dict(client_kw or {})
    if proto == "h2tls":
        kw["tls"] = True
    fn = h1 if proto == "h1" else h2c
    status, secs = fn(port, path, body, tid, **kw)
    time.sleep(settle)
    ob = env.observe(tid)
    c = {"id": tid, "group": group, "name": name, "proto": proto,
         "server": LABEL[port], "backend": backend,
         "path": path, "client_status": status, "seconds": round(secs, 2),
         "body_bytes": len(body), "obs": ob, "checks": {}, "ok": True}
    cases.append(c)
    return c


def check(c, label, cond):
    c["checks"][label] = bool(cond)
    if not cond:
        c["ok"] = False


def backend_view(c):
    """What the real backend reported for this case (or None)."""
    app = c["obs"]["php_app"] if c["backend"] == "php" else c["obs"]["tc_app"]
    return app[0] if len(app) == 1 else None


def backend_zero(c):
    ob = c["obs"]
    if c["backend"] == "php":
        return not ob["php_access"] and not ob["php_app"] and ob["pkts_php"] == 0
    return not ob["tc_access"] and not ob["tc_app"] and ob["pkts_tc"] == 0


def files_of(view):
    empty = hashlib.sha256(b"").hexdigest()
    return sorted((f["size"], f["sha256"] or empty) for f in view["file_list"])


def shield_of(c):
    return c["obs"]["shield"][0] if len(c["obs"]["shield"]) == 1 else {}


def show(c):
    sh = shield_of(c)
    ob = c["obs"]
    v = backend_view(c)
    print("%s %s %-9s %-16s %-5s %-52s st=%-4s %5.2fs shield=%s/%s "
          "backend: access=%d app=%d pkts=%d %s %s" % (
              "PASS" if c["ok"] else "FAIL", c["id"], c["group"], c["server"],
              c["proto"], (c["backend"] + ": " + c["name"])[:52],
              c["client_status"], c["seconds"], sh.get("action", "-"),
              sh.get("rule", "-"),
              len(ob["php_access"] if c["backend"] == "php" else ob["tc_access"]),
              len(ob["php_app"] if c["backend"] == "php" else ob["tc_app"]),
              ob["pkts_php"] if c["backend"] == "php" else ob["pkts_tc"],
              ("files=%d fields=%d" % (v["files"], v["fields"]))
              if v and "files" in v else "",
              "" if c["ok"] else [k for k, x in c["checks"].items() if not x]),
          flush=True)


TARGETS = (("php", "/upload.php"), ("tomcat", "/tc/upload"))


# ------------------------------------------------- 1. function with real backends

def group_function(env):
    data = [rnd(300000 + 1000 * i, 100 + i) for i in range(3)]
    normal, n_exp = build([F("title", b"quarterly report"),
                           U("f[]", "a.tar.gz", data[0]),
                           U("f[]", "b.min.js", data[1]),
                           U("f[]", "c.v1.2.pdf", data[2]), F("note", b"")])
    ok_file = rnd(200000, 7)
    violations = [
        ("last part: file over 4m limit", "MGUS-202", 413,
         build([F("t"), U("f[]", "ok.bin", ok_file),
                U("f[]", "big.bin", rnd(4 * 1024 * 1024 + 1, 8))])[0]),
        ("last part: 7th file (limit 6)", "MGUS-203", 403,
         build([U("f[]", "n%d" % i, ok_file[:40000]) for i in range(7)])[0]),
        ("last part: session progress field", "MGUS-301", 403,
         build([F("t"), U("f", "a.txt", ok_file),
                F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]),
        ("last part: form field over 64k", "MGUS-205", 413,
         build([U("f", "a.txt", ok_file), F("big", b"v" * 65537)])[0]),
        ("end of body: closing boundary missing", "MGUS-105", 400,
         build([F("t"), U("f", "a.txt", ok_file)], close=False)[0]),
    ]

    for backend, path in TARGETS:
        for port in (P_OFF, P_MON, P_BLK):
            for proto, kw in (("h1", {}), ("h1", {"chunked": True, "piece": 7919}),
                              ("h2", {})):
                c = run_case(env, "function", "normal multi-file upload"
                             + (" (chunked)" if kw else ""), proto, port,
                             backend, path, normal, kw)
                v = backend_view(c)
                check(c, "status 200", c["client_status"] == 200)
                check(c, "backend processed one request", v is not None)
                if v:
                    check(c, "files as sent", v["files"] == n_exp["files"])
                    check(c, "fields as sent", v["fields"] == n_exp["fields"])
                    check(c, "file bytes identical (sha256)",
                          files_of(v) == n_exp["file_list"])
                if port != P_OFF:
                    check(c, "shield pass", shield_of(c).get("action") == "pass")
                show(c)

        for name, rule, status, body in violations:
            c = run_case(env, "function", name, "h1", P_MON, backend, path, body)
            check(c, "delivered", backend_view(c) is not None)
            check(c, "shield monitor log", shield_of(c).get("action") == "monitor"
                  and shield_of(c).get("rule") == rule)
            show(c)
            for proto in ("h1", "h2"):
                c = run_case(env, "function", name, proto, P_BLK, backend, path,
                             body)
                check(c, "status %d" % status, c["client_status"] == status)
                check(c, "backend: 0 requests, 0 packets", backend_zero(c))
                check(c, "shield block log", shield_of(c).get("action") == "block"
                      and shield_of(c).get("rule") == rule)
                show(c)


# ----------------------------------- 2. Shield's reading vs PHP's and Tomcat's

def group_differential(env):
    d = [rnd(50000 + 777 * i, 200 + i) for i in range(4)]
    tricky = (b"line\r\n--" + B[:-1] + b"\r\nmore --" + B + b" inline\r\n-\r\n--\r"
              b"\n\r\n" + d[0][:5000])
    R = lambda hdr, data, kind: ("raw", hdr, data, kind)  # noqa: E731
    corpus = [
        ("single small file", [U("f", "a.txt", b"hello")], None),
        ("fields only", [F("a", b"1"), F("b", b"two"), F("c", b"")], None),
        ("three files under f[] plus two fields",
         [F("t", b"x"), U("f[]", "a.tar.gz", d[0]), U("f[]", "b.min.js", d[1]),
          U("f[]", "c.v1.2.pdf", d[2]), F("n", b"y")], None),
        ("distinct file names and nested field names",
         [U("doc", "d.pdf", d[0]), U("img", "i.png", d[1]),
          F("meta[owner][id]", b"7"), F("meta[tags][]", b"a"),
          F("meta[tags][]", b"b")], None),
        ("empty file control (filename=\"\")",
         [F("t", b"x"), U("f", "", b"")], None),
        ("zero-byte file with a name", [U("f", "empty.bin", b"")], None),
        ("UTF-8 and punctuated file names",
         [U("f[]", "\ubcf4\uace0\uc11c \ucd5c\uc885.txt", d[0]), U("f[]", "my file;v2 (1).txt", d[1])],
         None),
        ("file data containing boundary look-alikes", [U("f", "t.bin", tricky),
                                                       F("after", b"ok")], None),
        ("3.5 MB file", [U("f", "big.bin", rnd(3500000, 9))], None),
        ("multi-line and empty field values",
         [F("text", b"line1\r\nline2\r\n\r\nline4"), F("empty", b"")], None),
        ("same plain name twice for files (f, f)",
         [U("f", "1.txt", d[0]), U("f", "2.txt", d[1])],
         "PHP keeps only the last value of a repeated non-array name"),
        ("same plain name twice for fields (a, a)", [F("a", b"1"), F("a", b"2")],
         "PHP keeps only the last value of a repeated non-array name"),
        ("unquoted name parameter",
         [R(b"Content-Disposition: form-data; name=plain", b"v", "field")], None),
        ("header and parameter names in other case",
         [R(b'content-disposition: FORM-DATA; NAME="a"; FILENAME="x.bin"\r\n'
            b"content-type: text/plain", d[3], "file")], None),
        ("no space after semicolons",
         [R(b'Content-Disposition: form-data;name="a";filename="x.bin"', d[3],
            "file")], None),
        ("unknown parameter before name, trailing semicolon",
         [R(b'Content-Disposition: form-data; x=y; name="a";', b"v", "field")],
         None),
        ("Content-Type header before Content-Disposition",
         [R(b"Content-Type: text/plain\r\nContent-Disposition: form-data; "
            b'name="a"; filename="x.txt"', d[3], "file")], None),
    ]
    variants = [("h1", {}, CT, ""),
                ("h1", {"chunked": True, "piece": 4099}, CT, " [chunked]"),
                ("h2", {}, CT, "")]
    for name, parts, note in corpus:
        body, exp = build(parts)
        for backend, path in TARGETS:
            for proto, kw, ctype, suffix in (variants if name.startswith("three")
                                             else variants[:1]):
                c = run_case(env, "compare", name + suffix, proto, P_BLK, backend,
                             path, body, dict(kw, ctype=ctype))
                compare(c, exp, note if backend == "php" else None)
    # quoted boundary and closing delimiter without the final CRLF
    body, exp = build([F("a", b"1"), U("f", "x.bin", d[0])])
    for backend, path in TARGETS:
        c = run_case(env, "compare", "quoted boundary parameter", "h1", P_BLK,
                     backend, path, body,
                     {"ctype": 'multipart/form-data; boundary="%s"' % B.decode()})
        compare(c, exp, None)
        c = run_case(env, "compare", "no CRLF after closing boundary", "h1",
                     P_BLK, backend, path, body[:-2])
        compare(c, exp, None)
    # a real client
    fdir = os.path.join(env.run, "files")
    os.makedirs(fdir, exist_ok=True)
    names = ["a.tar.gz", "b.min.js", "c.txt"]
    fl = []
    for i, n in enumerate(names):
        blob = rnd(120000 + i, 300 + i)
        open(os.path.join(fdir, n), "wb").write(blob)
        fl.append((len(blob), hashlib.sha256(blob).hexdigest()))
    exp = {"files": 3, "fields": 1, "max_file_bytes": max(f[0] for f in fl),
           "file_list": sorted(fl)}
    for backend, path in TARGETS:
        for flag, proto in (("--http1.1", "h1"), ("--http2-prior-knowledge", "h2")):
            tid = "E%03d" % (len(cases) + 1)
            env.mark()
            args = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", flag,
                    "-H", "X-Test-Id: " + tid, "-F", "title=hello"]
            for n in names:
                args += ["-F", "f[]=@" + os.path.join(fdir, n)]
            t0 = time.time()
            p = subprocess.run(args + ["http://127.0.0.1:%d%s" % (P_BLK, path)],
                               capture_output=True, text=True)
            time.sleep(0.35)
            c = {"id": tid, "group": "compare", "name": "curl -F, three files",
                 "proto": proto, "server": "block", "backend": backend,
                 "path": path, "client_status": int(p.stdout or 0),
                 "seconds": round(time.time() - t0, 2), "body_bytes": None,
                 "obs": env.observe(tid), "checks": {}, "ok": True}
            cases.append(c)
            compare(c, exp, None)


def compare(c, exp, known_difference):
    sh = shield_of(c)
    v = backend_view(c)
    c["expected"] = {k: exp[k] for k in ("files", "fields", "max_file_bytes")}
    c["known_difference"] = known_difference
    check(c, "shield approved", sh.get("action") == "pass")
    check(c, "backend processed one request", v is not None
          and c["client_status"] == 200)
    if sh and v:
        same = (sh["files"] == v["files"] and sh["fields"] == v["fields"]
                and sh["max_file_bytes"] == v["max_file_bytes"])
        c["agree"] = same
        check(c, "shield counts equal what was sent",
              (sh["files"], sh["fields"], sh["max_file_bytes"])
              == (exp["files"], exp["fields"], exp["max_file_bytes"]))
        if known_difference is None:
            check(c, "files: shield = backend", sh["files"] == v["files"])
            check(c, "fields: shield = backend", sh["fields"] == v["fields"])
            check(c, "largest file: shield = backend",
                  sh["max_file_bytes"] == v["max_file_bytes"])
            check(c, "file bytes identical (sha256)",
                  files_of(v) == exp["file_list"])
        else:
            # recorded, not judged: the backend's own semantics differ
            c["checks"]["documented difference: " + known_difference] = True
    show(c)


# -------------------- 3. inputs the engine refuses: what the backends make of them

def group_ambiguous(env):
    x = rnd(30000, 400)
    cd = b"Content-Disposition: form-data; "
    raw = lambda parts, **kw: build([("raw", h, d, "field") for h, d in parts],  # noqa: E731
                                    **kw)[0]
    items = [
        ("bare-LF delimiter hiding a second part", "MGUS-102", CT,
         raw([(cd + b'name="f"; filename="x.bin"', x + b"\n--" + B + b"\r\n"
               + cd + b'name="smuggled"\r\n\r\nvalue')])),
        ("filename*= extended parameter only", "MGUS-107", CT,
         raw([(cd + b"name=\"f\"; filename*=UTF-8''x.php", x)])),
        ("backslash before quote in name", "MGUS-107", CT,
         raw([(cd + b'name="a\\"; filename="x.php"', x)])),
        ("two Content-Disposition headers", "MGUS-104", CT,
         raw([(cd + b'name="a"\r\n' + cd + b'name="b"; filename="x.php"', x)])),
        ("folded Content-Disposition header", "MGUS-103", CT,
         raw([(cd[:-1] + b'\r\n name="a"; filename="x.php"', x)])),
        ("LF-only line ends in part headers", "MGUS-103", CT,
         b"--" + B + b"\r\n" + cd + b'name="a"; filename="x.php"\n\n' + x
         + b"\r\n--" + B + b"--\r\n"),
        ("text before the first boundary", "MGUS-101", CT,
         b"preamble\r\n" + raw([(cd + b'name="a"', b"v")])),
        ("data after the closing boundary", "MGUS-106", CT,
         raw([(cd + b'name="a"', b"v")], tail=b"--" + B + b"\r\n" + cd
             + b'name="late"\r\n\r\nv\r\n--' + B + b"--\r\n")),
        ("two boundary parameters in Content-Type", "MGUS-100",
         "multipart/form-data; boundary=zzz; boundary=" + B.decode(),
         raw([(cd + b'name="a"', b"v")])),
        ("'boundary' substring in another parameter", "MGUS-100",
         "multipart/form-data; xboundary=zzz; boundary=" + B.decode(),
         raw([(cd + b'name="a"', b"v")])),
    ]
    for name, rule, ctype, body in items:
        for backend, path in TARGETS:
            c = run_case(env, "ambiguous", name, "h1", P_MON, backend, path, body,
                         {"ctype": ctype})
            check(c, "shield flags " + rule, shield_of(c).get("rule") == rule
                  and shield_of(c).get("action") == "monitor")
            show(c)
            c = run_case(env, "ambiguous", name, "h1", P_BLK, backend, path, body,
                         {"ctype": ctype})
            check(c, "status 400", c["client_status"] == 400)
            check(c, "backend: 0 requests, 0 packets", backend_zero(c))
            show(c)


# ------------------- 4. host-wide policy on paths without an upload feature

def group_vhost(env):
    blob = rnd(150000, 500)
    two_files, exp = build([U("x", "one.bin", blob), U("y", "two.bin", blob[:999])])
    progress_last = build([F("q", b"1"), U("x", "one.bin", blob),
                           F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]
    progress_only = build([F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]
    too_many = build([U("f[]", "n%d" % i, blob[:20000]) for i in range(7)])[0]
    form = b"q=1&PHP_SESSION_UPLOAD_PROGRESS=probe"

    for backend, path in (("php", "/page.php?q=1"), ("tomcat", "/tc/page")):
        c = run_case(env, "vhost", "no-upload path, shield off: multipart with 2 files",
                     "h1", P_OFF, backend, path, two_files)
        v = backend_view(c)
        check(c, "backend handled the request", v is not None)
        if backend == "php" and v:
            # the PHP engine parsed and stored the files although page.php has no upload code
            check(c, "PHP engine parsed 2 files on a page without upload code",
                  v["files"] == 2)
        show(c)

        for proto in ("h1", "h2"):
            c = run_case(env, "vhost", "no-upload path: normal multipart is inspected",
                         proto, P_BLK, backend, path, two_files)
            check(c, "status 200", c["client_status"] == 200)
            check(c, "shield inspected it (pass, files=2)",
                  shield_of(c).get("action") == "pass"
                  and shield_of(c).get("files") == 2)
            check(c, "delivered", backend_view(c) is not None)
            show(c)

        for name, body, rule in (
                ("no-upload path: progress field, last part", progress_last, "MGUS-301"),
                ("no-upload path: progress field only", progress_only, "MGUS-301"),
                ("no-upload path: 7 files (limit 6)", too_many, "MGUS-203")):
            c = run_case(env, "vhost", name, "h1", P_MON, backend, path, body)
            check(c, "delivered", backend_view(c) is not None)
            check(c, "shield monitor log", shield_of(c).get("action") == "monitor"
                  and shield_of(c).get("rule") == rule)
            show(c)
            for proto in ("h1", "h2"):
                c = run_case(env, "vhost", name, proto, P_BLK, backend, path, body)
                check(c, "status 403", c["client_status"] == 403)
                check(c, "backend: 0 requests, 0 packets", backend_zero(c))
                check(c, "shield block log", shield_of(c).get("action") == "block"
                      and shield_of(c).get("rule") == rule)
                show(c)

        c = run_case(env, "vhost", "urlencoded body with the same field name "
                     "(outside the module's scope)", "h1", P_BLK, backend, path,
                     form, {"ctype": "application/x-www-form-urlencoded"})
        check(c, "delivered uninspected", backend_view(c) is not None
              and not c["obs"]["shield"])
        show(c)


# --------------------------------------------- 5. size / timeout contract

def group_contract(env):
    mb = rnd(1024 * 1024, 600)
    b1, _ = build([U("f", "1m.bin", mb)])
    b3, _ = build([U("f[]", "a", mb), U("f[]", "b", mb), U("f[]", "c", mb)])
    b9, _ = build([U("f[]", "%d" % i, mb) for i in range(9)])
    slow, _ = build([U("f", "slow.bin", rnd(300000, 601))])
    lim8 = 8 * 1024 * 1024
    lim2 = 2 * 1024 * 1024

    def nolen(proto):
        return {"chunked": True} if proto == "h1" else {"with_length": False}

    def trickle(proto):       # ~5 s in total
        return {"piece": 30000, "delay": 0.5}

    for proto in ("h1", "h2"):
        def case(name, path, body, kw=None):
            c = run_case(env, "contract", name, proto, P_CON, "php", path, body,
                         kw, settle=0.5)
            c["contract"] = {"location": path}
            return c

        def expect(c, status, backend, action, rule=None, limit=None, src=None,
                   conflict=None, secs=None):
            sh = shield_of(c)
            check(c, "client status in %s" % (status,),
                  c["client_status"] in status)
            if backend == "delivered":
                check(c, "delivered to PHP-FPM", backend_view(c) is not None)
            else:
                check(c, "backend: 0 requests, 0 packets", backend_zero(c))
            if action is None:
                check(c, "no shield log", not c["obs"]["shield"])
            else:
                check(c, "shield action " + action, sh.get("action") == action)
            if rule:
                check(c, "rule " + rule, sh.get("rule") == rule)
            if limit is not None:
                check(c, "effective body limit %d from %s" % (limit, src),
                      sh.get("body_limit") == limit
                      and sh.get("body_limit_src") == src)
            if conflict is not None:
                check(c, "config_conflict=" + conflict,
                      sh.get("config_conflict") == conflict)
            if secs:
                check(c, "ended after %.1f-%.1f s" % secs,
                      secs[0] <= c["seconds"] <= secs[1])
            show(c)

        # ---- whole-request size
        expect(case("size unset: 3 MB", "/c/unset", b3), (200,), "delivered",
               "pass", limit=lim8, src="nginx", conflict="none")
        expect(case("size unset: 9 MB, length declared", "/c/unset", b9),
               (413,), "zero", None)
        expect(case("size unset: 9 MB, no declared length", "/c/unset", b9,
                    nolen(proto)), (413,), "zero", "aborted")
        expect(case("size 2m: 1 MB", "/c/small", b1), (200,), "delivered", "pass",
               limit=lim2, src="shield", conflict="none")
        expect(case("size 2m: 3 MB, length declared", "/c/small", b3), (413,),
               "zero", "block", "MGUS-401", limit=lim2, src="shield")
        expect(case("size 2m: 3 MB, no declared length", "/c/small", b3,
                    nolen(proto)), (413,), "zero", "block", "MGUS-401")
        expect(case("size 2m, MONITOR: 3 MB", "/c/small-m", b3), (200,),
               "delivered", "monitor", "MGUS-401")
        expect(case("size 32m > nginx 8m: 3 MB", "/c/conflict", b3), (200,),
               "delivered", "pass", limit=lim8, src="nginx",
               conflict="body_size,body_timeout")
        expect(case("size 32m > nginx 8m: 9 MB, length declared", "/c/conflict",
                    b9), (413,), "zero", None)

        # ---- body read time
        expect(case("timeout unset: upload trickles for ~5 s", "/c/unset", slow,
                    trickle(proto)), (200,), "delivered", "pass")
        expect(case("timeout unset: client stalls", "/c/unset", slow,
                    {"stall_at": 90000}), (None, 408), "zero", "aborted",
               secs=(7.5, 10.0))
        expect(case("timeout 2s: fast upload", "/c/small", b1), (200,),
               "delivered", "pass")
        expect(case("timeout 2s: upload trickles for ~5 s", "/c/small", slow,
                    trickle(proto)), (None, 408), "zero", "block", "MGUS-402",
               secs=(1.8, 3.2))
        expect(case("timeout 2s: client stalls", "/c/small", slow,
                    {"stall_at": 90000}), (None, 408), "zero", "block",
               "MGUS-402", secs=(1.8, 3.2))
        expect(case("timeout 2s, MONITOR: trickles for ~5 s", "/c/small-m", slow,
                    trickle(proto)), (200,), "delivered", "monitor", "MGUS-402")
        expect(case("timeout 30s > nginx 8s: trickles for ~5 s", "/c/conflict",
                    slow, trickle(proto)), (200,), "delivered", "pass",
               conflict="body_size,body_timeout")
        expect(case("timeout 30s > nginx 8s: client stalls", "/c/conflict", slow,
                    {"stall_at": 90000}), (None, 408), "zero", "aborted",
               conflict="body_size,body_timeout", secs=(7.5, 10.0))


# ------------------------------------------ 7. optional file name policy

def group_filename(env):
    blob = rnd(40000, 800)
    small = blob[:3000]

    def files(names, extra=()):
        return build([F("t", b"x")] + [U("f[]", n, small + n.encode())
                                       for n in names] + list(extra))

    compat = [
        ("ordinary and multi-extension names",
         files(["report.pdf", "archive.tar.gz", "jquery-3.7.1.min.js",
                "c.v1.2.pdf", "\ubcf4\uace0\uc11c \ucd5c\uc885.txt", "php.txt"])),
        ("no extension, dot file, look-alikes, empty file selection",
         files(["README", ".gitignore", "a.phpx", "photo.JPG",
                "my file;v2 (1).txt"], [U("attachment", "", b"")])),
        ("empty file selection only", build([F("t", b"x"), U("f", "", b"")])),
        ("zero-byte file with an ordinary name",
         build([U("f", "empty.tar.gz", b"")])),
    ]
    denied = [
        ("shell.php", "MGUS-311"), ("SHELL.PhP", "MGUS-311"),
        ("shell.php.jpg", "MGUS-311"), ("a.tar.phtml.gz", "MGUS-311"),
        (".htaccess", "MGUS-311"), ("page.jsp", "MGUS-311"),
        ("a.php.", "MGUS-311"), ("../up/a.txt", "MGUS-312"),
        ("a.txt.", "MGUS-312"), ("n" * 252 + ".txt", "MGUS-313"),
    ]

    def label(n):
        return n if len(n) < 40 else "256-byte name"

    for backend, path in TARGETS:
        for name, (body, exp) in compat:
            for proto in ("h1", "h2"):
                c = run_case(env, "filename", "allowed: " + name, proto, P_FN_BLK,
                             backend, path, body)
                v = backend_view(c)
                check(c, "status 200", c["client_status"] == 200)
                check(c, "shield pass", shield_of(c).get("action") == "pass")
                check(c, "backend processed one request", v is not None)
                if v:
                    check(c, "files as sent", v["files"] == exp["files"])
                    check(c, "fields as sent", v["fields"] == exp["fields"])
                    check(c, "file bytes identical (sha256)",
                          files_of(v) == exp["file_list"])
                show(c)

        for fname, rule in denied:
            body = build([F("t", b"x"), U("f[]", "ok.txt", blob),
                          U("f[]", fname, small)])[0]
            c = run_case(env, "filename", "last part named " + label(fname), "h1",
                         P_FN_MON, backend, path, body)
            check(c, "delivered", backend_view(c) is not None
                  and c["client_status"] == 200)
            check(c, "shield monitor log", shield_of(c).get("action") == "monitor"
                  and shield_of(c).get("rule") == rule)
            show(c)
            for proto in (("h1", "h2") if fname == "shell.php.jpg" else ("h1",)):
                c = run_case(env, "filename", "last part named " + label(fname),
                             proto, P_FN_BLK, backend, path, body)
                check(c, "status 403", c["client_status"] == 403)
                check(c, "backend: 0 requests, 0 packets", backend_zero(c))
                check(c, "shield block log", shield_of(c).get("action") == "block"
                      and shield_of(c).get("rule") == rule)
                show(c)

        # default is OFF: the same request on the host without the policy
        body, exp = build([F("t", b"x"), U("f[]", "ok.txt", blob),
                           U("f[]", "shell.php.jpg", small)])
        c = run_case(env, "filename", "policy off (default): last part named "
                     "shell.php.jpg", "h1", P_BLK, backend, path, body)
        v = backend_view(c)
        check(c, "status 200", c["client_status"] == 200)
        check(c, "shield pass", shield_of(c).get("action") == "pass")
        check(c, "delivered with both files", v is not None and v["files"] == 2)
        show(c)

    # operator-defined list replaces the built-in one (PHP-FPM only)
    for fname, status, action, rule in (("drawing.svg", 403, "block", "MGUS-311"),
                                        ("setup.EXE", 403, "block", "MGUS-311"),
                                        ("shell.php", 200, "pass", "none")):
        body = build([U("f", fname, small)])[0]
        c = run_case(env, "filename", "custom list (exe svg): " + fname, "h1",
                     P_FN_BLK, "php", "/custom.php", body)
        check(c, "status %d" % status, c["client_status"] == status)
        check(c, "shield " + action, shield_of(c).get("action") == action
              and shield_of(c).get("rule") == rule)
        if status == 200:
            check(c, "delivered", backend_view(c) is not None)
        else:
            check(c, "backend: 0 requests, 0 packets", backend_zero(c))
        show(c)


# ------------------------------------- 8. HTTP/2 over TLS, stream isolation

def h2_multi(port, streams, tls=True, wait=30):
    """Several uploads on ONE HTTP/2 connection. Each stream is a dict with
    path, body, tid and optionally start (s), piece, delay (s), stall_at.
    Returns (per-stream results, connection_closed_by_server_early)."""
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", port), 5)
    if tls:
        s = tls_h2(s)
    conn = h2.connection.H2Connection(
        h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    s.sendall(conn.data_to_send())
    st = {}
    for i, sp in enumerate(streams):
        st[2 * i + 1] = dict(sp, sent=0, started=False, done=False, status=None,
                             end=None, reset=None, next=sp.get("start", 0.0))
    closed = [False]

    def finish(sid, reset=None):
        x = st.get(sid)
        if x and not x["done"]:
            x["done"] = True
            x["reset"] = reset
            x["end"] = round(time.time() - t0, 2)

    def pump(timeout):
        s.settimeout(timeout)
        try:
            data = s.recv(65536)
        except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
            return
        except OSError:
            closed[0] = True
            return
        if not data:
            closed[0] = True
            return
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                st[ev.stream_id]["status"] = int(dict(ev.headers)[":status"])
            elif isinstance(ev, h2.events.StreamEnded):
                finish(ev.stream_id)
            elif isinstance(ev, h2.events.StreamReset):
                finish(ev.stream_id, ev.error_code)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                closed[0] = True
        out = conn.data_to_send()
        if out:
            s.sendall(out)

    try:
        while time.time() - t0 < wait and not closed[0] \
                and not all(x["done"] for x in st.values()):
            now = time.time() - t0
            for sid, x in st.items():
                if x["done"] or now < x["next"]:
                    continue
                if not x["started"]:
                    conn.send_headers(sid, [
                        (":method", "POST"), (":path", x["path"]),
                        (":scheme", "https" if tls else "http"),
                        (":authority", "test"), ("content-type", CT),
                        ("x-test-id", x["tid"]),
                        ("content-length", str(len(x["body"])))])
                    x["started"] = True
                body = x["body"]
                if x.get("stall_at") is not None and x["sent"] >= x["stall_at"]:
                    continue
                if x["sent"] < len(body):
                    n = min(conn.local_flow_control_window(sid),
                            conn.max_outbound_frame_size, x.get("piece", 16384),
                            len(body) - x["sent"])
                    if n > 0:
                        conn.send_data(sid, body[x["sent"]:x["sent"] + n],
                                       end_stream=(x["sent"] + n == len(body)))
                        x["sent"] += n
                        x["next"] = now + x.get("delay", 0.0)
            out = conn.data_to_send()
            if out:
                s.sendall(out)
            pump(0.01)
    except (OSError, h2.exceptions.ProtocolError) as e:
        closed[0] = True
        for x in st.values():
            x.setdefault("error", type(e).__name__)
    for x in st.values():
        if not x["done"]:
            x["end"] = round(time.time() - t0, 2)
    try:
        s.close()
    except OSError:
        pass
    return ([{k: x[k] for k in ("tid", "path", "status", "end", "reset", "done",
                                "sent")} for x in st.values()], closed[0])


def group_tls(env):
    blob = rnd(300000, 900)
    slow_body, slow_exp = build([U("f", "slow.bin", blob)])
    fast_body, fast_exp = build([U("f", "fast.bin", rnd(1024 * 1024, 901))])
    normal, n_exp = build([F("t", b"x"), U("f[]", "a.tar.gz", blob),
                           U("f[]", "b.min.js", blob[:70000])])
    bad = build([F("t", b"x"), U("f", "a.txt", blob),
                 F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]

    # single-stream basics over TLS
    for backend, path in TARGETS:
        c = run_case(env, "tls", "normal multi-file upload", "h2tls", P_TLS_BLK,
                     backend, path, normal)
        v = backend_view(c)
        check(c, "status 200", c["client_status"] == 200)
        check(c, "files as sent, bytes identical", v is not None
              and v["files"] == n_exp["files"]
              and files_of(v) == n_exp["file_list"])
        check(c, "shield pass", shield_of(c).get("action") == "pass")
        show(c)
        c = run_case(env, "tls", "last part: session progress field", "h2tls",
                     P_TLS_BLK, backend, path, bad)
        check(c, "status 403", c["client_status"] == 403)
        check(c, "backend: 0 requests, 0 packets", backend_zero(c))
        check(c, "shield block log", shield_of(c).get("rule") == "MGUS-301")
        show(c)
    c = run_case(env, "tls", "timeout 2s: client stalls", "h2tls", P_TLS_CON, "php",
                 "/c/small", slow_body, {"stall_at": 90000}, settle=0.5)
    check(c, "cut after 1.8-3.2 s", 1.8 <= c["seconds"] <= 3.2)
    check(c, "backend: 0 requests, 0 packets", backend_zero(c))
    check(c, "shield MGUS-402", shield_of(c).get("rule") == "MGUS-402")
    show(c)

    # several streams on one connection
    def scenario(name, tls, port, streams, expect):
        base = len(cases) + 1
        tid0 = "E%03d" % base
        for i, sp in enumerate(streams):
            sp["tid"] = "%s%s" % (tid0, "abcdef"[i])
        env.mark()
        t0 = time.time()
        res, closed = h2_multi(port, streams, tls=tls)
        time.sleep(0.6)
        ob_all = env.observe(tid0)
        c = {"id": tid0, "group": "streams", "name": name,
             "proto": "h2tls" if tls else "h2", "server": LABEL[port],
             "backend": "php", "path": "one connection, %d streams" % len(streams),
             "client_status": None, "seconds": round(time.time() - t0 - 0.6, 2),
             "body_bytes": None, "obs": ob_all, "checks": {}, "ok": True,
             "connection_closed_early": closed, "streams": []}
        cases.append(c)
        for r, sp, ex in zip(res, streams, expect):
            ob = env.observe(r["tid"])
            app = ob["php_app"] + ob["tc_app"]
            row = dict(r, role=sp["role"], backend_requests=len(app),
                       backend_access=len(ob["php_access"]) + len(ob["tc_access"]),
                       files_ok=None)
            if ex["kind"] == "ok":
                good = (r["status"] == 200 and len(app) == 1
                        and files_of(app[0]) == ex["exp"]["file_list"])
                row["files_ok"] = good
                check(c, "%s: 200 and file bytes identical" % sp["role"], good)
            elif ex["kind"] == "cut":
                check(c, "%s: ended after %.1f-%.1f s without a response"
                      % ((sp["role"],) + ex["secs"]),
                      r["status"] is None and r["done"]
                      and ex["secs"][0] <= r["end"] <= ex["secs"][1])
                check(c, "%s: nothing reached the backend" % sp["role"],
                      row["backend_requests"] == 0 and row["backend_access"] == 0)
            else:
                check(c, "%s: status %d, nothing reached the backend"
                      % (sp["role"], ex["status"]),
                      r["status"] == ex["status"] and row["backend_requests"] == 0)
            c["streams"].append(row)
        check(c, "connection stayed open until every stream ended", not closed)
        print("%s %s streams   %-9s %-5s %s" % (
            "PASS" if c["ok"] else "FAIL", c["id"], c["server"], c["proto"], name),
            flush=True)
        for row in c["streams"]:
            print("        %-48s status=%-5s end=%5.2fs reset=%-5s backend=%d %s" % (
                row["role"], row["status"], row["end"], row["reset"],
                row["backend_requests"], row["path"]), flush=True)
        if not c["ok"]:
            print("        failed:", [k for k, x in c["checks"].items() if not x])

    for tls, port in ((True, P_TLS_CON), (False, P_CON)):
        scenario("stalled stream is cut; uploads on other streams continue",
                 tls, port, [
                     {"role": "A stalls on the 2s-timeout location",
                      "path": "/c/small?s=A", "body": slow_body, "stall_at": 90000},
                     {"role": "B trickles ~5 s where no Shield timeout is set",
                      "path": "/c/unset?s=B", "body": slow_body, "piece": 30000,
                      "delay": 0.5},
                     {"role": "C starts at 3 s on the 2s-timeout location",
                      "path": "/c/small?s=C", "body": fast_body, "start": 3.0}],
                 [{"kind": "cut", "secs": (1.8, 3.2)},
                  {"kind": "ok", "exp": slow_exp},
                  {"kind": "ok", "exp": fast_exp}])
        scenario("slow stream is cut; fast and MONITOR streams are unaffected",
                 tls, port, [
                     {"role": "A trickles ~5 s on the 2s-timeout location",
                      "path": "/c/small?s=A", "body": slow_body, "piece": 30000,
                      "delay": 0.5},
                     {"role": "B fast upload on the same location",
                      "path": "/c/small?s=B", "body": fast_body},
                     {"role": "D trickles ~5 s on the MONITOR location",
                      "path": "/c/small-m?s=D", "body": slow_body, "piece": 30000,
                      "delay": 0.5},
                     {"role": "E fast upload at 4 s on the same location",
                      "path": "/c/small?s=E", "body": fast_body, "start": 4.0}],
                 [{"kind": "cut", "secs": (1.8, 3.2)},
                  {"kind": "ok", "exp": fast_exp},
                  {"kind": "ok", "exp": slow_exp},
                  {"kind": "ok", "exp": fast_exp}])
    for tls, port in ((True, P_TLS_BLK), (False, P_BLK)):
        scenario("rejected stream does not disturb a slow upload beside it",
                 tls, port, [
                     {"role": "A last-part policy violation (403)",
                      "path": "/upload.php?s=A", "body": bad},
                     {"role": "B trickles ~3 s to PHP-FPM",
                      "path": "/upload.php?s=B", "body": slow_body, "piece": 30000,
                      "delay": 0.3},
                     {"role": "C trickles ~3 s to Tomcat",
                      "path": "/tc/upload?s=C", "body": slow_body, "piece": 30000,
                      "delay": 0.3}],
                 [{"kind": "status", "status": 403},
                  {"kind": "ok", "exp": slow_exp},
                  {"kind": "ok", "exp": slow_exp}])


# ------------------------------------- 6. concurrent uploads, repeated rounds

def group_load(env, rounds, seconds, conc):
    blobs = [rnd(n, 700 + i) for i, n in enumerate((300000, 1200000, 2500000))]
    normal = [build([F("t", b"x"), U("f[]", "a.bin", b), U("f[]", "b.bin", b[:70000])])[0]
              for b in blobs]
    bad = build([F("t", b"x"), U("f", "a.bin", blobs[0])], close=False)[0]
    bad2 = build([U("f", "a.bin", blobs[1]),
                  F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]
    samples = []
    stop = threading.Event()

    def sampler():
        t0 = time.time()
        while not stop.is_set():
            s = env.snapshot()
            s["t"] = round(time.time() - t0, 1)
            samples.append(s)
            time.sleep(1.0)

    threading.Thread(target=sampler, daemon=True).start()
    out = []
    for rno in range(1, rounds + 1):
        counts = {}
        unexpected = []
        lock = threading.Lock()
        end = time.time() + seconds
        t_first = len(samples)

        def client(seed):
            r = random.Random(seed)
            while time.time() < end:
                backend, path = TARGETS[r.randrange(2)]
                x = r.random()
                try:
                    if x < 0.60:
                        st, _ = h1(P_BLK, path, r.choice(normal), "load", wait=60)
                        want = (200,)
                    elif x < 0.70:
                        st, _ = h2c(P_BLK, path, r.choice(normal), "load", wait=60)
                        want = (200,)
                    elif x < 0.80:
                        st, _ = h1(P_BLK, path, bad, "load")
                        want = (400,)
                    elif x < 0.88:
                        st, _ = h1(P_BLK, path, bad2, "load")
                        want = (403,)
                    elif x < 0.96:
                        st, _ = h1(P_BLK, path, r.choice(normal), "load",
                                   abort_at=r.randrange(1000, 250000))
                        want = (None,)
                    else:
                        st, _ = h1(P_BLK, path, normal[0], "load", piece=30000,
                                   delay=0.1)
                        want = (200,)
                except OSError as e:
                    st, want = "client-error:" + type(e).__name__, ()
                with lock:
                    counts[str(st)] = counts.get(str(st), 0) + 1
                    if st not in want:
                        unexpected.append(str(st))

        threads = [threading.Thread(target=client, args=(rno * 1000 + i,))
                   for i in range(conc)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        busy = samples[t_first:] or [env.snapshot()]
        time.sleep(3)
        idle = env.snapshot()
        row = {"round": rno, "seconds": seconds, "concurrency": conc,
               "requests": sum(counts.values()), "status_counts": counts,
               "unexpected": len(unexpected),
               "rss_kb_peak": max(s["rss_kb"] for s in busy),
               "fds_peak": max(s["fds"] for s in busy),
               "temp_open_peak": max(s["temp_open"] for s in busy),
               "temp_open_mb_peak": max(s["temp_open_mb"] for s in busy),
               "idle": idle}
        out.append(row)
        print("LOAD round %d: %d requests %s unexpected=%d | peak rss=%d kB "
              "fds=%d temp=%d (%s MB) | idle rss=%d kB fds=%d temp_open=%d "
              "temp_dir=%d php_tmp=%d" % (
                  rno, row["requests"], json.dumps(counts, sort_keys=True),
                  row["unexpected"], row["rss_kb_peak"], row["fds_peak"],
                  row["temp_open_peak"], row["temp_open_mb_peak"],
                  idle["rss_kb"], idle["fds"], idle["temp_open"],
                  idle["temp_dir_entries"], idle["php_upload_tmp"]), flush=True)
    stop.set()
    return {"rounds": out, "samples": samples,
            "worker_pids": env.workers()}


def main():
    nginx, module, out = sys.argv[1:4]

    def opt(name, default):
        return int(sys.argv[sys.argv.index(name) + 1]) if name in sys.argv \
            else default

    env = Env(nginx, module, out)
    env.start()
    meta = {"versions": env.versions(), "workers_at_start": env.workers(),
            "idle_at_start": env.snapshot(), "tomcat_stats_start": env.tomcat_stats()}
    print(json.dumps(meta["versions"], indent=1), flush=True)
    load = None
    try:
        group_function(env)
        group_differential(env)
        group_ambiguous(env)
        group_vhost(env)
        group_contract(env)
        group_filename(env)
        group_tls(env)
        time.sleep(1)
        meta["idle_after_functional"] = env.snapshot()
        meta["workers_after_functional"] = env.workers()
        if opt("--rounds", 0):
            load = group_load(env, opt("--rounds", 0), opt("--round-seconds", 30),
                              opt("--concurrency", 24))
        meta["tomcat_stats_end"] = env.tomcat_stats()
        meta["workers_at_end"] = env.workers()
    finally:
        env.stop()

    err = open(env.logs["shield"], errors="replace").read()
    meta["nginx_alerts"] = len(re.findall(r"\[(alert|emerg|crit)\]", err))
    meta["worker_exits_on_signal"] = len(re.findall(r"exited on signal", err))
    passed = sum(1 for c in cases if c["ok"])
    summary = {"total": len(cases), "passed": passed,
               "failed": len(cases) - passed}
    print("SUMMARY", json.dumps(summary), json.dumps(
        {k: v for k, v in meta.items() if k != "versions"}))
    json.dump({"summary": summary, "meta": meta, "cases": cases, "load": load},
              open(os.path.join(out, "results.json"), "w"), indent=1)
    for src, dst in (("nginx-error.log", "nginx-error.log"),
                     ("nginx-access.log", "nginx-access.log"),
                     ("nginx.conf", "nginx.conf"), ("php-fpm.conf", "php-fpm.conf"),
                     ("php-fpm-access.log", "php-fpm-access.log"),
                     ("php-fpm-error.log", "php-fpm-error.log"),
                     ("php-app.jsonl", "php-app.jsonl"),
                     ("tomcat-app.jsonl", "tomcat-app.jsonl"),
                     ("tomcat/logs/access.log", "tomcat-access.log"),
                     ("tomcat/conf/server.xml", "tomcat-server.xml")):
        try:
            shutil.copy(os.path.join(env.run, src), os.path.join(out, dst))
        except OSError:
            pass
    healthy = (meta["nginx_alerts"] == 0 and meta["worker_exits_on_signal"] == 0
               and meta["workers_at_start"] == meta["workers_at_end"])
    return 0 if passed == len(cases) and healthy else 1


if __name__ == "__main__":
    sys.exit(main())
