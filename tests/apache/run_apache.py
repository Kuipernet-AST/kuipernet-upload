#!/usr/bin/env python3
"""Apache 2.4 connector check with the distribution's apache2 package.

  instance 1 (event MPM):   mod_upload_shield -> mod_proxy_fcgi -> PHP-FPM (TCP)
  instance 2 (prefork MPM): mod_upload_shield -> mod_php (in process)

Backend-side evidence for PHP-FPM: its access log, the PHP scripts' record and
the kernel packet counter on the PHP-FPM port. For mod_php: the scripts' record.
All requests are harmless.

Usage: run_apache.py MOD_UPLOAD_SHIELD_SO OUT_DIR [--load SECONDS]
                     [--asan-preload /path/to/libasan.so]
With --asan-preload the module is an AddressSanitizer build: only the
mod_proxy_fcgi instance is started (with LD_PRELOAD) and the mod_php cases are
skipped, because PHP's extensions cannot be loaded under the sanitizer runtime.
"""
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

P_OFF, P_MON, P_BLK, P_PHP_MON, P_PHP_BLK, P_FPM = 18500, 18501, 18502, 18503, 18504, 19200
MB = 1024 * 1024
rows = []

POLICY = """
    UploadShield                     %s
    UploadShieldDenySessionProgress  On
    UploadShieldMaxFileSize          1m
    UploadShieldMaxFiles             4
    UploadShieldFilenameCheck        On
"""

COMMON = """ServerRoot /usr/lib/apache2
ServerName localhost
PidFile %(run)s/%(name)s.pid
ErrorLog %(run)s/%(name)s-error.log
LogLevel info
User www-data
Group www-data
LoadModule %(mpm)s
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule mime_module modules/mod_mime.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule env_module modules/mod_env.so
%(extra)s
LoadModule upload_shield_module %(so)s
TypesConfig /etc/mime.types
LogFormat "%%h %%t \\"%%r\\" %%>s tid=%%{X-Test-Id}i" tid
CustomLog %(run)s/%(name)s-access.log tid
DocumentRoot %(root)s
<Directory %(root)s>
    Require all granted
</Directory>
"""


def main():
    so, out = sys.argv[1:3]
    load_s = int(sys.argv[sys.argv.index("--load") + 1]) if "--load" in sys.argv else 0
    asan = sys.argv[sys.argv.index("--asan-preload") + 1] \
        if "--asan-preload" in sys.argv else None
    instances = ("apache-fcgi",) if asan else ("apache-fcgi", "apache-modphp")
    ap_env = dict(os.environ, LD_PRELOAD=asan,
                  ASAN_OPTIONS="detect_leaks=0:log_path=/tmp/mgus-ap-asan") \
        if asan else None
    run = "/tmp/mgus-apache"
    shutil.rmtree(run, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(run + "/php-upload-tmp")
    os.makedirs(out)
    root = run + "/php"
    shutil.copytree(os.path.join(HERE, "..", "e2e", "php"), root)
    os.chmod(run, 0o755)
    os.chmod(run + "/php-upload-tmp", 0o777)
    open(run + "/php-app.jsonl", "a").close()
    os.chmod(run + "/php-app.jsonl", 0o666)

    fcgi = ('<FilesMatch "\\.php$">\n        SetHandler "proxy:fcgi://127.0.0.1:%d"\n'
            "    </FilesMatch>" % P_FPM)
    conf1 = COMMON % {
        "run": run, "name": "apache-fcgi", "so": so, "root": root,
        "mpm": "mpm_event_module modules/mod_mpm_event.so",
        "extra": "LoadModule proxy_module modules/mod_proxy.so\n"
                 "LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so"} + """
Listen 127.0.0.1:%d
Listen 127.0.0.1:%d
Listen 127.0.0.1:%d
# baseline without the module's policy
<VirtualHost 127.0.0.1:%d>
    %s
</VirtualHost>
<VirtualHost 127.0.0.1:%d>
%s    %s
</VirtualHost>
<VirtualHost 127.0.0.1:%d>
%s    %s
    # a path of this host that does not take uploads
    <Location "/page.php">
        UploadShieldDenyMultipart On
    </Location>
</VirtualHost>
""" % (P_OFF, P_MON, P_BLK, P_OFF, fcgi, P_MON, POLICY % "monitor", fcgi, P_BLK,
       POLICY % "block", fcgi)
    php = ('<FilesMatch "\\.php$">\n        SetHandler application/x-httpd-php\n'
           "    </FilesMatch>")
    conf2 = COMMON % {
        "run": run, "name": "apache-modphp", "so": so, "root": root,
        "mpm": "mpm_prefork_module modules/mod_mpm_prefork.so",
        "extra": "LoadModule php_module modules/libphp8.3.so"} + """
SetEnv MGUS_LOG %s/php-app.jsonl
php_admin_value upload_tmp_dir %s/php-upload-tmp
php_admin_value upload_max_filesize 64M
php_admin_value post_max_size 128M
Listen 127.0.0.1:%d
Listen 127.0.0.1:%d
<VirtualHost 127.0.0.1:%d>
%s    %s
</VirtualHost>
<VirtualHost 127.0.0.1:%d>
%s    %s
</VirtualHost>
""" % (run, run, P_PHP_MON, P_PHP_BLK, P_PHP_MON, POLICY % "monitor", php,
       P_PHP_BLK, POLICY % "block", php)
    open(run + "/apache-fcgi.conf", "w").write(conf1)
    open(run + "/apache-modphp.conf", "w").write(conf2)
    open(run + "/php-fpm.conf", "w").write("""[global]
pid = %(run)s/php-fpm.pid
error_log = %(run)s/php-fpm-error.log
daemonize = yes
[www]
user = root
group = root
listen = 127.0.0.1:%(port)d
pm = static
pm.max_children = 8
access.log = %(run)s/php-fpm-access.log
access.format = "%%{%%s}T %%m %%r %%s len=%%l tid=%%{HTTP_X_TEST_ID}e"
env[MGUS_LOG] = %(run)s/php-app.jsonl
php_admin_value[upload_tmp_dir] = %(run)s/php-upload-tmp
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 128M
""" % {"run": run, "port": P_FPM})

    def sh(cmd):
        p = subprocess.run(cmd, capture_output=True, text=True)
        return (p.stdout + p.stderr).strip()

    meta = {"apache": sh(["apache2", "-v"]).splitlines()[0],
            "apache_package": sh(["dpkg-query", "-W", "-f", "${Version}", "apache2"]),
            "php_fpm": sh([e.PHP_FPM, "-v"]).splitlines()[0],
            "php_package": sh(["dpkg-query", "-W", "-f", "${Version}", "php8.3-fpm"]),
            "mod_php_package": sh(["dpkg-query", "-W", "-f", "${Version}",
                                   "libapache2-mod-php8.3"]),
            "os": sh(["sh", "-c", ". /etc/os-release; echo $PRETTY_NAME"]),
            "config_test": {}}
    for n in instances:
        meta["config_test"][n] = subprocess.run(
            ["apache2", "-t", "-f", "%s/%s.conf" % (run, n)], capture_output=True,
            text=True, env=ap_env).stderr.strip()
        print(n, meta["config_test"][n])
        if "Syntax OK" not in meta["config_test"][n]:
            return 2
    subprocess.run([e.PHP_FPM, "-y", run + "/php-fpm.conf", "-R"], check=True,
                   capture_output=True)
    for n in instances:
        subprocess.run(["apache2", "-f", "%s/%s.conf" % (run, n), "-k", "start"],
                       check=True, capture_output=True, env=ap_env)
    for port in (P_FPM, P_OFF, P_MON, P_BLK) + (() if asan else (P_PHP_MON, P_PHP_BLK)):
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
    for cmd in (["-N", "MGAP"], ["-I", "INPUT", "-j", "MGAP"],
                ["-A", "MGAP", "-p", "tcp", "--dport", str(P_FPM)]):
        subprocess.run(["iptables"] + cmd, check=True)
    logs = {"fcgi": run + "/apache-fcgi-error.log",
            "modphp": run + "/apache-modphp-error.log",
            "php_access": run + "/php-fpm-access.log", "php_app": run + "/php-app.jsonl"}
    for v in logs.values():
        open(v, "a").close()
    time.sleep(0.5)

    def packets():
        p = sh(["iptables", "-L", "MGAP", "-v", "-n", "-x"])
        m = re.search(r"^\s*(\d+)\s+\d+\s.*dpt:%d" % P_FPM, p, re.M)
        return int(m.group(1)) if m else 0

    def case(name, port, path, body, status, backend, action, rule=None, exp=None,
             **kw):
        tid = "A%02d" % (len(rows) + 1)
        inst = "fcgi" if port in (P_OFF, P_MON, P_BLK) else "modphp"
        off = {k: os.path.getsize(v) for k, v in logs.items()}
        pk0 = packets()
        st, secs = e.h1(port, path, body, tid, **kw)
        time.sleep(0.4)

        def new(k):
            with open(logs[k], errors="replace") as f:
                f.seek(off[k])
                return [x.rstrip("\n") for x in f if x.strip()]
        raw = [x for x in new(inst) if "upload_shield:" in x]
        shl = [json.loads(re.search(r"upload_shield: (\{.*\})", x).group(1)) for x in raw]
        acc = [x for x in new("php_access") if x.endswith("tid=" + tid)]
        app = [json.loads(x) for x in new("php_app") if json.loads(x)["test_id"] == tid]
        pk = packets() - pk0
        s = shl[0] if len(shl) == 1 else {}
        ok = st in (status if isinstance(status, tuple) else (status,))
        sha = None
        if backend == "delivered":
            ok = ok and len(app) == 1
            if exp and app:
                sha = (e.files_of(app[0]) == exp["file_list"]
                       and app[0]["fields"] == exp["fields"])
                ok = ok and sha
        else:
            ok = ok and not app and not acc and pk == 0
        if action is None:
            ok = ok and not shl
        else:
            acts = action if isinstance(action, tuple) else (action,)
            ok = ok and s.get("action") in acts and (rule is None or s.get("rule") == rule)
        rows.append({"id": tid, "name": name, "handler": "mod_proxy_fcgi" if inst == "fcgi"
                     else "mod_php", "mode": "off" if port == P_OFF else
                     "monitor" if port in (P_MON, P_PHP_MON) else "block", "path": path, "status": st, "seconds": round(secs, 2),
                     "shield_action": s.get("action"), "shield_rule": s.get("rule"),
                     "guarantee": s.get("guarantee"), "php_fpm_access_lines": len(acc),
                     "php_app_records": len(app), "php_fpm_port_packets": pk,
                     "sha256_match": sha, "ok": ok, "raw_log": raw,
                     "php_view": ({"files": app[0]["files"], "fields": app[0]["fields"],
                                   "content_length": app[0]["content_length"]}
                                  if app else None)})
        print("%s %s %-14s %-7s %-52s st=%-4s shield=%s/%s php=%d/%d/%d sha=%s" % (
            "PASS" if ok else "FAIL", tid, rows[-1]["handler"], rows[-1]["mode"],
            name[:52], st, s.get("action"), s.get("rule"), len(acc), len(app), pk, sha),
            flush=True)

    d = [e.rnd(300000 + 1000 * i, 100 + i) for i in range(3)]
    normal, n_exp = e.build([e.F("title", b"quarterly report"),
                             e.U("f[]", "archive.tar.gz", d[0]),
                             e.U("f[]", "jquery-3.7.1.min.js", d[1]),
                             e.U("f[]", "c.v1.2.pdf", d[2]), e.F("note", b"")])
    large, l_exp = e.build([e.U("f[]", "a.bin", e.rnd(990000, 21)),
                            e.U("f[]", "b.bin", e.rnd(990000, 22)),
                            e.U("f[]", "c.bin", e.rnd(990000, 23)),
                            e.U("f[]", "d.bin", e.rnd(990000, 24))])
    empty, e_exp = e.build([e.F("t", b"x"), e.U("doc", "report.pdf", d[0][:5000]),
                            e.U("attachment", "", b"")])
    small, s_exp = e.build([e.F("a", b"1"), e.U("f", "x.txt", b"hello\r\n")])
    viol = [
        ("last part: session progress field", e.build(
            [e.F("t", b"x"), e.U("f", "a.txt", d[0]),
             e.F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0], 403, "MGUS-301"),
        ("last part: file over the 1 MB limit", e.build(
            [e.F("t", b"x"), e.U("f[]", "ok.bin", d[0]),
             e.U("f[]", "big.bin", e.rnd(MB + 1, 9))])[0], 413, "MGUS-202"),
        ("last part: 5th file (limit 4)", e.build(
            [e.U("f[]", "n%d.bin" % i, d[0][:30000]) for i in range(5)])[0], 403,
         "MGUS-203"),
        ("end of body: closing boundary missing", e.build(
            [e.F("t", b"x"), e.U("f", "a.txt", d[0])], close=False)[0], 400, "MGUS-105"),
        ("last part named shell.php.jpg (file name policy)", e.build(
            [e.U("f[]", "ok.txt", d[0]), e.U("f[]", "shell.php.jpg", d[1][:5000])])[0],
         403, "MGUS-311"),
        ("bare-LF delimiter hiding a second part", e.build(
            [("raw", b'Content-Disposition: form-data; name="f"; filename="x.bin"',
              d[0][:70000] + b"\n--" + e.B + b"\r\nContent-Disposition: form-data; "
              b'name="smuggled"\r\n\r\nv', "file")])[0], 400, "MGUS-102"),
    ]
    load = None
    try:
        # ---------------- mod_proxy_fcgi -> PHP-FPM
        # Apache's own behaviour without the module's policy. For a chunked
        # request mod_proxy_fcgi forwards no CONTENT_LENGTH unless proxy-sendcl
        # is set, and PHP-FPM then ignores the body; this is recorded, not judged.
        case("baseline: normal multi-file upload", P_OFF, "/upload.php", normal, 200,
             "delivered", None, exp=n_exp)
        case("baseline: chunked upload (httpd/PHP-FPM behaviour, recorded only)", P_OFF,
             "/upload.php", normal, 200, "delivered", None, chunked=True, piece=7919)
        base_view = rows[-1]["php_view"]
        case("normal multi-file upload, multi-extension names", P_MON, "/upload.php",
             normal, 200, "delivered", "pass", exp=n_exp)
        # the backend may answer before the unread body ends: either log is fine
        case("chunked upload: MONITOR leaves httpd's behaviour unchanged", P_MON,
             "/upload.php", normal, 200, "delivered", ("pass", "aborted"), chunked=True,
             piece=7919)
        rows[-1]["same_as_baseline"] = rows[-1]["php_view"] == base_view
        rows[-1]["ok"] = rows[-1]["ok"] and rows[-1]["same_as_baseline"]
        print("     MONITOR chunked: PHP saw %s, baseline %s" % (rows[-1]["php_view"],
                                                              base_view))
        case("normal 4 MB upload", P_MON, "/upload.php", large, 200, "delivered", "pass",
             exp=l_exp)
        case("normal multi-file upload, multi-extension names", P_BLK, "/upload.php",
             normal, 200, "delivered", "pass", exp=n_exp)
        case("chunked upload: BLOCK spools it, PHP-FPM gets a length", P_BLK,
             "/upload.php", normal, 200, "delivered", "pass", exp=n_exp, chunked=True,
             piece=7919)
        case("normal 4 MB upload", P_BLK, "/upload.php", large, 200, "delivered", "pass",
             exp=l_exp)
        case("normal upload sent in 1-byte writes", P_BLK, "/upload.php", small, 200,
             "delivered", "pass", exp=s_exp, piece=1)
        case("empty file selection beside a real file", P_BLK, "/upload.php", empty, 200,
             "delivered", "pass", exp=e_exp)
        case("urlencoded form to the no-upload path (not inspected)", P_BLK,
             "/page.php?q=1", b"q=1&name=test", 200, "delivered", None,
             ctype="application/x-www-form-urlencoded")
        for name, body, st, rule in viol:
            case(name, P_MON, "/upload.php", body, 200, "delivered", "monitor", rule)
            case(name, P_BLK, "/upload.php", body, st, "none", "block", rule)
        case("last part: session progress field, chunked", P_BLK, "/upload.php",
             viol[0][1], 403, "none", "block", "MGUS-301", chunked=True, piece=30011)
        case("last part: file over the 1 MB limit, chunked", P_BLK, "/upload.php",
             viol[1][1], 413, "none", "block", "MGUS-202", chunked=True, piece=30011)
        case("multipart to the no-upload path", P_BLK, "/page.php?q=1", small, 403,
             "none", "block", "MGUS-302")
        case("client aborts mid-upload", P_BLK, "/upload.php", normal, None, "none",
             "aborted", abort_at=len(normal) // 2)

        # ---------------- mod_php (in process)
        if asan:
            raise StopIteration
        case("normal multi-file upload", P_PHP_MON, "/upload.php", normal, 200,
             "delivered", "pass", exp=n_exp)
        case("last part: session progress field", P_PHP_MON, "/upload.php", viol[0][1],
             200, "delivered", "monitor", "MGUS-301")
        case("BLOCK: normal multipart upload is refused", P_PHP_BLK, "/upload.php",
             normal, 500, "none", "block", "MGUS-901")
        case("BLOCK: violating multipart upload is refused", P_PHP_BLK, "/upload.php",
             viol[0][1], 500, "none", "block", "MGUS-901")
        case("BLOCK: urlencoded form (not inspected)", P_PHP_BLK, "/page.php?q=1",
             b"q=1&name=test", 200, "delivered", None,
             ctype="application/x-www-form-urlencoded")

    except StopIteration:
        pass
    try:
        if load_s:
            end = time.time() + load_s
            counts, bad, lock = {}, [], threading.Lock()

            def client(seed):
                r = random.Random(seed)
                while time.time() < end:
                    x = r.random()
                    if x < 0.6:
                        st, _ = e.h1(P_BLK, "/upload.php", normal, "load")
                        want = 200
                    elif x < 0.8:
                        st, _ = e.h1(P_BLK, "/upload.php", viol[0][1], "load")
                        want = 403
                    elif x < 0.9:
                        st, _ = e.h1(P_BLK, "/upload.php", viol[3][1], "load")
                        want = 400
                    else:
                        st, _ = e.h1(P_BLK, "/upload.php", normal, "load",
                                     abort_at=r.randrange(1000, 200000))
                        want = None
                    with lock:
                        counts[str(st)] = counts.get(str(st), 0) + 1
                        if st != want:
                            bad.append(str(st))
            ts = [threading.Thread(target=client, args=(i,)) for i in range(8)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            time.sleep(2)
            load = {"seconds": load_s, "concurrency": 8, "outcomes": counts,
                    "unexpected": len(bad)}
            print("LOAD", json.dumps(load))
        time.sleep(1)
        meta["proxy_spool_files_left_in_tmp"] = len(
            [f for f in os.listdir("/tmp") if f.startswith("modproxy.tmp.")])
        meta["php_upload_tmp_left"] = len(os.listdir(run + "/php-upload-tmp"))
    finally:
        for cmd in (["-D", "INPUT", "-j", "MGAP"], ["-F", "MGAP"], ["-X", "MGAP"]):
            subprocess.run(["iptables"] + cmd, capture_output=True)
        for n in instances:
            subprocess.run(["apache2", "-f", "%s/%s.conf" % (run, n), "-k", "stop"],
                           capture_output=True, env=ap_env)
        try:
            os.kill(int(open(run + "/php-fpm.pid").read()), 15)
        except (OSError, ValueError):
            pass
        time.sleep(2)

    meta["asan_build"] = bool(asan)
    for n in ("apache-fcgi", "apache-modphp"):
        if n not in instances:
            meta[n + "_child_crashes"] = None
            continue
        err = open("%s/%s-error.log" % (run, n), errors="replace").read()
        meta[n + "_child_crashes"] = len(re.findall(
            r"exit signal|Segmentation|AH00052|AH00051", err))
    passed = sum(1 for r in rows if r["ok"])
    summary = {"total": len(rows), "passed": passed, "failed": len(rows) - passed}
    print("SUMMARY", json.dumps(summary), json.dumps(
        {k: v for k, v in meta.items() if k != "config_test"})[:400])
    json.dump({"summary": summary, "meta": meta, "rows": rows, "load": load},
              open(out + "/results.json", "w"), indent=1)
    for n in os.listdir(run):
        if n.endswith((".log", ".conf", ".jsonl")):
            shutil.copy(os.path.join(run, n), out)
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
