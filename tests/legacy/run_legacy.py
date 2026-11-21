#!/usr/bin/env python3
"""Legacy configuration check: the distribution's own nginx package and
PHP-FPM package inside a chroot of that distribution, with the module built
there against the matching nginx source.

Usage: run_legacy.py CHROOT_DIR PHP_VERSION OUT_DIR [MODULE_BUILD_DESCRIPTION]
       (the chroot already has nginx, phpX.Y-fpm and
        /usr/lib/nginx/modules/ngx_http_upload_shield_module.so)

The module is loaded by /usr/sbin/nginx of the package, PHP-FPM is reached
over a unix socket (the distribution's default connection type) and both run
as www-data. Backend-side evidence: PHP-FPM's access log and the PHP scripts'
record. All requests are harmless.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))
import run_e2e as e  # noqa: E402

P_MON, P_BLK, P_H2 = 18401, 18402, 18403
MB = 1024 * 1024
rows = []


def main():
    chroot, phpv, out = sys.argv[1:4]
    T = "/mgus-test"
    base = chroot + T
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(base + "/run/php-upload-tmp")
    os.makedirs(out)
    shutil.copytree(os.path.join(HERE, "..", "e2e", "php"), base + "/php")

    def ch(cmd, check=True):
        p = subprocess.run(["chroot", chroot, "sh", "-c", cmd], capture_output=True,
                           text=True)
        if check and p.returncode:
            raise SystemExit("failed: %s\n%s" % (cmd, p.stderr))
        return (p.stdout + p.stderr).strip()

    fcgi = """fastcgi_pass unix:%s/run/php-fpm.sock;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;""" % T
    script = "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;"
    upload = "fastcgi_param SCRIPT_FILENAME $document_root/upload.php;"
    policy = """
        upload_shield                        %s;
        upload_shield_deny_session_progress  on;
        upload_shield_max_file_size          1m;
        upload_shield_max_files              4;
        upload_shield_filename_check         on;
"""
    conf = """# legacy check: distribution nginx package + module built for it
load_module /usr/lib/nginx/modules/ngx_http_upload_shield_module.so;
user www-data;
worker_processes 1;
error_log %(t)s/run/nginx-error.log info;
pid %(t)s/run/nginx.pid;
events { worker_connections 256; }
http {
    access_log %(t)s/run/nginx-access.log;
    client_body_temp_path %(t)s/run/client_body_temp;
    fastcgi_temp_path     %(t)s/run/fastcgi_temp;
    client_max_body_size  8m;
    client_body_timeout   8s;

    server {
        listen 127.0.0.1:%(mon)d;
        root %(t)s/php;
%(pm)s
        location ~ \\.php$ { %(script)s %(fcgi)s }
    }
    server {
        listen 127.0.0.1:%(blk)d;
        listen 127.0.0.1:%(h2)d http2;       # nginx 1.18: cleartext HTTP/2 needs its own port
        root %(t)s/php;
%(pb)s
        location ~ \\.php$     { %(script)s %(fcgi)s }
        location = /page.php  { upload_shield_deny_multipart on; %(script)s %(fcgi)s }
        location = /small.php { upload_shield_max_body_size 2m; upload_shield_body_timeout 2s; %(upload)s %(fcgi)s }
        location = /nobuf.php { fastcgi_request_buffering off; %(upload)s %(fcgi)s }
    }
}
""" % {"t": T, "mon": P_MON, "blk": P_BLK, "h2": P_H2, "pm": policy % "monitor",
       "pb": policy % "block", "script": script, "upload": upload, "fcgi": fcgi}
    open(base + "/nginx.conf", "w").write(conf)
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
pm.max_children = 4
access.log = %(t)s/run/php-fpm-access.log
access.format = "%%{%%s}T %%m %%r %%s len=%%l tid=%%{HTTP_X_TEST_ID}e"
env[MGUS_LOG] = %(t)s/run/php-app.jsonl
php_admin_value[upload_tmp_dir] = %(t)s/run/php-upload-tmp
""" % {"t": T})
    ch("chown -R www-data:www-data %s/run" % T)

    meta = {
        "os": ch(". /etc/os-release; echo $PRETTY_NAME"),
        "nginx_package": ch("dpkg-query -W -f '${Package} ${Version}' nginx-core"),
        "nginx_V": ch("nginx -V"),
        "php_package": ch("dpkg-query -W -f '${Package} ${Version}' php%s-fpm" % phpv),
        "php_version": ch("php-fpm%s -v | head -1" % phpv),
        "php_changelog_mentions_CVE_2026_109618": int(ch(
            "zcat /usr/share/doc/php%s-fpm/changelog.Debian.gz | grep -c CVE-2026-109618"
            % phpv, check=False) or 0),
        "php_ini": ch("php-fpm%s -i | grep -E '^(upload_max_filesize|post_max_size|"
                      "session.upload_progress.enabled|max_file_uploads) '" % phpv),
        "gcc": ch("gcc --version | head -1"),
        "module_build": sys.argv[4] if len(sys.argv) > 4 else
        "nginx 1.18.0 source (GitHub tag release-1.18.0): ./auto/configure "
        "--with-compat --with-http_v2_module --add-dynamic-module=...; make modules",
        "module_sha256": hashlib.sha256(open(
            chroot + "/usr/lib/nginx/modules/ngx_http_upload_shield_module.so",
            "rb").read()).hexdigest(),
        "connection": "fastcgi_pass over a unix socket, nginx and PHP-FPM as www-data",
        "nginx_config_test": ch("nginx -t -c %s/nginx.conf" % T, check=False),
    }
    print(meta["os"], "|", meta["nginx_package"], "|", meta["php_package"])
    print(meta["nginx_config_test"])
    if "successful" not in meta["nginx_config_test"]:
        json.dump({"meta": meta, "rows": []}, open(out + "/results.json", "w"), indent=1)
        return 2

    ch("php-fpm%s -y %s/php-fpm.conf" % (phpv, T))
    meta["nginx_start_output"] = ch("nginx -c %s/nginx.conf" % T)
    time.sleep(0.5)
    master = int(open(base + "/run/nginx.pid").read())
    procs = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                stat = open("/proc/%s/stat" % pid).read()
                if int(pid) == master or int(stat.rsplit(")", 1)[1].split()[1]) == master:
                    procs.append("%s %s exe=%s" % (
                        pid, open("/proc/%s/cmdline" % pid).read().replace("\0", " ").strip(),
                        os.readlink("/proc/%s/exe" % pid)))
            except OSError:
                pass
    meta["nginx_processes_after_start"] = procs
    maps = open("/proc/%d/maps" % master).read()
    meta["module_mapped_in_master"] = "ngx_http_upload_shield_module.so" in maps
    print("started:", procs, "module mapped:", meta["module_mapped_in_master"])
    for port in (P_MON, P_BLK, P_H2):
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
    logs = {"shield": base + "/run/nginx-error.log",
            "php_access": base + "/run/php-fpm-access.log",
            "php_app": base + "/run/php-app.jsonl"}
    for v in logs.values():
        open(v, "a").close()
    ch("chown www-data:www-data %s/run/php-app.jsonl" % T)
    time.sleep(0.5)

    def case(name, port, path, body, status, backend, action, rule=None, exp=None,
             proto="h1", **kw):
        tid = "L%02d" % (len(rows) + 1)
        off = {k: os.path.getsize(v) for k, v in logs.items()}
        t0 = time.time()
        if proto == "h2":
            st, _ = e.h2c(P_H2, path, body, tid, **kw)
        else:
            st, _ = e.h1(port, path, body, tid, **kw)
        secs = round(time.time() - t0, 2)
        time.sleep(0.4)

        def new(k):
            with open(logs[k], errors="replace") as f:
                f.seek(off[k])
                return [x.rstrip("\n") for x in f if x.strip()]
        sh = [json.loads(m.group(1)) for m in
              (re.search(r"upload_shield: (\{.*?\})", x) for x in new("shield")) if m]
        acc = [x for x in new("php_access") if x.endswith("tid=" + tid)]
        app = [json.loads(x) for x in new("php_app") if json.loads(x)["test_id"] == tid]
        s = sh[0] if len(sh) == 1 else {}
        ok = st in (status if isinstance(status, tuple) else (status,))
        sha = None
        if backend == "delivered":
            ok = ok and len(app) == 1 and len(acc) == 1
            if exp and app:
                sha = (e.files_of(app[0]) == exp["file_list"]
                       and app[0]["fields"] == exp["fields"])
                ok = ok and sha
        else:
            ok = ok and not app and not acc
        if action is None:
            ok = ok and not sh
        else:
            ok = ok and s.get("action") == action and (rule is None or s.get("rule") == rule)
        rows.append({"id": tid, "name": name, "proto": proto, "path": path,
                     "mode": "monitor" if port == P_MON else "block",
                     "status": st, "seconds": secs, "shield_action": s.get("action"),
                     "shield_rule": s.get("rule"), "php_access_lines": len(acc),
                     "php_app_records": len(app), "sha256_match": sha,
                     "php_view": ({"files": app[0]["files"], "fields": app[0]["fields"]}
                                  if app else None), "ok": ok})
        print("%s %s %-58s st=%-4s shield=%s/%s php=%d/%d sha=%s" % (
            "PASS" if ok else "FAIL", tid, (proto + " " + name)[:58], st, s.get("action"),
            s.get("rule"), len(acc), len(app), sha), flush=True)

    d = [e.rnd(300000 + 1000 * i, 100 + i) for i in range(3)]
    normal, n_exp = e.build([e.F("title", b"quarterly report"),
                             e.U("f[]", "archive.tar.gz", d[0]),
                             e.U("f[]", "jquery-3.7.1.min.js", d[1]),
                             e.U("f[]", "c.v1.2.pdf", d[2]), e.F("note", b"")])
    empty, e_exp = e.build([e.F("t", b"x"), e.U("doc", "report.pdf", d[0][:5000]),
                            e.U("attachment", "", b"")])
    small, s_exp = e.build([e.F("a", b"1"), e.U("f", "x.txt", b"hello\r\n")])
    progress = e.build([e.F("t", b"x"), e.U("f", "a.txt", d[0]),
                        e.F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]
    big_last = e.build([e.F("t", b"x"), e.U("f[]", "ok.bin", d[0]),
                        e.U("f[]", "big.bin", e.rnd(MB + 1, 9))])[0]
    five = e.build([e.U("f[]", "n%d.bin" % i, d[0][:30000]) for i in range(5)])[0]
    trunc = e.build([e.F("t", b"x"), e.U("f", "a.txt", d[0])], close=False)[0]
    badname = e.build([e.U("f[]", "ok.txt", d[0]), e.U("f[]", "shell.php.jpg", d[1][:5000])])[0]
    over2m = e.build([e.U("f[]", "a.bin", e.rnd(900000, 1)), e.U("f[]", "b.bin", e.rnd(900000, 2)),
                      e.U("f[]", "c.bin", e.rnd(800000, 3))])[0]
    slow = e.build([e.U("f", "slow.bin", d[0])])[0]

    try:
        # normal uploads
        for port, mode in ((P_MON, "monitor"), (P_BLK, "block")):
            case("normal multi-file upload, multi-extension names (%s)" % mode, port,
                 "/upload.php", normal, 200, "delivered", "pass", exp=n_exp)
        case("normal upload, chunked request", P_BLK, "/upload.php", normal, 200,
             "delivered", "pass", exp=n_exp, chunked=True, piece=7919)
        case("normal upload sent in 1-byte writes", P_BLK, "/upload.php", small, 200,
             "delivered", "pass", exp=s_exp, piece=1)
        case("empty file selection beside a real file", P_BLK, "/upload.php", empty, 200,
             "delivered", "pass", exp=e_exp)
        case("normal multi-file upload", P_BLK, "/upload.php", normal, 200, "delivered",
             "pass", exp=n_exp, proto="h2")
        case("urlencoded form to the no-upload path (not inspected)", P_BLK,
             "/page.php?q=1", b"q=1&name=test", 200, "delivered", None,
             ctype="application/x-www-form-urlencoded")

        # the same violations: delivered in MONITOR, refused in BLOCK
        for name, body, st, rule in (
                ("last part: session progress field", progress, 403, "MGUS-301"),
                ("last part: file over the 1 MB limit", big_last, 413, "MGUS-202"),
                ("last part: 5th file (limit 4)", five, 403, "MGUS-203"),
                ("end of body: closing boundary missing", trunc, 400, "MGUS-105"),
                ("last part named shell.php.jpg (file name policy)", badname, 403,
                 "MGUS-311")):
            case(name, P_MON, "/upload.php", body, 200, "delivered", "monitor", rule)
            case(name, P_BLK, "/upload.php", body, st, "none", "block", rule)
        case("last part: session progress field", P_BLK, "/upload.php", progress, 403,
             "none", "block", "MGUS-301", proto="h2")
        case("last part: session progress field, chunked", P_BLK, "/upload.php", progress,
             403, "none", "block", "MGUS-301", chunked=True, piece=30011)
        case("multipart to the no-upload path", P_BLK, "/page.php?q=1", small, 403, "none",
             "block", "MGUS-302")

        # whole-request size and whole-body timeout set in the Shield
        case("shield body limit 2m: 0.9 MB upload", P_BLK, "/small.php", normal, 200,
             "delivered", "pass", exp=n_exp)
        case("shield body limit 2m: 2.6 MB, length declared", P_BLK, "/small.php", over2m,
             413, "none", "block", "MGUS-401")
        case("shield body limit 2m: 2.6 MB, chunked", P_BLK, "/small.php", over2m, 413,
             "none", "block", "MGUS-401", chunked=True)
        case("shield body limit 2m: 2.6 MB, no content-length", P_BLK, "/small.php", over2m,
             413, "none", "block", "MGUS-401", proto="h2", with_length=False)
        case("shield timeout 2s: client stalls", P_BLK, "/small.php", slow, (None, 408),
             "none", "block", "MGUS-402", stall_at=90000)
        case("shield timeout 2s: client stalls", P_BLK, "/small.php", slow, (None, 408),
             "none", "block", "MGUS-402", proto="h2", stall_at=90000)
        case("shield timeout 2s: upload trickles ~5 s", P_BLK, "/small.php", slow,
             (None, 408), "none", "block", "MGUS-402", piece=30000, delay=0.5)

        # request buffering off: BLOCK refuses multipart requests
        case("buffering off, BLOCK: normal upload refused", P_BLK, "/nobuf.php", normal,
             500, "none", "block", "MGUS-901")
        # not part of the 28 cases: the HTTP/2 timeout path repeated on one
        # worker, mixed with normal HTTP/2 uploads (added after a worker crash
        # was found on this path with a module built from unpatched headers)
        def worker_pids():
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
        before = worker_pids()
        cut = okn = 0
        for i in range(20):
            st, secs = e.h2c(P_H2, "/small.php", slow, "rep", stall_at=90000)
            cut += (st is None and 1.8 <= secs <= 3.2)
            if i % 2 == 0:
                st, _ = e.h2c(P_H2, "/upload.php", normal, "rep")
                okn += (st == 200)
        meta["h2_timeout_repeat"] = {"timeouts_sent": 20, "cut_at_about_2s": cut,
                                     "normal_h2_uploads_sent": 10, "normal_200": okn,
                                     "worker_pids_before": before,
                                     "worker_pids_after": worker_pids()}
        print("H2 timeout repeat:", json.dumps(meta["h2_timeout_repeat"]))
        time.sleep(1)
        meta["temp_files_after"] = sum(len(f) for _, _, f in os.walk(
            base + "/run/client_body_temp"))
        meta["php_upload_tmp_after"] = len(os.listdir(base + "/run/php-upload-tmp"))
    finally:
        ch("nginx -c %s/nginx.conf -s quit" % T, check=False)
        ch("kill $(cat %s/run/php-fpm.pid)" % T, check=False)
        time.sleep(1)

    err = open(logs["shield"], errors="replace").read()
    meta["nginx_alerts"] = len(re.findall(r"\[(alert|emerg|crit)\]", err))
    meta["worker_exits_on_signal"] = len(re.findall(r"exited on signal", err))
    rep_ = meta.get("h2_timeout_repeat", {})
    meta["healthy"] = (meta["nginx_alerts"] == 0 and meta["worker_exits_on_signal"] == 0
                       and rep_.get("worker_pids_before") == rep_.get("worker_pids_after")
                       and rep_.get("cut_at_about_2s") == 20 and rep_.get("normal_200") == 10)
    passed = sum(1 for r in rows if r["ok"])
    summary = {"total": len(rows), "passed": passed, "failed": len(rows) - passed,
               "healthy": meta["healthy"]}
    print("SUMMARY", json.dumps(summary), meta["nginx_alerts"],
          meta["worker_exits_on_signal"], meta["temp_files_after"])
    json.dump({"summary": summary, "meta": meta, "rows": rows},
              open(out + "/results.json", "w"), indent=1)
    for n in ("nginx-error.log", "nginx-access.log", "php-fpm-access.log",
              "php-fpm-error.log", "php-app.jsonl"):
        try:
            shutil.copy(base + "/run/" + n, out)
        except OSError:
            pass
    shutil.copy(base + "/nginx.conf", out)
    shutil.copy(base + "/php-fpm.conf", out)
    return 0 if passed == len(rows) and meta["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())
