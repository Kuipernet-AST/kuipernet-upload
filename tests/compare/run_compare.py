#!/usr/bin/env python3
"""Side-by-side behaviour of Kuipernet Upload and ModSecurity with public
PHP2Shell mitigation rules, on the same nginx binary and one PHP-FPM instance.

  A   nginx + upload_shield module                      -> PHP-FPM
  B1  nginx + ModSecurity 3 + rules published by pentestit.com
  B2  nginx + ModSecurity 3 + rules published by Abstract Security

The same request bytes are sent to each configuration. All requests are
harmless: plain filler data and short strings, nothing that triggers a
vulnerability. The test records policy enforcement only.

Usage: run_compare.py NGINX_BINARY SHIELD_SO MODSEC_SO MODSEC_BASE_DIR OUT_DIR
"""
import gzip
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

PHP_ROOT = os.path.normpath(os.path.join(HERE, "..", "e2e", "php"))
P_A, P_B1, P_B2, P_FPM = 18301, 18311, 18312, 19100
CONFIGS = [("A", P_A), ("B1", P_B1), ("B2", P_B2)]
FIELD = "PHP_SESSION_UPLOAD_PROGRESS"
MB = 1024 * 1024


def filler(n, tag):
    """Compressible, recognisable test data of exactly n bytes."""
    line = ("%s Upload policy comparison filler content line\n" % tag).encode()
    return (line * (n // len(line) + 1))[:n]


PENTESTIT = r'''# Source: https://pentestit.com/php-cve-2026-109618-and-cve-2026-109619-what-we-know-about-php2shell/
# (article header: last updated Nov 14, 2026; retrieved 2026-11-20)
# Rule 1026109618 is reproduced as published.
SecRule ARGS_POST_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026109618,phase:2,deny,status:403,log,t:none,msg:'PHP session upload progress field (interim, PHP CVE-2026-109618/109619)'"

# Rule 1026109620 as published, except for the route allow-list: the article's
# example (^/wp-admin/(?:async-upload|media-new)\.php$) is replaced by this
# test site's only upload route, as the article instructs ("build yours").
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^\s*multipart/form-data" \
    "id:1026109620,phase:1,deny,status:415,log,t:none,msg:'multipart upload to a route that does not take uploads',chain"
    SecRule REQUEST_FILENAME "!@rx ^/upload\.php$" "t:none,t:normalizePath"
'''

ABSTRACT = r'''# Source: https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
# (published October 21, 2026; updated October 22, 2026; rules rev:2 ver:20261021;
#  retrieved 2026-11-20). Rule bodies reproduced as published; the long
#  explanatory comments of the original are omitted.
# ONE ADAPTATION: the published text has  ver:20261021  (ModSecurity 2 syntax).
# libmodsecurity 3.0.12 refuses to load that ("Expecting an action, got:
# ver:20261021"), so the value is quoted here: ver:'20261021'. Nothing else
# is changed.
SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:3201001,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'php2shell: session ID in multipart form field (session fixation)',\
    tag:'attack-rce',\
    tag:'attack-php',\
    tag:'php2shell',\
    severity:'CRITICAL',\
    rev:2,\
    ver:'20261021',\
    chain"
    SecRule ARGS_POST_NAMES "@streq PHPSESSID"

SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:3201002,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'php2shell: PHP open tag in multipart filename',\
    tag:'attack-rce',\
    tag:'attack-php',\
    tag:'php2shell',\
    severity:'CRITICAL',\
    rev:2,\
    ver:'20261021',\
    chain"
    SecRule MULTIPART_PART_HEADERS "@rx (?i)(?:^|\r\n)Content-Disposition\s*:[^\r\n]{0,500}?filename[ \t]*=[ \t]*[\x22\x27]?[^\r\n]{0,2000}?<\?(?:php\b|=)"

SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:3201003,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'php2shell: serialized-object syntax in multipart filename',\
    tag:'attack-rce',\
    tag:'attack-php',\
    tag:'php2shell',\
    severity:'CRITICAL',\
    rev:2,\
    ver:'20261021',\
    chain"
    SecRule MULTIPART_PART_HEADERS "@rx (?i)(?:^|\r\n)Content-Disposition\s*:[^\r\n]{0,500}?filename[ \t]*=[ \t]*[\x22\x27]?[^\r\n]{0,2000}?(?:[oO]\s*:\s*\d{1,10}\s*:\s*[\x22\x27]|[aA]\s*:\s*\d{1,10}\s*:\s*\{|[sS]\s*:\s*\d{1,10}\s*:\s*[\x22\x27]|[rR]\s*:\s*\d{1,10}\s*;|\|\s*[oO]\s*:\s*\d{1,10})"

SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:3201004,\
    phase:2,\
    pass,\
    log,\
    msg:'php2shell correlate: PHP_SESSION_UPLOAD_PROGRESS form field present',\
    tag:'php2shell',\
    severity:'INFO',\
    rev:2,\
    ver:'20261021',\
    chain"
    SecRule ARGS_POST_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS"
'''


class Env:
    def __init__(self, nginx, shield_so, modsec_so, modsec_base, out):
        self.nginx, self.out = nginx, out
        self.run = os.path.join(out, "run")
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(os.path.join(self.run, "php-upload-tmp"))
        os.makedirs(os.path.join(out, "requests"))
        os.makedirs(os.path.join(out, "config"))
        cfg = os.path.join(out, "config")

        # ---- ModSecurity: recommended base with the engine on and the same
        #      whole-body limit as configuration A (2 MB)
        base = open(os.path.join(modsec_base, "modsecurity.conf-recommended")).read()
        shutil.copy(os.path.join(modsec_base, "unicode.mapping"), cfg)
        edits = [
            ("SecRuleEngine DetectionOnly", "SecRuleEngine On"),
            ("SecRequestBodyLimit 13107200", "SecRequestBodyLimit %d" % (2 * MB)),
            ("SecAuditLog /var/log/modsec_audit.log",
             "SecAuditLog %s/modsec_audit.log" % self.run),
            ("SecResponseBodyAccess On", "SecResponseBodyAccess Off"),
            ("SecTmpDir /tmp/", "SecTmpDir %s/" % self.run),
            ("SecDataDir /tmp/", "SecDataDir %s/" % self.run),
        ]
        for a, b in edits:
            assert base.count(a) == 1, a
            base = base.replace(a, b)
        open(os.path.join(cfg, "modsecurity-base.conf"), "w").write(base)
        self.base_edits = edits
        open(os.path.join(cfg, "php2shell-pentestit.conf"), "w").write(PENTESTIT)
        open(os.path.join(cfg, "php2shell-abstract.conf"), "w").write(ABSTRACT)
        for name, rules in (("b1", "php2shell-pentestit.conf"),
                            ("b2", "php2shell-abstract.conf")):
            open(os.path.join(cfg, "modsec-%s.conf" % name), "w").write(
                "Include %s/modsecurity-base.conf\nInclude %s/%s\n" % (cfg, cfg, rules))

        common = """user root;
worker_processes 1;
error_log %(run)s/nginx-%(name)s-error.log info;
pid %(run)s/nginx-%(name)s.pid;
events { worker_connections 256; }
http {
    access_log %(run)s/nginx-%(name)s-access.log;
    client_body_temp_path %(run)s/client_body_temp_%(name)s;
    fastcgi_temp_path     %(run)s/fastcgi_temp_%(name)s;
    client_max_body_size  8m;
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
""" % P_FPM
        a = ("load_module %s;\n" % shield_so) + common % {"run": self.run, "name": "a"} + """
    # ---- A: Kuipernet Upload ----
    server {
        listen 127.0.0.1:%d;
        http2 on;
        root %s;

        upload_shield                        block;
        upload_shield_deny_session_progress  on;
        upload_shield_max_file_size          1m;
        upload_shield_max_body_size          2m;

        # a path of this site that does not take uploads
        location = /page.php {
            upload_shield_deny_multipart on;
            fastcgi_pass 127.0.0.1:%d;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;
        }
%s    }
}
""" % (P_A, PHP_ROOT, P_FPM, php)
        b = ("load_module %s;\n" % modsec_so) + common % {"run": self.run, "name": "b"}
        for name, port in (("b1", P_B1), ("b2", P_B2)):
            b += """
    # ---- %s: ModSecurity + public PHP2Shell rules ----
    server {
        listen 127.0.0.1:%d;
        http2 on;
        root %s;
        modsecurity on;
        modsecurity_rules_file %s/modsec-%s.conf;
%s    }
""" % (name.upper(), port, PHP_ROOT, cfg, name, php)
        b += "}\n"
        open(os.path.join(cfg, "nginx-a.conf"), "w").write(a)
        open(os.path.join(cfg, "nginx-b.conf"), "w").write(b)
        open(os.path.join(cfg, "php-fpm.conf"), "w").write("""[global]
pid = %(run)s/php-fpm.pid
error_log = %(run)s/php-fpm-error.log
daemonize = yes

[www]
user = root
group = root
listen = 127.0.0.1:%(port)d
pm = static
pm.max_children = 4
access.log = %(run)s/php-fpm-access.log
access.format = "%%{%%s}T %%m %%r %%s len=%%l tid=%%{HTTP_X_TEST_ID}e"
env[MGUS_LOG] = %(run)s/php-app.jsonl
php_admin_value[upload_tmp_dir] = %(run)s/php-upload-tmp
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 128M
""" % {"run": self.run, "port": P_FPM})
        self.cfg = cfg
        self.logs = {"a": self.run + "/nginx-a-error.log",
                     "b": self.run + "/nginx-b-error.log",
                     "php_access": self.run + "/php-fpm-access.log",
                     "php_app": self.run + "/php-app.jsonl"}
        self.off = {}
        self.pk = 0

    def start(self):
        test = ""
        for n in ("a", "b"):
            p = subprocess.run([self.nginx, "-t", "-c", "%s/nginx-%s.conf" % (self.cfg, n)],
                               capture_output=True, text=True)
            test += p.stderr
            if p.returncode:
                print(p.stderr)
                raise SystemExit("nginx -t failed for " + n)
        open(os.path.join(self.out, "nginx-config-test.txt"), "w").write(test)
        subprocess.run([e.PHP_FPM, "-y", self.cfg + "/php-fpm.conf", "-R"], check=True,
                       capture_output=True)
        for n in ("a", "b"):
            subprocess.run([self.nginx, "-c", "%s/nginx-%s.conf" % (self.cfg, n)],
                           check=True)
        for port in (P_FPM, P_A, P_B1, P_B2):
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
        for cmd in (["-N", "MGCMP"], ["-I", "INPUT", "-j", "MGCMP"],
                    ["-A", "MGCMP", "-p", "tcp", "--dport", str(P_FPM)]):
            subprocess.run(["iptables"] + cmd, check=True)
        for v in self.logs.values():
            open(v, "a").close()
        time.sleep(0.5)

    def stop(self):
        for cmd in (["-D", "INPUT", "-j", "MGCMP"], ["-F", "MGCMP"], ["-X", "MGCMP"]):
            subprocess.run(["iptables"] + cmd, capture_output=True)
        for n in ("a", "b"):
            subprocess.run([self.nginx, "-c", "%s/nginx-%s.conf" % (self.cfg, n),
                            "-s", "quit"])
        try:
            os.kill(int(open(self.run + "/php-fpm.pid").read()), 15)
        except (OSError, ValueError):
            pass
        time.sleep(1)

    def packets(self):
        p = subprocess.run(["iptables", "-L", "MGCMP", "-v", "-n", "-x"],
                           capture_output=True, text=True).stdout
        m = re.search(r"^\s*(\d+)\s+\d+\s.*dpt:%d" % P_FPM, p, re.M)
        return int(m.group(1)) if m else 0

    def mark(self):
        self.off = {k: os.path.getsize(v) for k, v in self.logs.items()}
        self.pk = self.packets()

    def new(self, key):
        with open(self.logs[key], errors="replace") as f:
            f.seek(self.off[key])
            return [x.rstrip("\n") for x in f if x.strip()]

    def versions(self):
        def out(cmd):
            p = subprocess.run(cmd, capture_output=True, text=True)
            return (p.stdout + p.stderr).strip()
        ini = out([e.PHP_FPM, "-c", "/etc/php/8.3/fpm/php.ini", "-i"])
        keep = {}
        for k in ("session.upload_progress.enabled", "session.upload_progress.name",
                  "upload_max_filesize", "post_max_size", "max_file_uploads",
                  "memory_limit", "file_uploads"):
            m = re.search(r"^%s => (.*?) => " % re.escape(k), ini, re.M)
            keep[k] = m.group(1) if m else None
        return {
            "nginx": out([self.nginx, "-V"]),
            "php_fpm": out([e.PHP_FPM, "-v"]).splitlines()[0],
            "php_package": out(["dpkg-query", "-W", "-f", "${Version}", "php8.3-fpm"]),
            "php_ini_defaults_before_pool_overrides": keep,
            "libmodsecurity": out(["dpkg-query", "-W", "-f", "${Version}",
                                   "libmodsecurity3t64"]),
            "kernel": os.uname().release,
        }


def requests():
    """(id, kind, expected, name, path, body, client options, file expectation)"""
    f = [filler(180000 + 1000 * i, "file%d" % i) for i in range(3)]
    out = []

    def add(rid, kind, expected, name, path, parts, opts=None, raw=None, ctype=None):
        if raw is None:
            body, exp = e.build(parts)
        else:
            body, exp = raw, None
        out.append({"id": rid, "kind": kind, "expected": expected, "name": name,
                    "path": path, "body": body, "opts": opts or {}, "exp": exp,
                    "ctype": ctype or e.CT})

    # ---- normal uploads: expected to be delivered unchanged
    add("N01", "normal", "allow", "multi-file upload (3 files under f[], 2 fields)",
        "/upload.php", [e.F("title", b"quarterly report"), e.U("f[]", "a.bin", f[0]),
                        e.U("f[]", "b.bin", f[1]), e.U("f[]", "c.bin", f[2]),
                        e.F("note", b"")])
    add("N02", "normal", "allow", "empty file selection beside a real file",
        "/upload.php", [e.F("title", b"x"), e.U("doc", "report.pdf", f[0]),
                        e.U("attachment", "", b"")])
    add("N03", "normal", "allow", "empty file selection only", "/upload.php",
        [e.F("title", b"x"), e.U("attachment", "", b"")])
    add("N04", "normal", "allow", "multi-extension file names", "/upload.php",
        [e.U("f[]", "archive.tar.gz", f[0]), e.U("f[]", "jquery-3.7.1.min.js", f[1]),
         e.U("f[]", "c.v1.2.pdf", f[2])])
    add("N05", "normal", "allow",
        "forbidden field name appears as an ordinary form VALUE", "/upload.php",
        [e.F("note", FIELD.encode()), e.F("comment", b"see " + FIELD.encode()
                                         + b" in the PHP manual"),
         e.U("f", "a.bin", f[0])])
    add("N06", "normal", "allow",
        "forbidden field name appears inside FILE CONTENT", "/upload.php",
        [e.U("f", "notes.txt", b"How upload progress works:\r\n<input type=\"hidden\" "
             b"name=\"" + FIELD.encode() + b"\" value=\"123\">\r\n"
             b"Content-Disposition: form-data; name=\"" + FIELD.encode() + b"\"\r\n"
             + f[0][:20000]), e.F("title", b"x")])
    add("N07", "normal", "allow",
        "field whose name merely contains the forbidden name", "/upload.php",
        [e.F("X_" + FIELD + "_NOTE", b"1"), e.U("f", "a.bin", f[0])])
    add("N08", "normal", "allow", "upload without Content-Length (chunked), 0.5 MB",
        "/upload.php", [e.U("f[]", "a.bin", f[0]), e.U("f[]", "b.bin", f[1]),
                        e.F("t", b"x")], {"nolen": True})
    add("N09", "normal", "allow", "1.9 MB upload, each file under 1 MB", "/upload.php",
        [e.U("f[]", "a.bin", filler(950000, "big-a")),
         e.U("f[]", "b.bin", filler(950000, "big-b"))])
    add("N10", "normal", "allow", "multi-file upload over HTTP/2", "/upload.php",
        [e.F("title", b"h2"), e.U("f[]", "a.bin", f[0]), e.U("f[]", "b.bin", f[1])],
        {"proto": "h2"})
    add("N11", "normal", "allow",
        "ordinary urlencoded form to the no-upload path", "/page.php?q=1", None,
        raw=b"q=1&name=test&note=hello+world",
        ctype="application/x-www-form-urlencoded")
    add("N12", "normal", "allow",
        "urlencoded form with a 200 kB text value (no files)", "/page.php?q=1", None,
        raw=b"q=1&text=" + filler(200000, "text").replace(b" ", b"+").replace(b"\n", b"%0A"),
        ctype="application/x-www-form-urlencoded")

    # ---- harmless policy violations: expected to be refused before PHP-FPM
    add("V01", "violation", "deny", "forbidden form field as the last part",
        "/upload.php", [e.F("title", b"x"), e.U("f", "a.bin", f[0]),
                        e.F(FIELD, b"probe")])
    add("V02", "violation", "deny", "forbidden form field only", "/upload.php",
        [e.F(FIELD, b"probe")])
    add("V03", "violation", "deny", "forbidden form field as the last part, HTTP/2",
        "/upload.php", [e.F("title", b"x"), e.U("f", "a.bin", f[0]),
                        e.F(FIELD, b"probe")], {"proto": "h2"})
    add("V04", "violation", "deny",
        "last part: one file over the 1 MB per-file limit (total 1.4 MB)",
        "/upload.php", [e.F("title", b"x"), e.U("f[]", "ok.bin", f[0]),
                        e.U("f[]", "big.bin", filler(MB + 200000, "over"))])
    add("V05", "violation", "deny", "multipart upload to the no-upload path",
        "/page.php?q=1", [e.F("q", b"1"), e.U("f", "a.bin", f[0])])
    add("V06", "violation", "deny",
        "multipart without files to the no-upload path", "/page.php?q=1",
        [e.F("q", b"1"), e.F("name", b"test")])
    add("V07", "violation", "deny",
        "no Content-Length (chunked): body 2.6 MB over the 2 MB limit", "/upload.php",
        [e.U("f[]", "a.bin", filler(900000, "c1")), e.U("f[]", "b.bin", filler(900000, "c2")),
         e.U("f[]", "c.bin", filler(800000, "c3"))], {"nolen": True})
    add("V08", "violation", "deny",
        "no content-length (HTTP/2): body 2.6 MB over the 2 MB limit", "/upload.php",
        [e.U("f[]", "a.bin", filler(900000, "c1")), e.U("f[]", "b.bin", filler(900000, "c2")),
         e.U("f[]", "c.bin", filler(800000, "c3"))], {"proto": "h2", "nolen": True})
    add("V09", "violation", "deny",
        "Content-Length declared: body 2.6 MB over the 2 MB limit", "/upload.php",
        [e.U("f[]", "a.bin", filler(900000, "c1")), e.U("f[]", "b.bin", filler(900000, "c2")),
         e.U("f[]", "c.bin", filler(800000, "c3"))])
    # ---- for reference only: shapes the published Abstract Security rules
    #      target and configuration A has no policy for (harmless values)
    add("X01", "reference", "n/a", "form field named PHPSESSID with a harmless value",
        "/upload.php", [e.F("PHPSESSID", b"abc123"), e.U("f", "a.bin", f[0])])
    add("X02", "reference", "n/a",
        "file name containing serialized-array-like text", "/upload.php",
        [e.U("f", "notes a:1:{x}.txt", f[0])])
    return out


def main():
    nginx, shield_so, modsec_so, modsec_base, out = sys.argv[1:6]
    env = Env(nginx, shield_so, modsec_so, modsec_base, out)
    reqs = requests()

    manifest = []
    for r in reqs:
        fn = "%s.body.gz" % r["id"]
        with gzip.open(os.path.join(out, "requests", fn), "wb") as g:
            g.write(r["body"])
        manifest.append({
            "id": r["id"], "kind": r["kind"], "expected": r["expected"],
            "name": r["name"], "method": "POST", "path": r["path"],
            "content_type": r["ctype"], "body_file": fn,
            "body_bytes": len(r["body"]),
            "body_sha256": hashlib.sha256(r["body"]).hexdigest(),
            "protocol": "HTTP/2 (cleartext)" if r["opts"].get("proto") == "h2" else "HTTP/1.1",
            "length_declared": not r["opts"].get("nolen", False)})
    json.dump(manifest, open(os.path.join(out, "requests", "manifest.json"), "w"),
              indent=1)

    env.start()
    meta = {"versions": env.versions(),
            "modsecurity_base_edits": [list(x) for x in env.base_edits],
            "sha256": {}}
    for label, path in (("nginx binary", nginx), ("upload_shield module", shield_so),
                        ("modsecurity connector module", modsec_so),
                        ("modsecurity-base.conf", env.cfg + "/modsecurity-base.conf"),
                        ("php2shell-pentestit.conf", env.cfg + "/php2shell-pentestit.conf"),
                        ("php2shell-abstract.conf", env.cfg + "/php2shell-abstract.conf")):
        meta["sha256"][label] = hashlib.sha256(open(path, "rb").read()).hexdigest()

    rows = []
    try:
        for r in reqs:
            for cname, port in CONFIGS:
                tid = "%s-%s" % (r["id"], cname)
                env.mark()
                o = r["opts"]
                if o.get("proto") == "h2":
                    status, secs = e.h2c(port, r["path"], r["body"], tid,
                                         ctype=r["ctype"],
                                         with_length=not o.get("nolen", False))
                else:
                    status, secs = e.h1(port, r["path"], r["body"], tid,
                                        ctype=r["ctype"],
                                        chunked=o.get("nolen", False), piece=32768)
                time.sleep(0.4)
                key = "a" if cname == "A" else "b"
                raw = env.new(key)
                rule, raw_keep = [], []
                for line in raw:
                    m = re.search(r"upload_shield: (\{.*?\})", line)
                    if m:
                        j = json.loads(m.group(1))
                        if j["rule"] != "none":
                            rule.append("%s %s (%s)" % (j["rule"], j["rule_name"],
                                                        j["action"]))
                        raw_keep.append(line)
                    if "ModSecurity:" in line:
                        ids = re.findall(r'\[id "(\d+)"\]', line)
                        act = "deny" if "Access denied" in line else "log"
                        for i in ids:
                            rule.append("%s (%s)" % (i, act))
                        if not ids:
                            rule.append("ModSecurity intervention without rule id (%s)"
                                        % act)
                        raw_keep.append(line)
                    elif "Request body limit is marked to reject" in line:
                        rule.append("SecRequestBodyLimit + SecRequestBodyLimitAction "
                                    "Reject (engine setting, no rule id)")
                        raw_keep.append(line)
                    elif "client intended to send too large" in line:
                        rule.append("nginx client_max_body_size")
                        raw_keep.append(line)
                acc = [x for x in env.new("php_access") if x.endswith("tid=" + tid)]
                app = [json.loads(x) for x in env.new("php_app")
                       if json.loads(x)["test_id"] == tid]
                pk = env.packets() - env.pk
                reached = bool(acc or app or pk)
                sha = None
                if r["exp"] is not None and len(app) == 1:
                    sha = e.files_of(app[0]) == r["exp"]["file_list"] \
                        and app[0]["fields"] == r["exp"]["fields"]
                actual = "allow" if (status == 200 and reached) else "deny"
                row = {"id": r["id"], "config": cname, "kind": r["kind"],
                       "name": r["name"], "expected": r["expected"],
                       "status": status, "actual": actual,
                       "as_expected": (actual == r["expected"]
                                       if r["expected"] != "n/a" else None),
                       "rules": rule, "php_fpm_reached": reached,
                       "php_access_lines": len(acc), "php_app_records": len(app),
                       "php_port_packets": pk, "sha256_match": sha,
                       "php_view": ({"files": app[0]["files"], "fields": app[0]["fields"]}
                                    if len(app) == 1 else None),
                       "raw_log": raw_keep}
                rows.append(row)
                print("%s %-7s %-3s exp=%-5s got=%-5s st=%-4s php=%-5s sha=%-5s %s | %s" % (
                    {True: "ok  ", False: "DIFF", None: "info"}[row["as_expected"]], tid, cname, r["expected"],
                    actual, status, reached, sha, "; ".join(rule)[:70], r["name"][:50]),
                    flush=True)
    finally:
        env.stop()

    json.dump({"meta": meta, "rows": rows}, open(os.path.join(out, "results.json"), "w"),
              indent=1)
    for n in ("nginx-a-error.log", "nginx-b-error.log", "nginx-a-access.log",
              "nginx-b-access.log", "php-fpm-access.log", "php-fpm-error.log",
              "php-app.jsonl", "modsec_audit.log"):
        try:
            shutil.copy(os.path.join(env.run, n), out)
        except OSError:
            pass
    shutil.rmtree(env.run, ignore_errors=True)


if __name__ == "__main__":
    main()
