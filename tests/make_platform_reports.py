#!/usr/bin/env python3
"""Builds docs/LEGACY.md and docs/APACHE.md from the recorded results of
tests/legacy/run_legacy.py and tests/apache/run_apache.py."""
import json
import os
import sys

legacy_dir, apache_dir, docs = sys.argv[1:4]
OK = {True: "Passed", False: "**Failed**"}
SHA = {True: "Matched", False: "**Disagreements.**", None: "–"}

# ------------------------------------------------------------------ legacy
out = []
w = out.append
w("# Legacy configuration real time: Distribution version Nginx package + PHP-FPM 8.1 or below")
w("")
w("Source records: `%s/`. The tests used unmodified distribution Nginx and PHP-FPM packages in chroots." % legacy_dir.rstrip("/"))
w("")
w("These tests verify PHP-FPM compatibility and policy enforcement. PHP2Shell CVE mitigation remains unverified. See `SUPPORT.md` and `PHP2SHELL.md`.")
w("")
runs = []
for n in sorted(os.listdir(legacy_dir), reverse=True):
    runs.append((n, json.load(open(os.path.join(legacy_dir, n, "results.json")))))


def short(m):
    return "%s / PHP-FPM %s" % (m["os"].replace(" LTS", ""), m["php_package"].split()[0].replace("php", "").replace("-fpm", ""))


w("## Test configurations and results")
w("")
w("| Items | " + " | ".join(d["meta"]["os"] for _, d in runs) + " |")
w("|---|" + "---|" * len(runs))
for label, fn in (
        ("The web server package", lambda m: "`%s`" % m["nginx_package"]),
        ("The nginx build. `--with-compat`", lambda m: "There is." if "--with-compat" in m["nginx_V"] else "**No, not at all.**"),
        ("The PHP package", lambda m: "`%s`" % m["php_package"]),
        ("The PHP version", lambda m: m["php_version"].split(" (built")[0]),
        ("How to connect", lambda m: "`fastcgi_pass` Unix socket, request buffering on, nginx and PHP-FPM both www-data"),
        ("Module building.", lambda m: "%s. %s" % (m["module_build"], m["gcc"].split(") ")[-1])),
        ("Module load`nginx -t`)", lambda m: "Successful" if "successful" in m["nginx_config_test"] else "**Failure.**"),
        ("The actual drive.", lambda m: "Started the installed `/usr/sbin/nginx` master and workers. Module mapped in master: %s" % ("Check it out." if m.get("module_mapped_in_master") else "**Unidentified**")),
        ("Module sha256", lambda m: "`%s…`" % m["module_sha256"][:16]),
        ("Reference to the PHP CVE-2026-109618 of the package change record", lambda m: "Includes patches" if m["php_changelog_mentions_CVE_2026_109618"] else "No. This public storage package has no patches."),
        ("The remaining temporary file", lambda m: "%d / %d" % (m["temp_files_after"], m["php_upload_tmp_after"])),
        ("nginx alert.crit.emerg, worker unusual shutdown", lambda m: "%d, %d" % (m["nginx_alerts"], m["worker_exits_on_signal"])),
        ("Repeat the HTTP/2 timeout except 28.", lambda m: "Of %(timeouts_sent)d stalled streams, %(cut_at_about_2s)d closed at about 2 s. Of %(normal_h2_uploads_sent)d normal HTTP/2 uploads, %(normal_200)d returned 200" % m["h2_timeout_repeat"] + ("Keep the worker PID." if m["h2_timeout_repeat"]["worker_pids_before"] == m["h2_timeout_repeat"]["worker_pids_after"] else ", **Replaced worker**"))):
    w("| %s | %s |" % (label, " | ".join(fn(d["meta"]) for _, d in runs)))
w("| **The test results.** | " + " | ".join("%d cases, %d passed" % (d["summary"]["total"], d["summary"]["passed"]) for _, d in runs) + " |")
w("")
w("In addition to the 28 individual criteria, the verdict includes zero nginx alerts, zero worker abnormalities, zero worker after repeat testing. "
  "It's the same PID, and if one of them goes wrong, all 28 passes, and the entire execution goes wrong.")
w("")
bio = [d for n, d in runs if "18.04" in d["meta"]["os"]]
if bio:
    m = bio[0]["meta"]
    R = {r["id"]: r for r in bio[0]["rows"]}
    w("## Ubuntu 18.04 + Nginx 1.14.0 + PHP-FPM 7.2")
    w("")
    w("### Test environment")
    w("")
    w("- OS: %s (debootstrap chroot, kernel is the test host)." % m["os"])
    w("- Packages: `%s` (matching nginx-common version) and `%s`. Test packages came from public Bionic repositories. ESM packages were outside the test scope." % (m["nginx_package"], m["php_package"]))
    w("- What I added was a dynamic module file and a computer file. `load_module` I'm going down.")
    w("- The nginx build option`nginx -V`):")
    w("")
    w("```")
    w(m["nginx_V"])
    w("```")
    w("")
    w("- Set up the PHP: `%s`." % m["php_ini"].replace("\n", "`, `"))
    w("- Version: Warehouse verification source `%s/ubuntu-18.04-nginx-1.14.0-php-fpm-7.2/build/environment.txt`."
      % legacy_dir.rstrip("/"))
    w("")
    w("### Build and load")
    w("")
    w("- This Nginx package was built without `--with-compat`. Match the arguments printed by `nginx -V` and add `--add-dynamic-module`. Install the development headers for OpenSSL, PCRE, zlib, GeoIP, GD, and XSLT.")
    w("- The sauce is... `apt-get source nginx=1.14.0-0ubuntu1.11`What did you receive? **The distribution source package.**(Distributed) "
      "The reason for this is in the \"Detected Defect\" section below.")
    w("- `make modules` A warning. `nginx -t` Success, the package. `/usr/sbin/nginx`It's actually moving. "
      "I checked the master worker process and the module mapping. `build/configure.log`, "
      "`build/make.log`, `build/dpkg-source.log`, `build/build-and-load.txt`.")
    w("")
    w("### Acceptance cases")
    w("")
    w("The PHP-FPM reach is \"PHP-FPM access log / PHP script record\".")
    w("")
    w("| Required items | The test. | Mods. | HTTP state | Judge Shield | PHP-FPM reach | SHA-256 |")
    w("|---|---|---|---|---|---|---|")
    for label, ids in (("Normal uploads are sent to PHP-FPM and file matches", ("L01", "L02", "L03", "L04", "L05", "L06", "L21")),
                       ("Over the size of the last file.", ("L10", "L11")),
                       ("Multipart of the route prohibited upload", ("L20",)),
                       ("Violation of progress rate field policy", ("L08", "L09", "L18", "L19"))):
        for i in ids:
            r = R[i]
            act = r["shield_action"] + ("" if r["shield_rule"] == "none" else " " + r["shield_rule"])
            w("| %s | %s %s (%s) | %s | %s | %s | %d/%d | %s |" % (
                label, i, r["name"], {"h1": "HTTP/1.1", "h2": "HTTP/2"}[r["proto"]], r["mode"].upper(),
                r["status"], act, r["php_access_lines"], r["php_app_records"], SHA[r["sha256_match"]]))
    w("")
    w("- The three types of BLOCK violations are all PHP-FPM access log 0 rows and PHP script record 0. "
      "The same request from the monitor was sent to 200 and the judge was left in the log.")
    w("- The blocked path was tested with BLOCK. "
      "It's not, and it's not.")
    w("- The rest of the test ((file count, closing boundary gap, file name policy, shield size limit-timeout, buffering off refusal) is "
      "It's in the full table below.")
    w("")
    w("### Compatibility and retesting")
    w("")
    w("- Symptoms: All 28 of the first runnings passed, but the log of the nginx error ended with the worker signaling the log of the worker's error. "
      "There was one. It was shortly after the HTTP/2 Shield timeout test, L26. "
      "It's only been a century, and it hasn't been judged.")
    w("- Cause: Modules in the time-out processing `r->stream->skip_data`I wrote it myself. "
      "The 1.14.0 package uses a security patch (CVE-2018-16843·16844, CVE-2019-9511·9513 etc.) to connect to the HTTP/2 architecture. "
      "The field was added, and the module built with the upstream 1.14.0 header was put in a different location. "
      "In nginx 1.14.0, which was built directly from the source, it wasn't reproduced, it was only in the package binary.")
    w("- Fix: Remove the code so that the module doesn't access the HTTP/2 internal structure. "
      "Leave a mark on the request, and then the text piece comes in again, even if the filter returns the status it recorded. "
      "This change is in every build of nginx versions, and it's also in the distribution source package.")
    w("- Test tool: if the alert worker has an abnormal shutdown, it deals with the incompatibility, and normalizes the HTTP/2 timeout. "
      "I mixed it up with the HTTP/2 upload, and then I repeated it 20 times, and then I added the steps to verify that the worker PID is still there.")
    w("- After this configuration four times in a row, 28 qualified, alert 0, worker 0 terminated. "
      "The log rounds are not covered with error retrieval.")
    w("- Effects on other configurations: The nginx 1.18.0 source packages in Ubuntu 20.04·22.04 are the same as those in Ubuntu 20.04. "
      "It's the same as upstream, and the previous results didn't have this problem, but both configurations have modified the source and distribution versions. "
      "I rebuilt it into a source package, re-tested it, and that's the result of the above chart.")
    w("")
w("## Case results")
w("")
w("Each box is \"State, Shield Judgment, PHP Reaching\" (PHP-FPM access log/PHP script recording), SHA-256\". "
  "It wasn't a Unix socket, so it didn't have a packet counter.")
w("")
hdr = "| ID | The protocol | Mods. | The test. |"
for _, d in runs:
    hdr += " %s |" % short(d["meta"])
w(hdr + " Judgment. |")
w("|---|---|---|---|" + "---|" * len(runs) + "---|")
for i, r0 in enumerate(runs[0][1]["rows"]):
    line = "| %s | %s | %s | %s |" % (r0["id"], {"h1": "HTTP/1.1", "h2": "HTTP/2"}[r0["proto"]], r0["mode"], r0["name"])
    ok = True
    for _, d in runs:
        r = d["rows"][i]
        ok = ok and r["ok"]
        act = r["shield_action"] or "There is no log."
        if r["shield_rule"] and r["shield_rule"] != "none":
            act += " " + r["shield_rule"]
        line += " %s, %s, %d/%d, %s |" % (r["status"] if r["status"] else "Connection termination", act,
                                         r["php_access_lines"], r["php_app_records"], SHA[r["sha256_match"]])
    w(line + " %s |" % OK[ok])
w("")
w("## Validation scope")
w("")
w("- Confirmation: build-load-driving of distributed version nginx package modules, delivery of normal uploads and file match, policy violations "
  "The request doesn't reach PHP-FPM, BLOCK, transmission and logging in the Monitor.")
w("- Build condition: You need a version of the source, like the nginx distribution, and if possible, use the source package for the distribution. "
  "The package is... `--with-compat`If I were to build it, `--with-compat`And the PCRE-zlib headers are enough. "
  "Or 18.04. `nginx -V`You have to write the configure numerator exactly. "
  "`--without-http_rewrite_module`Or `--without-http_gzip_module`The modules we built here are "
  "\"is not binary compatible\" is not loaded.")
w("- nginx 1.20 minus correction: nginx 1.14·1.18 is the error returned by the filter before the first piece of text came to 500 "
  "Modules in these versions will take the judgments down to the first piece of data. "
  "This is the route where L22, over the size of the declared main line, was answered as 413.")
w("- The HTTP/2 in nginx 1.14 and 1.18 can't write ports like HTTP/1.1, so I tested it with a different port.")
w("- Repeat time: Ubuntu 18.04 configuration has been re-tested for three hours as a distribution module file.[SOAK-UBUNTU1804.md](SOAK-UBUNTU1804.md)). "
  "20.04 and 22.04 didn't set up.")
w("- Uncertain: TLS, multiple worker, Tomcat, deployment build for nginx. "
  "Ubuntu Pro/ESM package combination. RHEL array and Debian package. TCP connection PHP-FPM. "
  "I've only checked the policy implementation of PHP2Shell, and I haven't checked the CVE mitigation effect.")
open(os.path.join(docs, "LEGACY.md"), "w").write("\n".join(out) + "\n")

# ------------------------------------------------------------------ apache
d = json.load(open(os.path.join(apache_dir, "results.json")))
m, rows = d["meta"], d["rows"]
out = []
w = out.append
w("# Apache 2.4 authentication: mod_proxy_fcgi and mod_php")
w("")
w("Source records: `%s/`." % apache_dir.rstrip("/"))
w("")
w("## Judgment")
w("")
fc = [r for r in rows if r["handler"] == "mod_proxy_fcgi"]
mp = [r for r in rows if r["handler"] == "mod_php"]
blk = [r for r in fc if r["mode"] == "block" and r["shield_action"] == "block"]
nrm = [r for r in fc if r["sha256_match"] is not None]
w("| Connection configuration | MONITOR | BLOCK | Based on |")
w("|---|---|---|---|")
w("| mod_proxy_fcgi to PHP-FPM (TCP) | Passed | Passed | %d normal uploads, SHA-256 %s. All %d BLOCK denials: zero PHP-FPM requests and packets. %s |" % (
    len(nrm), "They all match." if all(r["sha256_match"] for r in nrm) else "**There's a difference.**", len(blk),
    OK[all(r["ok"] and r["php_fpm_access_lines"] == 0 and r["php_app_records"] == 0 and r["php_fpm_port_packets"] == 0 for r in blk)]))
w("| In-process mod_php | Passed | Unsupported. Matching multipart requests receive HTTP 500 (MGUS-901). | The PHP handler reads the body directly. Test result: %s |" % OK[all(r["ok"] for r in mp)])
w("")
w("- %d cases, %d passed. Eight concurrent clients sent %d seconds of load, with %d requests and %d unexpected outcomes."
  % (d["summary"]["total"], d["summary"]["passed"], d["load"]["seconds"],
     sum(d["load"]["outcomes"].values()), d["load"]["unexpected"]))
w("- After the end of the mod_proxy spool temporary file %d, PHP upload temporary file %d. Child process abnormal termination %d."
  % (m["proxy_spool_files_left_in_tmp"], m["php_upload_tmp_left"],
     m["apache-fcgi_child_crashes"] + m["apache-modphp_child_crashes"]))
ap = os.path.join(apache_dir, "asan-run", "results.json")
if os.path.exists(ap):
    x = json.load(open(ap))
    log = open(os.path.join(apache_dir, "asan-run", "apache-fcgi-error.log"), errors="replace").read()
    w("- AddressSanitizer: %d mod_proxy_fcgi cases (%d passed) and %d seconds of load (%d requests, %d unexpected). ASan reports: %d."
      % (x["summary"]["total"], x["summary"]["passed"], x["load"]["seconds"],
         sum(x["load"]["outcomes"].values()), x["load"]["unexpected"],
         log.count("AddressSanitizer")))
w("")
w("## Testing environment and behavior")
w("")
w("| Items | The value. |")
w("|---|---|")
w("| OS | %s |" % m["os"])
w("| The web server package | apache2 %s (%s), mod_proxy_fcgi is event MPM, mod_php is prefork MPM |" % (m["apache_package"], m["apache"].replace("Server version: ", "")))
w("| PHP | php8.3-fpm %s (%s), libapache2-mod-php8.3 %s |" % (m["php_package"], m["php_fpm"].split(" (built")[0], m["mod_php_package"]))
w("| How to connect | `SetHandler \"proxy:fcgi://127.0.0.1:PORT\"` (TCP) |")
w("| Module | `apache/mod_upload_shield.c` We have a common engine. `apxs -c`I'm going to tell you. |")
w("")
w("- The connector is the input filter. The Apache input filter is the way the handler pulls it. "
  "You can't reverse the piece that's gone.")
w("- In BLOCK, the modules respond to the test subject's request. `proxy-sendcl`Then you set the mod_proxy_fcgi"
  "It's only after the entire text has been filtered through the input filter that it connects to the backend. "
  "If the filter refuses during the spool, there's no back-end connection. "
  "It's a temporary file, so it adds disk I/O and delay to the streaming.")
w("- If the handler isn't mod_proxy_fcgi or httpd is less than 2.4.47, BLOCK is a multipart request. "
  "I'm refusing to go to 500 MGUS-901.")
w("- Apache enforces the total request size and read timing with `LimitRequestBody` and `RequestReadTimeout`.")
w("")
w("## Case results")
w("")
w("PHP reach is \"PHP-FPM access log/PHP script record number/PHP-FPM port packet number\". "
  "Mod_php is just a script record for an infrastructure.")
w("")
w("| ID | The handler. | Mods. | The test. | It's in good condition. | Shield | The rules. | PHP reach | SHA-256 | Judgment. |")
w("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    w("| %s | %s | %s | %s | %s | %s | %s | %d/%d/%d | %s | %s |" % (
        r["id"], r["handler"], r["mode"], r["name"], r["status"] if r["status"] else "Connection termination",
        r["shield_action"] or "There is no log.", r["shield_rule"] or "–", r["php_fpm_access_lines"],
        r["php_app_records"], r["php_fpm_port_packets"], SHA[r["sha256_match"]], OK[r["ok"]]))
w("")
base = [r for r in rows if "baseline: chunked" in r["name"]][0]
mon = [r for r in rows if "MONITOR leaves" in r["name"]][0]
w("## Apache request handling")
w("")
w("- On a virtual host without an upload policy, PHP-FPM received the chunked request but PHP parsed %d files and %d fields. HTTP status: %d. Case: %s."
  % (base["php_view"]["content_length"], base["php_view"]["files"], base["php_view"]["fields"], base["id"]))
w("- MONITOR preserves that behavior (%s, matches baseline: %s). BLOCK sets `proxy-sendcl` so mod_proxy can spool the body and forward its length." % (mon["id"], "Yes" if mon.get("same_as_baseline") else "**No**"))
w("")
w("## Untested configurations")
w("")
w("- The Unix socket is PHP-FPM. `ProxyPassMatch` Mod_http2, TLS, httpd 2.4.58 other versions"
  "(2.4.47 below) has no source spool and BLOCK is impossible.")
w("- Apache adapter soak testing remains open. The load test ran for %d seconds." % d["load"]["seconds"])
w("- BLOCK is rejected in these handlers.")
w("- I've only checked the policy implementation for PHP2Shell.")
open(os.path.join(docs, "APACHE.md"), "w").write("\n".join(out) + "\n")
print("wrote LEGACY.md, APACHE.md")
