#!/usr/bin/env python3
"""Builds the repetition-test report from the records of soak_legacy.py.
Usage: make_soak_report.py RESULTS_DIR OUTPUT.md"""
import json
import os
import sys

src, dst = sys.argv[1:3]
m = json.load(open(os.path.join(src, "soak-meta.json")))
segs = [json.loads(x) for x in open(os.path.join(src, "soak-segments.jsonl"))]
samples = [json.loads(x) for x in open(os.path.join(src, "soak-samples.jsonl"))]
tot = m["totals"]
out = []
w = out.append
YN = {True: "Fulfilled", False: "**They're not enough.**"}
KO = {
    "normal upload, HTTP/2": ("Normal upload, HTTP/2", "200"),
    "normal upload, HTTP/1.1": ("Normal HTTP/1.1 upload (roughly 30% chunked)", "200"),
    "HTTP/2 shared connection: timeout stream + 2 normal streams":
        ("One connection: one timeout stream plus two normal streams.", "The time-out stream ends in about two seconds, the normal stream is 200, both of which keep the connection"),
    "HTTP/2 upload timeout, own connection": ("HTTP/2 upload timeout, single connection", "End in about two seconds."),
    "HTTP/1.1 upload timeout": ("HTTP/1.1 Upload timeout", "End in about two seconds."),
    "progress field, HTTP/2 (403)": ("Forward rate field violation, HTTP/2", "403"),
    "last file over limit, HTTP/1.1 (413)": ("Over the last file size, HTTP/1.1", "413"),
    "multipart to no-upload path (403)": ("Multipart of the route prohibited upload", "403"),
    "client abort mid-upload": ("The client is logging in.", "No answer."),
    "client exception": ("Except for the client.", "–"),
}
CK = {
    "no nginx alert/crit/emerg": "The nginx alert.crit.emerg log 0",
    "no worker exited on signal": "Worker abnormal shutdown",
    "worker PID unchanged from start to end": "The worker PID is the same from start to finish",
    "no failure recorded during segments": "No failure detection while running",
    "no unexpected client outcome": "Expected client results are zero.",
    "shared connection: every stalled stream cut, every other stream 200, connection kept":
        "One connection test: the timeout stream is all off, the normal stream of the same connection is all 200, keep the connection",
    "timeout/violation requests reaching PHP-FPM = 0": "PHP-FPM reaching zero for timeout policy violation requests",
    "every normal upload delivered once with matching SHA-256": "All normal uploads received 200 were delivered once and matched SHA-256.",
    "no temp file left": "0 temporary files left after the end.",
    "module file unchanged during the run": "No changes to the module file during the test.",
}
pk = dict((x.split()[0], x.split()[1]) for x in m["packages"])
h, mi = divmod(tot["seconds"] // 60, 60)
w("# Ubuntu 18.04 + Nginx 1.14.0 + PHP-FPM 7.2: Distribution modules with long-term repeat testing")
w("")
w("Source records: `%s/`, produced by `tests/legacy/soak_legacy.py`." % src.rstrip("/"))
w("")
w("## Result: %s" % {"PASS": "Passed", "FAIL": "**Failed**"}[m["verdict"]])
w("")
w("- Running time %d time %d minute ((%d second), request %d, out of the expected result %d." % (h, mi, tot["seconds"], tot["requests"], tot["unexpected"]))
w("- nginx alert·crit·emerg %dgan, worker abnormal termination %dgan. worker PID is start %s, end %s."
  % (m["nginx_alert_crit_emerg_lines"], m["worker_exits_on_signal"], m["workers"], m["workers_at_end"]))
w("- Period: %s to %s." % (m["started_text"], m["ended_text"]))
w("")
w("| Qualification requirements | Result |")
w("|---|---|")
for k, v in m["checks"].items():
    w("| %s | %s |" % (CK.get(k, k), YN[v]))
w("")
w("If one of them is not enough, it's not compatible. "
  "`failure-<seconds>/`It's written in the original, and then it's finished. "
  + ("It doesn't happen in this run and there's no directory." if m["verdict"] == "PASS" and not any(s["failure"] for s in segs)
     else "**This execution's storage location: %s**" % ", ".join(f["logs_preserved_in"] for s in segs for f in s["failure"])))
w("")
w("## Test environment")
w("")
w("| Items | The value. |")
w("|---|---|")
w("| Distribution module | `%s` |" % m["module_path"])
w("| Distribution module SHA-256 | `%s` (%d byte) |" % (m["module_sha256"], m["module_size"]))
w("| Shut down time SHA-256 | `%s` |" % m["module_sha256_at_end"])
w("| Modules mapped to the worker | `%s` |" % ", ".join(m["module_mapped_in_worker"]))
w("| OS | %s (debootstrap chroot, kernel is test host %s) |" % (m["os"], m["host_kernel"]))
for p in ("nginx", "nginx-core", "nginx-common", "php%s-fpm" % "7.2", "php7.2-common", "php7.2-cli",
          "libssl1.1", "libpcre3", "zlib1g", "libc6"):
    if p in pk:
        w("| Package. `%s` | `%s` |" % (p, pk[p]))
w("| PHP | %s |" % m["php_version"])
w("| Run the nginx file | `%s`, SHA-256 `%s` |" % (m["nginx_master_exe"], m["nginx_binary_sha256"]))
w("| Package storage | %s |" % "; ".join("`%s`" % x for x in m["apt_sources"] if x.startswith("deb ")))
w("| Ubuntu Pro/ESM storage | %s |" % ("Set up" if m["esm_sources_configured"] else "Not configured"))
w("| How to connect | `fastcgi_pass` Unix socket, request buffer on, one worker, six PHP-FPM children. |")
w("| Policy | BLOCK, progress rate field rejection, file 1 MB, four limits, file name checking, `/small.php`Shield full receiving timeout 2 seconds |")
w("")
w("The module is the Ubuntu source package. `nginx 1.14.0-0ubuntu1.11`packages in the `nginx -V` Configure the receiver exactly "
  "And we built it. [LEGACY.md](LEGACY.md)It's SHA-256, the same file I wrote in the 28 tests.")
w("")
w("## Workload and outcomes")
w("")
w("The same client, %d, randomly mixed the following types, all harmless requests." % segs[0]["concurrency"])
w("")
w("| Type | Expected | Count | As expected. |")
w("|---|---|---|---|")
for k, v in sorted(tot["kinds"].items(), key=lambda x: -x[1]["n"]):
    w("| %s | %s | %d | %d |" % (KO.get(k, (k, ""))[0], KO.get(k, ("", ""))[1], v["n"], v["ok"]))
w("")
s = tot["shared_connection"]
w("### The other normal stream of the same connection")
w("")
w("I sent three streams to one HTTP/2 connection."
  "It takes two seconds. Stream 3 sends 0.9 MB of normal uploads at intervals of 0.3 seconds. "
  "It's streaming in the moment. Stream 5 is a normal upload starting at the timeout point.")
w("")
w("| Items | Count |")
w("|---|---|")
w("| Connected and executed | %d |" % s["runs"])
w("| Stream 1 ends in about two seconds 1.8 to 3.5 seconds. | %d |" % s["stalled_cut"])
w("| Stream 3 is transmitting at the timeout point. | %d |" % s["inflight_200"])
w("| Stream 5 (start after timeout) is 200 | %d |" % s["later_200"])
w("| The server doesn't disconnect. | %d |" % s["connection_kept"])
w("")
w("### Backend measurements")
w("")
a = m["php_fpm_access_lines_by_test_id"]
p = m["php_app_records"]
w("| Items | The value. |")
w("|---|---|")
w("| The client received 200 normal uploads. | %d |" % tot["normal_200_seen_by_clients"])
w("| You can upload the PHP-FPM access log to normal. | %d |" % (a.get("sk-n0", 0) + a.get("sk-n1", 0)))
w("| The normal number of uploads of PHP script records / file of which SHA-256 matches the field number | %d / %d |" % (p["normal_records"], p["normal_sha256_match"]))
w("| I can give you the PHP-FPM access log of the timeout request. | %d |" % a.get("sk-timeout", 0))
w("| You can give the PHP-FPM access log of the policy violation request | %d |" % a.get("sk-violation", 0))
w("| I can give you the PHP-FPM access log of the interrupted upload. | %d |" % a.get("sk-abort", 0))
w("| Shield Log's judgmental touch. | %s |" % ", ".join("%s %d" % kv for kv in sorted(m["shield_log_by_action_rule"].items())))
w("")
w("## Load segments")
w("")
w("The environment was once up and maintained until the end, and then the load was split into sections.")
w("")
w("| Start of the period. | I'm going to run. | Requested | Except as expected. | Alert. Logged in | The worker afterwards RSS | Open the fd | Temporary file |")
w("|---|---|---|---|---|---|---|---|")
for g in segs:
    i = g["idle_after"]
    w("| %d | %d | %d | %d | %d | %s | %d | %d |" % (g["from_t"], g["seconds_run"], g["requests"], g["unexpected_count"],
                                                   g["bad_log_lines"], i["worker_rss_kb"], i["worker_fds"], i["temp_dir_entries"]))
w("")
w("## Resource measurements")
w("")
w("Worker RSS, open descriptors, and request-body temporary files were sampled every 10 seconds (%d samples)." % len(samples))
w("")
w("| Time and minutes | worker RSS(kB) | Open the fd | Temporary file open | PHP-FPM RSS sum of kB | worker PID |")
w("|---|---|---|---|---|---|")
step = max(1, len(samples) // 12)
for x in samples[::step] + ([samples[-1]] if (len(samples) - 1) % step else []):
    w("| %d | %s | %d | %d | %d | %s |" % (x["t"] // 60, sum(x["worker_rss_kb"]), x["worker_fds"], x["temp_open"],
                                         x["php_fpm_rss_kb"], x["workers"]))
w("")
late = [sum(x["worker_rss_kb"]) for x in samples if x["t"] >= 900]
if len(late) > 4:
    half = len(late) // 2
    w("- Worker RSS: %d kB at startup. After 15 minutes, the range was %d–%d kB, with a first-half mean of %d kB and a second-half mean of %d kB."
      % (sum(m["idle_at_start"]["worker_rss_kb"]), min(late), max(late), sum(late[:half]) / half, sum(late[half:]) / (len(late) - half)))
w("- Time worker RSS %d kB, open fd %d, temporary file %d, PHP upload temporary file %d."
  % (sum(m["idle_at_end"]["worker_rss_kb"]), m["idle_at_end"]["worker_fds"], m["idle_at_end"]["temp_dir_entries"], m["idle_at_end"]["php_upload_tmp"]))
w("")
ap = os.path.join(src, "attempt1-interrupted", "attempt1-summary.json")
if os.path.exists(ap):
    x = json.load(open(ap))
    c = x["completed_segment"]
    w("## Interrupted first attempt")
    w("")
    w("- The first execution started with %s as the same module file was interrupted when the test host VM restarted."
      "(Host booting time 2026-11-20 21:16:34 KST, last line %s of nginx log). "
      "And the result is that we're running it all over again." % (x["load_started"], x["last_nginx_log_line"]))
    w("- Before interruption: %d seconds of completed segments, %d requests, %d unexpected results, and %d successful shared-connection cases. Last sample: %d seconds. Worker PIDs: %s. Nginx alerts: %d. Worker exits: %d. Recorded uploads: %d, matching SHA-256: %d."
      % (c["seconds_run"], c["requests"], c["unexpected_count"], c["shared_connection"]["runs"],
         x["last_sample_t_seconds"], list(x["worker_pid_in_every_sample"][0]), x["nginx_alert_crit_emerg_lines"],
         x["worker_exits_on_signal"], x["php_app_normal_records"], x["php_app_normal_sha256_match"]))
    w("- About the last four minutes, the test client's statistics disappeared with the host reset, leaving only the server log. "
      "The original log `attempt1-interrupted/`It's in.")
    w("")
w("## Test scope")
w("")
w("- This test is modular stability and policy implementation on the front end of PHP-FPM 7.2, not PHP2Shell CVE mitigation testing.")
w("- One worker, a horizontal HTTP/2 port, a Unix socket configuration, TLS, multiple worker, TCP connection, PHP-FPM, "
  "The Ubuntu Pro/ESM package combination is not in this test.")
w("- The chroot kernel belongs to the test host, not the actual run on the 18.04 kernel.")
w("- It's not an ASan build, it's a distribution build.")
open(dst, "w").write("\n".join(out) + "\n")
print("wrote", dst, m["verdict"])
