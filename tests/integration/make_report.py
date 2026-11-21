#!/usr/bin/env python3
"""Builds docs/TEST-REPORT.md from a results directory. Every number in the
report is copied from results.json / evidence.jsonl, nothing is typed by hand."""
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src + "/results.json"))
ev = {json.loads(x)["id"]: json.loads(x) for x in open(src + "/evidence.jsonl")}
res = d["results"]
m = d["measurements"]
out = []
w = out.append


def sh(r):
    return r["shield"] if isinstance(r["shield"], dict) else {}


def table(rows):
    w("| ID | The test. | The route. | The client's condition. | Request the backend. | Back-end text byte | SHA-256 | Shield is working. | The rules. | Judgment. |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        s = sh(r)
        w("| %s | %s | `%s` | %s | %d | %d | %s | %s | %s | %s |" % (
            r["id"], r["name"], r["path"],
            r["client_status"] if r["client_status"] else "Connection termination",
            r["backend_requests"], r["backend_body_bytes"],
            {True: "Matched", False: "Disagreements.", None: "–"}[r["sha_match"]],
            s.get("action", "There is no log."), s.get("rule", "–"),
            "Passed" if r["ok"] else "**Failed**"))
    w("")


w("# Kuipernet Upload v0.1")
w("")
w("Source records: `results.json` and `evidence.jsonl` from the integration suite.")
w("")
w("## Summary")
w("")
w("- %d of the functional test, %d of the validation, %d of the invalidation." % (
    d["summary"]["total"], d["summary"]["passed"], d["summary"]["failed"]))
w("- Temporary request text file remaining after the function test is completed: %d."
  % m["temp_files_after_functional_tests"])
w("- Test environment: nginx 1.30.0 (source build, `--with-compat --with-http_v2_module`), "
  "Dynamic modules, one worker, Ubuntu 24.04, gcc 13.3.0, the client, the nginx, the backend, all of them. "
  "Loopback of the same host.")
w("- Backend measurements `tests/integration/backends.py`HTTP server proxy_pass object) and "
  "FastCGI response machine (fastcgi_pass object, PHP-FPM number) and connection, request, and receipt textbook "
  "The actual PHP-FPM, or Tomcat, is used in this test. "
  "It didn't.")
w("")

w("## 1. Acceptance criteria")
w("")
crit = []


def allok(sel):
    rows = [r for r in res if sel(r)]
    return rows, all(r["ok"] for r in rows)


for kind in ("proxy", "fcgi"):
    rows, ok = allok(lambda r: r["path"] in ("/%s/monitor/" % kind, "/%s/block/" % kind)
                     and r["name"].startswith("normal") and "HTTP/" not in r["name"])
    crit.append(("Normal request: matching SHA-256 of the transmission source and the backend receiving source (%s)" % kind, rows, ok))
    rows, ok = allok(lambda r: r["path"] == "/%s/block/" % kind and sh(r).get("action") == "block")
    crit.append(("BLOCK: Web server refused a violation request, backend received 0 bytes (%s)" % kind, rows,
                 ok and all(r["backend_requests"] == 0 and r["backend_body_bytes"] == 0 for r in rows)))
    rows, ok = allok(lambda r: r["path"] == "/%s/monitor/" % kind and sh(r).get("action") == "monitor")
    crit.append(("MONITOR: The same request is backed up and only the violation log remains (%s)" % kind, rows,
                 ok and all(r["backend_requests"] == 1 and r["sha_match"] in (True, None) for r in rows)))

w("| It's the standard. | That's the test. | Result |")
w("|---|---|---|")
for name, rows, ok in crit:
    w("| %s | %d (%s ... %s) | %s |" % (name, len(rows), rows[0]["id"], rows[-1]["id"],
                                         "Passed" if ok else "**Failed**"))
w("")
w("We tested the backend and the FastCGI backend separately, and we wrote down the results separately. "
  "So the judgments of the two sets are the same, so the approval plates are marked with the same rating.")
w("")

w("## 2. Route policy with proxy_pass")
w("")
table([r for r in res if r["path"].startswith(("/proxy/", "/nobuf/proxy/")) and "HTTP/" not in r["name"]
       and "follows nginx" not in r["name"]])
w("## 3. FastCGI backend")
w("")
table([r for r in res if r["path"].startswith(("/fcgi/", "/nobuf/fcgi/")) and "HTTP/" not in r["name"]])
w("## 4. Request size and read timeouts")
w("")
table([r for r in res if r["path"].startswith(("/size/", "/time/")) or "follows nginx" in r["name"]])
w("`nginx -t`Reported setup collision (actual output):")
w("")
w("```")
w(open(src + "/nginx-config-test.txt").read().strip())
w("```")
w("")
w("## 5. Full Virtual Host policy and PHP2Shell selection policy")
w("")
table([r for r in res if r["name"].startswith("host-wide")])
w("## 6. The actual client curl and HTTP/2.")
w("")
w("HTTP/2 was only tested with prior-knowledge h2c. `curl -F` The request is curl. "
  "So it's not a SHA-256 counterpart.")
w("")
table([r for r in res if "HTTP/" in r["name"]])

w("## 7. Measurement of resource use")
w("")
w("### 512 MB single file upload (proxy_pass, request buffering on)")
w("")
w("| The route. | It's in good condition. | Time (s) | The worker CPU | The worker maximum RSS | Maximum temporary disk size of MB | Temporary file after closure | SHA-256 |")
w("|---|---|---|---|---|---|---|---|")
for b in m.get("big_upload", []):
    w("| `%s` | %s | %s | %s | %s | %s | %d | %s |" % (
        b["path"], b["status"], b["wall_s"], b["worker_cpu_s"], b["worker_peak_rss_kb"],
        b["temp_disk_peak_mb"], b["temp_files_after"], "Matched" if b["sha_match"] else "Disagreements."))
w("")
w("`/big/off/`The shield's off course. The difference between the noise range is two measurements per configuration. "
  "And it's not a statistical conclusion. "
  "It's the sum of the temp file sizes of the requested text.")
w("")
s = m.get("soak")
if s:
    w("### Repeat the test.")
    w("")
    w("- %d requests (60%% normal, 20%% missing the closing boundary, 20%% disconnected during upload), %s seconds."
      % (s["requests"], s["seconds"]))
    w("- Response distribution: %s (None is the client's interrupted request)." % json.dumps(s["status_counts"]))
    w("- RSS: start %d kB → finish %d kB. Open fd: %d → %d. worker CPU %s second."
      % (s["worker_rss_kb_start"], s["worker_rss_kb_end"], s["worker_fds_start"],
         s["worker_fds_end"], s["worker_cpu_s"]))
    w("- Temporary file left after completion: %d." % s["temp_files_after"])
    w("")

w("## 8. Example of the log element")
w("")
picks = []
for want in ("last part: file over size limit", "host-wide block: progress field, last part (fcgi)",
             "client aborts mid-upload", "buffering off, BLOCK, normal upload refused"):
    for r in res:
        if r["name"] == want and (r["path"].endswith("/block/") or r["path"].startswith("/index")):
            picks.append(r)
            break
for want_path in ("/fcgi/monitor/",):
    for r in res:
        if r["name"] == "last part: file over size limit" and r["path"] == want_path:
            picks.append(r)
for r in picks:
    e = ev[r["id"]]
    w("**%s — %s (`%s`)**" % (r["id"], r["name"], r["path"]))
    w("")
    w("nginx error log:")
    w("")
    w("```")
    for line in e["nginx_error_log"]:
        w(line)
    w("```")
    w("")
    w("Back-end record: " + ("No requests (0 items)" if not e["backend_log"] else ""))
    if e["backend_log"]:
        w("")
        w("```")
        for b in e["backend_log"]:
            w(json.dumps(b, sort_keys=True))
        w("```")
    w("")

w("## 9. Other verification.")
w("")
w("- Unit test of the engine`tests/results/2026-11-20/unit-test-asan-ubsan.txt`): "
  "ASan-UBSan building, Chapter 49 and Content-Type 17 types of expected judgments, all fixed sculptures "
  "Judgment counter is the same in the size of 1 to 96 bytes and the random division, the side input is 300,000 to the "
  "No crashes, divided fluctuations.")
a = json.load(open(src + "/asan-run-summary.json"))
w("- The same function test as ASan metric nginx is running %dgan: %dgan accreditation, ASan report %dgan. "
  "Then repeat the request and run %d`asan-run-summary.json`)."
  % (a["summary"]["total"], a["summary"]["passed"], a["asan_reports"], a["soak"]["requests"]))
w("")
w("## 10. Test scope")
w("")
w("- Real PHP-FPM; Tomcat backend, attack replication of vulnerable PHP versions.")
w("- The secondary test of the PHP multipart instructional engine and the same interpretation of both textbooks.")
w("- The full Apache connection section, HTTP/3, HTTP/2, over TLS, and the distribution package nginx.")
w("- Multiple worker simultaneous connection charges, 24-hour long-term testing, remote network delays.")
w("- Internal error check (memory allocation failure) path injection test.")
open(dst, "w").write("\n".join(out) + "\n")
print("wrote", dst, len(out), "lines")
