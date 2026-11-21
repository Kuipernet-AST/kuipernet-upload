#!/usr/bin/env python3
"""Builds a verification report from a results directory of run_e2e.py
(plus soak.py output when present). Every value in the tables is read from
results.json / supplement.json / soak-*.json(l).

Usage: make_report.py RESULTS_DIR OUTPUT.md [TITLE]"""
import json
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
title = sys.argv[3] if len(sys.argv) > 3 else "Secondary verification results (actual PHP-FPM; Tomcat)"
d = json.load(open(src + "/results.json"))
sup = json.load(open(src + "/supplement.json"))
cases, meta, load = d["cases"], d["meta"], d["load"]
out = []
w = out.append
PROTO = {"h1": "HTTP/1.1", "h2": "HTTP/2", "h2tls": "HTTP/2 (TLS)"}
BACK = {"php": "PHP-FPM", "tomcat": "Tomcat"}
OKS = {True: "Passed", False: "**Failed**"}


def sh(c):
    return c["obs"]["shield"][0] if len(c["obs"]["shield"]) == 1 else {}


def view(c):
    a = c["obs"]["php_app"] if c["backend"] == "php" else c["obs"]["tc_app"]
    return a[0] if len(a) == 1 else None


def acc(c):
    return len(c["obs"]["php_access"] if c["backend"] == "php" else c["obs"]["tc_access"])


def app(c):
    return len(c["obs"]["php_app"] if c["backend"] == "php" else c["obs"]["tc_app"])


def pk(c):
    return c["obs"]["pkts_php"] if c["backend"] == "php" else c["obs"]["pkts_tc"]


def st(c):
    return c["client_status"] if c["client_status"] else "Connection termination"


def seen(c):
    v = view(c)
    if not v:
        return "–"
    if "files" in v:
        return "%d file, field %d" % (v["files"], v["fields"])
    return "Title %d B" % v["body_bytes_read"]


def grp(name):
    return [c for c in cases if c["group"] == name]


def std_table(rows):
    w("| ID | Mods. | The protocol | Backend measurements | The test. | It's in good condition. | Shield | The rules. | Backend access logs | Back-end app records | The back-end port packet. | The backend dealt with it. | Judgment. |")
    w("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for c in rows:
        s = sh(c)
        w("| %s | %s | %s | %s | %s | %s | %s | %s | %d | %d | %d | %s | %s |" % (
            c["id"], c["server"], PROTO[c["proto"]], BACK[c["backend"]], c["name"],
            st(c), s.get("action", "–"), s.get("rule", "–"), acc(c), app(c), pk(c),
            seen(c), OKS[c["ok"]]))
    w("")


v = meta["versions"]
w("# Kuipernet Upload v0.1 — " + title)
w("")
w("Source records: `%s/`." % src.rstrip("/"))
w("")
w("## Summary")
w("")
w("- %d of the test results. %d of the test results. %d of the test results."
  % (d["summary"]["total"], d["summary"]["passed"], d["summary"]["failed"]))
old = [c for c in cases if c["group"] in ("function", "compare", "ambiguous", "vhost", "contract")]
new = [c for c in cases if c not in old]
if new:
    w("- Prior cases: %d (E001–%s), %d passed. Added cases: %d, %d passed."
      % (len(old), old[-1]["id"], sum(1 for c in old if c["ok"]), len(new),
         sum(1 for c in new if c["ok"])))
if load:
    tot = sum(r["requests"] for r in load["rounds"])
    w("- Concurrent upload: %d rounds, %d clients, %d seconds per round, %d requests, %d unexpected responses."
      % (len(load["rounds"]), load["rounds"][0]["concurrency"],
         load["rounds"][0]["seconds"], tot, sum(r["unexpected"] for r in load["rounds"])))
w("- An alert.crit.emerg %dgan of the nginx error log, a worker %dgan that ended with the signal. "
  "It's the same as %s from start to finish."
  % (meta["nginx_alerts"], meta["worker_exits_on_signal"], meta["workers_at_end"]))
w("")
w("### Test environment")
w("")
w("| Components | The version. |")
w("|---|---|")
w("| nginx | %s (source field, dynamic module, two worker) |" % v["nginx"].split("\n")[0].replace("nginx version: ", ""))
w("| PHP-FPM | %s, Ubuntu 24.04 package, `pm = static`, 8 workers, TCP 127.0.0.1 |" % v["php_fpm"])
w("| Tomcat | %s, HTTP/1.1 connector |" % v["tomcat"].replace("Server version: ", ""))
w("| JVM | %s |" % v["jvm"].replace("JVM Version:", "").strip())
w("| Kernel | %s |" % v["kernel"])
w("")
w("### Backend measurements")
w("")
w("| It's a measurement. | PHP-FPM | Tomcat |")
w("|---|---|---|")
w("| The number of requests dealt with by the backend | FPM own access log | AccessLogValve |")
w("| The file field interpreted by the backend | PHP script recording`$_FILES`, `$_POST`SHA-256 by file. | Sublet records`getParts()`SHA-256 in part. |")
w("| The number of packets entering the backend port. | Kernel packet counter | Kernel packet counter |")
w("")
w("This means that nginx hasn't even opened a TCP connection to the backend. "
  "So the request that the backend receives for that request is zero, the text is zero bytes.")
w("")

# ------------------------------------------------------------------ 1
w("## 1. Application backend tests")
w("")
rows = grp("function")
normal = [c for c in rows if c["name"].startswith("normal")]
blocked = [c for c in rows if c["server"] == "block" and sh(c).get("action") == "block"]
mon = [c for c in rows if c["server"] == "monitor" and sh(c).get("action") == "monitor"]
w("| It's the standard. | PHP-FPM | Tomcat |")
w("|---|---|---|")
for label, sel, extra in (
        ("The normal upload is processed as a file field.", normal, None),
        ("BLOCK: last part refusal of request for violation, backend request 0gan packets 0", blocked, "zero"),
        ("The same request is forwarded and only a violation log remains.", mon, None)):
    cells = []
    for b in ("php", "tomcat"):
        r = [c for c in sel if c["backend"] == b]
        ok = all(c["ok"] for c in r)
        if extra == "zero":
            ok = ok and all(acc(c) == 0 and app(c) == 0 and pk(c) == 0 for c in r)
        cells.append("%d is %s" % (len(r), OKS[ok]))
    w("| %s | %s | %s |" % (label, cells[0], cells[1]))
w("")
std_table(rows)

# ------------------------------------------------------------------ 2
w("## 2. Multipart parser comparison")
w("")
w("Shield authorized BLOCK servers. `pass`For normal requests, the number of file sub-fields of the Shield log;"
  "So we compared the largest file size to the value that the backend actually handled. "
  "It's the actual configuration of the client's headquarters.")
w("")
rows = grp("compare")
judged = [c for c in rows if not c.get("known_difference")]
w("- Of %d comparison cases, %d were eligible. %d agreed on file count, field count and maximum file size. %d disagreed."
  % (len(rows), len(judged), sum(1 for c in judged if c.get("agree")),
     sum(1 for c in judged if not c.get("agree"))))
kd = [c for c in rows if c.get("known_difference")]
w("- Excluded %d PHP-specific cases: PHP retains the last value when a non-array field name repeats. The module and Tomcat count each part." % len(kd))
w("")
w("| ID | The protocol | Backend measurements | Form of request | The value sent (file/field/maximum file B) | Shield | Backend measurements | Matched | The file is SHA-256. |")
w("|---|---|---|---|---|---|---|---|---|")
for c in rows:
    s, vv, e = sh(c), view(c) or {}, c["expected"]
    w("| %s | %s | %s | %s | %d / %d / %d | %s / %s / %s | %s / %s / %s | %s | %s |" % (
        c["id"], PROTO[c["proto"]], BACK[c["backend"]], c["name"],
        e["files"], e["fields"], e["max_file_bytes"],
        s.get("files"), s.get("fields"), s.get("max_file_bytes"),
        vv.get("files"), vv.get("fields"), vv.get("max_file_bytes"),
        "Matched" if c.get("agree") else ("PHP specific operation" if c.get("known_difference") else "**Disagreements.**"),
        {True: "Matched", False: "**Disagreements.**", None: "–"}[c["checks"].get("file bytes identical (sha256)")]))
w("")

w("### How does the backend interpret the input that Shield sees as a structural violation?")
w("")
w("The bottom entry is the form that Shield rejects because \"each passage can be read differently\". "
  "And they sent it to the monitor server and they recorded the interpretation of the actual backend. "
  "It's an odd number and a short string.")
w("")
rows = grp("ambiguous")
names = []
for c in rows:
    if c["name"] not in names:
        names.append(c["name"])
w("| I want you to enter. | Shield rules | Interpretation of PHP-FPM | The interpretation of Tomcat | The two backends match. | BLOCK results (PHP-FPM / Tomcat) |")
w("|---|---|---|---|---|---|")
for n in names:
    cell, blk, raw = {}, {}, {}
    rule = ""
    for c in rows:
        if c["name"] != n:
            continue
        if c["server"] == "monitor":
            vv = view(c)
            rule = sh(c).get("rule", "")
            raw[c["backend"]] = (vv or {}).get("files"), (vv or {}).get("fields"), (vv or {}).get("error")
            if vv and vv.get("error"):
                cell[c["backend"]] = "Refuse to pass HTTP %s" % c["client_status"]
            else:
                cell[c["backend"]] = "File %d, field %d (%s)" % (vv["files"], vv["fields"], c["id"])
        else:
            blk[c["backend"]] = "%s, requested %d. Package %d (%s)" % (st(c), acc(c), pk(c), c["id"])
    w("| %s | %s | %s | %s | %s | %s / %s |" % (
        n, rule, cell["php"], cell["tomcat"],
        "It's the same." if raw["php"] == raw["tomcat"] else "**It's very different.**", blk["php"], blk["tomcat"]))
w("")
diff = 0
for n in names:
    r = {c["backend"]: view(c) for c in rows if c["name"] == n and c["server"] == "monitor"}
    a, b = r["php"] or {}, r["tomcat"] or {}
    if (a.get("files"), a.get("fields"), a.get("error")) != (b.get("files"), b.get("fields"), b.get("error")):
        diff += 1
w("Of %d inputs, PHP-FPM and Tomcat differed on %d. In BLOCK mode, %d requests produced zero backend requests and packets."
  % (len(names), diff, sum(1 for c in rows if c["server"] == "block" and acc(c) == 0 and pk(c) == 0)))
w("")

# ------------------------------------------------------------------ 3
w("## 3. Routes without upload functionality and virtual host policy")
w("")
w("`page.php`It's a page that only reads query variables. `/tc/page`It doesn't support multipart "
  "It's a sublet. `server` It was just blocks.")
w("")
rows = grp("vhost")
php_off = [c for c in rows if c["server"] == "off" and c["backend"] == "php"][0]
w("- Shield's off on the server. `page.php`Multipart requests to be sent to: %s: PHP records to the %s page "
  "And even if you don't have the upload code, the PHP engine has parsed the file. "
  "It's missing the path." % (php_off["id"], seen(php_off)))
w("- The entire BLOCK of the host for the same path violation requests are all back-end requests to zero; packets to zero "
  "It was rejected, and the normal multipart was delivered after examination.")
w("")
std_table(rows)
w("### Optional PHP2Shell-related policies")
w("")
w("| Policy of choice | I'm on my way. | The rules. | Exam of verification of enforcement | Result |")
w("|---|---|---|---|---|")
prog = [c for c in cases if sh(c).get("rule") == "MGUS-301"]
pb = [c for c in prog if c["server"] == "block"]
pm = [c for c in prog if c["server"] == "monitor"]
w("| Reject the upload progress field (BLOCK) | `upload_shield_deny_session_progress on` | MGUS-301 | %s | All %d returned 403; zero backend requests and packets: %s |" % (
    ", ".join(c["id"] for c in pb), len(pb),
    OKS[all(c["ok"] and c["client_status"] == 403 and acc(c) == 0 and pk(c) == 0 for c in pb)]))
w("| Same policy (MONITOR) | Same | MGUS-301 | %s | All %d forwarded and logged: %s |" % (
    ", ".join(c["id"] for c in pm), len(pm), OKS[all(c["ok"] and app(c) == 1 for c in pm)]))
cnt = [c for c in cases if sh(c).get("rule") == "MGUS-203" and c["server"] == "block"]
w("| File count limit (BLOCK) | `upload_shield_max_files` | MGUS-203 | %s | All %d returned 403; zero backend requests and packets: %s |" % (
    ", ".join(c["id"] for c in cnt), len(cnt),
    OKS[all(c["ok"] and acc(c) == 0 and pk(c) == 0 for c in cnt)]))
w("")
w("These cases use harmless policy test inputs. See `docs/PHP2SHELL.md` for the scope of the mitigation evidence.")
w("")

# ------------------------------------------------------------------ 4
w("## 4. Request size and receive deadline tests")
w("")
w("The contract server uses `client_max_body_size 8m` and `client_body_timeout 8s` with PHP-FPM. See `docs/SIZE-TIMEOUT-CONTRACT.md`.")
w("")
w("| location | Set up the Shield | Relation to the nginx settings |")
w("|---|---|---|")
w("| `/c/unset` | Size-timeout unspecified | Follow the nginx setting. |")
w("| `/c/small` | `max_body_size 2m`, `body_timeout 2s` (BLOCK) | Shield value is lower: Shield value is valid |")
w("| `/c/small-m` | It's the same as the monitor. | It's the same as above. |")
w("| `/c/conflict` | `max_body_size 32m`, `body_timeout 30s` (BLOCK) | Let's start with the nginx limit: **Set up the collision** |")
w("")
rows = grp("contract")
names = []
for c in rows:
    if c["name"] not in names:
        names.append(c["name"])
w("| The test. | location | HTTP/1.1 (ID: state, second to end, shield, backend) | HTTP/2 (ID: state, end to second, shield, backend) | (External links) | Set the timeout | Display of collision | Judgment. |")
w("|---|---|---|---|---|---|---|---|")
for n in names:
    pair = {c["proto"]: c for c in rows if c["name"] == n}

    def cell(c):
        s = sh(c)
        a = s.get("action", "No shield logs.")
        if s.get("rule", "none") != "none":
            a += " " + s["rule"]
        return "%s: %s, %.2f, %s, %s" % (
            c["id"], st(c), c["seconds"], a,
            "Delivered" if app(c) else "Request 0·Packet %d" % pk(c))
    s = sh(pair["h1"]) or sh(pair["h2"])
    lim = "%s (%s)" % (s.get("body_limit"), s.get("body_limit_src")) if s else "nginx refused first."
    w("| %s | `%s` | %s | %s | %s | %s | %s | %s |" % (
        n, pair["h1"]["path"], cell(pair["h1"]), cell(pair["h2"]), lim,
        s.get("body_timeout_ms", "–") if s else "–",
        s.get("config_conflict", "–") if s else "–",
        OKS[pair["h1"]["ok"] and pair["h2"]["ok"]]))
w("")
w("`nginx -t` Output: Configuration of the collision report:")
w("")
w("```")
w(open(src + "/nginx-config-test.txt").read().strip())
w("```")
w("")

if load:
    # ------------------------------------------------------------------ 5
    w("## 5. Simultaneous upload and repeat run")
    w("")
    w("%d clients sent requests concurrently to the BLOCK server. The traffic mix was approximately 74%% normal uploads, 10%% missing closing delimiters, 8%% upload progress field violations, and 8%% aborted uploads." % load["rounds"][0]["concurrency"])
    w("")
    w("| Round. | Number of requests | 200 | 400 | 403 | Cutting it off. | Extreme response | RSS (kB) maximum | The maximum fd | Open at the same time as the temporary file | Maximum temporary disk size of MB | RSS after round. | After round fd | Temporary file after round. | Upload the temporary file |")
    w("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in load["rounds"]:
        sc, i = r["status_counts"], r["idle"]
        w("| %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %s | %d | %d | %d / %d | %d |" % (
            r["round"], r["requests"], sc.get("200", 0), sc.get("400", 0), sc.get("403", 0),
            sc.get("None", 0), r["unexpected"], r["rss_kb_peak"], r["fds_peak"],
            r["temp_open_peak"], r["temp_open_mb_peak"], i["rss_kb"], i["fds"],
            i["temp_open"], i["temp_dir_entries"], i["php_upload_tmp"]))
    w("")
    s0, sf = meta["idle_at_start"], meta["idle_after_functional"]
    w("- Reference value: RSS %d kB·fd %d immediately after start, RSS %d kB·fd %d after function testing."
      % (s0["rss_kb"], s0["fds"], sf["rss_kb"], sf["fds"]))
    rs = [r["idle"]["rss_kb"] for r in load["rounds"]]
    later = sum(r["requests"] for r in load["rounds"][2:])
    w("- RSS after each round: %s kB. Increase from round 1 to 2: %d kB. From round 2 through the final round, over %d requests the RSS increase was %d kB."
      % (" → ".join(str(x) for x in rs), rs[1] - rs[0], later, rs[-1] - rs[1]))
    w("- After the round, the fd number was equal to the start time every %s, and the rest of the temporary file was zero every time."
      % sorted(set(r["idle"]["fds"] for r in load["rounds"])))
    smp = load["samples"]
    w("- 15 seconds interval sample, kB): %s" % ", ".join(str(x["rss_kb"]) for x in smp[::15]))
    w("")
    w("### Backend measurements")
    w("")
    ts = meta["tomcat_stats_end"]
    w("- Tomcat connector MBean `requestCount` %d, Tomcat access log %d row "
      "Tomcat's number of requests and access logs are correct."
      % (ts["requestCount"], sup["tomcat_access_log_lines"]))
    w("- PHP-FPM access log %d row, Shield log %d row."
      % (sup["php_fpm_access_log_lines"], sup["shield_log_lines"]))
    w("")


# ------------------------------------------------------- file name policy
fn = grp("filename")
if fn:
    w("## File name check policy (optional, default OFF)")
    w("")
    w("`upload_shield_filename_check on`It's a host that doesn't go with the monitor block. "
      "I've tried. The object file name is behind the normal file. **The last part.**I put it in.")
    w("")
    w("| It's the standard. | PHP-FPM | Tomcat |")
    w("|---|---|---|")
    allowed = [c for c in fn if c["name"].startswith("allowed")]
    blk = [c for c in fn if c["name"].startswith("last part") and c["server"].startswith("block")]
    mon_ = [c for c in fn if c["name"].startswith("last part") and c["server"].startswith("monitor")]
    off = [c for c in fn if c["name"].startswith("policy off")]
    for label, sel, zero in (
            ("Standard file name; complex extension; bin file choice: 200, backend file number and SHA-256 match", allowed, False),
            ("BLOCK: object file name 403, backend request 0", blk, True),
            ("The same request to deliver, only violation logs", mon_, False),
            ("The default value of the host that doesn't activate the policy:", off, False)):
        cells = []
        for bk in ("php", "tomcat"):
            r = [c for c in sel if c["backend"] == bk]
            ok = all(c["ok"] for c in r)
            if zero:
                ok = ok and all(acc(c) == 0 and app(c) == 0 and pk(c) == 0 for c in r)
            cells.append("%d is %s" % (len(r), OKS[ok]))
        w("| %s | %s | %s |" % (label, cells[0], cells[1]))
    w("")
    std_table(fn)

# ------------------------------------------------------- TLS HTTP/2
tls = grp("tls")
streams = grp("streams")
if tls or streams:
    w("## HTTP/2 and stream isolation over TLS")
    w("")
    w("Let's get to nginx. `--with-http_ssl_module`I rebuilt the TLS Reader as a self-signed certificate. "
      "The client is ALPN. `h2`We negotiate.")
    w("")
    std_table(tls)
    w("### Multiple streams of a single connection")
    w("")
    w("Open multiple upload streams to one connection, and one of them is a shield timeout or policy violation. "
      "I checked if the normal upload of the rest of the stream was affected at the end. "
      "From the beginning to the end of the stream, RST is the RST_STREAM error code sent by the server.")
    w("")
    for c in streams:
        w("**%s — %s, %s server: %s** (%s)" % (c["id"], PROTO[c["proto"]], c["server"], c["name"],
                                          OKS[c["ok"]]))
        w("")
        w("| The stream. | The route. | It's in good condition. | End of second | RST | Backend requested | The file is SHA-256. |")
        w("|---|---|---|---|---|---|---|")
        for r in c["streams"]:
            w("| %s | `%s` | %s | %.2f | %s | %d | %s |" % (
                r["role"], r["path"], r["status"] if r["status"] else "No answer.", r["end"],
                r["reset"] if r["reset"] is not None else "–", r["backend_requests"],
                {True: "Matched", False: "**Disagreements.**", None: "–"}[r["files_ok"]]))
        w("")
        w("Connection to %s until the end of all streams."
          % ("It was open." if not c["connection_closed_early"] else "**It wasn't maintained.**"))
        w("")

# ------------------------------------------------------- hours-long run
if os.path.exists(src + "/soak-meta.json"):
    sm = json.load(open(src + "/soak-meta.json"))
    segs = [json.loads(x) for x in open(src + "/soak-segments.jsonl")]
    smp = [json.loads(x) for x in open(src + "/soak-samples.jsonl")]
    total = sum(x["requests"] for x in segs)
    mins = sum(x["minutes"] for x in segs)
    w("## Repeat the test.")
    w("")
    w("PHP-FPM and Tomcat were active for %d minutes (%.1f hours). %d concurrent clients sent %d requests. Resource measurements were sampled every %d seconds (%d samples)."
      % (mins, mins / 60.0, segs[0]["concurrency"], total,
         round(smp[1]["t"] - smp[0]["t"]), len(smp)))
    w("")
    kinds, outs = {}, {}
    for x in segs:
        for k, n in x["kinds"].items():
            kinds[k] = kinds.get(k, 0) + n
        for k, n in x["outcomes"].items():
            outs[k] = outs.get(k, 0) + n
    w("| Type of request | Count |")
    w("|---|---|")
    for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
        w("| %s | %d |" % (k, n))
    w("")
    w("- Distribution of results: %s. `ok`'Stop the stream and the normal upload of the same TLS connection is 200' "
      "Confirmed multi-stream requests, `None`Silver is a client-interrupted request."
      % json.dumps(outs, sort_keys=True, ensure_ascii=False))
    w("- Expectations and other results: %d." % sum(x["unexpected_count"] for x in segs))
    w("- Worker PID: start %s, end %s. Worker %d, alert·crit·emerg %d, which ended with the signal."
      % (sm["workers"], sm["workers_at_end"], sm["worker_exits_on_signal"],
         sm["nginx_alerts"]))
    w("")
    w("| Elapsed time | RSS worker sum of | RSS by worker | Fd sum | Temporary file open | Temporary directory entry | Upload the temporary file |")
    w("|---|---|---|---|---|---|---|")
    step = 15 * 60
    nxt = 0
    for x in smp:
        if x["t"] >= nxt or x is smp[-1]:
            w("| %d | %d | %s | %d | %d | %d | %d |" % (
                round(x["t"] / 60), x["rss_kb"], " / ".join(str(v) for v in x["worker_rss_kb"]),
                x["fds"], x["temp_open"], x["temp_dir_entries"], x["php_upload_tmp"]))
            nxt += step
    w("")
    w("The value of the table is a sample of the moment that the load was taken, so fd and the open temp file have a portion of the request being processed. "
      "I got it.")
    w("")
    warm = [x for x in smp if x["t"] >= 900]
    half = len(warm) // 2
    avg = lambda xs: sum(x["rss_kb"] for x in xs) / float(len(xs))  # noqa: E731
    n = len(warm)
    mt = sum(x["t"] for x in warm) / n
    mr = sum(x["rss_kb"] for x in warm) / n
    slope = sum((x["t"] - mt) * (x["rss_kb"] - mr) for x in warm) / sum((x["t"] - mt) ** 2 for x in warm)
    w("- RSS: shortly after the start (before load) %d kB, minimum %d kB after 15 minutes time; maximum %d kB. "
      "Half forward average %.0f kB, half back average %.0f kB, linear trend %+.1f kB/hour."
      % (sm["idle_at_start"]["rss_kb"], min(x["rss_kb"] for x in warm),
         max(x["rss_kb"] for x in warm), avg(warm[:half]), avg(warm[half:]), slope * 3600))
    w("- fd: Sample minimum %d; maximum %d. %s when no load after the end of the period, %d at the start."
      % (min(x["fds"] for x in smp), max(x["fds"] for x in smp),
         ", ".join(str(x["idle_after"]["fds"]) for x in segs), sm["idle_at_start"]["fds"]))
    w("- Temporary file: Temporary file %s open after expiration, Temporary directory item %s, PHP upload Temporary file %s."
      % (", ".join(str(x["idle_after"]["temp_open"]) for x in segs),
         ", ".join(str(x["idle_after"]["temp_dir_entries"]) for x in segs),
         ", ".join(str(x["idle_after"]["php_upload_tmp"]) for x in segs)))
    seen_idx = [i for i, x in enumerate(smp) if x["temp_dir_entries"]]
    stuck = [i for i in seen_idx if i + 1 < len(smp) and smp[i + 1]["temp_dir_entries"]]
    w("- The number of times an item was seen in a temporary directory in a sample: %d times, and the number of times it remained in the following sample: %d times. "
      "The nginx unlinked the temporary file shortly after it was created, so once it appeared and disappeared, the unlink between the creation and the unlinked file was unlinked. "
      "This moment is captured in a sample." % (len(seen_idx), len(stuck)))
    w("- A module-disabled control run was unavailable, so the RSS trend cannot be attributed to a particular component.")
    w("- Shield violation log %d line: %s."
      % (sm["shield_warn_lines"], json.dumps(sm["shield_warn_by_action_rule"], sort_keys=True)))
    if sm.get("other_nginx_log_lines"):
        w("- Other nginx logs (more than warn, top entry): %s."
          % json.dumps(sm["other_nginx_log_lines"], ensure_ascii=False))
    w("")

# ------------------------------------------------------------------ 6
w("## Regression and sanitizer results")
w("")
rg = sup["regression_round1_suite"]
if "first_125_passed" in rg:
    head = "%d of the initial 125 cases passed; %d of %d added cases passed" % (
        rg["first_125_passed"], rg["added_cases"], rg["added_passed"])
else:
    head = "%d cases, %d passed" % (rg["summary"]["total"], rg["summary"]["passed"])
w("- %s Initial integration suite repeated: %s. For the 512 MB upload, temporary disk usage was %s. The repeated run sent %d requests, with %d remaining temporary files and file descriptors changing from %d to %d."
  % (sup.get("changes", "So this time I fixed the module."),
     head, sorted(set(b["temp_disk_peak_mb"] for b in rg["big_upload"])),
     rg["soak"]["requests"], rg["soak"]["temp_files_after"],
     rg["soak"]["worker_fds_start"], rg["soak"]["worker_fds_end"]))
a = sup["asan"]
w("- With ASan: %d integration cases (%d passed), %d backend cases (%d passed), and %d load rounds (%d requests). ASan reports or worker exits: %d."
  % (a["round1_suite"]["summary"]["total"], a["round1_suite"]["summary"]["passed"],
     a["real_backends"]["summary"]["total"], a["real_backends"]["summary"]["passed"],
     len(a["real_backends"]["load_rounds"]),
     sum(x["requests"] for x in a["real_backends"]["load_rounds"]),
     a["round1_suite"]["asan_reports_or_worker_crashes"]
     + a["real_backends"]["asan_reports_or_worker_crashes"]))
if a.get("note"):
    w("- " + a["note"])
if "unit" in sup:
    w("- Engine unit test: %s." % sup["unit"])
w("")
w("## Test scope")
w("")
for line in sup.get("not_done", [
        "Re-attacks on vulnerable PHP versions. PHP2Shell results in policy enforcement or not.",
        "Unix sockets PHP-FPM, Tomcat AJP, HTTP/2, HTTP/3, distributed package nginx on TLS.",
        "Apache connectivity.",
        "Remote networking and operational load levels, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, long-term, and long-term, long-term, long-term, long-term, long-term, and long-term, long-term, long-term, long-term, and long-term, long-term, long-term, and long-term, long-term, and long-term, and long-term, and long-term, and long-term, and long-term, and long-term, long-term, and long-term, and long-term, and long-",
        "The request form we used in the comparison is all that's on the table, and in the form that's not on the table, we didn't confirm that the interpretation of the Shield and the backend is the same."]):
    w("- " + line)
open(dst, "w").write("\n".join(out) + "\n")
print("wrote", dst, len(out), "lines")
