#!/usr/bin/env python3
"""Builds docs/COMPARE-MODSECURITY.md from a run_compare.py results directory.
Tables and counts are read from results.json and requests/manifest.json."""
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src + "/results.json"))
man = {m["id"]: m for m in json.load(open(src + "/requests/manifest.json"))}
rows, meta = d["rows"], d["meta"]
v = meta["versions"]
out = []
w = out.append
CFG = ["A", "B1", "B2"]
NAME = {"A": "A. Kuipernet Upload", "B1": "B1. ModSecurity + pentestit rule",
        "B2": "B2. ModSecurity + Abstract Security rules"}
VERD = {"allow": "Allow me.", "deny": "Block it.", "n/a": "–"}


def get(rid, c):
    return [r for r in rows if r["id"] == rid and r["config"] == c][0]


ids = []
for r in rows:
    if r["id"] not in ids:
        ids.append(r["id"])

w("# Comparison of Kuipernet Upload and ModSecurity's upload protection behavior")
w("")
w("Source records: `%s/`. The comparison ran on an isolated loopback interface using harmless policy test requests." % src.rstrip("/"))
w("")
w("**This test measures policy enforcement before PHP-FPM delivery. It does not establish mitigation of CVE-2026-109618 or CVE-2026-109619.**")
w("")
w("## Summary")
w("")
w("| Constructing | The normal request is Otam. | Policy violation request blocked | Reach PHP-FPM through unblocked violation requests | Reach PHP-FPM from blocked requests |")
w("|---|---|---|---|---|")
for c in CFG:
    n = [r for r in rows if r["config"] == c and r["kind"] == "normal"]
    x = [r for r in rows if r["config"] == c and r["kind"] == "violation"]
    fp = [r for r in n if r["actual"] == "deny"]
    bl = [r for r in x if r["actual"] == "deny"]
    miss = [r for r in x if r["actual"] == "allow"]
    w("| %s | %d / %d%s | %d / %d | %d%s | %d |" % (
        NAME[c], len(fp), len(n), " (%s)" % ", ".join(r["id"] for r in fp) if fp else "",
        len(bl), len(x), sum(1 for r in miss if r["php_fpm_reached"]),
        " (%s)" % ", ".join(r["id"] for r in miss) if miss else "",
        sum(1 for r in bl if r["php_fpm_reached"])))
w("")
ok_sha = [r for r in rows if r["kind"] == "normal" and r["actual"] == "allow"
          and r["sha256_match"] is not None]
w("- SHA-256 and the number of fields in the file SHA-256 and the number of fields in the normal multipart request %d "
  "%s." % (len(ok_sha), "It matched." if all(r["sha256_match"] for r in ok_sha)
           else "**There's something that doesn't match.**"))
w("- \"Otam\" and \"Different\" are the judgments of the policy guidelines set by this test. "
  "The settings that you can adjust to express are adjusted, and the items that don't fit into the public rules are left. "
  "So the subdivision of B usually means \"there are no rules in that set of rules\".")
w("")

w("## Test configuration")
w("")
w("| Items | The value. |")
w("|---|---|")
w("| nginx | %s, all three configurations are the same binary (sha256 `%s…`) |" % (
    v["nginx"].split("\n")[0].replace("nginx version: ", ""), meta["sha256"]["nginx binary"][:16]))
w("| The nginx build option | `%s` |" % v["nginx"].split("configure arguments: ")[1].strip())
w("| PHP-FPM | %s, the Ubuntu package `%s`The three formats have the same PHP-FPM instance. |" % (
    v["php_fpm"], v["php_package"]))
w("| PHP patch status | The distribution changelog records the PHP2Shell backports for the 8.3.6 package. |")
ini = v["php_ini_defaults_before_pool_overrides"]
w("| Set up the PHP | php.ini: %s. From the FPM pool `upload_max_filesize=64M`, `post_max_size=128M`Cover it with a cloth. |"
  % ", ".join("`%s=%s`" % kv for kv in ini.items()))
w("| Module A | upload_shield 0.1.1 (sha256 `%s…`) |" % meta["sha256"]["upload_shield module"][:16])
w("| Engine of B. | libmodsecurity %s, ModSecurity-nginx connector v1.0.4 (sha256 `%s…`) |" % (
    v["libmodsecurity"], meta["sha256"]["modsecurity connector module"][:16]))
w("| Common nginx settings | `client_max_body_size 8m`, request buffering default on , `fastcgi_pass` TCP |")
w("")
w("### Tested policies")
w("")
w("| Policy | A. Kuipernet Upload | B1. rule of pentestit | B2. Abstract security rules |")
w("|---|---|---|---|")
w("| Forbidden foam field`PHP_SESSION_UPLOAD_PROGRESS`) | `upload_shield_deny_session_progress on` | The rule is 1026109618 (deny 403) | Rule 3201004 only records the design. |")
w("| One file size is 1 MB | `upload_shield_max_file_size 1m` | There are no rules. | There are no rules. |")
w("| It's not an uploaded route.`/page.php`of the multipart). | `upload_shield_deny_multipart on` | Rule 1026109620 (deny 415), allow the route `/upload.php`It's called | There are no rules. |")
w("| Full text 2 MB | `upload_shield_max_body_size 2m` | `SecRequestBodyLimit 2097152` + `Reject` | It's the same. |")
w("| It's on the outside. | Multipart structural inspection and basic limitation | `modsecurity.conf-recommended`The basic rules of 200000 to 200005, etc. `SecRequestBodyNoFilesLimit 131072` | And then the rules are 3201001 to 3201003. |")
w("")
w("### Source and version of rules and settings")
w("")
w("| The file. | Source and version | sha256 |")
w("|---|---|---|")
w("| `config/modsecurity-base.conf` | ModSecurity v3.0.12 is a storage device. `modsecurity.conf-recommended`Apply the following adjustments to | `%s…` |" % meta["sha256"]["modsecurity-base.conf"][:16])
w("| `config/php2shell-pentestit.conf` | This is a list of the most commonly used types of pentestit.com articles. | `%s…` |" % meta["sha256"]["php2shell-pentestit.conf"][:16])
w("| `config/php2shell-abstract.conf` | Abstract Security article ((2026-10-21 posted, 10-22 updated, 2026-11-20 open) of the rules 3201001 to 3201004, rev 2, ver 20261021 | `%s…` |" % meta["sha256"]["php2shell-abstract.conf"][:16])
w("")
w("Change the string in the setup:")
w("")
for a, b in meta["modsecurity_base_edits"]:
    w("- `%s` → `%s`" % (a, b.replace(src.rstrip("/"), "…")))
w("")
w("Changes to the public rules:")
w("")
w("- Example of the permissible path of rule 1026109620`^/wp-admin/(?:async-upload|media-new)\\.php$`This test "
  "Upload path to the site `^/upload\\.php$`It's the part where I'm guided to make the writing myself.")
w("- The published Abstract Security rules did not load on libmodsecurity 3.0.12. Quoting the `ver:'20261021'` action resolved the load error.")
w("")

w("## Result")
w("")
w("The actual response is HTTP status code, \"PHP reach\" is the PHP-FPM access log. "
  "If you catch any of the kernel packet counters, `yes`SHA-256 is the number of files and fields received by PHP. "
  "It's a contrast to the original.")
w("")
for kind, title in (("normal", "Normal upload (example: allowed)"),
                    ("violation", "Innocence policy violation (example judgment: blocked)"),
                    ("reference", "Note: Public policy is targeted, but A has no policy.")):
    w("### " + title)
    w("")
    w("| ID | Requested | The protocol | Constructing | Expected | The real answer. | Judgment. | Blocking rules. | PHP reach | SHA-256 |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for rid in ids:
        if get(rid, "A")["kind"] != kind:
            continue
        m = man[rid]
        for c in CFG:
            r = get(rid, c)
            mark = {True: "As expected.", False: "**Expectations and variations**", None: "–"}[r["as_expected"]]
            w("| %s | %s | %s%s | %s | %s | %s (%s) | %s | %s | %s | %s |" % (
                rid if c == "A" else "", r["name"] if c == "A" else "",
                m["protocol"] if c == "A" else "",
                ("" if m["length_declared"] else "The path, the uncertainty.") if c == "A" else "",
                c, VERD[r["expected"]], r["status"], VERD[r["actual"]], mark,
                "; ".join(r["rules"]) or "–", "Yes" if r["php_fpm_reached"] else "No",
                {True: "Matched", False: "**Disagreements.**", None: "–"}[r["sha256_match"]]))
    w("")

w("## Cases with differing outcomes")
w("")
w("| ID | A | B1 | B2 | The rules that made the difference. |")
w("|---|---|---|---|---|")
WHY = {
    "N12": "`modsecurity.conf-recommended`of the `SecRequestBodyNoFilesLimit 131072`If a text that isn't a file is more than 128 kB, it's a text processing error, and the default rule 200002 is rejected as 400. It's an engine default that's inconsistent with the PHP2Shell rule. A doesn't check the urlencoded text.",
    "V01": "B2's rule 3201004 is written to block the progress field, not just record it.",
    "V02": "It's like V01.",
    "V03": "It's like V01.",
    "V04": "ModSecurity Recommended Settings and two Open Rule Sets have no items limiting one file size.`SecRequestBodyLimit`And then there's a. `upload_shield_max_file_size`I decided.",
    "V05": "B1 is the rule 1026109620 ((refuse the multipart outside the permissible path to 415), A is the `upload_shield_deny_multipart`The rule set of B2 has no path-based multipart blocking.",
    "V06": "It's like V05.",
    "X01": "Rule 3201001 of B2 is the name of the form field `PHPSESSID`A and B1 have no policy.",
    "X02": "B2's rule 3201003 -- if you have a string that looks like a file name alignment phrase -- refuses. A didn't activate the file name check policy, and even if it does, this form isn't subject to A's rule.",
}
for rid in ids:
    acts = [get(rid, c)["actual"] for c in CFG]
    if len(set(acts)) > 1:
        w("| %s | %s | %s | %s | %s |" % (
            rid, *["%s (%s)" % (VERD[get(rid, c)["actual"]], get(rid, c)["status"]) for c in CFG],
            WHY.get(rid, "**No explanation**")))
w("")
w("It's the same sentence, but if the answer is different:")
w("")
w("- The whole excess of this is: A is 413, and B is 403. "
  "Engine setting `SecRequestBodyLimitAction Reject`There's no rule ID left in the log. All three configurations are "
  "It didn't reach PHP-FPM, whether it was Content-Length or HTTP/2.")
w("- V05, V06): A is 403, B1 is 415 in the rules.")
w("")

w("## Distinguishing between the scope of policy implementation identified and the mitigation effect of CVE")
w("")
w("What this test confirmed:")
w("")
w("- Whether the request for the result table in each configuration reached PHP-FPM.")
w("- Whether the file of the normal upload is the same as the original.")
w("- In the lower nginx PHP-FPM ModSecurity version and settings. Other versions, different ruleboards, tables "
  "The composition that wrote the OWASP CRS together was not tested.")
w("")
w("What this test didn't confirm:")
w("")
w("- **None of the configurations have been confirmed to block CVE-2026-109618 or CVE-2026-109619 yet.** "
  "And the PHP that you wrote in the test, which you didn't send an attack request, is a patched build of two CVEs.")
w("- The PHP baseline value of `session.upload_progress.enabled` was `%s`. This comparison records field policy enforcement before delivery."
  % ini["session.upload_progress.enabled"])
w("- The progress field blocking only targets the request form used in the verified session path of CVE-2026-109619, "
  "There is an analysis that other variations of PHP revealed and CVE-2026-109618 (urlencoded text) can also be triggered. "
  "It doesn't. `docs/PHP2SHELL.md`It's the same as the A.")
w("- Parser behavior across input variants requires a separate comparison.")
w("")
w("## Test artifacts")
w("")
w("| The data. | Location |")
w("|---|---|")
w("| Test requests and lists | `%s/requests/` (`manifest.json`In the direction of the header SHA-256) |" % src.rstrip("/"))
w("| Applied settings and rules files | `%s/config/` |" % src.rstrip("/"))
w("| The original log. | `%s/`of the `nginx-a-error.log`, `nginx-b-error.log`, `modsec_audit.log`, `php-fpm-access.log`, `php-app.jsonl` |" % src.rstrip("/"))
w("| Request results and logs. | `%s/results.json` |" % src.rstrip("/"))
w("| Testing tools | `tests/compare/run_compare.py` |")
open(dst, "w").write("\n".join(out) + "\n")
print("wrote", dst, len(out))
