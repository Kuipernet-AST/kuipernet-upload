# Upload policy comparison with ModSecurity

The same 23 harmless HTTP test cases were sent to three configurations on Nginx 1.30.0. All three used the same patched Ubuntu PHP-FPM 8.3.6 package, buffered FastCGI over TCP, and an Nginx body limit of 8 MB. The ModSecurity cases used libmodsecurity 3.0.12-1.1build2 and the ModSecurity-nginx v1.0.4 connector.

| Configuration | Normal requests incorrectly blocked | Policy violations blocked | Unblocked violations reaching PHP-FPM | Blocked requests reaching PHP-FPM |
|---|---|---|---|---|
| A · Kuipernet Upload | 0 / 12 | 9 / 9 | 0 | 0 |
| B1 · ModSecurity with pentestit rules | 1 / 12 | 8 / 9 | 1 | 0 |
| B2 · ModSecurity with Abstract Security rules | 1 / 12 | 3 / 9 | 6 | 0 |

The 30 forwarded normal multipart requests matched the original file hashes and field counts. The 69-case rerun with the rc2 module returned the same per-case status, policy verdict, rule, backend delivery result, and hashes.

## Policies tested

| Policy | A | B1 | B2 |
|---|---|---|---|
| PHP session upload progress field | MGUS-301 blocks | Rule 1026109618 blocks | Rule 3201004 logs |
| 1 MB per-file limit | Enabled | No corresponding rule | No corresponding rule |
| Multipart on a route without uploads | MGUS-302 blocks | Rule 1026109620 blocks outside the configured upload path | No corresponding rule |
| 2 MB total body limit | Enabled | `SecRequestBodyLimit 2097152`, action Reject | Same as B1 |

Both ModSecurity configurations used the recommended rules with the engine set to `On`, a reduced body limit, and `SecResponseBodyAccess Off`. The common `SecRequestBodyNoFilesLimit 131072` rejected a normal 200 kB text field in both configurations. The pentestit allowlist was set to the test upload route. The Abstract Security rules used revision 2, version 20261021. The version action was quoted to load on libmodsecurity 3.0.12. Those rules also cover cases that configuration A does not implement, such as PHPSESSID form-field and serialized-looking filename checks.

The results describe these settings and rulesets. The test did not establish mitigation of either PHP2Shell CVE.

The current runner uses a neutral filler string. A new run computes new payload hashes. The results below describe the recorded rc1 and rc2 runs.

## Case results

| Case | Scenario | Protocol | Setup | Expected | Observed | Verdict | Matched rule | PHP-FPM delivery | Integrity |
|---|---|---|---|---|---|---|---|---|---|
| N01 | multi-file upload (3 files under f[], 2 fields) | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N01 | multi-file upload (3 files under f[], 2 fields) | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N01 | multi-file upload (3 files under f[], 2 fields) | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N02 | empty file selection beside a real file | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N02 | empty file selection beside a real file | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N02 | empty file selection beside a real file | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N03 | empty file selection only | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N03 | empty file selection only | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N03 | empty file selection only | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N04 | multi-extension file names | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N04 | multi-extension file names | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N04 | multi-extension file names | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N05 | forbidden field name appears as an ordinary form VALUE | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N05 | forbidden field name appears as an ordinary form VALUE | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N05 | forbidden field name appears as an ordinary form VALUE | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N06 | forbidden field name appears inside FILE CONTENT | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N06 | forbidden field name appears inside FILE CONTENT | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N06 | forbidden field name appears inside FILE CONTENT | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N07 | field whose name merely contains the forbidden name | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N07 | field whose name merely contains the forbidden name | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N07 | field whose name merely contains the forbidden name | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N08 | upload without Content-Length (chunked), 0.5 MB | HTTP/1.1, length omitted | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N08 | upload without Content-Length (chunked), 0.5 MB | HTTP/1.1, length omitted | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N08 | upload without Content-Length (chunked), 0.5 MB | HTTP/1.1, length omitted | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N09 | 1.9 MB upload, each file under 1 MB | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N09 | 1.9 MB upload, each file under 1 MB | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N09 | 1.9 MB upload, each file under 1 MB | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N10 | multi-file upload over HTTP/2 | HTTP/2 (cleartext) | A | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N10 | multi-file upload over HTTP/2 | HTTP/2 (cleartext) | B1 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N10 | multi-file upload over HTTP/2 | HTTP/2 (cleartext) | B2 | Allow | 200 (Allow) | As expected | – | Yes | Match |
| N11 | ordinary urlencoded form to the no-upload path | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | – |
| N11 | ordinary urlencoded form to the no-upload path | HTTP/1.1 | B1 | Allow | 200 (Allow) | As expected | – | Yes | – |
| N11 | ordinary urlencoded form to the no-upload path | HTTP/1.1 | B2 | Allow | 200 (Allow) | As expected | – | Yes | – |
| N12 | urlencoded form with a 200 kB text value (no files) | HTTP/1.1 | A | Allow | 200 (Allow) | As expected | – | Yes | – |
| N12 | urlencoded form with a 200 kB text value (no files) | HTTP/1.1 | B1 | Allow | 400 (Block) | **Unexpected** | 200002 (deny) | No | – |
| N12 | urlencoded form with a 200 kB text value (no files) | HTTP/1.1 | B2 | Allow | 400 (Block) | **Unexpected** | 200002 (deny) | No | – |
| V01 | forbidden form field as the last part | HTTP/1.1 | A | Block | 403 (Block) | As expected | MGUS-301 denied_field (block) | No | – |
| V01 | forbidden form field as the last part | HTTP/1.1 | B1 | Block | 403 (Block) | As expected | 1026109618 (deny) | No | – |
| V01 | forbidden form field as the last part | HTTP/1.1 | B2 | Block | 200 (Allow) | **Unexpected** | 3201004 (log) | Yes | Match |
| V02 | forbidden form field only | HTTP/1.1 | A | Block | 403 (Block) | As expected | MGUS-301 denied_field (block) | No | – |
| V02 | forbidden form field only | HTTP/1.1 | B1 | Block | 403 (Block) | As expected | 1026109618 (deny) | No | – |
| V02 | forbidden form field only | HTTP/1.1 | B2 | Block | 200 (Allow) | **Unexpected** | 3201004 (log) | Yes | Match |
| V03 | forbidden form field as the last part, HTTP/2 | HTTP/2 (cleartext) | A | Block | 403 (Block) | As expected | MGUS-301 denied_field (block) | No | – |
| V03 | forbidden form field as the last part, HTTP/2 | HTTP/2 (cleartext) | B1 | Block | 403 (Block) | As expected | 1026109618 (deny) | No | – |
| V03 | forbidden form field as the last part, HTTP/2 | HTTP/2 (cleartext) | B2 | Block | 200 (Allow) | **Unexpected** | 3201004 (log) | Yes | Match |
| V04 | last part: one file over the 1 MB per-file limit (total 1.4 MB) | HTTP/1.1 | A | Block | 413 (Block) | As expected | MGUS-202 file_size (block) | No | – |
| V04 | last part: one file over the 1 MB per-file limit (total 1.4 MB) | HTTP/1.1 | B1 | Block | 200 (Allow) | **Unexpected** | – | Yes | Match |
| V04 | last part: one file over the 1 MB per-file limit (total 1.4 MB) | HTTP/1.1 | B2 | Block | 200 (Allow) | **Unexpected** | – | Yes | Match |
| V05 | multipart upload to the no-upload path | HTTP/1.1 | A | Block | 403 (Block) | As expected | MGUS-302 multipart_denied (block) | No | – |
| V05 | multipart upload to the no-upload path | HTTP/1.1 | B1 | Block | 415 (Block) | As expected | 1026109620 (deny) | No | – |
| V05 | multipart upload to the no-upload path | HTTP/1.1 | B2 | Block | 200 (Allow) | **Unexpected** | – | Yes | Match |
| V06 | multipart without files to the no-upload path | HTTP/1.1 | A | Block | 403 (Block) | As expected | MGUS-302 multipart_denied (block) | No | – |
| V06 | multipart without files to the no-upload path | HTTP/1.1 | B1 | Block | 415 (Block) | As expected | 1026109620 (deny) | No | – |
| V06 | multipart without files to the no-upload path | HTTP/1.1 | B2 | Block | 200 (Allow) | **Unexpected** | – | Yes | Match |
| V07 | no Content-Length (chunked): body 2.6 MB over the 2 MB limit | HTTP/1.1, length omitted | A | Block | 413 (Block) | As expected | MGUS-401 body_size (block) | No | – |
| V07 | no Content-Length (chunked): body 2.6 MB over the 2 MB limit | HTTP/1.1, length omitted | B1 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| V07 | no Content-Length (chunked): body 2.6 MB over the 2 MB limit | HTTP/1.1, length omitted | B2 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| V08 | no content-length (HTTP/2): body 2.6 MB over the 2 MB limit | HTTP/2 (cleartext), length omitted | A | Block | 413 (Block) | As expected | MGUS-401 body_size (block) | No | – |
| V08 | no content-length (HTTP/2): body 2.6 MB over the 2 MB limit | HTTP/2 (cleartext), length omitted | B1 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| V08 | no content-length (HTTP/2): body 2.6 MB over the 2 MB limit | HTTP/2 (cleartext), length omitted | B2 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| V09 | Content-Length declared: body 2.6 MB over the 2 MB limit | HTTP/1.1 | A | Block | 413 (Block) | As expected | MGUS-401 body_size (block) | No | – |
| V09 | Content-Length declared: body 2.6 MB over the 2 MB limit | HTTP/1.1 | B1 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| V09 | Content-Length declared: body 2.6 MB over the 2 MB limit | HTTP/1.1 | B2 | Block | 403 (Block) | As expected | SecRequestBodyLimit + SecRequestBodyLimitAction Reject (engine setting, no rule id) | No | – |
| X01 | form field named PHPSESSID with a harmless value | HTTP/1.1 | A | – | 200 (Allow) | – | – | Yes | Match |
| X01 | form field named PHPSESSID with a harmless value | HTTP/1.1 | B1 | – | 200 (Allow) | – | – | Yes | Match |
| X01 | form field named PHPSESSID with a harmless value | HTTP/1.1 | B2 | – | 403 (Block) | – | 3201001 (deny) | No | – |
| X02 | file name containing serialized-array-like text | HTTP/1.1 | A | – | 200 (Allow) | – | – | Yes | Match |
| X02 | file name containing serialized-array-like text | HTTP/1.1 | B1 | – | 200 (Allow) | – | – | Yes | Match |
| X02 | file name containing serialized-array-like text | HTTP/1.1 | B2 | – | 403 (Block) | – | 3201003 (deny) | No | – |
