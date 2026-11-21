# Release-candidate backend validation

The rc1 run passed all 268 cases on Nginx 1.30.0 with PHP-FPM 8.3.6 and Tomcat 10.1.55, including all 194 previous cases and 74 additions. The rc2 module subsequently passed all 268 backend and 128 integration cases in standard and AddressSanitizer builds. The rc2 load run on Nginx 1.30.0 lasted 30 minutes and completed 93,514 cases with zero unexpected outcomes and zero worker exits.

| Area | Observation |
|---|---|
| Filename policy | 16 normal-name cases forwarded. All 22 BLOCK cases produced zero backend requests. |
| TLS and HTTP/2 | The timeout terminated the affected stream. Other uploads on the same connection completed successfully. |
| Three-hour run (rc1) | 570,242 test cases, no unexpected results or worker restarts. After the load, the descriptor count returned to 32 and no temporary files remained. |
| RSS trend (rc1) | From minute 15 onward, total worker RSS ranged from 17,940 to 18,136 kB, with a fitted slope of +56.6 kB per hour. The run had no module-disabled control for attribution. |
| Older Nginx three-hour run (rc2) | See the separate [Ubuntu 18.04 report](SOAK-UBUNTU1804.md). |

For the same-connection TLS tests, the active stream and the upload started after expiry both returned HTTP 200 with the expected content. The limit and timeout configuration is covered in the [settings reference](SIZE-TIMEOUT-CONTRACT.md). The PHP2Shell cases exercised policy enforcement.

## Case results

| Case | Mode | Protocol | Backend | Scenario | HTTP status | Action | Rule | Access log entries | Application records | Packets | Body or parsed result | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E001 | off | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | – | – | 1 | 1 | 26 | 3 files, 2 fields | Passed |
| E002 | off | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | – | – | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E003 | off | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | – | – | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E004 | monitor | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E005 | monitor | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E006 | monitor | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E007 | block | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E008 | block | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E009 | block | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E010 | monitor | HTTP/1.1 | PHP-FPM | last part: file over 4m limit | 200 | monitor | MGUS-202 | 1 | 1 | 80 | 2 files, 1 fields | Passed |
| E011 | block | HTTP/1.1 | PHP-FPM | last part: file over 4m limit | 413 | block | MGUS-202 | 0 | 0 | 0 | – | Passed |
| E012 | block | HTTP/2 | PHP-FPM | last part: file over 4m limit | 413 | block | MGUS-202 | 0 | 0 | 0 | – | Passed |
| E013 | monitor | HTTP/1.1 | PHP-FPM | last part: 7th file (limit 6) | 200 | monitor | MGUS-203 | 1 | 1 | 13 | 7 files, 0 fields | Passed |
| E014 | block | HTTP/1.1 | PHP-FPM | last part: 7th file (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E015 | block | HTTP/2 | PHP-FPM | last part: 7th file (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E016 | monitor | HTTP/1.1 | PHP-FPM | last part: session progress field | 200 | monitor | MGUS-301 | 1 | 1 | 12 | 1 files, 2 fields | Passed |
| E017 | block | HTTP/1.1 | PHP-FPM | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E018 | block | HTTP/2 | PHP-FPM | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E019 | monitor | HTTP/1.1 | PHP-FPM | last part: form field over 64k | 200 | monitor | MGUS-205 | 1 | 1 | 13 | 1 files, 1 fields | Passed |
| E020 | block | HTTP/1.1 | PHP-FPM | last part: form field over 64k | 413 | block | MGUS-205 | 0 | 0 | 0 | – | Passed |
| E021 | block | HTTP/2 | PHP-FPM | last part: form field over 64k | 413 | block | MGUS-205 | 0 | 0 | 0 | – | Passed |
| E022 | monitor | HTTP/1.1 | PHP-FPM | end of body: closing boundary missing | 200 | monitor | MGUS-105 | 1 | 1 | 12 | 1 files, 1 fields | Passed |
| E023 | block | HTTP/1.1 | PHP-FPM | end of body: closing boundary missing | 400 | block | MGUS-105 | 0 | 0 | 0 | – | Passed |
| E024 | block | HTTP/2 | PHP-FPM | end of body: closing boundary missing | 400 | block | MGUS-105 | 0 | 0 | 0 | – | Passed |
| E025 | off | HTTP/1.1 | Tomcat | normal multi-file upload | 200 | – | – | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E026 | off | HTTP/1.1 | Tomcat | normal multi-file upload (chunked) | 200 | – | – | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E027 | off | HTTP/2 | Tomcat | normal multi-file upload | 200 | – | – | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E028 | monitor | HTTP/1.1 | Tomcat | normal multi-file upload | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E029 | monitor | HTTP/1.1 | Tomcat | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E030 | monitor | HTTP/2 | Tomcat | normal multi-file upload | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E031 | block | HTTP/1.1 | Tomcat | normal multi-file upload | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E032 | block | HTTP/1.1 | Tomcat | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E033 | block | HTTP/2 | Tomcat | normal multi-file upload | 200 | pass | none | 1 | 1 | 25 | 3 files, 2 fields | Passed |
| E034 | monitor | HTTP/1.1 | Tomcat | last part: file over 4m limit | 200 | monitor | MGUS-202 | 1 | 1 | 88 | 2 files, 1 fields | Passed |
| E035 | block | HTTP/1.1 | Tomcat | last part: file over 4m limit | 413 | block | MGUS-202 | 0 | 0 | 0 | – | Passed |
| E036 | block | HTTP/2 | Tomcat | last part: file over 4m limit | 413 | block | MGUS-202 | 0 | 0 | 0 | – | Passed |
| E037 | monitor | HTTP/1.1 | Tomcat | last part: 7th file (limit 6) | 200 | monitor | MGUS-203 | 1 | 1 | 14 | 7 files, 0 fields | Passed |
| E038 | block | HTTP/1.1 | Tomcat | last part: 7th file (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E039 | block | HTTP/2 | Tomcat | last part: 7th file (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E040 | monitor | HTTP/1.1 | Tomcat | last part: session progress field | 200 | monitor | MGUS-301 | 1 | 1 | 13 | 1 files, 2 fields | Passed |
| E041 | block | HTTP/1.1 | Tomcat | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E042 | block | HTTP/2 | Tomcat | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E043 | monitor | HTTP/1.1 | Tomcat | last part: form field over 64k | 200 | monitor | MGUS-205 | 1 | 1 | 14 | 1 files, 1 fields | Passed |
| E044 | block | HTTP/1.1 | Tomcat | last part: form field over 64k | 413 | block | MGUS-205 | 0 | 0 | 0 | – | Passed |
| E045 | block | HTTP/2 | Tomcat | last part: form field over 64k | 413 | block | MGUS-205 | 0 | 0 | 0 | – | Passed |
| E046 | monitor | HTTP/1.1 | Tomcat | end of body: closing boundary missing | 400 | monitor | MGUS-105 | 1 | 1 | 13 | 0 files, 0 fields | Passed |
| E047 | block | HTTP/1.1 | Tomcat | end of body: closing boundary missing | 400 | block | MGUS-105 | 0 | 0 | 0 | – | Passed |
| E048 | block | HTTP/2 | Tomcat | end of body: closing boundary missing | 400 | block | MGUS-105 | 0 | 0 | 0 | – | Passed |
| E135 | off | HTTP/1.1 | PHP-FPM | no-upload path, shield off: multipart with 2 files | 200 | – | – | 1 | 1 | 10 | 2 files, 0 fields | Passed |
| E136 | block | HTTP/1.1 | PHP-FPM | no-upload path: normal multipart is inspected | 200 | pass | none | 1 | 1 | 10 | 2 files, 0 fields | Passed |
| E137 | block | HTTP/2 | PHP-FPM | no-upload path: normal multipart is inspected | 200 | pass | none | 1 | 1 | 10 | 2 files, 0 fields | Passed |
| E138 | monitor | HTTP/1.1 | PHP-FPM | no-upload path: progress field, last part | 200 | monitor | MGUS-301 | 1 | 1 | 10 | 1 files, 2 fields | Passed |
| E139 | block | HTTP/1.1 | PHP-FPM | no-upload path: progress field, last part | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E140 | block | HTTP/2 | PHP-FPM | no-upload path: progress field, last part | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E141 | monitor | HTTP/1.1 | PHP-FPM | no-upload path: progress field only | 200 | monitor | MGUS-301 | 1 | 1 | 5 | 0 files, 1 fields | Passed |
| E142 | block | HTTP/1.1 | PHP-FPM | no-upload path: progress field only | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E143 | block | HTTP/2 | PHP-FPM | no-upload path: progress field only | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E144 | monitor | HTTP/1.1 | PHP-FPM | no-upload path: 7 files (limit 6) | 200 | monitor | MGUS-203 | 1 | 1 | 10 | 7 files, 0 fields | Passed |
| E145 | block | HTTP/1.1 | PHP-FPM | no-upload path: 7 files (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E146 | block | HTTP/2 | PHP-FPM | no-upload path: 7 files (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E147 | block | HTTP/1.1 | PHP-FPM | urlencoded body with the same field name (outside the module's scope) | 200 | – | – | 1 | 1 | 5 | 0 files, 2 fields | Passed |
| E148 | off | HTTP/1.1 | Tomcat | no-upload path, shield off: multipart with 2 files | 200 | – | – | 1 | 1 | 11 | 151330 body bytes | Passed |
| E149 | block | HTTP/1.1 | Tomcat | no-upload path: normal multipart is inspected | 200 | pass | none | 1 | 1 | 11 | 151330 body bytes | Passed |
| E150 | block | HTTP/2 | Tomcat | no-upload path: normal multipart is inspected | 200 | pass | none | 1 | 1 | 11 | 151330 body bytes | Passed |
| E151 | monitor | HTTP/1.1 | Tomcat | no-upload path: progress field, last part | 200 | monitor | MGUS-301 | 1 | 1 | 11 | 150388 body bytes | Passed |
| E152 | block | HTTP/1.1 | Tomcat | no-upload path: progress field, last part | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E153 | block | HTTP/2 | Tomcat | no-upload path: progress field, last part | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E154 | monitor | HTTP/1.1 | Tomcat | no-upload path: progress field only | 200 | monitor | MGUS-301 | 1 | 1 | 6 | 157 body bytes | Passed |
| E155 | block | HTTP/1.1 | Tomcat | no-upload path: progress field only | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E156 | block | HTTP/2 | Tomcat | no-upload path: progress field only | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E157 | monitor | HTTP/1.1 | Tomcat | no-upload path: 7 files (limit 6) | 200 | monitor | MGUS-203 | 1 | 1 | 11 | 141035 body bytes | Passed |
| E158 | block | HTTP/1.1 | Tomcat | no-upload path: 7 files (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E159 | block | HTTP/2 | Tomcat | no-upload path: 7 files (limit 6) | 403 | block | MGUS-203 | 0 | 0 | 0 | – | Passed |
| E160 | block | HTTP/1.1 | Tomcat | urlencoded body with the same field name (outside the module's scope) | 200 | – | – | 1 | 1 | 6 | 37 body bytes | Passed |
| E195 | block+filename | HTTP/1.1 | PHP-FPM | allowed: ordinary and multi-extension names | 200 | pass | none | 1 | 1 | 7 | 6 files, 1 fields | Passed |
| E196 | block+filename | HTTP/2 | PHP-FPM | allowed: ordinary and multi-extension names | 200 | pass | none | 1 | 1 | 7 | 6 files, 1 fields | Passed |
| E197 | block+filename | HTTP/1.1 | PHP-FPM | allowed: no extension, dot file, look-alikes, empty file selection | 200 | pass | none | 1 | 1 | 6 | 6 files, 1 fields | Passed |
| E198 | block+filename | HTTP/2 | PHP-FPM | allowed: no extension, dot file, look-alikes, empty file selection | 200 | pass | none | 1 | 1 | 6 | 6 files, 1 fields | Passed |
| E199 | block+filename | HTTP/1.1 | PHP-FPM | allowed: empty file selection only | 200 | pass | none | 1 | 1 | 5 | 1 files, 1 fields | Passed |
| E200 | block+filename | HTTP/2 | PHP-FPM | allowed: empty file selection only | 200 | pass | none | 1 | 1 | 5 | 1 files, 1 fields | Passed |
| E201 | block+filename | HTTP/1.1 | PHP-FPM | allowed: zero-byte file with an ordinary name | 200 | pass | none | 1 | 1 | 5 | 1 files, 0 fields | Passed |
| E202 | block+filename | HTTP/2 | PHP-FPM | allowed: zero-byte file with an ordinary name | 200 | pass | none | 1 | 1 | 5 | 1 files, 0 fields | Passed |
| E203 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named shell.php | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E204 | block+filename | HTTP/1.1 | PHP-FPM | last part named shell.php | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E205 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named SHELL.PhP | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E206 | block+filename | HTTP/1.1 | PHP-FPM | last part named SHELL.PhP | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E207 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named shell.php.jpg | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E208 | block+filename | HTTP/1.1 | PHP-FPM | last part named shell.php.jpg | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E209 | block+filename | HTTP/2 | PHP-FPM | last part named shell.php.jpg | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E210 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named a.tar.phtml.gz | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E211 | block+filename | HTTP/1.1 | PHP-FPM | last part named a.tar.phtml.gz | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E212 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named .htaccess | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E213 | block+filename | HTTP/1.1 | PHP-FPM | last part named .htaccess | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E214 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named page.jsp | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E215 | block+filename | HTTP/1.1 | PHP-FPM | last part named page.jsp | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E216 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named a.php. | 200 | monitor | MGUS-311 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E217 | block+filename | HTTP/1.1 | PHP-FPM | last part named a.php. | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E218 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named ../up/a.txt | 200 | monitor | MGUS-312 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E219 | block+filename | HTTP/1.1 | PHP-FPM | last part named ../up/a.txt | 403 | block | MGUS-312 | 0 | 0 | 0 | – | Passed |
| E220 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named a.txt. | 200 | monitor | MGUS-312 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E221 | block+filename | HTTP/1.1 | PHP-FPM | last part named a.txt. | 403 | block | MGUS-312 | 0 | 0 | 0 | – | Passed |
| E222 | monitor+filename | HTTP/1.1 | PHP-FPM | last part named 256-byte name | 200 | monitor | MGUS-313 | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E223 | block+filename | HTTP/1.1 | PHP-FPM | last part named 256-byte name | 403 | block | MGUS-313 | 0 | 0 | 0 | – | Passed |
| E224 | block | HTTP/1.1 | PHP-FPM | policy off (default): last part named shell.php.jpg | 200 | pass | none | 1 | 1 | 9 | 2 files, 1 fields | Passed |
| E225 | block+filename | HTTP/1.1 | Tomcat | allowed: ordinary and multi-extension names | 200 | pass | none | 1 | 1 | 8 | 6 files, 1 fields | Passed |
| E226 | block+filename | HTTP/2 | Tomcat | allowed: ordinary and multi-extension names | 200 | pass | none | 1 | 1 | 8 | 6 files, 1 fields | Passed |
| E227 | block+filename | HTTP/1.1 | Tomcat | allowed: no extension, dot file, look-alikes, empty file selection | 200 | pass | none | 1 | 1 | 7 | 6 files, 1 fields | Passed |
| E228 | block+filename | HTTP/2 | Tomcat | allowed: no extension, dot file, look-alikes, empty file selection | 200 | pass | none | 1 | 1 | 7 | 6 files, 1 fields | Passed |
| E229 | block+filename | HTTP/1.1 | Tomcat | allowed: empty file selection only | 200 | pass | none | 1 | 1 | 6 | 1 files, 1 fields | Passed |
| E230 | block+filename | HTTP/2 | Tomcat | allowed: empty file selection only | 200 | pass | none | 1 | 1 | 6 | 1 files, 1 fields | Passed |
| E231 | block+filename | HTTP/1.1 | Tomcat | allowed: zero-byte file with an ordinary name | 200 | pass | none | 1 | 1 | 6 | 1 files, 0 fields | Passed |
| E232 | block+filename | HTTP/2 | Tomcat | allowed: zero-byte file with an ordinary name | 200 | pass | none | 1 | 1 | 6 | 1 files, 0 fields | Passed |
| E233 | monitor+filename | HTTP/1.1 | Tomcat | last part named shell.php | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E234 | block+filename | HTTP/1.1 | Tomcat | last part named shell.php | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E235 | monitor+filename | HTTP/1.1 | Tomcat | last part named SHELL.PhP | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E236 | block+filename | HTTP/1.1 | Tomcat | last part named SHELL.PhP | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E237 | monitor+filename | HTTP/1.1 | Tomcat | last part named shell.php.jpg | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E238 | block+filename | HTTP/1.1 | Tomcat | last part named shell.php.jpg | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E239 | block+filename | HTTP/2 | Tomcat | last part named shell.php.jpg | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E240 | monitor+filename | HTTP/1.1 | Tomcat | last part named a.tar.phtml.gz | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E241 | block+filename | HTTP/1.1 | Tomcat | last part named a.tar.phtml.gz | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E242 | monitor+filename | HTTP/1.1 | Tomcat | last part named .htaccess | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E243 | block+filename | HTTP/1.1 | Tomcat | last part named .htaccess | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E244 | monitor+filename | HTTP/1.1 | Tomcat | last part named page.jsp | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E245 | block+filename | HTTP/1.1 | Tomcat | last part named page.jsp | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E246 | monitor+filename | HTTP/1.1 | Tomcat | last part named a.php. | 200 | monitor | MGUS-311 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E247 | block+filename | HTTP/1.1 | Tomcat | last part named a.php. | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E248 | monitor+filename | HTTP/1.1 | Tomcat | last part named ../up/a.txt | 200 | monitor | MGUS-312 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E249 | block+filename | HTTP/1.1 | Tomcat | last part named ../up/a.txt | 403 | block | MGUS-312 | 0 | 0 | 0 | – | Passed |
| E250 | monitor+filename | HTTP/1.1 | Tomcat | last part named a.txt. | 200 | monitor | MGUS-312 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E251 | block+filename | HTTP/1.1 | Tomcat | last part named a.txt. | 403 | block | MGUS-312 | 0 | 0 | 0 | – | Passed |
| E252 | monitor+filename | HTTP/1.1 | Tomcat | last part named 256-byte name | 200 | monitor | MGUS-313 | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E253 | block+filename | HTTP/1.1 | Tomcat | last part named 256-byte name | 403 | block | MGUS-313 | 0 | 0 | 0 | – | Passed |
| E254 | block | HTTP/1.1 | Tomcat | policy off (default): last part named shell.php.jpg | 200 | pass | none | 1 | 1 | 10 | 2 files, 1 fields | Passed |
| E255 | block+filename | HTTP/1.1 | PHP-FPM | custom list (exe svg): drawing.svg | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E256 | block+filename | HTTP/1.1 | PHP-FPM | custom list (exe svg): setup.EXE | 403 | block | MGUS-311 | 0 | 0 | 0 | – | Passed |
| E257 | block+filename | HTTP/1.1 | PHP-FPM | custom list (exe svg): shell.php | 200 | pass | none | 1 | 1 | 5 | 1 files, 0 fields | Passed |
| E258 | block | HTTP/2 (TLS) | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 15 | 2 files, 1 fields | Passed |
| E259 | block | HTTP/2 (TLS) | PHP-FPM | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E260 | block | HTTP/2 (TLS) | Tomcat | normal multi-file upload | 200 | pass | none | 1 | 1 | 15 | 2 files, 1 fields | Passed |
| E261 | block | HTTP/2 (TLS) | Tomcat | last part: session progress field | 403 | block | MGUS-301 | 0 | 0 | 0 | – | Passed |
| E262 | contract | HTTP/2 (TLS) | PHP-FPM | timeout 2s: client stalls | Closed | block | MGUS-402 | 0 | 0 | 0 | – | Passed |

## Parser comparison

| Case | Protocol | Backend | Scenario | Sent (files/fields/max file bytes) | Module | Backend | Agreement | File SHA-256 |
|---|---|---|---|---|---|---|---|---|
| E049 | HTTP/1.1 | PHP-FPM | single small file | 1 / 0 / 5 | 1 / 0 / 5 | 1 / 0 / 5 | Match | Match |
| E050 | HTTP/1.1 | Tomcat | single small file | 1 / 0 / 5 | 1 / 0 / 5 | 1 / 0 / 5 | Match | Match |
| E051 | HTTP/1.1 | PHP-FPM | fields only | 0 / 3 / 0 | 0 / 3 / 0 | 0 / 3 / 0 | Match | Match |
| E052 | HTTP/1.1 | Tomcat | fields only | 0 / 3 / 0 | 0 / 3 / 0 | 0 / 3 / 0 | Match | Match |
| E053 | HTTP/1.1 | PHP-FPM | three files under f[] plus two fields | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E054 | HTTP/1.1 | PHP-FPM | three files under f[] plus two fields [chunked] | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E055 | HTTP/2 | PHP-FPM | three files under f[] plus two fields | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E056 | HTTP/1.1 | Tomcat | three files under f[] plus two fields | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E057 | HTTP/1.1 | Tomcat | three files under f[] plus two fields [chunked] | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E058 | HTTP/2 | Tomcat | three files under f[] plus two fields | 3 / 2 / 51554 | 3 / 2 / 51554 | 3 / 2 / 51554 | Match | Match |
| E059 | HTTP/1.1 | PHP-FPM | distinct file names and nested field names | 2 / 3 / 50777 | 2 / 3 / 50777 | 2 / 3 / 50777 | Match | Match |
| E060 | HTTP/1.1 | Tomcat | distinct file names and nested field names | 2 / 3 / 50777 | 2 / 3 / 50777 | 2 / 3 / 50777 | Match | Match |
| E061 | HTTP/1.1 | PHP-FPM | empty file control (filename="") | 1 / 1 / 0 | 1 / 1 / 0 | 1 / 1 / 0 | Match | Match |
| E062 | HTTP/1.1 | Tomcat | empty file control (filename="") | 1 / 1 / 0 | 1 / 1 / 0 | 1 / 1 / 0 | Match | Match |
| E063 | HTTP/1.1 | PHP-FPM | zero-byte file with a name | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | Match | Match |
| E064 | HTTP/1.1 | Tomcat | zero-byte file with a name | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | Match | Match |
| E065 | HTTP/1.1 | PHP-FPM | UTF-8 and punctuated file names | 2 / 0 / 50777 | 2 / 0 / 50777 | 2 / 0 / 50777 | Match | Match |
| E066 | HTTP/1.1 | Tomcat | UTF-8 and punctuated file names | 2 / 0 / 50777 | 2 / 0 / 50777 | 2 / 0 / 50777 | Match | Match |
| E067 | HTTP/1.1 | PHP-FPM | file data containing boundary look-alikes | 1 / 1 / 5104 | 1 / 1 / 5104 | 1 / 1 / 5104 | Match | Match |
| E068 | HTTP/1.1 | Tomcat | file data containing boundary look-alikes | 1 / 1 / 5104 | 1 / 1 / 5104 | 1 / 1 / 5104 | Match | Match |
| E069 | HTTP/1.1 | PHP-FPM | 3.5 MB file | 1 / 0 / 3500000 | 1 / 0 / 3500000 | 1 / 0 / 3500000 | Match | Match |
| E070 | HTTP/1.1 | Tomcat | 3.5 MB file | 1 / 0 / 3500000 | 1 / 0 / 3500000 | 1 / 0 / 3500000 | Match | Match |
| E071 | HTTP/1.1 | PHP-FPM | multi-line and empty field values | 0 / 2 / 0 | 0 / 2 / 0 | 0 / 2 / 0 | Match | Match |
| E072 | HTTP/1.1 | Tomcat | multi-line and empty field values | 0 / 2 / 0 | 0 / 2 / 0 | 0 / 2 / 0 | Match | Match |
| E073 | HTTP/1.1 | PHP-FPM | same plain name twice for files (f, f) | 2 / 0 / 50777 | 2 / 0 / 50777 | 1 / 0 / 50777 | PHP-specific behavior | – |
| E074 | HTTP/1.1 | Tomcat | same plain name twice for files (f, f) | 2 / 0 / 50777 | 2 / 0 / 50777 | 2 / 0 / 50777 | Match | Match |
| E075 | HTTP/1.1 | PHP-FPM | same plain name twice for fields (a, a) | 0 / 2 / 0 | 0 / 2 / 0 | 0 / 1 / 0 | PHP-specific behavior | – |
| E076 | HTTP/1.1 | Tomcat | same plain name twice for fields (a, a) | 0 / 2 / 0 | 0 / 2 / 0 | 0 / 2 / 0 | Match | Match |
| E077 | HTTP/1.1 | PHP-FPM | unquoted name parameter | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 | Match | Match |
| E078 | HTTP/1.1 | Tomcat | unquoted name parameter | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 | Match | Match |
| E079 | HTTP/1.1 | PHP-FPM | header and parameter names in other case | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E080 | HTTP/1.1 | Tomcat | header and parameter names in other case | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E081 | HTTP/1.1 | PHP-FPM | no space after semicolons | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E082 | HTTP/1.1 | Tomcat | no space after semicolons | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E083 | HTTP/1.1 | PHP-FPM | unknown parameter before name, trailing semicolon | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 | Match | Match |
| E084 | HTTP/1.1 | Tomcat | unknown parameter before name, trailing semicolon | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 | Match | Match |
| E085 | HTTP/1.1 | PHP-FPM | Content-Type header before Content-Disposition | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E086 | HTTP/1.1 | Tomcat | Content-Type header before Content-Disposition | 1 / 0 / 52331 | 1 / 0 / 52331 | 1 / 0 / 52331 | Match | Match |
| E087 | HTTP/1.1 | PHP-FPM | quoted boundary parameter | 1 / 1 / 50000 | 1 / 1 / 50000 | 1 / 1 / 50000 | Match | Match |
| E088 | HTTP/1.1 | PHP-FPM | no CRLF after closing boundary | 1 / 1 / 50000 | 1 / 1 / 50000 | 1 / 1 / 50000 | Match | Match |
| E089 | HTTP/1.1 | Tomcat | quoted boundary parameter | 1 / 1 / 50000 | 1 / 1 / 50000 | 1 / 1 / 50000 | Match | Match |
| E090 | HTTP/1.1 | Tomcat | no CRLF after closing boundary | 1 / 1 / 50000 | 1 / 1 / 50000 | 1 / 1 / 50000 | Match | Match |
| E091 | HTTP/1.1 | PHP-FPM | curl -F, three files | 3 / 1 / 120002 | 3 / 1 / 120002 | 3 / 1 / 120002 | Match | Match |
| E092 | HTTP/2 | PHP-FPM | curl -F, three files | 3 / 1 / 120002 | 3 / 1 / 120002 | 3 / 1 / 120002 | Match | Match |
| E093 | HTTP/1.1 | Tomcat | curl -F, three files | 3 / 1 / 120002 | 3 / 1 / 120002 | 3 / 1 / 120002 | Match | Match |
| E094 | HTTP/2 | Tomcat | curl -F, three files | 3 / 1 / 120002 | 3 / 1 / 120002 | 3 / 1 / 120002 | Match | Match |

## Body size and timeout cases

| Scenario | Route | HTTP/1.1 case, status, seconds, action, delivery | HTTP/2 case, status, seconds, action, delivery | Effective limit | Deadline (ms) | Conflict | Result |
|---|---|---|---|---|---|---|---|
| size unset: 3 MB | `/c/unset` | E161: 200, 0.02, pass, Forwarded | E178: 200, 0.28, pass, Forwarded | 8388608 (nginx) | 0 | none | Passed |
| size unset: 9 MB, length declared | `/c/unset` | E162: 413, 0.05, No module log, 0 requests, 0 packets | E179: 413, 0.00, No module log, 0 requests, 0 packets | Nginx rejected first | – | – | Passed |
| size unset: 9 MB, no declared length | `/c/unset` | E163: 413, 0.01, aborted, 0 requests, 0 packets | E180: 413, 0.59, aborted, 0 requests, 0 packets | 8388608 (nginx) | 0 | none | Passed |
| size 2m: 1 MB | `/c/small` | E164: 200, 0.01, pass, Forwarded | E181: 200, 0.12, pass, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| size 2m: 3 MB, length declared | `/c/small` | E165: 413, 0.00, block MGUS-401, 0 requests, 0 packets | E182: 413, 0.00, block MGUS-401, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| size 2m: 3 MB, no declared length | `/c/small` | E166: 413, 0.00, block MGUS-401, 0 requests, 0 packets | E183: 413, 0.15, block MGUS-401, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| size 2m, MONITOR: 3 MB | `/c/small-m` | E167: 200, 0.02, monitor MGUS-401, Forwarded | E184: 200, 0.28, monitor MGUS-401, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| size 32m > nginx 8m: 3 MB | `/c/conflict` | E168: 200, 0.02, pass, Forwarded | E185: 200, 0.29, pass, Forwarded | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
| size 32m > nginx 8m: 9 MB, length declared | `/c/conflict` | E169: 413, 0.04, No module log, 0 requests, 0 packets | E186: 413, 0.00, No module log, 0 requests, 0 packets | Nginx rejected first | – | – | Passed |
| timeout unset: upload trickles for ~5 s | `/c/unset` | E170: 200, 5.50, pass, Forwarded | E187: 200, 5.52, pass, Forwarded | 8388608 (nginx) | 0 | none | Passed |
| timeout unset: client stalls | `/c/unset` | E171: Closed, 8.01, aborted, 0 requests, 0 packets | E188: Closed, 8.01, aborted, 0 requests, 0 packets | 8388608 (nginx) | 0 | none | Passed |
| timeout 2s: fast upload | `/c/small` | E172: 200, 0.01, pass, Forwarded | E189: 200, 0.12, pass, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s: upload trickles for ~5 s | `/c/small` | E173: Closed, 2.50, block MGUS-402, 0 requests, 0 packets | E190: Closed, 2.51, block MGUS-402, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s: client stalls | `/c/small` | E174: Closed, 2.00, block MGUS-402, 0 requests, 0 packets | E191: Closed, 2.00, block MGUS-402, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s, MONITOR: trickles for ~5 s | `/c/small-m` | E175: 200, 5.50, monitor MGUS-402, Forwarded | E192: 200, 5.52, monitor MGUS-402, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| timeout 30s > nginx 8s: trickles for ~5 s | `/c/conflict` | E176: 200, 5.50, pass, Forwarded | E193: 200, 5.52, pass, Forwarded | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
| timeout 30s > nginx 8s: client stalls | `/c/conflict` | E177: Closed, 8.00, aborted, 0 requests, 0 packets | E194: Closed, 8.01, aborted, 0 requests, 0 packets | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
