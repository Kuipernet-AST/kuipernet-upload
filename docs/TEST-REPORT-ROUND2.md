# PHP-FPM and Tomcat validation

All 194 functional, parser comparison, and limit cases passed. Six 30-second rounds with 24 concurrent clients produced 39,771 requests and no unexpected responses. Worker PIDs were stable and the Nginx error log contained no alert, critical, or emergency entries.

The test environment used Nginx 1.30.0, PHP-FPM 8.3.6, and Tomcat 10.1.55. Backend delivery was measured using access logs, application records, and kernel packet counters. The verdict for supported BLOCK configurations required zero backend requests and packets for denied uploads.

| Test | PHP-FPM | Tomcat |
|---|---|---|
| Normal uploads | 9 passed, expected files and SHA-256 | 9 passed, expected files and SHA-256 |
| BLOCK with a final-part violation | 10 passed, zero backend requests | 10 passed, zero backend requests |
| MONITOR with the same type of violation | 5 passed, forwarded and logged | 5 passed, forwarded and logged |

All 44 judged parser comparison cases agreed on file count, field count, and maximum file size. Two cases with duplicated non-array field names were recorded separately because PHP retains the last value. The backends interpreted 6 of 10 rejected structures differently. The corresponding 20 BLOCK cases produced zero backend requests.

The HTTP/1.1 and cleartext HTTP/2 size and timeout contract cases returned the same outcomes. The total receive deadline was also applied to HTTP/2. The optional PHP session upload progress field rule was tested for policy enforcement. CVE mitigation was outside this result.

## Case results

| Case | Mode | Protocol | Backend | Scenario | HTTP status | Action | Rule | Access log entries | Application records | Packets | Body or parsed result | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E001 | off | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | – | – | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E002 | off | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | – | – | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E003 | off | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | – | – | 1 | 1 | 26 | 3 files, 2 fields | Passed |
| E004 | monitor | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E005 | monitor | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E006 | monitor | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E007 | block | HTTP/1.1 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E008 | block | HTTP/1.1 | PHP-FPM | normal multi-file upload (chunked) | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E009 | block | HTTP/2 | PHP-FPM | normal multi-file upload | 200 | pass | none | 1 | 1 | 24 | 3 files, 2 fields | Passed |
| E010 | monitor | HTTP/1.1 | PHP-FPM | last part: file over 4m limit | 200 | monitor | MGUS-202 | 1 | 1 | 87 | 2 files, 1 fields | Passed |
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
| E046 | monitor | HTTP/1.1 | Tomcat | end of body: closing boundary missing | 400 | monitor | MGUS-105 | 1 | 1 | 12 | 0 files, 0 fields | Passed |
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
| size unset: 3 MB | `/c/unset` | E161: 200, 0.03, pass, Forwarded | E178: 200, 0.29, pass, Forwarded | 8388608 (nginx) | 0 | none | Passed |
| size unset: 9 MB, length declared | `/c/unset` | E162: 413, 0.05, No module log, 0 requests, 0 packets | E179: 413, 0.00, No module log, 0 requests, 0 packets | Nginx rejected first | – | – | Passed |
| size unset: 9 MB, no declared length | `/c/unset` | E163: 413, 0.01, aborted, 0 requests, 0 packets | E180: 413, 0.62, aborted, 0 requests, 0 packets | 8388608 (nginx) | 0 | none | Passed |
| size 2m: 1 MB | `/c/small` | E164: 200, 0.01, pass, Forwarded | E181: 200, 0.12, pass, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| size 2m: 3 MB, length declared | `/c/small` | E165: 413, 0.00, block MGUS-401, 0 requests, 0 packets | E182: 413, 0.00, block MGUS-401, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| size 2m: 3 MB, no declared length | `/c/small` | E166: 413, 0.00, block MGUS-401, 0 requests, 0 packets | E183: 413, 0.17, block MGUS-401, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| size 2m, MONITOR: 3 MB | `/c/small-m` | E167: 200, 0.03, monitor MGUS-401, Forwarded | E184: 200, 0.30, monitor MGUS-401, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| size 32m > nginx 8m: 3 MB | `/c/conflict` | E168: 200, 0.02, pass, Forwarded | E185: 200, 0.30, pass, Forwarded | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
| size 32m > nginx 8m: 9 MB, length declared | `/c/conflict` | E169: 413, 0.01, No module log, 0 requests, 0 packets | E186: 413, 0.00, No module log, 0 requests, 0 packets | Nginx rejected first | – | – | Passed |
| timeout unset: upload trickles for ~5 s | `/c/unset` | E170: 200, 5.50, pass, Forwarded | E187: 200, 5.52, pass, Forwarded | 8388608 (nginx) | 0 | none | Passed |
| timeout unset: client stalls | `/c/unset` | E171: Closed, 8.01, aborted, 0 requests, 0 packets | E188: Closed, 8.00, aborted, 0 requests, 0 packets | 8388608 (nginx) | 0 | none | Passed |
| timeout 2s: fast upload | `/c/small` | E172: 200, 0.01, pass, Forwarded | E189: 200, 0.12, pass, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s: upload trickles for ~5 s | `/c/small` | E173: Closed, 2.50, block MGUS-402, 0 requests, 0 packets | E190: Closed, 2.51, block MGUS-402, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s: client stalls | `/c/small` | E174: Closed, 2.00, block MGUS-402, 0 requests, 0 packets | E191: Closed, 2.00, block MGUS-402, 0 requests, 0 packets | 2097152 (shield) | 2000 | none | Passed |
| timeout 2s, MONITOR: trickles for ~5 s | `/c/small-m` | E175: 200, 5.50, monitor MGUS-402, Forwarded | E192: 200, 5.52, monitor MGUS-402, Forwarded | 2097152 (shield) | 2000 | none | Passed |
| timeout 30s > nginx 8s: trickles for ~5 s | `/c/conflict` | E176: 200, 5.51, pass, Forwarded | E193: 200, 5.52, pass, Forwarded | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
| timeout 30s > nginx 8s: client stalls | `/c/conflict` | E177: Closed, 8.00, aborted, 0 requests, 0 packets | E194: Closed, 8.01, aborted, 0 requests, 0 packets | 8388608 (nginx) | 30000 | body_size,body_timeout | Passed |
