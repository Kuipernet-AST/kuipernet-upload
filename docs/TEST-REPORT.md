# Nginx integration test report

All 125 functional cases passed on Nginx 1.30.0 with the original test build. The isolated loopback setup used Ubuntu 24.04, GCC 13.3.0, one worker, and Nginx configured with `--with-compat --with-http_v2_module`. The HTTP and FastCGI test listeners recorded connection events, requests, body bytes, and SHA-256. See the later reports for application backend validation.

- Buffered `proxy_pass` and `fastcgi_pass` each passed 8 request body integrity cases and 11 BLOCK cases with zero backend requests and zero body bytes. MONITOR forwarded 10 policy-violation cases per transport while recording the violation.
- The tests covered ordinary and chunked requests, one-byte writes, missing boundaries, limits reached near the end of a body, client disconnects, and unbuffered configurations.
- In the 512 MB upload test, Nginx temporary disk use was the same with and without the module. The 3,000-request run left no temporary files and the worker descriptor count returned to its starting value.
- The 125 tests also passed with AddressSanitizer enabled. The rc2 regression includes the 3 later cases for a total of 128.

The test harness is `tests/integration/run_tests.py`. See the [README](../README.md#run-validation-tests) for invocation.

## Case results

| Case | Scenario | Route | HTTP status | Upstream requests | Body bytes | SHA-256 | Action | Rule | Result |
|---|---|---|---|---|---|---|---|---|---|
| T001 | normal multi-file upload | `/proxy/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T002 | normal upload, chunked request | `/proxy/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T003 | normal small upload (memory buffer) | `/proxy/monitor/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T004 | normal upload sent in 1-byte writes | `/proxy/monitor/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T005 | non-multipart POST (not inspected) | `/proxy/monitor/` | 200 | 1 | 100000 | Match | No log | – | Passed |
| T006 | normal multi-file upload | `/proxy/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T007 | normal upload, chunked request | `/proxy/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T008 | normal small upload (memory buffer) | `/proxy/block/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T009 | normal upload sent in 1-byte writes | `/proxy/block/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T010 | non-multipart POST (not inspected) | `/proxy/block/` | 200 | 1 | 100000 | Match | No log | – | Passed |
| T011 | last part: file over size limit | `/proxy/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T012 | last part: file over size limit | `/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T013 | end of body: closing boundary missing | `/proxy/monitor/` | 200 | 1 | 409825 | Match | monitor | MGUS-105 | Passed |
| T014 | end of body: closing boundary missing | `/proxy/block/` | 400 | 0 | 0 | – | block | MGUS-105 | Passed |
| T015 | last part: file count exceeded | `/proxy/monitor/` | 200 | 1 | 250751 | Match | monitor | MGUS-203 | Passed |
| T016 | last part: file count exceeded | `/proxy/block/` | 403 | 0 | 0 | – | block | MGUS-203 | Passed |
| T017 | end of body: data after closing boundary | `/proxy/monitor/` | 200 | 1 | 409788 | Match | monitor | MGUS-106 | Passed |
| T018 | end of body: data after closing boundary | `/proxy/block/` | 400 | 0 | 0 | – | block | MGUS-106 | Passed |
| T019 | last part: part header too large | `/proxy/monitor/` | 200 | 1 | 410529 | Match | monitor | MGUS-201 | Passed |
| T020 | last part: part header too large | `/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-201 | Passed |
| T021 | last part: form field too large | `/proxy/monitor/` | 200 | 1 | 410892 | Match | monitor | MGUS-205 | Passed |
| T022 | last part: form field too large | `/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-205 | Passed |
| T023 | bare-LF delimiter (parser differential) | `/proxy/monitor/` | 200 | 1 | 70272 | Match | monitor | MGUS-102 | Passed |
| T024 | bare-LF delimiter (parser differential) | `/proxy/block/` | 400 | 0 | 0 | – | block | MGUS-102 | Passed |
| T025 | last part: part count exceeded | `/proxy/monitor/` | 200 | 1 | 824 | Match | monitor | MGUS-204 | Passed |
| T026 | last part: part count exceeded | `/proxy/block/` | 403 | 0 | 0 | – | block | MGUS-204 | Passed |
| T027 | last-part violation, chunked request | `/proxy/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T028 | last-part violation, chunked request | `/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T029 | invalid boundary parameter | `/proxy/block/` | 400 | 0 | 0 | – | block | MGUS-100 | Passed |
| T030 | buffering off, MONITOR, violating upload | `/nobuf/proxy/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T031 | buffering off, MONITOR, normal upload | `/nobuf/proxy/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T032 | buffering off, BLOCK, normal upload refused | `/nobuf/proxy/block/` | 500 | 0 | 0 | – | block | MGUS-901 | Passed |
| T033 | buffering off, BLOCK, non-multipart POST | `/nobuf/proxy/block/` | 200 | 1 | 50000 | Match | No log | – | Passed |
| T034 | client aborts mid-upload | `/proxy/monitor/` | Closed | 0 | 0 | – | aborted | none | Passed |
| T035 | client aborts mid-upload | `/proxy/block/` | Closed | 0 | 0 | – | aborted | none | Passed |
| T036 | normal multi-file upload | `/fcgi/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T037 | normal upload, chunked request | `/fcgi/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T038 | normal small upload (memory buffer) | `/fcgi/monitor/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T039 | normal upload sent in 1-byte writes | `/fcgi/monitor/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T040 | non-multipart POST (not inspected) | `/fcgi/monitor/` | 200 | 1 | 100000 | Match | No log | – | Passed |
| T041 | normal multi-file upload | `/fcgi/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T042 | normal upload, chunked request | `/fcgi/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T043 | normal small upload (memory buffer) | `/fcgi/block/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T044 | normal upload sent in 1-byte writes | `/fcgi/block/` | 200 | 1 | 277 | Match | pass | none | Passed |
| T045 | non-multipart POST (not inspected) | `/fcgi/block/` | 200 | 1 | 100000 | Match | No log | – | Passed |
| T046 | last part: file over size limit | `/fcgi/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T047 | last part: file over size limit | `/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T048 | end of body: closing boundary missing | `/fcgi/monitor/` | 200 | 1 | 409825 | Match | monitor | MGUS-105 | Passed |
| T049 | end of body: closing boundary missing | `/fcgi/block/` | 400 | 0 | 0 | – | block | MGUS-105 | Passed |
| T050 | last part: file count exceeded | `/fcgi/monitor/` | 200 | 1 | 250751 | Match | monitor | MGUS-203 | Passed |
| T051 | last part: file count exceeded | `/fcgi/block/` | 403 | 0 | 0 | – | block | MGUS-203 | Passed |
| T052 | end of body: data after closing boundary | `/fcgi/monitor/` | 200 | 1 | 409788 | Match | monitor | MGUS-106 | Passed |
| T053 | end of body: data after closing boundary | `/fcgi/block/` | 400 | 0 | 0 | – | block | MGUS-106 | Passed |
| T054 | last part: part header too large | `/fcgi/monitor/` | 200 | 1 | 410529 | Match | monitor | MGUS-201 | Passed |
| T055 | last part: part header too large | `/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-201 | Passed |
| T056 | last part: form field too large | `/fcgi/monitor/` | 200 | 1 | 410892 | Match | monitor | MGUS-205 | Passed |
| T057 | last part: form field too large | `/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-205 | Passed |
| T058 | bare-LF delimiter (parser differential) | `/fcgi/monitor/` | 200 | 1 | 70272 | Match | monitor | MGUS-102 | Passed |
| T059 | bare-LF delimiter (parser differential) | `/fcgi/block/` | 400 | 0 | 0 | – | block | MGUS-102 | Passed |
| T060 | last part: part count exceeded | `/fcgi/monitor/` | 200 | 1 | 824 | Match | monitor | MGUS-204 | Passed |
| T061 | last part: part count exceeded | `/fcgi/block/` | 403 | 0 | 0 | – | block | MGUS-204 | Passed |
| T062 | last-part violation, chunked request | `/fcgi/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T063 | last-part violation, chunked request | `/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T064 | invalid boundary parameter | `/fcgi/block/` | 400 | 0 | 0 | – | block | MGUS-100 | Passed |
| T065 | buffering off, MONITOR, violating upload | `/nobuf/fcgi/monitor/` | 200 | 1 | 1868349 | Match | monitor | MGUS-202 | Passed |
| T066 | buffering off, MONITOR, normal upload | `/nobuf/fcgi/monitor/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T067 | buffering off, BLOCK, normal upload refused | `/nobuf/fcgi/block/` | 500 | 0 | 0 | – | block | MGUS-901 | Passed |
| T068 | buffering off, BLOCK, non-multipart POST | `/nobuf/fcgi/block/` | 200 | 1 | 50000 | Match | No log | – | Passed |
| T069 | client aborts mid-upload | `/fcgi/monitor/` | Closed | 0 | 0 | – | aborted | none | Passed |
| T070 | client aborts mid-upload | `/fcgi/block/` | Closed | 0 | 0 | – | aborted | none | Passed |
| T071 | shield body limit 2m: 1.2 MB upload | `/size/proxy/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T072 | shield body limit 2m: 3.5 MB (Content-Length) | `/size/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-401 | Passed |
| T073 | shield body limit 2m: 3.5 MB (chunked) | `/size/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-401 | Passed |
| T074 | shield body limit 2m: 1.2 MB upload | `/size/fcgi/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T075 | shield body limit 2m: 3.5 MB (Content-Length) | `/size/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-401 | Passed |
| T076 | shield body limit 2m: 3.5 MB (chunked) | `/size/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-401 | Passed |
| T077 | shield body limit 2m, MONITOR: 3.5 MB | `/size/proxy/monitor/` | 200 | 1 | 3687005 | Match | monitor | MGUS-401 | Passed |
| T078 | no shield limit: 3.5 MB follows nginx 64m | `/proxy/block/` | 200 | 1 | 3687005 | Match | pass | none | Passed |
| T079 | shield 128m > nginx 64m: 3.5 MB upload | `/size/conflict/` | 200 | 1 | 3687005 | Match | pass | none | Passed |
| T080 | shield 128m > nginx 64m: 70 MB declared | `/size/conflict/` | 413 | 0 | 0 | – | No log | – | Passed |
| T081 | shield body timeout 2s: fast upload | `/time/proxy/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T082 | shield body timeout 2s: upload takes ~5s | `/time/proxy/block/` | Closed | 0 | 0 | – | block | MGUS-402 | Passed |
| T083 | shield body timeout 2s: fast upload | `/time/fcgi/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T084 | shield body timeout 2s: upload takes ~5s | `/time/fcgi/block/` | Closed | 0 | 0 | – | block | MGUS-402 | Passed |
| T085 | shield body timeout 2s, MONITOR: ~5s upload | `/time/proxy/monitor/` | 200 | 1 | 300187 | Match | monitor | MGUS-402 | Passed |
| T086 | no shield timeout: ~5s upload follows nginx | `/proxy/block/` | 200 | 1 | 300187 | Match | pass | none | Passed |
| T087 | host-wide block: normal upload (fcgi) | `/index.php/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T088 | host-wide block: progress field, last part (fcgi) | `/index.php/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T089 | host-wide block: progress field only (fcgi) | `/index.php/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T090 | host-wide block: normal upload (fcgi) | `/any/other/page.php/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T091 | host-wide block: progress field, last part (fcgi) | `/any/other/page.php/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T092 | host-wide block: progress field only (fcgi) | `/any/other/page.php/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T093 | host-wide block: normal upload (proxy) | `/api/v1/items/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T094 | host-wide block: progress field, last part (proxy) | `/api/v1/items/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T095 | host-wide block: progress field only (proxy) | `/api/v1/items/` | 403 | 0 | 0 | – | block | MGUS-301 | Passed |
| T096 | host-wide block: field name depth 5 > 4 | `/a.php/` | 403 | 0 | 0 | – | block | MGUS-208 | Passed |
| T097 | host-wide block: field name 200 B > 128 | `/a.php/` | 403 | 0 | 0 | – | block | MGUS-207 | Passed |
| T098 | host-wide block: 6 headers in one part > 4 | `/a.php/` | 403 | 0 | 0 | – | block | MGUS-206 | Passed |
| T099 | host-wide block: no-upload path, any multipart | `/noupload/x.php/` | 403 | 0 | 0 | – | block | MGUS-302 | Passed |
| T100 | host-wide block: urlencoded POST (not inspected) | `/index.php/` | 200 | 1 | 37 | Match | No log | – | Passed |
| T101 | host-wide monitor: normal upload (fcgi) | `/index.php/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T102 | host-wide monitor: progress field, last part (fcgi) | `/index.php/` | 200 | 1 | 200390 | Match | monitor | MGUS-301 | Passed |
| T103 | host-wide monitor: progress field only (fcgi) | `/index.php/` | 200 | 1 | 157 | Match | monitor | MGUS-301 | Passed |
| T104 | host-wide monitor: normal upload (fcgi) | `/any/other/page.php/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T105 | host-wide monitor: progress field, last part (fcgi) | `/any/other/page.php/` | 200 | 1 | 200390 | Match | monitor | MGUS-301 | Passed |
| T106 | host-wide monitor: progress field only (fcgi) | `/any/other/page.php/` | 200 | 1 | 157 | Match | monitor | MGUS-301 | Passed |
| T107 | host-wide monitor: normal upload (proxy) | `/api/v1/items/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T108 | host-wide monitor: progress field, last part (proxy) | `/api/v1/items/` | 200 | 1 | 200390 | Match | monitor | MGUS-301 | Passed |
| T109 | host-wide monitor: progress field only (proxy) | `/api/v1/items/` | 200 | 1 | 157 | Match | monitor | MGUS-301 | Passed |
| T110 | host-wide monitor: field name depth 5 > 4 | `/a.php/` | 200 | 1 | 142 | Match | monitor | MGUS-208 | Passed |
| T111 | host-wide monitor: field name 200 B > 128 | `/a.php/` | 200 | 1 | 326 | Match | monitor | MGUS-207 | Passed |
| T112 | host-wide monitor: 6 headers in one part > 4 | `/a.php/` | 200 | 1 | 172 | Match | monitor | MGUS-206 | Passed |
| T113 | host-wide monitor: no-upload path, any multipart | `/noupload/x.php/` | 200 | 1 | 277 | Match | monitor | MGUS-302 | Passed |
| T114 | host-wide monitor: urlencoded POST (not inspected) | `/index.php/` | 200 | 1 | 37 | Match | No log | – | Passed |
| T115 | host-wide block: path exempted from progress rule | `/progress/up.php/` | 200 | 1 | 200390 | Match | pass | none | Passed |
| T116 | curl -F, three files [HTTP/1.1] | `/proxy/block/` | 200 | 1 | 450617 | – | pass | none | Passed |
| T117 | curl -F, three files [HTTP/2] | `/proxy/block/` | 200 | 1 | 450617 | – | pass | none | Passed |
| T118 | normal upload [HTTP/2] | `/proxy/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T119 | last-part violation [HTTP/2] | `/proxy/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T120 | last-part violation [HTTP/2] | `/proxy/monitor/` | 200 | 1 | 1868349 | – | monitor | MGUS-202 | Passed |
| T121 | curl -F, three files [HTTP/1.1] | `/fcgi/block/` | 200 | 1 | 450617 | – | pass | none | Passed |
| T122 | curl -F, three files [HTTP/2] | `/fcgi/block/` | 200 | 1 | 450617 | – | pass | none | Passed |
| T123 | normal upload [HTTP/2] | `/fcgi/block/` | 200 | 1 | 1229480 | Match | pass | none | Passed |
| T124 | last-part violation [HTTP/2] | `/fcgi/block/` | 413 | 0 | 0 | – | block | MGUS-202 | Passed |
| T125 | last-part violation [HTTP/2] | `/fcgi/monitor/` | 200 | 1 | 1868349 | – | monitor | MGUS-202 | Passed |
