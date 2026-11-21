# Apache 2.4 adapter

## Build

Build with the target Apache package's development headers and `apxs` in the source checkout.

```sh
cd apache
apxs -c -I ../src mod_upload_shield.c ../src/mgus_engine.c
```

Copy `.libs/mod_upload_shield.so` to the Apache modules directory, configure Apache, and validate with `apachectl configtest` before reloading. The following example uses buffered FastCGI to a PHP-FPM TCP endpoint. Adjust the endpoint and route for the application.

```apache
LoadModule upload_shield_module modules/mod_upload_shield.so
<VirtualHost *:80>
    UploadShield monitor
    UploadShieldMaxFileSize 20m
    <FilesMatch "\.php$">
        SetHandler "proxy:fcgi://127.0.0.1:9000"
    </FilesMatch>
    <Location "/upload/">
        UploadShield block
    </Location>
</VirtualHost>
```

BLOCK requires `mod_proxy_fcgi` on httpd 2.4.47 or newer. The adapter sets `proxy-sendcl` so Apache spools the inspected body before connecting to PHP-FPM. Bodies above the 16 kB in-memory threshold can use a temporary file. In-process `mod_php` supports MONITOR. Matching multipart requests in BLOCK mode return HTTP 500 (MGUS-901) for that handler.

Use `LimitRequestBody` and `RequestReadTimeout` for total size and read timing. The stock `mod_proxy_fcgi` behavior for chunked uploads can differ when `proxy-sendcl` enables spooling. Verify application behavior when switching to BLOCK.

## Validation

Apache 2.4.58 on Ubuntu 24.04 was tested with the event MPM and PHP-FPM 8.3.6 over TCP, and with prefork and in-process `mod_php`. All 32 cases passed. With FastCGI, all 8 approved upload hashes matched and all 9 BLOCK refusals produced zero PHP-FPM requests and packets.

The 60-second load run processed 16,485 requests with eight concurrent clients, zero unexpected responses or abnormal child exits, and no remaining spool or PHP upload files. The ASan FastCGI run passed all 27 cases and processed 10,337 requests in a 40-second load run with no unexpected responses or sanitizer reports. Long-duration load testing and other Apache transports remain untested.

## Case results

Backend counts are access log entries, application records, and packets, in that order.

| Case | Handler | Mode | Scenario | HTTP status | Action | Rule | Backend counts | SHA-256 | Result |
|---|---|---|---|---|---|---|---|---|---|
| A01 | mod_proxy_fcgi | off | baseline: normal multi-file upload | 200 | No log | – | 1/1/48 | Match | Passed |
| A02 | mod_proxy_fcgi | off | baseline: chunked upload (httpd/PHP-FPM behaviour, recorded only) | 200 | No log | – | 1/1/22 | – | Passed |
| A03 | mod_proxy_fcgi | monitor | normal multi-file upload, multi-extension names | 200 | pass | none | 1/1/36 | Match | Passed |
| A04 | mod_proxy_fcgi | monitor | chunked upload: MONITOR leaves httpd's behaviour unchanged | 200 | pass | none | 1/1/36 | – | Passed |
| A05 | mod_proxy_fcgi | monitor | normal 4 MB upload | 200 | pass | none | 1/1/285 | Match | Passed |
| A06 | mod_proxy_fcgi | block | normal multi-file upload, multi-extension names | 200 | pass | none | 1/1/35 | Match | Passed |
| A07 | mod_proxy_fcgi | block | chunked upload: BLOCK spools it, PHP-FPM gets a length | 200 | pass | none | 1/1/80 | Match | Passed |
| A08 | mod_proxy_fcgi | block | normal 4 MB upload | 200 | pass | none | 1/1/92 | Match | Passed |
| A09 | mod_proxy_fcgi | block | normal upload sent in 1-byte writes | 200 | pass | none | 1/1/9 | Match | Passed |
| A10 | mod_proxy_fcgi | block | empty file selection beside a real file | 200 | pass | none | 1/1/9 | Match | Passed |
| A11 | mod_proxy_fcgi | block | urlencoded form to the no-upload path (not inspected) | 200 | No log | – | 1/1/9 | – | Passed |
| A12 | mod_proxy_fcgi | monitor | last part: session progress field | 200 | monitor | MGUS-301 | 1/1/25 | – | Passed |
| A13 | mod_proxy_fcgi | block | last part: session progress field | 403 | block | MGUS-301 | 0/0/0 | – | Passed |
| A14 | mod_proxy_fcgi | monitor | last part: file over the 1 MB limit | 200 | monitor | MGUS-202 | 1/1/44 | – | Passed |
| A15 | mod_proxy_fcgi | block | last part: file over the 1 MB limit | 413 | block | MGUS-202 | 0/0/0 | – | Passed |
| A16 | mod_proxy_fcgi | monitor | last part: 5th file (limit 4) | 200 | monitor | MGUS-203 | 1/1/27 | – | Passed |
| A17 | mod_proxy_fcgi | block | last part: 5th file (limit 4) | 403 | block | MGUS-203 | 0/0/0 | – | Passed |
| A18 | mod_proxy_fcgi | monitor | end of body: closing boundary missing | 200 | monitor | MGUS-105 | 1/1/26 | – | Passed |
| A19 | mod_proxy_fcgi | block | end of body: closing boundary missing | 400 | block | MGUS-105 | 0/0/0 | – | Passed |
| A20 | mod_proxy_fcgi | monitor | last part named shell.php.jpg (file name policy) | 200 | monitor | MGUS-311 | 1/1/25 | – | Passed |
| A21 | mod_proxy_fcgi | block | last part named shell.php.jpg (file name policy) | 403 | block | MGUS-311 | 0/0/0 | – | Passed |
| A22 | mod_proxy_fcgi | monitor | bare-LF delimiter hiding a second part | 200 | monitor | MGUS-102 | 1/1/17 | – | Passed |
| A23 | mod_proxy_fcgi | block | bare-LF delimiter hiding a second part | 400 | block | MGUS-102 | 0/0/0 | – | Passed |
| A24 | mod_proxy_fcgi | block | last part: session progress field, chunked | 403 | block | MGUS-301 | 0/0/0 | – | Passed |
| A25 | mod_proxy_fcgi | block | last part: file over the 1 MB limit, chunked | 413 | block | MGUS-202 | 0/0/0 | – | Passed |
| A26 | mod_proxy_fcgi | block | multipart to the no-upload path | 403 | block | MGUS-302 | 0/0/0 | – | Passed |
| A27 | mod_proxy_fcgi | block | client aborts mid-upload | Closed | aborted | none | 0/0/0 | – | Passed |
| A28 | mod_php | monitor | normal multi-file upload | 200 | pass | none | 0/1/0 | Match | Passed |
| A29 | mod_php | monitor | last part: session progress field | 200 | monitor | MGUS-301 | 0/1/0 | – | Passed |
| A30 | mod_php | block | BLOCK: normal multipart upload is refused | 500 | block | MGUS-901 | 0/0/0 | – | Passed |
| A31 | mod_php | block | BLOCK: violating multipart upload is refused | 500 | block | MGUS-901 | 0/0/0 | – | Passed |
| A32 | mod_php | block | BLOCK: urlencoded form (not inspected) | 200 | No log | – | 0/1/0 | – | Passed |
