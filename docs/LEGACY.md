# Legacy Nginx and PHP-FPM validation

Each of the following combinations passed 28 cases using the distribution packages in an isolated chroot. The kernel was supplied by the test host. Each used buffered FastCGI over a Unix socket and tested HTTP/1.1 and cleartext HTTP/2.

| OS | Nginx package | PHP-FPM package | Build option |
|---|---|---|---|
| Ubuntu 22.04 | `nginx-core 1.18.0-6ubuntu14.24` | `php8.1-fpm 8.1.2-1ubuntu2.29` | `--with-compat` |
| Ubuntu 20.04 | `nginx-core 1.18.0-0ubuntu1.7` | `php7.4-fpm 7.4.3-4ubuntu2.29` | `--with-compat` |
| Ubuntu 18.04 | `nginx-core 1.14.0-0ubuntu1.11` | `php7.2-fpm 7.2.24-0ubuntu0.18.04.17` | Match all package arguments. This package omits `--with-compat`. |

## Ubuntu 18.04 build

Enable the matching distribution source repository and retrieve `apt-get source nginx=1.14.0-0ubuntu1.11`. The test build used public Bionic repositories. Ubuntu Pro/ESM builds may have different versions and were outside the matrix.

Use the output of `nginx -V` for configure arguments, then add the module using [the build helper](../README.md#build-and-install). The tested Ubuntu 18.04 arguments require development headers for OpenSSL, PCRE, zlib, GeoIP, GD, and XSLT. A build that added `--with-compat` failed the package's module compatibility check.

```text
nginx version: nginx/1.14.0 (Ubuntu)
built with OpenSSL 1.1.1  11 Sep 2018
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2 -fdebug-prefix-map=/build/nginx-YlUNvj/nginx-1.14.0=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-mail=dynamic --with-mail_ssl_module
```

The module built without compiler warnings, passed `nginx -t`, and was loaded by the installed `/usr/sbin/nginx`. The fixed module passed four consecutive 28-case runs and a separate sequence of 20 HTTP/2 timeout checks with a stable worker PID. See the [three-hour run](SOAK-UBUNTU1804.md) for sustained load.

## Case results

Backend counts are PHP-FPM access log entries and PHP application records. The case descriptions identify the tested method and expected behavior.

| Case | Mode | HTTP status | Action | Backend counts | SHA-256 |
|---|---|---|---|---|---|
| L01 normal multi-file upload, multi-extension names (monitor) (HTTP/1.1) | MONITOR | 200 | pass | 1/1 | Match |
| L02 normal multi-file upload, multi-extension names (block) (HTTP/1.1) | BLOCK | 200 | pass | 1/1 | Match |
| L03 normal upload, chunked request (HTTP/1.1) | BLOCK | 200 | pass | 1/1 | Match |
| L04 normal upload sent in 1-byte writes (HTTP/1.1) | BLOCK | 200 | pass | 1/1 | Match |
| L05 empty file selection beside a real file (HTTP/1.1) | BLOCK | 200 | pass | 1/1 | Match |
| L06 normal multi-file upload (HTTP/2) | BLOCK | 200 | pass | 1/1 | Match |
| L21 shield body limit 2m: 0.9 MB upload (HTTP/1.1) | BLOCK | 200 | pass | 1/1 | Match |
| L10 last part: file over the 1 MB limit (HTTP/1.1) | MONITOR | 200 | monitor MGUS-202 | 1/1 | – |
| L11 last part: file over the 1 MB limit (HTTP/1.1) | BLOCK | 413 | block MGUS-202 | 0/0 | – |
| L20 multipart to the no-upload path (HTTP/1.1) | BLOCK | 403 | block MGUS-302 | 0/0 | – |
| L08 last part: session progress field (HTTP/1.1) | MONITOR | 200 | monitor MGUS-301 | 1/1 | – |
| L09 last part: session progress field (HTTP/1.1) | BLOCK | 403 | block MGUS-301 | 0/0 | – |
| L18 last part: session progress field (HTTP/2) | BLOCK | 403 | block MGUS-301 | 0/0 | – |
| L19 last part: session progress field, chunked (HTTP/1.1) | BLOCK | 403 | block MGUS-301 | 0/0 | – |

## Cross-platform cases

| Case | Protocol | Mode | Scenario | Ubuntu 22.04 / PHP 8.1 | Ubuntu 20.04 / PHP 7.4 | Ubuntu 18.04 / PHP 7.2 | Result |
|---|---|---|---|---|---|---|---|
| L01 | HTTP/1.1 | monitor | normal multi-file upload, multi-extension names (monitor) | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L02 | HTTP/1.1 | block | normal multi-file upload, multi-extension names (block) | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L03 | HTTP/1.1 | block | normal upload, chunked request | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L04 | HTTP/1.1 | block | normal upload sent in 1-byte writes | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L05 | HTTP/1.1 | block | empty file selection beside a real file | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L06 | HTTP/2 | block | normal multi-file upload | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L07 | HTTP/1.1 | block | urlencoded form to the no-upload path (not inspected) | 200, No log, 1/1, – | 200, No log, 1/1, – | 200, No log, 1/1, – | Passed |
| L08 | HTTP/1.1 | monitor | last part: session progress field | 200, monitor MGUS-301, 1/1, – | 200, monitor MGUS-301, 1/1, – | 200, monitor MGUS-301, 1/1, – | Passed |
| L09 | HTTP/1.1 | block | last part: session progress field | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | Passed |
| L10 | HTTP/1.1 | monitor | last part: file over the 1 MB limit | 200, monitor MGUS-202, 1/1, – | 200, monitor MGUS-202, 1/1, – | 200, monitor MGUS-202, 1/1, – | Passed |
| L11 | HTTP/1.1 | block | last part: file over the 1 MB limit | 413, block MGUS-202, 0/0, – | 413, block MGUS-202, 0/0, – | 413, block MGUS-202, 0/0, – | Passed |
| L12 | HTTP/1.1 | monitor | last part: 5th file (limit 4) | 200, monitor MGUS-203, 1/1, – | 200, monitor MGUS-203, 1/1, – | 200, monitor MGUS-203, 1/1, – | Passed |
| L13 | HTTP/1.1 | block | last part: 5th file (limit 4) | 403, block MGUS-203, 0/0, – | 403, block MGUS-203, 0/0, – | 403, block MGUS-203, 0/0, – | Passed |
| L14 | HTTP/1.1 | monitor | end of body: closing boundary missing | 200, monitor MGUS-105, 1/1, – | 200, monitor MGUS-105, 1/1, – | 200, monitor MGUS-105, 1/1, – | Passed |
| L15 | HTTP/1.1 | block | end of body: closing boundary missing | 400, block MGUS-105, 0/0, – | 400, block MGUS-105, 0/0, – | 400, block MGUS-105, 0/0, – | Passed |
| L16 | HTTP/1.1 | monitor | last part named shell.php.jpg (file name policy) | 200, monitor MGUS-311, 1/1, – | 200, monitor MGUS-311, 1/1, – | 200, monitor MGUS-311, 1/1, – | Passed |
| L17 | HTTP/1.1 | block | last part named shell.php.jpg (file name policy) | 403, block MGUS-311, 0/0, – | 403, block MGUS-311, 0/0, – | 403, block MGUS-311, 0/0, – | Passed |
| L18 | HTTP/2 | block | last part: session progress field | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | Passed |
| L19 | HTTP/1.1 | block | last part: session progress field, chunked | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | 403, block MGUS-301, 0/0, – | Passed |
| L20 | HTTP/1.1 | block | multipart to the no-upload path | 403, block MGUS-302, 0/0, – | 403, block MGUS-302, 0/0, – | 403, block MGUS-302, 0/0, – | Passed |
| L21 | HTTP/1.1 | block | shield body limit 2m: 0.9 MB upload | 200, pass, 1/1, Match | 200, pass, 1/1, Match | 200, pass, 1/1, Match | Passed |
| L22 | HTTP/1.1 | block | shield body limit 2m: 2.6 MB, length declared | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | Passed |
| L23 | HTTP/1.1 | block | shield body limit 2m: 2.6 MB, chunked | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | Passed |
| L24 | HTTP/2 | block | shield body limit 2m: 2.6 MB, no content-length | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | 413, block MGUS-401, 0/0, – | Passed |
| L25 | HTTP/1.1 | block | shield timeout 2s: client stalls | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Passed |
| L26 | HTTP/2 | block | shield timeout 2s: client stalls | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Passed |
| L27 | HTTP/1.1 | block | shield timeout 2s: upload trickles ~5 s | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Closed, block MGUS-402, 0/0, – | Passed |
| L28 | HTTP/1.1 | block | buffering off, BLOCK: normal upload refused | 500, block MGUS-901, 0/0, – | 500, block MGUS-901, 0/0, – | 500, block MGUS-901, 0/0, – | Passed |
