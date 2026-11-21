# Tested configurations

The table covers Kuipernet Upload v0.1.1 rc2. **Passed** means the tested configuration met its documented acceptance criteria. BLOCK results include backend-side checks. **Limited** means only the scenarios in the linked report were tested.

| ID | OS | Web server | Backend and transport | Client protocol | MONITOR | BLOCK |
|---|---|---|---|---|---|---|
| N1 | Ubuntu 24.04 | Nginx 1.30.0, source build | PHP-FPM 8.3.6 (`8.3.6-0ubuntu0.24.04.14`), buffered FastCGI over TCP | HTTP/1.1 and cleartext HTTP/2 | Passed | Passed |
| N2 | Ubuntu 24.04 | Nginx 1.30.0, source build | Tomcat 10.1.55, buffered HTTP/1.1 proxy | HTTP/1.1 and cleartext HTTP/2 | Passed | Passed |
| N3 | Ubuntu 24.04 | Nginx 1.30.0, source build with TLS | PHP-FPM and Tomcat, as above | HTTP/2 over TLS | Limited | Limited |
| L1 | Ubuntu 22.04 | `nginx-core 1.18.0-6ubuntu14.24` | `php8.1-fpm 8.1.2-1ubuntu2.29`, buffered FastCGI over Unix socket | HTTP/1.1 and cleartext HTTP/2, separate ports | Passed | Passed |
| L2 | Ubuntu 20.04 | `nginx-core 1.18.0-0ubuntu1.7` | `php7.4-fpm 7.4.3-4ubuntu2.29`, buffered FastCGI over Unix socket | HTTP/1.1 and cleartext HTTP/2, separate ports | Passed | Passed |
| L3 | Ubuntu 18.04 | `nginx-core 1.14.0-0ubuntu1.11` | `php7.2-fpm 7.2.24-0ubuntu0.18.04.17`, buffered FastCGI over Unix socket | HTTP/1.1 and cleartext HTTP/2, separate ports | Passed | Passed |
| A1 | Ubuntu 24.04 | `apache2 2.4.58-1ubuntu8.19`, event MPM | PHP-FPM 8.3.6 via `mod_proxy_fcgi` over TCP | HTTP/1.1 | Passed | Passed |
| A2 | Ubuntu 24.04 | `apache2 2.4.58-1ubuntu8.19`, prefork MPM | In-process `mod_php` 8.3.6 | HTTP/1.1 | Passed | Unsupported. BLOCK returns HTTP 500 for matching multipart requests. |

- N1–N3 ran 128 integration tests and 268 backend tests in standard and ASan builds after the rc2 change. The three-hour Nginx 1.30.0 run used rc1. The rc2 run lasted 30 minutes. N3 used a self-signed certificate and test clients. The full request size and backend parser comparisons were exercised separately from TLS. See [backend validation](TEST-REPORT-ROUND3.md).
- L1–L3 used unmodified distribution packages in chroots sharing the test host kernel. Each configuration passed 28 cases. The Ubuntu 18.04 build used the distribution configure arguments without `--with-compat`. ESM packages were outside the test scope. See the [legacy report](LEGACY.md) and [Ubuntu 18.04 soak test](SOAK-UBUNTU1804.md).
- A1–A2 used `apxs` to build and load the adapter. See the [Apache report](APACHE.md).

## Other configurations

| Configuration | Status |
|---|---|
| Nginx HTTP or FastCGI proxying with request buffering disabled | MONITOR can forward and report. BLOCK rejects multipart requests with HTTP 500 (MGUS-901). Tested on Nginx 1.30.0 and L1–L3. |
| Nginx `grpc_pass` | Untested. The upstream request body is unbuffered. |
| Nginx HTTP/3, `uwsgi_pass`, `scgi_pass`, Tomcat AJP, other distributions or ESM builds | Untested. |
| Nginx with other modules that read the request body, including ModSecurity | Combined operation is untested. The comparison used separate configurations. |
| Apache `mod_proxy_fcgi` before 2.4.47 | BLOCK unsupported. |
| Apache `mod_proxy_fcgi` using Unix sockets, `ProxyPassMatch`, `mod_http2`, or TLS | Untested. |
| Apache `mod_proxy_http`, AJP, CGI, and `mod_php` | BLOCK unsupported. |

## Optional policies

| Policy | Default | Tested configurations |
|---|---|---|
| Reject the upload progress field | Off | N1, N2, N3, L1, L2, L3, A1 |
| Reject multipart on routes without uploads | Off | N1, L1, L2, L3, A1 |
| Inspect filenames | Off | N1, N2, L1, L2, L3, A1 |
| Set a module-level total body limit or receive deadline | Unset | N1, L1, L2, L3. N3 tested the deadline. These directives are Nginx-only. |

## PHP2Shell evidence

The tests establish policy enforcement for the configurations above. N1–N3 and L1 used PHP packages with the two CVE patches recorded in their package changelogs. L2 and L3 exercised policy enforcement using older public packages. None of these runs established mitigation of CVE-2026-109618 or CVE-2026-109619 on a vulnerable PHP build. See [PHP2Shell policy scope](PHP2SHELL.md).
