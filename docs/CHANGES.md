# Changelog

## 0.1.1 rc2 · 2026-11-20

- Build and load verified on the Ubuntu 18.04 Nginx 1.14.0 package with PHP-FPM 7.2. The Nginx adapter handles HTTP/2 receive deadlines without accessing private stream structures.
- Retested Ubuntu 20.04 and 22.04 with modules built against the matching distribution source packages.
- Added worker exit and alert checks to the integration, backend, and legacy runners. Added repeated HTTP/2 timeout tests to the legacy suite.
- Passed 128 integration cases and 268 backend cases on Nginx 1.30.0 in both standard and ASan builds. The Ubuntu 18.04 module passed a three-hour soak run.

## 0.1.1 · 2026-11-20

- Added optional filename policies and rules MGUS-311 through MGUS-313. The policies are disabled by default.
- Added the Apache 2.4 adapter. BLOCK requires `mod_proxy_fcgi` and httpd 2.4.47 or later.
- Added HTTP/2 stream isolation checks over TLS and the test runner for extended load.
- For Nginx versions below 1.20, defer an early body decision until the first data chunk to preserve the expected response status.
- Added legacy distribution package tests and a policy comparison with two public ModSecurity rulesets.

## 0.1.0 · 2026-11-20

- Added the shared multipart parser, Nginx adapter, and integration suite.
- Extended whole-body timeout enforcement to HTTP/2 streams, added conflict logging, and introduced PHP-FPM and Tomcat end-to-end tests.
