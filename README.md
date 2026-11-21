![Kuipernet](docs/kuipernet-logo.png)

# Kuipernet Upload

Kuipernet Upload is a standalone web server module for inspecting `multipart/form-data` requests. It applies upload size, part count, and other multipart policies by route or virtual host. In supported Nginx configurations with request buffering enabled, it blocks noncompliant requests before they reach the backend and forwards approved uploads intact.

The repository contains a shared C99 inspection engine, an Nginx module, and an Apache 2.4 adapter for `mod_proxy_fcgi`. Check the [support matrix](docs/SUPPORT.md) before deploying. Start in MONITOR mode and review violations against normal upload traffic before switching a route to BLOCK.

| Guide | Contents |
|---|---|
| [Support matrix](docs/SUPPORT.md) | Tested packages, backend connections, protocols, and evidence for each configuration |
| [Legacy Nginx and PHP-FPM](docs/LEGACY.md) | Build and validation results for Ubuntu 18.04, 20.04, and 22.04 with PHP-FPM 7.2, 7.4, and 8.1 |
| [Apache 2.4](docs/APACHE.md) | Build and configuration for `mod_proxy_fcgi`, plus `mod_php` limitations |
| [Request size and timeout settings](docs/SIZE-TIMEOUT-CONTRACT.md) | How Nginx and module limits interact |
| [Nginx configuration example](examples/nginx-upload-shield.conf) | Per-route and virtual host policies |
| [Ubuntu 18.04 soak test](docs/SOAK-UBUNTU1804.md) | Three-hour run with the release-candidate module |
| [Validation reports](docs/TEST-REPORT-ROUND3.md) | PHP-FPM and Tomcat tests, filename policies, HTTP/2 stream isolation, and load tests. See also the [initial](docs/TEST-REPORT.md) and [second-round](docs/TEST-REPORT-ROUND2.md) reports. |
| [ModSecurity comparison](docs/COMPARE-MODSECURITY.md) | Results for the specific public rulesets and configurations tested |
| [PHP2Shell](docs/PHP2SHELL.md) | Policy enforcement results and the scope of CVE mitigation evidence |
| [Changelog](docs/CHANGES.md) | Changes by version |

## Repository layout

| Path | Purpose |
|---|---|
| `src/` | Shared multipart inspection engine |
| `nginx/` | Nginx request body filter and module build configuration |
| `apache/` | Apache 2.4 input filter |
| `scripts/` | Build helper |
| `examples/` | Sample Nginx configuration |
| `tests/` | Unit, integration, backend, comparison, and legacy test tools |
| `docs/` | Support, configuration, and validation documentation |

## Request processing

The Nginx request body filter sends decoded body chunks to the inspection engine. The module uses Nginx's existing body buffers and temporary files. Its per-request inspection context is approximately 8.5 KB.

- **MONITOR** forwards chunks and records the inspection result in a structured log.
- **BLOCK** ends the request when a policy violation is found. With request buffering enabled for `proxy_pass` or `fastcgi_pass`, Nginx starts the backend request after the body passes inspection. A violation in the final part can therefore be blocked before the backend receives the request.

For example, with a 20 MB per-file limit and a sufficient total body limit, the same route accepts two 15 MB files and rejects a single 25 MB file.

## Validation highlights

- Each tested Ubuntu package pair passed 28 checks. The pairs used Nginx 1.14.0 with PHP-FPM 7.2 on Ubuntu 18.04, and Nginx 1.18.0 with PHP-FPM 7.4 and 8.1 on Ubuntu 20.04 and 22.04, respectively.
- The Ubuntu 18.04 release-candidate module completed a three-hour run with 47,930 test cases, no unexpected results, and no worker exits. PHP-FPM received all 45,069 successful uploads with matching SHA-256 hashes. It received none of the requests stopped by timeout or policy.
- PHP2Shell-related tests verified policy enforcement before backend delivery. Mitigation of either CVE on a vulnerable PHP build remains unverified.

## Build and install

Build against the exact Nginx version and configuration used by the target package. Run `nginx -V` to identify the build options. For a distribution package, use the distribution's matching source package and install the build dependencies for its configure options.

```sh
nginx -V 2>&1
make test
# Example for a compatible upstream Nginx build.
bash scripts/build-nginx-module.sh /path/to/nginx-1.30.0 --with-compat
```

The build puts `ngx_http_upload_shield_module.so` in the Nginx source tree's `objs/` directory. Copy it to the target Nginx modules directory and add the following directive in the main context of `nginx.conf`.

```nginx
load_module modules/ngx_http_upload_shield_module.so;
```

Use the target package's configure arguments. The tested Ubuntu 18.04 package was built without `--with-compat`; reproduce the package options and add the dynamic module. See the [legacy build notes](docs/LEGACY.md) for package versions and dependencies.

Validate the configuration and reload Nginx using the service manager for your installation.

```sh
sudo nginx -t
sudo systemctl reload nginx
```

To roll back, remove the policy directives and the module load directive, then validate and reload the restored configuration.

### Run validation tests

```sh
python3 tests/integration/run_tests.py /path/to/sbin/nginx /path/to/ngx_http_upload_shield_module.so /tmp/mgus-out --big 512 --soak 3000
python3 tests/integration/make_report.py /tmp/mgus-out docs/TEST-REPORT.md

python3 tests/e2e/run_e2e.py /path/to/sbin/nginx /path/to/ngx_http_upload_shield_module.so /tmp/mgus-e2e --rounds 6 --round-seconds 30 --concurrency 24
```

The backend suite uses PHP-FPM, Tomcat, iptables, curl, and the Python `h2` package. It needs administrative privileges in a dedicated test environment. TLS HTTP/2 cases require Nginx built with `--with-http_v2_module` and `--with-http_ssl_module`.

For the Apache module and its build command, see [Apache 2.4](docs/APACHE.md).

## Configure Nginx

Start with MONITOR at the virtual-host level. Use BLOCK on a route after reviewing normal upload traffic. Keep request buffering enabled. Replace the proxy destination with your application upstream.

```nginx
server {
    listen 80;
    server_name uploads.example.com;

    upload_shield monitor;
    upload_shield_max_files 10;

    location /upload/ {
        upload_shield block;
        upload_shield_max_file_size 20m;
        proxy_request_buffering on;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### Nginx directives

These directives are available in the `http`, `server`, and `location` contexts. Child contexts inherit settings and can override them.

| Directive | Default | Description |
|---|---|---|
| `upload_shield off \| on \| monitor \| block` | `off` | Select a mode. `on` is equivalent to `monitor`. |
| `upload_shield_max_file_size size` | `0` (unlimited) | Maximum size of an individual file part. |
| `upload_shield_max_files count` | `20` | Maximum number of parts with a `filename`, including empty file selections. |
| `upload_shield_max_parts count` | `1000` | Maximum number of multipart parts. |
| `upload_shield_max_part_header_size size` | `2k` | Maximum header block size per part, from 1 to 8192 bytes. |
| `upload_shield_max_field_size size` | `1m` | Maximum value size for an individual non-file form field. |
| `upload_shield_max_part_headers count` | `8` | Maximum number of header lines per part. |
| `upload_shield_max_field_name_size size` | `256` | Maximum form field name length. |
| `upload_shield_max_field_name_depth count` | `8` | Maximum number of opening brackets in a form field name. |
| `upload_shield_max_body_size size` | Unset | Total multipart request body limit. When unset, Nginx's `client_max_body_size` applies. |
| `upload_shield_body_timeout time` | Unset | Time limit for receiving the full multipart body. When unset, only Nginx's `client_body_timeout` applies. |
| `upload_shield_deny_multipart on \| off` | `off` | Treat multipart requests in this context as policy violations. Use on routes that do not accept uploads. |
| `upload_shield_deny_session_progress on \| off` | `off` | Treat the configured PHP session upload progress field as a policy violation. |
| `upload_shield_session_progress_name name` | `PHP_SESSION_UPLOAD_PROGRESS` | Match PHP's `session.upload_progress.name`. |
| `upload_shield_filename_check on \| off` | `off` | Enable optional filename inspection. |
| `upload_shield_filename_deny_ext extension ...` | Built-in list | Replace the built-in list with case-insensitive extensions without leading dots. |
| `upload_shield_max_filename_size size` | `255` | Maximum filename length in bytes when filename inspection is enabled. |

### Body limits and timeouts

When the module body limit and timeout are unset, Nginx enforces `client_max_body_size` and `client_body_timeout`. A module limit applies only to multipart traffic in enabled contexts. It cannot raise the Nginx limit. Both timeout settings can apply at once: the Nginx timeout measures idle time between reads, and the module deadline measures total receive time.

| Configuration | Effective behavior |
|---|---|
| Module body limit smaller than Nginx's | The module applies its limit to multipart requests. BLOCK returns HTTP 413 (MGUS-401). MONITOR records the violation. |
| Nginx body limit smaller than the module's | Nginx can return HTTP 413 first. Use `nginx -t` to check for the configuration warning. |
| Stalled upload | Either deadline can expire first. |
| Slowly sending upload that stays within the Nginx read interval | The module's total receive deadline can still expire. In HTTP/2 BLOCK mode, only the affected stream is terminated. |

See the [settings reference](docs/SIZE-TIMEOUT-CONTRACT.md) for the contract and validation cases.

### Optional filename inspection

Enable `upload_shield_filename_check on` to check extension segments, filename characters, and length. The module checks all extension segments after the first dot against the case-insensitive denylist. It also rejects slashes, tabs, and trailing dots or spaces under the filename policy. Empty file selections skip these filename checks. The filename limit is 255 bytes by default. Names such as `archive.tar.gz` pass when their extension segments are absent from the denylist.

Use `upload_shield_filename_deny_ext` to replace the built-in list. The module evaluates the filename bytes as received. Filename decode and normalization performed by the application are outside this check. Uploaded content is outside the filename policy.

### Request outcomes

| Request | MONITOR | BLOCK |
|---|---|---|
| Policy violation | Forward and log the violation | Return HTTP 400 for structural violations, 413 for size limits, or 403 for count and policy violations. In supported buffered configurations, the backend receives no request. |
| Non-multipart body | Forward without multipart inspection | Same |
| Multipart request with request buffering disabled | Inspect and forward, with `guarantee: unbuffered` | Return HTTP 500 (MGUS-901). |
| Inspection context allocation fails | Forward | Return HTTP 500. |

Applying `upload_shield_deny_multipart on` to a route makes all multipart requests in that context violations. Reserve it for routes that do not accept uploads. Keep multipart enabled on upload routes and apply file and part limits there.

### Rule IDs

| Rule | Meaning |
|---|---|
| MGUS-100–107 | Boundary and delimiter validation, part headers, disposition, truncation, epilogue, or unsupported multipart syntax |
| MGUS-201–208 | Part header size, file size, file count, part count, field size, part header count, field name length, or field name depth |
| MGUS-301–302 | Disallowed upload progress field or multipart on a route that prohibits it |
| MGUS-311–313 | Disallowed extension, filename characters, or filename length |
| MGUS-401–402 | Total body size or receive deadline |
| MGUS-900–901 | Internal error or unsupported BLOCK configuration |

### Logs

Nginx writes one structured inspection record for an inspected request. Normal results use `info`; violations use `warn`. Access log formats can use `$upload_shield_action` and `$upload_shield_rule`. The action is `pass`, `monitor`, `block`, or `aborted`.

The inspection record includes rule IDs, request IDs, counters, and effective limits. It excludes body contents, filenames, form names and values, and cookies. Nginx may append its standard request context separately, including the query string.

## Apache and scope

The [Apache guide](docs/APACHE.md) describes build, configuration, and test coverage. Apache BLOCK requires `mod_proxy_fcgi`; use MONITOR with in-process `mod_php`.

The inspection engine handles multipart bodies. JSON and URL-encoded bodies are outside its scope. Rebuild and retest the Nginx module when switching server packages. See the [support matrix](docs/SUPPORT.md) for tested protocols, package versions, and backend transports.
