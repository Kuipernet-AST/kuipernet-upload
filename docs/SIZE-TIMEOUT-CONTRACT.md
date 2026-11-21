# Request size limits and receive deadlines

The Nginx module's total-body controls apply to `multipart/form-data` in contexts where inspection is enabled. Per-file limits are evaluated separately.

| Setting | What it measures | When the module setting is absent |
|---|---|---|
| `upload_shield_max_body_size` | Total multipart request body size | Nginx enforces `client_max_body_size`. |
| `upload_shield_body_timeout` | Time from the first body read to completion of the body | Nginx enforces `client_body_timeout`, which measures the interval between two reads. |

## Size limits

In BLOCK mode a module body-size violation produces HTTP 413 (MGUS-401). MONITOR logs the violation and continues forwarding, subject to Nginx's own limit. If the Nginx limit is smaller, it can reject the body first. A zero Nginx limit disables its size check, and a configured module limit can still apply.

## Timeouts

The Nginx idle limit and the module's total receive deadline run independently. A stalled client can reach the idle limit first. A slowly sending client can reach the total receive deadline while staying within the Nginx read interval.

In BLOCK mode, the module terminates the HTTP/1.x connection on expiry. For HTTP/2 it terminates the affected stream and leaves other streams on the connection active. In MONITOR mode the module records the expiry and allows the request to proceed, subject to the Nginx timeouts.

## Configuration diagnostics

Run `nginx -t` after changing limits. See `config_conflict` in the request log for configurations where Nginx can apply its limit before the module. The log also records `body_limit`, `body_limit_src`, and `body_timeout_ms`.

## Verification

The [backend report](TEST-REPORT-ROUND3.md) contains tests E161–E177 for HTTP/1.1, E178–E194 for cleartext HTTP/2, and E262–E268 for HTTP/2 over TLS. The shared-connection tests confirm stream isolation. The case of a continuously sending client with a module deadline longer than the Nginx idle limit was documented separately from the tested stalled-client case.

Apache applies `LimitRequestBody` and `RequestReadTimeout`. The Apache adapter does not expose module-wide total size and receive deadline directives.
