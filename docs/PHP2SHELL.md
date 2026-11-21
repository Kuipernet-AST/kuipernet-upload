# PHP2Shell policy scope

This document covers CVE-2026-109618 and CVE-2026-109619. Kuipernet Upload can enforce selected request policies at the web server. The tests establish whether those policies keep matching requests from reaching a backend. They leave CVE mitigation on vulnerable PHP builds unverified.

| Policy | Setting | Evidence |
|---|---|---|
| Reject the PHP session upload progress field | `upload_shield_deny_session_progress on`. Match `upload_shield_session_progress_name` to the PHP configuration. | Verified before backend delivery in the tested BLOCK configurations. Rule MGUS-301. |
| Reject multipart on routes without uploads | `upload_shield_deny_multipart on` | Verified before delivery in the tested BLOCK configurations. Rule MGUS-302. |
| Limit files, multipart parts, headers, and field sizes | See the [Nginx directives](../README.md#nginx-directives). | Enforcement was measured with policy test cases. Coverage varies by configuration. |

CVE-2026-109619 includes a documented PHP session upload progress path. The optional field rule covers requests that contain the configured field. Any application that uses this field will need a route-specific policy decision.

Public analysis describes CVE-2026-109618 paths using `application/x-www-form-urlencoded`. The module's multipart inspection does not cover that content type.

Both issues have upstream PHP fixes. Use the PHP advisory and the package vendor's security information to determine whether the running PHP package includes the fixes. The [support matrix](SUPPORT.md) identifies which packages were used in module validation.

- [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory for CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [NCSC-NL operational guidance](https://github.com/NCSC-NL/php2shell)
- [Datadog Security Labs analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)

See the [ModSecurity comparison](COMPARE-MODSECURITY.md) for the policy tests and [backend validation](TEST-REPORT-ROUND3.md) for the delivery checks.
