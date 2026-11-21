# Ubuntu 18.04 three-hour soak test

**Result: passed.** The rc2 Nginx module completed a 10,918-second workload with 47,930 test cases and zero unexpected results. Nginx recorded no alert, critical, or emergency events. The worker PID was 223 throughout.

| Item | Value |
|---|---|
| Run | 2026-11-20 21:17:23 to 2026-11-21 00:21:00 KST |
| Environment | Ubuntu 18.04 chroot using the host kernel. Public Bionic repositories. |
| Nginx package | `1.14.0-0ubuntu1.11` |
| PHP-FPM package | `7.2.24-0ubuntu0.18.04.17` |
| Access | Buffered FastCGI on a Unix socket, one Nginx worker and six FPM children |
| Module bytes | 140,112 |
| Module SHA-256, before and after | `0304473a33a082fe62533e32a9e317f3bf3001ad05a713f61707655c8b9fb7c0` |

The module was built against the matching Ubuntu source package using the configure arguments reported by `nginx -V`. It was the same file used for the [28-case legacy suite](LEGACY.md). The load sent a mix of requests from six simultaneous clients. BLOCK enforced the upload progress field policy, a one-megabyte per-file limit, a four-file limit, the filename policy, and a two-second receive deadline on the test route.

| Scenario | Cases | Observed outcome |
|---|---:|---|
| Normal HTTP/2 upload | 14,466 | HTTP 200 |
| Shared HTTP/2 connection | 10,511 | Stalled stream closed. Both normal streams returned HTTP 200. Connection remained open. |
| Normal HTTP/1.1 upload | 9,581 | HTTP 200. About 30% used chunked encoding. |
| HTTP/2 timeout, standalone connection | 5,601 | Closed at about two seconds |
| HTTP/1.1 timeout | 1,937 | Closed at about two seconds |
| Disallowed progress field over HTTP/2 | 1,927 | HTTP 403 |
| Client disconnected during upload | 1,467 | No response |
| Final file exceeded size limit | 1,423 | HTTP 413 |
| Multipart sent to a route without uploads | 1,017 | HTTP 403 |

The PHP-FPM access log and application records each counted 45,069 successful uploads. All matched the expected file SHA-256 and field count. PHP-FPM logged zero timeout, policy violation, or aborted upload cases. In each shared-connection case, one normal upload was in progress when the timeout fired and another began afterward.

The runner sampled RSS, file descriptors, and temporary files about every 10 seconds (1,074 samples). Worker RSS remained at 4,692 kB in the later samples. At completion the worker had 12 open descriptors and zero remaining Nginx or PHP upload temporary files.

## Load segments

| Start (s) | Duration (s) | Cases | Unexpected | Alerts/exits | Worker RSS (kB) | Open descriptors | Temporary files |
|---|---|---|---|---|---|---|---|
| 0 | 910 | 4031 | 0 | 0 | [4608] | 12 | 0 |
| 902 | 910 | 4018 | 0 | 0 | [4676] | 12 | 0 |
| 1807 | 910 | 3861 | 0 | 0 | [4692] | 12 | 0 |
| 2715 | 909 | 4021 | 0 | 0 | [4692] | 12 | 0 |
| 3617 | 910 | 3876 | 0 | 0 | [4692] | 12 | 0 |
| 4523 | 910 | 4184 | 0 | 0 | [4692] | 12 | 0 |
| 5432 | 910 | 3972 | 0 | 0 | [4692] | 12 | 0 |
| 6333 | 910 | 3858 | 0 | 0 | [4692] | 12 | 0 |
| 7237 | 910 | 4007 | 0 | 0 | [4692] | 12 | 0 |
| 8146 | 909 | 4154 | 0 | 0 | [4692] | 12 | 0 |
| 9045 | 909 | 3937 | 0 | 0 | [4692] | 12 | 0 |
| 9950 | 911 | 4011 | 0 | 0 | [4692] | 12 | 0 |

## Resource samples

| Minute | Worker RSS (kB) | Open descriptors | Open temporary files | PHP-FPM RSS (kB) | Worker PID |
|---|---|---|---|---|---|
| 0 | 4332 | 25 | 7 | 42512 | [223] |
| 14 | 4608 | 28 | 10 | 63032 | [223] |
| 29 | 4676 | 27 | 9 | 63180 | [223] |
| 44 | 4692 | 27 | 9 | 63212 | [223] |
| 59 | 4692 | 26 | 8 | 63228 | [223] |
| 74 | 4692 | 27 | 9 | 63232 | [223] |
| 89 | 4692 | 27 | 9 | 63232 | [223] |
| 104 | 4692 | 27 | 9 | 63232 | [223] |
| 119 | 4692 | 24 | 6 | 63240 | [223] |
| 134 | 4692 | 27 | 9 | 63240 | [223] |
| 149 | 4692 | 26 | 8 | 63240 | [223] |
| 164 | 4692 | 25 | 7 | 63240 | [223] |
| 180 | 4692 | 26 | 8 | 63240 | [223] |
| 180 | 4692 | 12 | 0 | 63240 | [223] |

An earlier attempt ended when the test VM restarted. Its 24,033 cases across 5,410 seconds of complete segments are excluded from the totals. The successful run restarted from zero with the same module.

The 18.04 soak used cleartext HTTP/2 and a local PHP-FPM socket. TLS, ESM packages, TCP FastCGI, and multiple Nginx workers were outside the test scope. The results cover compatibility and policy enforcement.
