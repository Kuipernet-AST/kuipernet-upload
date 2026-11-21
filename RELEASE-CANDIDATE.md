# Kuipernet Upload 0.1.1 rc2

The source hashes identify the files in this snapshot. The engine and adapter changes after rc2 validation are comment-only branding edits. The binary hashes identify the original modules used during validation.

## Source SHA-256

```text
fe039677a10c7c5b74756b3bc203e3a5cffbf7aba849a223e20ddf58465bb3ae  src/mgus_engine.c
9cab68ff2dd9c84b64c642e24b7526231475f9839ea40fed8111b80ad73d7fa1  src/mgus_engine.h
2f2f1cbd57ce9570e57807cee7b82db50e430358b0fea9a1506ba70d2265b69b  nginx/ngx_http_upload_shield_module.c
edfc82da640f0d8093684f5c79fc3888cf8ad1db948cf9c60d88ff85c58afa3c  nginx/config
63eb9a23b658f7aac270210e73c36334569142c4407d270599e4c2123742eec2  apache/mod_upload_shield.c
```

## Tested module SHA-256

| Target | SHA-256 | Validation |
|---|---|---|
| Nginx 1.30.0 source build, Ubuntu 24.04, GCC 13.3.0 | `73718eb1e7dc888b590ea96d0cec096b6572733071965bc7d9f108c9b480ffb7` | 128 integration cases, 268 backend cases, 30-minute load run, ModSecurity comparison |
| Ubuntu 18.04 Nginx 1.14.0 distribution package | `0304473a33a082fe62533e32a9e317f3bf3001ad05a713f61707655c8b9fb7c0` | 28 functional cases and three-hour soak |
| Ubuntu 20.04 Nginx 1.18.0 distribution package | `f349e0b170edbbeffd9a1238f1cba66fcdce1a914b27a494cb95086d7bc9443c` | 28 functional cases |
| Ubuntu 22.04 Nginx 1.18.0 distribution package | `c72dc1312a7b8e709a1641f2e2df137db8c56b85f8664d06082f84f11a280277` | 28 functional cases |

Build or select the module for the target Nginx package and configure options. The Apache adapter source is the same as in rc1.
