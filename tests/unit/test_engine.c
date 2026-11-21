/*
 * Engine unit tests:
 *   1. table of bodies with an expected rule,
 *   2. split invariance: every case is fed whole, byte by byte, in every fixed
 *      chunk size and in random splits; verdict and counters must not change,
 *   3. mutation loop (run under ASan/UBSan): random edits of valid bodies must
 *      never crash and must keep split invariance.
 */
#include "mgus_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B "XbOuNdArY123"

static int failures;

static mgus_limits_t
default_limits(void)
{
    mgus_limits_t  l;

    memset(&l, 0, sizeof(l));
    l.max_file_size = 100;
    l.max_field_size = 20;
    l.max_files = 3;
    l.max_parts = 5;
    l.max_part_header_size = 200;
    l.max_part_headers = 3;
    l.max_name_size = 40;
    l.max_name_depth = 2;
    l.deny_name = (const unsigned char *) "PHP_SESSION_UPLOAD_PROGRESS";
    l.deny_name_len = 27;
    return l;
}

typedef struct {
    int           rule;
    mgus_stats_t  st;
} result_t;

static result_t
run(const mgus_limits_t *l, const unsigned char *body, size_t len, size_t chunk,
    unsigned *seed)
{
    static mgus_ctx_t  c;
    result_t           r;
    size_t             off = 0, n;

    memset(&r, 0, sizeof(r));
    r.rule = mgus_init(&c, l, (const unsigned char *) B, sizeof(B) - 1);
    if (r.rule) {
        return r;
    }

    while (off < len) {
        if (seed) {
            n = 1 + (size_t) (rand_r(seed) % 37);
        } else {
            n = chunk ? chunk : len;
        }
        if (n > len - off) {
            n = len - off;
        }
        mgus_feed(&c, body + off, n);
        off += n;
    }

    r.rule = mgus_finish(&c);
    r.st = *mgus_stats(&c);
    return r;
}

static int
same(const result_t *a, const result_t *b)
{
    return a->rule == b->rule && memcmp(&a->st, &b->st, sizeof(a->st)) == 0;
}

static int
check_split_invariance(const mgus_limits_t *l, const unsigned char *body,
    size_t len, const result_t *whole)
{
    size_t    chunk;
    unsigned  seed, i;
    result_t  r;

    for (chunk = 1; chunk <= len && chunk <= 96; chunk++) {
        r = run(l, body, len, chunk, NULL);
        if (!same(&r, whole)) {
            return (int) chunk;
        }
    }
    for (i = 1; i <= 20; i++) {
        seed = i * 7919u;
        r = run(l, body, len, 0, &seed);
        if (!same(&r, whole)) {
            return -(int) i;
        }
    }
    return 0;
}

static void
expect(const char *name, const mgus_limits_t *l, const char *body, size_t len,
    int rule)
{
    result_t  w;
    int       bad;

    w = run(l, (const unsigned char *) body, len, 0, NULL);
    bad = check_split_invariance(l, (const unsigned char *) body, len, &w);

    if (w.rule != rule || bad) {
        failures++;
        printf("FAIL %-34s expected %d got %d split=%d\n", name, rule, w.rule,
               bad);
    } else {
        printf("ok   %-34s rule=%d parts=%u files=%u fields=%u\n", name,
               w.rule, w.st.parts, w.st.files, w.st.fields);
    }
}

#define E(name, body, rule) \
    expect(name, &l, body, sizeof(body) - 1, rule)

#define P_FIELD(n, v) \
    "--" B "\r\nContent-Disposition: form-data; name=\"" n "\"\r\n\r\n" v "\r\n"
#define P_FILE(n, f, v) \
    "--" B "\r\nContent-Disposition: form-data; name=\"" n "\"; filename=\"" f \
    "\"\r\nContent-Type: application/octet-stream\r\n\r\n" v "\r\n"
#define CLOSE "--" B "--\r\n"

static void
expect_ct(const char *name, const char *ct, int rc, const char *b)
{
    const unsigned char  *p = NULL;
    size_t                n = 0;
    int                   got;

    got = mgus_boundary((const unsigned char *) ct, strlen(ct), &p, &n);
    if (got != rc || (rc == 0 && (n != strlen(b) || memcmp(p, b, n) != 0))) {
        failures++;
        printf("FAIL ct %-31s expected %d got %d\n", name, rc, got);
    } else {
        printf("ok   ct %-31s rc=%d\n", name, got);
    }
}

static void
mutate(unsigned rounds)
{
    static const char  base[] =
        P_FIELD("a", "1") P_FILE("f[]", "a.tar.gz", "hello\r\nworld")
        P_FILE("f[]", "b.txt", "\r\n--XbOuNd\n--\r") P_FIELD("b", "") CLOSE;
    static const char  toks[] = "\r\n-\"; =:*\\\t./ph" B;
    unsigned char      buf[sizeof(base) + 64];
    mgus_limits_t      l = default_limits();
    unsigned           seed = 12345, i, j, edits;

    l.filename_check = 1;
    l.max_filename_size = 12;
    l.deny_ext = (const unsigned char *) "php js gz";
    l.deny_ext_len = 9;

    size_t             len, pos, k;
    result_t           w;
    int                hist[1000];

    memset(hist, 0, sizeof(hist));

    for (i = 0; i < rounds; i++) {
        len = sizeof(base) - 1;
        memcpy(buf, base, len);
        edits = 1 + (unsigned) rand_r(&seed) % 3;

        for (j = 0; j < edits && len > 1; j++) {
            pos = (size_t) rand_r(&seed) % len;
            switch (rand_r(&seed) % 4) {
            case 0:     /* overwrite */
                buf[pos] = (unsigned char) toks[(size_t) rand_r(&seed)
                                                % (sizeof(toks) - 1)];
                break;
            case 1:     /* delete */
                memmove(buf + pos, buf + pos + 1, len - pos - 1);
                len--;
                break;
            case 2:     /* insert token byte */
                memmove(buf + pos + 1, buf + pos, len - pos);
                buf[pos] = (unsigned char) toks[(size_t) rand_r(&seed)
                                                % (sizeof(toks) - 1)];
                len++;
                break;
            default:    /* truncate or random byte */
                if (rand_r(&seed) % 4 == 0) {
                    len = pos + 1;
                } else {
                    buf[pos] = (unsigned char) rand_r(&seed);
                }
                break;
            }
        }

        w = run(&l, buf, len, 0, NULL);
        hist[w.rule]++;

        for (k = 1; k <= 3; k++) {
            result_t  r = run(&l, buf, len, k, NULL);
            if (!same(&r, &w)) {
                failures++;
                printf("FAIL mutation %u: split %zu differs\n", i, k);
                return;
            }
        }
        {
            unsigned  s2 = i + 1;
            result_t  r = run(&l, buf, len, 0, &s2);
            if (!same(&r, &w)) {
                failures++;
                printf("FAIL mutation %u: random split differs\n", i);
                return;
            }
        }
    }

    printf("ok   mutation rounds=%u verdicts:", rounds);
    for (i = 0; i < 1000; i++) {
        if (hist[i]) {
            printf(" %u=%d", i, hist[i]);
        }
    }
    printf("\n");
}

int
main(int argc, char **argv)
{
    mgus_limits_t  l = default_limits();
    unsigned       rounds = argc > 1 ? (unsigned) atoi(argv[1]) : 200000;

    /* accepted */
    E("single field", P_FIELD("a", "1") CLOSE, 0);
    E("close without CRLF", P_FIELD("a", "1") "--" B "--", 0);
    E("empty form", CLOSE, 0);
    E("multi-file same name", P_FILE("f[]", "a.tar.gz", "x")
      P_FILE("f[]", "b.min.js", "y") P_FILE("f[]", "c", "z") CLOSE, 0);
    E("empty file control", P_FILE("f", "", "") CLOSE, 0);
    E("file exactly at limit", P_FILE("f", "a",
      "0123456789012345678901234567890123456789012345678901234567890123456789"
      "012345678901234567890123456789") CLOSE, 0);
    E("data with CR/LF/dashes", P_FILE("f", "a",
      "\r\n--XbOuNdArY12\r\n--\n-\r\r\n") CLOSE, 0);
    E("unquoted name", "--" B "\r\nContent-Disposition: form-data; name=a\r\n"
      "\r\nv\r\n" CLOSE, 0);
    E("header case, extra param", "--" B "\r\ncontent-disposition: FORM-DATA;"
      " x=y; NAME=\"a\"\r\n\r\nv\r\n" CLOSE, 0);
    E("field at limit", P_FIELD("a", "01234567890123456789") CLOSE, 0);

    /* structure */
    E("preamble", "junk\r\n" P_FIELD("a", "1") CLOSE, MGUS_R_PREAMBLE);
    E("leading CRLF", "\r\n" P_FIELD("a", "1") CLOSE, MGUS_R_PREAMBLE);
    E("empty body", "", MGUS_R_TRUNCATED);
    E("truncated in data", P_FIELD("a", "1") "--" B "\r\nContent-Disposition: "
      "form-data; name=\"f\"; filename=\"x\"\r\n\r\ndata", MGUS_R_TRUNCATED);
    E("truncated before close", P_FIELD("a", "1"), MGUS_R_TRUNCATED);
    E("truncated in headers", "--" B "\r\nContent-Dispo", MGUS_R_TRUNCATED);
    E("bare LF delimiter", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\r\n\r\n1\n--" B "\r\nContent-Disposition: form-data; "
      "name=\"b\"\r\n\r\n2\r\n" CLOSE, MGUS_R_DELIMITER);
    E("junk after delimiter", "--" B "X\r\n" P_FIELD("a", "1") CLOSE,
      MGUS_R_DELIMITER);
    E("space after delimiter", "--" B " \r\nContent-Disposition: form-data; "
      "name=\"a\"\r\n\r\n1\r\n" CLOSE, MGUS_R_DELIMITER);
    E("epilogue", P_FIELD("a", "1") CLOSE "extra", MGUS_R_EPILOGUE);
    E("second message after close", P_FIELD("a", "1") CLOSE
      P_FIELD("b", "2") CLOSE, MGUS_R_EPILOGUE);
    E("bare LF in headers", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\n\r\n1\r\n" CLOSE, MGUS_R_PART_HEADER);
    E("LF-only header end", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\n\n1\r\n" CLOSE, MGUS_R_PART_HEADER);
    E("folded header", "--" B "\r\nContent-Disposition: form-data;\r\n "
      "name=\"a\"\r\n\r\n1\r\n" CLOSE, MGUS_R_PART_HEADER);
    E("header without colon", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\r\nbogus\r\n\r\n1\r\n" CLOSE, MGUS_R_PART_HEADER);
    E("NUL in headers", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\0b\"\r\n\r\n1\r\n" CLOSE, MGUS_R_PART_HEADER);
    E("no headers", "--" B "\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("no content-disposition", "--" B "\r\nContent-Type: text/plain\r\n\r\n1"
      "\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("duplicate content-disposition", "--" B "\r\nContent-Disposition: "
      "form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"b\"; "
      "filename=\"x\"\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("duplicate name", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"; name=\"b\"\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("missing name", "--" B "\r\nContent-Disposition: form-data; "
      "filename=\"x\"\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("not form-data", "--" B "\r\nContent-Disposition: attachment; "
      "name=\"a\"\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("unterminated quote", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\r\n\r\n1\r\n" CLOSE, MGUS_R_DISPOSITION);
    E("backslash in quoted value", "--" B "\r\nContent-Disposition: "
      "form-data; name=\"a\\\"; filename=\"x\"\r\n\r\n1\r\n" CLOSE,
      MGUS_R_UNSUPPORTED);
    E("filename* parameter", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"; filename*=UTF-8''x\r\n\r\n1\r\n" CLOSE, MGUS_R_UNSUPPORTED);
    E("nested multipart", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\r\nContent-Type: multipart/mixed; boundary=q\r\n\r\n1\r\n"
      CLOSE, MGUS_R_UNSUPPORTED);
    E("content-transfer-encoding", "--" B "\r\nContent-Disposition: "
      "form-data; name=\"a\"\r\nContent-Transfer-Encoding: base64\r\n\r\n1\r\n"
      CLOSE, MGUS_R_UNSUPPORTED);

    /* limits */
    E("file one byte over limit", P_FILE("f", "a",
      "0123456789012345678901234567890123456789012345678901234567890123456789"
      "0123456789012345678901234567890") CLOSE, MGUS_R_FILE_SIZE);
    E("last part file over limit", P_FIELD("a", "1") P_FILE("f", "ok", "fine")
      P_FILE("g", "big",
      "0123456789012345678901234567890123456789012345678901234567890123456789"
      "0123456789012345678901234567890123456789") CLOSE, MGUS_R_FILE_SIZE);
    E("field over limit", P_FIELD("a", "012345678901234567890") CLOSE,
      MGUS_R_FIELD_SIZE);
    E("too many files", P_FILE("f", "1", "") P_FILE("f", "2", "")
      P_FILE("f", "3", "") P_FILE("f", "4", "") CLOSE, MGUS_R_FILE_COUNT);
    E("too many parts", P_FIELD("a", "") P_FIELD("b", "") P_FIELD("c", "")
      P_FIELD("d", "") P_FIELD("e", "") P_FIELD("f", "") CLOSE,
      MGUS_R_PART_COUNT);
    E("part header too large", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\r\nX-Pad: 0123456789012345678901234567890123456789012345678"
      "9012345678901234567890123456789012345678901234567890123456789012345678"
      "9012345678901234567890123456789012345678901234567890123456789\r\n\r\n1"
      "\r\n" CLOSE, MGUS_R_PART_HEADER_SIZE);
    E("too many part headers", "--" B "\r\nContent-Disposition: form-data; "
      "name=\"a\"\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n1\r\n" CLOSE,
      MGUS_R_PART_HEADER_COUNT);
    E("field name too long", P_FIELD(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1") CLOSE, MGUS_R_NAME_SIZE);
    E("field name too deep", P_FIELD("a[b][c][d]", "1") CLOSE,
      MGUS_R_NAME_DEPTH);

    /* policy */
    E("denied field", P_FIELD("a", "1")
      P_FIELD("PHP_SESSION_UPLOAD_PROGRESS", "x") CLOSE, MGUS_R_DENIED_FIELD);
    E("denied field as last part", P_FILE("f", "a", "data")
      P_FIELD("PHP_SESSION_UPLOAD_PROGRESS", "x") CLOSE, MGUS_R_DENIED_FIELD);
    E("similar field name allowed", P_FIELD("PHP_SESSION_UPLOAD_PROGRES", "x")
      CLOSE, 0);

    /* optional file name policy (off above: such names passed) */
    E("policy off: shell.php passes", P_FILE("f", "shell.php", "x") CLOSE, 0);
    l.filename_check = 1;
    l.max_filename_size = 40;
    l.deny_ext = (const unsigned char *) "php phtml phar jsp htaccess";
    l.deny_ext_len = 27;

    E("fn ok: report.pdf", P_FILE("f", "report.pdf", "x") CLOSE, 0);
    E("fn ok: archive.tar.gz", P_FILE("f", "archive.tar.gz", "x") CLOSE, 0);
    E("fn ok: jquery-3.7.1.min.js", P_FILE("f", "jquery-3.7.1.min.js", "x")
      CLOSE, 0);
    E("fn ok: c.v1.2.pdf", P_FILE("f", "c.v1.2.pdf", "x") CLOSE, 0);
    E("fn ok: no extension", P_FILE("f", "README", "x") CLOSE, 0);
    E("fn ok: dot file", P_FILE("f", ".gitignore", "x") CLOSE, 0);
    E("fn ok: php.txt (base name)", P_FILE("f", "php.txt", "x") CLOSE, 0);
    E("fn ok: a.phpx / myphp.jpg", P_FILE("f", "a.phpx", "x")
      P_FILE("g", "myphp.jpg", "y") CLOSE, 0);
    E("fn ok: spaces, semicolon, UTF-8", P_FILE("f",
      "my file;v2 (1) \xeb\xb3\xb4\xea\xb3\xa0.txt", "x") CLOSE, 0);
    E("fn ok: empty file selection", P_FILE("f", "", "") CLOSE, 0);
    E("fn ok: field named like a file", P_FIELD("shell.php", "x") CLOSE, 0);
    E("fn ok: 40-byte name", P_FILE("f",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt", "x") CLOSE, 0);

    E("fn deny: shell.php", P_FILE("f", "shell.php", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: SHELL.PhP", P_FILE("f", "SHELL.PhP", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: shell.php.jpg", P_FILE("f", "shell.php.jpg", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: a.tar.phtml.gz", P_FILE("f", "a.tar.phtml.gz", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: .htaccess", P_FILE("f", ".htaccess", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: a.php. (trailing dot)", P_FILE("f", "a.php.", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: a.php  (trailing space)", P_FILE("f", "a.php ", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: a.php::$DATA", P_FILE("f", "a.php::$DATA", "x") CLOSE,
      MGUS_R_FILENAME_EXT);
    E("fn deny: last part of several", P_FILE("f[]", "ok.txt", "x")
      P_FILE("f[]", "b.jsp", "y") CLOSE, MGUS_R_FILENAME_EXT);
    E("fn deny: a.txt. (trailing dot)", P_FILE("f", "a.txt.", "x") CLOSE,
      MGUS_R_FILENAME_CHARS);
    E("fn deny: trailing space", P_FILE("f", "a.txt ", "x") CLOSE,
      MGUS_R_FILENAME_CHARS);
    E("fn deny: path separator", P_FILE("f", "../up/a.txt", "x") CLOSE,
      MGUS_R_FILENAME_CHARS);
    E("fn deny: tab", P_FILE("f", "a\tb.txt", "x") CLOSE,
      MGUS_R_FILENAME_CHARS);
    E("fn deny: dot-dot", P_FILE("f", "..", "x") CLOSE, MGUS_R_FILENAME_CHARS);
    E("fn deny: 41-byte name", P_FILE("f",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt", "x") CLOSE,
      MGUS_R_FILENAME_SIZE);
    E("fn: backslash stays a structure rule", "--" B "\r\nContent-Disposition:"
      " form-data; name=\"f\"; filename=\"C:\\dir\\a.txt\"\r\n\r\nx\r\n" CLOSE,
      MGUS_R_UNSUPPORTED);
    l = default_limits();

    /* Content-Type */
    expect_ct("plain", "multipart/form-data; boundary=abc", 0, "abc");
    expect_ct("quoted", "multipart/form-data; boundary=\"a-b_c\"", 0, "a-b_c");
    expect_ct("charset first", "Multipart/Form-Data; charset=utf-8; "
              "BOUNDARY=----WebKitFormBoundary7MA4YWxk", 0,
              "----WebKitFormBoundary7MA4YWxk");
    expect_ct("not multipart", "application/json", 1, "");
    expect_ct("other multipart", "multipart/mixed; boundary=abc", 1, "");
    expect_ct("prefix media type", "multipart/form-dataX; boundary=abc", 1, "");
    expect_ct("missing boundary", "multipart/form-data", MGUS_R_BOUNDARY, "");
    expect_ct("empty boundary", "multipart/form-data; boundary=",
              MGUS_R_BOUNDARY, "");
    expect_ct("two boundary substrings", "multipart/form-data; xboundary=a; "
              "boundary=b", MGUS_R_BOUNDARY, "");
    expect_ct("duplicate boundary", "multipart/form-data; boundary=a; "
              "boundary=b", MGUS_R_BOUNDARY, "");
    expect_ct("comma in boundary", "multipart/form-data; boundary=a,b",
              MGUS_R_BOUNDARY, "");
    expect_ct("space in boundary", "multipart/form-data; boundary=\"a b\"",
              MGUS_R_BOUNDARY, "");
    expect_ct("mixed case then lower", "multipart/form-data; Boundary=a; "
              "boundary=b", MGUS_R_BOUNDARY, "");
    expect_ct("lower inside upper value", "multipart/form-data; "
              "BOUNDARY=xboundaryx", MGUS_R_BOUNDARY, "");
    expect_ct("space after unquoted", "multipart/form-data; boundary=abc ; "
              "charset=x", MGUS_R_BOUNDARY, "");
    expect_ct("firefox style", "multipart/form-data; boundary=-------------"
              "--------------735323031399963166993862150", 0,
              "---------------------------735323031399963166993862150");
    expect_ct("too long", "multipart/form-data; boundary=aaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              MGUS_R_BOUNDARY, "");

    mutate(rounds);

    printf("%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures != 0;
}
