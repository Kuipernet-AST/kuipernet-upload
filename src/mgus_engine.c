/*
 * Kuipernet Upload - common multipart/form-data inspection engine.
 *
 * Design rule: whenever two reasonable parsers could disagree about where a
 * part starts or what it is called, the input is a structure violation.
 * The engine therefore accepts a strict subset of RFC 7578:
 *   - the body starts with "--boundary" (no preamble),
 *   - lines end in CRLF only; a bare LF before "--boundary" is a violation
 *     (PHP treats "\n--boundary" as a delimiter),
 *   - a delimiter is followed by CRLF or "--" only,
 *   - part headers: one per line, no folding, no control characters,
 *     exactly one Content-Disposition: form-data with exactly one name,
 *   - no backslash inside quoted parameters, no RFC 5987 "param*" forms,
 *     no nested multipart parts, no Content-Transfer-Encoding,
 *   - nothing but an optional CRLF after the closing boundary.
 *
 * Version 0.1.1 adds the optional file name policy (check_filename).
 */
#include "mgus_engine.h"

#include <string.h>

enum {
    S_FIRST = 0,        /* matching the initial "--boundary" */
    S_AFTER,            /* first byte after a delimiter */
    S_AFTER_DASH,       /* "-" seen after a delimiter */
    S_AFTER_CR,         /* CR seen after a delimiter */
    S_HEADERS,
    S_DATA,
    S_CLOSE0,           /* closing boundary seen */
    S_CLOSE1,           /* CR after closing boundary */
    S_END,              /* closing boundary and CRLF seen */
    S_DEAD              /* terminal violation: only count bytes */
};

static int
lc(int ch)
{
    return (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch;
}

static int
ieq(const unsigned char *a, size_t alen, const char *b)
{
    size_t  i, blen = strlen(b);

    if (alen != blen) {
        return 0;
    }
    for (i = 0; i < alen; i++) {
        if (lc(a[i]) != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int
iprefix(const unsigned char *a, size_t alen, const char *b)
{
    size_t  blen = strlen(b);

    return alen >= blen && ieq(a, blen, b);
}

static int
is_lws(int ch)
{
    return ch == ' ' || ch == '\t';
}

static int
is_token(int ch)
{
    if (ch <= 0x20 || ch >= 0x7f) {
        return 0;
    }
    return strchr("()<>@,;:\\\"/[]?={}", ch) == NULL;
}

static int
is_bchar(int ch)
{
    if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z')
        || (ch >= 'A' && ch <= 'Z'))
    {
        return 1;
    }
    return ch != 0 && strchr("'()+_-./:=?", ch) != NULL;
}

static void
violate(mgus_ctx_t *c, int rule, int terminal)
{
    if (c->rule == 0) {
        c->rule = rule;
    }
    if (terminal) {
        c->state = S_DEAD;
    }
}

void
mgus_set_rule(mgus_ctx_t *c, int rule)
{
    if (c->rule == 0) {
        c->rule = rule;
    }
}

int
mgus_boundary(const unsigned char *ct, size_t len, const unsigned char **b,
    size_t *blen)
{
    static const char   mt[] = "multipart/form-data";
    size_t              i, j, n, first, first_lc;
    int                 found = 0;
    const unsigned char *v;

    while (len && is_lws(ct[0])) {
        ct++;
        len--;
    }

    n = sizeof(mt) - 1;
    if (!iprefix(ct, len, mt)) {
        return 1;
    }
    if (len > n && ct[n] != ';' && !is_lws(ct[n])) {
        return 1;
    }

    /*
     * PHP locates the boundary by searching the header value for the
     * substring "boundary" (exact lower case first, then case-insensitively)
     * instead of parsing parameters. "first" and "first_lc" record where those
     * searches would land so that the parameter found below can be required
     * to be the same one. Browser boundaries such as "----WebKitFormBoundary.."
     * contain the substring themselves, so later occurrences are fine.
     */
    first = len;
    first_lc = len;
    for (i = n; i + 8 <= len; i++) {
        if (first == len && iprefix(ct + i, len - i, "boundary")) {
            first = i;
        }
        if (first_lc == len && memcmp(ct + i, "boundary", 8) == 0) {
            first_lc = i;
        }
    }
    if (first == len) {
        return MGUS_R_BOUNDARY;
    }

    i = n;
    for ( ;; ) {
        while (i < len && is_lws(ct[i])) {
            i++;
        }
        if (i == len) {
            return found ? 0 : MGUS_R_BOUNDARY;
        }
        if (ct[i] != ';') {
            return MGUS_R_BOUNDARY;
        }
        i++;
        while (i < len && is_lws(ct[i])) {
            i++;
        }

        j = i;
        while (j < len && is_token(ct[j])) {
            j++;
        }
        if (j == i || j == len || ct[j] != '=') {
            return MGUS_R_BOUNDARY;
        }

        if (ieq(ct + i, j - i, "boundary")) {
            if (found || i != first || (first_lc != len && first_lc != i)) {
                return MGUS_R_BOUNDARY;
            }
            j++;
            if (j < len && ct[j] == '"') {
                v = ct + ++j;
                while (j < len && ct[j] != '"') {
                    j++;
                }
                if (j == len) {
                    return MGUS_R_BOUNDARY;
                }
                n = (size_t) (ct + j - v);
                j++;

            } else {
                v = ct + j;
                while (j < len && ct[j] != ';') {
                    j++;
                }
                n = (size_t) (ct + j - v);
            }

            if (n == 0 || n > MGUS_BOUNDARY_MAX) {
                return MGUS_R_BOUNDARY;
            }
            for (i = 0; i < n; i++) {
                if (!is_bchar(v[i])) {
                    return MGUS_R_BOUNDARY;
                }
            }

            *b = v;
            *blen = n;
            found = 1;
            i = j;
            continue;
        }

        /* skip another parameter's value */
        j++;
        if (j < len && ct[j] == '"') {
            j++;
            while (j < len && ct[j] != '"') {
                if (ct[j] == '\\') {
                    return MGUS_R_BOUNDARY;
                }
                j++;
            }
            if (j == len) {
                return MGUS_R_BOUNDARY;
            }
            j++;

        } else {
            while (j < len && ct[j] != ';' && !is_lws(ct[j])) {
                j++;
            }
        }
        i = j;
    }
}

int
mgus_init(mgus_ctx_t *c, const mgus_limits_t *lim, const unsigned char *boundary,
    size_t blen)
{
    size_t  i;

    if (c == NULL || lim == NULL || boundary == NULL) {
        return MGUS_R_INTERNAL;
    }
    if (blen == 0 || blen > MGUS_BOUNDARY_MAX) {
        return MGUS_R_BOUNDARY;
    }
    for (i = 0; i < blen; i++) {
        if (!is_bchar(boundary[i])) {
            return MGUS_R_BOUNDARY;
        }
    }

    memset(c, 0, offsetof(mgus_ctx_t, hdr));
    c->lim = *lim;

    if (c->lim.max_part_header_size == 0
        || c->lim.max_part_header_size > MGUS_HDR_BUF)
    {
        c->lim.max_part_header_size = MGUS_HDR_BUF;
    }
    if (c->lim.deny_name_len > MGUS_NAME_MAX) {
        return MGUS_R_INTERNAL;
    }

    c->pat[0] = '\n';
    c->pat[1] = '-';
    c->pat[2] = '-';
    memcpy(c->pat + 3, boundary, blen);
    c->plen = 3 + blen;

    c->state = S_FIRST;
    c->k = 1;           /* the first delimiter has no leading CRLF */

    return 0;
}

/*
 * Parses "name=value" parameters of a Content-Disposition value.
 * Returns 0 or a rule.
 */
/*
 * Optional file name policy. Returns 0 or a rule.
 *
 * An extension is every dot-separated piece after the first dot, so that
 * "a.php.jpg" and ".htaccess" are caught while "php.txt" is not. A piece is
 * compared up to its first ':' and without trailing spaces ("a.php::$DATA").
 * Nothing is decoded: the bytes are judged as the client sent them.
 */
static int
check_filename(const mgus_ctx_t *c, const unsigned char *f, size_t len)
{
    size_t                i, start, end, n, t;
    const unsigned char  *d = c->lim.deny_ext;
    size_t                dlen = c->lim.deny_ext_len;

    if (len == 0) {
        return 0;       /* empty file control: nothing was selected */
    }

    if (c->lim.max_filename_size && len > c->lim.max_filename_size) {
        return MGUS_R_FILENAME_SIZE;
    }

    for (i = 0; i < len; i++) {
        if (f[i] == '/' || f[i] == '\\' || f[i] == '\t') {
            return MGUS_R_FILENAME_CHARS;
        }
    }
    start = 0;
    while (start < len && f[start] != '.') {
        start++;
    }

    while (start < len) {
        start++;                        /* skip the dot */
        end = start;
        while (end < len && f[end] != '.') {
            end++;
        }

        n = 0;
        while (start + n < end && f[start + n] != ':') {
            n++;
        }
        while (n && f[start + n - 1] == ' ') {
            n--;
        }

        t = 0;
        while (n && t < dlen) {
            size_t  e = t;

            while (e < dlen && d[e] != ' ') {
                e++;
            }
            if (e - t == n) {
                for (i = 0; i < n && lc(f[start + i]) == d[t + i]; i++) { /* */ }
                if (i == n) {
                    return MGUS_R_FILENAME_EXT;
                }
            }
            t = e + 1;
        }

        start = end;
    }

    if (f[len - 1] == '.' || f[len - 1] == ' ') {
        return MGUS_R_FILENAME_CHARS;
    }

    return 0;
}


static int
parse_disposition(mgus_ctx_t *c, const unsigned char *v, size_t len,
    const unsigned char **name, size_t *name_len, int *is_file,
    const unsigned char **fname, size_t *fname_len)
{
    size_t                i, j, klen, vlen;
    int                   have_name = 0, have_file = 0;
    const unsigned char  *val;

    i = 0;
    while (i < len && is_lws(v[i])) {
        i++;
    }
    if (!iprefix(v + i, len - i, "form-data")) {
        return MGUS_R_DISPOSITION;
    }
    i += 9;

    for ( ;; ) {
        while (i < len && is_lws(v[i])) {
            i++;
        }
        if (i == len) {
            break;
        }
        if (v[i] != ';') {
            return MGUS_R_DISPOSITION;
        }
        i++;
        while (i < len && is_lws(v[i])) {
            i++;
        }
        if (i == len) {
            break;      /* trailing ";" */
        }

        j = i;
        while (j < len && is_token(v[j])) {
            j++;
        }
        if (j == i || j == len || v[j] != '=') {
            return MGUS_R_DISPOSITION;
        }
        if (v[j - 1] == '*') {
            return MGUS_R_UNSUPPORTED;      /* RFC 5987 extended parameter */
        }
        klen = j - i;

        val = v + j + 1;
        if (val < v + len && *val == '"') {
            val++;
            vlen = 0;
            while (val + vlen < v + len && val[vlen] != '"') {
                if (val[vlen] == '\\') {
                    return MGUS_R_UNSUPPORTED;   /* escape rules differ */
                }
                vlen++;
            }
            if (val + vlen == v + len) {
                return MGUS_R_DISPOSITION;
            }
            j = (size_t) (val + vlen + 1 - v);

        } else {
            vlen = 0;
            while (val + vlen < v + len && val[vlen] != ';'
                   && !is_lws(val[vlen]))
            {
                if (val[vlen] == '"' || val[vlen] == '\\') {
                    return MGUS_R_DISPOSITION;
                }
                vlen++;
            }
            j = (size_t) (val + vlen - v);
        }

        if (ieq(v + i, klen, "name")) {
            if (have_name) {
                return MGUS_R_DISPOSITION;
            }
            have_name = 1;
            *name = val;
            *name_len = vlen;

        } else if (ieq(v + i, klen, "filename")) {
            if (have_file) {
                return MGUS_R_DISPOSITION;
            }
            have_file = 1;
            *fname = val;
            *fname_len = vlen;
        }

        i = j;
    }

    (void) c;

    if (!have_file) {
        *fname = NULL;
        *fname_len = 0;
    }

    if (!have_name) {
        return MGUS_R_DISPOSITION;
    }

    *is_file = have_file;
    return 0;
}

/* c->hdr[0 .. hdr_len) holds the header block including the final CRLFCRLF */
static void
parse_headers(mgus_ctx_t *c)
{
    size_t                pos, eol, colon, i, nlen = 0, flen = 0, depth;
    uint32_t              lines = 0;
    int                   rc, have_cd = 0, is_file = 0;
    const unsigned char  *h = c->hdr, *name = NULL, *fname = NULL;
    size_t                len = c->hdr_len;

    if (len > c->st.max_part_header_bytes) {
        c->st.max_part_header_bytes = (uint32_t) len;
    }

    /* pass 1: line syntax */
    pos = 0;
    while (pos + 2 <= len) {
        eol = pos;
        while (h[eol] != '\r') {
            eol++;
        }
        if (eol == pos) {
            break;      /* empty line: end of headers */
        }

        lines++;

        colon = pos;
        while (colon < eol && is_token(h[colon])) {
            colon++;
        }
        /* a leading SP/HT (folded header) is not a token character */
        if (colon == pos || colon == eol || h[colon] != ':') {
            violate(c, MGUS_R_PART_HEADER, 1);
            return;
        }

        pos = eol + 2;
    }

    /* pass 2: meaning */
    pos = 0;
    while (pos + 2 <= len) {
        eol = pos;
        while (h[eol] != '\r') {
            eol++;
        }
        if (eol == pos) {
            break;
        }

        colon = pos;
        while (h[colon] != ':') {
            colon++;
        }

        if (ieq(h + pos, colon - pos, "content-disposition")) {
            if (have_cd) {
                violate(c, MGUS_R_DISPOSITION, 1);
                return;
            }
            have_cd = 1;
            rc = parse_disposition(c, h + colon + 1, eol - colon - 1,
                                   &name, &nlen, &is_file, &fname, &flen);
            if (rc != 0) {
                violate(c, rc, 1);
                return;
            }

        } else if (ieq(h + pos, colon - pos, "content-type")) {
            i = colon + 1;
            while (i < eol && is_lws(h[i])) {
                i++;
            }
            if (iprefix(h + i, eol - i, "multipart/")) {
                violate(c, MGUS_R_UNSUPPORTED, 1);  /* nested multipart */
                return;
            }

        } else if (ieq(h + pos, colon - pos, "content-transfer-encoding")) {
            violate(c, MGUS_R_UNSUPPORTED, 1);
            return;
        }

        pos = eol + 2;
    }

    if (!have_cd) {
        violate(c, MGUS_R_DISPOSITION, 1);
        return;
    }

    if (c->lim.max_part_headers && lines > c->lim.max_part_headers) {
        violate(c, MGUS_R_PART_HEADER_COUNT, 0);
    }

    if (c->lim.max_name_size && nlen > c->lim.max_name_size) {
        violate(c, MGUS_R_NAME_SIZE, 0);
    }

    if (c->lim.max_name_depth) {
        depth = 0;
        for (i = 0; i < nlen; i++) {
            if (name[i] == '[') {
                depth++;
            }
        }
        if (depth > c->lim.max_name_depth) {
            violate(c, MGUS_R_NAME_DEPTH, 0);
        }
    }

    if (c->lim.deny_name != NULL && nlen == c->lim.deny_name_len
        && memcmp(name, c->lim.deny_name, nlen) == 0)
    {
        violate(c, MGUS_R_DENIED_FIELD, 0);
    }

    if (is_file && c->lim.filename_check) {
        rc = check_filename(c, fname, flen);
        if (rc != 0) {
            violate(c, rc, 0);
        }
    }

    c->is_file = is_file;

    if (is_file) {
        c->st.files++;
        if (c->lim.max_files && c->st.files > c->lim.max_files) {
            violate(c, MGUS_R_FILE_COUNT, 0);
        }

    } else {
        c->st.fields++;
    }
}

static void
begin_part(mgus_ctx_t *c)
{
    c->st.parts++;
    if (c->lim.max_parts && c->st.parts > c->lim.max_parts) {
        violate(c, MGUS_R_PART_COUNT, 0);
    }

    c->hdr_len = 0;
    c->prev = '\n';
    c->state = S_HEADERS;
}

static void
check_part_size(mgus_ctx_t *c, uint64_t size)
{
    if (c->is_file) {
        if (size > c->st.max_file_bytes) {
            c->st.max_file_bytes = size;
        }
        if (c->lim.max_file_size && size > c->lim.max_file_size) {
            violate(c, MGUS_R_FILE_SIZE, 0);
        }

    } else {
        if (size > c->st.max_field_bytes) {
            c->st.max_field_bytes = size;
        }
        if (c->lim.max_field_size && size > c->lim.max_field_size) {
            violate(c, MGUS_R_FIELD_SIZE, 0);
        }
    }
}

int
mgus_feed(mgus_ctx_t *c, const unsigned char *p, size_t n)
{
    const unsigned char  *end = p + n, *q;
    unsigned char         ch;
    uint64_t              pending;

    c->st.body_bytes += n;

    while (p < end) {

        switch (c->state) {

        case S_DEAD:
            return c->rule;

        case S_FIRST:
            ch = *p++;
            if (ch != c->pat[c->k]) {
                violate(c, MGUS_R_PREAMBLE, 1);
                break;
            }
            if (++c->k == c->plen) {
                c->state = S_AFTER;
            }
            break;

        case S_AFTER:
            ch = *p++;
            if (ch == '-') {
                c->state = S_AFTER_DASH;
            } else if (ch == '\r') {
                c->state = S_AFTER_CR;
            } else {
                violate(c, MGUS_R_DELIMITER, 1);
            }
            break;

        case S_AFTER_DASH:
            ch = *p++;
            if (ch == '-') {
                c->state = S_CLOSE0;
            } else {
                violate(c, MGUS_R_DELIMITER, 1);
            }
            break;

        case S_AFTER_CR:
            ch = *p++;
            if (ch == '\n') {
                begin_part(c);
            } else {
                violate(c, MGUS_R_DELIMITER, 1);
            }
            break;

        case S_HEADERS:
            ch = *p++;

            if (ch == '\0' || (ch < 0x20 && ch != '\t' && ch != '\r'
                               && ch != '\n') || ch == 0x7f)
            {
                violate(c, MGUS_R_PART_HEADER, 1);
                break;
            }
            if ((ch == '\n') != (c->prev == '\r')) {
                /* bare LF, or CR not followed by LF */
                violate(c, MGUS_R_PART_HEADER, 1);
                break;
            }

            if (c->hdr_len >= c->lim.max_part_header_size) {
                if (c->hdr_len + 1 > c->st.max_part_header_bytes) {
                    c->st.max_part_header_bytes = c->hdr_len + 1;
                }
                violate(c, MGUS_R_PART_HEADER_SIZE, 1);
                break;
            }

            c->hdr[c->hdr_len++] = ch;
            c->prev = ch;

            if (ch == '\n'
                && (c->hdr_len == 2
                    || (c->hdr_len >= 4 && c->hdr[c->hdr_len - 3] == '\n')))
            {
                parse_headers(c);
                if (c->state == S_DEAD) {
                    break;
                }
                c->state = S_DATA;
                c->k = 0;
                c->cr_before = 0;
                c->part_bytes = 0;
                c->prev = 0;
            }
            break;

        case S_DATA:
            if (c->k == 0) {
                /* fast path: nothing can match until the next LF */
                q = memchr(p, '\n', (size_t) (end - p));
                if (q == NULL) {
                    c->part_bytes += (uint64_t) (end - p);
                    c->prev = end[-1];
                    p = end;

                } else {
                    c->part_bytes += (uint64_t) (q - p) + 1;
                    c->cr_before = ((q > p ? q[-1] : c->prev) == '\r');
                    c->prev = '\n';
                    c->k = 1;
                    p = q + 1;
                }

            } else {
                ch = *p++;
                c->part_bytes++;

                if (ch == c->pat[c->k]) {
                    c->k++;

                } else if (ch == '\n') {
                    c->cr_before = (c->prev == '\r');
                    c->k = 1;

                } else {
                    c->k = 0;
                }
                c->prev = ch;

                if (c->k == c->plen) {
                    if (!c->cr_before) {
                        violate(c, MGUS_R_DELIMITER, 1);    /* bare LF */
                        break;
                    }
                    check_part_size(c, c->part_bytes - c->plen - 1);
                    c->k = 0;
                    c->state = S_AFTER;
                    break;
                }
            }

            /* bytes that may still turn out to belong to a delimiter */
            if (c->k) {
                pending = c->k + (c->cr_before ? 1 : 0);
            } else {
                pending = (c->prev == '\r') ? 1 : 0;
            }
            check_part_size(c, c->part_bytes - pending);
            break;

        case S_CLOSE0:
            ch = *p++;
            if (ch == '\r') {
                c->state = S_CLOSE1;
            } else {
                violate(c, MGUS_R_EPILOGUE, 1);
            }
            break;

        case S_CLOSE1:
            ch = *p++;
            if (ch == '\n') {
                c->state = S_END;
            } else {
                violate(c, MGUS_R_EPILOGUE, 1);
            }
            break;

        case S_END:
            violate(c, MGUS_R_EPILOGUE, 1);
            break;

        default:
            violate(c, MGUS_R_INTERNAL, 1);
            break;
        }
    }

    return c->rule;
}

int
mgus_finish(mgus_ctx_t *c)
{
    if (c->state == S_CLOSE0 || c->state == S_END || c->state == S_DEAD) {
        return c->rule;
    }

    violate(c, MGUS_R_TRUNCATED, 1);
    return c->rule;
}

const mgus_stats_t *
mgus_stats(const mgus_ctx_t *c)
{
    return &c->st;
}

const char *
mgus_rule_name(int rule)
{
    switch (rule) {
    case MGUS_OK:                   return "none";
    case MGUS_R_BOUNDARY:           return "boundary";
    case MGUS_R_PREAMBLE:           return "preamble";
    case MGUS_R_DELIMITER:          return "delimiter";
    case MGUS_R_PART_HEADER:        return "part_header";
    case MGUS_R_DISPOSITION:        return "content_disposition";
    case MGUS_R_TRUNCATED:          return "truncated";
    case MGUS_R_EPILOGUE:           return "epilogue";
    case MGUS_R_UNSUPPORTED:        return "unsupported_construct";
    case MGUS_R_PART_HEADER_SIZE:   return "part_header_size";
    case MGUS_R_FILE_SIZE:          return "file_size";
    case MGUS_R_FILE_COUNT:         return "file_count";
    case MGUS_R_PART_COUNT:         return "part_count";
    case MGUS_R_FIELD_SIZE:         return "field_size";
    case MGUS_R_PART_HEADER_COUNT:  return "part_header_count";
    case MGUS_R_NAME_SIZE:          return "field_name_size";
    case MGUS_R_NAME_DEPTH:         return "field_name_depth";
    case MGUS_R_DENIED_FIELD:       return "denied_field";
    case MGUS_R_MULTIPART_DENIED:   return "multipart_denied";
    case MGUS_R_FILENAME_EXT:       return "filename_extension";
    case MGUS_R_FILENAME_CHARS:     return "filename_chars";
    case MGUS_R_FILENAME_SIZE:      return "filename_size";
    case MGUS_R_BODY_SIZE:          return "body_size";
    case MGUS_R_BODY_TIMEOUT:       return "body_timeout";
    case MGUS_R_INTERNAL:           return "internal_error";
    case MGUS_R_UNBUFFERED:         return "unbuffered_config";
    default:                        return "unknown";
    }
}
