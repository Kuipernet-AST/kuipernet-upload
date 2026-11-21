/*
 * Kuipernet Upload - common multipart/form-data inspection engine.
 *
 * The engine is independent of any web server API. It performs no I/O and no
 * dynamic allocation: the caller owns one fixed-size mgus_ctx_t per request
 * and feeds the (already de-chunked) request body in arbitrary pieces.
 * The engine never copies or modifies body data.
 */
#ifndef MGUS_ENGINE_H
#define MGUS_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#define MGUS_VERSION            "0.1.1"

#define MGUS_BOUNDARY_MAX       70      /* RFC 2046 */
#define MGUS_HDR_BUF            8192    /* hard cap of one part's header block */
#define MGUS_NAME_MAX           1024    /* hard cap of the deny-name setting */

/* Rule identifiers. 0 means "no violation". */
enum {
    MGUS_OK                     = 0,

    /* structure: the request cannot be interpreted unambiguously */
    MGUS_R_BOUNDARY             = 100,  /* Content-Type boundary missing/invalid/ambiguous */
    MGUS_R_PREAMBLE             = 101,  /* body does not start with the boundary */
    MGUS_R_DELIMITER            = 102,  /* malformed delimiter line */
    MGUS_R_PART_HEADER          = 103,  /* malformed part header block */
    MGUS_R_DISPOSITION          = 104,  /* Content-Disposition missing/duplicate/invalid */
    MGUS_R_TRUNCATED            = 105,  /* body ended before the closing boundary */
    MGUS_R_EPILOGUE             = 106,  /* data after the closing boundary */
    MGUS_R_UNSUPPORTED          = 107,  /* construct the engine refuses to interpret */

    /* limits */
    MGUS_R_PART_HEADER_SIZE     = 201,
    MGUS_R_FILE_SIZE            = 202,
    MGUS_R_FILE_COUNT           = 203,
    MGUS_R_PART_COUNT           = 204,
    MGUS_R_FIELD_SIZE           = 205,
    MGUS_R_PART_HEADER_COUNT    = 206,
    MGUS_R_NAME_SIZE            = 207,
    MGUS_R_NAME_DEPTH           = 208,

    /* optional policies */
    MGUS_R_DENIED_FIELD         = 301,  /* e.g. PHP session upload progress field */
    MGUS_R_MULTIPART_DENIED     = 302,  /* connector: multipart not allowed here */
    MGUS_R_FILENAME_EXT         = 311,  /* denied extension anywhere in the file name */
    MGUS_R_FILENAME_CHARS       = 312,  /* path separator, tab, trailing dot or space */
    MGUS_R_FILENAME_SIZE        = 313,  /* file name too long */

    /* connector-level */
    MGUS_R_BODY_SIZE            = 401,
    MGUS_R_BODY_TIMEOUT         = 402,
    MGUS_R_INTERNAL             = 900,
    MGUS_R_UNBUFFERED           = 901   /* BLOCK requested where it cannot be guaranteed */
};

typedef struct {
    uint64_t    max_file_size;          /* bytes per file part, 0 = no limit */
    uint64_t    max_field_size;         /* bytes per non-file part, 0 = no limit */
    uint32_t    max_files;              /* parts carrying a filename, 0 = no limit */
    uint32_t    max_parts;              /* all parts, 0 = no limit */
    uint32_t    max_part_header_size;   /* 1..MGUS_HDR_BUF; 0 selects MGUS_HDR_BUF */
    uint32_t    max_part_headers;       /* header lines per part, 0 = no limit */
    uint32_t    max_name_size;          /* bytes of the form field name, 0 = no limit */
    uint32_t    max_name_depth;         /* '[' occurrences in the name, 0 = no limit */
    const unsigned char *deny_name;     /* exact field name to deny, NULL = none */
    size_t      deny_name_len;

    /* optional file name policy; applies to non-empty file names only */
    int         filename_check;         /* 0 = off */
    uint32_t    max_filename_size;      /* bytes, 0 = no limit */
    const unsigned char *deny_ext;      /* lower-case extensions separated by ' ' */
    size_t      deny_ext_len;
} mgus_limits_t;

typedef struct {
    uint64_t    body_bytes;
    uint64_t    max_file_bytes;         /* largest file part seen */
    uint64_t    max_field_bytes;        /* largest non-file part seen */
    uint32_t    parts;
    uint32_t    files;
    uint32_t    fields;
    uint32_t    max_part_header_bytes;
} mgus_stats_t;

typedef struct {
    mgus_limits_t   lim;
    mgus_stats_t    st;

    int             rule;               /* first violation, 0 if none */
    int             state;

    unsigned char   pat[3 + MGUS_BOUNDARY_MAX];   /* "\n--" boundary */
    size_t          plen;
    size_t          k;                  /* matched prefix of pat */
    int             cr_before;          /* candidate delimiter was preceded by CR */
    unsigned char   prev;               /* previous body byte in the current state */

    int             is_file;
    uint64_t        part_bytes;

    uint32_t        hdr_len;
    unsigned char   hdr[MGUS_HDR_BUF];
} mgus_ctx_t;

/*
 * Extracts the boundary from a Content-Type header value.
 * Returns 0 and sets *b / *blen (pointing into ct) for multipart/form-data,
 * 1 if the media type is not multipart/form-data, or MGUS_R_BOUNDARY.
 */
int mgus_boundary(const unsigned char *ct, size_t len,
                  const unsigned char **b, size_t *blen);

/* Returns 0 or MGUS_R_BOUNDARY / MGUS_R_INTERNAL. */
int mgus_init(mgus_ctx_t *c, const mgus_limits_t *lim,
              const unsigned char *boundary, size_t blen);

/* Feed body bytes. Returns the first violation recorded so far (0 if none). */
int mgus_feed(mgus_ctx_t *c, const unsigned char *p, size_t n);

/* Call once after the last byte. Returns the first violation (0 if none). */
int mgus_finish(mgus_ctx_t *c);

/* Record a connector-level violation unless one is already recorded. */
void mgus_set_rule(mgus_ctx_t *c, int rule);

const mgus_stats_t *mgus_stats(const mgus_ctx_t *c);
const char *mgus_rule_name(int rule);

#endif /* MGUS_ENGINE_H */
