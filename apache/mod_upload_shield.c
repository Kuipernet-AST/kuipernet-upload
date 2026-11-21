/*
 * Kuipernet Upload - Apache 2.4 connector (mod_upload_shield).
 *
 * The module is an input filter around the common engine. An Apache input
 * filter is pulled by the handler, so by itself it cannot keep already
 * delivered pieces away from the backend. BLOCK is therefore offered only for
 * the one handler that can be made to read the whole body first:
 *
 *   mod_proxy_fcgi (httpd 2.4.47 or later) with the "proxy-sendcl" variable:
 *   the proxy spools the complete request body through the input filters
 *   before it connects to the FastCGI backend. The module sets the variable
 *   itself for inspected requests.
 *
 * For every other handler (mod_php, mod_proxy_http, CGI ...) BLOCK refuses
 * multipart requests with 500 (MGUS-901) instead of pretending to protect;
 * MONITOR works everywhere.
 *
 * Whole-request size and read timeouts are left to LimitRequestBody and
 * RequestReadTimeout in this version.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"
#include "ap_release.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include "mgus_engine.h"

#define US_UNSET    (-1)
#define US_OFF      0
#define US_MONITOR  1
#define US_BLOCK    2

#define US_FILTER   "UPLOAD_SHIELD_IN"

#define US_DENY_EXT                                                           \
    "php php3 php4 php5 php7 php8 phtml pht phar phps "                       \
    "jsp jspx jspf jsw jsv war asp aspx ashx asmx asa cer cgi "               \
    "htaccess htpasswd"

module AP_MODULE_DECLARE_DATA upload_shield_module;

typedef struct {
    int          mode;
    apr_off_t    max_file_size;
    apr_off_t    max_field_size;
    int          max_files;
    int          max_parts;
    int          max_part_header_size;
    int          max_part_headers;
    int          max_name_size;
    int          max_name_depth;
    int          deny_multipart;
    int          deny_progress;
    const char  *progress_name;
    int          filename_check;
    int          max_filename_size;
    const char  *deny_ext;
} us_conf;

typedef struct {
    mgus_ctx_t   engine;
    int          mode;
    int          inspecting;
    int          done;
    int          logged;
    int          status;
    const char  *action;
} us_ctx;


static void *us_create_conf(apr_pool_t *p, char *dir)
{
    us_conf  *c = apr_pcalloc(p, sizeof(us_conf));

    c->mode = US_UNSET;
    c->max_file_size = US_UNSET;
    c->max_field_size = US_UNSET;
    c->max_files = US_UNSET;
    c->max_parts = US_UNSET;
    c->max_part_header_size = US_UNSET;
    c->max_part_headers = US_UNSET;
    c->max_name_size = US_UNSET;
    c->max_name_depth = US_UNSET;
    c->deny_multipart = US_UNSET;
    c->deny_progress = US_UNSET;
    c->filename_check = US_UNSET;
    c->max_filename_size = US_UNSET;
    return c;
}

#define US_MERGE(f)  n->f = (add->f != US_UNSET) ? add->f : base->f

static void *us_merge_conf(apr_pool_t *p, void *basev, void *addv)
{
    us_conf  *base = basev, *add = addv, *n = apr_pcalloc(p, sizeof(us_conf));

    US_MERGE(mode);
    US_MERGE(max_file_size);
    US_MERGE(max_field_size);
    US_MERGE(max_files);
    US_MERGE(max_parts);
    US_MERGE(max_part_header_size);
    US_MERGE(max_part_headers);
    US_MERGE(max_name_size);
    US_MERGE(max_name_depth);
    US_MERGE(deny_multipart);
    US_MERGE(deny_progress);
    US_MERGE(filename_check);
    US_MERGE(max_filename_size);
    n->progress_name = add->progress_name ? add->progress_name : base->progress_name;
    n->deny_ext = add->deny_ext ? add->deny_ext : base->deny_ext;
    return n;
}

#define US_VAL(v, def)  ((v) != US_UNSET ? (v) : (def))


static int us_status(int rule)
{
    switch (rule) {
    case MGUS_R_PART_HEADER_SIZE:
    case MGUS_R_FILE_SIZE:
    case MGUS_R_FIELD_SIZE:
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    case MGUS_R_INTERNAL:
    case MGUS_R_UNBUFFERED:
        return HTTP_INTERNAL_SERVER_ERROR;
    default:
        return (rule >= 100 && rule < 200) ? HTTP_BAD_REQUEST : HTTP_FORBIDDEN;
    }
}

/* identifiers, the rule and counters only: no body, names, values, cookies */
static void us_log(request_rec *r, us_ctx *ctx, const char *guarantee)
{
    const mgus_stats_t  *st = mgus_stats(&ctx->engine);
    int                  rule = ctx->engine.rule;

    if (ctx->logged) {
        return;
    }
    ctx->logged = 1;

    ap_log_rerror(APLOG_MARK, rule ? APLOG_WARNING : APLOG_INFO, 0, r,
                  "upload_shield: {\"shield\":\"mgus\",\"v\":\"" MGUS_VERSION
                  "\",\"request_id\":\"%s\",\"mode\":\"%s\",\"action\":\"%s\","
                  "\"rule\":\"%s\",\"rule_name\":\"%s\",\"status\":%d,"
                  "\"guarantee\":\"%s\",\"parts\":%u,\"files\":%u,\"fields\":%u,"
                  "\"body_bytes\":%" APR_UINT64_T_FMT ",\"max_file_bytes\":%"
                  APR_UINT64_T_FMT ",\"max_field_bytes\":%" APR_UINT64_T_FMT
                  ",\"max_part_header_bytes\":%u}",
                  r->log_id ? r->log_id : "",
                  ctx->mode == US_BLOCK ? "block" : "monitor", ctx->action,
                  rule ? apr_psprintf(r->pool, "MGUS-%d", rule) : "none",
                  mgus_rule_name(rule), ctx->status, guarantee,
                  st->parts, st->files, st->fields,
                  (apr_uint64_t) st->body_bytes, (apr_uint64_t) st->max_file_bytes,
                  (apr_uint64_t) st->max_field_bytes, st->max_part_header_bytes);
}

static apr_status_t us_cleanup(void *data)
{
    request_rec  *r = data;
    us_ctx       *ctx = ap_get_module_config(r->request_config, &upload_shield_module);

    if (ctx && !ctx->logged) {
        ctx->action = "aborted";        /* request ended before the body did */
        us_log(r, ctx, "spooled");
    }
    return APR_SUCCESS;
}

/* answer the request from inside an input filter */
static apr_status_t us_reject(ap_filter_t *f, us_ctx *ctx, const char *guarantee)
{
    request_rec         *r = f->r;
    apr_bucket_brigade  *bb;

    ctx->done = 1;
    ctx->action = "block";
    ctx->status = us_status(ctx->engine.rule);
    us_log(r, ctx, guarantee);

    r->connection->keepalive = AP_CONN_CLOSE;   /* the rest is not read */

    bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, ap_bucket_error_create(ctx->status, NULL, r->pool,
                                                       f->c->bucket_alloc));
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
    ap_pass_brigade(r->output_filters, bb);

    return AP_FILTER_ERROR;
}

static apr_status_t us_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    us_ctx       *ctx = f->ctx;
    apr_bucket   *b;
    apr_status_t  rv;
    int           last = 0;

    if (ctx->done || mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (ctx->engine.rule && ctx->mode == US_BLOCK) {
        /* decided before any byte was read (configuration, boundary) */
        return us_reject(f, ctx, ctx->engine.rule == MGUS_R_UNBUFFERED
                                 ? "unsupported-handler" : "spooled");
    }

    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        const char  *data;
        apr_size_t   len;

        if (APR_BUCKET_IS_EOS(b)) {
            last = 1;
            break;
        }
        if (APR_BUCKET_IS_METADATA(b)) {
            continue;
        }
        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (len) {
            if (ctx->inspecting) {
                (void) mgus_feed(&ctx->engine, (const unsigned char *) data, len);
            } else {
                ctx->engine.st.body_bytes += len;
            }
        }
    }

    if (last && ctx->inspecting) {
        (void) mgus_finish(&ctx->engine);
    }

    if (ctx->engine.rule && ctx->mode == US_BLOCK) {
        apr_brigade_cleanup(bb);
        return us_reject(f, ctx, "spooled");
    }

    if (last) {
        ctx->done = 1;
        ctx->action = ctx->engine.rule ? "monitor" : "pass";
        us_log(f->r, ctx, ctx->mode == US_BLOCK ? "spooled" : "not-applicable");
    }

    return APR_SUCCESS;
}

/* Is this request going to be handled by mod_proxy_fcgi? */
static int us_is_proxy_fcgi(request_rec *r)
{
    if (r->handler && strncasecmp(r->handler, "proxy:fcgi:", 11) == 0) {
        return 1;
    }
    if (r->filename && strncasecmp(r->filename, "proxy:fcgi:", 11) == 0) {
        return 1;
    }
    return 0;
}

static int us_spool_capable(void)
{
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    ap_version_t  v;

    ap_get_server_revision(&v);     /* the running server, not the headers */
    return v.major == 2 && v.minor == 4 && v.patch >= 47;
#else
    return 0;
#endif
}

static int us_fixups(request_rec *r)
{
    us_conf              *conf = ap_get_module_config(r->per_dir_config,
                                                      &upload_shield_module);
    us_ctx               *ctx;
    mgus_limits_t         lim;
    const char           *ct;
    const unsigned char  *boundary;
    size_t                blen;
    int                   rc, mode = US_VAL(conf->mode, US_OFF);

    if (mode == US_OFF || r->main != NULL || r->prev != NULL) {
        return DECLINED;
    }

    ct = apr_table_get(r->headers_in, "Content-Type");
    if (ct == NULL) {
        return DECLINED;
    }
    rc = mgus_boundary((const unsigned char *) ct, strlen(ct), &boundary, &blen);
    if (rc == 1) {
        return DECLINED;        /* not multipart/form-data: not inspected */
    }
    if (apr_table_get(r->headers_in, "Content-Length") == NULL
        && apr_table_get(r->headers_in, "Transfer-Encoding") == NULL)
    {
        return DECLINED;        /* no request body */
    }

    ctx = apr_pcalloc(r->pool, sizeof(us_ctx));
    ctx->mode = mode;
    ctx->action = "pass";
    ap_set_module_config(r->request_config, &upload_shield_module, ctx);
    apr_pool_cleanup_register(r->pool, r, us_cleanup, apr_pool_cleanup_null);

    memset(&lim, 0, sizeof(lim));
    lim.max_file_size = (apr_uint64_t) US_VAL(conf->max_file_size, 0);
    lim.max_field_size = (apr_uint64_t) US_VAL(conf->max_field_size, 1024 * 1024);
    lim.max_files = US_VAL(conf->max_files, 20);
    lim.max_parts = US_VAL(conf->max_parts, 1000);
    lim.max_part_header_size = US_VAL(conf->max_part_header_size, 2048);
    lim.max_part_headers = US_VAL(conf->max_part_headers, 8);
    lim.max_name_size = US_VAL(conf->max_name_size, 256);
    lim.max_name_depth = US_VAL(conf->max_name_depth, 8);
    if (US_VAL(conf->deny_progress, 0)) {
        lim.deny_name = (const unsigned char *) (conf->progress_name
                        ? conf->progress_name : "PHP_SESSION_UPLOAD_PROGRESS");
        lim.deny_name_len = strlen((const char *) lim.deny_name);
    }
    if (US_VAL(conf->filename_check, 0)) {
        lim.filename_check = 1;
        lim.max_filename_size = US_VAL(conf->max_filename_size, 255);
        lim.deny_ext = (const unsigned char *) (conf->deny_ext ? conf->deny_ext
                                                               : US_DENY_EXT);
        lim.deny_ext_len = strlen((const char *) lim.deny_ext);
    }

    if (rc == 0) {
        rc = mgus_init(&ctx->engine, &lim, boundary, blen);
    }
    if (rc != 0) {
        (void) mgus_init(&ctx->engine, &lim, (const unsigned char *) "x", 1);
        mgus_set_rule(&ctx->engine, rc);
    } else {
        ctx->inspecting = 1;
    }

    if (US_VAL(conf->deny_multipart, 0)) {
        mgus_set_rule(&ctx->engine, MGUS_R_MULTIPART_DENIED);
    }

    if (mode == US_BLOCK) {
        if (us_is_proxy_fcgi(r) && us_spool_capable()) {
            /* make mod_proxy_fcgi read the whole body before it connects */
            apr_table_setn(r->subprocess_env, "proxy-sendcl", "1");

        } else {
            /* no way to keep the body from the handler: refuse (fail closed) */
            ctx->engine.rule = MGUS_R_UNBUFFERED;
            ctx->done = 1;
            ctx->action = "block";
            ctx->status = HTTP_INTERNAL_SERVER_ERROR;
            us_log(r, ctx, "unsupported-handler");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ap_add_input_filter(US_FILTER, ctx, r, r->connection);
    return DECLINED;
}


static const char *us_set_mode(cmd_parms *cmd, void *cv, const char *arg)
{
    us_conf  *c = cv;

    if (!strcasecmp(arg, "off")) {
        c->mode = US_OFF;
    } else if (!strcasecmp(arg, "on") || !strcasecmp(arg, "monitor")) {
        c->mode = US_MONITOR;
    } else if (!strcasecmp(arg, "block")) {
        c->mode = US_BLOCK;
    } else {
        return "UploadShield takes off, on, monitor or block";
    }
    return NULL;
}

/* sizes accept a plain number or a k/m/g suffix */
static const char *us_parse_size(const char *arg, apr_off_t *out)
{
    char       *end;
    apr_off_t   v;

    if (apr_strtoff(&v, arg, &end, 10) != APR_SUCCESS || v < 0) {
        return "invalid size";
    }
    switch (*end) {
    case 'k': case 'K': v *= 1024; end++; break;
    case 'm': case 'M': v *= 1024 * 1024; end++; break;
    case 'g': case 'G': v *= 1024 * 1024 * 1024; end++; break;
    }
    if (*end != '\0') {
        return "invalid size";
    }
    *out = v;
    return NULL;
}

static const char *us_set_off(cmd_parms *cmd, void *cv, const char *arg)
{
    return us_parse_size(arg, (apr_off_t *) ((char *) cv + (apr_size_t) cmd->info));
}

static const char *us_set_int(cmd_parms *cmd, void *cv, const char *arg)
{
    apr_off_t    v;
    const char  *err = us_parse_size(arg, &v);

    if (err || v > 0x7fffffff) {
        return "invalid number";
    }
    *(int *) ((char *) cv + (apr_size_t) cmd->info) = (int) v;
    return NULL;
}

static const char *us_set_header_size(cmd_parms *cmd, void *cv, const char *arg)
{
    const char  *err = us_set_int(cmd, cv, arg);
    us_conf     *c = cv;

    if (err == NULL && (c->max_part_header_size < 1
                        || c->max_part_header_size > MGUS_HDR_BUF))
    {
        return "UploadShieldMaxPartHeaderSize must be between 1 and 8192";
    }
    return err;
}

static const char *us_set_deny_ext(cmd_parms *cmd, void *cv, const char *arg)
{
    us_conf  *c = cv;
    char     *s;

    if (*arg == '\0' || strpbrk(arg, ".: \t") != NULL) {
        return "UploadShieldFilenameDenyExt: write extensions without the dot";
    }
    s = apr_pstrdup(cmd->pool, arg);
    ap_str_tolower(s);
    c->deny_ext = c->deny_ext ? apr_pstrcat(cmd->pool, c->deny_ext, " ", s, NULL) : s;
    return NULL;
}

#define US_OFFSET(f)  ((void *) APR_OFFSETOF(us_conf, f))
#define US_WHERE      (RSRC_CONF | ACCESS_CONF)

static const command_rec us_cmds[] = {
    AP_INIT_TAKE1("UploadShield", us_set_mode, NULL, US_WHERE,
                  "off | on | monitor | block"),
    AP_INIT_TAKE1("UploadShieldMaxFileSize", us_set_off, US_OFFSET(max_file_size),
                  US_WHERE, "size of one file part, 0 = no limit"),
    AP_INIT_TAKE1("UploadShieldMaxFieldSize", us_set_off, US_OFFSET(max_field_size),
                  US_WHERE, "size of one non-file part"),
    AP_INIT_TAKE1("UploadShieldMaxFiles", us_set_int, US_OFFSET(max_files), US_WHERE,
                  "number of file parts"),
    AP_INIT_TAKE1("UploadShieldMaxParts", us_set_int, US_OFFSET(max_parts), US_WHERE,
                  "number of parts"),
    AP_INIT_TAKE1("UploadShieldMaxPartHeaderSize", us_set_header_size,
                  US_OFFSET(max_part_header_size), US_WHERE,
                  "size of one part's header block (1..8192)"),
    AP_INIT_TAKE1("UploadShieldMaxPartHeaders", us_set_int,
                  US_OFFSET(max_part_headers), US_WHERE, "header lines per part"),
    AP_INIT_TAKE1("UploadShieldMaxFieldNameSize", us_set_int,
                  US_OFFSET(max_name_size), US_WHERE, "length of a field name"),
    AP_INIT_TAKE1("UploadShieldMaxFieldNameDepth", us_set_int,
                  US_OFFSET(max_name_depth), US_WHERE, "'[' count in a field name"),
    AP_INIT_FLAG("UploadShieldDenyMultipart", ap_set_flag_slot,
                 US_OFFSET(deny_multipart), US_WHERE,
                 "treat every multipart request in this scope as a violation"),
    AP_INIT_FLAG("UploadShieldDenySessionProgress", ap_set_flag_slot,
                 US_OFFSET(deny_progress), US_WHERE,
                 "deny the PHP session upload progress field"),
    AP_INIT_TAKE1("UploadShieldSessionProgressName", ap_set_string_slot,
                  US_OFFSET(progress_name), US_WHERE, "name of that field"),
    AP_INIT_FLAG("UploadShieldFilenameCheck", ap_set_flag_slot,
                 US_OFFSET(filename_check), US_WHERE,
                 "optional file name policy (default off)"),
    AP_INIT_ITERATE("UploadShieldFilenameDenyExt", us_set_deny_ext, NULL, US_WHERE,
                    "denied extensions, replaces the built-in list"),
    AP_INIT_TAKE1("UploadShieldMaxFilenameSize", us_set_int,
                  US_OFFSET(max_filename_size), US_WHERE, "length of a file name"),
    { NULL }
};

static void us_register_hooks(apr_pool_t *p)
{
    ap_register_input_filter(US_FILTER, us_in_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_fixups(us_fixups, NULL, NULL, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(upload_shield) = {
    STANDARD20_MODULE_STUFF,
    us_create_conf,
    us_merge_conf,
    NULL,
    NULL,
    us_cmds,
    us_register_hooks
};
