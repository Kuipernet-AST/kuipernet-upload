/*
 * Kuipernet Upload - nginx connector.
 *
 * The module is a request body filter. nginx calls it with every piece of the
 * (de-chunked) request body before the piece is stored in the request body
 * buffer or temporary file. With request buffering enabled (the default for
 * proxy_pass and fastcgi_pass) nginx starts the upstream request only after
 * the whole body has passed the filter chain, so returning an error from the
 * filter ends the request before a single byte is sent to the backend.
 * The module allocates one fixed-size context per inspected request, creates
 * no files and never copies or modifies body data.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "mgus_engine.h"


#define NGX_HTTP_UPLOAD_SHIELD_OFF      0
#define NGX_HTTP_UPLOAD_SHIELD_MONITOR  1
#define NGX_HTTP_UPLOAD_SHIELD_BLOCK    2


typedef struct {
    ngx_uint_t      mode;
    off_t           max_file_size;
    off_t           max_field_size;
    ngx_uint_t      max_files;
    ngx_uint_t      max_parts;
    size_t          max_part_header_size;
    ngx_uint_t      max_part_headers;
    size_t          max_name_size;
    ngx_uint_t      max_name_depth;
    off_t           max_body_size;      /* NGX_CONF_UNSET: follow nginx */
    ngx_msec_t      body_timeout;       /* NGX_CONF_UNSET_MSEC: follow nginx */
    ngx_flag_t      deny_multipart;
    ngx_flag_t      deny_progress;
    ngx_str_t       progress_name;
    ngx_flag_t      filename_check;
    size_t          max_filename_size;
    ngx_str_t       deny_ext;           /* lower case, separated by ' ' */
} ngx_http_upload_shield_loc_conf_t;


#define NGX_HTTP_UPLOAD_SHIELD_DENY_EXT                                       \
    "php php3 php4 php5 php7 php8 phtml pht phar phps "                       \
    "jsp jspx jspf jsw jsv war asp aspx ashx asmx asa cer cgi "               \
    "htaccess htpasswd"


typedef struct {
    ngx_http_request_t  *request;
    mgus_ctx_t           engine;
    ngx_event_t          timer;
    ngx_str_t            request_id;
    off_t                body_limit;        /* effective limit, 0 = none */
    const char          *body_limit_src;
    ngx_msec_t           body_timeout;      /* shield value, 0 = follow nginx */
    ngx_msec_t           deadline;
    const char          *conflict;          /* nginx limit applies first */
    ngx_uint_t           mode;
    ngx_uint_t           status;
    const char          *action;
    unsigned             skip:1;            /* not multipart/form-data */
    unsigned             inspecting:1;      /* engine initialized */
    unsigned             unbuffered:1;
    unsigned             done:1;            /* decision made */
    unsigned             blocked:1;         /* refused: never pass data on */
    unsigned             logged:1;
} ngx_http_upload_shield_ctx_t;


static ngx_int_t ngx_http_upload_shield_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upload_shield_init(ngx_conf_t *cf);
static void *ngx_http_upload_shield_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upload_shield_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_upload_shield_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static char *ngx_http_upload_shield_deny_ext(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_conf_enum_t  ngx_http_upload_shield_modes[] = {
    { ngx_string("off"),     NGX_HTTP_UPLOAD_SHIELD_OFF },
    { ngx_string("on"),      NGX_HTTP_UPLOAD_SHIELD_MONITOR },
    { ngx_string("monitor"), NGX_HTTP_UPLOAD_SHIELD_MONITOR },
    { ngx_string("block"),   NGX_HTTP_UPLOAD_SHIELD_BLOCK },
    { ngx_null_string, 0 }
};


#define NGX_HTTP_UPLOAD_SHIELD_CONF                                           \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1)

#define NGX_HTTP_UPLOAD_SHIELD_FLAG                                           \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG)


static ngx_command_t  ngx_http_upload_shield_commands[] = {

    { ngx_string("upload_shield"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, mode),
      &ngx_http_upload_shield_modes },

    { ngx_string("upload_shield_max_file_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_file_size),
      NULL },

    { ngx_string("upload_shield_max_field_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_field_size),
      NULL },

    { ngx_string("upload_shield_max_files"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_files),
      NULL },

    { ngx_string("upload_shield_max_parts"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_parts),
      NULL },

    { ngx_string("upload_shield_max_part_header_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_part_header_size),
      NULL },

    { ngx_string("upload_shield_max_part_headers"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_part_headers),
      NULL },

    { ngx_string("upload_shield_max_field_name_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_name_size),
      NULL },

    { ngx_string("upload_shield_max_field_name_depth"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_name_depth),
      NULL },

    { ngx_string("upload_shield_max_body_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_body_size),
      NULL },

    { ngx_string("upload_shield_body_timeout"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, body_timeout),
      NULL },

    { ngx_string("upload_shield_deny_multipart"),
      NGX_HTTP_UPLOAD_SHIELD_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, deny_multipart),
      NULL },

    { ngx_string("upload_shield_deny_session_progress"),
      NGX_HTTP_UPLOAD_SHIELD_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, deny_progress),
      NULL },

    { ngx_string("upload_shield_session_progress_name"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, progress_name),
      NULL },

    { ngx_string("upload_shield_filename_check"),
      NGX_HTTP_UPLOAD_SHIELD_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, filename_check),
      NULL },

    { ngx_string("upload_shield_filename_deny_ext"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_upload_shield_deny_ext,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upload_shield_max_filename_size"),
      NGX_HTTP_UPLOAD_SHIELD_CONF,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_shield_loc_conf_t, max_filename_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upload_shield_module_ctx = {
    ngx_http_upload_shield_add_variables,   /* preconfiguration */
    ngx_http_upload_shield_init,            /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_upload_shield_create_loc_conf, /* create location configuration */
    ngx_http_upload_shield_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_upload_shield_module = {
    NGX_MODULE_V1,
    &ngx_http_upload_shield_module_ctx,     /* module context */
    ngx_http_upload_shield_commands,        /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_request_body_filter_pt  ngx_http_next_request_body_filter;


static ngx_uint_t
ngx_http_upload_shield_status(int rule)
{
    switch (rule) {

    case MGUS_R_PART_HEADER_SIZE:
    case MGUS_R_FILE_SIZE:
    case MGUS_R_FIELD_SIZE:
    case MGUS_R_BODY_SIZE:
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;

    case MGUS_R_BODY_TIMEOUT:
        return NGX_HTTP_REQUEST_TIME_OUT;

    case MGUS_R_INTERNAL:
    case MGUS_R_UNBUFFERED:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    default:
        return (rule >= 100 && rule < 200) ? NGX_HTTP_BAD_REQUEST
                                           : NGX_HTTP_FORBIDDEN;
    }
}


/*
 * One JSON object per inspected request. It carries identifiers, the rule and
 * counters only: no body bytes, file names, field names or values, cookies.
 */
static void
ngx_http_upload_shield_log(ngx_http_request_t *r,
    ngx_http_upload_shield_ctx_t *ctx)
{
    int                  rule;
    u_char               id[sizeof("MGUS-") + NGX_INT_T_LEN];
    ngx_uint_t           level;
    const mgus_stats_t  *st;

    if (ctx->logged) {
        return;
    }
    ctx->logged = 1;

    rule = ctx->engine.rule;
    st = mgus_stats(&ctx->engine);
    level = NGX_LOG_INFO;
    ngx_cpystrn(id, (u_char *) "none", sizeof(id));
    if (rule) {
        level = NGX_LOG_WARN;
        *ngx_sprintf(id, "MGUS-%d", rule) = '\0';
    }

    ngx_log_error(level, r->connection->log, 0,
                  "upload_shield: {\"shield\":\"mgus\",\"v\":\"" MGUS_VERSION
                  "\",\"request_id\":\"%V\",\"mode\":\"%s\",\"action\":\"%s\","
                  "\"rule\":\"%s\",\"rule_name\":\"%s\",\"status\":%ui,"
                  "\"guarantee\":\"%s\",\"parts\":%uD,\"files\":%uD,"
                  "\"fields\":%uD,\"body_bytes\":%uL,\"max_file_bytes\":%uL,"
                  "\"max_field_bytes\":%uL,\"max_part_header_bytes\":%uD,"
                  "\"body_limit\":%O,\"body_limit_src\":\"%s\","
                  "\"body_timeout_ms\":%M,\"config_conflict\":\"%s\"}",
                  &ctx->request_id,
                  ctx->mode == NGX_HTTP_UPLOAD_SHIELD_BLOCK ? "block"
                                                            : "monitor",
                  ctx->action,
                  id, mgus_rule_name(rule),
                  ctx->status,
                  ctx->unbuffered ? "unbuffered" : "buffered",
                  st->parts, st->files, st->fields, st->body_bytes,
                  st->max_file_bytes, st->max_field_bytes,
                  st->max_part_header_bytes,
                  ctx->body_limit, ctx->body_limit_src,
                  ctx->body_timeout, ctx->conflict);
}


static void
ngx_http_upload_shield_cleanup(void *data)
{
    ngx_http_upload_shield_ctx_t  *ctx = data;

    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    if (!ctx->skip && !ctx->logged) {
        /* the request ended before the body was complete */
        ctx->action = "aborted";
        ngx_http_upload_shield_log(ctx->request, ctx);
    }
}


/*
 * upload_shield_body_timeout bounds the time for receiving the whole body.
 * nginx's own client_body_timeout (time between two reads) stays in effect.
 */
static void
ngx_http_upload_shield_timeout(ngx_event_t *ev)
{
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_upload_shield_ctx_t  *ctx;

    ctx = ev->data;
    r = ctx->request;
    c = r->connection;

    if (ctx->done) {
        return;
    }

    mgus_set_rule(&ctx->engine, MGUS_R_BODY_TIMEOUT);

    if (ctx->mode != NGX_HTTP_UPLOAD_SHIELD_BLOCK) {
        return;         /* MONITOR: reported when the body completes */
    }

    ctx->done = 1;
    ctx->action = "block";
    ctx->status = NGX_HTTP_REQUEST_TIME_OUT;
    ngx_http_upload_shield_log(r, ctx);

    /*
     * Nothing of nginx's HTTP/2 internals (ngx_http_v2_stream_t) is touched
     * here: distributions add fields to those structures in security updates,
     * so a module built from upstream headers would write to the wrong place
     * (seen as a worker crash with Ubuntu 18.04's nginx 1.14.0). Finalizing
     * closes the stream; should the filter be called again for this request,
     * it answers with the recorded status (see the body filter).
     */
    ctx->blocked = 1;

    c->timedout = 1;
    ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
    ngx_http_run_posted_requests(c);
}


static ngx_http_upload_shield_ctx_t *
ngx_http_upload_shield_create_ctx(ngx_http_request_t *r,
    ngx_http_upload_shield_loc_conf_t *conf)
{
    int                            rc;
    size_t                         blen;
    ngx_str_t                      name;
    mgus_limits_t                  lim;
    const unsigned char           *boundary;
    ngx_pool_cleanup_t            *cln;
    ngx_http_variable_value_t     *vv;
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_upload_shield_ctx_t  *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_upload_shield_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->request = r;
    ctx->mode = conf->mode;
    ctx->action = "pass";
    ctx->body_limit_src = "none";
    ctx->conflict = "none";
    ctx->unbuffered = r->request_body_no_buffering;

    ngx_http_set_ctx(r, ctx, ngx_http_upload_shield_module);

    if (r->headers_in.content_type == NULL) {
        ctx->skip = 1;
        return ctx;
    }

    rc = mgus_boundary(r->headers_in.content_type->value.data,
                       r->headers_in.content_type->value.len,
                       &boundary, &blen);
    if (rc == 1) {
        ctx->skip = 1;
        return ctx;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = ngx_http_upload_shield_cleanup;
    cln->data = ctx;

    ngx_str_set(&name, "request_id");
    vv = ngx_http_get_variable(r, &name, ngx_hash_key(name.data, name.len));
    if (vv != NULL && !vv->not_found) {
        ctx->request_id.data = vv->data;
        ctx->request_id.len = vv->len;
    }

    ngx_memzero(&lim, sizeof(mgus_limits_t));
    lim.max_file_size = (uint64_t) conf->max_file_size;
    lim.max_field_size = (uint64_t) conf->max_field_size;
    lim.max_files = (uint32_t) conf->max_files;
    lim.max_parts = (uint32_t) conf->max_parts;
    lim.max_part_header_size = (uint32_t) conf->max_part_header_size;
    lim.max_part_headers = (uint32_t) conf->max_part_headers;
    lim.max_name_size = (uint32_t) conf->max_name_size;
    lim.max_name_depth = (uint32_t) conf->max_name_depth;

    if (conf->deny_progress) {
        lim.deny_name = conf->progress_name.data;
        lim.deny_name_len = conf->progress_name.len;
    }

    if (conf->filename_check) {
        lim.filename_check = 1;
        lim.max_filename_size = (uint32_t) conf->max_filename_size;
        lim.deny_ext = conf->deny_ext.data;
        lim.deny_ext_len = conf->deny_ext.len;
    }

    if (rc == 0) {
        rc = mgus_init(&ctx->engine, &lim, boundary, blen);
    }

    if (rc != 0) {
        /* no usable boundary: nothing can be inspected */
        static const unsigned char  dummy[] = "x";

        (void) mgus_init(&ctx->engine, &lim, dummy, 1);
        mgus_set_rule(&ctx->engine, rc);

    } else {
        ctx->inspecting = 1;
    }

    if (conf->deny_multipart) {
        mgus_set_rule(&ctx->engine, MGUS_R_MULTIPART_DENIED);
    }

    /* effective whole-request limit and where it comes from */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->client_max_body_size) {
        ctx->body_limit = clcf->client_max_body_size;
        ctx->body_limit_src = "nginx";
    }

    if (conf->max_body_size != NGX_CONF_UNSET && conf->max_body_size > 0) {

        if (ctx->body_limit == 0 || conf->max_body_size <= ctx->body_limit) {
            ctx->body_limit = conf->max_body_size;
            ctx->body_limit_src = "shield";

            if (r->headers_in.content_length_n > conf->max_body_size) {
                mgus_set_rule(&ctx->engine, MGUS_R_BODY_SIZE);
            }

        } else {
            ctx->conflict = "body_size";
        }
    }

    if (conf->body_timeout != NGX_CONF_UNSET_MSEC && conf->body_timeout > 0) {
        ctx->body_timeout = conf->body_timeout;
        ctx->deadline = ngx_current_msec + conf->body_timeout;

        if (clcf->client_body_timeout < conf->body_timeout) {
            ctx->conflict = (ctx->conflict[0] == 'b') ? "body_size,body_timeout"
                                                      : "body_timeout";
        }

        ctx->timer.handler = ngx_http_upload_shield_timeout;
        ctx->timer.data = ctx;
        ctx->timer.log = r->connection->log;
        ngx_add_timer(&ctx->timer, conf->body_timeout);
    }

    return ctx;
}


static ngx_int_t
ngx_http_upload_shield_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                                 rule;
    size_t                              n;
    ngx_uint_t                          last;
    ngx_chain_t                        *cl;
    ngx_http_upload_shield_ctx_t       *ctx;
    ngx_http_upload_shield_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_upload_shield_module);

    if (conf->mode == NGX_HTTP_UPLOAD_SHIELD_OFF || r != r->main) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_upload_shield_module);

    if (ctx == NULL) {
        ctx = ngx_http_upload_shield_create_ctx(r, conf);
        if (ctx == NULL) {
            if (conf->mode == NGX_HTTP_UPLOAD_SHIELD_BLOCK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;      /* fail closed */
            }
            return ngx_http_next_request_body_filter(r, in);
        }

        /*
         * BLOCK promises that the backend sees nothing before approval.
         * Without request buffering nginx forwards each piece right after
         * this filter returns, so the promise cannot be kept: refuse.
         */
        if (!ctx->skip && ctx->unbuffered
            && ctx->mode == NGX_HTTP_UPLOAD_SHIELD_BLOCK)
        {
            ctx->engine.rule = MGUS_R_UNBUFFERED;
        }
    }

    if (ctx->blocked) {
        return ctx->status;
    }

    if (ctx->skip || ctx->done) {
        return ngx_http_next_request_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            n = cl->buf->last - cl->buf->pos;
            if (n) {
                if (ctx->inspecting) {
                    (void) mgus_feed(&ctx->engine, cl->buf->pos, n);
                } else {
                    ctx->engine.st.body_bytes += n;
                }
            }
        }
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    if (ngx_strcmp(ctx->body_limit_src, "shield") == 0
        && (off_t) ctx->engine.st.body_bytes > ctx->body_limit)
    {
        mgus_set_rule(&ctx->engine, MGUS_R_BODY_SIZE);
    }

    /* backstop for the timer: the deadline is also checked on arrival */
    if (ctx->body_timeout
        && (ngx_msec_int_t) (ngx_current_msec - ctx->deadline) >= 0)
    {
        mgus_set_rule(&ctx->engine, MGUS_R_BODY_TIMEOUT);
    }

    if (last && ctx->inspecting) {
        (void) mgus_finish(&ctx->engine);
    }

    rule = ctx->engine.rule;

#if (nginx_version < 1020000)
    /*
     * nginx 1.18 turns any error returned from the first, empty filter call
     * into 500. With request buffering nothing is forwarded before the whole
     * body has been read, so the decision can wait for the first call that
     * carries data and then be answered with its own status code.
     */
    if (in == NULL && rule && rule != MGUS_R_UNBUFFERED
        && !r->request_body_no_buffering)
    {
        return ngx_http_next_request_body_filter(r, in);
    }
#endif

    if (rule && ctx->mode == NGX_HTTP_UPLOAD_SHIELD_BLOCK) {
        ctx->done = 1;
        ctx->blocked = 1;
        ctx->action = "block";
        ctx->status = ngx_http_upload_shield_status(rule);
        ngx_http_upload_shield_log(r, ctx);

        if (ctx->timer.timer_set) {
            ngx_del_timer(&ctx->timer);
        }

        /* the rest of the body is not read: do not reuse the connection */
        r->keepalive = 0;

        return ctx->status;
    }

    if (last) {
        ctx->done = 1;
        ctx->action = rule ? "monitor" : "pass";
        ngx_http_upload_shield_log(r, ctx);

        if (ctx->timer.timer_set) {
            ngx_del_timer(&ctx->timer);
        }
    }

    return ngx_http_next_request_body_filter(r, in);
}


static ngx_int_t
ngx_http_upload_shield_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                        *p;
    ngx_http_upload_shield_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_upload_shield_module);

    if (ctx == NULL || ctx->skip) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (data == 0) {
        v->data = (u_char *) ctx->action;
        v->len = ngx_strlen(ctx->action);

    } else {
        p = ngx_pnalloc(r->pool, sizeof("MGUS-") + NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }
        v->data = p;
        v->len = ngx_sprintf(p, ctx->engine.rule ? "MGUS-%d" : "-",
                             ctx->engine.rule) - p;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upload_shield_add_variables(ngx_conf_t *cf)
{
    ngx_str_t             name;
    ngx_http_variable_t  *var;

    ngx_str_set(&name, "upload_shield_action");
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_upload_shield_variable;
    var->data = 0;

    ngx_str_set(&name, "upload_shield_rule");
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_upload_shield_variable;
    var->data = 1;

    return NGX_OK;
}


static void *
ngx_http_upload_shield_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upload_shield_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upload_shield_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_CONF_UNSET_UINT;
    conf->max_file_size = NGX_CONF_UNSET;
    conf->max_field_size = NGX_CONF_UNSET;
    conf->max_files = NGX_CONF_UNSET_UINT;
    conf->max_parts = NGX_CONF_UNSET_UINT;
    conf->max_part_header_size = NGX_CONF_UNSET_SIZE;
    conf->max_part_headers = NGX_CONF_UNSET_UINT;
    conf->max_name_size = NGX_CONF_UNSET_SIZE;
    conf->max_name_depth = NGX_CONF_UNSET_UINT;
    conf->max_body_size = NGX_CONF_UNSET;
    conf->body_timeout = NGX_CONF_UNSET_MSEC;
    conf->deny_multipart = NGX_CONF_UNSET;
    conf->deny_progress = NGX_CONF_UNSET;
    conf->filename_check = NGX_CONF_UNSET;
    conf->max_filename_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_upload_shield_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upload_shield_loc_conf_t  *prev = parent;
    ngx_http_upload_shield_loc_conf_t  *conf = child;

    ngx_uint_t                 explicit;
    ngx_http_core_loc_conf_t  *clcf;

    /* was something relevant set at this very level? */
    explicit = (conf->mode != NGX_CONF_UNSET_UINT
                || conf->max_body_size != NGX_CONF_UNSET
                || conf->body_timeout != NGX_CONF_UNSET_MSEC);

    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                              NGX_HTTP_UPLOAD_SHIELD_OFF);
    ngx_conf_merge_off_value(conf->max_file_size, prev->max_file_size, 0);
    ngx_conf_merge_off_value(conf->max_field_size, prev->max_field_size,
                             1024 * 1024);
    ngx_conf_merge_uint_value(conf->max_files, prev->max_files, 20);
    ngx_conf_merge_uint_value(conf->max_parts, prev->max_parts, 1000);
    ngx_conf_merge_size_value(conf->max_part_header_size,
                              prev->max_part_header_size, 2048);
    ngx_conf_merge_uint_value(conf->max_part_headers, prev->max_part_headers,
                              8);
    ngx_conf_merge_size_value(conf->max_name_size, prev->max_name_size, 256);
    ngx_conf_merge_uint_value(conf->max_name_depth, prev->max_name_depth, 8);
    ngx_conf_merge_off_value(conf->max_body_size, prev->max_body_size,
                             NGX_CONF_UNSET);
    ngx_conf_merge_msec_value(conf->body_timeout, prev->body_timeout,
                              NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_value(conf->deny_multipart, prev->deny_multipart, 0);
    ngx_conf_merge_value(conf->deny_progress, prev->deny_progress, 0);
    ngx_conf_merge_str_value(conf->progress_name, prev->progress_name,
                             "PHP_SESSION_UPLOAD_PROGRESS");
    ngx_conf_merge_value(conf->filename_check, prev->filename_check, 0);
    ngx_conf_merge_size_value(conf->max_filename_size, prev->max_filename_size,
                              255);
    ngx_conf_merge_str_value(conf->deny_ext, prev->deny_ext,
                             NGX_HTTP_UPLOAD_SHIELD_DENY_EXT);

    if (conf->max_part_header_size == 0
        || conf->max_part_header_size > MGUS_HDR_BUF)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "upload_shield_max_part_header_size must be "
                           "between 1 and %d", MGUS_HDR_BUF);
        return NGX_CONF_ERROR;
    }

    if (conf->progress_name.len == 0
        || conf->progress_name.len > MGUS_NAME_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid upload_shield_session_progress_name");
        return NGX_CONF_ERROR;
    }

    if (conf->mode == NGX_HTTP_UPLOAD_SHIELD_OFF || !explicit) {
        return NGX_CONF_OK;
    }

    /*
     * Report which whole-request limits are really in force here.
     * The core module's configuration is already merged at this point.
     */

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (conf->max_body_size != NGX_CONF_UNSET && conf->max_body_size > 0) {
        if (clcf->client_max_body_size
            && conf->max_body_size > clcf->client_max_body_size)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upload_shield: config conflict: "
                               "upload_shield_max_body_size "
                               "%O exceeds client_max_body_size %O which "
                               "nginx applies first; effective limit is %O",
                               conf->max_body_size,
                               clcf->client_max_body_size,
                               clcf->client_max_body_size);
        } else {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "upload_shield: effective request body limit "
                               "is %O (upload_shield_max_body_size; "
                               "client_max_body_size is %O)",
                               conf->max_body_size,
                               clcf->client_max_body_size);
        }
    }

    if (conf->body_timeout != NGX_CONF_UNSET_MSEC && conf->body_timeout > 0) {
        if (clcf->client_body_timeout < conf->body_timeout) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upload_shield: config conflict: "
                               "upload_shield_body_timeout "
                               "%Mms bounds the whole body; a stalled client "
                               "is closed earlier by client_body_timeout %Mms",
                               conf->body_timeout, clcf->client_body_timeout);
        } else {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "upload_shield: whole body must arrive within "
                               "%Mms (upload_shield_body_timeout); "
                               "client_body_timeout between reads is %Mms",
                               conf->body_timeout, clcf->client_body_timeout);
        }
    }

    return NGX_CONF_OK;
}


/* upload_shield_filename_deny_ext ext ...;  replaces the built-in list */
static char *
ngx_http_upload_shield_deny_ext(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_shield_loc_conf_t  *uscf = conf;

    u_char      *p;
    size_t       len;
    ngx_str_t   *value;
    ngx_uint_t   i, j;

    if (uscf->deny_ext.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    len = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            return "has an empty extension";
        }
        for (j = 0; j < value[i].len; j++) {
            if (value[i].data[j] <= ' ' || value[i].data[j] == '.'
                || value[i].data[j] == ':' || value[i].data[j] >= 0x7f)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid extension \"%V\": write it "
                                   "without the dot", &value[i]);
                return NGX_CONF_ERROR;
            }
        }
        len += value[i].len + 1;
    }

    p = ngx_pnalloc(cf->pool, len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->deny_ext.data = p;

    for (i = 1; i < cf->args->nelts; i++) {
        p = ngx_cpymem(p, value[i].data, value[i].len);
        *p++ = ' ';
    }

    uscf->deny_ext.len = len - 1;
    ngx_strlow(uscf->deny_ext.data, uscf->deny_ext.data, uscf->deny_ext.len);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upload_shield_init(ngx_conf_t *cf)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_upload_shield_body_filter;

    return NGX_OK;
}
