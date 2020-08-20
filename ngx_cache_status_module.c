

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*see ngx_http_cache.h*/
#define CACHE_REQUESTS_SLOT     0
#define CACHE_MISS_SLOT         1
#define CACHE_BYPASS_SLOT	    2
#define CACHE_EXPIRED_SLOT	    3
#define CACHE_STALE_SLOT	    4
#define CACHE_UPDATING_SLOT	    5
#define CACHE_REVALIDATED_SLOT  6
#define CACHE_HIT_SLOT	        7
#define CACHE_SCARCE_SLOT       8
#define CACHE_MISC_SLOT   		9
#define CACHE_SLOT_COUNT   		10

typedef struct {
    ngx_msec_t                   start_msec;
    ngx_uint_t                  *cache_status;
    ngx_shm_zone_t              *shm_zone;
} ngx_cache_status_main_conf_t;

static ngx_http_output_header_filter_pt  ngx_original_filter_ptr;

static void *ngx_cache_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_cache_status_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_cache_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_cache_status_filter(ngx_http_request_t *r);
static ngx_int_t ngx_cache_status_filter_init(ngx_conf_t *cf);

static ngx_command_t  ngx_cache_status_commands[] = {

    { ngx_string("cache_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_cache_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_cache_status_module_ctx = {
    NULL,				                    /* preconfiguration */
    ngx_cache_status_filter_init,           /* postconfiguration */

    ngx_cache_status_create_main_conf,      /* create main configuration */
    ngx_cache_status_init_main_conf,        /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_cache_status_module = {
    NGX_MODULE_V1,
    &ngx_cache_status_module_ctx,          /* module context */
    ngx_cache_status_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_msec_t
ngx_http_cache_status_current_msec(void)
{
    time_t           sec;
    ngx_uint_t       msec;
    struct timeval   tv;

    ngx_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (ngx_msec_t) sec * 1000 + msec;
}

static void *
ngx_cache_status_create_main_conf(ngx_conf_t *cf)
{
    ngx_cache_status_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_cache_status_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }
    cmcf->start_msec = ngx_http_cache_status_current_msec();

    return cmcf;
}


static ngx_int_t
ngx_cache_status_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t                *shpool;
    ngx_cache_status_main_conf_t   *cmcf = shm_zone->data;
    ngx_cache_status_main_conf_t   *ocmcf = data;

    if (ocmcf) {
        cmcf->cache_status = ocmcf->cache_status;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cmcf->cache_status = shpool->data;
        return NGX_OK;
    }

    cmcf->cache_status = ngx_slab_calloc(shpool, sizeof(ngx_uint_t) * CACHE_SLOT_COUNT);
    if (cmcf->cache_status == NULL) {
        return NGX_ERROR;
    }

    shpool->data = cmcf->cache_status;

    ngx_sprintf(shpool->log_ctx, " in cache_status zone \"%V\"%Z",
            &shm_zone->shm.name);

    return NGX_OK;
}

#define CACHE_STATUS_SHM_NAME_LEN  256
static char *
ngx_cache_status_init_main_conf(ngx_conf_t *cf, void *conf)
{
    u_char                             *last;
    ngx_str_t                           shm_name;
    ngx_uint_t                          shm_size;
    ngx_shm_zone_t                     *shm_zone;
    ngx_cache_status_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_cache_status_module);

    shm_name.data = ngx_palloc(cf->pool, CACHE_STATUS_SHM_NAME_LEN);
    if (shm_name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    last = ngx_snprintf(shm_name.data, CACHE_STATUS_SHM_NAME_LEN, "%s",
                        "ngx_http_cache_module");

    shm_name.len = last - shm_name.data;
    shm_size = 256 * 1024;

    shm_zone = ngx_shared_memory_add(cf, &shm_name, shm_size,
                                     &ngx_cache_status_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->data = cmcf;
    shm_zone->init = ngx_cache_status_init_zone;

    return NGX_CONF_OK;
}

#define NGX_HTTP_CACHE_STATUS_HEADER   \
    "{"                     \
    "\"start_time\":%M,"   \
    "\"requests\":%ui,"     \
    "\"miss\":%ui,"         \
    "\"bypass\":%ui,"       \
    "\"expired\":%ui,"      \
    "\"stale\":%ui,"        \
    "\"updating\":%ui,"     \
    "\"revalidated\":%ui,"  \
    "\"hit\":%ui,"          \
    "\"scarce\":%ui,"       \
    "\"misc\":%ui"         \
    "}"

static ngx_int_t
ngx_cache_status_handler(ngx_http_request_t *r)
{
    size_t                              size;
    ngx_int_t                           rc;
    ngx_uint_t                         *cache_status;
    ngx_buf_t                          *b;
    ngx_chain_t                         out;
    ngx_cache_status_main_conf_t  *cmcf;

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_cache_status_module);
    cache_status = cmcf->cache_status;

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "application/json");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
   
    size = sizeof(NGX_HTTP_CACHE_STATUS_HEADER) + NGX_INT64_LEN * CACHE_SLOT_COUNT;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;
    
    if (cache_status != NULL) {
        b->last = ngx_sprintf(b->last, NGX_HTTP_CACHE_STATUS_HEADER,
                                cmcf->start_msec / 1000,
                                cache_status[CACHE_REQUESTS_SLOT],
                                cache_status[CACHE_MISS_SLOT],
                                cache_status[CACHE_BYPASS_SLOT],
                                cache_status[CACHE_EXPIRED_SLOT],
                                cache_status[CACHE_STALE_SLOT],
                                cache_status[CACHE_UPDATING_SLOT],
                                cache_status[CACHE_REVALIDATED_SLOT],
                                cache_status[CACHE_HIT_SLOT],
                                cache_status[CACHE_SCARCE_SLOT],
                                cache_status[CACHE_MISC_SLOT]);
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_cache_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t            *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_cache_status_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_cache_status_filter_init(ngx_conf_t *cf)
{   
    ngx_original_filter_ptr = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_cache_status_filter;
    
    return NGX_OK;
}

static ngx_int_t
ngx_cache_status_filter(ngx_http_request_t *r) 
{
    ngx_uint_t                         *cache_status;
    ngx_cache_status_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_cache_status_module);
    cache_status = cmcf->cache_status;

#if (NGX_HTTP_CACHE)
    if (cache_status == NULL || r->upstream == NULL|| r->upstream->cache_status == 0) {
        return ngx_original_filter_ptr(r);
    }

    cache_status[CACHE_REQUESTS_SLOT] ++;
    if (r->upstream->cache_status > NGX_HTTP_CACHE_SCARCE) {
        cache_status[CACHE_MISC_SLOT]++;
    } else {
        cache_status[r->upstream->cache_status]++;
    }
#endif
    
    return ngx_original_filter_ptr(r);
}