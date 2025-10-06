#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "ap_config.h"

#include <hiredis/hiredis.h>
#include <time.h>
#include <string.h>

module AP_MODULE_DECLARE_DATA redis_log_module;

typedef struct {
    const char *host;
    int port;
    int db;
    const char *prefix;
    int bucket_seconds;
    int retention_seconds;
    int fail_open; // 1=do not block requests if Redis down
} rl_cfg;

typedef struct {
    redisContext *ctx;
} rl_child_ctx;

static rl_child_ctx *g_child_ctx = NULL;

static void *rl_create_srv(apr_pool_t *p, server_rec *s) {
    rl_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));
    cfg->host = "127.0.0.1";
    cfg->port = 6379;
    cfg->db = 0;
    cfg->prefix = "rl";
    cfg->bucket_seconds = 600;
    cfg->retention_seconds = 14*24*3600;
    cfg->fail_open = 1;
    return cfg;
}

/* Directives */
static const char *set_host(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->host = arg; return NULL;
}
static const char *set_port(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->port = atoi(arg); return NULL;
}
static const char *set_db(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->db = atoi(arg); return NULL;
}
static const char *set_prefix(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->prefix = arg; return NULL;
}
static const char *set_bucket(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->bucket_seconds = atoi(arg); return NULL;
}
static const char *set_retention(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->retention_seconds = atoi(arg); return NULL;
}
static const char *set_failopen(cmd_parms *cmd, void *dummy, const char *arg) {
    rl_cfg *cfg = ap_get_module_config(cmd->server->module_config, &redis_log_module);
    cfg->fail_open = (!strcasecmp(arg, "on") || !strcmp(arg, "1")) ? 1 : 0; return NULL;
}

static const command_rec rl_cmds[] = {
    AP_INIT_TAKE1("RedisLogHost", set_host, NULL, RSRC_CONF, "Redis host"),
    AP_INIT_TAKE1("RedisLogPort", set_port, NULL, RSRC_CONF, "Redis port"),
    AP_INIT_TAKE1("RedisLogDB", set_db, NULL, RSRC_CONF, "Redis database index"),
    AP_INIT_TAKE1("RedisLogKeyPrefix", set_prefix, NULL, RSRC_CONF, "Redis key prefix"),
    AP_INIT_TAKE1("RedisLogBucketSeconds", set_bucket, NULL, RSRC_CONF, "Bucket size in seconds"),
    AP_INIT_TAKE1("RedisLogRetentionSeconds", set_retention, NULL, RSRC_CONF, "Key TTL"),
    AP_INIT_TAKE1("RedisLogFailOpen", set_failopen, NULL, RSRC_CONF, "Fail-open (On/Off)"),
    { NULL }
};

static void rl_connect_child(server_rec *s, rl_cfg *cfg) {
    struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 }; // 300ms connect timeout
    redisContext *c = redisConnectWithTimeout(cfg->host, cfg->port, tv);
    if (!c || c->err) {
        if (c) { ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "redis connect error: %s", c->errstr); redisFree(c); }
        else   { ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "redis connect error: cannot allocate"); }
        g_child_ctx->ctx = NULL;
        return;
    }
    if (cfg->db > 0) {
        redisReply *r = redisCommand(c, "SELECT %d", cfg->db);
        if (!r || r->type == REDIS_REPLY_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "redis select db error");
            if (r) freeReplyObject(r);
            redisFree(c);
            g_child_ctx->ctx = NULL;
            return;
        }
        freeReplyObject(r);
    }
    g_child_ctx->ctx = c;
}

static void rl_child_init(apr_pool_t *p, server_rec *s) {
    g_child_ctx = apr_pcalloc(p, sizeof(*g_child_ctx));
    rl_cfg *cfg = ap_get_module_config(s->module_config, &redis_log_module);
    rl_connect_child(s, cfg);
}

static int rl_log_transaction(request_rec *r) {
    if (r->main) return DECLINED; // only once per request
    rl_cfg *cfg = ap_get_module_config(r->server->module_config, &redis_log_module);

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua) ua = "-";
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    const char *ip = r->useragent_ip;
#else
    const char *ip = r->connection->remote_ip;
#endif
    if (!ip) ip = "-";

    // Compute bucket key suffix YYYYMMDDHHMM
    apr_time_t now = apr_time_now(); // microseconds
    time_t secs = (time_t)(now / APR_USEC_PER_SEC);
    time_t bucket = secs - (secs % cfg->bucket_seconds);

    struct tm t; gmtime_r(&bucket, &t);
    char ts[16]; // YYYYMMDDHHMM\0
    snprintf(ts, sizeof(ts), "%04d%02d%02d%02d%02d",
             t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min);

    char key_ip[256], key_ua[256];
    snprintf(key_ip, sizeof(key_ip), "%s:ip:%s", cfg->prefix, ts);
    snprintf(key_ua, sizeof(key_ua), "%s:ua:%s", cfg->prefix, ts);

    // Connect if not connected
    if (!g_child_ctx || !g_child_ctx->ctx) rl_connect_child(r->server, cfg);
    if (!g_child_ctx || !g_child_ctx->ctx) {
        if (!cfg->fail_open) return HTTP_SERVICE_UNAVAILABLE;
        return DECLINED;
    }

    // HINCRBY key field 1; set TTL
    redisReply *ri = redisCommand(g_child_ctx->ctx, "HINCRBY %s %s 1", key_ip, ip);
    if (!ri || ri->type == REDIS_REPLY_ERROR) {
        if (ri) freeReplyObject(ri);
        redisFree(g_child_ctx->ctx); g_child_ctx->ctx = NULL;
        if (!cfg->fail_open) return HTTP_SERVICE_UNAVAILABLE;
        return DECLINED;
    }
    freeReplyObject(ri);

    redisReply *ru = redisCommand(g_child_ctx->ctx, "HINCRBY %s %b 1", key_ua, ua, (size_t)strlen(ua));
    if (!ru || ru->type == REDIS_REPLY_ERROR) {
        if (ru) freeReplyObject(ru);
        redisFree(g_child_ctx->ctx); g_child_ctx->ctx = NULL;
        if (!cfg->fail_open) return HTTP_SERVICE_UNAVAILABLE;
        return DECLINED;
    }
    freeReplyObject(ru);

    // Ensure TTL exists (idempotent)
    redisReply *ti = redisCommand(g_child_ctx->ctx, "EXPIRE %s %d", key_ip, cfg->retention_seconds);
    if (ti) freeReplyObject(ti);
    redisReply *tu = redisCommand(g_child_ctx->ctx, "EXPIRE %s %d", key_ua, cfg->retention_seconds);
    if (tu) freeReplyObject(tu);

    return DECLINED; // don’t interfere with normal logging
}

static void rl_register_hooks(apr_pool_t *p) {
    ap_hook_child_init(rl_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(rl_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA redis_log_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, rl_create_srv, NULL, rl_cmds, rl_register_hooks
};

