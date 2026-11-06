/*
 * detect.c - 规则检测引擎
 *
 * 规则分两类：
 *   1) 内容规则：对 URI 做特征匹配（SQL 注入、目录遍历），见 CONTENT_RULES 表
 *   2) 行为规则：基于滑动窗口的频次统计（暴力破解、404 扫描、端口扫描）
 *
 * 扩展方式：
 *   - 新增内容特征：直接往 CONTENT_RULES 加一行 {类型, 特征串}，工具自动生效；
 *   - 新增事件类型：在 logids.h 的 evt_t 中追加，然后在 evt_name/evt_code/
 *     evt_severity 里补一行，并在 detect_record 中调用 alert_emit。
 */
#include "logids.h"
#include <string.h>
#include <stdlib.h>

/* -------- 内容特征规则表（全部按不区分大小写匹配，URI 会先做 URL 解码） -------- */
typedef struct {
    evt_t       type;
    const char *pattern;
} pattern_rule_t;

static const pattern_rule_t CONTENT_RULES[] = {
    /* SQL 注入特征 */
    { EVT_SQLI,      "union select" },
    { EVT_SQLI,      "union/**/select" },
    { EVT_SQLI,      "union all select" },
    { EVT_SQLI,      "or 1=1" },
    { EVT_SQLI,      "' or '1'='1" },
    { EVT_SQLI,      "\" or \"1\"=\"1" },
    { EVT_SQLI,      "drop table" },
    { EVT_SQLI,      "information_schema" },
    { EVT_SQLI,      "sleep(" },
    { EVT_SQLI,      "benchmark(" },
    { EVT_SQLI,      "extractvalue(" },
    { EVT_SQLI,      "updatexml(" },
    /* 目录遍历特征 */
    { EVT_TRAVERSAL, "../" },
    { EVT_TRAVERSAL, "..\\" },
    { EVT_TRAVERSAL, "/etc/passwd" },
    { EVT_TRAVERSAL, "/etc/shadow" },
    { EVT_TRAVERSAL, "/proc/self" },
    { EVT_TRAVERSAL, "win.ini" },
    { EVT_TRAVERSAL, "boot.ini" },
    { EVT_TRAVERSAL, "%00" }
};

const char *evt_name(evt_t t) {
    switch (t) {
        case EVT_BRUTEFORCE: return "暴力破解";
        case EVT_SCAN404:    return "路径扫描(404)";
        case EVT_SCANPORT:   return "端口扫描";
        case EVT_SQLI:       return "SQL注入";
        case EVT_TRAVERSAL:  return "目录遍历";
        default:             return "未知";
    }
}

/* CSV 里用英文类型码，避免部分表格软件对中文列值的编码问题 */
const char *evt_code(evt_t t) {
    switch (t) {
        case EVT_BRUTEFORCE: return "BRUTE_FORCE";
        case EVT_SCAN404:    return "SCAN_404";
        case EVT_SCANPORT:   return "SCAN_PORT";
        case EVT_SQLI:       return "SQL_INJECTION";
        case EVT_TRAVERSAL:  return "PATH_TRAVERSAL";
        default:             return "UNKNOWN";
    }
}

const char *sev_name(severity_t s) {
    switch (s) {
        case SEV_CRITICAL: return "严重";
        case SEV_HIGH:     return "高";
        case SEV_MEDIUM:   return "中";
        case SEV_LOW:      return "低";
        default:           return "未知";
    }
}

static severity_t evt_severity(evt_t t) {
    switch (t) {
        case EVT_SQLI:       return SEV_CRITICAL;
        case EVT_BRUTEFORCE: return SEV_HIGH;
        case EVT_TRAVERSAL:  return SEV_HIGH;
        case EVT_SCANPORT:   return SEV_MEDIUM;
        case EVT_SCAN404:    return SEV_MEDIUM;
        default:             return SEV_LOW;
    }
}

void detect_init(detector_t *d, config_t *cfg) {
    memset(d, 0, sizeof(*d));
    d->cfg = cfg;
}

/* -------- 滑动窗口辅助 -------- */

/* 追加时间戳，超出容量时整体前移（只保留最近的） */
static void push_ts(long long *arr, int *n, long long ts) {
    if (*n >= WIN_MAX) {
        memmove(arr, arr + 1, sizeof(long long) * (WIN_MAX - 1));
        *n = WIN_MAX - 1;
    }
    arr[(*n)++] = ts;
}

/* 丢弃窗口外的记录，返回窗口内剩余数量 */
static int prune_ts(long long *arr, int *n, long long now, int window) {
    int i, k = 0;
    long long limit = now - (long long)window;
    for (i = 0; i < *n; i++) {
        if (arr[i] >= limit && arr[i] <= now) arr[k++] = arr[i];
    }
    *n = k;
    return k;
}

/* 取/建某个 IP 的状态 */
static ip_stat_t *get_ip_stat(detector_t *d, const char *ip) {
    int i;
    for (i = 0; i < d->nip; i++)
        if (strcmp(d->ips[i].ip, ip) == 0) return &d->ips[i];
    if (d->nip >= MAX_IPS) return &d->ips[MAX_IPS - 1];  /* 满了复用最后一个，避免越界 */
    memset(&d->ips[d->nip], 0, sizeof(ip_stat_t));
    snprintf(d->ips[d->nip].ip, IP_LEN, "%s", ip);
    return &d->ips[d->nip++];
}

/* -------- 告警输出 -------- */
static void alert_emit(detector_t *d, const char *ip, evt_t type,
                       long long ts, const char *evidence) {
    int i;
    char tbuf[32];
    severity_t sev = evt_severity(type);
    config_t *cfg = d->cfg;

    /* 同类同 IP 在合并窗口内只累计次数，避免刷屏 */
    for (i = d->nalert - 1; i >= 0; i--) {
        alert_t *a = &d->alerts[i];
        if (a->type == type && strcmp(a->ip, ip) == 0 &&
            ts - a->last_ts <= (long long)cfg->alert_dedup_seconds) {
            a->count++;
            a->last_ts = ts;
            snprintf(a->evidence, sizeof(a->evidence), "%s", evidence);
            d->cnt_by_type[type]++;
            return;
        }
    }

    if (d->nalert < MAX_ALERTS) {
        alert_t *a = &d->alerts[d->nalert++];
        memset(a, 0, sizeof(*a));
        snprintf(a->ip, sizeof(a->ip), "%s", ip);
        a->type  = type;
        a->sev   = sev;
        a->first_ts = ts;
        a->last_ts  = ts;
        a->count = 1;
        snprintf(a->evidence, sizeof(a->evidence), "%s", evidence);
    }
    d->cnt_by_type[type]++;

    /* 实时告警打印 */
    fmt_time(ts, tbuf, sizeof(tbuf));
    if (cfg->color) {
        const char *c = (sev == SEV_CRITICAL) ? "\033[1;31m"
                      : (sev == SEV_HIGH)     ? "\033[1;35m"
                      : (sev == SEV_MEDIUM)   ? "\033[1;33m"
                                              : "\033[1;36m";
        printf("%s[告警]%s %s  %-12s 源IP=%-15s 严重度=%-4s %s\n",
               c, "\033[0m", tbuf, evt_name(type), ip, sev_name(sev), evidence);
    } else {
        printf("[告警] %s  %-12s 源IP=%-15s 严重度=%-4s %s\n",
               tbuf, evt_name(type), ip, sev_name(sev), evidence);
    }
}

/* -------- 行为规则 -------- */

/* 暴力破解：窗口内失败登录次数达到阈值 */
static void check_bruteforce(detector_t *d, const log_record_t *rec, ip_stat_t *st) {
    char ev[256];
    int c;
    push_ts(st->failed_ts, &st->nfailed, rec->ts);
    c = prune_ts(st->failed_ts, &st->nfailed, rec->ts, d->cfg->window_seconds);
    if (c >= d->cfg->brute_force_threshold) {
        if (rec->user[0])
            snprintf(ev, sizeof(ev), "窗口内失败登录 %d 次，最新目标用户=%.30s", c, rec->user);
        else
            snprintf(ev, sizeof(ev), "窗口内失败登录 %d 次", c);
        alert_emit(d, rec->ip, EVT_BRUTEFORCE, rec->ts, ev);
    }
}

/* 目录/路径扫描：窗口内 404 次数达到阈值 */
static void check_notfound(detector_t *d, const log_record_t *rec, ip_stat_t *st) {
    char ev[256];
    int c;
    push_ts(st->notfound_ts, &st->nnotfound, rec->ts);
    c = prune_ts(st->notfound_ts, &st->nnotfound, rec->ts, d->cfg->window_seconds);
    if (c >= d->cfg->notfound_threshold) {
        snprintf(ev, sizeof(ev), "窗口内 404 响应 %d 次，疑似目录枚举", c);
        alert_emit(d, rec->ip, EVT_SCAN404, rec->ts, ev);
    }
}

/* 端口扫描：窗口内同一 IP 访问的不同端口数达到阈值 */
static void check_ports(detector_t *d, const log_record_t *rec, ip_stat_t *st) {
    int i, k = 0;
    char ev[256];
    long long limit = rec->ts - (long long)d->cfg->window_seconds;

    if (rec->port <= 0 || !rec->port_is_dst) return;

    /* 先按窗口清理旧端口 */
    for (i = 0; i < st->nports; i++) {
        if (st->port_ts[i] >= limit) {
            st->ports[k]   = st->ports[i];
            st->port_ts[k] = st->port_ts[i];
            k++;
        }
    }
    st->nports = k;

    /* 该端口是否已在窗口内出现 */
    for (i = 0; i < st->nports; i++) {
        if (st->ports[i] == rec->port) { st->port_ts[i] = rec->ts; break; }
    }
    if (i == st->nports && st->nports < MAX_PORTS) {
        st->ports[st->nports]   = rec->port;
        st->port_ts[st->nports] = rec->ts;
        st->nports++;
    }

    if (st->nports >= d->cfg->distinct_port_threshold) {
        snprintf(ev, sizeof(ev), "窗口内访问 %d 个不同端口", st->nports);
        alert_emit(d, rec->ip, EVT_SCANPORT, rec->ts, ev);
    }
}

/* 内容规则：SQL 注入 / 目录遍历 */
static void check_content(detector_t *d, const log_record_t *rec) {
    char decoded[URI_LEN * 2];
    char ev[256];
    size_t i;
    int hit_sqli = 0, hit_trav = 0;
    size_t total = sizeof(CONTENT_RULES) / sizeof(CONTENT_RULES[0]);

    if (!rec->uri[0]) return;

    /* 原始 URI 与实际解码后的 URI 都要匹配，防止 %20 之类的绕过 */
    url_decode(rec->uri, decoded, sizeof(decoded));

    for (i = 0; i < total; i++) {
        const pattern_rule_t *r = &CONTENT_RULES[i];

        /* 每类特征每条日志只报一次，避免一个请求刷出多条同类告警 */
        if (r->type == EVT_SQLI && hit_sqli) continue;
        if (r->type == EVT_TRAVERSAL && hit_trav) continue;

        if (str_contains_ci(rec->uri, r->pattern) ||
            str_contains_ci(decoded, r->pattern)) {
            snprintf(ev, sizeof(ev), "命中特征 [%s] URI=%.160s", r->pattern, rec->uri);
            alert_emit(d, rec->ip, r->type, rec->ts, ev);
            if (r->type == EVT_SQLI) hit_sqli = 1;
            else                     hit_trav = 1;
        }
        if (hit_sqli && hit_trav) break;
    }
}

void detect_record(detector_t *d, const log_record_t *rec) {
    ip_stat_t *st;

    if (!rec->ip[0] || rec->ts <= 0) return;
    st = get_ip_stat(d, rec->ip);

    /* 行为规则 */
    if (rec->failed_login) check_bruteforce(d, rec, st);
    if (rec->is_web && rec->status == 404) check_notfound(d, rec, st);
    check_ports(d, rec, st);

    /* 内容规则 */
    if (rec->is_web) check_content(d, rec);
}
