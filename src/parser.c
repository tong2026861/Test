/*
 * parser.c - 日志解析
 * 支持三类来源（可用 log_format 强制指定，默认自动识别）：
 *   1) Web 访问日志（Apache/Nginx combined 或 common）
 *   2) SSH/系统认证日志（sshd Failed password）
 *   3) ISO 时间开头的自定义日志
 * 解析策略：只抽取检测需要的字段，遇到无法识别的行返回 0，由调用方计入 skipped。
 */
#include "logids.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* 判断是否为 Web 访问日志：包含 "METHOD 前面带引号" 的特征 */
static int looks_like_web(const char *line) {
    static const char *marks[] = { "\"GET ", "\"POST ", "\"HEAD ",
                                   "\"PUT ", "\"DELETE ", "\"OPTIONS ", NULL };
    int i;
    for (i = 0; marks[i]; i++) {
        if (str_contains_ci(line, marks[i])) return 1;
    }
    return 0;
}

/* 从 "1.2.3.4:5678" 或 "1.2.3.4" 中取出 IP 与端口 */
static void split_ip_port(const char *tok, log_record_t *rec) {
    const char *colon;
    size_t len;
    rec->port = 0;

    /* IPv6 不加处理，只处理常见 IPv4 与 host:port */
    colon = strrchr(tok, ':');
    if (colon && strchr(tok, ':') == colon) {
        len = (size_t)(colon - tok);
        if (len >= IP_LEN) len = IP_LEN - 1;
        memcpy(rec->ip, tok, len);
        rec->ip[len] = '\0';
        rec->port = atoi(colon + 1);
    } else {
        snprintf(rec->ip, sizeof(rec->ip), "%s", tok);
    }
}

/* 解析 Web 访问日志 */
static int parse_web(const char *line, config_t *cfg, log_record_t *rec) {
    const char *p, *q, *r;
    char timebuf[64];
    char raw[URI_LEN];

    memset(rec, 0, sizeof(*rec));
    rec->is_web = 1;

    /* 源 IP：行首第一个空白前的 token */
    p = line;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (p == line) return 0;
    {
        size_t len = (size_t)(p - line);
        if (len >= IP_LEN) len = IP_LEN - 1;
        memcpy(rec->ip, line, len);
        rec->ip[len] = '\0';
        split_ip_port(rec->ip, rec);   /* 兼容 ip:port 写法 */
    }

    /* 时间：优先 [..]，否则尝试行首 ISO 格式 */
    r = strchr(p, '[');
    if (r) {
        q = strchr(r, ']');
        if (!q) return 0;
        if ((size_t)(q - r - 1) >= sizeof(timebuf)) return 0;
        memcpy(timebuf, r + 1, (size_t)(q - r - 1));
        timebuf[q - r - 1] = '\0';
        rec->ts = parse_time_web(timebuf);
        p = q + 1;
    } else {
        rec->ts = parse_time_iso(line);
        if (rec->ts == 0) return 0;
    }

    /* 请求行："GET /path HTTP/1.1" */
    r = strchr(p, '"');
    if (!r) return 0;
    r++;                                  /* 跳过起始引号 */
    q = strchr(r, ' ');
    if (!q) return 0;
    {
        size_t mlen = (size_t)(q - r);
        if (mlen >= sizeof(rec->method)) mlen = sizeof(rec->method) - 1;
        memcpy(rec->method, r, mlen);
        rec->method[mlen] = '\0';
        str_tolower(rec->method);
    }
    r = q + 1;                            /* URI 起始 */
    q = strchr(r, ' ');
    if (!q) q = strchr(r, '"');
    if (!q) return 0;
    {
        size_t ulen = (size_t)(q - r);
        if (ulen >= sizeof(raw)) ulen = sizeof(raw) - 1;
        memcpy(raw, r, ulen);
        raw[ulen] = '\0';
    }
    /* 保留原始 URI，同时准备解码版本供规则匹配（在 detect 中再做解码） */
    snprintf(rec->uri, sizeof(rec->uri), "%s", raw);

    /* 状态码：请求行结束引号之后 */
    r = strchr(q, '"');
    if (r) {
        int status;
        if (sscanf(r + 1, " %d", &status) == 1) rec->status = status;
    }

    (void)cfg;
    return rec->ts != 0;
}

/* 解析 SSH/系统认证日志，也兼容形如：
 *   2024-01-10 12:00:01 src=203.0.113.9 dst_port=21 result=DROP
 * 的防火墙/自定义日志（此时端口为目的端口，可用于端口扫描检测） */
static int parse_ssh(const char *line, config_t *cfg, log_record_t *rec) {
    const char *p;

    memset(rec, 0, sizeof(*rec));
    rec->is_web = 0;

    /* 时间：ISO 开头（YYYY-）用 ISO 解析，否则按 syslog 格式 */
    if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
        isdigit((unsigned char)line[2]) && isdigit((unsigned char)line[3]) &&
        line[4] == '-') {
        rec->ts = parse_time_iso(line);
    } else {
        rec->ts = parse_time_ssh(line, cfg->default_year);
    }
    if (rec->ts == 0) return 0;

    /* 失败特征（注意：防火墙的 result=DROP 属于拦截动作，不算登录失败） */
    if (str_contains_ci(line, "failed password") ||
        str_contains_ci(line, "failed publickey") ||
        str_contains_ci(line, "authentication failure") ||
        str_contains_ci(line, "invalid user")) {
        rec->failed_login = 1;
    }

    /* 源 IP：from 之后，或 src= 之后 */
    p = strstr(line, " from ");
    if (p) {
        char tok[128];
        if (sscanf(p + 6, "%127s", tok) == 1) split_ip_port(tok, rec);
    }
    if (rec->ip[0] == '\0') {
        p = strstr(line, "src=");
        if (p) {
            char tok[128];
            if (sscanf(p + 4, "%127s", tok) == 1) split_ip_port(tok, rec);
        }
    }
    if (rec->ip[0] == '\0') return 0;

    /* 目的端口：dst_port= / dport= ；否则取 syslog 里的 port（属源端口，不参与扫描判断） */
    p = strstr(line, "dst_port=");
    if (!p) p = strstr(line, "dport=");
    if (p) {
        const char *v = strchr(p, '=') + 1;
        rec->port = atoi(v);
        rec->port_is_dst = 1;
    } else {
        p = strstr(line, " port ");
        if (p) rec->port = atoi(p + 6);   /* sshd 日志中的 port 是源端口 */
    }

    /* 用户名：for xxx / invalid user xxx */
    p = strstr(line, "invalid user ");
    if (p) {
        char u[USER_LEN];
        if (sscanf(p + 13, "%63s", u) == 1) snprintf(rec->user, sizeof(rec->user), "%s", u);
    } else {
        p = strstr(line, " for ");
        if (p) {
            char u[USER_LEN];
            if (sscanf(p + 5, "%63s", u) == 1) snprintf(rec->user, sizeof(rec->user), "%s", u);
        }
    }
    return 1;
}

int parse_line(const char *line, config_t *cfg, log_record_t *rec) {
    if (!line || !*line) return 0;
    if (!strcmp(cfg->log_format, "web"))  return parse_web(line, cfg, rec);
    if (!strcmp(cfg->log_format, "ssh"))  return parse_ssh(line, cfg, rec);

    /* auto */
    if (looks_like_web(line)) return parse_web(line, cfg, rec);
    return parse_ssh(line, cfg, rec);
}
