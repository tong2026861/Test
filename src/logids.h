/*
 * logids.h - 轻量级日志入侵检测与风险告警工具
 * 公共数据结构与接口声明
 */
#ifndef LOGIDS_H
#define LOGIDS_H

#include <stdio.h>
#include <time.h>

#define LOGIDS_VERSION   "1.0.0"
#define MAX_IPS          512
#define IP_LEN           64
#define URI_LEN          1024
#define USER_LEN         64
#define WIN_MAX          256     /* 每个 IP 保存的时间戳窗口容量 */
#define MAX_ALERTS       2048
#define MAX_PORTS        64

/* 严重程度：数值越大越严重 */
typedef enum {
    SEV_LOW = 1,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

/* 事件类型（新增规则类型时在此追加，并在 detect.c 的规则表中登记） */
typedef enum {
    EVT_BRUTEFORCE = 0,   /* 暴力破解 */
    EVT_SCAN404,          /* 目录/路径扫描（大量 404） */
    EVT_SCANPORT,         /* 端口扫描（短时间访问多个端口） */
    EVT_SQLI,             /* SQL 注入特征 */
    EVT_TRAVERSAL,        /* 目录遍历 */
    EVT_TYPE_COUNT
} evt_t;

/* ---------------- 配置 ---------------- */
typedef struct {
    int  window_seconds;          /* 滑动窗口长度（秒），默认 300 */
    int  brute_force_threshold;   /* 窗口内失败登录次数阈值，默认 5 */
    int  notfound_threshold;      /* 窗口内 404 次数阈值，默认 20 */
    int  distinct_port_threshold; /* 窗口内不同端口数阈值，默认 10 */
    int  alert_dedup_seconds;     /* 同类告警合并时间，默认 60 */
    int  default_year;            /* SSH 日志无年份时使用的年份 */
    int  verbose;                 /* 逐行打印解析结果 */
    int  color;                   /* 控制台彩色输出 */
    char report_file[260];        /* CSV 报告路径 */
    char log_format[16];          /* auto | web | ssh */
} config_t;

/* ---------------- 解析后的一条日志 ---------------- */
typedef struct {
    char      ip[IP_LEN];
    char      user[USER_LEN];
    char      method[16];
    char      uri[URI_LEN];
    int       status;       /* HTTP 状态码，非 Web 日志为 0 */
    int       port;         /* 端口号，未知为 0 */
    int       port_is_dst;  /* 1 = port 为目的端口（可用于端口扫描判断），
                               0 = 源端口（客户端随机端口，不参与扫描判断） */
    long long ts;           /* Unix 时间戳（秒） */
    int       failed_login; /* 1 = 登录失败事件 */
    int       is_web;       /* 1 = Web 访问日志，0 = 系统/SSH 日志 */
} log_record_t;

/* ---------------- 告警 ---------------- */
typedef struct {
    char      ip[IP_LEN];
    evt_t     type;
    severity_t sev;
    long long first_ts;
    long long last_ts;
    int       count;
    char      evidence[256];
} alert_t;

/* ---------------- 单 IP 的状态（滑动窗口用） ---------------- */
typedef struct {
    char      ip[IP_LEN];
    long long failed_ts[WIN_MAX];
    int       nfailed;
    long long notfound_ts[WIN_MAX];
    int       nnotfound;
    int       ports[MAX_PORTS];
    long long port_ts[MAX_PORTS];
    int       nports;
} ip_stat_t;

/* ---------------- 检测器 ---------------- */
typedef struct {
    config_t  *cfg;
    ip_stat_t  ips[MAX_IPS];
    int        nip;
    alert_t    alerts[MAX_ALERTS];
    int        nalert;
    long long  lines_total;
    long long  lines_parsed;
    long long  lines_skipped;
    int        cnt_by_type[EVT_TYPE_COUNT];
} detector_t;

/* config.c */
void config_defaults(config_t *cfg);
int  config_load(const char *path, config_t *cfg);

/* util.c */
void  str_trim(char *s);
void  str_tolower(char *s);
int   str_contains_ci(const char *hay, const char *needle);
int   url_decode(const char *src, char *dst, size_t dstsz);
long long parse_time_web(const char *s);   /* 10/Jan/2024:12:00:00 */
long long parse_time_ssh(const char *s, int def_year); /* Jan 10 12:00:00 */
long long parse_time_iso(const char *s);   /* 2024-01-10 12:00:00 / T 分隔 */
void  fmt_time(long long ts, char *buf, size_t n);

/* parser.c */
int parse_line(const char *line, config_t *cfg, log_record_t *rec);

/* detect.c */
const char *evt_name(evt_t t);
const char *evt_code(evt_t t);
const char *sev_name(severity_t s);
void detect_init(detector_t *d, config_t *cfg);
void detect_record(detector_t *d, const log_record_t *rec);

/* report.c */
int  report_write_csv(detector_t *d, const char *path);
void report_print_alerts(detector_t *d);
void report_print_summary(detector_t *d);

#endif /* LOGIDS_H */
