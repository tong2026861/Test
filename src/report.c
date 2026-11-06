/*
 * report.c - 告警汇总与 CSV 报告导出
 * CSV 使用 UTF-8 BOM 开头，Excel 直接双击打开不会乱码
 */
#include "logids.h"
#include <string.h>
#include <stdlib.h>

/* 按严重程度降序、时间升序排序 */
static int cmp_alert(const void *a, const void *b) {
    const alert_t *x = (const alert_t *)a;
    const alert_t *y = (const alert_t *)b;
    if (x->sev != y->sev) return (int)y->sev - (int)x->sev;
    if (x->first_ts != y->first_ts) return (x->first_ts < y->first_ts) ? -1 : 1;
    return 0;
}

/* 输出一个 CSV 字段：含逗号/引号/换行时加引号并把内部引号翻倍 */
static void csv_field(FILE *fp, const char *s) {
    const char *p;
    int need = 0;
    if (!s) { fputs("\"\"", fp); return; }
    for (p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') { need = 1; break; }
    }
    if (!need) { fputs(s, fp); return; }
    fputc('"', fp);
    for (p = s; *p; p++) {
        if (*p == '"') fputc('"', fp);
        fputc(*p, fp);
    }
    fputc('"', fp);
}

/* ---------- 控制台表格对齐：按显示宽度计算（中文占 2 列） ---------- */
static int utf8_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c >> 5) == 0x6) return 2;
    if ((c >> 4) == 0xE) return 3;
    if ((c >> 3) == 0x1E) return 4;
    return 1;
}

static int cp_width(unsigned int cp) {
    /* 常见宽字符区间：CJK、全角符号、假名、韩文 */
    if (cp >= 0x1100 && (cp <= 0x115F || cp == 0x2329 || cp == 0x232A ||
        (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
        (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE6F) ||
        (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6)))
        return 2;
    return 1;
}

static int disp_width(const char *s) {
    int w = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (p && *p) {
        int len = utf8_len(*p), i;
        unsigned int cp = 0;
        if (len == 1) cp = *p;
        else if (len == 2) cp = (unsigned int)(p[0] & 0x1F) << 6 | (p[1] & 0x3F);
        else if (len == 3) cp = (unsigned int)(p[0] & 0x0F) << 12 |
                                  (unsigned int)(p[1] & 0x3F) << 6 | (p[2] & 0x3F);
        else cp = (unsigned int)(p[0] & 0x07) << 18 |
                  (unsigned int)(p[1] & 0x3F) << 12 |
                  (unsigned int)(p[2] & 0x3F) << 6 | (p[3] & 0x3F);
        w += cp_width(cp);
        for (i = 0; i < len && p[i]; i++) p++;
    }
    return w;
}

/* 打印字符串并补齐到指定显示宽度 */
static void pad_print(const char *s, int width) {
    int w = disp_width(s);
    fputs(s, stdout);
    while (w < width) { fputc(' ', stdout); w++; }
}

int report_write_csv(detector_t *d, const char *path) {
    FILE *fp;
    int i;
    char tb1[32], tb2[32];
    alert_t *sorted;

    if (!path || !*path) path = d->cfg->report_file;

    fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "[错误] 无法写入报告文件 %s\n", path);
        return -1;
    }

    /* UTF-8 BOM */
    fputs("\xEF\xBB\xBF", fp);
    fputs("序号,首次告警时间,最后告警时间,源IP,攻击类型,类型代码,严重程度,累计次数,证据\n", fp);

    if (d->nalert > 0) {
        sorted = (alert_t *)malloc(sizeof(alert_t) * d->nalert);
        if (sorted) {
            memcpy(sorted, d->alerts, sizeof(alert_t) * d->nalert);
            qsort(sorted, (size_t)d->nalert, sizeof(alert_t), cmp_alert);
            for (i = 0; i < d->nalert; i++) {
                fmt_time(sorted[i].first_ts, tb1, sizeof(tb1));
                fmt_time(sorted[i].last_ts, tb2, sizeof(tb2));
                fprintf(fp, "%d,", i + 1);
                csv_field(fp, tb1); fputc(',', fp);
                csv_field(fp, tb2); fputc(',', fp);
                csv_field(fp, sorted[i].ip); fputc(',', fp);
                csv_field(fp, evt_name(sorted[i].type)); fputc(',', fp);
                csv_field(fp, evt_code(sorted[i].type)); fputc(',', fp);
                csv_field(fp, sev_name(sorted[i].sev)); fputc(',', fp);
                fprintf(fp, "%d,", sorted[i].count);
                csv_field(fp, sorted[i].evidence);
                fputc('\n', fp);
            }
            free(sorted);
        }
    }
    fclose(fp);
    printf("[报告] 已导出 %d 条告警到 %s\n", d->nalert, path);
    return 0;
}

void report_print_alerts(detector_t *d) {
    int i;
    char tb1[32];

    if (d->nalert == 0) {
        printf("\n[结果] 未发现可疑行为。\n");
        return;
    }

    printf("\n==================== 告警明细（按发现顺序） ====================\n");
    pad_print("序号", 5);
    pad_print("首次告警时间", 21);
    pad_print("攻击类型", 15);
    pad_print("源IP", 16);
    pad_print("严重度", 8);
    pad_print("次数", 5);
    printf("\n");
    printf("----------------------------------------------------------------\n");
    for (i = 0; i < d->nalert; i++) {
        char idx[8], cnt[8];
        alert_t *a = &d->alerts[i];
        fmt_time(a->first_ts, tb1, sizeof(tb1));
        snprintf(idx, sizeof(idx), "%d", i + 1);
        snprintf(cnt, sizeof(cnt), "%d", a->count);
        pad_print(idx, 5);
        pad_print(tb1, 21);
        pad_print(evt_name(a->type), 15);
        pad_print(a->ip, 16);
        pad_print(sev_name(a->sev), 8);
        pad_print(cnt, 5);
        printf("\n");
        printf("     证据：%s\n", a->evidence);
    }
    printf("================================================================\n");
}

void report_print_summary(detector_t *d) {
    int i, t;

    printf("\n---------------- 检测统计 ----------------\n");
    printf("读取日志行数：%lld\n", d->lines_total);
    printf("成功解析行数：%lld\n", d->lines_parsed);
    printf("跳过无法识别：%lld\n", d->lines_skipped);
    printf("涉及源 IP 数：%d\n", d->nip);
    printf("告警总数：%d\n", d->nalert);
    for (t = 0; t < EVT_TYPE_COUNT; t++) {
        if (d->cnt_by_type[t] > 0)
            printf("  - %-12s %d 次\n", evt_name((evt_t)t), d->cnt_by_type[t]);
    }

    /* 按源 IP 聚合告警次数，打印 TOP3 */
    if (d->nalert > 0) {
        typedef struct { char ip[IP_LEN]; int total; } ip_rank_t;
        ip_rank_t rank[MAX_IPS];
        int nrank = 0, r, k, j;

        for (i = 0; i < d->nalert; i++) {
            for (r = 0; r < nrank; r++)
                if (!strcmp(rank[r].ip, d->alerts[i].ip)) break;
            if (r == nrank) {
                memset(&rank[nrank], 0, sizeof(rank[0]));
                snprintf(rank[nrank].ip, IP_LEN, "%s", d->alerts[i].ip);
                nrank++;
            }
            rank[r].total += d->alerts[i].count;
        }
        /* 简单的选择排序取前三 */
        for (k = 0; k < nrank - 1; k++)
            for (j = k + 1; j < nrank; j++)
                if (rank[j].total > rank[k].total) {
                    ip_rank_t t = rank[k]; rank[k] = rank[j]; rank[j] = t;
                }

        printf("高风险源 IP（TOP3，按累计次数）：\n");
        for (k = 0; k < nrank && k < 3; k++)
            printf("  %-15s 累计 %d 次\n", rank[k].ip, rank[k].total);
    }
    printf("------------------------------------------\n");
}
