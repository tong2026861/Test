/*
 * config.c - 规则阈值与运行参数配置
 * 配置文件为 key=value 文本，# 或 ; 开头为注释
 */
#include "logids.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

void config_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->window_seconds          = 300;
    cfg->brute_force_threshold   = 5;
    cfg->notfound_threshold      = 20;
    cfg->distinct_port_threshold = 10;
    cfg->alert_dedup_seconds     = 60;
    cfg->default_year            = 2026;
    cfg->verbose                 = 0;
    cfg->color                   = 1;
    strcpy(cfg->report_file, "report.csv");
    strcpy(cfg->log_format, "auto");
}

int config_load(const char *path, config_t *cfg) {
    FILE *fp;
    char line[512];
    int lineno = 0, applied = 0;

    config_defaults(cfg);
    if (!path) return 0;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[警告] 无法打开配置文件 %s，使用默认阈值\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *eq, *key, *val;
        lineno++;
        str_trim(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') continue;

        eq = strchr(line, '=');
        if (!eq) {
            fprintf(stderr, "[警告] 配置第 %d 行缺少 '='，已忽略\n", lineno);
            continue;
        }
        *eq = '\0';
        key = line;
        val = eq + 1;
        str_trim(key);
        str_trim(val);

        if      (!strcmp(key, "window_seconds"))          cfg->window_seconds = atoi(val);
        else if (!strcmp(key, "brute_force_threshold"))   cfg->brute_force_threshold = atoi(val);
        else if (!strcmp(key, "notfound_threshold"))      cfg->notfound_threshold = atoi(val);
        else if (!strcmp(key, "distinct_port_threshold")) cfg->distinct_port_threshold = atoi(val);
        else if (!strcmp(key, "alert_dedup_seconds"))     cfg->alert_dedup_seconds = atoi(val);
        else if (!strcmp(key, "default_year"))            cfg->default_year = atoi(val);
        else if (!strcmp(key, "verbose"))                 cfg->verbose = atoi(val);
        else if (!strcmp(key, "color"))                   cfg->color = atoi(val);
        else if (!strcmp(key, "report_file")) {
            strncpy(cfg->report_file, val, sizeof(cfg->report_file) - 1);
            cfg->report_file[sizeof(cfg->report_file) - 1] = '\0';
        }
        else if (!strcmp(key, "log_format")) {
            strncpy(cfg->log_format, val, sizeof(cfg->log_format) - 1);
            cfg->log_format[sizeof(cfg->log_format) - 1] = '\0';
        }
        else {
            fprintf(stderr, "[警告] 未知配置项 '%s'（第 %d 行），已忽略\n", key, lineno);
            continue;
        }
        applied++;
    }
    fclose(fp);

    /* 参数合法性校正，避免误配置导致全部逻辑失效 */
    if (cfg->window_seconds <= 0)          cfg->window_seconds = 300;
    if (cfg->brute_force_threshold <= 0)   cfg->brute_force_threshold = 5;
    if (cfg->notfound_threshold <= 0)      cfg->notfound_threshold = 20;
    if (cfg->distinct_port_threshold <= 0) cfg->distinct_port_threshold = 10;
    if (cfg->alert_dedup_seconds < 0)      cfg->alert_dedup_seconds = 60;
    if (cfg->default_year < 1970)          cfg->default_year = 2026;

    printf("[配置] 已加载 %d 项：窗口=%ds 暴力破解阈值=%d 404阈值=%d 端口阈值=%d 报告=%s\n",
           applied, cfg->window_seconds, cfg->brute_force_threshold,
           cfg->notfound_threshold, cfg->distinct_port_threshold, cfg->report_file);
    return 0;
}
