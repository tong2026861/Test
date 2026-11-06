/*
 * main.c - 命令行入口
 *
 * 用法：
 *   logids [选项] <日志文件> [更多日志文件...]
 *
 * 选项：
 *   -c <file>   指定配置文件（默认 ./config.ini）
 *   -o <file>   指定 CSV 报告输出路径（覆盖配置项）
 *   -f <format> 强制日志格式：auto|web|ssh
 *   -v          逐行打印解析结果（调试用）
 *   --no-color  关闭彩色输出
 *   -h          帮助
 *
 * 示例：
 *   logids samples/auth.log samples/access.log -o report.csv
 */
#include "logids.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#endif

static void enable_utf8_console(void) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode))
            SetConsoleMode(h, mode | 0x0004); /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
    }
#endif
}

static void usage(const char *prog) {
    printf("轻量级日志入侵检测与风险告警工具 v%s\n\n", LOGIDS_VERSION);
    printf("用法: %s [选项] <日志文件...>\n\n", prog);
    printf("选项:\n");
    printf("  -c <file>    配置文件路径（默认 ./config.ini）\n");
    printf("  -o <file>    CSV 报告输出路径（默认取配置 report_file）\n");
    printf("  -f <format>  日志格式: auto|web|ssh（默认 auto）\n");
    printf("  -v           逐行打印解析结果\n");
    printf("  --no-color   关闭彩色输出\n");
    printf("  -h           显示本帮助\n\n");
    printf("检测项: 暴力破解 / 路径扫描(404) / 端口扫描 / SQL注入 / 目录遍历\n");
    printf("示例:   %s samples/auth.log samples/access.log -o report.csv\n", prog);
}

int main(int argc, char **argv) {
    config_t cfg;
    /* 注意：detector_t 内含各 IP 的时间戳窗口，体积约 3MB，
       必须放在静态存储区，放到栈上会直接栈溢出崩溃 */
    static detector_t det;
    int i, nfiles = 0;
    int nopened = 0;
    int opt_verbose = 0;
    const char *cfg_path = "config.ini";
    const char *out_path = NULL;
    const char *fmt = NULL;
    int use_color = 1;
    long long total_alerts;

    enable_utf8_console();

    /* ---- 参数解析 ---- */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            out_path = argv[++i];
        } else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            fmt = argv[++i];
        } else if (!strcmp(argv[i], "-v")) {
            opt_verbose = 1;
        } else if (!strcmp(argv[i], "--no-color")) {
            use_color = 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "[错误] 未知选项: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        } else {
            argv[nfiles++] = argv[i];  /* 就地收集文件参数 */
        }
    }

    if (nfiles == 0) {
        fprintf(stderr, "[错误] 未指定日志文件\n\n");
        usage(argv[0]);
        return 2;
    }

    /* ---- 配置 ---- */
    config_load(cfg_path, &cfg);
    cfg.verbose = opt_verbose;
    cfg.color   = use_color && cfg.color;
    if (out_path) snprintf(cfg.report_file, sizeof(cfg.report_file), "%s", out_path);
    if (fmt) {
        if (strcmp(fmt, "web") && strcmp(fmt, "ssh") && strcmp(fmt, "auto")) {
            fprintf(stderr, "[错误] -f 只能是 auto / web / ssh\n");
            return 2;
        }
        snprintf(cfg.log_format, sizeof(cfg.log_format), "%s", fmt);
    }

    detect_init(&det, &cfg);

    printf("==============================================\n");
    printf(" 轻量级日志入侵检测工具 v%s\n", LOGIDS_VERSION);
    printf(" 检测窗口 %ds | 暴力破解阈值 %d 次 | 404 阈值 %d 次 | 端口阈值 %d 个\n",
           cfg.window_seconds, cfg.brute_force_threshold,
           cfg.notfound_threshold, cfg.distinct_port_threshold);
    printf(" 待分析文件 %d 个\n", nfiles);
    printf("==============================================\n\n");

    /* ---- 逐文件分析 ---- */
    for (i = 0; i < nfiles; i++) {
        FILE *fp = fopen(argv[i], "r");
        char line[4096];
        long long before = det.nalert;

        if (!fp) {
            fprintf(stderr, "[错误] 无法打开日志文件: %s\n", argv[i]);
            continue;
        }
        nopened++;
        printf("[分析] %s ...\n", argv[i]);

        while (fgets(line, sizeof(line), fp)) {
            log_record_t rec;
            size_t len = strlen(line);
            char tbuf[32];

            /* 处理 Windows 换行与超长行截断 */
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
            if (len == 0) continue;
            if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
                int ch;
                while ((ch = fgetc(fp)) != '\n' && ch != EOF) { }  /* 丢弃超长行剩余部分 */
            }

            det.lines_total++;

            if (!parse_line(line, &cfg, &rec)) {
                det.lines_skipped++;
                if (cfg.verbose) printf("  [跳过] %s\n", line);
                continue;
            }
            det.lines_parsed++;

            if (cfg.verbose) {
                fmt_time(rec.ts, tbuf, sizeof(tbuf));
                printf("  [解析] %s ip=%-15s status=%-3d port=%-5d fail=%d uri=%s\n",
                       tbuf, rec.ip, rec.status, rec.port, rec.failed_login,
                       rec.uri[0] ? rec.uri : "-");
            }

            detect_record(&det, &rec);
        }
        fclose(fp);
        printf("        完成，本章新增告警 %lld 条\n\n", det.nalert - before);
    }

    if (nopened == 0) {
        fprintf(stderr, "[错误] 没有任何日志文件可读取，已中止\n");
        return 2;
    }

    /* ---- 输出 ---- */
    report_print_alerts(&det);
    total_alerts = det.nalert;
    report_print_summary(&det);

    if (report_write_csv(&det, cfg.report_file) != 0) {
        fprintf(stderr, "[错误] 报告导出失败\n");
        return 1;
    }

    printf("\n完成：共 %lld 条告警。\n", total_alerts);
    return (total_alerts > 0) ? 1 : 0;   /* 有告警返回 1，便于脚本集成 */
}
