/*
 * util.c - 字符串与时间处理工具
 */
#include "logids.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* 去掉首尾空白 */
void str_trim(char *s) {
    char *p = s;
    size_t len;
    if (!s) return;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

/* 原地转小写 */
void str_tolower(char *s) {
    for (; s && *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* 不区分大小写的子串查找，返回 1 表示包含 */
int str_contains_ci(const char *hay, const char *needle) {
    size_t hl, nl, i;
    if (!hay || !needle || !*needle) return 0;
    hl = strlen(hay);
    nl = strlen(needle);
    if (nl > hl) return 0;
    for (i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        while (j < nl && tolower((unsigned char)hay[i + j]) ==
                         tolower((unsigned char)needle[j])) j++;
        if (j == nl) return 1;
    }
    return 0;
}

/* URL 解码：%XX 与 + （用于识别编码后的注入特征） */
int url_decode(const char *src, char *dst, size_t dstsz) {
    size_t i = 0, o = 0;
    if (!src || !dst || dstsz == 0) return 0;
    while (src[i] && o + 1 < dstsz) {
        if (src[i] == '%' && isxdigit((unsigned char)src[i + 1]) &&
            isxdigit((unsigned char)src[i + 2])) {
            char hex[3] = { src[i + 1], src[i + 2], 0 };
            dst[o++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[o++] = ' ';
            i++;
        } else {
            dst[o++] = src[i++];
        }
    }
    dst[o] = '\0';
    return (int)o;
}

static const char *MONTHS[] = { "Jan","Feb","Mar","Apr","May","Jun",
                                "Jul","Aug","Sep","Oct","Nov","Dec" };

static int ci_equal3(const char *a, const char *b) {
    int i;
    for (i = 0; i < 3; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

static int month_index(const char *s) {
    int i;
    for (i = 0; i < 12; i++) {
        if (ci_equal3(s, MONTHS[i])) return i;
    }
    return -1;
}

/* Apache/Nginx 通用日志时间：10/Jan/2024:12:00:00 */
long long parse_time_web(const char *s) {
    struct tm tm;
    char mon[4];
    int d, y, H, M, S;
    if (!s) return 0;
    if (sscanf(s, "%d/%3[A-Za-z]/%d:%d:%d:%d", &d, mon, &y, &H, &M, &S) != 6)
        return 0;
    memset(&tm, 0, sizeof(tm));
    tm.tm_mday = d;
    tm.tm_mon  = month_index(mon);
    tm.tm_year = y - 1900;
    tm.tm_hour = H;
    tm.tm_min  = M;
    tm.tm_sec  = S;
    tm.tm_isdst = -1;
    if (tm.tm_mon < 0) return 0;
    return (long long)mktime(&tm);
}

/* SSH 认证日志时间：Jan 10 12:00:00（无年份） */
long long parse_time_ssh(const char *s, int def_year) {
    struct tm tm;
    char mon[4];
    int d, H, M, S;
    if (!s) return 0;
    if (sscanf(s, "%3[A-Za-z] %d %d:%d:%d", mon, &d, &H, &M, &S) != 5)
        return 0;
    memset(&tm, 0, sizeof(tm));
    tm.tm_mday = d;
    tm.tm_mon  = month_index(mon);
    tm.tm_year = def_year - 1900;
    tm.tm_hour = H;
    tm.tm_min  = M;
    tm.tm_sec  = S;
    tm.tm_isdst = -1;
    if (tm.tm_mon < 0) return 0;
    return (long long)mktime(&tm);
}

/* ISO 风格：2024-01-10 12:00:00 或 2024-01-10T12:00:00 */
long long parse_time_iso(const char *s) {
    struct tm tm;
    int y, mo, d, H = 0, M = 0, S = 0;
    if (!s) return 0;
    if (sscanf(s, "%d-%d-%d%*1[ T]%d:%d:%d", &y, &mo, &d, &H, &M, &S) < 3)
        return 0;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = H;
    tm.tm_min  = M;
    tm.tm_sec  = S;
    tm.tm_isdst = -1;
    return (long long)mktime(&tm);
}

/* 时间戳格式化为可读字符串 */
void fmt_time(long long ts, char *buf, size_t n) {
    time_t t = (time_t)ts;
    struct tm *lt = localtime(&t);
    if (!lt) { snprintf(buf, n, "(无效时间)"); return; }
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", lt);
}
