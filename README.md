# logids — 轻量级日志入侵检测与风险告警工具

读取服务器 / Web 日志文件，识别**暴力破解、端口扫描、SQL 注入、目录遍历**等可疑行为，
在控制台实时输出告警，并导出 CSV 检测报告。

> 定位：课程项目 · 网络安全入门 · 小型系统管理员自检
> 形态：纯命令行（C 语言实现，无第三方依赖）
> 范围：日志驱动，不做实时抓包，不做自动封禁

---

## 一、功能

| 编号 | 功能 | 说明 |
|---|---|---|
| 1 | 日志采集 | 按行读取一个或多个文本日志，支持混合输入 |
| 2 | 日志解析 | 提取时间、源 IP、用户名、请求方法、URI、状态码、端口 |
| 3 | 规则检测 | 5 类事件（4 类要求 + 附加 1 类），阈值可配置 |
| 4 | 告警输出 | 控制台实时告警，含时间 / 源 IP / 类型 / 严重程度 / 证据 |
| 5 | 报告导出 | CSV（UTF-8 BOM，Excel 双击即开，无乱码） |
| 6 | 规则配置 | 外部 `config.ini`，改阈值不用重新编译 |

退出码：`0` 无告警，`1` 有告警，`2` 参数错误 —— 方便接入脚本 / CI。

---

## 二、检测规则

| 规则 | 类型码 | 判定条件 | 严重度 | 可配置项 |
|---|---|---|---|---|
| 暴力破解 | `BRUTE_FORCE` | 同一 IP 在窗口内失败登录 ≥ 阈值 | 高 | `brute_force_threshold` |
| 路径扫描 | `SCAN_404` | 同一 IP 在窗口内产生 404 ≥ 阈值（目录枚举特征） | 中 | `notfound_threshold` |
| 端口扫描 | `SCAN_PORT` | 同一 IP 在窗口内访问的不同**目的端口** ≥ 阈值 | 中 | `distinct_port_threshold` |
| SQL 注入 | `SQL_INJECTION` | URI 命中注入特征库（12 条） | 严重 | 特征表 + URL 解码 |
| 目录遍历 | `PATH_TRAVERSAL` | URI 命中遍历特征库（8 条） | 高 | 特征表 + URL 解码 |

**SQL 注入特征**：`union select`、`union/**/select`、`union all select`、`or 1=1`、
`' or '1'='1`、`" or "1"="1`、`drop table`、`information_schema`、`sleep(`、
`benchmark(`、`extractvalue(`、`updatexml(`

**目录遍历特征**：`../`、`..\`、`/etc/passwd`、`/etc/shadow`、`/proc/self`、
`win.ini`、`boot.ini`、`%00`

匹配前会先做 **URL 解码**（`%20`、`%2f` 等），所以 `1%20UNION%20SELECT`、
`..%2f..%2fetc%2fpasswd` 这类编码绕过同样能识别。

---

## 三、快速开始

### Windows

```bat
:: 一键编译（自动查找 gcc，找不到 gcc 时回退到 winget 安装的 WinLibs）
build.bat

:: 编译 + 跑样例 + 自动打开报告
build.bat demo

:: 手动运行
logids.exe -c config.ini samples\auth.log samples\access.log samples\firewall.log -o report.csv
```

没有编译器时先装一个：

```bat
winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT
```

### Linux / macOS

```bash
make                 # 生成 logids
make demo            # 用样例日志演示
./logids -c config.ini samples/auth.log samples/access.log -o report.csv
```

---

## 四、命令行参数

```
logids [选项] <日志文件...>

  -c <file>    配置文件路径（默认 ./config.ini）
  -o <file>    CSV 报告输出路径（默认取配置 report_file）
  -f <format>  强制日志格式：auto | web | ssh（默认 auto）
  -v           逐行打印解析结果（调试用，可看清每行提取了什么）
  --no-color   关闭彩色输出（重定向到文件时建议加）
  -h           显示帮助
```

`-v` 的典型用途：日志解析结果为空时，用它确认是格式不匹配还是字段抽取失败。

---

## 五、配置文件

```ini
window_seconds=300            ; 滑动窗口长度（秒）
brute_force_threshold=5       ; 窗口内失败登录次数阈值
notfound_threshold=20         ; 窗口内 404 次数阈值
distinct_port_threshold=10    ; 窗口内不同目的端口数阈值
alert_dedup_seconds=60        ; 同 IP 同类型告警合并窗口
default_year=2026             ; SSH 日志无年份时补全
log_format=auto               ; auto | web | ssh
report_file=report.csv        ; 报告路径
color=1                       ; 1 彩色 / 0 纯文本
```

改阈值不需要重新编译。误报多就调大阈值或缩短窗口；漏报就反过来。

---

## 六、样例演示

```bat
logids.exe -c config.ini samples/auth.log samples/access.log samples/firewall.log -o report.csv
```

实际输出（节选）：

```
[配置] 已加载 9 项：窗口=300s 暴力破解阈值=5 404阈值=20 端口阈值=10 报告=report.csv

[分析] samples/auth.log ...
[告警] 2026-01-10 09:02:22  暴力破解 源IP=203.0.113.45    严重度=高  窗口内失败登录 5 次，最新目标用户=admin

[分析] samples/access.log ...
[告警] 2026-01-10 09:02:10  SQL注入    源IP=198.51.100.7    严重度=严重 命中特征 [union select] URI=/product.php?id=1%20UNION%20SELECT%20...
[告警] 2026-01-10 09:03:05  目录遍历 源IP=198.51.100.7    严重度=高  命中特征 [../] URI=/download?file=../../../../etc/passwd
[告警] 2026-01-10 09:04:20  路径扫描(404) 源IP=192.0.2.99   严重度=中  窗口内 404 响应 20 次，疑似目录枚举

[分析] samples/firewall.log ...
[告警] 2024-01-10 12:00:19  端口扫描 源IP=203.0.113.9     严重度=中  窗口内访问 10 个不同端口

---------------- 检测统计 ----------------
读取日志行数：64
成功解析行数：64
跳过无法识别：0
告警总数：5
高风险源 IP（TOP3，按累计次数）：
  198.51.100.7    累计 7 次
  203.0.113.45    累计 4 次
  192.0.2.99      累计 3 次
[报告] 已导出 5 条告警到 report.csv
```

误报验证：`samples/clean.log` 是纯正常流量（含一次 `union law` 关键词搜索、
两次 404、一次失败登录），运行结果为 **0 告警**：

```bat
logids.exe -c config.ini samples/clean.log -o report_clean.csv
```
```
[结果] 未发现可疑行为。
告警总数：0
```

---

## 七、目录结构

```
logids/
├── src/
│   ├── logids.h     公共数据结构与接口
│   ├── main.c       命令行入口、文件遍历
│   ├── config.c     配置加载
│   ├── parser.c     日志解析（web / ssh / 自定义）
│   ├── detect.c     规则引擎（内容规则 + 行为规则）
│   ├── report.c     控制台输出与 CSV 导出
│   └── util.c       字符串与时间工具
├── samples/
│   ├── auth.log      SSH 认证日志（含暴力破解）
│   ├── access.log    Web 访问日志（含注入 / 遍历 / 404 扫描）
│   ├── firewall.log  防火墙日志（含端口扫描）
│   └── clean.log     正常流量（用于误报验证）
├── config.ini
├── Makefile
├── build.bat
└── README.md
```

---

## 八、规则怎么扩展

分三个层次，从易到难：

**① 加一条特征串（最常见，改一行）**
在 `src/detect.c` 的 `CONTENT_RULES` 表里加一行即可，无需改逻辑：

```c
{ EVT_SQLI,      "load_file(" },
{ EVT_TRAVERSAL, "/root/.ssh/id_rsa" },
```

**② 加一种新的事件类型**
1. `logids.h` 的 `evt_t` 里追加枚举值（放在 `EVT_TYPE_COUNT` 之前）；
2. `detect.c` 里给 `evt_name / evt_code / evt_severity` 各补一行；
3. 写判定函数（参考 `check_bruteforce`），在 `detect_record` 中调用
   `alert_emit(...)` 抛出告警。

**③ 加一种新的行为规则（滑窗统计）**
复用 `ip_stat_t` 里的窗口数组，或新增字段，然后按
`push_ts → prune_ts → 比较阈值 → alert_emit` 四步写。

---

## 九、设计要点

**解析层**：按行读取、逐行识别格式，不依赖正则库。
Web 日志靠 `"GET ` 等请求行特征识别；SSH 日志靠 syslog 时间戳 + `from` / `failed password`；
另外兼容 `2024-01-10 12:00:01 src=1.2.3.4 dst_port=22` 这类防火墙日志。
无法识别的行计入 `skipped`，不中断运行。

**检测层**：内容规则走特征表遍历，行为规则走滑动窗口。
窗口用「时间戳数组 + 逐次裁剪」实现，单个 IP 最多保留 256 条，内存占用恒定、不随日志量增长。

**误报控制**（这是最关键的一环）：
1. 阈值全部可配，默认值偏保守；
2. **源端口不参与端口扫描判断**——浏览器每次连接的源端口都不同，若拿它统计会疯狂误报，
   因此只统计日志中明确记录的目的端口（`dst_port=`）；
3. 防火墙 `result=DROP` 不算登录失败，避免把拦截动作误判成暴力破解；
4. 同一 IP 同类告警在 `alert_dedup_seconds` 内合并为一条并累计次数，避免刷屏；
5. 一条日志同类特征只报一次（例如一个请求里同时含 `union select` 和 `or 1=1`，只出一条 SQL 注入告警）。

**输出层**：CSV 带 UTF-8 BOM，Excel 直接打开不乱码；控制台表格按「显示宽度」对齐
（中文按 2 列计算），避免中文错位。

---

## 十、已知限制

- **不做实时抓包**：只读已经落盘的日志文件，需要配合 `tail -f` / 日志轮转使用；
- 单机单进程，无多节点聚合；
- 内容规则是子串匹配，不是正则，不支持复杂模式；需要正则时可在此基础上引入 PCRE；
- SSH 日志的 `port` 是源端口，故 `auth.log` 不参与端口扫描判断，端口扫描依赖防火墙/流量日志；
- 状态全部在内存，进程退出后窗口统计清零（日志重新跑一遍即可，无状态丢失风险）；
- 未做日志轮转文件（`.1`、`.gz`）自动发现。

---

## 十一、安全与授权声明

本工具仅用于**自己拥有或已获得书面授权的环境**（本地虚拟机、实验机房、自建服务器）。
对未授权系统采集、分析日志可能违反法律法规与学校纪律。样例日志中的 IP
均取自文档专用网段（RFC 5737：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），
不对应真实主机。
