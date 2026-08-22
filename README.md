# DomainCheck (Go)

域名扫描工具（原 Python 版本的 Go 重构版），支持任意后缀，可设置扫描间隔，并可添加自定义字典。

## 字典生成

内置字典生成器，按候选字符与长度穷举组合：

```
./domaincheck -gen -charset abc123 -len 3 -out mydict.txt
```

- 输出写入 `dict/mydict.txt`（目录不存在会自动创建）
- 候选字符自动去重；支持多字节字符（如中文）
- 同名文件已存在时拒绝覆盖，防止误覆盖手工维护的字典
- 组合数超出上限（5000 万条）会拒绝并提示缩小规模

## 目录结构

```
DomainCheck/
├── tld.json        后缀配置
├── dict/           字典（可由 -gen 生成）
├── result/         扫描结果日志 *.log（自动创建）
└── state/          断点续扫状态 *.state.json + *.journal（自动创建）
```

扫描**全部完成**后，`state/` 下对应任务的状态文件会被自动删除；
中断或存在失败项时保留，供 `-resume` 恢复。

## 扫描流程（v2 新增 DNS NS 预检）

对每个域名按以下顺序判断：

1. **DNS NS 预检**（Go 原生 `net.Resolver` 实现，不依赖 dig/nslookup，跨平台）：
   查询域名的 NS 记录——**有 NS 记录则必然已注册**，直接判定并跳过 WHOIS；
2. 无 NS 记录时再走 **WHOIS 服务器**查询（带重试与指数退避）；
3. 若某后缀的 WHOIS 服务器反爬严格、重试预算耗尽，任务自动**降级为仅 DNS 判断模式**
   （不再请求该 WHOIS 服务器），降级状态会持久化，续扫时保持；此类结果带
   `[dns, uncertain]` 标记；
4. 扫描 `tld.json` 未配置的后缀时同样仅用 DNS 判断，启动时会显著提示该判断
   **不完全可靠**（已注册但未设置解析的域名看起来与可注册域名相同）；交互模式下需确认；
5. DNS 查询与 WHOIS 一样遵循 `-delay` 抖动延迟规则，自身失败也有指数退避重试。

可用 `-dns 1.1.1.1:53` 指定自定义解析器（默认走系统配置）。

相比原 Python 版本，Go 版本重点增强了稳健性：

- **状态记忆 / 断点续扫**：每查询完一个域名，任务状态都会原子性地写入
  `result/*.state.json`。无论是崩溃、断网还是 Ctrl+C 中断，进度都不会丢失，
  可以随时从断点继续。
- **报错自动重试 + 指数退避**：单次 WHOIS 查询失败（超时、连接失败等）会自动重试，
  重试间隔按 `基础间隔 × 2ⁿ` 指数增长并带随机抖动、设上限；重试次数用尽后该域名被
  标记为 `failed` 并**继续扫描后面的域名**（而不是像旧版那样直接退出）。
- **优雅处理 Ctrl+C / SIGTERM**：中断时保存进度后正常退出（退出码 130），
  再次运行时选择续扫即可。
- **分级查询间隔**：纯 DNS 判定的域名之间固定间隔 0.5s（DNS 解析器可承受此频率）；
  `-delay` 设定值（含 ±25% 抖动）仅作用于真正访问 WHOIS 服务器的域名之间，
  避免对脆弱的 nic 服务器造成压力。
- **输入校验与容错**：TLD/字典/延迟输入错误会重新提示而不是退出；
  续扫时自动从 `tld.json` 刷新 whois 服务器配置。

## 编译

需要 Go 1.24+：

```
go build -o domaincheck .
```

## 使用方法

### 交互模式（与原版一致）

```
./domaincheck
```

随后按提示输入：

```
Enter tld name: xyz #输入需要查询的后缀
Enter dict name: allpy #输入字典，位于dict文件夹下
Enter delay [0]: 0 # 查询间隔（秒），部分whois/nic对频繁查询行为进行了限制
Task Start
****************
bo.xyz is available #可以注册的域名
bai.xyz is NOT available #不可注册的域名
```

如果有未完成的任务，启动时会先列出这些任务，输入编号即可断点续扫，
直接回车则开始新任务。

### 命令行参数模式（适合自动化）

```
./domaincheck -tld xyz -dict allpy -delay 0
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-tld` | 要扫描的域名后缀（需在 `tld.json` 中登记） |
| `-dict` | `dict/` 目录下的字典文件名 |
| `-delay` | **WHOIS 查询**间隔（秒），默认 0；实际等待在设定值附近随机抖动 ±25%。纯 DNS 判定的域名之间固定间隔 0.5s，不受此参数影响 |
| `-resume` | 续扫：`latest` 为最近一个未完成任务，或指定 `.state.json` 路径 |
| `-data` | 数据目录（含 `tld.json`、`dict/`、`result/`），默认当前目录 |
| `-timeout` | 单次 WHOIS 查询超时（默认 10s） |
| `-retries` | 每个域名的额外重试次数（默认 4，即最多尝试 5 次） |
| `-base-backoff` | 首次重试等待时长（默认 1s，之后逐次翻倍） |
| `-max-backoff` | 重试等待上限（默认 60s） |
| `-dns` | 自定义 DNS 解析器（host:port），用于 NS 预检 |
| `-gen` / `-charset` / `-len` / `-out` | 字典生成模式及参数 |
| `-list-tlds` / `-list-dicts` | 列出可用的后缀 / 字典 |

示例——续扫上次因断网失败的任务：

```
./domaincheck -resume latest
# 或
./domaincheck -resume result/su_allpy_2026-08-21-14-29-09.state.json
```

## 文件说明

`tld.json`为域名的字典，格式如下：
```
  "xyz": { #域名后缀
    "nic": "whois.nic.xyz", #whois/nic服务器
    "response": "object does not exist" #未注册域名的响应反馈
  }
```

`dict`为字典：
- allpy 所有单拼
- test 测试

`result`输出目录：
- `<tld>_<dict>_<时间>.log`：结果日志，格式与原版完全一致（仅记录可注册域名）
- `<tld>_<dict>_<时间>.journal`：追加式逐域名历史（含 dns 来源标记）
- `<tld>_<dict>_<时间>.state.json`：轻量元数据（几百字节，与字典规模无关），
  只存任务配置、进度水位和失败列表；每查完一个域名原子性重写一次
- `<tld>_<dict>_<时间>.journal`：追加式全量历史，每个域名一行（O(1) 追加），
  供审计与统计，不会整体载入内存

**内存与磁盘开销**：状态记忆的内存占用 O(失败数)，与字典大小无关；
10 万域名实测峰值 RSS 约 18MB（主要是字典本身与运行时），元数据始终约 420 字节。
对比旧版把全部结果存在单个 JSON 里反复全量重写的方案，大字典下写入量降低数个数量级。

## 查找whois server

可以在`https://www.iana.org/domains/root/db/??.html`中找到tld nic whois server，其中??为对应tld/域名后缀

## 运行测试

```
go test ./...
```

测试包含针对伪造 WHOIS 服务器的端到端测试，覆盖：正常扫描、连续失败重试、
重试耗尽后不退出、断点续扫只补查未完成域名、Ctrl+C 中断后恢复等场景。

Check the available domain of a TLD with dict, based on Go.
