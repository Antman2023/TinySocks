# TinySocks

**单文件 C 实现的 SOCKS5 代理，使用 Zig 交叉编译，支持 TCP 与 UDP 转发。**

适合需要独立代理程序的 Linux、Windows、macOS 环境，也提供 ARM 和 MIPS 的静态 Linux 构建。

[下载最新版](https://github.com/Antman2023/TinySocks/releases/latest) · [构建与测试](https://github.com/Antman2023/TinySocks/actions) · [技术说明](docs/technical-notes.md) · [反馈问题](https://github.com/Antman2023/TinySocks/issues)

> **安全提示：TinySocks 不提供身份认证，也不加密代理传输。默认监听 `0.0.0.0:1080`，即所有 IPv4 接口。仅本机使用时请显式绑定 `127.0.0.1`；对其他设备开放时，务必使用防火墙或受信任网络限制访问。**

## 功能与边界

- 支持 SOCKS5 `CONNECT`（TCP）和 `UDP ASSOCIATE`，不支持 `BIND`。
- 支持 IPv4、IPv6 和域名目标；域名由代理所在系统解析。
- TCP 支持双向非阻塞转发、背压和半关闭；单方向转发缓冲区为 16 KiB。
- UDP 支持来源校验、目标回复许可和会话内域名缓存；不支持 SOCKS5 UDP 分片（`FRAG` 必须为 `0`）。
- 使用会话数量、解析任务数量及超时限制控制资源占用。
- 无配置文件、用户名密码、HTTP 代理接口或内置访问控制列表；运行参数仅为监听地址和端口。

## 快速开始

### 1. 下载对应程序

从 [Releases](https://github.com/Antman2023/TinySocks/releases/latest) 下载与你的操作系统、CPU 架构匹配的附件。运行预编译程序不需要安装 Zig 或 Make。

| 系统 | 架构 | 文件名 |
| --- | --- | --- |
| Linux | x86_64 | `tinysocks-linux-x86_64` |
| Linux | ARM64 | `tinysocks-linux-arm64` |
| Linux | ARMv7 | `tinysocks-linux-armv7` |
| Linux | MIPS 小端 | `tinysocks-linux-mipsel` |
| Linux | MIPS 大端 | `tinysocks-linux-mips` |
| Windows | x86_64 | `tinysocks-windows-x86_64.exe` |
| Windows | ARM64 | `tinysocks-windows-arm64.exe` |
| macOS | Intel | `tinysocks-macos-x86_64` |
| macOS | Apple Silicon | `tinysocks-macos-arm64` |

Linux 发布程序为静态链接。MIPS 附件使用 MIPS32 soft-float ABI，ARMv7 使用 hard-float ABI；请核对设备的架构、大小端及 ABI，静态链接不代表兼容所有内核或 CPU。

每个 Release 还提供 `SHA256SUMS`。下载后可计算程序的 SHA-256，并与该文件中对应文件名的值比较：

```sh
# Linux
sha256sum tinysocks-linux-x86_64

# macOS
shasum -a 256 tinysocks-macos-arm64
```

```powershell
# Windows PowerShell
Get-FileHash .\tinysocks-windows-x86_64.exe -Algorithm SHA256
```

### 2. 启动代理

Linux（x86_64 示例）：

```sh
chmod +x tinysocks-linux-x86_64
./tinysocks-linux-x86_64 127.0.0.1 1080
```

macOS（Apple Silicon 示例）：

```sh
chmod +x tinysocks-macos-arm64
./tinysocks-macos-arm64 127.0.0.1 1080
```

Windows（PowerShell，x86_64 示例）：

```powershell
.\tinysocks-windows-x86_64.exe 127.0.0.1 1080
```

看到 `SOCKS5 listening on 127.0.0.1:1080` 后即可连接。程序在前台运行，按 `Ctrl+C` 退出。

### 3. 配置或测试客户端

将客户端的代理类型设为 **SOCKS5**，地址设为 `127.0.0.1`，端口设为 `1080`，无需用户名和密码。

在另一个终端使用 curl 测试 TCP 转发：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

`--socks5-hostname` 将目标域名交给代理解析。Windows PowerShell 中可使用 `curl.exe`，避免旧版 PowerShell 的 `curl` 别名。此命令需要外网访问，且只验证 TCP；UDP 需要支持 SOCKS5 UDP 的客户端。

## 运行参数

```text
tinysocks [监听地址 [端口]]
```

以下示例使用本机编译后的程序名；使用发布附件时替换为对应文件名。

```sh
./tinysocks 127.0.0.1 1080  # 仅 IPv4 本机访问，建议从这里开始
./tinysocks ::1 1080        # 仅 IPv6 本机访问
./tinysocks 0.0.0.0 1080    # 所有 IPv4 接口，需自行限制访问来源
./tinysocks 127.0.0.1 0     # 由系统分配端口，实际端口见启动日志
./tinysocks --help          # 或 -h
```

- 不传参数时监听 `0.0.0.0:1080`；只传监听地址时端口为 `1080`。
- 端口必须为 `0` 至 `65535` 的十进制数字。不能省略地址、只传端口。
- IPv6 监听地址作为独立参数直接填写，不加方括号；启动日志会显示为 `[::1]:1080`。
- 监听 IPv6 通配地址时，不应假定它同时接收 IPv4；具体行为取决于系统设置。

## 从源码编译

需要 [Zig](https://ziglang.org/download/) 和 GNU Make；运行测试另需 Python 3。当前 [CI 工作流](.github/workflows/build-release.yml) 使用 Zig **0.16.0**。

```sh
git clone https://github.com/Antman2023/TinySocks.git
cd TinySocks
make host
./tinysocks 127.0.0.1 1080
```

Windows 的本机输出为 `tinysocks.exe`，在 PowerShell 中使用 `.\tinysocks.exe` 启动。

| 命令 | 输出 |
| --- | --- |
| `make host` | 当前系统程序：`tinysocks` 或 `tinysocks.exe` |
| `make` 或 `make mipsel` | 小端 MIPS 静态程序：`tinysocks-mipsel` |
| `make mips` | 大端 MIPS 静态程序：`tinysocks-mips` |
| `make release` | 九种发布程序，位于 `dist/` |
| `make cross-fault-tests` | 四种 Linux 跨架构故障测试程序，位于 `test-bin/` |

> 注意：裸 `make` 的默认目标是 **MIPSel**，不是当前电脑。日常本机编译请使用 `make host`。

构建规则及完整交叉编译参数见 [Makefile](Makefile)。MIPS hard-float 设备需要自行使用 `musleabihf` 目标构建。Linux 构建中的 `-Wl,-z,stack-size=1048576` 用于 musl 线程栈设置，自定义静态编译时应保留；背景及各平台直接编译命令见[技术说明](docs/technical-notes.md#编译)。

### 编译时配置

这些是编译期宏，不是命令行选项或环境变量：

| 宏 | 默认值 | 含义 |
| --- | --- | --- |
| `MAX_CLIENTS` | `64` | 同时处理的客户端会话上限 |
| `MAX_RESOLVERS` | `8` | 整个进程同时执行的目标域名解析任务上限 |
| `HANDSHAKE_TIMEOUT_SECONDS` | `15` | 方法协商与请求字段读取的共享预算；协议回复另有同样时长的发送上限 |
| `CONNECT_TIMEOUT_SECONDS` | `10` | TCP 解析和全部连接候选的总预算；也限制 UDP 单次域名解析等待 |
| `IDLE_TIMEOUT_SECONDS` | `300` | 已建立 TCP/UDP 会话的连续空闲上限 |

例如，在 Linux 上直接编译，将并发会话上限调整为 128：

```sh
zig cc -std=c11 -O2 -flto -Wall -Wextra \
  -ffunction-sections -fdata-sections \
  -Wl,--gc-sections -Wl,-z,stack-size=1048576 -s \
  -DMAX_CLIENTS=128 tinysocks.c -o tinysocks -pthread
```

数量必须为正数且不超过 `UINT_MAX`；超时必须为正数，换算成毫秒后不能超过 `INT_MAX`。增大会话上限会增加潜在资源需求，请按目标设备验证。

## UDP、DNS 与部署注意事项

### UDP 会话

客户端先通过 TCP 建立 `UDP ASSOCIATE`，再向回复中的地址和端口发送 SOCKS5 UDP 数据报。**TCP 控制连接必须保持打开**；关闭或发送 EOF 会结束对应 UDP 会话。

- 只接收来自该 TCP 客户端 IP 的数据报，并校验 UDP 端口。请求端口为 `0` 时，以首个成功转发的有效数据报锁定来源端口。
- 只转发最近 60 秒内成功访问过的目标地址与端口的回复；每会话最多记录 64 个目标。
- 无效报文、来源不匹配报文及 TCP 控制数据不会刷新空闲计时。
- UDP 关联使用系统分配的端口。跨设备使用时，防火墙仅放行 TCP `1080` 不足以支持 UDP；还需允许关联端口及所需的 UDP 出站/回包流量，并限制可信来源。
- 数据报加上 SOCKS5 头后仍须满足所用 IP 版本的 UDP 长度限制，无法封装的回复会被整份丢弃，不会截短转发。

### 域名解析

- 数字 IPv4/IPv6 目标不需要 DNS。标准数字字面量即使通过域名格式提交，也会直接解析为数字地址。
- TCP 域名连接按解析结果交替尝试 IPv4/IPv6 候选；未完成时每隔 250 毫秒尝试后续候选，已知失败时立即继续，全部候选共享连接预算。
- UDP 每会话最多缓存 8 个成功转发的域名地址，固定有效期为 60 秒，不随命中续期；同一域名的不同端口共用地址缓存。
- UDP 缓存的有效期独立于 DNS 记录 TTL。常规 ASCII 名称不区分大小写，带尾点与不带尾点的名称分别缓存。
- 系统解析器运行于受限后台线程。客户端超时或离开不会强制中断已开始的系统解析；任务结束前继续占用解析名额，迟到结果会回收。

### 平台差异

Windows 对 TCP 监听和 UDP 套接字使用独占地址绑定。Linux/macOS 的 TCP 监听使用 `SO_REUSEADDR`；macOS 不能提供相同的独占保证，需避免通配地址与具体地址的重叠绑定。macOS UDP 套接字也会调整发送容量以支持较大数据报。详细行为及失败处理见[技术说明](docs/technical-notes.md#运行)。

## 测试与发布流程

```sh
make test          # 短超时/低并发限制的协议回归、内部检查和故障注入
make test-release  # 使用默认运行限制的本机程序进行协议回归
```

测试使用本地回环连接，不依赖外网；IPv6 回环不可用时跳过相应检查。Windows 默认使用 `python`，其他系统使用 `python3`，可通过 `make test PYTHON=解释器路径` 覆盖。

还可以检查下载的发布程序：

```sh
python3 tests/test_proxy.py ./tinysocks-linux-x86_64 --release -v
```

CI 在 `master` 推送、Pull Request、`v*` 标签推送及手动触发时执行：

1. Linux、Windows、macOS 协议与故障回归，以及 Linux AddressSanitizer/UndefinedBehaviorSanitizer 检查。
2. 构建九种发布程序和四种 Linux 跨架构故障程序，生成 SHA-256 校验文件。
3. 在三个系统测试实际发布附件，并通过 QEMU 测试 ARM64、ARMv7、MIPS、MIPSel 发布及故障附件。
4. 仅在 `v*` 标签构建通过发布所需检查后创建 GitHub Release；普通分支构建的产物可从 Actions 下载。

测试涵盖握手、TCP/UDP 转发、IPv4/IPv6、背压、半关闭、超时、DNS 缓存和取消、来源校验及资源回收。完整回归细节见[技术说明](docs/technical-notes.md#测试)，执行入口见 [tests/test_proxy.py](tests/test_proxy.py) 与 [tests/test_faults.c](tests/test_faults.c)。

## 常见问题

**启动后其他设备连不上？** 绑定 `127.0.0.1` 或 `::1` 时仅允许本机访问。确认监听地址、启动日志、系统防火墙和网络路由；开放网络接口前先限制可信来源。

**TCP 可以用，UDP 不通？** 确认客户端支持 SOCKS5 UDP、保持 TCP 控制连接打开，并能访问服务端返回的 UDP 端点。只支持 TCP 的代理设置不会自动获得 UDP 转发能力。

**提示 `Could not listen`？** 检查地址是否属于本机、端口是否已被占用，以及当前账户是否有绑定权限；可以先用 `127.0.0.1 0` 验证。

**下载后无法执行？** Linux/macOS 先设置执行权限，再检查系统、CPU 架构及 ABI。不要仅凭设备厂商或“MIPS”名称选择大小端版本。

**可以直接作为公网代理吗？** 不建议。任何能连接监听端口的人都可使用这个无认证代理，并可能访问服务器能够访问的网络目标；请通过外部网络访问控制保护它。
