# TinySocks

一个单文件 C 实现的 SOCKS5 代理，使用 `zig cc` 编译。支持无认证的 TCP `CONNECT` 和 `UDP ASSOCIATE` 命令，以及 IPv4、IPv6 和域名目标。

## 自动编译与发布

推送到 `master`、提交 Pull Request 或手动运行 GitHub Actions 时，会先在 Linux、Windows 和 macOS 上运行协议回归测试，通过后自动编译以下版本。编译结果可在对应的 Actions 运行页面下载。

| 系统 | 架构 | 发布文件 |
| --- | --- | --- |
| Linux | x86_64、arm64、armv7 | `tinysocks-linux-*` |
| Linux | MIPS 小端、大端 | `tinysocks-linux-mipsel`、`tinysocks-linux-mips` |
| Windows | x86_64、arm64 | `tinysocks-windows-*.exe` |
| macOS | x86_64、arm64 | `tinysocks-macos-*` |

Linux 版本为静态编译。推送以 `v` 开头的版本标签（例如 `v1.0.0`）后，Actions 会创建 GitHub Release，附上全部程序及 `SHA256SUMS` 校验文件：

```sh
git tag v1.0.0
git push origin v1.0.0
```

Linux 和 macOS 程序下载后需要添加执行权限，例如 `chmod +x tinysocks-linux-x86_64`。

## 编译

安装 Zig 和 GNU Make 后，在仓库目录运行：

```sh
make        # 默认：这台设备使用的小端 MIPS 静态版本
make mips   # 大端 MIPS 静态版本
make host   # 当前电脑的版本
```

修改源码或 Makefile 后再次运行 `make` 会自动重新编译。也可以不用 Make，直接运行以下 `zig cc` 命令。

Windows（PowerShell）：

```powershell
zig cc -std=c11 -O2 -Wall -Wextra tinysocks.c -o tinysocks.exe -lws2_32
```

Linux/macOS：

```sh
zig cc -std=c11 -O2 -Wall -Wextra tinysocks.c -o tinysocks -pthread
```

Linux MIPS 交叉编译（静态链接，按体积优化，适用于相应的 MIPS32 soft-float ABI）：

```sh
# 小端 MIPS (mipsel)
zig cc -target mipsel-linux-musleabi -std=c11 -Oz -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables '-Wl,--gc-sections' -s tinysocks.c -o tinysocks-mipsel -pthread -static

# 大端 MIPS (mips)
zig cc -target mips-linux-musleabi -std=c11 -Oz -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables '-Wl,--gc-sections' -s tinysocks.c -o tinysocks-mips -pthread -static
```

目标设备如果使用 hard-float ABI，可把目标名中的 `musleabi` 改为 `musleabihf`。请按设备的大小端和 ABI 选择对应产物。

早期版本曾在 Ingenic Xburst 小端 MIPS、Linux 3.0.8 的设备上验证 SOCKS5 转发，当时使用 Zig 0.16.0 编译的 `tinysocks-mipsel` 为 88,460 字节；当前版本体积以实际编译结果为准。该设备使用 glibc 2.6.1，静态链接避免了旧版动态库的兼容问题。

## 运行

```text
tinysocks [监听地址 [端口]]
```

默认监听 `0.0.0.0:1080`。例如，仅允许本机连接时运行 `tinysocks 127.0.0.1 1080`。

端口必须为 `0` 到 `65535` 的十进制数字；端口 `0` 由系统分配可用端口，例如 `tinysocks 127.0.0.1 0`。启动日志显示实际绑定的数字地址和端口，IPv6 地址使用方括号，如 `[::1]:1080`。使用 `tinysocks --help` 或 `tinysocks -h` 查看用法。

可用 `curl --socks5-hostname 127.0.0.1:1080 http://example.com/` 测试 TCP 转发。TCP 使用非阻塞双向转发，每个方向最多缓存 16 KiB；环形缓冲区避免部分发送后反复搬移数据，接收端变慢时仍可处理反向流量。支持 TCP 半关闭，已接收的数据发送完毕后才向另一端传递 EOF。

UDP 客户端通过 TCP 建立 `UDP ASSOCIATE` 后，向回复中的地址和端口发送 SOCKS5 UDP 数据报；TCP 连接关闭时 UDP 会话随之结束。仅接受来自该 TCP 客户端地址及指定 UDP 端口的数据报；请求端口为 0 时，使用首个成功转发的有效数据报的来源端口。无效报文不会锁定端口。UDP 回复必须来自最近 60 秒内成功转发过的目标地址和端口，每个会话最多记录 64 个目标。UDP 分片（`FRAG` 非 0）不受支持。

TCP 和 UDP 的 IPv4/IPv6 数字地址直接用于连接或转发，无需转换为文本或调用地址解析器；域名目标仍使用系统解析器。IPv4 映射的 IPv6 目标（如 `::ffff:127.0.0.1`）在 TCP 和 UDP 中均通过 IPv4 套接字转发，回复使用 IPv4 地址格式；域名解析返回此类地址时也做相同处理。支持 IPv6 监听地址，例如 `tinysocks ::1 1080`，以及 IPv6 客户端的 UDP 会话。

UDP 每个会话最多缓存 8 个成功转发的域名地址，固定缓存 60 秒，命中时无需再次解析，同一域名的不同端口共用 IP 地址缓存。缓存发送失败时立即重新解析并尝试候选地址；解析或发送失败不会写入缓存。该缓存期限独立于 DNS 记录的 TTL，地址变更最迟在缓存到期后的下一次请求时重新解析；首次解析仍同步执行。

最多同时处理 64 个客户端会话；认证收发和请求字段读取共享 15 秒预算，目标连接的全部候选地址共享 10 秒连接预算。域名解析使用系统同步解析器，不计入连接预算。连接或 UDP 绑定完成后，协议回复发送另有 15 秒上限；发送失败会立即回收会话。已建立的 TCP 或 UDP 会话连续空闲 5 分钟后关闭；无效或来源不符的 UDP 报文，以及 UDP 会话的 TCP 控制数据，不会刷新空闲计时。

可在编译时用 `-DMAX_CLIENTS=数量`、`-DHANDSHAKE_TIMEOUT_SECONDS=秒数`、`-DCONNECT_TIMEOUT_SECONDS=秒数` 和 `-DIDLE_TIMEOUT_SECONDS=秒数` 调整。参数必须为正数，超时还须满足毫秒值不超过 `INT_MAX`。代理不提供身份认证；监听公网地址时，请自行限制访问来源。

单个待接入连接中断或出现临时网络错误时，监听循环会继续处理后续连接。文件描述符、套接字缓冲区或内存暂时不足时，每次等待 100 毫秒再重试，避免退出服务或持续忙循环；不可恢复的监听错误仍会记录并退出。

## 测试

安装 Zig、GNU Make 和 Python 3 后运行：

```sh
make test
```

测试会自动编译专用程序，使用 2 个客户端、1 秒握手和 3 秒空闲限制。使用系统分配的监听端口，无需预留端口或建立探测连接。覆盖命令行参数和帮助、实际监听地址、协议拒绝、最大认证方法列表、截断及分段握手、握手与应用数据连发后半关闭、IPv4/IPv6 监听与目标、域名和 TCP/UDP IPv4 映射地址、双向转发背压、大数据半关闭、客户端数量限制，以及 UDP 来源校验、端口锁定、发送失败后重新识别客户端端口、空载荷与大报文、空闲超时和会话回收；无效 UDP 报文和 TCP 控制数据均不能延长 UDP 会话寿命。不需要访问外网，IPv6 回环不可用时跳过相应测试。

Windows 上默认使用 `python`，其他平台使用 `python3`；可通过 `make test PYTHON=解释器路径` 指定解释器。

测试还验证 UDP 域名缓存的不同端口转发、固定过期、容量淘汰和失败重解析；受控解析器确认同一域名连续发送 100 个数据报只调用一次解析器。故障注入程序先模拟连接中断与资源不足，再执行 TCP/UDP 和 IPv6 端到端测试，验证监听服务能够恢复。GitHub Actions 的三个系统均执行这些检查。
