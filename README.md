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

发布程序保留 `-O2` 优化，移除调试信息并清理未使用代码；Linux 还使用链接时优化（LTO）。Windows 和 macOS 使用各自支持的链接参数。发布附件只包含九个程序及校验文件，不包含 PDB 调试文件。CI 会下载实际构建附件，在三个系统上校验 SHA256 并执行协议测试，通过后才创建 Release。

## 编译

安装 Zig 和 GNU Make 后，在仓库目录运行：

```sh
make        # 默认：这台设备使用的小端 MIPS 静态版本
make mips   # 大端 MIPS 静态版本
make host   # 当前电脑的版本
make release # 全部九个平台/架构，输出到 dist/
```

修改源码或 Makefile 后再次运行 `make` 会自动重新编译。也可以不用 Make，直接运行以下 `zig cc` 命令。

Windows（PowerShell）：

```powershell
zig cc -std=c11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections '-Wl,--gc-sections' -s tinysocks.c -o tinysocks.exe -lws2_32
```

Linux：

```sh
zig cc -std=c11 -O2 -flto -Wall -Wextra -ffunction-sections -fdata-sections '-Wl,--gc-sections' -s tinysocks.c -o tinysocks -pthread
```

macOS：

```sh
zig cc -std=c11 -O2 -Wall -Wextra '-Wl,-dead_strip' -s tinysocks.c -o tinysocks -pthread
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

以域名格式（`ATYP=3`）提交的标准 IPv4/IPv6 字面量（如 `127.0.0.1`、`::1`、`::ffff:127.0.0.1`）也直接转换为数字地址，不调用解析器或占用 DNS 名额；UDP 中也不占用域名缓存。即使全部后台解析任务阻塞，这些目标仍可连接或转发。IPv4 缩写、带前导零的写法及带作用域的 IPv6 等未识别形式仍交给系统解析器，保留原有解释方式。

UDP 每个会话最多缓存 8 个成功转发的域名地址，固定缓存 60 秒，命中时无需再次解析，同一域名的不同端口共用 IP 地址缓存。仅包含 ASCII 字母、数字、连字符、下划线和点的名称按 ASCII 大小写不敏感比较，共享一项缓存；解析器仍收到原始拼写。带尾点的绝对名称与不带尾点的名称分别缓存；作用域、转义或非 ASCII 等特殊输入仍按原文比较。命中不会延长过期时间，即使解析名额全部被阻塞任务占满，也可转发缓存中的大小写变体。缓存发送失败时立即重新解析并尝试候选地址；解析或发送失败不会写入缓存。该缓存期限独立于 DNS 记录的 TTL，地址变更最迟在缓存到期后的下一次请求时重新解析。首次解析在后台线程执行，会话等待结果的上限取连接预算和剩余空闲预算中的较短值；超时请求被丢弃，不会锁定客户端端口、写入缓存或刷新空闲计时。

最多同时处理 64 个客户端会话；认证收发和请求字段读取共享 15 秒预算，TCP 目标域名解析和全部候选地址共享 10 秒连接预算。目标域名仍使用系统解析器，在后台线程执行，等待结果的时间计入预算；数字目标地址和 UDP 缓存命中均无需创建解析任务。连接或 UDP 绑定完成后，协议回复发送另有 15 秒上限；发送失败会立即回收会话。已建立的 TCP 或 UDP 会话连续空闲 5 分钟后关闭；无效或来源不符的 UDP 报文，以及 UDP 会话的 TCP 控制数据，不会刷新空闲计时。

整个进程最多同时执行 8 个目标域名解析任务。名额不足时，会话在原有截止时间内等待，已有任务结束后继续解析；等待不会延长连接或空闲预算。系统解析调用结束前始终占用名额，客户端等待超时或 UDP 控制连接关闭不会额外创建替代任务；迟到的解析结果自动回收，不会用于后续连接或转发。这样即使系统解析器长时间阻塞，也不会持续增加后台线程数量。启动时监听地址的解析仍由主线程直接执行。

UDP 等待域名解析或解析名额时，同时检查 TCP 控制连接。收到 EOF 或连接错误后立即结束会话，丢弃待转发的数据报，不等待系统解析返回；尚未结束的后台解析继续占用原有名额，完成后回收结果。控制连接中的数据仍被忽略，不刷新空闲预算，也不会覆盖待转发的 UDP 载荷。TCP `CONNECT` 保持原有半关闭支持，域名解析期间发送 FIN 仍可在连接成功后接收回复。

TCP 在目标解析、解析名额排队和连接候选等待期间检查客户端套接字错误，阻塞等待的检查间隔不超过 50 毫秒。客户端发生重置等错误时停止建立目标连接，回收待连接套接字和客户端名额；已运行的系统解析仍保持原有后台名额，返回后释放迟到结果。检查错误状态并用 `MSG_PEEK` 查看接收状态，不读取待转发的应用数据；FIN 和未读载荷均不会取消正常请求，也不会造成持续的可读事件忙循环。解析与连接仍使用同一超时预算。

域名 TCP 连接优先尝试解析器返回的首个可用地址族，之后交替尝试 IPv4、IPv6，保留每个地址族内的解析顺序。连接尚未完成时，每隔 250 毫秒尝试下一个候选；已知失败时立即尝试后续候选，避免首个慢地址独占连接预算。每个会话最多保留 8 个待连接套接字，达到上限时等待已有尝试完成，再补充候选。首个成功的连接用于转发，其余套接字立即关闭；数字地址仍仅连接指定目标。访问被系统拒绝时返回 SOCKS5 状态 `2`，连接被目标拒绝时返回状态 `5`，整个连接预算耗尽时返回状态 `4`。

可在编译时用 `-DMAX_CLIENTS=数量`、`-DMAX_RESOLVERS=数量`、`-DHANDSHAKE_TIMEOUT_SECONDS=秒数`、`-DCONNECT_TIMEOUT_SECONDS=秒数` 和 `-DIDLE_TIMEOUT_SECONDS=秒数` 调整。客户端和解析任务数量须为正数且不超过 `UINT_MAX`，超时须为正数且毫秒值不超过 `INT_MAX`。`CONNECT_TIMEOUT_SECONDS` 同时决定 TCP 解析与连接的总预算，以及 UDP 单次域名解析的最大等待时间。代理不提供身份认证；监听公网地址时，请自行限制访问来源。

单个待接入连接中断或出现临时网络错误时，监听循环会继续处理后续连接。文件描述符、套接字缓冲区或内存暂时不足时，每次等待 100 毫秒再重试，避免退出服务或持续忙循环；不可恢复的监听错误仍会记录并退出。

## 测试

安装 Zig、GNU Make 和 Python 3 后运行：

```sh
make test
```

测试会自动编译专用程序，使用 2 个客户端、1 秒握手和 3 秒空闲限制。使用系统分配的监听端口，无需预留端口或建立探测连接。覆盖命令行参数和帮助、实际监听地址、协议拒绝、最大认证方法列表、截断及分段握手、握手与应用数据连发后半关闭、IPv4/IPv6 监听与目标、域名和 TCP/UDP IPv4 映射地址、双向转发背压、大数据半关闭、客户端数量限制，以及 UDP 来源校验、端口锁定、发送失败后重新识别客户端端口、空载荷与大报文、空闲超时和会话回收；无效 UDP 报文和 TCP 控制数据均不能延长 UDP 会话寿命。不需要访问外网，IPv6 回环不可用时跳过相应测试。

Windows 上默认使用 `python`，其他平台使用 `python3`；可通过 `make test PYTHON=解释器路径` 指定解释器。

`make test` 使用与本机发布程序相同的优化和链接参数。`make test-release` 则编译并测试默认运行限制的本机程序；跨平台附件也可用 `python tests/test_proxy.py 程序路径 --release -v` 检查。发布测试保留 TCP/UDP、域名、IPv4/IPv6、背压和半关闭等协议检查，仅跳过依赖短超时或两客户端限制的检查及故障注入专用检查；这些检查仍由 `make test` 和内存检查任务执行。

测试还验证 UDP 域名缓存的不同端口转发、固定过期、容量淘汰和失败重解析；受控解析器确认同一域名的 16 种大小写变体连续发送 100 个数据报只调用一次解析器、只占一项缓存。覆盖尾点、ASCII 编码的国际化域名、下划线、作用域、转义和非 ASCII 输入的缓存边界，并检查原始解析拼写和失败重解析。端到端故障测试先填满解析名额，再验证缓存名称的大小写变体仍能向不同端口转发并接收回复。故障注入程序先模拟连接中断与资源不足，再执行 TCP/UDP 和 IPv6 端到端测试，验证监听服务能够恢复。GitHub Actions 的三个系统均执行这些检查。

TCP 故障测试模拟首批地址迟迟无法连接，验证备用地址在同一预算内成功转发、IPv4/IPv6 交替尝试、全部候选共享超时，以及成功或失败后回收待连接套接字；同时检查异步连接拒绝和系统访问拒绝的回复状态。故障注入程序的连接预算缩短为 1 秒，无需依赖外部网络或真实的不可达地址。

慢解析测试让系统解析器延迟 2 秒，验证 TCP 在 1 秒预算内返回失败、UDP 超时请求不锁定端口，且迟到的结果不会连接目标或转发数据；接近空闲截止时间的 UDP 解析也不能延长会话寿命。内部检查还覆盖解析名额耗尽、排队恢复、迟到结果释放，以及内存、通知资源和线程创建失败后的回收。故障程序以 2 个解析任务为上限运行，这些检查已纳入 `make test` 和三个系统的 GitHub Actions。

UDP 关闭回归还使用 600 毫秒解析延迟，验证控制连接关闭后即使 DNS 在预算内成功返回，也不会转发数据报；控制连接含有未读数据时同样成立。发送端半关闭须在 400 毫秒内结束 UDP 会话，迟到结果不会转发；控制数据与等待中的 UDP 载荷使用独立缓冲区。内部检查验证解析中及名额满时的取消、迟到结果释放、后台名额保持，以及 Windows 控制事件创建或注册失败后的恢复；同时验证慢域名 TCP 连接的半关闭仍能收发数据。

TCP 重置回归确认两个受控解析任务已阻塞后，再让客户端异常关闭；在解析中及名额已满时，均须在 400 毫秒内恢复新客户端接入并成功转发数字目标。600 毫秒解析延迟还验证异常关闭后不会连接迟到的目标。内部检查覆盖解析前、解析中、名额排队和连接候选等待中的取消，确认待连接套接字全部回收、后台名额保持至解析返回，并释放迟到结果；正常 FIN 带 30 KiB 待转发载荷仍须完整传递和接收回复。真实 `localhost` 的 UDP 大小写变体与不同目标端口检查纳入常规及正式附件测试。

数字字面量回归在普通配置和解析名额被阻塞任务占满时，分别验证域名格式的 IPv4、IPv6、映射 IPv6 的 TCP/UDP 转发及 TCP 半关闭。内部检查确认连续 100 个数字字面量 UDP 请求不调用解析器、不写入域名缓存，并验证缩写、前导零、作用域等形式仍走原有解析路径。

Linux CI 还使用 Clang 的 AddressSanitizer 和 UndefinedBehaviorSanitizer 执行内部故障检查及域名转发测试，检测解析任务生命周期中的内存泄漏、释放后访问及未定义行为；通过后才继续构建发布程序。
