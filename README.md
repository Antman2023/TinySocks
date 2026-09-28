# TinySocks

一个单文件 C 实现的 SOCKS5 代理，使用 `zig cc` 编译。支持无认证的 TCP `CONNECT` 和 `UDP ASSOCIATE` 命令，以及 IPv4、IPv6 和域名目标。

## 自动编译与发布

推送到 `master`、提交 Pull Request 或手动运行 GitHub Actions 时，会自动编译以下版本。编译结果可在对应的 Actions 运行页面下载。

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

在 Ingenic Xburst 小端 MIPS、Linux 3.0.8 的设备上，使用 Zig 0.16.0 编译的 `tinysocks-mipsel` 为 88,460 字节。该设备使用 glibc 2.6.1，静态链接避免了旧版动态库的兼容问题；已在设备上验证 SOCKS5 转发。

## 运行

```text
tinysocks [监听地址 [端口]]
```

默认监听 `0.0.0.0:1080`。例如，仅允许本机连接时运行 `tinysocks 127.0.0.1 1080`。

可用 `curl --socks5-hostname 127.0.0.1:1080 http://example.com/` 测试 TCP 转发。UDP 客户端通过 TCP 建立 `UDP ASSOCIATE` 后，向回复中的地址和端口发送 SOCKS5 UDP 数据报；TCP 连接关闭时 UDP 会话随之结束。仅接受来自该 TCP 客户端地址及指定 UDP 端口的数据报；请求端口为 0 时使用首个数据报的来源端口。UDP 分片（`FRAG` 非 0）不受支持。代理不提供身份认证；监听公网地址时，请自行限制访问来源。
