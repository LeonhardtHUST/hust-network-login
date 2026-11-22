# HUST-Network-Login

极简主义的华中科技大学校园网络认证工具，支持有线和无线网络。下载即用，大小约为 400k，静态链接无依赖。为路由器等嵌入式设备开发，支持所有主流硬件软件平台。No Python, No Dependencies, No Bullshit.

## 使用

从 Release 下载对应硬件和操作系统平台的可执行文件。

配置文件只有两行, 第一行为用户名，第二行为密码，例如

```text
M2020123123
mypasswordmypassword
```

保存为 my.conf

然后运行

```shell
./hust-network-login ./my.conf
```

my.conf 是刚才的配置文件，你可以换成其他名字。

连接成功后，程序将会每间隔 15s 测试一次网络连通性。如果无法连接则进行重新登陆。

## 服务管理

内置的 `service` 子命令会根据系统类型自动选择策略，无需额外脚本或依赖：

```shell
hust-network-login service install [--system] [配置文件]
hust-network-login service uninstall [--system]
hust-network-login service start
hust-network-login service stop
hust-network-login service restart
hust-network-login service status
hust-network-login service logs
```

默认安装为**用户级**服务。加 `--system`（或 `-s`）安装为系统级：`install` 时 Windows 弹 UAC 提权，Linux/macOS 通过 `sudo` 提权。

| 系统 | 用户级策略 | 系统级策略 |
|---|---|---|
| Windows | 登录时触发的计划任务（LIMITED） | SYSTEM 账户、开机触发的计划任务（HIGHEST，需 UAC） |
| Linux (systemd) | `~/.config/systemd/user/`，`systemctl --user` | `/etc/systemd/system/`，`systemctl`（需 sudo） |
| Linux (OpenWrt) | procd init script（本身就是系统级） | 同左 |
| macOS | `~/Library/LaunchAgents` | `/Library/LaunchDaemons`（需 sudo） |

| 系统 | 配置文件默认值 | 日志 |
|---|---|---|
| Windows 用户级 | `~/.hust-network-login.conf` | `~/.hust-network-login.log` |
| Windows 系统级 | `C:\ProgramData\hust-network-login\login.conf` | `C:\ProgramData\hust-network-login\service.log` |
| Linux 系统级 / OpenWrt | `/etc/hust-network-login.conf` | `journalctl -u hust-network-login` / `logread` |
| Linux 用户级 | `~/.config/hust-network-login.conf` | `journalctl --user -u hust-network-login` |
| macOS 用户级 | `~/.config/hust-network-login.conf` | `~/.hust-network-login.log` |
| macOS 系统级 | `/etc/hust-network-login.conf` | `/var/log/hust-network-login.log` |

`install` 可以显式指定配置文件路径：

```shell
hust-network-login service install ./my.conf
hust-network-login service install --system /etc/hust-network-login.conf
```

系统级安装需要相应权限（Windows UAC / Linux 与 macOS 的 sudo）；用户级不需要。

## 编译

编译本地平台只需要使用 `cargo`。

```shell
cargo build --release
strip ./target/release/hust-network-login
```

strip 可以去除调试符号表，将体积减少到 500k 以下。

交叉编译推荐使用 `cross`，当然你也可以自己手动配置工具链。

```shell
cargo install cross
cross build --release --target mips-unknown-linux-musl
mips-linux-gnu-strip ./target/mips-unknown-linux-musl/release/hust-network-login
```

你应当根据自己的路由器平台选择硬件平台。支持的目标平台戳[这里](https://github.com/rust-embedded/cross)。
