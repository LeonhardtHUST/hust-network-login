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
hust-network-login service install [配置文件]
hust-network-login service uninstall
hust-network-login service start
hust-network-login service stop
hust-network-login service restart
hust-network-login service status
hust-network-login service logs
```

| 系统 | 策略 | 配置文件默认值 | 日志 |
|---|---|---|---|
| Windows | 登录时触发的计划任务 | `~/.hust-network-login.conf` | `~/.hust-network-login.log` |
| Linux (systemd) | systemd unit，异常自动重启 | `/etc/hust-network-login.conf` | `journalctl -u hust-network-login` |
| Linux (OpenWrt) | procd init script | `/etc/hust-network-login.conf` | `logread` |
| macOS | launchd LaunchAgent | `~/.config/hust-network-login.conf` | `~/.hust-network-login.log` |

`install` 可以显式指定配置文件路径：

```shell
hust-network-login service install ./my.conf
```

Windows 下创建计划任务可能需要管理员权限；systemd 和 OpenWrt 需要 root。

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
