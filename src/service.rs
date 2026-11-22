//! Cross-platform service management.
//!
//! The binary itself is the service manager: `hust-network-login service
//! <action>`. The strategy is picked at runtime from the host OS / init
//! system, so the same executable works on Windows, systemd Linux, OpenWrt
//! and macOS without extra scripts or dependencies.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

const WIN_TASK: &str = "HUSTNetworkLogin";
const UNIT: &str = "hust-network-login.service";
const UNIT_PATH: &str = "/etc/systemd/system/hust-network-login.service";
const OPENWRT_INIT: &str = "/etc/init.d/hust-network-login";
const LAUNCH_LABEL: &str = "com.hust-network-login";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
    Systemd,
    OpenWrt,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
    Logs,
}

impl Action {
    fn parse(s: &str) -> io::Result<Self> {
        match s {
            "install" | "i" => Ok(Self::Install),
            "uninstall" | "remove" | "rm" => Ok(Self::Uninstall),
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "restart" | "reload" => Ok(Self::Restart),
            "status" | "ps" => Ok(Self::Status),
            "logs" | "log" => Ok(Self::Logs),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown service action: {s}"),
            )),
        }
    }
}

fn detect_platform() -> Platform {
    match std::env::consts::OS {
        "windows" => Platform::Windows,
        "macos" => Platform::MacOs,
        "linux" => {
            if Path::new("/etc/openwrt_release").exists() || Path::new("/sbin/procd").exists() {
                Platform::OpenWrt
            } else if Path::new("/run/systemd/system").exists() || has_command("systemctl") {
                Platform::Systemd
            } else {
                Platform::Unsupported
            }
        }
        _ => Platform::Unsupported,
    }
}

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn exe_path() -> io::Result<PathBuf> {
    std::env::current_exe()
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn conf_path(arg: Option<&String>, platform: Platform) -> io::Result<PathBuf> {
    if let Some(arg) = arg {
        return absolute(Path::new(arg));
    }
    Ok(match platform {
        Platform::Windows => home().join(".hust-network-login.conf"),
        Platform::MacOs => home().join(".config/hust-network-login.conf"),
        _ => PathBuf::from("/etc/hust-network-login.conf"),
    })
}

/// Single quotes for POSIX shell payloads.
fn sh_quote(value: &Path) -> String {
    format!("'{}'", value.display().to_string().replace('\'', "'\\''"))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    println!("+ {} {}", program, args.join(" "));
    let output = Command::new(program).args(args).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        print!("{stdout}");
    }
    if !stderr.trim().is_empty() {
        eprint!("{stderr}");
    }
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("{program} exited with {status}", status = output.status),
        ))
    }
}

fn tail(path: &Path, lines: usize) -> io::Result<()> {
    if !path.exists() {
        println!("no log file yet: {}", path.display());
        return Ok(());
    }
    let mut text = String::new();
    fs::File::open(path)?.read_to_string(&mut text)?;
    for line in text.lines().rev().take(lines).collect::<Vec<_>>().into_iter().rev() {
        println!("{line}");
    }
    Ok(())
}

pub fn handle(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    let action = Action::parse(&args[0])?;
    let conf_arg = args.get(1);
    let platform = detect_platform();
    println!("detected platform: {platform:?}");

    match platform {
        Platform::Windows => windows(action, conf_arg),
        Platform::MacOs => launchd(action, conf_arg),
        Platform::Systemd => systemd(action, conf_arg),
        Platform::OpenWrt => openwrt(action, conf_arg),
        Platform::Unsupported => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported platform; install the service manually",
        )),
    }
}

fn print_usage() {
    println!("usage: hust-network-login service <action> [config-file]");
    println!("actions: install | uninstall | start | stop | restart | status | logs");
    println!("strategy: Windows -> Task Scheduler, Linux -> systemd/OpenWrt, macOS -> launchd");
}

// ---- Windows: scheduled task at logon -----------------------------------

fn schtasks(args: &[&str]) -> io::Result<()> {
    run("schtasks", args)
}

fn task_exists() -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", WIN_TASK])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn windows(action: Action, conf_arg: Option<&String>) -> io::Result<()> {
    let exe = exe_path()?;
    let log = home().join(".hust-network-login.log");

    if action != Action::Install && action != Action::Logs && !task_exists() {
        println!("task {WIN_TASK} is not installed");
        return Ok(());
    }

    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::Windows)?;
            if !conf.exists() {
                println!("warning: config file does not exist yet: {}", conf.display());
            }
            // Redirect both streams so wake-up failures remain diagnosable.
            let command = format!(
                "cmd /c \"\"{}\" \"{}\" >> \"{}\" 2>&1\"",
                exe.display(),
                conf.display(),
                log.display()
            );
            schtasks(&[
                "/Create",
                "/TN",
                WIN_TASK,
                "/TR",
                &command,
                "/SC",
                "ONLOGON",
                "/RL",
                "LIMITED",
                "/F",
            ])?;
            schtasks(&["/Run", "/TN", WIN_TASK])?;
            println!("installed task {WIN_TASK}; log: {}", log.display());
        }
        Action::Uninstall => schtasks(&["/Delete", "/TN", WIN_TASK, "/F"])?,
        Action::Start => schtasks(&["/Run", "/TN", WIN_TASK])?,
        Action::Stop => schtasks(&["/End", "/TN", WIN_TASK])?,
        Action::Restart => {
            let _ = schtasks(&["/End", "/TN", WIN_TASK]);
            schtasks(&["/Run", "/TN", WIN_TASK])?;
        }
        Action::Status => schtasks(&["/Query", "/TN", WIN_TASK, "/FO", "LIST", "/V"])?,
        Action::Logs => tail(&log, 50)?,
    }
    Ok(())
}

// ---- Linux: systemd -----------------------------------------------------

fn systemd(action: Action, conf_arg: Option<&String>) -> io::Result<()> {
    let unit_path = Path::new(UNIT_PATH);
    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::Systemd)?;
            if !conf.exists() {
                println!("warning: config file does not exist yet: {}", conf.display());
            }
            let content = format!(
                "[Unit]\n\
                 Description=HUST campus network auto login\n\
                 After=network-online.target\n\
                 Wants=network-online.target\n\
                 StartLimitIntervalSec=0\n\
                 \n\
                 [Service]\n\
                 Type=simple\n\
                 ExecStart={} {}\n\
                 Restart=always\n\
                 RestartSec=3\n\
                 \n\
                 [Install]\n\
                 WantedBy=multi-user.target\n",
                exe_path()?.display(),
                conf.display()
            );
            fs::write(unit_path, content)?;
            run("systemctl", &["daemon-reload"])?;
            run("systemctl", &["enable", "--now", UNIT])?;
        }
        Action::Uninstall => {
            let _ = run("systemctl", &["disable", "--now", UNIT]);
            if unit_path.exists() {
                fs::remove_file(unit_path)?;
            }
            run("systemctl", &["daemon-reload"])?;
        }
        Action::Start => run("systemctl", &["start", UNIT])?,
        Action::Stop => run("systemctl", &["stop", UNIT])?,
        Action::Restart => run("systemctl", &["restart", UNIT])?,
        Action::Status => run("systemctl", &["status", UNIT, "--no-pager"])?,
        Action::Logs => run("journalctl", &["-u", UNIT, "-n", "50", "--no-pager"])?,
    }
    Ok(())
}

// ---- Linux: OpenWrt / procd ---------------------------------------------

fn openwrt(action: Action, conf_arg: Option<&String>) -> io::Result<()> {
    let init_path = Path::new(OPENWRT_INIT);
    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::OpenWrt)?;
            let content = format!(
                "#!/bin/sh /etc/rc.common\n\
                 START=95\n\
                 STOP=10\n\
                 USE_PROCD=1\n\
                 \n\
                 start_service() {{\n\
                   procd_open_instance\n\
                   procd_set_param command {} {}\n\
                   procd_set_param respawn\n\
                   procd_close_instance\n\
                 }}\n",
                sh_quote(&exe_path()?),
                sh_quote(&conf)
            );
            fs::write(init_path, content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(init_path, fs::Permissions::from_mode(0o755))?;
            }
            run(init_path.to_str().unwrap_or(OPENWRT_INIT), &["enable"])?;
            run(init_path.to_str().unwrap_or(OPENWRT_INIT), &["start"])?;
        }
        Action::Uninstall => {
            let _ = run(OPENWRT_INIT, &["stop"]);
            let _ = run(OPENWRT_INIT, &["disable"]);
            if init_path.exists() {
                fs::remove_file(init_path)?;
            }
        }
        Action::Start => run(OPENWRT_INIT, &["start"])?,
        Action::Stop => run(OPENWRT_INIT, &["stop"])?,
        Action::Restart => run(OPENWRT_INIT, &["restart"])?,
        Action::Status => run(OPENWRT_INIT, &["status"])?,
        Action::Logs => run("logread", &["-e", "hust-network-login"])?,
    }
    Ok(())
}

// ---- macOS: launchd -----------------------------------------------------

fn launchd(action: Action, conf_arg: Option<&String>) -> io::Result<()> {
    let plist = home().join("Library/LaunchAgents/com.hust-network-login.plist");
    let log = home().join(".hust-network-login.log");
    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::MacOs)?;
            if !conf.exists() {
                println!("warning: config file does not exist yet: {}", conf.display());
            }
            let exe = exe_path()?;
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\"><dict>\n\
                   <key>Label</key><string>{label}</string>\n\
                   <key>ProgramArguments</key><array>\n\
                     <string>{exe}</string><string>{conf}</string>\n\
                   </array>\n\
                   <key>RunAtLoad</key><true/>\n\
                   <key>KeepAlive</key><true/>\n\
                   <key>StandardOutPath</key><string>{log}</string>\n\
                   <key>StandardErrorPath</key><string>{log}</string>\n\
                 </dict></plist>\n",
                label = LAUNCH_LABEL,
                exe = xml_escape(&exe.display().to_string()),
                conf = xml_escape(&conf.display().to_string()),
                log = xml_escape(&log.display().to_string()),
            );
            if let Some(parent) = plist.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&plist, content)?;
            run("launchctl", &["load", "-w", plist.to_str().unwrap_or("")])?;
        }
        Action::Uninstall => {
            let _ = run("launchctl", &["unload", "-w", plist.to_str().unwrap_or("")]);
            if plist.exists() {
                fs::remove_file(plist)?;
            }
        }
        Action::Start => run("launchctl", &["start", LAUNCH_LABEL])?,
        Action::Stop => run("launchctl", &["stop", LAUNCH_LABEL])?,
        Action::Restart => {
            let _ = run("launchctl", &["stop", LAUNCH_LABEL]);
            run("launchctl", &["start", LAUNCH_LABEL])?;
        }
        Action::Status => run("launchctl", &["list", LAUNCH_LABEL])?,
        Action::Logs => tail(&log, 50)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_aliases() {
        assert_eq!(Action::parse("install").unwrap(), Action::Install);
        assert_eq!(Action::parse("i").unwrap(), Action::Install);
        assert_eq!(Action::parse("rm").unwrap(), Action::Uninstall);
        assert_eq!(Action::parse("logs").unwrap(), Action::Logs);
        assert!(Action::parse("bogus").is_err());
    }

    #[test]
    fn quotes_shell_paths() {
        assert_eq!(sh_quote(Path::new("/opt/my app/bin")), "'/opt/my app/bin'");
        assert_eq!(sh_quote(Path::new("/a'b")), "'/a'\\''b'");
    }

    #[test]
    fn escapes_plist_values() {
        assert_eq!(xml_escape("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
    }

    #[test]
    fn detects_current_platform() {
        let expected = match std::env::consts::OS {
            "windows" => Platform::Windows,
            "macos" => Platform::MacOs,
            _ => detect_platform(),
        };
        assert_eq!(detect_platform(), expected);
    }
}
