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
const USER_UNIT_PATH: &str = ".config/systemd/user/hust-network-login.service";
const OPENWRT_INIT: &str = "/etc/init.d/hust-network-login";
const LAUNCH_LABEL: &str = "com.hust-network-login";
const SYSTEM_LOG_DIR: &str = "C:\\ProgramData\\hust-network-login";

#[cfg(windows)]
mod elevation_win {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
        #[allow(non_snake_case)]
        fn ShellExecuteW(
            hwnd: *mut c_void,
            lpOperation: *const u16,
            lpFile: *const u16,
            lpParameters: *const u16,
            lpDirectory: *const u16,
            nShowCmd: i32,
        ) -> *mut c_void;
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    pub fn is_admin() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }

    pub fn run_as_admin(exe: &Path, parameters: &str) -> std::io::Result<()> {
        let operation = wide("runas");
        let file = wide(&exe.to_string_lossy());
        let parameters = wide(parameters);
        let result = unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                parameters.as_ptr(),
                ptr::null(),
                1,
            )
        };
        if result as usize > 32 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "UAC elevation was cancelled or failed",
            ))
        }
    }
}

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

fn conf_path(arg: Option<&String>, platform: Platform, system: bool) -> io::Result<PathBuf> {
    if let Some(arg) = arg {
        return absolute(Path::new(arg));
    }
    Ok(match (platform, system) {
        (Platform::Windows, true) => PathBuf::from("C:\\ProgramData\\hust-network-login\\login.conf"),
        (Platform::Windows, false) => home().join(".hust-network-login.conf"),
        (Platform::MacOs, true) => PathBuf::from("/etc/hust-network-login.conf"),
        (Platform::MacOs, false) => home().join(".config/hust-network-login.conf"),
        (_, true) => PathBuf::from("/etc/hust-network-login.conf"),
        (_, false) => home().join(".config/hust-network-login.conf"),
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

/// Split flags from positional arguments. `--elevated` is internal and only
/// used by the UAC re-launch to avoid an elevation loop.
fn parse_args(args: &[String]) -> (bool, bool, Vec<String>) {
    let mut system = false;
    let mut elevated = false;
    let mut positional = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--system" | "-s" => system = true,
            "--elevated" => elevated = true,
            _ => positional.push(arg.clone()),
        }
    }
    (system, elevated, positional)
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn elevate(platform: Platform, system: bool, elevated: bool, args: &[String]) -> io::Result<()> {
    if !system || elevated {
        return Ok(());
    }

    match platform {
        Platform::Windows => {
            #[cfg(windows)]
            {
                if elevation_win::is_admin() {
                    return Ok(());
                }
                let exe = exe_path()?;
                let mut parts = vec!["service".to_owned()];
                parts.extend_from_slice(args);
                parts.push("--elevated".to_owned());
                let parameters = parts
                    .iter()
                    .map(|p| format!("\"{}\"", p.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(" ");
                elevation_win::run_as_admin(&exe, &parameters)?;
                println!("UAC prompt launched; finish it in the elevated window");
                std::process::exit(0);
            }
            #[cfg(not(windows))]
            let _ = (platform, args);
        }
        Platform::MacOs | Platform::Systemd | Platform::OpenWrt => {
            if is_root() {
                return Ok(());
            }
            let exe = exe_path()?;
            let status = Command::new("sudo").arg(exe).args(args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Platform::Unsupported => {}
    }
    Ok(())
}

pub fn handle(args: &[String]) -> io::Result<()> {
    let (system, elevated, positional) = parse_args(args);
    if positional.is_empty() {
        print_usage();
        return Ok(());
    }
    let action = Action::parse(&positional[0])?;
    let conf_arg = positional.get(1);
    let platform = detect_platform();
    println!("detected platform: {platform:?}");
    println!("scope: {}", if system { "system" } else { "user" });
    elevate(platform, system, elevated, args)?;

    match platform {
        Platform::Windows => windows(action, conf_arg, system),
        Platform::MacOs => launchd(action, conf_arg, system),
        Platform::Systemd => systemd(action, conf_arg, system),
        Platform::OpenWrt => openwrt(action, conf_arg),
        Platform::Unsupported => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported platform; install the service manually",
        )),
    }
}

fn print_usage() {
    println!("usage: hust-network-login service <action> [--system] [config-file]");
    println!("actions: install | uninstall | start | stop | restart | status | logs");
    println!("--system: machine-wide service (UAC on Windows, sudo elsewhere); default is user scope");
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

fn windows(action: Action, conf_arg: Option<&String>, system: bool) -> io::Result<()> {
    let exe = exe_path()?;
    let log = if system {
        PathBuf::from(SYSTEM_LOG_DIR).join("service.log")
    } else {
        home().join(".hust-network-login.log")
    };

    if action != Action::Install && action != Action::Logs && !task_exists() {
        println!("task {WIN_TASK} is not installed");
        return Ok(());
    }

    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::Windows, system)?;
            if !conf.exists() {
                println!("warning: config file does not exist yet: {}", conf.display());
            }
            if system {
                fs::create_dir_all(SYSTEM_LOG_DIR)?;
            }
            // Redirect both streams so wake-up failures remain diagnosable.
            let command = format!(
                "cmd /c \"\"{}\" \"{}\" >> \"{}\" 2>&1\"",
                exe.display(),
                conf.display(),
                log.display()
            );
            let mut args = vec!["/Create", "/TN", WIN_TASK, "/TR", &command];
            if system {
                // Machine-wide: SYSTEM account, triggered at boot. Requires UAC.
                args.extend_from_slice(&["/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST"]);
            } else {
                args.extend_from_slice(&["/SC", "ONLOGON", "/RL", "LIMITED"]);
            }
            args.push("/F");
            schtasks(&args)?;
            schtasks(&["/Run", "/TN", WIN_TASK])?;
            println!(
                "installed {scope} task {WIN_TASK}; log: {}",
                log.display(),
                scope = if system { "system" } else { "user" }
            );
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

fn systemd(action: Action, conf_arg: Option<&String>, system: bool) -> io::Result<()> {
    let unit_path: PathBuf = if system {
        PathBuf::from(UNIT_PATH)
    } else {
        home().join(USER_UNIT_PATH)
    };
    let scope: &[&str] = if system { &[] } else { &["--user"] };
    let wanted_by = if system { "multi-user.target" } else { "default.target" };
    let unit_display = unit_path.display().to_string();

    let ctl = |args: &[&str]| -> io::Result<()> {
        let mut full = scope.to_vec();
        full.extend_from_slice(args);
        run("systemctl", &full)
    };

    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::Systemd, system)?;
            if !conf.exists() {
                println!("warning: config file does not exist yet: {}", conf.display());
            }
            if let Some(parent) = unit_path.parent() {
                fs::create_dir_all(parent)?;
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
                 WantedBy={}\n",
                exe_path()?.display(),
                conf.display(),
                wanted_by
            );
            fs::write(&unit_path, content)?;
            ctl(&["daemon-reload"])?;
            ctl(&["enable", "--now", UNIT])?;
        }
        Action::Uninstall => {
            let _ = ctl(&["disable", "--now", UNIT]);
            if unit_path.exists() {
                fs::remove_file(&unit_path)?;
            }
            ctl(&["daemon-reload"])?;
        }
        Action::Start => ctl(&["start", UNIT])?,
        Action::Stop => ctl(&["stop", UNIT])?,
        Action::Restart => ctl(&["restart", UNIT])?,
        Action::Status => ctl(&["status", UNIT, "--no-pager"])?,
        Action::Logs => {
            let mut args = scope.to_vec();
            args.extend_from_slice(&["-u", UNIT, "-n", "50", "--no-pager"]);
            run("journalctl", &args)?;
        }
    }
    println!(
        "unit: {unit_display} ({scope})",
        scope = if system { "system" } else { "user" }
    );
    Ok(())
}

// ---- Linux: OpenWrt / procd ---------------------------------------------

fn openwrt(action: Action, conf_arg: Option<&String>) -> io::Result<()> {
    let init_path = Path::new(OPENWRT_INIT);
    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::OpenWrt, true)?;
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

fn launchd(action: Action, conf_arg: Option<&String>, system: bool) -> io::Result<()> {
    let plist: PathBuf = if system {
        PathBuf::from("/Library/LaunchDaemons/com.hust-network-login.plist")
    } else {
        home().join("Library/LaunchAgents/com.hust-network-login.plist")
    };
    let log: PathBuf = if system {
        PathBuf::from("/var/log/hust-network-login.log")
    } else {
        home().join(".hust-network-login.log")
    };
    match action {
        Action::Install => {
            let conf = conf_path(conf_arg, Platform::MacOs, system)?;
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
    fn splits_system_flag() {
        let args = vec![
            "install".to_owned(),
            "--system".to_owned(),
            "./my.conf".to_owned(),
        ];
        let (system, elevated, positional) = parse_args(&args);
        assert!(system);
        assert!(!elevated);
        assert_eq!(positional, vec!["install", "./my.conf"]);

        let args = vec!["status".to_owned(), "--elevated".to_owned()];
        let (system, elevated, positional) = parse_args(&args);
        assert!(!system);
        assert!(elevated);
        assert_eq!(positional, vec!["status"]);
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
