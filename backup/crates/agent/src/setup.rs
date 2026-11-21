//! Windows setup: install the agent as the `FenrirBackupAgent` service.
//!
//! * `Fenrir-Backup-Setup.exe` from the server is the agent with its settings
//!   appended (`protocol::setup`). Started with no arguments (double-click)
//!   it installs itself; `/quiet` does the same without waiting for a key.
//! * `fenrir-backup-agent install --server ... --token ...` does it explicitly.
//!
//! The installed copy in `%ProgramFiles%\Fenrir` is the plain agent (the
//! settings block removed), byte-identical to the server's build.

use protocol::setup::SetupConfig;

/// Settings appended to this executable, and the executable without them.
pub fn embedded() -> Option<(SetupConfig, Vec<u8>)> {
    let me = std::env::current_exe().ok()?;
    let data = std::fs::read(me).ok()?;
    let (cfg, at) = protocol::setup::read(&data)?;
    let mut exe = data;
    exe.truncate(at);
    Some((cfg, exe))
}

pub fn is_quiet_flag(a: &str) -> bool {
    matches!(
        a.to_ascii_lowercase().as_str(),
        "/quiet" | "/q" | "/s" | "--quiet"
    )
}

#[cfg(windows)]
pub use win::{install, uninstall};

#[cfg(not(windows))]
pub fn install(_: &SetupConfig, _: Option<Vec<u8>>, _: Option<&str>) -> anyhow::Result<bool> {
    anyhow::bail!(
        "installing as a service is for Windows; on Linux and macOS use the install script"
    )
}

#[cfg(not(windows))]
pub fn uninstall() -> anyhow::Result<()> {
    anyhow::bail!("uninstall is for Windows; on Linux and macOS use the uninstall script")
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context};
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::SetupConfig;

    use crate::names::{EXE_STEM, WIN_FOLDER, WIN_SERVICE as NAME, WIN_SERVICE_DISPLAY};

    fn exe_name() -> String {
        format!("{EXE_STEM}.exe")
    }

    /// A service with our name that runs something else belongs to another
    /// product: never stop, reconfigure or delete it.
    fn check_ours(svc: &windows_service::service::Service, target: &Path) -> anyhow::Result<()> {
        let cfg = svc
            .query_config()
            .context("reading the existing service's settings")?;
        let runs = cfg.executable_path.to_string_lossy().to_ascii_lowercase();
        if !runs.contains(&target.to_string_lossy().to_ascii_lowercase()) {
            bail!(
                "a service named {NAME} already exists but runs {}; it is not Fenrir-Backup's, so it was left untouched",
                cfg.executable_path.display()
            );
        }
        Ok(())
    }

    fn elevated() -> bool {
        unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
    }

    /// Start this program again with administrator rights (UAC prompt).
    fn relaunch_elevated(args: &str) -> anyhow::Result<()> {
        use windows::core::{w, HSTRING, PCWSTR};
        let me = std::env::current_exe()?;
        let r = unsafe {
            windows::Win32::UI::Shell::ShellExecuteW(
                None,
                w!("runas"),
                &HSTRING::from(me.as_os_str()),
                &HSTRING::from(args),
                PCWSTR::null(),
                windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        if (r.0 as isize) <= 32 {
            bail!("administrator rights are needed to install the agent (the prompt was declined or failed)");
        }
        Ok(())
    }

    pub fn install_dir() -> PathBuf {
        PathBuf::from(
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into()),
        )
        .join(WIN_FOLDER)
    }

    fn wait_for(svc: &windows_service::service::Service, state: ServiceState, secs: u64) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if svc
                .query_status()
                .map(|s| s.current_state == state)
                .unwrap_or(false)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    /// Install or update the agent and its service. `exe` is the plain
    /// agent to install (None: this executable). `relaunch_args` repeat the
    /// request after an elevation prompt.
    pub fn install(
        cfg: &SetupConfig,
        exe: Option<Vec<u8>>,
        relaunch_args: Option<&str>,
    ) -> anyhow::Result<bool> {
        if !elevated() {
            if let Some(a) = relaunch_args {
                relaunch_elevated(a)?;
                return Ok(false);
            }
            bail!("run this as Administrator");
        }
        println!("Installing the Fenrir-Backup agent for {}", cfg.server);
        let mgr = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("opening the service manager")?;
        if cfg.role == "hyperv"
            && mgr
                .open_service("vmms", ServiceAccess::QUERY_STATUS)
                .is_err()
        {
            bail!("this machine is not a Hyper-V host (the vmms service is missing); download the Windows installer instead");
        }

        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::QUERY_CONFIG
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;
        let dir = install_dir();
        let target = dir.join(exe_name());
        let existing = mgr.open_service(NAME, access).ok();
        if let Some(s) = &existing {
            check_ours(s, &target)?;
            if s.query_status()?.current_state != ServiceState::Stopped {
                println!("Stopping the running agent...");
                let _ = s.stop();
                if !wait_for(s, ServiceState::Stopped, 60) {
                    bail!("the running agent did not stop; try again in a minute");
                }
            }
        }

        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let me = std::env::current_exe()?;
        let bytes = match exe {
            Some(b) => b,
            None => std::fs::read(&me)?,
        };
        if !same_file(&me, &target) {
            let tmp = dir.join(format!("{}.new", exe_name()));
            std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
            std::fs::rename(&tmp, &target)
                .with_context(|| format!("replacing {}", target.display()))?;
        }

        println!("Enrolling with the server...");
        if let Err(e) = crate::enroll(&cfg.server, &cfg.token, &cfg.pin, &cfg.role) {
            // A fresh install that could not enrol leaves nothing behind (the
            // all-in-one Fenrir setup may run this for a deployment without backup).
            if existing.is_none() && !same_file(&me, &target) {
                let _ = std::fs::remove_file(&target);
                let _ = std::fs::remove_dir(&dir);
            }
            return Err(e);
        }

        let info = ServiceInfo {
            name: OsString::from(NAME),
            display_name: OsString::from(WIN_SERVICE_DISPLAY),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: target.clone(),
            launch_arguments: vec![OsString::from("service")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let svc = match existing {
            Some(s) => {
                s.change_config(&info).context("updating the service")?;
                s
            }
            None => mgr
                .create_service(&info, access)
                .context("creating the service")?,
        };
        let _ = svc.set_description("Backs up this machine for Fenrir-Backup.");
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        let _ = svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(60), restart(60), restart(300)]),
        });
        // The agent exits with code 75 after a self-update; restart then too.
        let _ = svc.set_failure_actions_on_non_crash_failures(true);
        svc.start::<&str>(&[]).context("starting the service")?;
        if !wait_for(&svc, ServiceState::Running, 30) {
            bail!(
                "the service did not start; see {}",
                crate::config::state_dir().join("agent.log").display()
            );
        }
        println!("Done. The agent runs as the {NAME} service; this machine appears in the web UI within a minute.");
        Ok(true)
    }

    fn same_file(a: &Path, b: &Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    /// Stop and delete the service, then remove the program folder (after
    /// this process has exited) and the agent's identity.
    pub fn uninstall() -> anyhow::Result<()> {
        if !elevated() {
            bail!("run this as Administrator");
        }
        if crate::names::legacy_install() {
            bail!("this agent was installed under the old names (FenrirAgent, C:\\Program Files\\Fenrir), which other software also uses; remove it by hand as described in the deployment guide");
        }
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let dir = install_dir();
        if let Ok(s) = mgr.open_service(
            NAME,
            ServiceAccess::QUERY_STATUS
                | ServiceAccess::QUERY_CONFIG
                | ServiceAccess::STOP
                | ServiceAccess::DELETE,
        ) {
            check_ours(&s, &dir.join(exe_name()))?;
            if s.query_status()?.current_state != ServiceState::Stopped {
                let _ = s.stop();
                wait_for(&s, ServiceState::Stopped, 60);
            }
            s.delete().context("deleting the service")?;
        }
        let _ = std::fs::remove_dir_all(crate::config::state_dir());
        // This executable may be the installed one: delete the folder from a
        // detached helper once we have exited.
        use std::os::windows::process::CommandExt;
        // raw_arg: cmd.exe does not understand the \" escaping Rust would
        // apply to the quoted path.
        let _ = std::process::Command::new("cmd.exe")
            .raw_arg(format!(
                "/C ping -n 3 127.0.0.1 >NUL & rmdir /S /Q \"{}\"",
                dir.display()
            ))
            .creation_flags(0x0000_0008 | 0x0000_0200)
            .spawn();
        println!("Fenrir-Backup agent removed. Backups already stored are kept; remove the machine in the web UI as well.");
        Ok(())
    }
}
