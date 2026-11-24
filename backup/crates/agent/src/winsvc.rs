//! Windows service entry point (`fenrir-backup-agent service`), registered
//! by the installer as `FenrirBackupAgent`.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(crate::names::win_service(), ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s2.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(crate::names::win_service(), handler) else {
        return;
    };
    let status = |state, accept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = h.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ));
    match crate::run_loop(stop) {
        Ok(crate::LoopExit::Restart) => schedule_restart(),
        Ok(crate::LoopExit::Stopped) => {}
        Err(e) => crate::log::error(&format!("agent stopped: {e:#}")),
    }
    let _ = h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
}

/// After an update: a detached helper starts the service again a few
/// seconds after this instance has stopped.
fn schedule_restart() {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let r = std::process::Command::new("cmd.exe")
        .raw_arg(format!(
            "/C ping -n 6 127.0.0.1 >NUL & sc.exe start {}",
            crate::names::win_service()
        ))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn();
    if let Err(e) = r {
        crate::log::error(&format!(
            "could not schedule the restart after updating: {e}"
        ));
    }
}
