//! Minimal VSS requester.
//!
//! `IVssBackupComponents` is declared in the Windows SDK header
//! `vsbackup.h` but is absent from the Win32 metadata used by the `windows`
//! crate, so its vtable is declared here by hand, in header order. Only the
//! methods we call are typed; the rest are placeholders that keep the
//! slot positions. Any change here must be checked against the header.

use std::ffi::c_void;
use std::ptr::null_mut;

use windows::core::BOOL;
use windows::core::{Interface, BSTR, GUID, HRESULT, PCWSTR};
use windows::Win32::Storage::Vss::{
    IVssAsync, VSS_BACKUP_TYPE, VSS_CTX_BACKUP, VSS_SNAPSHOT_PROP, VSS_S_ASYNC_CANCELLED,
    VSS_S_ASYNC_FINISHED,
};
use windows::Win32::System::Threading::INFINITE;

type Slot = usize;
type This = *mut c_void;

#[repr(C)]
#[allow(non_snake_case)]
struct IVssBackupComponentsVtbl {
    QueryInterface: Slot,
    AddRef: Slot,
    Release: unsafe extern "system" fn(This) -> u32,
    GetWriterComponentsCount: Slot,
    GetWriterComponents: Slot,
    InitializeForBackup: unsafe extern "system" fn(This, *mut u16) -> HRESULT,
    SetBackupState: unsafe extern "system" fn(This, bool, bool, VSS_BACKUP_TYPE, bool) -> HRESULT,
    InitializeForRestore: Slot,
    SetRestoreState: Slot,
    GatherWriterMetadata: unsafe extern "system" fn(This, *mut *mut c_void) -> HRESULT,
    GetWriterMetadataCount: Slot,
    GetWriterMetadata: Slot,
    FreeWriterMetadata: unsafe extern "system" fn(This) -> HRESULT,
    AddComponent: Slot,
    PrepareForBackup: unsafe extern "system" fn(This, *mut *mut c_void) -> HRESULT,
    AbortBackup: unsafe extern "system" fn(This) -> HRESULT,
    GatherWriterStatus: unsafe extern "system" fn(This, *mut *mut c_void) -> HRESULT,
    GetWriterStatusCount: unsafe extern "system" fn(This, *mut u32) -> HRESULT,
    FreeWriterStatus: unsafe extern "system" fn(This) -> HRESULT,
    GetWriterStatus: unsafe extern "system" fn(
        This,
        u32,
        *mut GUID,
        *mut GUID,
        *mut *mut u16,
        *mut i32,
        *mut HRESULT,
    ) -> HRESULT,
    SetBackupSucceeded: Slot,
    SetBackupOptions: Slot,
    SetSelectedForRestore: Slot,
    SetRestoreOptions: Slot,
    SetAdditionalRestores: Slot,
    SetPreviousBackupStamp: Slot,
    SaveAsXML: Slot,
    BackupComplete: unsafe extern "system" fn(This, *mut *mut c_void) -> HRESULT,
    AddAlternativeLocationMapping: Slot,
    AddRestoreSubcomponent: Slot,
    SetFileRestoreStatus: Slot,
    AddNewTarget: Slot,
    SetRangesFilePath: Slot,
    PreRestore: Slot,
    PostRestore: Slot,
    SetContext: unsafe extern "system" fn(This, i32) -> HRESULT,
    StartSnapshotSet: unsafe extern "system" fn(This, *mut GUID) -> HRESULT,
    AddToSnapshotSet: unsafe extern "system" fn(This, *const u16, GUID, *mut GUID) -> HRESULT,
    DoSnapshotSet: unsafe extern "system" fn(This, *mut *mut c_void) -> HRESULT,
    DeleteSnapshots: Slot,
    ImportSnapshots: Slot,
    BreakSnapshotSet: Slot,
    GetSnapshotProperties: unsafe extern "system" fn(This, GUID, *mut VSS_SNAPSHOT_PROP) -> HRESULT,
    Query: Slot,
    IsVolumeSupported: unsafe extern "system" fn(This, GUID, *const u16, *mut BOOL) -> HRESULT,
}

#[link(name = "vssapi", kind = "raw-dylib")]
extern "system" {
    fn CreateVssBackupComponentsInternal(pp: *mut This) -> HRESULT;
    fn VssFreeSnapshotPropertiesInternal(prop: *mut VSS_SNAPSHOT_PROP);
}

/// Owned `IVssBackupComponents` pointer.
struct Components(This);

// The object is used from one thread at a time; VSS requires MTA, which
// the caller sets up.
unsafe impl Send for Components {}

impl Components {
    // The vtable outlives every use: it belongs to the object, which lives
    // until `Components` drops.
    fn vtbl(&self) -> &'static IVssBackupComponentsVtbl {
        unsafe { &**(self.0 as *const *const IVssBackupComponentsVtbl) }
    }
}

impl Drop for Components {
    fn drop(&mut self) {
        // Releasing the requester deletes non-persistent (VSS_CTX_BACKUP)
        // snapshots.
        unsafe { (self.vtbl().Release)(self.0) };
    }
}

#[derive(Debug)]
pub struct VssError {
    pub step: &'static str,
    pub hr: HRESULT,
}

impl std::fmt::Display for VssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VSS {} failed: 0x{:08X} ({})",
            self.step,
            self.hr.0 as u32,
            self.hr.message()
        )
    }
}

impl std::error::Error for VssError {}

fn check(step: &'static str, hr: HRESULT) -> Result<(), VssError> {
    if hr.is_ok() {
        Ok(())
    } else {
        Err(VssError { step, hr })
    }
}

/// Run an async VSS operation to completion.
fn wait(step: &'static str, f: impl FnOnce(*mut *mut c_void) -> HRESULT) -> Result<(), VssError> {
    let mut p: *mut c_void = null_mut();
    check(step, f(&mut p))?;
    let a = unsafe { IVssAsync::from_raw(p) };
    unsafe { a.Wait(INFINITE) }.map_err(|e| VssError { step, hr: e.code() })?;
    let mut status = HRESULT(0);
    unsafe { a.QueryStatus(&mut status, null_mut()) }
        .map_err(|e| VssError { step, hr: e.code() })?;
    if status == VSS_S_ASYNC_CANCELLED {
        return Err(VssError { step, hr: status });
    }
    if status != VSS_S_ASYNC_FINISHED && status.is_err() {
        return Err(VssError { step, hr: status });
    }
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { PCWSTR(p).to_string().unwrap_or_default() }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Original volume GUID path, e.g. `\\?\Volume{...}\`.
    pub volume: String,
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`.
    pub device: String,
}

#[derive(Debug, Clone)]
pub struct WriterIssue {
    pub writer: String,
    pub state: i32,
    pub failure: HRESULT,
}

/// A live snapshot set. Snapshots disappear when this is dropped.
pub struct SnapshotSet {
    comp: Components,
    pub snapshots: Vec<Snapshot>,
    pub writer_issues: Vec<WriterIssue>,
    finished: bool,
}

/// `VSS_WS_FAILED_AT_IDENTIFY` (7) and above are failure states.
const FIRST_FAILED_STATE: i32 = 7;

impl SnapshotSet {
    /// Create a snapshot set of `volumes` with writer participation.
    ///
    /// `backup_type`: `VSS_BT_COPY` leaves application log chains alone
    /// (default); `VSS_BT_FULL` lets writers such as SQL Server and
    /// Exchange truncate logs after `complete(true)`.
    pub fn create(
        volumes: &[String],
        backup_type: VSS_BACKUP_TYPE,
    ) -> Result<SnapshotSet, VssError> {
        let mut raw: This = null_mut();
        check("CreateVssBackupComponents", unsafe {
            CreateVssBackupComponentsInternal(&mut raw)
        })?;
        let comp = Components(raw);
        let v = comp.vtbl();
        unsafe {
            check(
                "InitializeForBackup",
                (v.InitializeForBackup)(comp.0, null_mut()),
            )?;
            check("SetContext", (v.SetContext)(comp.0, VSS_CTX_BACKUP.0))?;
            // Whole-volume image: no component selection (all writers'
            // components are implicitly included), bootable system state.
            check(
                "SetBackupState",
                (v.SetBackupState)(comp.0, false, true, backup_type, false),
            )?;
            wait("GatherWriterMetadata", |p| {
                (v.GatherWriterMetadata)(comp.0, p)
            })?;
            check("FreeWriterMetadata", (v.FreeWriterMetadata)(comp.0))?;

            let mut set_id = GUID::zeroed();
            check(
                "StartSnapshotSet",
                (v.StartSnapshotSet)(comp.0, &mut set_id),
            )?;
            let mut ids = Vec::new();
            for vol in volumes {
                let w = wide(vol);
                let mut sid = GUID::zeroed();
                check(
                    "AddToSnapshotSet",
                    (v.AddToSnapshotSet)(comp.0, w.as_ptr(), GUID::zeroed(), &mut sid),
                )?;
                ids.push((vol.clone(), sid));
            }
            let mut set = SnapshotSet {
                comp,
                snapshots: vec![],
                writer_issues: vec![],
                finished: false,
            };
            let v = set.comp.vtbl();
            let c = set.comp.0;
            wait("PrepareForBackup", |p| (v.PrepareForBackup)(c, p))?;
            set.collect_writer_status()?;
            wait("DoSnapshotSet", |p| (v.DoSnapshotSet)(c, p))?;
            set.collect_writer_status()?;
            for (vol, sid) in ids {
                let mut prop = VSS_SNAPSHOT_PROP::default();
                check(
                    "GetSnapshotProperties",
                    (v.GetSnapshotProperties)(c, sid, &mut prop),
                )?;
                let device = from_wide_ptr(prop.m_pwszSnapshotDeviceObject);
                VssFreeSnapshotPropertiesInternal(&mut prop);
                set.snapshots.push(Snapshot {
                    volume: vol,
                    device,
                });
            }
            Ok(set)
        }
    }

    /// Ask the provider whether it can snapshot `volume` (FAT volumes such
    /// as the ESP cannot be). Uses a throwaway requester.
    pub fn is_supported(volume: &str) -> bool {
        let mut raw: This = null_mut();
        if unsafe { CreateVssBackupComponentsInternal(&mut raw) }.is_err() {
            return false;
        }
        let comp = Components(raw);
        let v = comp.vtbl();
        let w = wide(volume);
        let mut ok = BOOL(0);
        unsafe {
            if (v.InitializeForBackup)(comp.0, null_mut()).is_err()
                || (v.SetContext)(comp.0, VSS_CTX_BACKUP.0).is_err()
            {
                return false;
            }
            (v.IsVolumeSupported)(comp.0, GUID::zeroed(), w.as_ptr(), &mut ok).is_ok()
                && ok.as_bool()
        }
    }

    fn collect_writer_status(&mut self) -> Result<(), VssError> {
        let v = self.comp.vtbl();
        let c = self.comp.0;
        unsafe {
            wait("GatherWriterStatus", |p| (v.GatherWriterStatus)(c, p))?;
            let mut n = 0u32;
            check("GetWriterStatusCount", (v.GetWriterStatusCount)(c, &mut n))?;
            for i in 0..n {
                let mut inst = GUID::zeroed();
                let mut wid = GUID::zeroed();
                let mut name: *mut u16 = null_mut();
                let mut state = 0i32;
                let mut failure = HRESULT(0);
                if (v.GetWriterStatus)(
                    c,
                    i,
                    &mut inst,
                    &mut wid,
                    &mut name,
                    &mut state,
                    &mut failure,
                )
                .is_ok()
                {
                    let writer = if name.is_null() {
                        String::new()
                    } else {
                        BSTR::from_raw(name).to_string()
                    };
                    if state >= FIRST_FAILED_STATE
                        && !self.writer_issues.iter().any(|w| w.writer == writer)
                    {
                        self.writer_issues.push(WriterIssue {
                            writer,
                            state,
                            failure,
                        });
                    }
                }
            }
            check("FreeWriterStatus", (v.FreeWriterStatus)(c))?;
        }
        Ok(())
    }

    /// Finish the backup. `success = true` tells writers the backup is
    /// complete (BackupComplete); false aborts it. Snapshots are released
    /// when `self` drops at the end of this call.
    pub fn complete(mut self, success: bool) -> Result<(), VssError> {
        self.finished = true;
        let v = self.comp.vtbl();
        let c = self.comp.0;
        if success {
            unsafe { wait("BackupComplete", |p| (v.BackupComplete)(c, p)) }
        } else {
            unsafe { check("AbortBackup", (v.AbortBackup)(c)) }
        }
    }
}

impl Drop for SnapshotSet {
    fn drop(&mut self) {
        if !self.finished {
            let v = self.comp.vtbl();
            unsafe {
                let _ = (v.AbortBackup)(self.comp.0);
            }
        }
    }
}
