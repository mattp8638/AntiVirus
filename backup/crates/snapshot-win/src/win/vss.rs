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
    GetWriterMetadataCount: unsafe extern "system" fn(This, *mut u32) -> HRESULT,
    GetWriterMetadata: unsafe extern "system" fn(This, u32, *mut GUID, *mut This) -> HRESULT,
    FreeWriterMetadata: unsafe extern "system" fn(This) -> HRESULT,
    AddComponent:
        unsafe extern "system" fn(This, GUID, GUID, i32, *const u16, *const u16) -> HRESULT,
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
    SetBackupSucceeded:
        unsafe extern "system" fn(This, GUID, GUID, i32, *const u16, *const u16, bool) -> HRESULT,
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

/// `IVssExamineWriterMetadata` (vsbackup.h), only the methods used.
#[repr(C)]
#[allow(non_snake_case)]
struct IVssExamineWriterMetadataVtbl {
    QueryInterface: Slot,
    AddRef: Slot,
    Release: unsafe extern "system" fn(This) -> u32,
    GetIdentity: unsafe extern "system" fn(
        This,
        *mut GUID,
        *mut GUID,
        *mut *mut u16,
        *mut i32,
        *mut i32,
    ) -> HRESULT,
    GetFileCounts: unsafe extern "system" fn(This, *mut u32, *mut u32, *mut u32) -> HRESULT,
    GetIncludeFile: Slot,
    GetExcludeFile: Slot,
    GetComponent: unsafe extern "system" fn(This, u32, *mut This) -> HRESULT,
}

/// `IVssWMComponent` (vsbackup.h).
#[repr(C)]
#[allow(non_snake_case)]
struct IVssWMComponentVtbl {
    QueryInterface: Slot,
    AddRef: Slot,
    Release: unsafe extern "system" fn(This) -> u32,
    GetComponentInfo: unsafe extern "system" fn(This, *mut *mut ComponentInfo) -> HRESULT,
    FreeComponentInfo: unsafe extern "system" fn(This, *mut ComponentInfo) -> HRESULT,
    GetFile: unsafe extern "system" fn(This, u32, *mut This) -> HRESULT,
    GetDatabaseFile: unsafe extern "system" fn(This, u32, *mut This) -> HRESULT,
    GetDatabaseLogFile: unsafe extern "system" fn(This, u32, *mut This) -> HRESULT,
    GetDependency: Slot,
}

/// `VSS_COMPONENTINFO` (vsbackup.h); `bool` is one byte.
#[repr(C)]
struct ComponentInfo {
    kind: i32,
    logical_path: *mut u16,
    name: *mut u16,
    caption: *mut u16,
    icon: *mut u8,
    icon_len: u32,
    restore_metadata: u8,
    notify_on_backup_complete: u8,
    selectable: u8,
    selectable_for_restore: u8,
    flags: u32,
    files: u32,
    databases: u32,
    log_files: u32,
    dependencies: u32,
}

/// An owned COM pointer, released on drop.
struct Unk(This);

impl Unk {
    fn vtbl<T>(&self) -> &'static T {
        unsafe { &**(self.0 as *const *const T) }
    }
}

impl Drop for Unk {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // IUnknown::Release is the third slot of every interface.
            unsafe {
                let vt = *(self.0 as *const *const [unsafe extern "system" fn(This) -> u32; 3]);
                ((*vt)[2])(self.0);
            }
        }
    }
}

fn bstr_string(p: *mut u16) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { BSTR::from_raw(p) }.to_string()
    }
}

fn guid_string(g: &GUID) -> String {
    format!("{g:?}")
        .trim_matches(['{', '}'])
        .to_ascii_lowercase()
}

/// A component added to the backup, to report back on.
struct Added {
    instance: GUID,
    writer: GUID,
    kind: i32,
    logical_path: Vec<u16>,
    name: Vec<u16>,
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
    /// Application components found, and whether each was added.
    pub applications: Vec<core_format::manifest::ApplicationInfo>,
    added: Vec<Added>,
    finished: bool,
}

/// `VSS_WS_FAILED_AT_IDENTIFY` (7) and above are failure states.
const FIRST_FAILED_STATE: i32 = 7;

impl SnapshotSet {
    /// Create a snapshot set of `volumes`, coordinated with the writers'
    /// components on those volumes (component mode, docs/design/app-aware.md).
    ///
    /// `backup_type`: `VSS_BT_COPY` leaves application log chains alone
    /// (default; SQL Server records a copy-only backup); `VSS_BT_FULL` lets
    /// writers such as SQL Server and Exchange record a full backup and
    /// truncate their logs after `complete(true)`.
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
            // Component mode: the components on the imaged volumes are added,
            // so their writers treat this as a backup of them; bootable
            // system state.
            check(
                "SetBackupState",
                (v.SetBackupState)(comp.0, true, true, backup_type, false),
            )?;
            wait("GatherWriterMetadata", |p| {
                (v.GatherWriterMetadata)(comp.0, p)
            })?;
            let (found, ids) = writer_components(&comp)?;
            let sel = crate::apps::select(&found, volumes);
            let mut added = Vec::new();
            for &i in &sel.add {
                let c = &found[i];
                let (instance, writer) = ids[i];
                let path = wide(&c.logical_path);
                let name = wide(&c.name);
                let lp = if c.logical_path.is_empty() {
                    std::ptr::null()
                } else {
                    path.as_ptr()
                };
                check(
                    "AddComponent",
                    (v.AddComponent)(comp.0, instance, writer, c.kind, lp, name.as_ptr()),
                )?;
                added.push(Added {
                    instance,
                    writer,
                    kind: c.kind,
                    logical_path: path,
                    name,
                });
            }
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
                applications: sel.report,
                added,
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
            // Each added component is reported as backed up, so its writer
            // can record the backup (and, for a FULL backup, truncate logs).
            for a in &self.added {
                let lp = if a.logical_path.len() <= 1 {
                    std::ptr::null()
                } else {
                    a.logical_path.as_ptr()
                };
                // A component that cannot be marked still lets the others,
                // and BackupComplete, go ahead.
                let _ = unsafe {
                    (v.SetBackupSucceeded)(
                        c,
                        a.instance,
                        a.writer,
                        a.kind,
                        lp,
                        a.name.as_ptr(),
                        true,
                    )
                };
            }
            unsafe { wait("BackupComplete", |p| (v.BackupComplete)(c, p)) }
        } else {
            unsafe { check("AbortBackup", (v.AbortBackup)(c)) }
        }
    }
}

/// Every component of every writer, with the volumes of its files, and the
/// (writer instance, writer class) ids to add it with.
type FoundComponents = (Vec<crate::apps::Component>, Vec<(GUID, GUID)>);

unsafe fn writer_components(comp: &Components) -> Result<FoundComponents, VssError> {
    let v = comp.vtbl();
    let mut n = 0u32;
    check(
        "GetWriterMetadataCount",
        (v.GetWriterMetadataCount)(comp.0, &mut n),
    )?;
    let mut out = Vec::new();
    let mut ids = Vec::new();
    for w in 0..n {
        let mut instance = GUID::zeroed();
        let mut raw: This = null_mut();
        check(
            "GetWriterMetadata",
            (v.GetWriterMetadata)(comp.0, w, &mut instance, &mut raw),
        )?;
        let meta = Unk(raw);
        let mv: &IVssExamineWriterMetadataVtbl = meta.vtbl();
        let (mut inst2, mut writer_id) = (GUID::zeroed(), GUID::zeroed());
        let (mut name, mut usage, mut source) = (null_mut(), 0i32, 0i32);
        check(
            "GetIdentity",
            (mv.GetIdentity)(
                meta.0,
                &mut inst2,
                &mut writer_id,
                &mut name,
                &mut usage,
                &mut source,
            ),
        )?;
        let writer = bstr_string(name);
        let (mut inc, mut exc, mut count) = (0u32, 0u32, 0u32);
        check(
            "GetFileCounts",
            (mv.GetFileCounts)(meta.0, &mut inc, &mut exc, &mut count),
        )?;
        for k in 0..count {
            let mut rc: This = null_mut();
            if (mv.GetComponent)(meta.0, k, &mut rc).is_err() {
                continue;
            }
            let wc = Unk(rc);
            let cv: &IVssWMComponentVtbl = wc.vtbl();
            let mut info: *mut ComponentInfo = null_mut();
            if (cv.GetComponentInfo)(wc.0, &mut info).is_err() || info.is_null() {
                continue;
            }
            let i = &*info;
            let mut volumes = Vec::new();
            for (getter, count) in [
                (cv.GetFile, i.files),
                (cv.GetDatabaseFile, i.databases),
                (cv.GetDatabaseLogFile, i.log_files),
            ] {
                for f in 0..count {
                    let mut fd: This = null_mut();
                    if getter(wc.0, f, &mut fd).is_err() || fd.is_null() {
                        volumes.push(None);
                        continue;
                    }
                    let desc = windows::Win32::Storage::Vss::IVssWMFiledesc::from_raw(fd);
                    volumes.push(desc.GetPath().ok().and_then(|p| volume_of(&p.to_string())));
                }
            }
            let c = crate::apps::Component {
                writer_id: guid_string(&writer_id),
                writer: writer.clone(),
                // The component info's strings belong to it: copied, not freed.
                logical_path: from_wide_ptr(i.logical_path),
                name: from_wide_ptr(i.name),
                caption: from_wide_ptr(i.caption),
                kind: i.kind,
                selectable: i.selectable != 0,
                volumes,
            };
            let _ = (cv.FreeComponentInfo)(wc.0, info);
            out.push(c);
            ids.push((instance, writer_id));
        }
    }
    Ok((out, ids))
}

/// The volume GUID name (`\\?\Volume{...}\`) holding `path` (environment
/// variables such as `%SystemRoot%` expanded).
fn volume_of(path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
    let src = wide(path.trim());
    let mut expanded = vec![0u16; 32768];
    let n =
        unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut expanded)) } as usize;
    if n == 0 || n > expanded.len() {
        return None;
    }
    let mut mount = vec![0u16; 1024];
    unsafe { GetVolumePathNameW(PCWSTR(expanded.as_ptr()), &mut mount) }.ok()?;
    let mut name = vec![0u16; 64];
    unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(mount.as_ptr()), &mut name) }.ok()?;
    Some(from_wide_ptr(name.as_ptr()))
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
