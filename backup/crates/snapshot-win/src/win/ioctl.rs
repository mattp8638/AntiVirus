//! Device and filesystem control calls used for imaging.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use core_format::extent::{self, Extent};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_MORE_DATA, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_GET_RETRIEVAL_POINTERS, FSCTL_GET_VOLUME_BITMAP,
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_QUERY_PROPERTY,
};
use windows::Win32::System::IO::DeviceIoControl;

use crate::parse;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_with(path: &str, access: u32) -> io::Result<File> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|e| io::Error::other(format!("open {path}: {e}")))?;
    Ok(unsafe { File::from_raw_handle(h.0) })
}

/// Open a disk, volume or snapshot device read-only. Nothing in the
/// backup path opens a device for writing.
pub fn open_read(path: &str) -> io::Result<File> {
    open_with(path, GENERIC_READ.0)
}

/// Open a disk or volume for writing (restore only, after the caller's
/// checks and the administrator's confirmation).
pub fn open_rw(path: &str) -> io::Result<File> {
    open_with(
        path,
        GENERIC_READ.0 | windows::Win32::Foundation::GENERIC_WRITE.0,
    )
}

/// Open a file for metadata queries only (no data access).
pub fn open_attributes(path: &str) -> io::Result<File> {
    open_with(path, FILE_READ_ATTRIBUTES.0)
}

/// DeviceIoControl; returns (bytes returned, more data pending).
pub(crate) fn ioctl(
    f: &File,
    code: u32,
    input: &[u8],
    out: &mut [u8],
) -> io::Result<(usize, bool)> {
    let mut n = 0u32;
    let r = unsafe {
        DeviceIoControl(
            HANDLE(f.as_raw_handle()),
            code,
            (!input.is_empty()).then_some(input.as_ptr().cast()),
            input.len() as u32,
            Some(out.as_mut_ptr().cast()),
            out.len() as u32,
            Some(&mut n),
            None,
        )
    };
    match r {
        Ok(()) => Ok((n as usize, false)),
        Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => Ok((n as usize, true)),
        Err(e) => Err(io::Error::from_raw_os_error(e.code().0 & 0xFFFF)),
    }
}

/// (disk size in bytes, logical sector size).
pub fn disk_geometry(f: &File) -> io::Result<(u64, u32)> {
    let mut out = vec![0u8; 256];
    let (n, _) = ioctl(f, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut out)?;
    if n < 32 {
        return Err(io::Error::other("short DISK_GEOMETRY_EX"));
    }
    let bps = u32::from_le_bytes(out[20..24].try_into().unwrap());
    let size = i64::from_le_bytes(out[24..32].try_into().unwrap()) as u64;
    Ok((size, bps))
}

/// Length of a disk or volume device (GET_LENGTH_INFORMATION). On a
/// shadow-copy device this is the partition's length, which can exceed
/// what the device serves; see `ntfs_volume_length`.
pub fn device_length(f: &File) -> io::Result<u64> {
    let mut out = [0u8; 8];
    let (n, _) = ioctl(f, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut out)?;
    if n < 8 {
        return Err(io::Error::other("short GET_LENGTH_INFORMATION"));
    }
    Ok(i64::from_le_bytes(out).max(0) as u64)
}

fn storage_query(f: &File, property_id: u32) -> io::Result<Vec<u8>> {
    let mut q = [0u8; 12];
    q[0..4].copy_from_slice(&property_id.to_le_bytes()); // QueryType 0 = standard
    let mut out = vec![0u8; 4096];
    let (n, _) = ioctl(f, IOCTL_STORAGE_QUERY_PROPERTY, &q, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// (vendor + product, serial).
pub fn device_description(f: &File) -> (String, String) {
    match storage_query(f, 0) {
        Ok(b) if b.len() >= 28 => {
            let off = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            let vendor = parse::descriptor_string(&b, off(12));
            let product = parse::descriptor_string(&b, off(16));
            let serial = parse::descriptor_string(&b, off(24));
            (format!("{vendor} {product}").trim().to_string(), serial)
        }
        _ => (String::new(), String::new()),
    }
}

pub fn physical_sector_size(f: &File) -> Option<u32> {
    let b = storage_query(f, 6).ok()?; // StorageAccessAlignmentProperty
    (b.len() >= 24).then(|| u32::from_le_bytes(b[20..24].try_into().unwrap()))
}

pub fn volume_disk_extents(f: &File) -> io::Result<Vec<(u32, u64, u64)>> {
    let mut out = vec![0u8; 8 + 24 * 32];
    let (n, more) = ioctl(f, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], &mut out)?;
    if more {
        return Err(io::Error::other("volume spans more than 32 extents"));
    }
    parse::parse_disk_extents(&out[..n])
        .ok_or_else(|| io::Error::other("malformed VOLUME_DISK_EXTENTS"))
}

/// NTFS cluster size, or None if the volume is not NTFS.
pub fn ntfs_cluster_size(f: &File) -> Option<u64> {
    let mut out = vec![0u8; 512];
    let (n, _) = ioctl(f, FSCTL_GET_NTFS_VOLUME_DATA, &[], &mut out).ok()?;
    (n >= 48)
        .then(|| u32::from_le_bytes(out[44..48].try_into().unwrap()) as u64)
        .filter(|c| *c > 0)
}

/// Bytes an NTFS volume device can serve (whole clusters; see
/// `parse::ntfs_readable_bytes`). Smaller than the partition, while
/// GET_LENGTH_INFORMATION on a shadow-copy device reports the partition
/// length; reads past this size fail.
pub fn ntfs_volume_length(f: &File) -> Option<u64> {
    let mut out = vec![0u8; 512];
    let (n, _) = ioctl(f, FSCTL_GET_NTFS_VOLUME_DATA, &[], &mut out).ok()?;
    parse::ntfs_readable_bytes(&out[..n])
}

/// Used clusters of a volume as absolute disk extents.
pub fn volume_bitmap(f: &File, cluster: u64, volume_offset: u64) -> io::Result<Vec<Extent>> {
    let mut out = vec![0u8; 16 + 1024 * 1024];
    let mut lcn: i64 = 0;
    let mut used = Vec::new();
    loop {
        let (n, more) = ioctl(f, FSCTL_GET_VOLUME_BITMAP, &lcn.to_le_bytes(), &mut out)?;
        let (start, total) = parse::parse_bitmap_header(&out[..n])
            .ok_or_else(|| io::Error::other("short VOLUME_BITMAP_BUFFER"))?;
        // BitmapSize counts clusters from `start` to the end of the volume;
        // this call returned as many of them as fit in the buffer.
        let clusters = (n.saturating_sub(16) as u64 * 8).min(total.max(0) as u64);
        used.extend(parse::bitmap_to_extents(
            &out[16..n],
            start as u64,
            clusters,
            cluster,
            volume_offset,
        ));
        if !more || clusters == 0 {
            break;
        }
        lcn = start + clusters as i64;
    }
    Ok(extent::normalize(used))
}

/// On-disk extents of a file (absolute disk offsets).
pub fn file_extents(f: &File, cluster: u64, volume_offset: u64) -> io::Result<Vec<Extent>> {
    let mut out = vec![0u8; 64 * 1024];
    let mut vcn: i64 = 0;
    let mut v = Vec::new();
    loop {
        let (n, more) = ioctl(
            f,
            FSCTL_GET_RETRIEVAL_POINTERS,
            &vcn.to_le_bytes(),
            &mut out,
        )?;
        let (start, runs) = parse::parse_retrieval_pointers(&out, n)
            .ok_or_else(|| io::Error::other("short RETRIEVAL_POINTERS_BUFFER"))?;
        v.extend(parse::runs_to_extents(start, &runs, cluster, volume_offset));
        match (more, runs.last()) {
            (true, Some(&(next, _))) => vcn = next,
            _ => break,
        }
    }
    Ok(extent::normalize(v))
}
