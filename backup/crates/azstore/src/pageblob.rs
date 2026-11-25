//! Restoring a disk to Azure as a fixed VHD page blob, from which a managed
//! disk (and a VM) is created (design: docs/design/cloud-restore.md).
//!
//! The blob is created at the disk's size rounded up to a whole MiB plus the
//! 512-byte VHD footer. Only non-zero data is written (a page blob reads as
//! zeros where nothing was put), in pages of at most 4 MiB at 512-byte
//! boundaries; the footer goes last, so a blob without it was not finished.

use std::io;

use crate::AzureBackend;

const PAGE: u64 = 512;
const MAX_PUT: usize = 4 << 20;

impl AzureBackend {
    /// `https://account.blob.core.windows.net/container/prefix/name`.
    pub fn blob_url(&self, name: &str) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.host,
            self.path(&self.blob(name))
        )
    }

    /// Create an empty page blob of `size` bytes (a multiple of 512); fails
    /// if a blob of that name exists.
    pub fn create_page_blob(&self, name: &str, size: u64) -> core_format::error::Result<()> {
        let blob = self.blob(name);
        let h = vec![
            ("x-ms-blob-type", "PageBlob".to_string()),
            ("x-ms-blob-content-length", size.to_string()),
            ("if-none-match", "*".to_string()),
        ];
        let r = self.request("PUT", &blob, &[], &h, b"")?;
        match r.status {
            201 => Ok(()),
            409 | 412 => Err(crate::io(format!(
                "{blob} already exists in the container; choose another name"
            ))),
            _ => Err(self.fail("create", &blob, &r)),
        }
    }

    /// Write `data` (512-byte aligned, at most 4 MiB) at `offset`.
    pub fn put_pages(
        &self,
        name: &str,
        offset: u64,
        data: &[u8],
    ) -> core_format::error::Result<()> {
        let blob = self.blob(name);
        let h = vec![
            ("x-ms-page-write", "update".to_string()),
            (
                "x-ms-range",
                format!("bytes={}-{}", offset, offset + data.len() as u64 - 1),
            ),
        ];
        let r = self.request("PUT", &blob, &[("comp", "page")], &h, data)?;
        match r.status {
            201 => Ok(()),
            _ => Err(self.fail("write pages of", &blob, &r)),
        }
    }
}

/// A restore target writing a disk into a new fixed-VHD page blob.
pub struct PageBlobTarget {
    az: AzureBackend,
    name: String,
    size: u64,
    disk_size: u64,
}

impl PageBlobTarget {
    pub fn create(az: AzureBackend, name: &str, size: u64) -> io::Result<Self> {
        if size == 0 || size % PAGE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the disk size must be a multiple of 512",
            ));
        }
        let disk_size = vdisk::vhd::azure_size(size);
        az.create_page_blob(name, disk_size + PAGE)
            .map_err(io::Error::other)?;
        Ok(PageBlobTarget {
            az,
            name: name.into(),
            size,
            disk_size,
        })
    }

    pub fn url(&self) -> String {
        self.az.blob_url(&self.name)
    }

    /// The VHD's disk size (a whole number of MiB).
    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    /// Write the VHD footer: the blob is a valid fixed VHD after this.
    pub fn finish(self, unique_id: [u8; 16]) -> io::Result<String> {
        let f =
            vdisk::vhd::fixed_footer(self.disk_size, unique_id, core_format::timefmt::now_unix());
        self.az
            .put_pages(&self.name, self.disk_size, &f)
            .map_err(io::Error::other)?;
        Ok(self.url())
    }
}

impl engine::WriteTarget for PageBlobTarget {
    fn size(&self) -> u64 {
        self.size
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if offset % PAGE != 0 || data.len() as u64 % PAGE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "page blob writes must be 512-byte aligned",
            ));
        }
        if offset + data.len() as u64 > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write beyond the disk",
            ));
        }
        for (i, piece) in data.chunks(MAX_PUT).enumerate() {
            // Unwritten pages read as zeros: skip runs of zeros.
            let base = offset + (i * MAX_PUT) as u64;
            let mut start = None;
            for (k, page) in piece.chunks(PAGE as usize).enumerate() {
                let zero = page.iter().all(|&b| b == 0);
                match (zero, start) {
                    (false, None) => start = Some(k),
                    (true, Some(s)) => {
                        let (a, b) = (s * PAGE as usize, k * PAGE as usize);
                        self.az
                            .put_pages(&self.name, base + a as u64, &piece[a..b])
                            .map_err(io::Error::other)?;
                        start = None;
                    }
                    _ => {}
                }
            }
            if let Some(s) = start {
                let a = s * PAGE as usize;
                self.az
                    .put_pages(&self.name, base + a as u64, &piece[a..])
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        self.url()
    }
}
