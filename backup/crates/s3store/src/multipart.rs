//! Uploading a large file as one object with S3 multipart upload (restores
//! to AWS: a VHDX for VM Import, design: docs/design/cloud-restore.md).

use std::io::Read;
use std::path::Path;

use core_format::error::Result;

use crate::S3Backend;

/// Parts are at least 5 MiB (S3's minimum, except the last) and at most
/// 10,000 per upload.
pub const MIN_PART: u64 = 5 << 20;

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let i = xml.find(&open)? + open.len();
    let j = xml[i..].find(&format!("</{name}>"))? + i;
    Some(&xml[i..j])
}

impl S3Backend {
    /// `https://bucket.host/prefix/name` or `https://host/bucket/prefix/name`.
    pub fn object_url(&self, name: &str) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.host,
            self.path(&self.object(name))
        )
    }

    /// `s3://bucket/prefix/name`.
    pub fn s3_uri(&self, name: &str) -> String {
        format!("s3://{}/{}", self.cfg.bucket, self.object(name))
    }

    /// Upload `file` as object `name` in parts; an upload that fails is
    /// aborted, so no partial object or stray parts are left.
    pub fn upload_file(&self, name: &str, file: &Path, progress: &dyn Fn(u64, u64)) -> Result<()> {
        let obj = self.object(name);
        let total = std::fs::metadata(file)?.len();
        let part = MIN_PART
            .max(total.div_ceil(9_000))
            .next_multiple_of(1 << 20);
        let r = self.request("POST", &obj, &[("uploads", "")], &[], b"")?;
        if r.status != 200 {
            return Err(self.fail("start uploading", &obj, &r));
        }
        let body = String::from_utf8_lossy(&r.body).to_string();
        let id = tag(&body, "UploadId")
            .ok_or_else(|| crate::io(format!("start uploading {obj}: no upload ID in the reply")))?
            .to_string();
        let result = (|| -> Result<()> {
            let mut f = std::fs::File::open(file)?;
            let mut etags = Vec::new();
            let mut buf = vec![0u8; part as usize];
            let mut done = 0u64;
            let mut n = 1u32;
            loop {
                let mut got = 0;
                while got < buf.len() {
                    let k = f.read(&mut buf[got..])?;
                    if k == 0 {
                        break;
                    }
                    got += k;
                }
                if got == 0 && n > 1 {
                    break;
                }
                let num = n.to_string();
                let r = self.request(
                    "PUT",
                    &obj,
                    &[("partNumber", &num), ("uploadId", &id)],
                    &[("content-md5", crate::md5_b64(&buf[..got]))],
                    &buf[..got],
                )?;
                if r.status != 200 {
                    return Err(self.fail("upload a part of", &obj, &r));
                }
                let etag = r
                    .header("etag")
                    .ok_or_else(|| {
                        crate::io(format!("upload a part of {obj}: no ETag in the reply"))
                    })?
                    .to_string();
                etags.push((n, etag));
                done += got as u64;
                progress(done, total);
                n += 1;
                if (got as u64) < part {
                    break;
                }
            }
            let parts: String = etags
                .iter()
                .map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"))
                .collect();
            let xml = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
            let r = self.request("POST", &obj, &[("uploadId", &id)], &[], xml.as_bytes())?;
            // S3 can answer 200 with an error in the body.
            if r.status != 200 || String::from_utf8_lossy(&r.body).contains("<Error>") {
                return Err(self.fail("finish uploading", &obj, &r));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = self.request("DELETE", &obj, &[("uploadId", &id)], &[], b"");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_tags() {
        let x = "<InitiateMultipartUploadResult><Bucket>b</Bucket><UploadId>abc-123</UploadId></InitiateMultipartUploadResult>";
        assert_eq!(super::tag(x, "UploadId"), Some("abc-123"));
        assert_eq!(super::tag(x, "Key"), None);
    }
}
