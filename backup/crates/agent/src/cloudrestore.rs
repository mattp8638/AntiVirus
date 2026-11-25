//! Restoring to the cloud (design: docs/design/cloud-restore.md).
//!
//! * Azure: each disk as a fixed VHD page blob in a storage container
//!   (only non-zero data is written), then a managed disk and a VM are made
//!   from it with the Azure CLI commands the job returns.
//! * AWS: each disk as a VHDX written to a staging folder here, uploaded to
//!   an S3 bucket in parts and removed; VM Import turns it into an AMI with
//!   the AWS CLI command the job returns.

use std::path::Path;

use anyhow::{anyhow, bail};
use core_format::{ManifestBody, Repository};
use engine::RestoreOptions;
use protocol::seal::Sealed;
use protocol::{JobState, JobUpdate};
use serde_json::json;

use crate::jobs::{finished, Ctx, Reporter};

/// Names of blobs and objects made from `name`: letters, digits, `.`, `-`, `_`.
pub fn check_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        bail!("names for cloud disks are 1 to 64 letters, digits, dots, hyphens or underscores");
    }
    Ok(())
}

fn selected<'a>(m: &'a ManifestBody, disks: &[u32]) -> Vec<&'a core_format::manifest::DiskImage> {
    m.disks
        .iter()
        .filter(|d| disks.is_empty() || disks.contains(&d.index))
        .collect()
}

fn os_type(m: &ManifestBody) -> &'static str {
    if m.os.family.eq_ignore_ascii_case("linux") {
        "Linux"
    } else {
        "Windows"
    }
}

fn uefi(m: &ManifestBody) -> bool {
    m.disks
        .first()
        .and_then(|d| crate::restore::image_firmware(m, d))
        .map(|f| f == "uefi")
        .unwrap_or(false)
}

/// Azure CLI commands that make managed disks and a VM from the blobs.
pub fn azure_commands(uefi: bool, os: &str, name: &str, account: &str, urls: &[String]) -> String {
    let gen = if uefi { "V2" } else { "V1" };
    let mut s = format!(
        "# Run in Azure Cloud Shell or with the Azure CLI. Set RG to the storage account's resource group;\n\
         # the disks are created in the storage account's region.\n\
         RG=<resource-group>\n\
         SA=$(az storage account show -n {account} -g $RG --query id -o tsv)\n"
    );
    for (i, u) in urls.iter().enumerate() {
        let extra = if i == 0 {
            format!(" --os-type {os} --hyper-v-generation {gen}")
        } else {
            String::new()
        };
        s += &format!("az disk create -g $RG -n {name}-disk{i} --source {u} --source-storage-account-id $SA{extra}\n");
    }
    let data: Vec<String> = (1..urls.len()).map(|i| format!("{name}-disk{i}")).collect();
    s += &format!(
        "az vm create -g $RG -n {name} --attach-os-disk {name}-disk0 --os-type {}{} --size Standard_D2s_v5{}\n",
        os.to_lowercase(),
        if data.is_empty() { String::new() } else { format!(" --attach-data-disks {}", data.join(" ")) },
        if gen == "V2" { " --security-type Standard" } else { "" },
    );
    s
}

/// AWS CLI command that imports the uploaded disks as an AMI.
pub fn aws_commands(uefi: bool, name: &str, bucket: &str, keys: &[String], region: &str) -> String {
    let containers: Vec<String> = keys
        .iter()
        .map(|k| format!("\"Format=VHDX,UserBucket={{S3Bucket={bucket},S3Key={k}}}\""))
        .collect();
    format!(
        "# Needs the vmimport service role (AWS VM Import/Export documentation). Then:\n\
         aws ec2 import-image --region {region} --description \"{name} restored by Fenrir\"{} --disk-containers {}\n\
         # Follow it with: aws ec2 describe-import-image-tasks --region {region}\n",
        if uefi { " --boot-mode uefi" } else { "" },
        containers.join(" ")
    )
}

pub fn azure(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    (location, endpoint, name): (&str, &str, &str),
    sealed: &Sealed,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    check_name(name)?;
    let creds = crate::share::open_credentials(ctx.key, sealed)?;
    let (container, prefix) = azstore::parse_url(location)
        .ok_or_else(|| anyhow!("{location} is not an azure://container/prefix location"))?;
    let endpoint = if endpoint.trim().is_empty() {
        format!("https://{}.blob.core.windows.net", creds.username)
    } else {
        endpoint.trim().to_string()
    };
    let make = || {
        azstore::AzureBackend::new(azstore::AzureConfig {
            endpoint: endpoint.clone(),
            account: creds.username.clone(),
            container: container.clone(),
            prefix: prefix.clone(),
            credential: azstore::credential_from(&creds.password),
            lock: None,
            access_tier: None,
        })
    };
    let mut urls = Vec::new();
    let chosen = selected(m, disks);
    let total: u64 = chosen.iter().map(|d| d.size).sum();
    let mut base = 0u64;
    for d in chosen {
        let blob = format!("{name}-disk{}.vhd", d.index);
        let t = azstore::pageblob::PageBlobTarget::create(make()?, &blob, d.size)?;
        let label = format!("disk {} → {blob}", d.index);
        let cb = |done: u64, _t: u64| rep.progress("uploading", base + done, total, &label);
        engine::restore_disk(
            repo,
            m,
            d.index,
            &t,
            &RestoreOptions {
                workers: 8,
                zero_fill: false,
                fit: false,
                grow: false,
            },
            &ctx.ctl,
            &cb,
        )?;
        urls.push(t.finish(*uuid::Uuid::new_v4().as_bytes())?);
        base += d.size;
    }
    let mut u = finished(JobState::Succeeded);
    u.result = Some(json!({
        "cloud": "azure", "blobs": urls, "commands": azure_commands(uefi(m), os_type(m), name, &creds.username, &urls),
    }));
    if os_type(m) == "Windows" && m.vm.is_none() {
        u.state = JobState::Warning;
        u.warnings.push("This Windows system comes from a physical machine: if the Azure VM does not start, restore it with the recovery media onto a Hyper-V VM first (it prepares Windows for virtual hardware), then restore that.".into());
    }
    Ok(u)
}

pub fn aws(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    (location, endpoint, region, name, staging): (&str, &str, &str, &str, &str),
    sealed: &Sealed,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    check_name(name)?;
    let creds = crate::share::open_credentials(ctx.key, sealed)?;
    let (bucket, prefix) = s3store::parse_url(location)
        .ok_or_else(|| anyhow!("{location} is not an s3://bucket/prefix location"))?;
    let region = if region.trim().is_empty() {
        "us-east-1"
    } else {
        region.trim()
    };
    let endpoint = if endpoint.trim().is_empty() {
        format!("https://s3.{region}.amazonaws.com")
    } else {
        endpoint.trim().to_string()
    };
    let s3 = s3store::S3Backend::new(s3store::S3Config {
        endpoint: endpoint.clone(),
        region: region.to_string(),
        bucket: bucket.clone(),
        prefix,
        path_style: !endpoint.contains("amazonaws.com"),
        access_key: creds.username,
        secret_key: creds.password,
        lock: None,
        storage_class: None,
    })?;
    let dir = Path::new(staging.trim()).join(format!("fenrir-{name}-{}", crate::restore::stamp(m)));
    if !Path::new(staging.trim()).is_absolute() {
        bail!("the staging folder must be a full path on this machine");
    }
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let files =
        crate::restore::write_disk_files(ctx, repo, m, disks, &dir, vdisk::Format::Vhdx, rep)?;
    let mut keys = Vec::new();
    for (i, path) in &files {
        let object = format!("{name}-disk{i}.vhdx");
        let label = format!("disk {i} → {}", s3.s3_uri(&object));
        s3.upload_file(&object, path, &|done, total| {
            rep.progress("uploading", done, total, &label)
        })?;
        let _ = std::fs::remove_file(path);
        keys.push(
            s3.s3_uri(&object)
                .trim_start_matches(&format!("s3://{bucket}/"))
                .to_string(),
        );
    }
    let mut u = finished(JobState::Succeeded);
    u.result = Some(json!({
        "cloud": "aws", "objects": keys.iter().map(|k| format!("s3://{bucket}/{k}")).collect::<Vec<_>>(),
        "commands": aws_commands(uefi(m), name, &bucket, &keys, region),
    }));
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_commands() {
        assert!(check_name("pm-acer_2026.11").is_ok());
        assert!(check_name("x; rm -rf /").is_err() && check_name("").is_err());
        let az = azure_commands(
            true,
            "Windows",
            "pm-acer",
            "fenrirdr",
            &[
                "https://a/b/pm-acer-disk0.vhd".into(),
                "https://a/b/pm-acer-disk1.vhd".into(),
            ],
        );
        assert!(az.contains("az disk create -g $RG -n pm-acer-disk0 --source https://a/b/pm-acer-disk0.vhd --source-storage-account-id $SA --os-type Windows --hyper-v-generation V2"));
        assert!(az.contains(
            "--attach-os-disk pm-acer-disk0 --os-type windows --attach-data-disks pm-acer-disk1"
        ));
        let aws = aws_commands(
            true,
            "web",
            "vm-import",
            &["dr/web-disk0.vhdx".into()],
            "eu-west-2",
        );
        assert!(aws.contains(r#"--boot-mode uefi --disk-containers "Format=VHDX,UserBucket={S3Bucket=vm-import,S3Key=dr/web-disk0.vhdx}""#));
        assert!(aws.contains("--region eu-west-2"));
    }
}
