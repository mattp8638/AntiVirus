//! The exported objects as one stream, stored in a repository like a disk:
//! a 512-byte header (magic, length of the JSON), the JSON, zero padding to
//! a whole number of 4 KiB blocks.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Resource;

pub const MAGIC: &[u8; 16] = b"FENRIR-K8S-V1\0\0\0";
const HEADER: usize = 512;
const BLOCK: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Namespace {
    pub name: String,
    #[serde(default)]
    pub labels: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Object {
    pub namespace: String,
    pub resource: Resource,
    pub object: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Archive {
    pub version: u32,
    pub namespaces: Vec<Namespace>,
    pub objects: Vec<Object>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Claims whose data is in the image (stage 2).
    #[serde(default)]
    pub volumes: Vec<crate::volumes::VolumeRecord>,
}

impl Archive {
    /// The stream to store (a multiple of 4 KiB).
    pub fn to_disk(&self) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let mut out = vec![0u8; HEADER];
        out[..16].copy_from_slice(MAGIC);
        out[16..24].copy_from_slice(&(json.len() as u64).to_le_bytes());
        out.extend(json);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        Ok(out)
    }

    pub fn from_disk(d: &[u8]) -> Result<Archive, String> {
        if d.len() < HEADER || &d[..16] != MAGIC {
            return Err("not a Fenrir Kubernetes backup".into());
        }
        let n = u64::from_le_bytes(d[16..24].try_into().expect("8 bytes")) as usize;
        let body = d
            .get(HEADER..HEADER + n)
            .ok_or("the Kubernetes backup is cut short")?;
        serde_json::from_slice(body)
            .map_err(|e| format!("the Kubernetes backup cannot be read: {e}"))
    }

    /// Objects per kind, for reports.
    pub fn summary(&self) -> Vec<(String, usize)> {
        let mut m: std::collections::BTreeMap<String, usize> = Default::default();
        for o in &self.objects {
            *m.entry(o.resource.kind.clone()).or_default() += 1;
        }
        m.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_a_disk_stream() {
        let a = Archive {
            version: 1,
            namespaces: vec![Namespace {
                name: "shop".into(),
                labels: serde_json::json!({ "team": "web" }),
            }],
            objects: vec![Object {
                namespace: "shop".into(),
                resource: Resource {
                    group: "apps".into(),
                    version: "v1".into(),
                    plural: "deployments".into(),
                    kind: "Deployment".into(),
                    namespaced: true,
                },
                object: serde_json::json!({ "metadata": { "name": "web" } }),
            }],
            warnings: vec![],
            volumes: vec![],
        };
        let d = a.to_disk().unwrap();
        assert_eq!(d.len() % 4096, 0);
        assert_eq!(Archive::from_disk(&d).unwrap(), a);
        assert!(Archive::from_disk(&d[..600]).is_err());
        assert!(Archive::from_disk(&vec![0u8; 4096]).is_err());
        assert_eq!(a.summary(), vec![("Deployment".into(), 1)]);
    }
}
