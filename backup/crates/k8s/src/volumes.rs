//! Volume data (docs/design/kubernetes.md, stage 2).
//!
//! Backup: snapshot the claim with its CSI driver (VolumeSnapshot), create a
//! temporary claim from the snapshot, mount it read-only in a short-lived
//! reader pod running this program (`k8s volume-server`), and fetch its
//! files as a tar stream through the API server's pod proxy, so it works
//! from inside the cluster or outside without opening a port. A claim whose
//! driver cannot snapshot is read live (on the node of the pod using it) and
//! marked so. Restore: a writer pod mounts the restored claim and receives the
//! stream.

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{err, Client, Result};

pub const PORT: u16 = 8080;

/// A claim's data in a backup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub namespace: String,
    pub claim: String,
    /// Disk of the image holding the tar stream.
    pub disk: u32,
    /// "snapshot" (a CSI snapshot, consistent) or "live" (read while in use).
    pub method: String,
    pub bytes: u64,
}

/// A claim to back up and how.
#[derive(Debug, Clone)]
pub struct Claim {
    pub name: String,
    pub storage_class: String,
    pub size: String,
    pub snapshot_class: Option<String>,
    /// Node of a pod using it (a live read must run there).
    pub node: Option<String>,
}

fn sanitize(s: &str) -> String {
    let t: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    t.chars()
        .take(40)
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn suffix() -> String {
    format!(
        "{:08x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            ^ std::process::id()
    )
}

impl Client {
    /// The namespace's claims, with the snapshot class of their driver.
    pub fn claims(&self, ns: &str) -> Result<Vec<Claim>> {
        let pvcs = self.get(&format!("/api/v1/namespaces/{ns}/persistentvolumeclaims"))?;
        let classes = self
            .get("/apis/storage.k8s.io/v1/storageclasses")
            .unwrap_or(Value::Null);
        let snapclasses = self
            .get("/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses")
            .unwrap_or(Value::Null);
        let default_sc = classes["items"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| {
                c["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"]
                    == "true"
            })
            .and_then(|c| c["metadata"]["name"].as_str())
            .unwrap_or("")
            .to_string();
        let pods = self.get(&format!("/api/v1/namespaces/{ns}/pods"))?;
        let mut out = Vec::new();
        for p in pvcs["items"].as_array().into_iter().flatten() {
            let name = p["metadata"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let sc = p["spec"]["storageClassName"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| default_sc.clone());
            let driver = classes["items"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| c["metadata"]["name"].as_str() == Some(sc.as_str()))
                .and_then(|c| c["provisioner"].as_str())
                .unwrap_or("")
                .to_string();
            let mut candidates: Vec<&Value> = snapclasses["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|c| c["driver"].as_str() == Some(driver.as_str()))
                .collect();
            candidates.sort_by_key(|c| {
                c["metadata"]["annotations"]["snapshot.storage.kubernetes.io/is-default-class"]
                    != "true"
            });
            let node = pods["items"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|pod| {
                    pod["spec"]["volumes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|v| {
                            v["persistentVolumeClaim"]["claimName"].as_str() == Some(name.as_str())
                        })
                        && pod["spec"]["nodeName"].is_string()
                })
                .and_then(|pod| pod["spec"]["nodeName"].as_str())
                .map(str::to_string);
            out.push(Claim {
                size: p["status"]["capacity"]["storage"]
                    .as_str()
                    .or(p["spec"]["resources"]["requests"]["storage"].as_str())
                    .unwrap_or("1Gi")
                    .to_string(),
                snapshot_class: candidates
                    .first()
                    .and_then(|c| c["metadata"]["name"].as_str())
                    .map(str::to_string),
                storage_class: sc,
                name,
                node,
            });
        }
        Ok(out)
    }

    fn create(&self, path: &str, body: &Value) -> Result<()> {
        match self.call("POST", path, Some(body))? {
            (200..=299, _) => Ok(()),
            (s, v) => Err(err(format!(
                "POST {path}: {s} {}",
                v["message"].as_str().unwrap_or("")
            ))),
        }
    }

    fn delete(&self, path: &str) {
        let _ = self.call(
            "DELETE",
            path,
            Some(&json!({ "propagationPolicy": "Background", "gracePeriodSeconds": 0 })),
        );
    }

    fn wait<T>(
        &self,
        what: &str,
        timeout: Duration,
        mut f: impl FnMut() -> Result<Option<T>>,
    ) -> Result<T> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = f()? {
                return Ok(v);
            }
            if Instant::now() > deadline {
                return Err(err(format!(
                    "{what}: not ready after {} s",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// A pod running `volume-server` with `claim` at /data; waits until it answers.
    fn volume_pod(
        &self,
        ns: &str,
        name: &str,
        claim: &str,
        image: &str,
        mode: &str,
        node: Option<&str>,
    ) -> Result<()> {
        let mut spec = json!({
            "restartPolicy": "Never",
            "securityContext": { "runAsUser": 0 },
            "containers": [{
                "name": "fenrir",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/fenrir-backup", "k8s", "volume-server", "--dir", "/data", "--mode", mode],
                "ports": [{ "containerPort": PORT }],
                "volumeMounts": [{ "name": "data", "mountPath": "/data", "readOnly": mode == "read" }],
            }],
            "volumes": [{ "name": "data", "persistentVolumeClaim": { "claimName": claim, "readOnly": mode == "read" } }],
        });
        if let Some(n) = node {
            spec["nodeName"] = json!(n);
        }
        self.create(&format!("/api/v1/namespaces/{ns}/pods"), &json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": name, "labels": { "app.kubernetes.io/managed-by": "fenrir-backup" } },
            "spec": spec,
        }))?;
        let ready = format!("/api/v1/namespaces/{ns}/pods/{name}:{PORT}/proxy/ready");
        self.wait(&format!("pod {name}"), Duration::from_secs(600), || {
            let p = self.get(&format!("/api/v1/namespaces/{ns}/pods/{name}"))?;
            match p["status"]["phase"].as_str() {
                Some("Failed") | Some("Succeeded") => Err(err(format!(
                    "pod {name} stopped: {}",
                    p["status"]["containerStatuses"][0]["state"]
                ))),
                Some("Running") => {
                    Ok(matches!(self.call("GET", &ready, None), Ok((200, _))).then_some(()))
                }
                _ => Ok(None),
            }
        })
    }

    /// Back up one claim's files into `out` (a tar stream).
    pub fn backup_claim(
        &self,
        ns: &str,
        c: &Claim,
        image: &str,
        out: &mut impl Write,
    ) -> Result<(String, u64)> {
        let tag = format!("{}-{}", sanitize(&c.name), suffix());
        let snap = format!("fenrir-{tag}");
        let clone = format!("fenrir-read-{tag}");
        let pod = format!("fenrir-reader-{tag}");
        let cleanup = || {
            self.delete(&format!("/api/v1/namespaces/{ns}/pods/{pod}"));
            self.delete(&format!(
                "/api/v1/namespaces/{ns}/persistentvolumeclaims/{clone}"
            ));
            self.delete(&format!(
                "/apis/snapshot.storage.k8s.io/v1/namespaces/{ns}/volumesnapshots/{snap}"
            ));
        };
        let r = (|| -> Result<(String, u64)> {
            let (claim, method, node) = match &c.snapshot_class {
                Some(class) => {
                    self.create(&format!("/apis/snapshot.storage.k8s.io/v1/namespaces/{ns}/volumesnapshots"), &json!({
                        "apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
                        "metadata": { "name": snap, "labels": { "app.kubernetes.io/managed-by": "fenrir-backup" } },
                        "spec": { "volumeSnapshotClassName": class, "source": { "persistentVolumeClaimName": c.name } },
                    }))?;
                    self.wait(&format!("snapshot of {}", c.name), Duration::from_secs(600), || {
                        let s = self.get(&format!("/apis/snapshot.storage.k8s.io/v1/namespaces/{ns}/volumesnapshots/{snap}"))?;
                        if let Some(e) = s["status"]["error"]["message"].as_str() {
                            return Err(err(format!("snapshot of {}: {e}", c.name)));
                        }
                        Ok((s["status"]["readyToUse"] == true).then_some(()))
                    })?;
                    self.create(&format!("/api/v1/namespaces/{ns}/persistentvolumeclaims"), &json!({
                        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                        "metadata": { "name": clone, "labels": { "app.kubernetes.io/managed-by": "fenrir-backup" } },
                        "spec": {
                            "storageClassName": c.storage_class, "accessModes": ["ReadWriteOnce"],
                            "resources": { "requests": { "storage": c.size } },
                            "dataSource": { "name": snap, "kind": "VolumeSnapshot", "apiGroup": "snapshot.storage.k8s.io" },
                        },
                    }))?;
                    (clone.clone(), "snapshot", None)
                }
                None => (c.name.clone(), "live", c.node.as_deref()),
            };
            self.volume_pod(ns, &pod, &claim, image, "read", node)?;
            let path = format!("/api/v1/namespaces/{ns}/pods/{pod}:{PORT}/proxy/tar");
            let resp = self
                .agent
                .get(&format!("{}{path}", self.server))
                .set("Authorization", &format!("Bearer {}", self.token))
                .timeout(Duration::from_secs(24 * 3600))
                .call()
                .map_err(|e| err(format!("reading {}: {e}", c.name)))?;
            let n = std::io::copy(&mut resp.into_reader(), out)
                .map_err(|e| err(format!("reading {}: {e}", c.name)))?;
            Ok((method.to_string(), n))
        })();
        cleanup();
        r
    }

    /// Write a tar stream into a claim (which exists) through a writer pod.
    pub fn restore_claim(
        &self,
        ns: &str,
        claim: &str,
        image: &str,
        len: u64,
        data: impl Read + Send + 'static,
    ) -> Result<Value> {
        let pod = format!("fenrir-writer-{}-{}", sanitize(claim), suffix());
        let r = (|| -> Result<Value> {
            self.volume_pod(ns, &pod, claim, image, "write", None)?;
            let path = format!("/api/v1/namespaces/{ns}/pods/{pod}:{PORT}/proxy/tar");
            let resp = self
                .agent
                .put(&format!("{}{path}", self.server))
                .set("Authorization", &format!("Bearer {}", self.token))
                .set("Content-Type", "application/x-tar")
                .set("Content-Length", &len.to_string())
                .timeout(Duration::from_secs(24 * 3600))
                .send(data)
                .map_err(|e| err(format!("writing {claim}: {e}")))?;
            resp.into_json()
                .map_err(|e| err(format!("writing {claim}: {e}")))
        })();
        self.delete(&format!("/api/v1/namespaces/{ns}/pods/{pod}"));
        r
    }
}

// ---------------------------------------------------------------- in the pod

/// `k8s volume-server`: answer the backup or restore on PORT, then exit.
/// GET /ready; GET /tar (mode read): the folder as a tar stream; PUT /tar
/// (mode write): extract into the folder.
pub fn serve(dir: &Path, write: bool) -> std::io::Result<()> {
    let l = std::net::TcpListener::bind(("0.0.0.0", PORT))?;
    for s in l.incoming() {
        let mut s = s?;
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 16 << 10 {
            if s.read(&mut b)? == 0 {
                break;
            }
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head).to_string();
        let first = head.lines().next().unwrap_or("").to_string();
        let len: u64 = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let path = first.split_whitespace().nth(1).unwrap_or("");
        let done = match (
            first.split_whitespace().next().unwrap_or(""),
            path.split('?').next().unwrap_or(""),
        ) {
            ("GET", "/ready") => {
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )?;
                false
            }
            ("GET", "/tar") if !write => {
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nConnection: close\r\n\r\n")?;
                let mut w = std::io::BufWriter::with_capacity(1 << 20, &mut s);
                crate::tar::write_dir(dir, &mut w)?;
                w.flush()?;
                true
            }
            ("PUT", "/tar") if write => {
                let mut body = (&mut s).take(len);
                let r = crate::tar::extract(&mut body, dir)?;
                std::io::copy(&mut body, &mut std::io::sink())?;
                let j = serde_json::to_vec(&r).unwrap_or_default();
                s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", j.len()).as_bytes())?;
                s.write_all(&j)?;
                true
            }
            _ => {
                s.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
                false
            }
        };
        drop(s);
        if done {
            return Ok(());
        }
    }
    Ok(())
}
