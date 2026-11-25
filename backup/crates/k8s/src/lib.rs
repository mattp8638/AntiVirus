//! Kubernetes backup (docs/design/kubernetes.md): the API objects of chosen
//! namespaces, exported as an archive that is stored in a repository like a
//! disk image, and created again on restore (in the same or another
//! namespace, on this cluster or another).
//!
//! Talks to the API server over HTTPS with a bearer token: in a pod, its
//! service account (`/var/run/secrets/kubernetes.io/serviceaccount`); outside,
//! an address, a token and the cluster's CA certificate.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod archive;
pub mod repo;
pub mod tar;
pub mod volumes;

const SA: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}

/// How to reach the API server.
#[derive(Debug, Clone, Default)]
pub struct Connect {
    /// `https://host:port`; empty: in-cluster.
    pub server: String,
    pub token: String,
    /// PEM; empty: the system's roots (in-cluster: the service account CA).
    pub ca_pem: String,
}

impl Connect {
    /// The pod's service account (KUBERNETES_SERVICE_HOST/PORT).
    pub fn in_cluster() -> Result<Connect> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| err("not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set): give the API server, a token and the CA"))?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let read = |f: &str| {
            std::fs::read_to_string(format!("{SA}/{f}")).map_err(|e| err(format!("{SA}/{f}: {e}")))
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Connect {
            server: format!("https://{host}:{port}"),
            token: read("token")?.trim().to_string(),
            ca_pem: read("ca.crt")?,
        })
    }
}

pub struct Client {
    pub(crate) agent: ureq::Agent,
    pub(crate) server: String,
    pub(crate) token: String,
}

/// One API resource type: where its objects are listed and created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// "" for the core group.
    pub group: String,
    pub version: String,
    /// Plural name used in URLs, e.g. "deployments".
    pub plural: String,
    pub kind: String,
    pub namespaced: bool,
}

impl Resource {
    pub fn api_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }
    fn base(&self) -> String {
        if self.group.is_empty() {
            format!("/api/{}", self.version)
        } else {
            format!("/apis/{}/{}", self.group, self.version)
        }
    }
    pub fn path(&self, namespace: &str) -> String {
        format!("{}/namespaces/{namespace}/{}", self.base(), self.plural)
    }
}

impl Client {
    pub fn new(c: &Connect) -> Result<Client> {
        if !c.server.starts_with("https://") {
            return Err(err("the API server address must start with https://"));
        }
        let mut roots = rustls::RootCertStore::empty();
        if c.ca_pem.trim().is_empty() {
            return Err(err(
                "the cluster's CA certificate is needed to check the API server",
            ));
        }
        use rustls_pki_types::pem::PemObject;
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(c.ca_pem.as_bytes()) {
            let cert = cert.map_err(|e| err(format!("CA certificate: {e:?}")))?;
            roots
                .add(cert)
                .map_err(|e| err(format!("CA certificate: {e}")))?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| err(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(tls))
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build();
        Ok(Client {
            agent,
            server: c.server.trim_end_matches('/').to_string(),
            token: c.token.clone(),
        })
    }

    pub(crate) fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let req = self
            .agent
            .request(method, &format!("{}{path}", self.server))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/json");
        let r = match body {
            Some(b) => req
                .set("Content-Type", "application/json")
                .send_string(&b.to_string()),
            None => req.call(),
        };
        let resp = match r {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => return Err(err(format!("{method} {path}: {t}"))),
        };
        let status = resp.status();
        let v: Value = resp.into_json().unwrap_or(Value::Null);
        Ok((status, v))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        match self.call("GET", path, None)? {
            (200, v) => Ok(v),
            (s, v) => Err(err(format!(
                "GET {path}: {s} {}",
                v["message"].as_str().unwrap_or("")
            ))),
        }
    }

    /// Every resource type that is namespaced and can be listed and created.
    pub fn resources(&self) -> Result<Vec<Resource>> {
        let mut groups: Vec<(String, String)> = vec![(String::new(), "v1".into())];
        for g in self.get("/apis")?["groups"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            if let (Some(name), Some(v)) = (
                g["name"].as_str(),
                g["preferredVersion"]["version"].as_str(),
            ) {
                groups.push((name.to_string(), v.to_string()));
            }
        }
        let mut out = Vec::new();
        for (group, version) in groups {
            let path = if group.is_empty() {
                "/api/v1".to_string()
            } else {
                format!("/apis/{group}/{version}")
            };
            // A group whose API service is down must not stop the backup.
            let Ok(list) = self.get(&path) else { continue };
            for r in list["resources"].as_array().cloned().unwrap_or_default() {
                let name = r["name"].as_str().unwrap_or_default();
                let verbs: Vec<&str> = r["verbs"]
                    .as_array()
                    .map(|v| v.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if name.contains('/')
                    || !r["namespaced"].as_bool().unwrap_or(false)
                    || !verbs.contains(&"list")
                    || !verbs.contains(&"create")
                {
                    continue;
                }
                out.push(Resource {
                    group: group.clone(),
                    version: version.clone(),
                    plural: name.to_string(),
                    kind: r["kind"].as_str().unwrap_or_default().to_string(),
                    namespaced: true,
                });
            }
        }
        Ok(out)
    }

    pub fn namespace_exists(&self, ns: &str) -> Result<bool> {
        Ok(self
            .call("GET", &format!("/api/v1/namespaces/{ns}"), None)?
            .0
            == 200)
    }

    pub fn create_namespace(&self, ns: &str, labels: &Value) -> Result<()> {
        let body = json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": ns, "labels": labels } });
        match self.call("POST", "/api/v1/namespaces", Some(&body))? {
            (200..=299, _) | (409, _) => Ok(()),
            (s, v) => Err(err(format!(
                "creating namespace {ns}: {s} {}",
                v["message"].as_str().unwrap_or("")
            ))),
        }
    }

    /// Create (or with `replace`, replace) one object; Ok(false) when it
    /// already existed and was left alone.
    pub fn apply(&self, r: &Resource, ns: &str, obj: &Value, replace: bool) -> Result<bool> {
        let name = obj["metadata"]["name"].as_str().unwrap_or_default();
        match self.call("POST", &r.path(ns), Some(obj))? {
            (200..=299, _) => Ok(true),
            (409, _) if replace => {
                let (s, cur) = self.call("GET", &format!("{}/{name}", r.path(ns)), None)?;
                if s != 200 {
                    return Err(err(format!(
                        "{} {name}: exists but cannot be read ({s})",
                        r.kind
                    )));
                }
                let mut o = obj.clone();
                o["metadata"]["resourceVersion"] = cur["metadata"]["resourceVersion"].clone();
                match self.call("PUT", &format!("{}/{name}", r.path(ns)), Some(&o))? {
                    (200..=299, _) => Ok(true),
                    (s, v) => Err(err(format!(
                        "{} {name}: {s} {}",
                        r.kind,
                        v["message"].as_str().unwrap_or("")
                    ))),
                }
            }
            (409, _) => Ok(false),
            (s, v) => Err(err(format!(
                "{} {name}: {s} {}",
                r.kind,
                v["message"].as_str().unwrap_or("")
            ))),
        }
    }
}

// ---------------------------------------------------------------- what is backed up

/// Kinds left out: recreated by controllers or by Kubernetes itself, or
/// describing the past.
const SKIP: &[(&str, &str)] = &[
    ("", "events"),
    ("events.k8s.io", "events"),
    ("", "endpoints"),
    ("discovery.k8s.io", "endpointslices"),
    ("coordination.k8s.io", "leases"),
    ("apps", "controllerrevisions"),
    ("metrics.k8s.io", "pods"),
    ("authorization.k8s.io", "localsubjectaccessreviews"),
    ("", "bindings"),
];

/// Order of creation on restore: what others refer to first.
pub fn restore_rank(kind: &str) -> u8 {
    match kind {
        "ServiceAccount" => 0,
        "Secret" | "ConfigMap" => 1,
        "LimitRange" | "ResourceQuota" | "NetworkPolicy" => 2,
        "PersistentVolumeClaim" => 3,
        "Role" | "RoleBinding" => 4,
        "Service" => 5,
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" | "CronJob" | "Pod" => 7,
        "HorizontalPodAutoscaler" | "PodDisruptionBudget" | "Ingress" => 8,
        _ => 6,
    }
}

/// Should this object be backed up? Objects owned by another (a Deployment's
/// ReplicaSets and their Pods, a CronJob's Jobs) are recreated by it.
pub fn wanted(r: &Resource, obj: &Value) -> bool {
    if SKIP.iter().any(|(g, p)| *g == r.group && *p == r.plural) {
        return false;
    }
    let meta = &obj["metadata"];
    if meta["ownerReferences"]
        .as_array()
        .is_some_and(|o| !o.is_empty())
    {
        return false;
    }
    let name = meta["name"].as_str().unwrap_or_default();
    match r.kind.as_str() {
        "ConfigMap" => name != "kube-root-ca.crt",
        "ServiceAccount" => name != "default",
        "Secret" => obj["type"].as_str() != Some("kubernetes.io/service-account-token"),
        _ => true,
    }
}

/// The object as it can be created again: no server-assigned identity, no
/// status, nothing bound to this cluster's allocation (Service IPs, the
/// PersistentVolume a claim was bound to).
pub fn clean(kind: &str, obj: &Value) -> Value {
    let mut o = obj.clone();
    if let Some(m) = o["metadata"].as_object_mut() {
        for k in [
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "managedFields",
            "selfLink",
            "ownerReferences",
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
        ] {
            m.remove(k);
        }
        if let Some(a) = m.get_mut("annotations").and_then(Value::as_object_mut) {
            a.retain(|k, _| {
                !k.starts_with("pv.kubernetes.io/")
                    && k != "kubectl.kubernetes.io/last-applied-configuration"
                    && !k.starts_with("deployment.kubernetes.io/")
            });
        }
    }
    if let Some(m) = o.as_object_mut() {
        m.remove("status");
    }
    match kind {
        "Service" => {
            if let Some(spec) = o["spec"].as_object_mut() {
                if spec.get("clusterIP").and_then(Value::as_str) != Some("None") {
                    spec.remove("clusterIP");
                    spec.remove("clusterIPs");
                }
                spec.remove("healthCheckNodePort");
                if let Some(ports) = spec.get_mut("ports").and_then(Value::as_array_mut) {
                    for p in ports {
                        if let Some(p) = p.as_object_mut() {
                            p.remove("nodePort");
                        }
                    }
                }
            }
        }
        "PersistentVolumeClaim" => {
            if let Some(spec) = o["spec"].as_object_mut() {
                spec.remove("volumeName");
            }
        }
        "Job" => {
            // Its selector and pod labels are generated; Kubernetes makes new ones.
            if let Some(spec) = o["spec"].as_object_mut() {
                spec.remove("selector");
            }
            if let Some(l) = o["spec"]["template"]["metadata"]["labels"].as_object_mut() {
                l.retain(|k, _| {
                    k != "controller-uid"
                        && k != "batch.kubernetes.io/controller-uid"
                        && k != "job-name"
                        && k != "batch.kubernetes.io/job-name"
                });
            }
        }
        _ => {}
    }
    o
}

/// Export the objects of `namespaces`.
pub fn export(
    c: &Client,
    namespaces: &[String],
    progress: &dyn Fn(&str),
) -> Result<archive::Archive> {
    let resources = c.resources()?;
    let mut a = archive::Archive {
        version: 1,
        namespaces: vec![],
        objects: vec![],
        warnings: vec![],
        volumes: vec![],
    };
    for ns in namespaces {
        let meta = c
            .get(&format!("/api/v1/namespaces/{ns}"))
            .map_err(|e| err(format!("namespace {ns}: {e}")))?;
        a.namespaces.push(archive::Namespace {
            name: ns.clone(),
            labels: meta["metadata"]["labels"].clone(),
        });
        for r in &resources {
            progress(&format!("{ns}: {}", r.plural));
            let list = match c.get(&r.path(ns)) {
                Ok(l) => l,
                Err(e) => {
                    a.warnings.push(format!("{ns}/{}: {e}", r.plural));
                    continue;
                }
            };
            for item in list["items"].as_array().cloned().unwrap_or_default() {
                if !wanted(r, &item) {
                    continue;
                }
                let mut obj = clean(&r.kind, &item);
                obj["apiVersion"] = json!(r.api_version());
                obj["kind"] = json!(r.kind);
                a.objects.push(archive::Object {
                    namespace: ns.clone(),
                    resource: r.clone(),
                    object: obj,
                });
            }
        }
    }
    Ok(a)
}

/// What a restore did.
#[derive(Debug, Default, Serialize)]
pub struct RestoreReport {
    /// Claims whose data was written back.
    pub volumes: Vec<Value>,
    pub created: usize,
    pub existing: usize,
    pub failed: Vec<String>,
    pub namespaces: Vec<String>,
}

/// Create the archive's objects again. `map`: namespace renames (old, new);
/// `only`: restore only these (original) namespaces (empty: all).
pub fn restore(
    c: &Client,
    a: &archive::Archive,
    only: &[String],
    map: &[(String, String)],
    replace: bool,
) -> Result<RestoreReport> {
    restore_with(c, a, only, map, replace, &mut |_| Ok(()))
}

/// As `restore`, calling `after_claims` once the claims exist and before
/// anything that would use them is created (to put their data back).
pub fn restore_with(
    c: &Client,
    a: &archive::Archive,
    only: &[String],
    map: &[(String, String)],
    replace: bool,
    after_claims: &mut dyn FnMut(&mut RestoreReport) -> Result<()>,
) -> Result<RestoreReport> {
    let target = |ns: &str| {
        map.iter()
            .find(|(o, _)| o == ns)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| ns.to_string())
    };
    let pick = |ns: &str| only.is_empty() || only.iter().any(|o| o == ns);
    let mut rep = RestoreReport::default();
    for n in a.namespaces.iter().filter(|n| pick(&n.name)) {
        let t = target(&n.name);
        c.create_namespace(&t, &n.labels)?;
        rep.namespaces.push(t);
    }
    let mut objs: Vec<&archive::Object> = a.objects.iter().filter(|o| pick(&o.namespace)).collect();
    objs.sort_by_key(|o| restore_rank(&o.resource.kind));
    let claims_rank = restore_rank("PersistentVolumeClaim");
    let mut hooked = false;
    for o in objs {
        if !hooked && restore_rank(&o.resource.kind) > claims_rank {
            hooked = true;
            after_claims(&mut rep)?;
        }
        let t = target(&o.namespace);
        let mut obj = o.object.clone();
        obj["metadata"]["namespace"] = json!(t);
        // A RoleBinding naming a ServiceAccount of the renamed namespace follows it.
        if let Some(subjects) = obj["subjects"].as_array_mut() {
            for s in subjects {
                if s["kind"] == "ServiceAccount"
                    && s["namespace"].as_str() == Some(o.namespace.as_str())
                {
                    s["namespace"] = json!(t);
                }
            }
        }
        match c.apply(&o.resource, &t, &obj, replace) {
            Ok(true) => rep.created += 1,
            Ok(false) => rep.existing += 1,
            Err(e) => rep.failed.push(e.0),
        }
    }
    if !hooked {
        after_claims(&mut rep)?;
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(group: &str, plural: &str, kind: &str) -> Resource {
        Resource {
            group: group.into(),
            version: "v1".into(),
            plural: plural.into(),
            kind: kind.into(),
            namespaced: true,
        }
    }

    #[test]
    fn owned_and_generated_objects_are_left_out() {
        let rs = res("apps", "replicasets", "ReplicaSet");
        assert!(!wanted(
            &rs,
            &json!({ "metadata": { "name": "web-5d9", "ownerReferences": [{ "kind": "Deployment" }] } })
        ));
        assert!(wanted(
            &res("apps", "deployments", "Deployment"),
            &json!({ "metadata": { "name": "web" } })
        ));
        assert!(!wanted(
            &res("", "configmaps", "ConfigMap"),
            &json!({ "metadata": { "name": "kube-root-ca.crt" } })
        ));
        assert!(!wanted(
            &res("", "secrets", "Secret"),
            &json!({ "metadata": { "name": "t" }, "type": "kubernetes.io/service-account-token" })
        ));
        assert!(wanted(
            &res("", "secrets", "Secret"),
            &json!({ "metadata": { "name": "db" }, "type": "Opaque" })
        ));
        assert!(!wanted(
            &res("", "events", "Event"),
            &json!({ "metadata": { "name": "e" } })
        ));
    }

    #[test]
    fn objects_are_cleaned_for_creating_again() {
        let svc = json!({ "metadata": { "name": "web", "uid": "u", "resourceVersion": "9", "managedFields": [],
                          "annotations": { "kubectl.kubernetes.io/last-applied-configuration": "{}", "keep": "1" } },
                          "spec": { "clusterIP": "10.0.0.7", "clusterIPs": ["10.0.0.7"], "ports": [{ "port": 80, "nodePort": 30080 }] },
                          "status": { "loadBalancer": {} } });
        let c = clean("Service", &svc);
        assert!(
            c["metadata"].get("uid").is_none()
                && c["metadata"].get("resourceVersion").is_none()
                && c.get("status").is_none()
        );
        assert!(
            c["spec"].get("clusterIP").is_none() && c["spec"]["ports"][0].get("nodePort").is_none()
        );
        assert_eq!(c["metadata"]["annotations"], json!({ "keep": "1" }));
        let headless = clean(
            "Service",
            &json!({ "metadata": {}, "spec": { "clusterIP": "None" } }),
        );
        assert_eq!(
            headless["spec"]["clusterIP"], "None",
            "a headless service stays headless"
        );
        let pvc = clean(
            "PersistentVolumeClaim",
            &json!({ "metadata": { "annotations": { "pv.kubernetes.io/bind-completed": "yes" } }, "spec": { "volumeName": "pvc-1" } }),
        );
        assert!(
            pvc["spec"].get("volumeName").is_none() && pvc["metadata"]["annotations"] == json!({})
        );
        assert!(
            restore_rank("Secret") < restore_rank("Deployment")
                && restore_rank("PersistentVolumeClaim") < restore_rank("StatefulSet")
        );
    }
}
