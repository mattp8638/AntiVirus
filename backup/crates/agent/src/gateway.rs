//! NAS gateway (protocol::gateway).
//!
//! * **Gateway side**: an agent inside the network serves repositories (a
//!   folder on a NAS or file server it can reach) to the agents the server
//!   lists for each repository. Requests arrive directly on `listen_port`
//!   (LAN, VPN or a forwarded port) and through the server's relay; both carry
//!   the same end-to-end encrypted messages. Remote agents may add objects
//!   and read, but never delete or overwrite backup data: only lock files
//!   (`locks/`) can be removed. Retention and space reclamation run on the
//!   gateway itself.
//! * **Client side**: [`RemoteBackend`] is a `core_format::Backend` that sends
//!   each storage operation to the gateway, directly when it answers and
//!   through the relay otherwise.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use core_format::backend::{Backend, LocalBackend, PutOutcome};
use protocol::gateway::{self, Channel, GatewayConfig, GatewayRoute, Op, Request, Response};
use protocol::seal::AgentKey;
use uuid::Uuid;

use crate::client::Client;

const RELAY_WORKERS: usize = 4;
const PATH: &str = "/fenrir-gateway/v1";

/// Opens a served repository's storage from its path and sealed share sign-in.
type Opener<'a> =
    &'a dyn Fn(&str, Option<&protocol::seal::Sealed>) -> anyhow::Result<Arc<dyn Backend>>;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Gateway side
// ---------------------------------------------------------------------------

struct ServedRepo {
    path: String,
    sealed_share: Option<protocol::seal::Sealed>,
    clients: Vec<Uuid>,
    backend: Option<Arc<dyn Backend>>,
}

/// What this agent currently serves, from the server's last heartbeat.
pub struct Served {
    repos: HashMap<Uuid, ServedRepo>,
    /// Client agent id → public key.
    clients: HashMap<Uuid, String>,
}

impl Served {
    pub fn new(cfg: &GatewayConfig) -> Served {
        let mut clients = HashMap::new();
        let mut repos = HashMap::new();
        for r in &cfg.repositories {
            for c in &r.clients {
                clients.insert(c.agent_id, c.public_key.clone());
            }
            repos.insert(
                r.repository_id,
                ServedRepo {
                    path: r.path.clone(),
                    sealed_share: r.sealed_share.clone(),
                    clients: r.clients.iter().map(|c| c.agent_id).collect(),
                    backend: None,
                },
            );
        }
        Served { repos, clients }
    }

    /// For tests: serve `backend` as repository `id` to `clients`.
    #[cfg(test)]
    pub fn with_backend(id: Uuid, backend: Arc<dyn Backend>, clients: &[(Uuid, String)]) -> Served {
        let mut s = Served {
            repos: HashMap::new(),
            clients: HashMap::new(),
        };
        for (c, pk) in clients {
            s.clients.insert(*c, pk.clone());
        }
        s.repos.insert(
            id,
            ServedRepo {
                path: String::new(),
                sealed_share: None,
                clients: clients.iter().map(|c| c.0).collect(),
                backend: Some(backend),
            },
        );
        s
    }
}

/// The policy: everything a backup, verify or restore needs, and nothing that
/// removes backup data.
fn allowed(op: &Op) -> Result<(), String> {
    match op {
        Op::Delete { key } if !key.starts_with("locks/") => Err(
            "this repository is served append-only through a gateway: deleting backups (retention, space reclamation) runs on the gateway itself"
                .into(),
        ),
        _ => Ok(()),
    }
}

fn execute(b: &dyn Backend, op: &Op, body: &[u8]) -> (Response, Vec<u8>) {
    let r = match op {
        Op::Put { key } => b.put(key, body).map(|o| {
            (
                Response {
                    created: o == PutOutcome::Created,
                    ..Default::default()
                },
                vec![],
            )
        }),
        Op::Get { key } => b.get(key).map(|d| (Response::default(), d)),
        Op::Exists { key } => b.exists(key).map(|e| {
            (
                Response {
                    exists: e,
                    ..Default::default()
                },
                vec![],
            )
        }),
        Op::Size { key } => b.size(key).map(|n| {
            (
                Response {
                    size: n,
                    ..Default::default()
                },
                vec![],
            )
        }),
        Op::List { prefix } => b.list(prefix).map(|k| {
            (
                Response {
                    keys: k,
                    ..Default::default()
                },
                vec![],
            )
        }),
        Op::Delete { key } => b.delete(key).map(|_| (Response::default(), vec![])),
    };
    match r {
        Ok(x) => x,
        Err(e) => {
            let kind = match &e {
                core_format::Error::NotFound(_) => "not_found",
                core_format::Error::InvalidArgument(_) => "invalid",
                _ => "io",
            };
            (
                Response {
                    error: Some(kind.into()),
                    message: e.to_string(),
                    ..Default::default()
                },
                vec![],
            )
        }
    }
}

/// Answer one encrypted request. `open` opens a served repository's storage.
pub fn handle(
    me: &AgentKey,
    served: &RwLock<Served>,
    wire: &[u8],
    open: Opener,
) -> Result<Vec<u8>, String> {
    let (_, client) = gateway::peek(wire).map_err(|e| e.to_string())?;
    let pk = served
        .read()
        .unwrap()
        .clients
        .get(&client)
        .cloned()
        .ok_or("this machine is not allowed to use the gateway")?;
    let ch = Channel::gateway(me, client, &pk).map_err(|e| e.to_string())?;
    let (rid, req, body) = ch.open_request(wire, now()).map_err(|e| e.to_string())?;
    let deny = |msg: String| {
        ch.response(
            &rid,
            &Response {
                error: Some("denied".into()),
                message: msg,
                ..Default::default()
            },
            b"",
        )
    };
    let backend = {
        let s = served.read().unwrap();
        let Some(repo) = s.repos.get(&req.repository_id) else {
            return Ok(deny("the gateway does not serve that repository".into()));
        };
        if !repo.clients.contains(&client) {
            return Ok(deny(
                "this machine has no access to that repository through the gateway".into(),
            ));
        }
        repo.backend
            .clone()
            .map(Ok)
            .unwrap_or_else(|| Err((repo.path.clone(), repo.sealed_share.clone())))
    };
    let backend = match backend {
        Ok(b) => b,
        Err((path, share)) => match open(&path, share.as_ref()) {
            Ok(b) => {
                if let Some(r) = served.write().unwrap().repos.get_mut(&req.repository_id) {
                    r.backend = Some(b.clone());
                }
                b
            }
            Err(e) => {
                let resp = Response {
                    error: Some("io".into()),
                    message: format!("the gateway cannot open the repository: {e:#}"),
                    ..Default::default()
                };
                return Ok(ch.response(&rid, &resp, b""));
            }
        },
    };
    if let Err(m) = allowed(&req.op) {
        return Ok(deny(m));
    }
    let (resp, out) = execute(backend.as_ref(), &req.op, &body);
    Ok(ch.response(&rid, &resp, &out))
}

/// The running gateway: config from heartbeats, a direct listener and relay workers.
pub struct Gateway {
    key: Arc<AgentKey>,
    client: Client,
    served: Arc<RwLock<Served>>,
    active: Arc<AtomicBool>,
    port: Arc<AtomicU16>,
    started_workers: AtomicBool,
    addresses: Mutex<Vec<String>>,
}

static SERVING: AtomicBool = AtomicBool::new(false);

/// Is this agent serving repositories? (Keeps network shares connected.)
pub fn serving() -> bool {
    SERVING.load(Ordering::SeqCst)
}

fn open_local(
    key: &AgentKey,
    path: &str,
    share: Option<&protocol::seal::Sealed>,
) -> anyhow::Result<Arc<dyn Backend>> {
    let folder = |p: &str| -> anyhow::Result<Arc<dyn Backend>> {
        Ok(Arc::new(LocalBackend::open(crate::share::prepare(
            key, p, share,
        )?)?))
    };
    // A dedup group member: its folder plus the group's shared store.
    if let Some((root, _)) = core_format::group::split_member_path(path) {
        return Ok(Arc::new(core_format::group::GroupBackend {
            member: folder(path)?,
            shared: folder(&root)?,
        }));
    }
    folder(path)
}

impl Gateway {
    pub fn new(key: Arc<AgentKey>, client: Client) -> Gateway {
        Gateway {
            key,
            client,
            served: Arc::new(RwLock::new(Served {
                repos: HashMap::new(),
                clients: HashMap::new(),
            })),
            active: Arc::new(AtomicBool::new(false)),
            port: Arc::new(AtomicU16::new(0)),
            started_workers: AtomicBool::new(false),
            addresses: Mutex::new(vec![]),
        }
    }

    /// Where direct connections reach this gateway (reported in the inventory).
    pub fn addresses(&self) -> Vec<String> {
        self.addresses.lock().unwrap().clone()
    }

    /// Apply the configuration from a heartbeat (None: serve nothing).
    pub fn apply(&self, cfg: Option<&GatewayConfig>) {
        let cfg = cfg.filter(|c| !c.repositories.is_empty());
        let Some(cfg) = cfg else {
            if self.active.swap(false, Ordering::SeqCst) {
                crate::log::info("gateway: no longer serving repositories");
            }
            SERVING.store(false, Ordering::SeqCst);
            *self.served.write().unwrap() = Served {
                repos: HashMap::new(),
                clients: HashMap::new(),
            };
            *self.addresses.lock().unwrap() = vec![];
            return;
        };
        {
            // Keep opened storage for repositories whose path and sign-in did not change.
            let mut new = Served::new(cfg);
            let old = self.served.read().unwrap();
            for (id, r) in new.repos.iter_mut() {
                if let Some(o) = old
                    .repos
                    .get(id)
                    .filter(|o| o.path == r.path && o.sealed_share == r.sealed_share)
                {
                    r.backend = o.backend.clone();
                }
            }
            drop(old);
            *self.served.write().unwrap() = new;
        }
        if !self.active.swap(true, Ordering::SeqCst) {
            crate::log::info(&format!(
                "gateway: serving {} repositories",
                cfg.repositories.len()
            ));
        }
        SERVING.store(true, Ordering::SeqCst);
        if !self.started_workers.swap(true, Ordering::SeqCst) {
            for i in 0..RELAY_WORKERS {
                let (key, client, served, active) = (
                    self.key.clone(),
                    self.client.clone(),
                    self.served.clone(),
                    self.active.clone(),
                );
                std::thread::Builder::new()
                    .name(format!("gateway-relay-{i}"))
                    .spawn(move || relay_worker(&key, &client, &served, &active))
                    .ok();
            }
        }
        let want = cfg.listen_port;
        if want != 0 && self.port.load(Ordering::SeqCst) != want {
            match TcpListener::bind(("0.0.0.0", want)) {
                Ok(l) => {
                    allow_in_firewall(want);
                    self.port.store(want, Ordering::SeqCst);
                    *self.addresses.lock().unwrap() = local_addresses(want);
                    crate::log::info(&format!(
                        "gateway: listening for direct connections on port {want}"
                    ));
                    let (key, served, active, port) = (
                        self.key.clone(),
                        self.served.clone(),
                        self.active.clone(),
                        self.port.clone(),
                    );
                    std::thread::Builder::new()
                        .name("gateway-listen".into())
                        .spawn(move || listen(l, want, &key, &served, &active, &port))
                        .ok();
                }
                Err(e) => crate::log::warn(&format!(
                    "gateway: cannot listen on port {want}: {e}; relay only"
                )),
            }
        } else if want == 0 {
            self.port.store(0, Ordering::SeqCst);
            self.addresses.lock().unwrap().clear();
        }
    }
}

/// Windows: let other machines on Domain and Private networks (never Public
/// ones) reach the gateway port. One rule, replaced when the port changes.
fn allow_in_firewall(port: u16) {
    if !cfg!(windows) {
        return;
    }
    const RULE: &str = "Fenrir-Backup gateway";
    let run = |args: &[&str]| {
        std::process::Command::new("netsh")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    let _ = run(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={RULE}"),
    ]);
    let local = format!("localport={port}");
    if !run(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={RULE}"),
        "dir=in",
        "action=allow",
        "protocol=TCP",
        &local,
        "profile=domain,private",
    ]) {
        crate::log::warn(&format!(
            "gateway: could not add a Windows Firewall rule for port {port}; allow it yourself"
        ));
    }
}

/// This machine's address on its default route, with `port`.
fn local_addresses(port: u16) -> Vec<String> {
    let s =
        std::net::UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect("192.0.2.1:9").map(|_| s));
    match s.and_then(|s| s.local_addr()) {
        Ok(a) if !a.ip().is_loopback() && !a.ip().is_unspecified() => {
            vec![format!("{}:{port}", a.ip())]
        }
        _ => vec![],
    }
}

fn relay_worker(key: &AgentKey, client: &Client, served: &RwLock<Served>, active: &AtomicBool) {
    let open = |p: &str, s: Option<&protocol::seal::Sealed>| open_local(key, p, s);
    let mut backoff = 1;
    loop {
        if !active.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        match client.raw(
            "GET",
            "/api/agent/relay/next",
            None,
            Duration::from_secs(60),
            gateway::MAX_MESSAGE as u64 + 8192,
        ) {
            Ok((200, Some(id), body)) => {
                backoff = 1;
                let reply = match handle(key, served, &body, &open) {
                    Ok(r) => r,
                    Err(e) => {
                        crate::log::warn(&format!("gateway: refused a relayed request: {e}"));
                        continue; // the client times out; nothing to answer it with
                    }
                };
                if let Err(e) = client.raw(
                    "POST",
                    &format!("/api/agent/relay/reply/{id}"),
                    Some(&reply),
                    Duration::from_secs(120),
                    4096,
                ) {
                    crate::log::warn(&format!(
                        "gateway: could not return a relayed answer: {e:#}"
                    ));
                }
            }
            Ok(_) => backoff = 1, // 204: nothing waiting
            Err(e) => {
                crate::log::warn(&format!("gateway: relay unavailable: {e:#}"));
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

fn listen(
    l: TcpListener,
    my_port: u16,
    key: &Arc<AgentKey>,
    served: &Arc<RwLock<Served>>,
    active: &Arc<AtomicBool>,
    port: &Arc<AtomicU16>,
) {
    let open_conns = Arc::new(AtomicU16::new(0));
    for conn in l.incoming() {
        if port.load(Ordering::SeqCst) != my_port {
            return; // the port changed: a new listener took over
        }
        let Ok(stream) = conn else { continue };
        if !active.load(Ordering::SeqCst) || open_conns.load(Ordering::SeqCst) >= 32 {
            drop(stream);
            continue;
        }
        open_conns.fetch_add(1, Ordering::SeqCst);
        let (key, served, n) = (key.clone(), served.clone(), open_conns.clone());
        std::thread::spawn(move || {
            let _ = serve_connection(stream, &key, &served);
            n.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Minimal HTTP/1.1 with keep-alive: `POST /fenrir-gateway/v1` with a binary
/// body in, a binary body out. Anything else is 404. Confidentiality and
/// authentication come from the message layer, so plain HTTP is fine.
fn serve_connection(
    stream: TcpStream,
    key: &AgentKey,
    served: &RwLock<Served>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_nodelay(true)?;
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let open = |p: &str, s: Option<&protocol::seal::Sealed>| open_local(key, p, s);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut parts = line.split_whitespace();
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let mut len: Option<usize> = None;
        let mut close = false;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h)? == 0 || h.len() > 8192 {
                return Ok(());
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => len = v.trim().parse().ok(),
                    "connection" => close = v.trim().eq_ignore_ascii_case("close"),
                    "transfer-encoding" => return reply(&mut w, 411, b"", true),
                    _ => {}
                }
            }
        }
        if method != "POST" || path != PATH {
            return reply(&mut w, 404, b"", true);
        }
        let Some(len) = len.filter(|n| *n <= gateway::MAX_MESSAGE + 8192) else {
            return reply(&mut w, 413, b"", true);
        };
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        match handle(key, served, &body, &open) {
            Ok(out) => reply(&mut w, 200, &out, close)?,
            Err(_) => reply(&mut w, 403, b"", close)?,
        }
        if close {
            return Ok(());
        }
    }
}

fn reply(w: &mut TcpStream, status: u16, body: &[u8], close: bool) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        411 => "Length Required",
        _ => "Payload Too Large",
    };
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        body.len(),
        if close { "close" } else { "keep-alive" }
    )?;
    w.write_all(body)?;
    w.flush()
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// How a request reaches the gateway.
pub trait Transport: Send + Sync {
    fn send(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn describe(&self) -> String;
}

/// Direct connections first (remembering which address answered), the relay
/// when none does. A direct address that failed is retried after 5 minutes.
pub struct Route {
    route: GatewayRoute,
    server: Client,
    direct: ureq::Agent,
    working: Mutex<Option<String>>,
    failed_at: Mutex<Option<Instant>>,
}

impl Route {
    pub fn new(route: GatewayRoute, server: Client) -> Route {
        Route {
            route,
            server,
            // Direct means direct: a LAN or VPN address never goes through a web proxy.
            direct: ureq::AgentBuilder::new()
                .try_proxy_from_env(false)
                .timeout_connect(Duration::from_secs(3))
                .timeout(Duration::from_secs(120))
                .build(),
            working: Mutex::new(None),
            failed_at: Mutex::new(None),
        }
    }

    fn direct(&self, addr: &str, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let r = self
            .direct
            .post(&format!("http://{addr}{PATH}"))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(wire)?;
        let mut buf = Vec::new();
        r.into_reader()
            .take(gateway::MAX_MESSAGE as u64 + 8192)
            .read_to_end(&mut buf)?;
        Ok(buf)
    }
}

impl Transport for Route {
    fn send(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let retry_direct = self
            .failed_at
            .lock()
            .unwrap()
            .is_none_or(|t| t.elapsed() > Duration::from_secs(300));
        if retry_direct {
            let known = self.working.lock().unwrap().clone();
            let candidates: Vec<String> = known
                .into_iter()
                .chain(self.route.addresses.iter().cloned())
                .collect();
            for addr in candidates {
                match self.direct(&addr, wire) {
                    Ok(b) => {
                        *self.working.lock().unwrap() = Some(addr);
                        return Ok(b);
                    }
                    Err(e) => crate::log::info(&format!(
                        "gateway: {addr} not reachable directly ({e}); trying the next way"
                    )),
                }
            }
            *self.working.lock().unwrap() = None;
            *self.failed_at.lock().unwrap() = Some(Instant::now());
        }
        if !self.route.relay {
            anyhow::bail!("the gateway is not reachable directly and relaying is off");
        }
        let (status, _, body) = self.server.raw(
            "POST",
            &format!("/api/agent/relay/{}", self.route.agent_id),
            Some(wire),
            Duration::from_secs(150),
            gateway::MAX_MESSAGE as u64 + 8192,
        )?;
        if status != 200 {
            anyhow::bail!("relay answered {status}");
        }
        Ok(body)
    }

    fn describe(&self) -> String {
        match self.working.lock().unwrap().as_deref() {
            Some(a) => format!("gateway {} at {a}", self.route.agent_id),
            None => format!("gateway {} (relayed)", self.route.agent_id),
        }
    }
}

/// A repository reached through a gateway.
pub struct RemoteBackend {
    channel: Channel,
    repository: Uuid,
    transport: Box<dyn Transport>,
}

impl RemoteBackend {
    pub fn new(
        me: &AgentKey,
        my_id: Uuid,
        gateway_pk: &str,
        repository: Uuid,
        transport: Box<dyn Transport>,
    ) -> anyhow::Result<RemoteBackend> {
        Ok(RemoteBackend {
            channel: Channel::client(me, my_id, gateway_pk)?,
            repository,
            transport,
        })
    }

    fn call(&self, op: Op, body: &[u8]) -> core_format::Result<(Response, Vec<u8>)> {
        let req = Request {
            repository_id: self.repository,
            ts: now(),
            op,
        };
        let (rid, wire) = self.channel.request(&req, body);
        let mut last = None;
        // Transient network trouble: try three times.
        for attempt in 0..3 {
            match self
                .transport
                .send(&wire)
                .and_then(|b| Ok(self.channel.open_response(&rid, &b)?))
            {
                Ok((resp, data)) => {
                    return match resp.error.as_deref() {
                        None => Ok((resp, data)),
                        Some("not_found") => Err(core_format::Error::NotFound(resp.message)),
                        Some("invalid") => Err(core_format::Error::InvalidArgument(resp.message)),
                        Some(_) => Err(core_format::Error::Io(std::io::Error::other(resp.message))),
                    };
                }
                Err(e) => last = Some(e),
            }
            std::thread::sleep(Duration::from_millis(500 << attempt));
        }
        Err(core_format::Error::Io(std::io::Error::other(format!(
            "cannot reach the repository through the gateway: {:#}",
            last.expect("an attempt failed")
        ))))
    }
}

impl Backend for RemoteBackend {
    fn put(&self, key: &str, data: &[u8]) -> core_format::Result<PutOutcome> {
        core_format::backend::validate_key(key)?;
        let (r, _) = self.call(Op::Put { key: key.into() }, data)?;
        Ok(if r.created {
            PutOutcome::Created
        } else {
            PutOutcome::AlreadyExists
        })
    }
    fn get(&self, key: &str) -> core_format::Result<Vec<u8>> {
        Ok(self.call(Op::Get { key: key.into() }, b"")?.1)
    }
    fn exists(&self, key: &str) -> core_format::Result<bool> {
        Ok(self.call(Op::Exists { key: key.into() }, b"")?.0.exists)
    }
    fn size(&self, key: &str) -> core_format::Result<u64> {
        Ok(self.call(Op::Size { key: key.into() }, b"")?.0.size)
    }
    fn list(&self, prefix: &str) -> core_format::Result<Vec<String>> {
        Ok(self
            .call(
                Op::List {
                    prefix: prefix.into(),
                },
                b"",
            )?
            .0
            .keys)
    }
    fn delete(&self, key: &str) -> core_format::Result<()> {
        self.call(Op::Delete { key: key.into() }, b"").map(|_| ())
    }
    fn describe(&self) -> String {
        self.transport.describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-process transport straight into a gateway's handler.
    struct Loopback {
        key: Arc<AgentKey>,
        served: Arc<RwLock<Served>>,
    }

    impl Transport for Loopback {
        fn send(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
            handle(&self.key, &self.served, wire, &|_, _| {
                anyhow::bail!("not used")
            })
            .map_err(|e| anyhow::anyhow!(e))
        }
        fn describe(&self) -> String {
            "loopback".into()
        }
    }

    fn setup() -> (
        tempfile::TempDir,
        Arc<AgentKey>,
        Arc<RwLock<Served>>,
        AgentKey,
        Uuid,
        Uuid,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Backend> =
            Arc::new(LocalBackend::create(dir.path().join("repo")).unwrap());
        let gw = Arc::new(AgentKey::generate());
        let client = AgentKey::generate();
        let (cid, rid) = (Uuid::new_v4(), Uuid::new_v4());
        let served = Arc::new(RwLock::new(Served::with_backend(
            rid,
            backend,
            &[(cid, client.public_b64())],
        )));
        (dir, gw, served, client, cid, rid)
    }

    #[test]
    fn a_repository_through_the_gateway_is_append_only() {
        let (_d, gw, served, client, cid, rid) = setup();
        let t = Loopback {
            key: gw.clone(),
            served: served.clone(),
        };
        let b = RemoteBackend::new(&client, cid, &gw.public_b64(), rid, Box::new(t)).unwrap();
        assert_eq!(
            b.put("chunks/ab/abcd", b"data").unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            b.put("chunks/ab/abcd", b"other").unwrap(),
            PutOutcome::AlreadyExists
        );
        assert_eq!(
            b.get("chunks/ab/abcd").unwrap(),
            b"data",
            "existing objects are never overwritten"
        );
        assert!(b.exists("chunks/ab/abcd").unwrap());
        assert_eq!(b.size("chunks/ab/abcd").unwrap(), 4);
        assert_eq!(
            b.list("chunks").unwrap(),
            vec!["chunks/ab/abcd".to_string()]
        );
        assert!(matches!(
            b.get("chunks/zz/none"),
            Err(core_format::Error::NotFound(_))
        ));
        // Lock files come and go; backup data cannot be deleted.
        b.put("locks/x-0", b"{}").unwrap();
        b.delete("locks/x-0").unwrap();
        let e = b.delete("chunks/ab/abcd").unwrap_err().to_string();
        assert!(e.contains("append-only"), "{e}");
        assert!(b.exists("chunks/ab/abcd").unwrap());
    }

    #[test]
    fn strangers_and_other_repositories_are_refused() {
        let (_d, gw, served, _client, _cid, rid) = setup();
        let stranger = AgentKey::generate();
        let sid = Uuid::new_v4();
        let t = Loopback {
            key: gw.clone(),
            served: served.clone(),
        };
        let b = RemoteBackend::new(&stranger, sid, &gw.public_b64(), rid, Box::new(t)).unwrap();
        assert!(b.exists("config.json").is_err());

        let (_d2, gw2, served2, client2, cid2, _rid2) = setup();
        let t = Loopback {
            key: gw2.clone(),
            served: served2,
        };
        let other_repo = RemoteBackend::new(
            &client2,
            cid2,
            &gw2.public_b64(),
            Uuid::new_v4(),
            Box::new(t),
        )
        .unwrap();
        assert!(other_repo
            .exists("config.json")
            .unwrap_err()
            .to_string()
            .contains("does not serve"));
    }

    #[test]
    fn a_whole_repository_works_through_the_gateway() {
        use core_format::crypto::KdfParams;
        use core_format::{InitOptions, Repository};

        let (_d, gw, served, client, cid, rid) = setup();
        let remote = |s: &Arc<RwLock<Served>>| -> Arc<dyn Backend> {
            Arc::new(
                RemoteBackend::new(
                    &client,
                    cid,
                    &gw.public_b64(),
                    rid,
                    Box::new(Loopback {
                        key: gw.clone(),
                        served: s.clone(),
                    }),
                )
                .unwrap(),
            )
        };
        // Create, back up, read back and verify a disk entirely through the gateway.
        let (repo, _) = Repository::init(
            remote(&served),
            b"pw",
            InitOptions {
                chunk_size: 1 << 20,
                kdf: KdfParams::INSECURE_FAST,
                ..Default::default()
            },
        )
        .unwrap();
        let disk: Vec<u8> = (0..3u32 << 20).map(|i| (i % 251) as u8).collect();
        let src = engine::ReadAtSource {
            info: engine::DiskInfo {
                size: disk.len() as u64,
                logical_sector_size: 512,
                ..Default::default()
            },
            inner: disk.clone(),
        };
        let meta = engine::ImageMeta {
            machine: core_format::manifest::MachineInfo {
                machine_id: "m".into(),
                hostname: "h".into(),
            },
            consistency: core_format::manifest::Consistency::Offline,
            os: Default::default(),
            boot: Default::default(),
            drivers: vec![],
            label: None,
            warnings: vec![],
            vm: None,
            applications: vec![],
        };
        let r = engine::backup(
            &repo,
            &[&src as &dyn engine::DiskSource],
            meta,
            &Default::default(),
            &engine::JobControl::new(),
            &|_| {},
        )
        .unwrap();
        let again = Repository::unlock_with_passphrase(remote(&served), b"pw").unwrap();
        let m = again.load_manifest(&r.image_id).unwrap();
        let chunk = again.get_chunk(&m.disks[0].chunks[0].1).unwrap();
        assert_eq!(&chunk[..], &disk[..chunk.len()]);
        // Retention through the gateway is refused: it runs on the gateway.
        assert!(again
            .backend()
            .delete(&format!("manifests/{}", r.image_id))
            .is_err());
    }

    #[test]
    fn direct_connections_over_a_real_socket() {
        let (_d, gw, served, client, cid, rid) = setup();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        let (active, port) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicU16::new(p)));
        let (k2, s2, a2, p2) = (gw.clone(), served.clone(), active.clone(), port.clone());
        std::thread::spawn(move || listen(l, p, &k2, &s2, &a2, &p2));
        // A dead address first: the route moves on to the next one, and has no relay to fall back to.
        let route = GatewayRoute {
            agent_id: Uuid::new_v4(),
            public_key: gw.public_b64(),
            addresses: vec!["127.0.0.1:1".into(), format!("127.0.0.1:{p}")],
            relay: false,
        };
        let server = Client::new("https://127.0.0.1:9", "", None).unwrap();
        let b = RemoteBackend::new(
            &client,
            cid,
            &gw.public_b64(),
            rid,
            Box::new(Route::new(route, server)),
        )
        .unwrap();
        let big: Vec<u8> = (0..5u32 << 20).map(|i| (i * 7 % 253) as u8).collect();
        for i in 0..20 {
            assert_eq!(
                b.put(&format!("chunks/0{}/x{i}", i % 4), &big[..1 + i * 1000])
                    .unwrap(),
                PutOutcome::Created
            );
        }
        b.put("chunks/ff/big", &big).unwrap();
        assert_eq!(b.get("chunks/ff/big").unwrap(), big);
        assert_eq!(b.list("chunks").unwrap().len(), 21);
        assert!(
            b.describe().contains(&format!("127.0.0.1:{p}")),
            "{}",
            b.describe()
        );
        // Anything that is not a gateway message is refused.
        let plain = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
        let r = plain
            .post(&format!("http://127.0.0.1:{p}{PATH}"))
            .send_bytes(b"hello");
        assert!(matches!(r, Err(ureq::Error::Status(403, _))));
        assert!(matches!(
            plain.get(&format!("http://127.0.0.1:{p}/")).call(),
            Err(ureq::Error::Status(404, _))
        ));
    }
}
