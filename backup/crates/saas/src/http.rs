//! HTTP for the connectors: JSON and bytes, bearer tokens, retries when a
//! service throttles (429/503 with Retry-After).

use std::io::Read;
use std::time::Duration;

use serde_json::Value;

use crate::{err, Result};

pub struct Http {
    agent: ureq::Agent,
}

pub enum Body<'a> {
    None,
    Json(&'a Value),
    Form(&'a [(&'a str, &'a str)]),
    Bytes(&'a [u8], &'a str),
}

impl Default for Http {
    fn default() -> Self {
        Http {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(20))
                .timeout(Duration::from_secs(600))
                .build(),
        }
    }
}

impl Http {
    /// One request with retries; returns (status, body bytes).
    pub fn send(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Body,
    ) -> Result<(u16, Vec<u8>)> {
        let mut wait = Duration::from_secs(2);
        for attempt in 0..6 {
            let mut req = self.agent.request(method, url);
            if let Some(t) = token {
                req = req.set("Authorization", &format!("Bearer {t}"));
            }
            for (k, v) in headers {
                req = req.set(k, v);
            }
            let r = match &body {
                Body::None => req.call(),
                Body::Json(v) => req
                    .set("Content-Type", "application/json")
                    .send_string(&v.to_string()),
                Body::Form(f) => req.send_form(f),
                Body::Bytes(b, ct) => req.set("Content-Type", ct).send_bytes(b),
            };
            let resp = match r {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(ureq::Error::Transport(t)) => {
                    if attempt == 5 {
                        return Err(err(format!("{method} {url}: {t}")));
                    }
                    std::thread::sleep(wait);
                    wait *= 2;
                    continue;
                }
            };
            let status = resp.status();
            if (status == 429 || status == 503) && attempt < 5 {
                let after = resp
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .unwrap_or(wait);
                std::thread::sleep(after.min(Duration::from_secs(120)));
                wait *= 2;
                continue;
            }
            let mut b = Vec::new();
            resp.into_reader()
                .take(4 << 30)
                .read_to_end(&mut b)
                .map_err(|e| err(format!("{method} {url}: {e}")))?;
            return Ok((status, b));
        }
        Err(err(format!(
            "{method} {url}: the service kept refusing (throttled)"
        )))
    }

    pub fn json(&self, method: &str, url: &str, token: Option<&str>, body: Body) -> Result<Value> {
        let (s, b) = self.send(method, url, token, &[("Accept", "application/json")], body)?;
        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        if !(200..300).contains(&s) {
            let msg = v["error"]["message"]
                .as_str()
                .or(v["error_description"].as_str())
                .or(v["error"].as_str())
                .or(v[0]["message"].as_str())
                .unwrap_or("");
            return Err(err(format!("{method} {}: {s} {msg}", strip_query(url))));
        }
        Ok(v)
    }

    pub fn bytes(&self, url: &str, token: Option<&str>) -> Result<Vec<u8>> {
        let (s, b) = self.send("GET", url, token, &[], Body::None)?;
        if !(200..300).contains(&s) {
            return Err(err(format!("GET {}: {s}", strip_query(url))));
        }
        Ok(b)
    }
}

fn strip_query(u: &str) -> &str {
    u.split('?').next().unwrap_or(u)
}

pub fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
