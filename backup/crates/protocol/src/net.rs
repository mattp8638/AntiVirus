//! HTTP client helpers shared by the server and the storage backends.
//!
//! ureq can send requests through the proxy named in the environment
//! (HTTPS_PROXY etc.) but ignores NO_PROXY, so callers decide per request.

pub fn no_proxy_env() -> String {
    std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default()
}

/// Whether a request to `url` goes through the proxy named in the
/// environment (HTTPS_PROXY etc.): not for loopback addresses, nor hosts
/// matched by NO_PROXY (`*`, exact names or IPs, and domain suffixes such as
/// `.corp.example` or `corp.example`).
pub fn use_env_proxy(url: &str, no_proxy: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
    .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        return false;
    }
    !no_proxy.split(',').map(str::trim).any(|e| {
        let e = e.to_ascii_lowercase();
        let e = e.split(':').next().unwrap_or("");
        e == "*"
            || (!e.is_empty()
                && (host == e.trim_start_matches('.')
                    || host.ends_with(&format!(".{}", e.trim_start_matches('.')))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_proxy_skips_loopback_and_no_proxy() {
        assert!(use_env_proxy("https://hooks.slack.com/services/x", ""));
        assert!(!use_env_proxy("http://127.0.0.1:9000/hook", ""));
        assert!(!use_env_proxy("http://[::1]:9000/hook", ""));
        assert!(!use_env_proxy("http://localhost/hook", ""));
        let np = "corp.example, .internal ,10.0.0.5";
        assert!(!use_env_proxy("https://alerts.corp.example/x", np));
        assert!(!use_env_proxy("https://corp.example/x", np));
        assert!(!use_env_proxy("https://a.b.internal:8443/x", np));
        assert!(!use_env_proxy("http://10.0.0.5/x", np));
        assert!(use_env_proxy("https://notcorp.example/x", np));
        assert!(!use_env_proxy("https://anything/x", "*"));
    }
}
