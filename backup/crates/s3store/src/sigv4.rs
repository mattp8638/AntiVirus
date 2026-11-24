//! AWS Signature Version 4 for S3 requests (AWS documentation: "Signing AWS
//! API requests" / "Authenticating Requests: Using the Authorization
//! Header").

use crate::{hmac, sha256_hex};

pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    /// Already URI-encoded path.
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    /// Extra headers to send and sign (lower-case names).
    pub headers: &'a [(&'a str, String)],
    pub payload: &'a [u8],
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub unix_time: i64,
}

/// RFC 3986 percent-encoding of everything but unreserved characters.
pub fn encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Encode each segment of an object name, keeping the slashes.
pub fn encode_path(p: &str) -> String {
    p.split('/').map(encode).collect::<Vec<_>>().join("/")
}

/// Sorted, encoded `k=v&...` (also the query string sent).
pub fn canonical_query(q: &[(&str, &str)]) -> String {
    let mut v: Vec<(String, String)> = q.iter().map(|(k, v)| (encode(k), encode(v))).collect();
    v.sort();
    v.into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn amz_date(t: i64) -> (String, String) {
    let s = core_format::timefmt::rfc3339_utc(t); // YYYY-MM-DDTHH:MM:SSZ
    let date = s[..10].replace('-', "");
    let time = s[11..19].replace(':', "");
    (format!("{date}T{time}Z"), date)
}

/// The headers to send, including `Authorization`, `x-amz-date`,
/// `x-amz-content-sha256` and `host`.
pub fn sign(r: &Request) -> Vec<(String, String)> {
    let (amz, date) = amz_date(r.unix_time);
    let payload_hash = sha256_hex(r.payload);
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), r.host.to_string()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz.clone()),
    ];
    for (k, v) in r.headers {
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    headers.sort();
    let signed: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        r.method,
        r.path,
        canonical_query(r.query),
        canonical_headers,
        signed,
        payload_hash
    );
    let scope = format!("{date}/{}/s3/aws4_request", r.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let k = hmac(format!("AWS4{}", r.secret_key).as_bytes(), date.as_bytes());
    let k = hmac(&k, r.region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let signature = hex::encode(hmac(&k, to_sign.as_bytes()));
    headers.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed},Signature={signature}",
            r.access_key
        ),
    ));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "GET Object" example of the S3 SigV4 documentation
    /// (Authenticating Requests: Using the Authorization Header).
    #[test]
    fn aws_documentation_example() {
        // 20130524T000000Z
        let t = core_format::timefmt::days_from_civil(2013, 5, 24) * 86_400;
        let h = sign(&Request {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            query: &[],
            headers: &[("range", "bytes=0-9".to_string())],
            payload: b"",
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            unix_time: t,
        });
        let auth = &h.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn query_and_path_encoding() {
        assert_eq!(
            canonical_query(&[("prefix", "a b/c"), ("list-type", "2")]),
            "list-type=2&prefix=a%20b%2Fc"
        );
        assert_eq!(canonical_query(&[("retention", "")]), "retention=");
        assert_eq!(encode_path("pre fix/chunks/ab"), "pre%20fix/chunks/ab");
    }
}
