use crate::config::RuntimeConfig;
use openssl::base64;
use openssl::hash::MessageDigest;
use openssl::sha::Sha256;
use openssl::sign::Signer;
use std::time::{SystemTime, UNIX_EPOCH};

const SIGNED_HEADERS: &[&str] = &[
    "from",
    "sender",
    "reply-to",
    "subject",
    "date",
    "message-id",
    "to",
    "cc",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "in-reply-to",
    "references",
];

#[derive(Clone, Debug)]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Header {
    pub fn new(name: &[u8], value: &[u8]) -> Result<Self, String> {
        if name.is_empty()
            || name.len() > 998
            || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            || value.contains(&0)
        {
            return Err("invalid header supplied by MTA".to_owned());
        }
        Ok(Self {
            name: name.to_vec(),
            value: value.to_vec(),
        })
    }

    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }
}

pub struct BodyCanonicalizer {
    hasher: Sha256,
    pending_wsp: bool,
    pending_empty_lines: usize,
    line_has_content: bool,
    emitted_content: bool,
    saw_cr: bool,
}

impl Default for BodyCanonicalizer {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            pending_wsp: false,
            pending_empty_lines: 0,
            line_has_content: false,
            emitted_content: false,
            saw_cr: false,
        }
    }
}

impl BodyCanonicalizer {
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            if self.saw_cr {
                self.saw_cr = false;
                self.end_line();
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.saw_cr = true,
                b'\n' => self.end_line(),
                b' ' | b'\t' => self.pending_wsp = true,
                _ => {
                    if !self.line_has_content && self.pending_empty_lines > 0 {
                        for _ in 0..self.pending_empty_lines {
                            self.hasher.update(b"\r\n");
                        }
                        self.pending_empty_lines = 0;
                    }
                    if self.pending_wsp {
                        self.hasher.update(b" ");
                        self.pending_wsp = false;
                    }
                    self.hasher.update(&[byte]);
                    self.line_has_content = true;
                    self.emitted_content = true;
                }
            }
        }
    }

    fn end_line(&mut self) {
        self.pending_wsp = false;
        if self.line_has_content {
            self.hasher.update(b"\r\n");
            self.line_has_content = false;
        } else {
            self.pending_empty_lines = self.pending_empty_lines.saturating_add(1);
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.saw_cr {
            self.end_line();
        } else if self.line_has_content {
            self.pending_wsp = false;
            self.hasher.update(b"\r\n");
        }
        if !self.emitted_content {
            self.hasher.update(b"\r\n");
        }
        self.hasher.finish()
    }
}

pub fn sign(
    config: &RuntimeConfig,
    headers: &[Header],
    body_hash: [u8; 32],
) -> Result<String, String> {
    let from_headers: Vec<&Header> = headers.iter().filter(|h| h.is("from")).collect();
    if from_headers.len() != 1 {
        return Err("message must contain exactly one From header".to_owned());
    }
    let from_domain = from_domain(&from_headers[0].value)
        .ok_or_else(|| "cannot extract a single From domain".to_owned())?;
    if !from_domain.eq_ignore_ascii_case(&config.domain) {
        return Err(format!(
            "From domain {from_domain} does not match configured domain"
        ));
    }

    let mut selected = Vec::new();
    let mut h_names = Vec::new();
    for &name in SIGNED_HEADERS {
        if let Some(header) = headers.iter().rev().find(|h| h.is(name)) {
            selected.push(header);
            h_names.push(name);
        }
        if name == "from" {
            h_names.push("from"); // Oversign From; the second instance has no input bytes.
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_owned())?
        .as_secs();
    let body_hash = base64::encode_block(&body_hash);
    let unsigned_value = format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        config.domain,
        config.selector,
        timestamp,
        h_names.join(":"),
        body_hash
    );

    let mut signer = Signer::new(MessageDigest::sha256(), config.key.as_ref())
        .map_err(|e| format!("cannot initialize RSA-SHA256 signer: {e}"))?;
    for header in selected {
        signer
            .update(&canonicalize_header(&header.name, &header.value))
            .map_err(|e| format!("cannot hash header: {e}"))?;
    }
    signer
        .update(&canonicalize_signature_header(unsigned_value.as_bytes()))
        .map_err(|e| format!("cannot hash DKIM-Signature: {e}"))?;
    let signature = signer
        .sign_to_vec()
        .map_err(|e| format!("RSA-SHA256 signing failed: {e}"))?;
    Ok(fold_signature(&format!(
        "{unsigned_value}{}",
        base64::encode_block(&signature)
    )))
}

pub fn canonicalize_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 3);
    out.extend(name.iter().map(u8::to_ascii_lowercase));
    out.push(b':');
    let mut pending_wsp = false;
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b' ' | b'\t' => pending_wsp = true,
            b'\r' if value.get(index + 1) == Some(&b'\n') => {
                index += 1;
                pending_wsp = true;
            }
            b'\r' | b'\n' => pending_wsp = true,
            byte => {
                if pending_wsp && out.last() != Some(&b':') {
                    out.push(b' ');
                }
                pending_wsp = false;
                out.push(byte);
            }
        }
        index += 1;
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn canonicalize_signature_header(value: &[u8]) -> Vec<u8> {
    let mut canonical = canonicalize_header(b"DKIM-Signature", value);
    // RFC 6376 section 3.7 requires the signature field itself to be the final
    // hash input with b= empty and without the canonicalizer's trailing CRLF.
    canonical.truncate(canonical.len() - 2);
    canonical
}

fn from_domain(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?.trim();
    let mut quoted = false;
    let mut escaped = false;
    let mut comment_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut commas = 0usize;
    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
        } else if comment_depth == 0 && ch == '"' {
            quoted = !quoted;
        } else if !quoted {
            match ch {
                '(' => comment_depth += 1,
                ')' if comment_depth > 0 => comment_depth -= 1,
                '<' if comment_depth == 0 => angle_depth += 1,
                '>' if comment_depth == 0 && angle_depth > 0 => angle_depth -= 1,
                ',' if comment_depth == 0 && angle_depth == 0 => commas += 1,
                _ => {}
            }
        }
    }
    if quoted || comment_depth != 0 || angle_depth != 0 || commas != 0 {
        return None;
    }
    let address = match (text.rfind('<'), text.rfind('>')) {
        (Some(start), Some(end)) if start < end => &text[start + 1..end],
        (None, None) => text,
        _ => return None,
    };
    let (_, domain) = address.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn fold_signature(value: &str) -> String {
    const LIMIT: usize = 72;
    let mut out = String::with_capacity(value.len() + value.len() / LIMIT * 3);
    let mut column = 0;
    for token in value.split(' ') {
        let needed = if column == 0 {
            token.len()
        } else {
            token.len() + 1
        };
        if column > 0 && column + needed > LIMIT {
            out.push_str("\r\n\t");
            column = 1;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(token);
        column += token.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenAddr, RuntimeConfig};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Verifier;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn body(parts: &[&[u8]]) -> String {
        let mut c = BodyCanonicalizer::default();
        for part in parts {
            c.update(part);
        }
        base64::encode_block(&c.finish())
    }

    #[test]
    fn relaxed_header() {
        assert_eq!(
            canonicalize_header(b"SUBJect", b"  hello\r\n\tworld  "),
            b"subject:hello world\r\n"
        );
    }

    #[test]
    fn rfc6376_relaxed_canonicalization_examples() {
        assert_eq!(canonicalize_header(b"A", b" X\r\n Y\tZ  "), b"a:X Y Z\r\n");
        assert_eq!(body(&[b" C \r\nD \t E\r\n\r\n"]), body(&[b" C\r\nD E\r\n"]));
    }

    #[test]
    fn body_accepts_non_utf8_bytes() {
        assert_eq!(
            body(&[&[0xff, b' ', b'\n']]),
            body(&[&[0xff, b'\r', b'\n']])
        );
    }

    #[test]
    fn relaxed_body_is_chunk_independent() {
        let expected = body(&[b" C \r\nD \t E\r\n\r\n".as_slice()]);
        assert_eq!(
            expected,
            body(&[b" C \r", b"\nD ", b"\t E\r\n", b"\r", b"\n"])
        );
    }

    #[test]
    fn empty_body_is_one_crlf() {
        let mut sha = Sha256::new();
        sha.update(b"\r\n");
        let expected = base64::encode_block(&sha.finish());
        assert_eq!(body(&[]), expected);
        assert_eq!(body(&[b"\r\n\r\n"]), expected);
    }

    #[test]
    fn keeps_leading_empty_lines_before_content() {
        assert_eq!(body(&[b"\r\nA"]), body(&[b"\r", b"\n", b"A"]));
        assert_ne!(body(&[b"\r\nA"]), body(&[b"A"]));
    }

    #[test]
    fn parses_single_from_domain() {
        assert_eq!(
            from_domain(b"Alice (team) <alice@Example.COM>"),
            Some("example.com".into())
        );
        assert_eq!(from_domain(b"a@example.com, b@example.com"), None);
    }

    #[test]
    fn generated_signature_verifies_and_oversigns_from() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let config = RuntimeConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            private_key: PathBuf::from("unused"),
            listen: ListenAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8891)),
            require_fips: false,
            key: Arc::new(key.clone()),
        };
        let headers = vec![
            Header::new(b"From", b"Alice <alice@example.com>").unwrap(),
            Header::new(b"Subject", b"A  test").unwrap(),
        ];
        let mut body = BodyCanonicalizer::default();
        body.update(b"hello\n");
        let value = sign(&config, &headers, body.finish()).unwrap();
        assert!(value.contains("h=from:from:subject;"));

        let b_start = value.find("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();
        let mut unsigned = value[..b_start].to_owned();
        // The signer canonicalizes the semantically equivalent unfolded value.
        unsigned = String::from_utf8(canonicalize_signature_header(unsigned.as_bytes())).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier
            .update(&canonicalize_header(b"From", b"Alice <alice@example.com>"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"Subject", b"A  test"))
            .unwrap();
        verifier.update(unsigned.as_bytes()).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
