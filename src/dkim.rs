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
    saw_cr: bool,
}

impl Default for BodyCanonicalizer {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            pending_wsp: false,
            pending_empty_lines: 0,
            line_has_content: false,
            saw_cr: false,
        }
    }
}

impl BodyCanonicalizer {
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.saw_cr {
                self.saw_cr = false;
                self.end_line();
                if data[0] == b'\n' {
                    data = &data[1..];
                    continue;
                }
            }

            let ordinary = data
                .iter()
                .position(|byte| matches!(*byte, b'\r' | b'\n' | b' ' | b'\t'))
                .unwrap_or(data.len());
            if ordinary > 0 {
                self.emit_content(&data[..ordinary]);
                data = &data[ordinary..];
                continue;
            }

            match data[0] {
                b'\r' => {
                    self.saw_cr = true;
                    data = &data[1..];
                }
                b'\n' => {
                    self.end_line();
                    data = &data[1..];
                }
                b' ' | b'\t' => {
                    self.pending_wsp = true;
                    let whitespace = data
                        .iter()
                        .position(|byte| !matches!(*byte, b' ' | b'\t'))
                        .unwrap_or(data.len());
                    data = &data[whitespace..];
                }
                _ => unreachable!(),
            }
        }
    }

    fn emit_content(&mut self, content: &[u8]) {
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
        self.hasher.update(content);
        self.line_has_content = true;
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
    let value_start = out.len();
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
                if pending_wsp && out.len() > value_start {
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
    // Unfold legal header folding before validating quoted local parts.
    let mut unfolded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte == b'\r' {
            if value.get(index + 1) != Some(&b'\n')
                || !matches!(value.get(index + 2), Some(b' ' | b'\t'))
            {
                return None;
            }
            index += 2;
            continue;
        }
        if byte.is_ascii_control() && byte != b'\t' {
            return None;
        }
        unfolded.push(byte);
        index += 1;
    }
    // Strip comments before looking for structural punctuation. Quoted strings
    // and quoted-pairs keep their bytes; punctuation inside them is not syntax.
    let mut mailbox = Vec::with_capacity(value.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut comment_depth = 0usize;
    for &byte in &unfolded {
        if escaped {
            if comment_depth == 0 {
                mailbox.push(byte);
            }
            escaped = false;
            continue;
        }
        if comment_depth > 0 {
            match byte {
                b'\\' => escaped = true,
                b'(' => comment_depth = comment_depth.checked_add(1)?,
                b')' => comment_depth -= 1,
                _ => {}
            }
        } else if quoted {
            mailbox.push(byte);
            match byte {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else {
            match byte {
                b'(' => {
                    comment_depth = 1;
                    mailbox.push(b' ');
                }
                b')' => return None,
                b'"' => {
                    quoted = true;
                    mailbox.push(byte);
                }
                _ => mailbox.push(byte),
            }
        }
    }
    if quoted || escaped || comment_depth != 0 {
        return None;
    }
    let text = std::str::from_utf8(&mailbox).ok()?.trim();
    let mut start = None;
    let mut end = None;
    for (index, byte) in text.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted {
            match byte {
                b'<' if start.is_none() => start = Some(index),
                b'>' if start.is_some() && end.is_none() => end = Some(index),
                b'<' | b'>' | b',' | b':' | b';' => return None,
                _ => {}
            }
        }
    }
    let address = match (start, end) {
        (Some(start), Some(end)) => {
            // Before angle-addr only a display phrase is allowed; after it only
            // whitespace/comments are allowed. Never discard a second address.
            if !display_name(&text.as_bytes()[..start]) || !text[end + 1..].trim().is_empty() {
                return None;
            }
            text[start + 1..end].trim()
        }
        (None, None) => text,
        _ => return None,
    };
    let mut separator = None;
    for (index, byte) in address.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b'@' && separator.replace(index).is_some() {
            return None;
        }
    }
    let separator = separator?;
    let local = address[..separator].trim();
    let domain = address[separator + 1..].trim().trim_end_matches('.');
    if !local_part(local.as_bytes())
        || domain.is_empty()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn atom_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}

fn local_part(value: &[u8]) -> bool {
    if value.first() == Some(&b'"') {
        let mut escaped = false;
        for (index, &byte) in value.iter().enumerate().skip(1) {
            if byte.is_ascii_control() && byte != b'\t' {
                return false;
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return index == value.len() - 1;
            }
        }
        false
    } else {
        !value.is_empty()
            && value
                .split(|&byte| byte == b'.')
                .all(|part| !part.is_empty() && part.iter().all(|&byte| atom_byte(byte)))
    }
}

fn display_name(value: &[u8]) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for &byte in value {
        if escaped {
            if byte.is_ascii_control() {
                return false;
            }
            escaped = false;
        } else if quoted {
            match byte {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ if byte.is_ascii_control() && byte != b'\t' => return false,
                _ => {}
            }
        } else if byte == b'"' {
            quoted = true;
        } else if !atom_byte(byte) && byte != b'.' && !byte.is_ascii_whitespace() && byte.is_ascii()
        {
            return false;
        }
    }
    !quoted && !escaped
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

    fn reference_body(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut pending_wsp = false;
        let mut pending_empty_lines = 0usize;
        let mut line_has_content = false;
        let mut saw_cr = false;
        let end_line = |hasher: &mut Sha256,
                        pending_wsp: &mut bool,
                        pending_empty_lines: &mut usize,
                        line_has_content: &mut bool| {
            *pending_wsp = false;
            if *line_has_content {
                hasher.update(b"\r\n");
                *line_has_content = false;
            } else {
                *pending_empty_lines = pending_empty_lines.saturating_add(1);
            }
        };
        for &byte in data {
            if saw_cr {
                saw_cr = false;
                end_line(
                    &mut hasher,
                    &mut pending_wsp,
                    &mut pending_empty_lines,
                    &mut line_has_content,
                );
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => saw_cr = true,
                b'\n' => end_line(
                    &mut hasher,
                    &mut pending_wsp,
                    &mut pending_empty_lines,
                    &mut line_has_content,
                ),
                b' ' | b'\t' => pending_wsp = true,
                _ => {
                    if !line_has_content && pending_empty_lines > 0 {
                        for _ in 0..pending_empty_lines {
                            hasher.update(b"\r\n");
                        }
                        pending_empty_lines = 0;
                    }
                    if pending_wsp {
                        hasher.update(b" ");
                        pending_wsp = false;
                    }
                    hasher.update(&[byte]);
                    line_has_content = true;
                }
            }
        }
        if saw_cr {
            end_line(
                &mut hasher,
                &mut pending_wsp,
                &mut pending_empty_lines,
                &mut line_has_content,
            );
        } else if line_has_content {
            hasher.update(b"\r\n");
        }
        hasher.finish()
    }

    fn optimized_body(parts: &[&[u8]]) -> [u8; 32] {
        let mut canonicalizer = BodyCanonicalizer::default();
        for part in parts {
            canonicalizer.update(part);
        }
        canonicalizer.finish()
    }

    #[test]
    fn relaxed_header_preserves_whitespace_after_value_colons() {
        assert_eq!(
            canonicalize_header(b"Subject", b"  Re: \t hello: world  "),
            b"subject:Re: hello: world\r\n"
        );
        assert_eq!(
            canonicalize_header(b"Subject", b"Re:\r\n\t hello"),
            b"subject:Re: hello\r\n"
        );
    }

    #[test]
    fn from_parser_ignores_quoted_and_commented_punctuation() {
        for value in [
            b"alice@EXAMPLE.COM.".as_slice(),
            b"Alice (team) <alice@Example.COM>",
            b"alice (team) @ example.com",
            b"\"folded\r\n \tlocal\"@example.com",
            b"\"display <fake@other.test>\" <alice@example.com>",
            b"Alice (outer (nested) note <fake@other.test>) <alice@example.com>",
            b"Alice (escaped \\) <fake@other.test>) <alice@example.com>",
            b"\"a\\\"b@local\"@Example.COM.",
        ] {
            assert_eq!(
                from_domain(value).as_deref(),
                Some("example.com"),
                "{value:?}"
            );
        }
        assert_eq!(
            from_domain(b"attacker@other.test (note <user@example.com>)").as_deref(),
            Some("other.test")
        );
    }

    #[test]
    fn from_parser_rejects_extra_mailboxes_and_unbalanced_syntax() {
        for value in [
            b"a@example.com, b@example.com".as_slice(),
            b"a@example.com <b@example.com>",
            b"<a@example.com> <b@example.com>",
            b"<a@example.com> b@example.com",
            b"<a@example.com,b@example.com>",
            b"a@example.com b@example.com",
            b"<a@example.com>>",
            b"<<a@example.com>",
            b"a@example.com>",
            b"<a@example.com",
            b"a@example.com (unfinished",
            b"a@example.com )",
            b"\"unfinished <a@example.com>",
            b"\"quoted\" extra@example.com",
            b"a@@example.com",
            b"@example.com",
            b"a..b@example.com",
            b"\"bad\r\nlocal\"@example.com",
            b"\"bad\n local\"@example.com",
        ] {
            assert_eq!(from_domain(value), None, "{value:?}");
        }
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
    fn relaxed_empty_body_hashes_no_bytes() {
        // RFC 6376 section 3.4.4 gives this SHA-256 hash for an empty body.
        const EMPTY_HASH: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        for input in [b"".as_slice(), b"\r\n\r\n", b" \t", b" \t\r\n\t\r\n"] {
            assert_eq!(body(&[input]), EMPTY_HASH);
            for split in 0..=input.len() {
                assert_eq!(body(&[&input[..split], &input[split..]]), EMPTY_HASH);
            }
        }
    }

    #[test]
    fn keeps_leading_empty_lines_before_content() {
        assert_eq!(body(&[b"\r\nA"]), body(&[b"\r", b"\n", b"A"]));
        assert_ne!(body(&[b"\r\nA"]), body(&[b"A"]));
    }

    #[test]
    fn optimized_body_matches_reference_for_all_split_positions() {
        let mut state = 0x6d5a_56e9_1234_5678u64;
        let mut arbitrary = Vec::with_capacity(4096);
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let byte = match state & 15 {
                0 => b'\r',
                1 => b'\n',
                2 | 3 => b' ',
                4 => b'\t',
                _ => (state >> 24) as u8,
            };
            arbitrary.push(byte);
        }
        let mut long_runs = vec![b' '; 2048];
        long_runs.extend_from_slice(&vec![b'\n'; 2048]);
        long_runs.extend_from_slice(&vec![b'x'; 4096]);

        for data in [
            b"".as_slice(),
            b"\r\n\r\n".as_slice(),
            b" C \r\nD \t E\r\n\r\n".as_slice(),
            &[0xff, b' ', b'\r', b'\n', 0x80],
            arbitrary.as_slice(),
            long_runs.as_slice(),
        ] {
            let expected = reference_body(data);
            assert_eq!(optimized_body(&[data]), expected);
            for split in 0..=data.len() {
                assert_eq!(optimized_body(&[&data[..split], &data[split..]]), expected);
            }
            for chunk_size in 1..=64 {
                let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
                assert_eq!(optimized_body(&chunks), expected);
            }
        }
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
    fn generated_signatures_verify_against_literal_rfc_inputs() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let config = RuntimeConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            private_key: PathBuf::from("unused"),
            listen: ListenAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8891)),
            require_fips: false,
            key: Arc::new(key.clone()),
        };
        let subjects: &[(&[u8], &[u8])] = &[
            (b"hello", b"subject:hello\r\n"),
            (b"Re: hello", b"subject:Re: hello\r\n"),
            (
                b"  Re:\r\n\t hello: \tworld  ",
                b"subject:Re: hello: world\r\n",
            ),
        ];
        let bodies: &[(&[u8], &str)] = &[
            (b"", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b"\r\n\r\n", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b" \t\r\n\t", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b"hello\r\n", "zS7KNTV0HyeorkDDGwxB1AV6enuRKzO5rthkhdHIRnY="),
        ];
        for &(subject, expected_subject) in subjects {
            for &(input, expected_hash) in bodies {
                let mut canonical = BodyCanonicalizer::default();
                for byte in input {
                    canonical.update(std::slice::from_ref(byte));
                }
                let headers = [
                    Header::new(b"From", b"Alice <alice@example.com>").unwrap(),
                    Header::new(b"Subject", subject).unwrap(),
                ];
                let value = sign(&config, &headers, canonical.finish()).unwrap();
                let unfolded = value.replace("\r\n\t", " ");
                assert!(unfolded.contains("h=from:from:subject;"));
                assert!(unfolded.contains(&format!("bh={expected_hash};")));
                let timestamp = unfolded
                    .split(';')
                    .find_map(|tag| tag.trim().strip_prefix("t="))
                    .unwrap();
                let b_start = unfolded.find("b=").unwrap() + 2;
                let signature = base64::decode_block(&unfolded[b_start..]).unwrap();
                // Literal expected canonical bytes, independent of all production
                // canonicalizers. The timestamp is the only nondeterministic tag.
                let unsigned = format!(
                    "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test; t={timestamp}; h=from:from:subject; bh={expected_hash}; b="
                );
                let mut verifier =
                    Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
                verifier
                    .update(b"from:Alice <alice@example.com>\r\n")
                    .unwrap();
                verifier.update(expected_subject).unwrap();
                verifier.update(unsigned.as_bytes()).unwrap();
                assert!(
                    verifier.verify(&signature).unwrap(),
                    "subject={subject:?}, body={input:?}"
                );
            }
        }
    }
}
