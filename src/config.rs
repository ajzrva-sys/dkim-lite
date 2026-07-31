use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use std::collections::HashSet;
use std::ffi::{c_char, c_void};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenAddr {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

#[derive(Clone)]
pub struct RuntimeConfig {
    pub domain: String,
    pub selector: String,
    pub private_key: PathBuf,
    pub listen: ListenAddr,
    pub require_fips: bool,
    pub key: Arc<PKey<Private>>,
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input =
            fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut seen = HashSet::new();
        let mut domain = None;
        let mut selector = None;
        let mut private_key = None;
        let mut listen = None;
        let mut require_fips = true;

        for (index, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected name=value", index + 1))?;
            let name = name.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("line {}: empty value for {name}", index + 1));
            }
            if !seen.insert(name.to_owned()) {
                return Err(format!("line {}: duplicate setting {name}", index + 1));
            }
            match name {
                "domain" => domain = Some(validate_dns_name("domain", value)?),
                "selector" => selector = Some(validate_dns_name("selector", value)?),
                "private_key" => private_key = Some(PathBuf::from(value)),
                "listen" => listen = Some(parse_listen(value)?),
                "require_fips" => {
                    require_fips = match value {
                        "true" => true,
                        "false" => false,
                        _ => {
                            return Err(format!(
                                "line {}: require_fips must be true or false",
                                index + 1
                            ))
                        }
                    }
                }
                _ => return Err(format!("line {}: unknown setting {name}", index + 1)),
            }
        }

        let domain = domain.ok_or_else(|| "missing domain".to_owned())?;
        let selector = selector.ok_or_else(|| "missing selector".to_owned())?;
        let private_key = private_key.ok_or_else(|| "missing private_key".to_owned())?;
        if !private_key.is_absolute() {
            return Err("private_key must be an absolute path".to_owned());
        }
        let listen = listen.ok_or_else(|| "missing listen".to_owned())?;
        let key_bytes = fs::read(&private_key)
            .map_err(|e| format!("cannot read private key {}: {e}", private_key.display()))?;
        let key = PKey::private_key_from_pem(&key_bytes)
            .map_err(|e| format!("cannot parse unencrypted PEM private key: {e}"))?;
        validate_key(&key)?;

        Ok(Self {
            domain,
            selector,
            private_key,
            listen,
            require_fips,
            key: Arc::new(key),
        })
    }
}

fn validate_key(key: &PKey<Private>) -> Result<(), String> {
    let rsa: Rsa<Private> = key
        .rsa()
        .map_err(|_| "private key must be RSA".to_owned())?;
    if rsa.size() * 8 < 2048 {
        return Err(format!(
            "RSA key is {} bits; at least 2048 required",
            rsa.size() * 8
        ));
    }
    if rsa.size() * 8 > 4096 {
        return Err(format!(
            "RSA key is {} bits; at most 4096 supported",
            rsa.size() * 8
        ));
    }
    let mut signer = Signer::new(MessageDigest::sha256(), key)
        .map_err(|e| format!("RSA-SHA256 is unavailable from system OpenSSL: {e}"))?;
    signer
        .update(b"dkim-lite startup self-test")
        .and_then(|_| signer.sign_to_vec())
        .map_err(|e| format!("RSA-SHA256 startup self-test failed: {e}"))?;
    Ok(())
}

fn validate_dns_name(kind: &str, value: &str) -> Result<String, String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(format!("invalid {kind}: {value}"));
    }
    Ok(value)
}

fn parse_listen(value: &str) -> Result<ListenAddr, String> {
    if let Some(path) = value.strip_prefix("unix:") {
        if !path.starts_with('/') || path.as_bytes().contains(&0) {
            return Err("unix listen path must be absolute".to_owned());
        }
        return Ok(ListenAddr::Unix(PathBuf::from(path)));
    }
    if let Some(addr) = value.strip_prefix("tcp:") {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| format!("invalid TCP listen address: {addr}"))?;
        if !matches!(addr.ip(), IpAddr::V4(ip) if ip.is_loopback())
            && !matches!(addr.ip(), IpAddr::V6(ip) if ip.is_loopback())
        {
            return Err("TCP listener must use a loopback address".to_owned());
        }
        return Ok(ListenAddr::Tcp(addr));
    }
    Err("listen must start with unix: or tcp:".to_owned())
}

pub fn check_fips_environment(required: bool) -> Result<(), String> {
    if !required {
        return Ok(());
    }
    let path = Path::new("/proc/sys/crypto/fips_enabled");
    match fs::read_to_string(path) {
        Ok(value) if value.trim() == "1" => {
            if openssl_fips_enabled() {
                Ok(())
            } else {
                Err("kernel FIPS mode is enabled but system OpenSSL is not in FIPS mode".to_owned())
            }
        }
        Ok(value) if value.trim() == "0" => {
            Err("system FIPS mode is disabled; dkim-lite production builds require FIPS".to_owned())
        }
        Ok(value) => Err(format!(
            "unexpected FIPS status in {}: {value:?}",
            path.display()
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot inspect {}: {e}", path.display())),
    }
}

fn openssl_fips_enabled() -> bool {
    unsafe {
        // OpenSSL 3 (RHEL 9/10): query the active default provider properties.
        let symbol = libc::dlsym(
            libc::RTLD_DEFAULT,
            b"EVP_default_properties_is_fips_enabled\0".as_ptr() as *const c_char,
        );
        if !symbol.is_null() {
            let check: unsafe extern "C" fn(*mut c_void) -> libc::c_int =
                std::mem::transmute(symbol);
            return check(std::ptr::null_mut()) == 1;
        }

        // OpenSSL 1.1.1 FIPS (RHEL 8): use the legacy validated-module API.
        let symbol = libc::dlsym(libc::RTLD_DEFAULT, b"FIPS_mode\0".as_ptr() as *const c_char);
        if !symbol.is_null() {
            let check: unsafe extern "C" fn() -> libc::c_int = std::mem::transmute(symbol);
            return check() == 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_non_loopback_tcp() {
        assert!(parse_listen("tcp:0.0.0.0:8891").is_err());
        assert!(parse_listen("tcp:127.0.0.1:8891").is_ok());
        assert!(parse_listen("tcp:[::1]:8891").is_ok());
    }

    #[test]
    fn validates_names() {
        assert_eq!(
            validate_dns_name("domain", "Example.COM.").unwrap(),
            "example.com"
        );
        assert!(validate_dns_name("domain", "-bad.example").is_err());
    }

    #[test]
    fn fips_can_be_explicitly_disabled() {
        assert!(check_fips_environment(false).is_ok());
    }

    #[test]
    fn require_fips_defaults_true_and_parses_strict_boolean() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("dkim-lite-config-{nonce}"));
        fs::create_dir(&directory).unwrap();
        let key_path = directory.join("key.pem");
        let config_path = directory.join("dkim-lite.conf");
        let key = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
        fs::write(&key_path, key).unwrap();
        let base = format!(
            "domain=example.com\nselector=test\nprivate_key={}\nlisten=tcp:127.0.0.1:8891\n",
            key_path.display()
        );
        fs::write(&config_path, &base).unwrap();
        assert!(RuntimeConfig::load(&config_path).unwrap().require_fips);
        fs::write(&config_path, format!("{base}require_fips=false\n")).unwrap();
        assert!(!RuntimeConfig::load(&config_path).unwrap().require_fips);
        fs::write(&config_path, format!("{base}require_fips=yes\n")).unwrap();
        assert!(RuntimeConfig::load(&config_path).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
