use crate::config::{check_fips_environment, validate_dns_name, validate_key};
use openssl::base64;
use openssl::pkey::{Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct GenerateOptions {
    pub domain: String,
    pub selector: String,
    pub private_key: PathBuf,
    pub bits: u32,
    pub require_fips: bool,
}

#[derive(Debug)]
pub struct GeneratedKey {
    pub domain: String,
    pub selector: String,
    pub private_key: PathBuf,
    pub bits: u32,
    pub dns_record: String,
}

pub fn generate(options: GenerateOptions) -> Result<GeneratedKey, String> {
    check_fips_environment(options.require_fips)?;
    let domain = validate_dns_name("domain", &options.domain)?;
    let selector = validate_dns_name("selector", &options.selector)?;
    if !matches!(options.bits, 2048 | 3072 | 4096) {
        return Err("RSA bits must be 2048, 3072, or 4096".to_owned());
    }
    if !options.private_key.is_absolute() {
        return Err("private key output path must be absolute".to_owned());
    }

    let key = generate_rsa(options.bits)?;
    validate_key(&key)?;
    let public_der = key
        .public_key_to_der()
        .map_err(|e| format!("cannot encode RSA public key: {e}"))?;
    let mut private_pem = key
        .private_key_to_pem_pkcs8()
        .map_err(|e| format!("cannot encode PKCS#8 private key: {e}"))?;
    let write_result = write_private_key(&options.private_key, &private_pem);
    private_pem.fill(0);
    write_result?;

    Ok(GeneratedKey {
        dns_record: dns_record(&domain, &selector, &public_der),
        domain,
        selector,
        private_key: options.private_key,
        bits: options.bits,
    })
}

fn generate_rsa(bits: u32) -> Result<PKey<Private>, String> {
    let mut context = PkeyCtx::new_id(Id::RSA)
        .map_err(|e| format!("system OpenSSL cannot initialize RSA key generation: {e}"))?;
    context
        .keygen_init()
        .and_then(|_| context.set_rsa_keygen_bits(bits))
        .map_err(|e| format!("system OpenSSL cannot configure RSA key generation: {e}"))?;
    context
        .keygen()
        .map_err(|e| format!("system OpenSSL RSA key generation failed: {e}"))
}

fn write_private_key(target: &Path, contents: &[u8]) -> Result<(), String> {
    if target.exists() {
        return Err(format!("refusing to overwrite {}", target.display()));
    }
    let parent = target
        .parent()
        .ok_or_else(|| "private key output path has no parent directory".to_owned())?;
    if !parent.is_dir() {
        return Err(format!(
            "parent directory does not exist: {}",
            parent.display()
        ));
    }
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "private key output filename is invalid".to_owned())?;

    let (temporary, mut file) = create_temporary(parent, name)?;
    let result = (|| -> Result<(), String> {
        file.write_all(contents)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        drop(file);
        fs::hard_link(&temporary, target).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite {}", target.display())
            } else {
                format!("cannot install private key {}: {e}", target.display())
            }
        })?;
        fs::remove_file(&temporary)
            .map_err(|e| format!("cannot remove temporary key file: {e}"))?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_temporary(parent: &Path, name: &str) -> Result<(PathBuf, File), String> {
    for _ in 0..100 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => {
                if let Err(error) =
                    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
                {
                    drop(file);
                    let _ = fs::remove_file(&temporary);
                    return Err(format!("cannot secure temporary key file: {error}"));
                }
                return Ok((temporary, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create temporary key file: {error}")),
        }
    }
    Err("cannot allocate a unique temporary key filename".to_owned())
}

fn dns_record(domain: &str, selector: &str, public_der: &[u8]) -> String {
    const CHUNK: usize = 180;
    let value = format!("v=DKIM1; k=rsa; p={}", base64::encode_block(public_der));
    let strings = value
        .as_bytes()
        .chunks(CHUNK)
        .map(|chunk| format!("\"{}\"", String::from_utf8_lossy(chunk)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{selector}._domainkey.{domain}. IN TXT {strings}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("dkim-lite-keygen-{nonce}"));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn generates_secure_pkcs8_key_and_dns_record() {
        let directory = directory();
        let target = directory.join("selector.pem");
        let generated = generate(GenerateOptions {
            domain: "Example.COM.".to_owned(),
            selector: "Mail2026".to_owned(),
            private_key: target.clone(),
            bits: 2048,
            require_fips: false,
        })
        .unwrap();

        let metadata = fs::metadata(&target).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let key = PKey::private_key_from_pem(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(key.bits(), 2048);
        assert_eq!(generated.domain, "example.com");
        assert_eq!(generated.selector, "mail2026");
        assert!(generated
            .dns_record
            .starts_with("mail2026._domainkey.example.com. IN TXT \"v=DKIM1; k=rsa; p="));
        assert!(generate(GenerateOptions {
            domain: "example.com".to_owned(),
            selector: "mail2026".to_owned(),
            private_key: target.clone(),
            bits: 2048,
            require_fips: false,
        })
        .unwrap_err()
        .contains("refusing to overwrite"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_unsupported_size_before_creating_file() {
        let directory = directory();
        let target = directory.join("key.pem");
        let error = generate(GenerateOptions {
            domain: "example.com".to_owned(),
            selector: "test".to_owned(),
            private_key: target.clone(),
            bits: 1024,
            require_fips: false,
        })
        .unwrap_err();
        assert!(error.contains("2048, 3072, or 4096"));
        assert!(!target.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
