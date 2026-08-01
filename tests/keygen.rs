use openssl::pkey::PKey;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("dkim-lite-cli-keygen-{nonce}"));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn command_generates_key_and_refuses_overwrite() {
    let directory = directory();
    let key_path = directory.join("mail.pem");
    let binary = env!("CARGO_BIN_EXE_dkim-lite");
    let arguments = [
        "generate-key",
        "--domain",
        "example.com",
        "--selector",
        "mail2026",
        "--private-key",
        key_path.to_str().unwrap(),
        "--require-fips",
        "false",
    ];

    let output = Command::new(binary).args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("generated 2048-bit RSA private key"));
    assert!(stdout.contains("mail2026._domainkey.example.com. IN TXT"));
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let key = PKey::private_key_from_pem(&fs::read(&key_path).unwrap()).unwrap();
    assert_eq!(key.bits(), 2048);

    let second = Command::new(binary).args(arguments).output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8(second.stderr)
        .unwrap()
        .contains("refusing to overwrite"));
    fs::remove_dir_all(directory).unwrap();
}
