use dkim_lite::config::check_fips_environment;
use openssl::rsa::Rsa;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn required_fips_cli_matches_environment_and_preserves_files_on_failure() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("dkim-lite-fips-{nonce}"));
    fs::create_dir(&directory).unwrap();
    let binary = env!("CARGO_BIN_EXE_dkim-lite");
    let expected = check_fips_environment(true);
    let kernel_confirmed = fs::read_to_string("/proc/sys/crypto/fips_enabled")
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    if !kernel_confirmed {
        assert!(
            expected.is_err(),
            "unconfirmed kernel FIPS status must reject"
        );
    }

    // Omitted and explicit true must have the same required-FIPS policy.
    for explicit in [false, true] {
        let key = directory.join(format!("generated-{explicit}.pem"));
        let mut command = Command::new(binary);
        command.args([
            "generate-key",
            "--domain",
            "example.com",
            "--selector",
            "test",
            "--private-key",
            key.to_str().unwrap(),
        ]);
        if explicit {
            command.args(["--require-fips", "true"]);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.success(), expected.is_ok());
        assert_eq!(key.exists(), expected.is_ok());
        if let Err(error) = &expected {
            assert!(String::from_utf8_lossy(&output.stderr).contains(error));
            assert!(output.stdout.is_empty());
        }
    }

    let key = directory.join("existing.pem");
    let original = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
    fs::write(&key, &original).unwrap();
    let config = directory.join("signer.conf");
    let base = format!(
        "domain=example.com\nselector=test\nprivate_key={}\nlisten=unix:{}\n",
        key.display(),
        directory.join("signer.sock").display(),
    );
    for policy in ["", "require_fips=true\n", "require_fips=false\n"] {
        fs::write(&config, format!("{base}{policy}")).unwrap();
        let output = Command::new(binary)
            .args(["--check-config", "--config", config.to_str().unwrap()])
            .output()
            .unwrap();
        let should_succeed = policy == "require_fips=false\n" || expected.is_ok();
        assert_eq!(output.status.success(), should_succeed);
        if !should_succeed {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected.as_ref().unwrap_err())
            );
        }
        assert_eq!(fs::read(&key).unwrap(), original);
        assert!(!directory.join("signer.sock").exists());
    }
    fs::remove_dir_all(directory).unwrap();
}
