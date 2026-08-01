use dkim_lite::config::{check_fips_environment, RuntimeConfig};
use dkim_lite::keygen::{self, GenerateOptions};
use dkim_lite::milter;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

static RELOAD: AtomicBool = AtomicBool::new(false);
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_reload(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

extern "C" fn on_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dkim-lite: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    match parse_args(&args)? {
        Command::Version => {
            println!("dkim-lite {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::GenerateKey(options) => {
            let generated = keygen::generate(options)?;
            println!(
                "generated {}-bit RSA private key: {}",
                generated.bits,
                generated.private_key.display()
            );
            println!("DNS record:\n{}", generated.dns_record);
            Ok(())
        }
        Command::Serve {
            config_path,
            check_only,
        } => run_daemon(config_path, check_only),
    }
}

fn run_daemon(config_path: PathBuf, check_only: bool) -> Result<(), String> {
    let initial = Arc::new(RuntimeConfig::load(&config_path)?);
    check_fips_environment(initial.require_fips)?;
    if check_only {
        println!("configuration valid");
        return Ok(());
    }
    install_signal_handlers()?;

    let active = Arc::new(RwLock::new(initial.clone()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let monitor_active = active.clone();
    let monitor_shutdown = shutdown.clone();
    let monitor_path = config_path.clone();
    let monitor = thread::spawn(move || {
        while !SHUTDOWN.load(Ordering::Relaxed) {
            if RELOAD.swap(false, Ordering::Relaxed) {
                match RuntimeConfig::load(&monitor_path) {
                    Ok(config) => {
                        let old_listen = monitor_active.read().ok().map(|c| c.listen.clone());
                        if let Err(error) = check_fips_environment(config.require_fips) {
                            eprintln!("dkim-lite: reload rejected: {error}");
                        } else if old_listen.as_ref() != Some(&config.listen) {
                            eprintln!(
                                "dkim-lite: reload rejected: listen cannot change without restart"
                            );
                        } else if let Ok(mut active) = monitor_active.write() {
                            *active = Arc::new(config);
                            eprintln!("dkim-lite: configuration reloaded");
                        }
                    }
                    Err(error) => eprintln!("dkim-lite: reload rejected: {error}"),
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        monitor_shutdown.store(true, Ordering::Relaxed);
    });

    let workers = thread::available_parallelism()
        .map_or(4, usize::from)
        .clamp(2, 32);
    let result = milter::serve(initial, active, shutdown, workers);
    SHUTDOWN.store(true, Ordering::Relaxed);
    let _ = monitor.join();
    result
}

enum Command {
    Serve {
        config_path: PathBuf,
        check_only: bool,
    },
    GenerateKey(GenerateOptions),
    Version,
    Help,
}

const USAGE: &str = "Usage:
  dkim-lite [--config PATH] [--check-config]
  dkim-lite generate-key --domain DOMAIN --selector SELECTOR --private-key PATH [--bits 2048|3072|4096] [--require-fips true|false]
  dkim-lite --version
";

fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.get(1).map(String::as_str) == Some("generate-key") {
        return parse_generate_args(&args[2..]);
    }
    let mut config = None;
    let mut check = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--version" if args.len() == 2 => return Ok(Command::Version),
            "--help" | "-h" if args.len() == 2 => return Ok(Command::Help),
            "--check-config" if !check => check = true,
            "--check-config" => return Err("duplicate --check-config".to_owned()),
            "--config" if config.is_none() => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--config requires a path".to_owned())?;
                config = Some(PathBuf::from(value));
            }
            "--config" => return Err("duplicate --config".to_owned()),
            value => return Err(format!("unknown argument: {value}")),
        }
        index += 1;
    }
    Ok(Command::Serve {
        config_path: config.unwrap_or_else(|| PathBuf::from("/etc/dkim-lite/dkim-lite.conf")),
        check_only: check,
    })
}

fn parse_generate_args(args: &[String]) -> Result<Command, String> {
    let mut domain = None;
    let mut selector = None;
    let mut private_key = None;
    let mut bits = None;
    let mut require_fips = None;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if matches!(option, "--help" | "-h") {
            return Ok(Command::Help);
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--domain" if domain.is_none() => domain = Some(value.clone()),
            "--selector" if selector.is_none() => selector = Some(value.clone()),
            "--private-key" if private_key.is_none() => private_key = Some(PathBuf::from(value)),
            "--bits" if bits.is_none() => {
                bits = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| "--bits requires an integer".to_owned())?,
                )
            }
            "--require-fips" if require_fips.is_none() => {
                require_fips = Some(match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err("--require-fips must be true or false".to_owned()),
                })
            }
            "--domain" | "--selector" | "--private-key" | "--bits" | "--require-fips" => {
                return Err(format!("duplicate {option}"))
            }
            _ => return Err(format!("unknown generate-key argument: {option}")),
        }
        index += 1;
    }
    Ok(Command::GenerateKey(GenerateOptions {
        domain: domain.ok_or_else(|| "generate-key requires --domain".to_owned())?,
        selector: selector.ok_or_else(|| "generate-key requires --selector".to_owned())?,
        private_key: private_key.ok_or_else(|| "generate-key requires --private-key".to_owned())?,
        bits: bits.unwrap_or(2048),
        require_fips: require_fips.unwrap_or(true),
    }))
}

fn install_signal_handlers() -> Result<(), String> {
    unsafe {
        if install_signal(libc::SIGHUP, on_reload)
            || install_signal(libc::SIGTERM, on_shutdown)
            || install_signal(libc::SIGINT, on_shutdown)
        {
            return Err("cannot install signal handlers".to_owned());
        }
    }
    Ok(())
}

unsafe fn install_signal(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) -> bool {
    let mut action: libc::sigaction = std::mem::zeroed();
    action.sa_sigaction = handler as *const () as libc::sighandler_t;
    libc::sigemptyset(&mut action.sa_mask);
    action.sa_flags = 0;
    libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_generate_key_defaults() {
        let command = parse_args(&strings(&[
            "dkim-lite",
            "generate-key",
            "--domain",
            "example.com",
            "--selector",
            "mail",
            "--private-key",
            "/tmp/mail.pem",
        ]))
        .unwrap();
        match command {
            Command::GenerateKey(options) => {
                assert_eq!(options.bits, 2048);
                assert!(options.require_fips);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_generate_key_overrides_strictly() {
        let command = parse_args(&strings(&[
            "dkim-lite",
            "generate-key",
            "--domain",
            "example.com",
            "--selector",
            "mail",
            "--private-key",
            "/tmp/mail.pem",
            "--bits",
            "4096",
            "--require-fips",
            "false",
        ]))
        .unwrap();
        match command {
            Command::GenerateKey(options) => {
                assert_eq!(options.bits, 4096);
                assert!(!options.require_fips);
            }
            _ => panic!("unexpected command"),
        }
        assert!(parse_args(&strings(&["dkim-lite", "generate-key", "--domain"])).is_err());
    }
}
