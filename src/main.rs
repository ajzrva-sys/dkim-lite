use dkim_lite::config::{check_fips_environment, RuntimeConfig};
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
    let (config_path, check_only) = parse_args(&args)?;

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

fn parse_args(args: &[String]) -> Result<(PathBuf, bool), String> {
    let mut config = None;
    let mut check = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--version" => {
                println!("dkim-lite {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
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
    Ok((
        config.unwrap_or_else(|| PathBuf::from("/etc/dkim-lite/dkim-lite.conf")),
        check,
    ))
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
