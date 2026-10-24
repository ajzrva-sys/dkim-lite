#![cfg(unix)]

use openssl::rsa::Rsa;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Daemon {
    child: Child,
    directory: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        if wait_for_exit(&mut self.child, Duration::from_millis(500))
            .ok()
            .flatten()
            .is_none()
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate(daemon: &mut Daemon) {
    assert_eq!(
        unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = wait_for_exit(&mut daemon.child, Duration::from_secs(2)).unwrap();
    if status.is_none() {
        daemon.child.kill().unwrap();
        daemon.child.wait().unwrap();
    }
    assert!(
        status.is_some(),
        "daemon did not terminate within two seconds"
    );
    assert!(status.unwrap().success(), "daemon shutdown failed");
}

fn packet(stream: &mut impl Write, command: u8, payload: &[u8]) {
    let length = u32::try_from(payload.len() + 1).unwrap();
    stream.write_all(&length.to_be_bytes()).unwrap();
    stream.write_all(&[command]).unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn response(stream: &mut impl Read) -> Vec<u8> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut value = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut value).unwrap();
    value
}

fn header(stream: &mut (impl Read + Write), name: &[u8], value: &[u8]) {
    let mut payload = Vec::new();
    payload.extend_from_slice(name);
    payload.push(0);
    payload.extend_from_slice(value);
    payload.push(0);
    packet(stream, b'L', &payload);
    assert_eq!(response(stream), vec![b'c']);
}

fn begin(stream: &mut (impl Read + Write)) {
    packet(stream, b'M', b"<alice@example.com>\0");
    assert_eq!(response(stream), vec![b'c']);
    header(stream, b"From", b"Alice <alice@example.com>");
    header(stream, b"Subject", b"daemon integration");
}

fn finish(stream: &mut (impl Read + Write)) -> String {
    packet(stream, b'B', b"body\r\n");
    assert_eq!(response(stream), vec![b'c']);
    packet(stream, b'E', &[]);
    let action = response(stream);
    assert_eq!(action[0], b'i');
    assert_eq!(response(stream), vec![b'a']);
    String::from_utf8_lossy(&action).into_owned()
}

fn write_config(path: &Path, socket: &Path, key: &Path, selector: &str) {
    fs::write(
        path,
        format!(
            "domain=example.com\nselector={selector}\nprivate_key={}\nlisten=unix:{}\nrequire_fips=false\n",
            key.display(),
            socket.display()
        ),
    )
    .unwrap();
}

#[test]
fn unix_listener_reload_is_atomic_and_restartable() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("dkim-lite-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let socket = directory.join("milter.sock");
    let config = directory.join("dkim-lite.conf");
    let key1 = directory.join("one.pem");
    let key2 = directory.join("two.pem");
    fs::write(
        &key1,
        Rsa::generate(2048).unwrap().private_key_to_pem().unwrap(),
    )
    .unwrap();
    fs::write(
        &key2,
        Rsa::generate(2048).unwrap().private_key_to_pem().unwrap(),
    )
    .unwrap();
    write_config(&config, &socket, &key1, "one");

    let child = Command::new(env!("CARGO_BIN_EXE_dkim-lite"))
        .args(["--config", config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut daemon = Daemon { child, directory };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists());

    let mut stream = UnixStream::connect(&socket).unwrap();
    let mut options = Vec::new();
    options.extend_from_slice(&6u32.to_be_bytes());
    options.extend_from_slice(&0x11u32.to_be_bytes());
    options.extend_from_slice(&0u32.to_be_bytes());
    packet(&mut stream, b'O', &options);
    assert_eq!(response(&mut stream)[0], b'O');

    begin(&mut stream);
    write_config(&config, &socket, &key2, "two");
    unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGHUP) };
    thread::sleep(Duration::from_millis(300));
    assert!(finish(&mut stream).contains("s=one;"));

    begin(&mut stream);
    assert!(finish(&mut stream).contains("s=two;"));

    packet(&mut stream, b'M', b"<alice@example.com>\0");
    assert_eq!(response(&mut stream), vec![b'c']);
    header(
        &mut stream,
        b"From",
        b"attacker@other.test (note <user@example.com>)",
    );
    packet(&mut stream, b'E', &[]);
    // Ineligible mail is accepted unchanged, with no signature action first.
    assert_eq!(response(&mut stream), vec![b'a']);

    packet(&mut stream, b'M', b"<alice@example.com>\0");
    assert_eq!(response(&mut stream), vec![b'c']);
    header(
        &mut stream,
        b"From",
        b"alice@example.com (note <other@other.test>)",
    );
    assert!(finish(&mut stream).contains("s=two;"));

    if dkim_lite::config::check_fips_environment(true).is_err() {
        write_config(&config, &socket, &key1, "rejected");
        let required = fs::read_to_string(&config)
            .unwrap()
            .replace("require_fips=false", "require_fips=true");
        fs::write(&config, required).unwrap();
        unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGHUP) };
        thread::sleep(Duration::from_millis(300));
        begin(&mut stream);
        assert!(finish(&mut stream).contains("s=two;"));
        write_config(&config, &socket, &key2, "two");
    }
    packet(&mut stream, b'Q', &[]);
    drop(stream);

    terminate(&mut daemon);
    daemon.child = Command::new(env!("CARGO_BIN_EXE_dkim-lite"))
        .args(["--config", config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut restarted = None;
    while restarted.is_none() && Instant::now() < deadline {
        restarted = UnixStream::connect(&socket).ok();
        if restarted.is_none() {
            thread::sleep(Duration::from_millis(20));
        }
    }
    assert!(restarted.is_some());
    let mut restarted = restarted.unwrap();
    packet(&mut restarted, b'O', &options);
    assert_eq!(response(&mut restarted)[0], b'O');
    packet(&mut restarted, b'Q', &[]);
    drop(restarted);

    terminate(&mut daemon);
}

trait MilterStream: Read + Write {}
impl<T: Read + Write> MilterStream for T {}

#[derive(Clone)]
enum Endpoint {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Endpoint {
    fn connect(&self) -> io::Result<Box<dyn MilterStream>> {
        let timeout = Some(Duration::from_secs(2));
        match self {
            Self::Tcp(address) => {
                let stream = TcpStream::connect_timeout(address, Duration::from_millis(100))?;
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)?;
                Ok(Box::new(stream))
            }
            Self::Unix(path) => {
                let stream = UnixStream::connect(path)?;
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)?;
                Ok(Box::new(stream))
            }
        }
    }

    fn listen(&self) -> String {
        match self {
            Self::Tcp(address) => format!("tcp:{address}"),
            Self::Unix(path) => format!("unix:{}", path.display()),
        }
    }
}

struct Churn {
    stop: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    producers: Vec<thread::JoinHandle<()>>,
}

impl Churn {
    fn start(endpoint: &Endpoint) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let producers = (0..4)
            .map(|_| {
                let endpoint = endpoint.clone();
                let stop = stop.clone();
                let connections = connections.clone();
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(mut stream) = endpoint.connect() {
                            // Retain the peer until the worker processes Quit.
                            // macOS rejects timeout configuration on a Unix
                            // socket whose peer closed before it was accepted.
                            if stream.write_all(&[0, 0, 0, 1, b'Q']).is_ok()
                                && matches!(stream.read(&mut [0]), Ok(0))
                            {
                                connections.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                })
            })
            .collect();
        Self {
            stop,
            connections,
            producers,
        }
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for producer in self.producers.drain(..) {
            producer.join().unwrap();
        }
    }
}

impl Drop for Churn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn spawn_daemon(config: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_dkim-lite"))
        .args(["--config", config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // Queue-full drops are expected while the producers saturate the listener.
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn connect_ready(endpoint: &Endpoint) -> Box<dyn MilterStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(stream) = endpoint.connect() {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "daemon listener did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn negotiate(stream: &mut impl MilterStream) {
    let mut options = Vec::new();
    options.extend_from_slice(&6u32.to_be_bytes());
    options.extend_from_slice(&0x11u32.to_be_bytes());
    options.extend_from_slice(&0u32.to_be_bytes());
    packet(stream, b'O', &options);
    assert_eq!(response(stream)[0], b'O');
}

fn shutdown_under_connection_churn(tcp: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let transport = if tcp { "tcp" } else { "unix" };
    let directory =
        std::env::temp_dir().join(format!("dkim-{transport}-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let endpoint = if tcp {
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        Endpoint::Tcp(reservation.local_addr().unwrap())
    } else {
        Endpoint::Unix(directory.join("milter.sock"))
    };
    let key = directory.join("key.pem");
    fs::write(
        &key,
        Rsa::generate(2048).unwrap().private_key_to_pem().unwrap(),
    )
    .unwrap();
    let config = directory.join("dkim-lite.conf");
    fs::write(
        &config,
        format!(
            "domain=example.com\nselector=churn\nprivate_key={}\nlisten={}\nrequire_fips=false\n",
            key.display(),
            endpoint.listen()
        ),
    )
    .unwrap();
    let child = spawn_daemon(&config);
    let mut daemon = Daemon { child, directory };
    let mut client = connect_ready(&endpoint);
    negotiate(&mut client);
    begin(&mut client);
    assert!(finish(&mut client).contains("s=churn;"));

    let churn = Churn::start(&endpoint);
    let deadline = Instant::now() + Duration::from_secs(5);
    while churn.connections.load(Ordering::Relaxed) < 128 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let connections = churn.connections.load(Ordering::Relaxed);
    // Finish the active protocol session so worker cleanup does not depend on
    // the independent idle-connection timeout. Producers stay active until exit.
    packet(&mut client, b'Q', &[]);
    terminate(&mut daemon);
    churn.finish();
    assert!(
        connections >= 128,
        "connection producers made insufficient progress"
    );
    let closed = client.read(&mut [0]);
    assert!(
        matches!(closed, Ok(0))
            || matches!(closed, Err(error) if error.kind() == io::ErrorKind::ConnectionReset),
        "worker left the completed client connection open"
    );
    drop(client);

    // Successful exit includes joining every worker. Rebind the same endpoint
    // and sign a message to also detect leaked listener/connection resources.
    daemon.child = spawn_daemon(&config);
    let mut restarted = connect_ready(&endpoint);
    negotiate(&mut restarted);
    begin(&mut restarted);
    assert!(finish(&mut restarted).contains("s=churn;"));
    packet(&mut restarted, b'Q', &[]);
    drop(restarted);
    terminate(&mut daemon);
}

#[test]
fn tcp_listener_shutdown_under_connection_churn_is_restartable() {
    shutdown_under_connection_churn(true);
}

#[test]
fn unix_listener_shutdown_under_connection_churn_is_restartable() {
    shutdown_under_connection_churn(false);
}
