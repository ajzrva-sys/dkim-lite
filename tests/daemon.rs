#![cfg(unix)]

use openssl::rsa::Rsa;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Daemon {
    child: Child,
    directory: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn packet(stream: &mut UnixStream, command: u8, payload: &[u8]) {
    let length = u32::try_from(payload.len() + 1).unwrap();
    stream.write_all(&length.to_be_bytes()).unwrap();
    stream.write_all(&[command]).unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn response(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut value = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut value).unwrap();
    value
}

fn header(stream: &mut UnixStream, name: &[u8], value: &[u8]) {
    let mut payload = Vec::new();
    payload.extend_from_slice(name);
    payload.push(0);
    payload.extend_from_slice(value);
    payload.push(0);
    packet(stream, b'L', &payload);
    assert_eq!(response(stream), vec![b'c']);
}

fn begin(stream: &mut UnixStream) {
    packet(stream, b'M', b"<alice@example.com>\0");
    assert_eq!(response(stream), vec![b'c']);
    header(stream, b"From", b"Alice <alice@example.com>");
    header(stream, b"Subject", b"daemon integration");
}

fn finish(stream: &mut UnixStream) -> String {
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
    packet(&mut stream, b'Q', &[]);
    drop(stream);

    let shutdown_started = Instant::now();
    unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGTERM) };
    assert!(daemon.child.wait().unwrap().success());
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(2),
        "daemon shutdown exceeded the bounded poll interval"
    );
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

    let shutdown_started = Instant::now();
    unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGTERM) };
    assert!(daemon.child.wait().unwrap().success());
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(2),
        "restarted daemon shutdown exceeded the bounded poll interval"
    );
}
