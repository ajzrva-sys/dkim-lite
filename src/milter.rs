use crate::config::{ListenAddr, RuntimeConfig};
use crate::dkim::{self, BodyCanonicalizer, Header};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PACKET: usize = 1024 * 1024;
const MAX_HEADERS: usize = 1_000;
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const ACTION_ADD_HEADER: u32 = 0x0000_0001;
const ACTION_CHANGE_HEADER: u32 = 0x0000_0010;

#[derive(Default)]
struct MessageState {
    config: Option<Arc<RuntimeConfig>>,
    headers: Vec<Header>,
    header_bytes: usize,
    body: BodyCanonicalizer,
    error: Option<String>,
}

impl MessageState {
    fn begin(&mut self, config: Arc<RuntimeConfig>) {
        *self = Self {
            config: Some(config),
            ..Self::default()
        };
    }

    fn fail(&mut self, reason: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(reason.into());
        }
    }
}

enum Connection {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

impl Connection {
    fn set_blocking(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(false),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_nonblocking(false),
        }
    }

    fn set_timeouts(&self) -> io::Result<()> {
        let timeout = Some(CONNECTION_TIMEOUT);
        match self {
            Self::Tcp(stream) => {
                // Milter is a synchronous request/response protocol with many small
                // packets.  Avoid delayed-ACK stalls on TCP listeners.
                stream.set_nodelay(true)?;
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)
            }
            #[cfg(unix)]
            Self::Unix(stream) => {
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)
            }
        }
    }
}

pub fn serve(
    initial: Arc<RuntimeConfig>,
    active: Arc<RwLock<Arc<RuntimeConfig>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    workers: usize,
) -> Result<(), String> {
    let listener = Listener::bind(&initial.listen)?;
    let (sender, receiver) = mpsc::sync_channel::<Connection>(workers * 2);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut worker_handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let receiver = receiver.clone();
        let active = active.clone();
        let worker_shutdown = shutdown.clone();
        worker_handles.push(thread::spawn(move || loop {
            let connection = match receiver.lock().expect("worker queue poisoned").recv() {
                Ok(connection) => connection,
                Err(_) => break,
            };
            if worker_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Err(error) = handle_connection(connection, &active) {
                eprintln!("dkim-lite: milter connection closed: {error}");
            }
        }));
    }

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok(connection) => {
                if sender.try_send(connection).is_err() {
                    eprintln!("dkim-lite: worker queue full; dropping milter connection");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(format!("listener failed: {error}")),
        }
    }
    drop(sender);
    for worker in worker_handles {
        if worker.join().is_err() {
            return Err("milter worker thread panicked".to_owned());
        }
    }
    Ok(())
}

enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    fn bind(address: &ListenAddr) -> Result<Self, String> {
        match address {
            ListenAddr::Tcp(address) => {
                let listener = TcpListener::bind(address)
                    .map_err(|e| format!("cannot bind TCP listener {address}: {e}"))?;
                listener
                    .set_nonblocking(true)
                    .map_err(|e| format!("cannot configure TCP listener: {e}"))?;
                Ok(Self::Tcp(listener))
            }
            ListenAddr::Unix(path) => {
                #[cfg(unix)]
                {
                    if let Ok(metadata) = fs::symlink_metadata(path) {
                        if !metadata.file_type().is_socket() {
                            return Err(format!(
                                "refusing to replace non-socket path {}",
                                path.display()
                            ));
                        }
                        fs::remove_file(path).map_err(|e| {
                            format!("cannot remove stale socket {}: {e}", path.display())
                        })?;
                    }
                    let listener = UnixListener::bind(path)
                        .map_err(|e| format!("cannot bind Unix socket {}: {e}", path.display()))?;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(|e| {
                        format!("cannot set permissions on {}: {e}", path.display())
                    })?;
                    listener
                        .set_nonblocking(true)
                        .map_err(|e| format!("cannot configure Unix listener: {e}"))?;
                    Ok(Self::Unix(listener))
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err("Unix sockets are unsupported on this platform".to_owned())
                }
            }
        }
    }

    fn accept(&self) -> io::Result<Connection> {
        match self {
            Self::Tcp(listener) => listener.accept().and_then(|(stream, _)| {
                let connection = Connection::Tcp(stream);
                connection.set_blocking()?;
                connection.set_timeouts()?;
                Ok(connection)
            }),
            #[cfg(unix)]
            Self::Unix(listener) => listener.accept().and_then(|(stream, _)| {
                let connection = Connection::Unix(stream);
                connection.set_blocking()?;
                connection.set_timeouts()?;
                Ok(connection)
            }),
        }
    }
}

fn handle_connection(
    mut stream: Connection,
    active: &Arc<RwLock<Arc<RuntimeConfig>>>,
) -> Result<(), String> {
    let mut state = MessageState::default();
    let mut actions = 0u32;
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err("milter connection lifetime exceeded".to_owned());
        }
        let packet = match read_packet(&mut stream) {
            Ok(Some(packet)) => packet,
            Ok(None) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let (&command, payload) = packet
            .split_first()
            .ok_or_else(|| "empty milter packet".to_owned())?;
        match command {
            b'O' => {
                if payload.len() != 12 {
                    return Err("invalid option negotiation packet".to_owned());
                }
                let version = u32::from_be_bytes(payload[0..4].try_into().unwrap()).min(6);
                let offered = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                actions = offered & (ACTION_ADD_HEADER | ACTION_CHANGE_HEADER);
                let mut response = Vec::with_capacity(12);
                response.extend_from_slice(&version.to_be_bytes());
                response.extend_from_slice(&actions.to_be_bytes());
                response.extend_from_slice(&0u32.to_be_bytes());
                write_packet(&mut stream, b'O', &response)?;
            }
            b'M' => {
                let config = active
                    .read()
                    .map_err(|_| "configuration lock poisoned")?
                    .clone();
                state.begin(config);
                write_status(&mut stream, b'c')?;
            }
            b'L' => {
                if state.config.is_none() {
                    let config = active
                        .read()
                        .map_err(|_| "configuration lock poisoned")?
                        .clone();
                    state.begin(config);
                }
                receive_header(&mut state, payload);
                write_status(&mut stream, b'c')?;
            }
            b'B' => {
                if state.config.is_none() {
                    state.fail("body received before message start");
                } else if state.error.is_none() {
                    state.body.update(payload);
                }
                write_status(&mut stream, b'c')?;
            }
            b'E' => {
                finish_message(&mut stream, &mut state, actions)?;
                state = MessageState::default();
            }
            b'A' => {
                state = MessageState::default();
            }
            b'Q' | b'K' => return Ok(()),
            b'D' => {
                // Macro definition packets are attached to the following command and
                // never receive their own response.
            }
            b'C' | b'H' | b'R' | b'T' | b'N' | b'U' => {
                write_status(&mut stream, b'c')?;
            }
            _ => return Err(format!("unsupported milter command 0x{command:02x}")),
        }
    }
}

fn receive_header(state: &mut MessageState, payload: &[u8]) {
    if state.error.is_some() {
        return;
    }
    let Some(separator) = payload.iter().position(|b| *b == 0) else {
        state.fail("malformed milter header packet");
        return;
    };
    let name = &payload[..separator];
    let value_with_nul = &payload[separator + 1..];
    let Some(value) = value_with_nul.strip_suffix(&[0]) else {
        state.fail("malformed milter header value");
        return;
    };
    if value.contains(&0) {
        state.fail("malformed milter header value");
        return;
    }
    state.header_bytes = state.header_bytes.saturating_add(name.len() + value.len());
    if state.headers.len() >= MAX_HEADERS || state.header_bytes > MAX_HEADER_BYTES {
        state.fail("message header limit exceeded");
        return;
    }
    match Header::new(name, value) {
        Ok(header) => state.headers.push(header),
        Err(error) => state.fail(error),
    }
}

fn finish_message(
    stream: &mut Connection,
    state: &mut MessageState,
    actions: u32,
) -> Result<(), String> {
    if state.config.is_none() {
        state.fail("end of message received before message start");
    }
    if state.error.is_none() && actions & (ACTION_ADD_HEADER | ACTION_CHANGE_HEADER) == 0 {
        state.fail("MTA did not grant permission to add headers");
    }
    if state.error.is_none() {
        let body = std::mem::take(&mut state.body).finish();
        let config = state
            .config
            .as_ref()
            .ok_or("message has no configuration")?;
        match dkim::sign(config, &state.headers, body) {
            Ok(value) => {
                if actions & ACTION_CHANGE_HEADER != 0 {
                    let mut payload = Vec::with_capacity(value.len() + 24);
                    payload.extend_from_slice(&0u32.to_be_bytes());
                    payload.extend_from_slice(b"DKIM-Signature\0");
                    payload.extend_from_slice(value.as_bytes());
                    payload.push(0);
                    write_packet(stream, b'i', &payload)?;
                } else {
                    let mut payload = Vec::with_capacity(value.len() + 20);
                    payload.extend_from_slice(b"DKIM-Signature\0");
                    payload.extend_from_slice(value.as_bytes());
                    payload.push(0);
                    write_packet(stream, b'h', &payload)?;
                }
            }
            Err(error) => state.fail(error),
        }
    }
    if let Some(error) = &state.error {
        eprintln!("dkim-lite: accepting message unsigned: {error}");
    }
    write_status(stream, b'a')
}

fn read_packet(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid milter packet length",
        ));
    }
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet)?;
    Ok(Some(packet))
}

/// Entry point used by the separately packaged fuzz harness.
#[doc(hidden)]
pub fn fuzz_milter_frame(data: &[u8]) {
    let _ = read_packet(&mut io::Cursor::new(data));
}

fn write_status(stream: &mut impl Write, status: u8) -> Result<(), String> {
    write_packet(stream, status, &[])
}

fn write_packet(stream: &mut impl Write, command: u8, payload: &[u8]) -> Result<(), String> {
    let length = 1usize
        .checked_add(payload.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| "milter response is too large".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(&[command]))
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("cannot write milter response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ListenAddr;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    #[test]
    fn packet_reader_handles_partial_reads() {
        let bytes = [0, 0, 0, 4, b'B', 1, 2, 3];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(
            read_packet(&mut reader).unwrap().unwrap(),
            vec![b'B', 1, 2, 3]
        );
    }

    #[test]
    fn tcp_connections_disable_nagle_delays() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let connection = Connection::Tcp(server);
        connection.set_timeouts().unwrap();
        match connection {
            Connection::Tcp(stream) => assert!(stream.nodelay().unwrap()),
            #[cfg(unix)]
            Connection::Unix(_) => unreachable!(),
        }
        drop(client);
    }

    #[test]
    fn malformed_header_becomes_message_error() {
        let mut state = MessageState::default();
        receive_header(&mut state, b"From: a@example.com");
        assert!(state.error.is_some());
    }

    #[test]
    fn rejects_empty_and_oversized_packets_before_allocation() {
        for length in [0u32, (MAX_PACKET as u32) + 1] {
            let mut reader = io::Cursor::new(length.to_be_bytes());
            assert_eq!(
                read_packet(&mut reader).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn header_limits_fail_the_message_without_growing_state() {
        let mut state = MessageState::default();
        let value = vec![b'a'; MAX_HEADER_BYTES];
        let mut packet = b"Subject\0".to_vec();
        packet.extend_from_slice(&value);
        packet.push(0);
        receive_header(&mut state, &packet);
        assert!(state.error.is_some());
        assert!(state.headers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn complete_milter_exchange_adds_signature() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let config = Arc::new(RuntimeConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            private_key: PathBuf::from("unused"),
            listen: ListenAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8891)),
            require_fips: false,
            key: Arc::new(key),
        });
        let active = Arc::new(RwLock::new(config));
        let (server, mut client) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || {
            handle_connection(Connection::Unix(server), &active).unwrap();
        });

        let mut options = Vec::new();
        options.extend_from_slice(&6u32.to_be_bytes());
        options.extend_from_slice(&(ACTION_ADD_HEADER | ACTION_CHANGE_HEADER).to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
        write_packet(&mut client, b'O', &options).unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap()[0], b'O');

        // Macro definitions have no response; the next packet read must be MAIL's response.
        write_packet(&mut client, b'D', b"M{i}\0ABC123\0").unwrap();
        write_packet(&mut client, b'M', b"<alice@example.com>\0").unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'c']);

        for (name, value) in [
            (b"From".as_slice(), b"Alice <alice@example.com>".as_slice()),
            (b"Subject".as_slice(), b"milter test".as_slice()),
        ] {
            let mut header = Vec::new();
            header.extend_from_slice(name);
            header.push(0);
            header.extend_from_slice(value);
            header.push(0);
            write_packet(&mut client, b'L', &header).unwrap();
            assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'c']);
        }
        write_packet(&mut client, b'N', &[]).unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'c']);
        write_packet(&mut client, b'B', b"hello\r\n").unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'c']);
        write_packet(&mut client, b'E', &[]).unwrap();
        let action = read_packet(&mut client).unwrap().unwrap();
        assert_eq!(action[0], b'i');
        assert!(action
            .windows(b"DKIM-Signature".len())
            .any(|window| window == b"DKIM-Signature"));
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'a']);

        write_packet(&mut client, b'Q', &[]).unwrap();
        handle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn abort_resets_state_and_connection_can_be_reused() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let config = Arc::new(RuntimeConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            private_key: PathBuf::from("unused"),
            listen: ListenAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8891)),
            require_fips: false,
            key: Arc::new(key),
        });
        let active = Arc::new(RwLock::new(config));
        let (server, mut client) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || {
            handle_connection(Connection::Unix(server), &active).unwrap();
        });

        let mut options = Vec::new();
        options.extend_from_slice(&6u32.to_be_bytes());
        options.extend_from_slice(&ACTION_ADD_HEADER.to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
        write_packet(&mut client, b'O', &options).unwrap();
        read_packet(&mut client).unwrap();

        write_packet(&mut client, b'M', b"<bad@example.com>\0").unwrap();
        read_packet(&mut client).unwrap();
        write_packet(&mut client, b'L', b"From\0broken\0").unwrap();
        read_packet(&mut client).unwrap();
        write_packet(&mut client, b'A', &[]).unwrap();

        write_packet(&mut client, b'M', b"<alice@example.com>\0").unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'c']);
        write_packet(&mut client, b'L', b"From\0alice@example.com\0").unwrap();
        read_packet(&mut client).unwrap();
        write_packet(&mut client, b'B', b"ok\r\n").unwrap();
        read_packet(&mut client).unwrap();
        write_packet(&mut client, b'E', &[]).unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap()[0], b'h');
        assert_eq!(read_packet(&mut client).unwrap().unwrap(), vec![b'a']);
        write_packet(&mut client, b'Q', &[]).unwrap();
        handle.join().unwrap();
    }
}
