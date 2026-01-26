use std::sync::Arc;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::path::Path;
use std::time::{Duration, SystemTime};
use chrono::{SecondsFormat, Utc};
use rustls::{
    client::{ClientConfig, ClientConnection},
    RootCertStore,
    Connection,
    ConnectionTrafficSecrets
};
use rustls::pki_types::{CertificateDer, ServerName, PrivateKeyDer};
use base64::Engine;
use rustls_openssl::default_provider;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;
use ::time::format_description::well_known::Rfc3339;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;

#[derive(Clone, Copy)]
enum Side {
    Client,
    Server,
    Info,
    Error,
}

struct Event {
    t: SystemTime,
    side: Side,
    msg: String,
}

impl Event {
    fn new(side: Side, msg: impl Into<String>) -> Self {
        Self { t: SystemTime::now(), side, msg: msg.into() }
    }

    fn fmt(&self) -> String {
        let dt = chrono::DateTime::<Utc>::from(self.t).to_rfc3339_opts(SecondsFormat::Millis, true);
        let tag = match self.side {
            Side::Client => "CLIENT",
            Side::Server => "SERVER",
            Side::Info   => "INFO",
            Side::Error  => "ERROR",
        };
        format!("{dt} {tag}: {}", self.msg)
    }
}

struct RecordingIo<'a> {
    inner: &'a mut TcpStream,
    events: &'a mut Vec<Event>,
}

impl<'a> RecordingIo<'a> {
    fn log(&mut self, side: Side, msg: impl Into<String>) {
        self.events.push(Event::new(side, msg));
    }
}

impl<'a> Read for RecordingIo<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            let enco = hex::encode(&buf);
            let displ = enco.trim_end_matches('0');
            self.events.push(Event::new(
                Side::Server,
                format!("read {n} byte(s) from server <<- hex={displ}"),
            ));
        }
        Ok(n)
    }
}

impl<'a> Write for RecordingIo<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            let enco = hex::encode(buf);
            let displ = enco.trim_end_matches('0');
            self.events.push(Event::new(
                Side::Client,
                format!("sent {n} byte(s) to server ->> hex={displ}"),
            ));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}


/// Function for debugging with mTLS.
pub fn auth_debug(target_arg: &str, roots_path: &str, client_auth_path: &str) {
    if let Err(e) = auth_run(target_arg, roots_path, client_auth_path) {
        eprintln!("{} ERROR: {e}", Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    }
}

/// Function for debugging with regular TLS.
pub fn debug(target_arg: &str, roots_path: &str) {
    if let Err(e) = run(target_arg, roots_path) {
        eprintln!("{} ERROR: {e}", Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    }
}

/// Function for debugging with regular TLS with secrets extraction.
pub fn extract_debug(target_arg: &str, roots_path: &str) {
    if let Err(e) = extract_run(target_arg, roots_path) {
        eprintln!("{} ERROR: {e}", Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    }
}

/// Function for debugging mTLS with secrets extraction.
pub fn extract_auth_debug(target_arg: &str, roots_path: &str, client_auth_path: &str) {
    if let Err(e) = extract_auth_run(target_arg, roots_path, client_auth_path) {
        eprintln!("{} ERROR: {e}", Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    }
}

/// Use a RusTLS client to debug a TLS connection.
/// Capture timing information, payloads, certificates, key exchange, cipher details, and more.
fn run(target_arg: &str, roots_path: &str) -> Result<(), Box<dyn Error>> {
    let (host, port) = parse_host_port(target_arg)?;
    let addr_str = format!("{host}:{port}");
    let sock_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("Failed to resolve host"))?;

    let root_store = load_roots(roots_path)?;
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider())).with_safe_default_protocol_versions()
        .unwrap().with_root_certificates(root_store);
    let config = builder.with_no_client_auth();
    let config = Arc::new(config);
    let mut events: Vec<Event> = Vec::new();
    events.push(Event::new(Side::Info, format!("Starting TLS handshake run against {addr_str}")));
    events.push(Event::new(Side::Client, format!("Resolving & connecting to {sock_addr}")));
    let mut tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    events.push(Event::new(Side::Client, "TCP connected"));

    let server_name: ServerName<'static> = host.clone().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid SNI name"))?;
    let mut conn = ClientConnection::new(config.clone(), server_name)?;

    let mut recorder = RecordingIo {
        inner: &mut tcp,
        events: &mut events
    };
    let mut flight = 0usize;

    while conn.is_handshaking() {
        let (rd, wr) = match conn.complete_io(&mut recorder) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
            Err(e) => {
                recorder.log(Side::Error, format!("I/O during handshake failed: {e}"));
                break;
            }
        };
        if wr > 0 {
            flight += 1;
            recorder.log(Side::Client, format!("Handshake flight #{flight} (TLS wrote {wr} byte(s))"));
        }
        if rd > 0 {
            recorder.log(Side::Server, format!("Received {rd} byte(s) during handshake"));
        }
        if rd == 0 && wr == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    drop(recorder);

    if let Some(kx) = conn.negotiated_key_exchange_group() {
        let named = kx.name();
        let iana: u16 = named.into();
        let fips = if kx.fips() { " (FIPS impl)" } else { "" };
        events.push(Event::new(
            Side::Info,
            format!("Key agreement group: {:?} (IANA 0x{:04x}){}", named, iana, fips),
        ));
    } else {
        events.push(Event::new(Side::Info, "Key agreement group: <none/unknown>"));
    }

    let mut cert_pem_path = None::<PathBuf>;
    if !conn.is_handshaking() {
        events.push(Event::new(Side::Info, "TLS handshake completed"));
        if let Some(v) = conn.protocol_version() {
            events.push(Event::new(Side::Info, format!("Negotiated TLS version: {:?}", v)));
        } else {
            events.push(Event::new(Side::Info, "Negotiated TLS version: <unknown>"));
        }
        if let Some(cs) = conn.negotiated_cipher_suite() {
            events.push(Event::new(Side::Info, format!("Cipher suite: {:?}", cs.suite())));
        } else {
            events.push(Event::new(Side::Info, "Cipher suite: <unknown>"));
        }
        if let Some(proto) = conn.alpn_protocol() {
            let printable = String::from_utf8_lossy(proto).to_string();
            events.push(Event::new(Side::Info, format!("ALPN protocol: {printable}")));
        } else {
            events.push(Event::new(Side::Info, "ALPN protocol: (none)"));
        }

        if let Some(chain) = conn.peer_certificates() {
            events.push(Event::new(Side::Info, format!("Server sent {} certificate(s)", chain.len())));
            let fname = artifact_filename("server-certs", &host, "pem");
            let pem_path = PathBuf::from(&fname);
            save_cert_chain_as_pem(&pem_path, chain)?;
            cert_pem_path = Some(pem_path.clone());
            events.push(Event::new(Side::Info, format!("Saved server cert chain bundle: ./{}", pem_path.display())));

            for (idx, cert) in chain.iter().enumerate() {
                match summarize_cert(cert) {
                    Ok(summary) => {
                        events.push(Event::new(
                            Side::Info,
                            format!("cert[{}]: {}", idx, summary),
                        ));
                    }
                    Err(e) => {
                        events.push(Event::new(
                            Side::Error,
                            format!("cert[{}]: Failed to parse: {e}", idx),
                        ));
                    }
                }
            }
        } else {
            events.push(Event::new(Side::Info, "No peer certificate chain available"));
        }

        conn.send_close_notify();

        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }

        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");

        let cert_path_text = cert_pem_path
            .as_ref()
            .map(|p| format!(", server certs: ./{}", p.display()))
            .unwrap_or_default();

        println!(
            "{} INFO: Run complete. Artifacts saved: log: ./{}{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name,
            cert_path_text
        );
    } else {
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }
        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");
        println!(
            "{} ERROR: Run finished with errors before handshake completion. Artifacts saved: log: ./{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name
        );
    }

    Ok(())
}

/// Just like 'run' but with mTLS.
fn auth_run(target_arg: &str, roots_path: &str, client_auth_path: &str) -> Result<(), Box<dyn Error>> {
    let (host, port) = parse_host_port(target_arg)?;
    let addr_str = format!("{host}:{port}");
    let sock_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("Failed to resolve host"))?;

    let root_store = load_roots(roots_path)?;
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider())).with_safe_default_protocol_versions()
        .unwrap().with_root_certificates(root_store);
    let config = {
        let (certs, key) = load_client_auth(client_auth_path)?;
        builder.with_client_auth_cert(certs, key)?
    };
    let config = Arc::new(config);
    let mut events: Vec<Event> = Vec::new();
    events.push(Event::new(Side::Info, format!("Starting TLS handshake run against {addr_str}")));
    events.push(Event::new(Side::Client, format!("Resolving & connecting to {sock_addr}")));
    let mut tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    events.push(Event::new(Side::Client, "TCP connected"));

    let server_name: ServerName<'static> = host.clone().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid SNI name"))?;
    let mut conn = ClientConnection::new(config.clone(), server_name)?;

    let mut recorder = RecordingIo {
        inner: &mut tcp,
        events: &mut events
    };
    let mut flight = 0usize;

    while conn.is_handshaking() {
        let (rd, wr) = match conn.complete_io(&mut recorder) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
            Err(e) => {
                recorder.log(Side::Error, format!("I/O during handshake failed: {e}"));
                break;
            }
        };
        if wr > 0 {
            flight += 1;
            recorder.log(Side::Client, format!("handshake flight #{flight} (TLS wrote {wr} byte(s))"));
        }
        if rd > 0 {
            recorder.log(Side::Server, format!("received {rd} byte(s) during handshake"));
        }
        if rd == 0 && wr == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    drop(recorder);

    if let Some(kx) = conn.negotiated_key_exchange_group() {
        let named = kx.name();
        let iana: u16 = named.into();
        let fips = if kx.fips() { " (FIPS impl)" } else { "" };
        events.push(Event::new(
            Side::Info,
            format!("Key agreement group: {:?} (IANA 0x{:04x}){}", named, iana, fips),
        ));
    } else {
        events.push(Event::new(Side::Info, "Key agreement group: <none/unknown>"));
    }

    let mut cert_pem_path = None::<PathBuf>;

    if !conn.is_handshaking() {
        events.push(Event::new(Side::Info, "TLS handshake completed"));
        if let Some(v) = conn.protocol_version() {
            events.push(Event::new(Side::Info, format!("Negotiated TLS version: {:?}", v)));
        } else {
            events.push(Event::new(Side::Info, "Negotiated TLS version: <unknown>"));
        }
        if let Some(cs) = conn.negotiated_cipher_suite() {
            events.push(Event::new(Side::Info, format!("Cipher suite: {:?}", cs.suite())));
        } else {
            events.push(Event::new(Side::Info, "Cipher suite: <unknown>"));
        }
        if let Some(proto) = conn.alpn_protocol() {
            let printable = String::from_utf8_lossy(proto).to_string();
            events.push(Event::new(Side::Info, format!("ALPN protocol: {printable}")));
        } else {
            events.push(Event::new(Side::Info, "ALPN protocol: (none)"));
        }

        if let Some(chain) = conn.peer_certificates() {
            events.push(Event::new(Side::Info, format!("Server sent {} certificate(s)", chain.len())));
            let fname = artifact_filename("server-certs", &host, "pem");
            let pem_path = PathBuf::from(&fname);
            save_cert_chain_as_pem(&pem_path, chain)?;
            cert_pem_path = Some(pem_path.clone());
            events.push(Event::new(Side::Info, format!("Saved server cert chain bundle: ./{}", pem_path.display())));

            for (idx, cert) in chain.iter().enumerate() {
                match summarize_cert(cert) {
                    Ok(summary) => {
                        events.push(Event::new(
                            Side::Info,
                            format!("cert[{}]: {}", idx, summary),
                        ));
                    }
                    Err(e) => {
                        events.push(Event::new(
                            Side::Error,
                            format!("cert[{}]: failed to parse: {e}", idx),
                        ));
                    }
                }
            }
        } else {
            events.push(Event::new(Side::Info, "No peer certificate chain available"));
        }

        conn.send_close_notify();

        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }

        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");

        let cert_path_text = cert_pem_path
            .as_ref()
            .map(|p| format!(", server certs: ./{}", p.display()))
            .unwrap_or_default();

        println!(
            "{} INFO: Run complete. Artifacts saved: log: ./{}{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name,
            cert_path_text
        );
    } else {
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }
        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");
        println!(
            "{} ERROR: Run finished with errors before handshake completion. Artifacts saved: log: ./{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name
        );
    }

    Ok(())
}

/// Like run but also extract secrets from protected memory.
fn extract_run(target_arg: &str, roots_path: &str) -> Result<(), Box<dyn Error>> {
    let (host, port) = parse_host_port(target_arg)?;
    let addr_str = format!("{host}:{port}");
    let sock_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("Failed to resolve host"))?;

    let root_store = load_roots(roots_path)?;
    let mut base = ClientConfig::builder_with_provider(Arc::new(default_provider())).with_safe_default_protocol_versions()
        .unwrap().with_root_certificates(root_store)
                                          .with_no_client_auth();
    base.enable_secret_extraction = true;
    let config = Arc::new(base);

    let mut events: Vec<Event> = Vec::new();
    events.push(Event::new(Side::Info, format!("Starting TLS handshake run against {addr_str}")));
    events.push(Event::new(Side::Client, format!("Resolving & connecting to {sock_addr}")));

    let mut tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    events.push(Event::new(Side::Client, "TCP connected"));

    let server_name: ServerName<'static> = host.clone().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid SNI name"))?;
    let mut conn = ClientConnection::new(config.clone(), server_name.clone())?;

    let mut recorder = RecordingIo {
        inner: &mut tcp,
        events: &mut events
    };
    let mut flight = 0usize;

    while conn.is_handshaking() {
        let (rd, wr) = match conn.complete_io(&mut recorder) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
            Err(e) => {
                recorder.log(Side::Error, format!("I/O during handshake failed: {e}"));
                break;
            }
        };
        if wr > 0 {
            flight += 1;
            recorder.log(Side::Client, format!("Handshake flight #{flight} (TLS wrote {wr} byte(s))"));
        }
        if rd > 0 {
            recorder.log(Side::Server, format!("Received {rd} byte(s) during handshake"));
        }
        if rd == 0 && wr == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    drop(recorder);

    if let Some(kx) = conn.negotiated_key_exchange_group() {
        let named = kx.name();
        let iana: u16 = named.into();
        let fips = if kx.fips() { " (FIPS impl)" } else { "" };
        events.push(Event::new(
            Side::Info,
            format!("Key agreement group: {:?} (IANA 0x{:04x}){}", named, iana, fips),
        ));
    } else {
        events.push(Event::new(Side::Info, "Key agreement group: <none/unknown>"));
    }

    let mut cert_pem_path = None::<PathBuf>;
    if !conn.is_handshaking() {
        events.push(Event::new(Side::Info, "TLS handshake completed"));
        if let Some(v) = conn.protocol_version() {
            events.push(Event::new(Side::Info, format!("Negotiated TLS version: {:?}", v)));
        } else {
            events.push(Event::new(Side::Info, "Negotiated TLS version: <unknown>"));
        }
        if let Some(cs) = conn.negotiated_cipher_suite() {
            events.push(Event::new(Side::Info, format!("Cipher suite: {:?}", cs.suite())));
        } else {
            events.push(Event::new(Side::Info, "Cipher suite: <unknown>"));
        }
        if let Some(proto) = conn.alpn_protocol() {
            let printable = String::from_utf8_lossy(proto).to_string();
            events.push(Event::new(Side::Info, format!("ALPN protocol: {printable}")));
        } else {
            events.push(Event::new(Side::Info, "ALPN protocol: (none)"));
        }

        if let Some(chain) = conn.peer_certificates() {
            events.push(Event::new(Side::Info, format!("Server sent {} certificate(s)", chain.len())));
            let fname = artifact_filename("server-certs", &host, "pem");
            let pem_path = PathBuf::from(&fname);
            save_cert_chain_as_pem(&pem_path, chain)?;
            cert_pem_path = Some(pem_path.clone());
            events.push(Event::new(Side::Info, format!("Saved server cert chain bundle: ./{}", pem_path.display())));

            for (idx, cert) in chain.iter().enumerate() {
                match summarize_cert(cert) {
                    Ok(summary) => events.push(Event::new(Side::Info, format!("cert[{idx}]: {summary}"))),
                    Err(e) => events.push(Event::new(Side::Error, format!("cert[{idx}]: Failed to parse: {e}"))),
                }
            }
        } else {
            events.push(Event::new(Side::Info, "No peer certificate chain available"));
        }

        let conn_enum: Connection = conn.into();
        match conn_enum.dangerous_extract_secrets() {
            Ok(secrets) => {
                // tx
                let (tx_seq, tx) = secrets.tx;
                log_secrets(&mut events, "tx", tx_seq, tx);
                // rx
                let (rx_seq, rx) = secrets.rx;
                log_secrets(&mut events, "rx", rx_seq, rx);
            }
            Err(e) => {
                events.push(Event::new(
                    Side::Error,
                    format!("Failed to extract TLS traffic secrets: {e}"),
                ));
            }
        }
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }

        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");

        let cert_path_text = cert_pem_path
            .as_ref()
            .map(|p| format!(", server certs: ./{}", p.display()))
            .unwrap_or_default();

        println!(
            "{} INFO: Run complete. Artifacts saved: log: ./{}{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name,
            cert_path_text
        );
    } else {
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }
        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");
        println!(
            "{} ERROR: Run finished with errors before handshake completion. Artifacts saved: log: ./{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name
        );
    }

    Ok(())
}

/// Like extract_run but for mTLS.
fn extract_auth_run(target_arg: &str, roots_path: &str, client_auth_path: &str) -> Result<(), Box<dyn Error>> {
    let (host, port) = parse_host_port(target_arg)?;
    let addr_str = format!("{host}:{port}");
    let sock_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("Failed to resolve host"))?;

    let root_store = load_roots(roots_path)?;
    let base = ClientConfig::builder_with_provider(Arc::new(default_provider())).with_safe_default_protocol_versions()
        .unwrap().with_root_certificates(root_store);
    let mut base = {
        let (certs, key) = load_client_auth(client_auth_path)?;
        base.with_client_auth_cert(certs, key)?
    };

    base.enable_secret_extraction = true;
    let config = Arc::new(base);

    let mut events: Vec<Event> = Vec::new();
    events.push(Event::new(Side::Info, format!("Starting TLS handshake run against {addr_str}")));
    events.push(Event::new(Side::Client, format!("Resolving & connecting to {sock_addr}")));

    let mut tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    events.push(Event::new(Side::Client, "TCP connected"));

    let server_name: ServerName<'static> = host.clone().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid SNI name"))?;
    let mut conn = ClientConnection::new(config.clone(), server_name.clone())?;

    let mut recorder = RecordingIo {
        inner: &mut tcp,
        events: &mut events
    };
    let mut flight = 0usize;

    while conn.is_handshaking() {
        let (rd, wr) = match conn.complete_io(&mut recorder) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
            Err(e) => {
                recorder.log(Side::Error, format!("I/O during handshake failed: {e}"));
                break;
            }
        };
        if wr > 0 {
            flight += 1;
            recorder.log(Side::Client, format!("Handshake flight #{flight} (TLS wrote {wr} byte(s))"));
        }
        if rd > 0 {
            recorder.log(Side::Server, format!("Received {rd} byte(s) during handshake"));
        }
        if rd == 0 && wr == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    drop(recorder);

    if let Some(kx) = conn.negotiated_key_exchange_group() {
        let named = kx.name();
        let iana: u16 = named.into();
        let fips = if kx.fips() { " (FIPS impl)" } else { "" };
        events.push(Event::new(
            Side::Info,
            format!("Key agreement group: {:?} (IANA 0x{:04x}){}", named, iana, fips),
        ));
    } else {
        events.push(Event::new(Side::Info, "Key agreement group: <none/unknown>"));
    }

    let mut cert_pem_path = None::<PathBuf>;
    if !conn.is_handshaking() {
        events.push(Event::new(Side::Info, "TLS handshake completed"));
        if let Some(v) = conn.protocol_version() {
            events.push(Event::new(Side::Info, format!("Negotiated TLS version: {:?}", v)));
        } else {
            events.push(Event::new(Side::Info, "Negotiated TLS version: <unknown>"));
        }
        if let Some(cs) = conn.negotiated_cipher_suite() {
            events.push(Event::new(Side::Info, format!("Cipher suite: {:?}", cs.suite())));
        } else {
            events.push(Event::new(Side::Info, "Cipher suite: <unknown>"));
        }
        if let Some(proto) = conn.alpn_protocol() {
            let printable = String::from_utf8_lossy(proto).to_string();
            events.push(Event::new(Side::Info, format!("ALPN protocol: {printable}")));
        } else {
            events.push(Event::new(Side::Info, "ALPN protocol: (none)"));
        }

        if let Some(chain) = conn.peer_certificates() {
            events.push(Event::new(Side::Info, format!("Server sent {} certificate(s)", chain.len())));
            let fname = artifact_filename("server-certs", &host, "pem");
            let pem_path = PathBuf::from(&fname);
            save_cert_chain_as_pem(&pem_path, chain)?;
            cert_pem_path = Some(pem_path.clone());
            events.push(Event::new(Side::Info, format!("Saved server cert chain bundle: ./{}", pem_path.display())));

            for (idx, cert) in chain.iter().enumerate() {
                match summarize_cert(cert) {
                    Ok(summary) => events.push(Event::new(Side::Info, format!("cert[{idx}]: {summary}"))),
                    Err(e) => events.push(Event::new(Side::Error, format!("cert[{idx}]: Failed to parse: {e}"))),
                }
            }
        } else {
            events.push(Event::new(Side::Info, "No peer certificate chain available"));
        }

        let conn_enum: Connection = conn.into();
        match conn_enum.dangerous_extract_secrets() {
            Ok(secrets) => {
                let (tx_seq, tx) = secrets.tx;
                log_secrets(&mut events, "tx", tx_seq, tx);
                let (rx_seq, rx) = secrets.rx;
                log_secrets(&mut events, "rx", rx_seq, rx);
            }
            Err(e) => {
                events.push(Event::new(
                    Side::Error,
                    format!("Failed to extract TLS traffic secrets: {e}"),
                ));
            }
        }
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }

        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");

        let cert_path_text = cert_pem_path
            .as_ref()
            .map(|p| format!(", server certs: ./{}", p.display()))
            .unwrap_or_default();

        println!(
            "{} INFO: Run complete. Artifacts saved: log: ./{}{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name,
            cert_path_text
        );
    } else {
        events.sort_by_key(|e| e.t);
        let mut log_text = String::new();
        for e in &events {
            log_text.push_str(&e.fmt());
            log_text.push('\n');
        }
        let log_name = artifact_filename("tls-handshake", &host, "log");
        fs::write(&log_name, &log_text)?;
        print!("{log_text}");
        println!(
            "{} ERROR: Run finished with errors before handshake completion. Artifacts saved: log: ./{}",
            chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
            log_name
        );
    }

    Ok(())
}

fn log_secrets(events: &mut Vec<Event>, dir: &str, seq: u64, cts: ConnectionTrafficSecrets) {
    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write as _;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }

    match cts {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            events.push(Event::new(
                Side::Info,
                format!(
                    "secrets[{dir}]: suite=AES_128_GCM, seq={seq}, key={}, iv={}",
                    hex(key.as_ref()),
                    hex(iv.as_ref())
                ),
            ));
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            events.push(Event::new(
                Side::Info,
                format!(
                    "secrets[{dir}]: suite=AES_256_GCM, seq={seq}, key={}, iv={}",
                    hex(key.as_ref()),
                    hex(iv.as_ref())
                ),
            ));
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            events.push(Event::new(
                Side::Info,
                format!(
                    "secrets[{dir}]: suite=CHACHA20_POLY1305, seq={seq}, key={}, iv={}",
                    hex(key.as_ref()),
                    hex(iv.as_ref())
                ),
            ));
        }
       _ => ()
    }
}

/// A port is required for the target.
fn parse_host_port(input: &str) -> Result<(String, u16), Box<dyn Error>> {
    let s = if let Some(idx) = input.find("://") { &input[(idx + 3)..] } else { input };
    let s = s.split('/').next().unwrap_or(s);
    let mut parts = s.rsplitn(2, ':');
    let port_str = parts.next().ok_or("Missing host:port")?;
    let host_part = parts.next().ok_or("Missing host:port")?;
    let host = if host_part.starts_with('[') && host_part.ends_with(']') {
        host_part[1..host_part.len() - 1].to_string()
    } else {
        host_part.to_string()
    };
    let port: u16 = port_str.parse()?;
    Ok((host, port))
}

/// Load user supplied trusted roots.
fn load_roots<P: AsRef<Path>>(pem_path: P) -> io::Result<RootCertStore> {
    let mut rd = BufReader::new(File::open(pem_path.as_ref())?);
    let mut roots = RootCertStore::empty();
    let mut added_any = false;
    for cert in rustls_pemfile::certs(&mut rd) {
        let cert = cert?;
        let (added, _skipped) =
            roots.add_parsable_certificates(std::iter::once(CertificateDer::from(cert)));
        if added > 0 {
            added_any = true;
        }
    }

    if !added_any {
        Err(io::Error::new(io::ErrorKind::InvalidData, "No valid roots in bundle"))
    } else {
        Ok(roots)
    }
}

/// Load user supplied client auth PEM bundle for mTLS - optional.
fn load_client_auth<P: AsRef<Path>>(
    pem_path: P,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut rd = BufReader::new(File::open(pem_path.as_ref())?);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()?;

    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No certs in client bundle"));
    }

    let mut rd = BufReader::new(File::open(pem_path.as_ref())?);
    for item in rustls_pemfile::read_all(&mut rd) {
        match item {
            Ok(rustls_pemfile::Item::Pkcs8Key(k)) => {
                return Ok((certs, PrivateKeyDer::from(k)));
            }
            Ok(rustls_pemfile::Item::Pkcs1Key(k)) => {
                return Ok((certs, PrivateKeyDer::from(k)));
            }
            Ok(rustls_pemfile::Item::Sec1Key(k)) => {
                return Ok((certs, PrivateKeyDer::from(k)));
            }
            _ => continue,
        }
    }

    Err(io::Error::new(io::ErrorKind::InvalidData, "No private key found in client bundle"))
}

fn artifact_filename(prefix: &str, host: &str, ext: &str) -> String {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
        .replace(':', "-");
    format!("{prefix}_{host}_{ts}.{ext}")
}

fn save_cert_chain_as_pem(path: &Path, chain: &[CertificateDer<'static>]) -> io::Result<()> {
    let mut f = File::create(path)?;
    for cert in chain {
        writeln!(f, "-----BEGIN CERTIFICATE-----")?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        for chunk in b64.as_bytes().chunks(64) {
            f.write_all(chunk)?;
            f.write_all(b"\n")?;
        }
        writeln!(f, "-----END CERTIFICATE-----")?;
    }
    Ok(())
}

fn summarize_cert(der: &[u8]) -> Result<String, Box<dyn Error>> {
    let (_, x509) = x509_parser::prelude::X509Certificate::from_der(der)
        .map_err(|e| format!("x509 parse error: {e:?}"))?;
    let mut subject_cn: Option<String> = None;
    for attr in x509.subject().iter_attributes() {
        if *attr.attr_type() == OID_X509_COMMON_NAME {
            if let Ok(s) = attr.as_str() {
                subject_cn = Some(s.to_string());
                break;
            }
        }
    }

    let mut sans: Vec<String> = Vec::new();
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(d) => sans.push(format!("DNS:{d}")),
                    GeneralName::IPAddress(b) => {
                        if let Some(ip) = ip_from_octets(b) {
                            sans.push(format!("IP:{ip}"));
                        } else {
                            sans.push(format!("IP:<{} bytes>", b.len()));
                        }
                    }
                    GeneralName::URI(u) => sans.push(format!("URI:{u}")),
                    GeneralName::RFC822Name(m) => sans.push(format!("EMAIL:{m}")),
                    _ => {}
                }
            }
        }
    }

    let nb = x509.validity().not_before.to_datetime();
    let na = x509.validity().not_after.to_datetime();
    let nb_s = nb.format(&Rfc3339).map_err(|e| format!("time format error: {e}"))?;
    let na_s = na.format(&Rfc3339).map_err(|e| format!("time format error: {e}"))?;
    let cn_text = subject_cn.unwrap_or_else(|| "<none>".into());
    let san_text = if sans.is_empty() { "(none)".into() } else { sans.join(", ") };

    Ok(format!(
        "Subject CN=\"{}\"; SANs=[{}]; notBefore={}, notAfter={}",
        cn_text, san_text, nb_s, na_s
    ))
}

fn ip_from_octets(b: &[u8]) -> Option<std::net::IpAddr> {
    match b.len() {
        4 => Some(std::net::IpAddr::from([b[0], b[1], b[2], b[3]])),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(std::net::IpAddr::from(a))
        }
        _ => None,
    }
}
