//! OpenSSL TLS backend for the MITM path.
//!
//! This is a port of the openssl implementation that existed immediately
//! before commit 700748c ("feat(ssl): migrate TLS backend from openssl to
//! rustls"), reshaped to expose exactly the same surface as `ssl_rustls`
//! so `mitm.rs` is backend agnostic.
//!
//! Why it exists: rustls (with any CryptoProvider) cannot negotiate
//! TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) — static RSA key exchange, CBC mode
//! and a SHA-1 MAC are all outside what rustls implements. Some head units
//! offer nothing else. A captured ClientHello from a Sony AX3200 advertises
//! exactly one usable suite (0x002F), no supported_groups and no key_share.
//!
//! OpenSSL negotiates that suite with its default cipher list at the default
//! security level, which is why the historical configuration below sets no
//! cipher list and no security level — it is deliberately left as it was.

use crate::mitm::ProxyType;
use openssl::ssl::{ErrorCode, Ssl, SslContextBuilder, SslFiletype, SslMethod, SslStream};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// SslMemBuf — in-memory BIO equivalent
// ---------------------------------------------------------------------------

/// rust-openssl does not expose BIO_s_mem, so `SslStream` is given a type that
/// implements `Read`/`Write` over two shared queues instead.
/// See https://github.com/sfackler/rust-openssl/issues/1697
///
/// The clone held by `SslStream` and the clone held by the caller share the
/// same buffers, so `feed_incoming` / `drain_outgoing` on the caller's handle
/// are visible to the stream and vice versa.
type LocalDataBuffer = Arc<Mutex<VecDeque<u8>>>;

#[derive(Clone)]
pub struct SslMemBuf {
    /// written by OpenSSL, drained by the caller (towards the peer)
    server_stream: LocalDataBuffer,
    /// written by the caller (received from the peer), read by OpenSSL
    client_stream: LocalDataBuffer,
}

impl SslMemBuf {
    pub fn new() -> Self {
        Self {
            server_stream: Arc::new(Mutex::new(VecDeque::new())),
            client_stream: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Feed data received from the peer (stripped from AA encapsulation).
    /// Historical name: `write_from`.
    pub fn feed_incoming(&mut self, data: &[u8]) {
        if let Ok(mut buf) = self.client_stream.lock() {
            let _ = buf.write(data);
        }
    }

    /// Take all data OpenSSL generated (to be wrapped in AA encapsulation).
    /// Historical name: `read_to`.
    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if let Ok(mut buf) = self.server_stream.lock() {
            let _ = buf.read_to_end(&mut out);
        }
        out
    }
}

impl Default for SslMemBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Read implementation used internally by OpenSSL.
impl Read for SslMemBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.client_stream
            .lock()
            .map_err(|_| std::io::Error::other("SslMemBuf client_stream poisoned"))?
            .read(buf)
    }
}

/// Write implementation used internally by OpenSSL.
impl Write for SslMemBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.server_stream
            .lock()
            .map_err(|_| std::io::Error::other("SslMemBuf server_stream poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.server_stream
            .lock()
            .map_err(|_| std::io::Error::other("SslMemBuf server_stream poisoned"))?
            .flush()
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error type for the openssl backend. Kept as a plain message so it is
/// unconditionally `Send + Sync + 'static` and can be boxed by callers.
#[derive(Debug)]
pub struct OpenSslError(String);

impl std::fmt::Display for OpenSslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for OpenSslError {}

impl OpenSslError {
    fn new<T: std::fmt::Display>(e: T) -> Self {
        Self(e.to_string())
    }
}

/// A non-blocking memory BIO signals "no more data" in ways OpenSSL reports as
/// WANT_READ / WANT_WRITE, and an exhausted `VecDeque` reads as EOF which
/// surfaces as SYSCALL. None of those are real failures — they mean "call me
/// again when there is more data". This mirrors the historical
/// `ssl_check_failure` exactly.
fn ssl_check_failure<T>(
    res: std::result::Result<T, openssl::ssl::Error>,
) -> std::result::Result<(), OpenSslError> {
    match res {
        Ok(_) => Ok(()),
        Err(err) => match err.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE | ErrorCode::SYSCALL => Ok(()),
            _ => Err(OpenSslError::new(err)),
        },
    }
}

// ---------------------------------------------------------------------------
// AaConnection
// ---------------------------------------------------------------------------

/// Wraps an OpenSSL `SslStream` over the shared memory buffer, exposing the
/// same methods as `ssl_rustls::AaConnection`.
pub struct AaConnection {
    stream: SslStream<SslMemBuf>,
    /// which handshake entry point to drive
    server_side: bool,
}

impl AaConnection {
    /// Drive the TLS state machine one step. Incoming bytes are already in the
    /// shared buffer (the caller used `feed_incoming`), and anything OpenSSL
    /// produces lands in the shared outgoing buffer for `drain_outgoing`.
    ///
    /// Returns whether the handshake is still in progress.
    pub fn process(&mut self, _mem_buf: &mut SslMemBuf) -> std::result::Result<bool, OpenSslError> {
        // The buffers are shared with `self.stream`, so `_mem_buf` needs no
        // explicit plumbing here — it is accepted only to match the rustls
        // backend's signature.
        if self.server_side {
            ssl_check_failure(self.stream.accept())?;
        } else {
            ssl_check_failure(self.stream.do_handshake())?;
        }
        Ok(!self.stream.ssl().is_init_finished())
    }

    pub fn is_handshaking(&self) -> bool {
        !self.stream.ssl().is_init_finished()
    }

    /// OpenSSL's own handshake state description.
    pub fn state_string(&self) -> String {
        self.stream.ssl().state_string_long().to_string()
    }

    /// Negotiated cipher suite name, e.g. "AES128-SHA".
    /// Only meaningful once the handshake has completed.
    pub fn cipher_suite(&self) -> &'static str {
        self.stream
            .ssl()
            .current_cipher()
            .map(|c| c.name())
            .unwrap_or("unknown")
    }

    /// Encrypt `plaintext`; ciphertext lands in the shared outgoing buffer.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        _mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), OpenSslError> {
        self.stream
            .ssl_write(plaintext)
            .map_err(OpenSslError::new)?;
        Ok(())
    }

    /// Feed `ciphertext` into OpenSSL and return the decrypted plaintext.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, OpenSslError> {
        mem_buf.feed_incoming(ciphertext);
        let mut plaintext: Vec<u8> = Vec::new();
        self.stream
            .read_to_end(&mut plaintext)
            .map_err(OpenSslError::new)?;
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build an `AaConnection` for the given proxy side.
///
/// Roles and certificate selection are unchanged from the historical
/// implementation and match the rustls backend:
///   ProxyType::HeadUnit     -> act as MobileDevice toward the HU, "md" certs,
///                              set_accept_state()  (SSL server)
///   ProxyType::MobileDevice -> act as HeadUnit toward the phone, "hu" certs,
///                              set_connect_state() (SSL client)
///
/// Deliberately sets no cipher list and no security level: OpenSSL's defaults
/// already include the legacy suites old head units require.
pub fn ssl_builder(proxy_type: ProxyType, keys_path: &str) -> Result<(AaConnection, SslMemBuf)> {
    let mut ctx_builder = SslContextBuilder::new(SslMethod::tls())?;

    let prefix = match proxy_type {
        ProxyType::HeadUnit => "md",
        ProxyType::MobileDevice => "hu",
    };
    ctx_builder.set_certificate_file(format!("{keys_path}/{prefix}_cert.pem"), SslFiletype::PEM)?;
    ctx_builder.set_private_key_file(format!("{keys_path}/{prefix}_key.pem"), SslFiletype::PEM)?;
    ctx_builder.check_private_key()?;
    // trusted root certificates:
    ctx_builder.set_ca_file(format!("{keys_path}/galroot_cert.pem"))?;

    ctx_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    ctx_builder.set_options(openssl::ssl::SslOptions::NO_TLSV1_3);

    let openssl_ctx = ctx_builder.build();
    let mut ssl = Ssl::new(&openssl_ctx)?;

    let server_side = match proxy_type {
        ProxyType::HeadUnit => {
            ssl.set_accept_state(); // SSL server
            true
        }
        ProxyType::MobileDevice => {
            ssl.set_connect_state(); // SSL client
            false
        }
    };

    let mem_buf = SslMemBuf::new();
    let stream = SslStream::new(ssl, mem_buf.clone())?;

    Ok((
        AaConnection {
            stream,
            server_side,
        },
        mem_buf,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Directory holding the five AA certificates. Tests are skipped when it is
    /// not set, so the suite stays runnable without the private key material.
    fn keys_path() -> Option<String> {
        let p = std::env::var("AA_TEST_KEYS_PATH").ok()?;
        std::path::Path::new(&p)
            .join("md_cert.pem")
            .exists()
            .then_some(p)
    }

    /// Drives both sides of the MITM against each other using the same
    /// state-driven loop shape `mitm.rs` uses:
    ///
    ///   loop { process(); drain_outgoing(); if !is_handshaking() { break } ; feed_incoming() }
    ///
    /// Deliberately NOT the historical fixed `STEPS = 3` loop.
    #[test]
    fn openssl_handshake_completes_and_transfers() {
        let Some(keys) = keys_path() else {
            eprintln!("AA_TEST_KEYS_PATH unset - skipping");
            return;
        };

        // HeadUnit side = SSL server (md certs); MobileDevice side = SSL client (hu certs)
        let (mut srv, mut srv_buf) = ssl_builder(ProxyType::HeadUnit, &keys).expect("server build");
        let (mut cli, mut cli_buf) =
            ssl_builder(ProxyType::MobileDevice, &keys).expect("client build");

        let mut flights = 0;
        for _ in 0..32 {
            // client step
            let c_hs = cli.process(&mut cli_buf).expect("client process");
            let c_out = cli_buf.drain_outgoing();
            if !c_out.is_empty() {
                srv_buf.feed_incoming(&c_out);
                flights += 1;
            }
            // server step
            let s_hs = srv.process(&mut srv_buf).expect("server process");
            let s_out = srv_buf.drain_outgoing();
            if !s_out.is_empty() {
                cli_buf.feed_incoming(&s_out);
                flights += 1;
            }
            if !c_hs && !s_hs {
                break;
            }
        }

        assert!(!cli.is_handshaking(), "client still handshaking");
        assert!(!srv.is_handshaking(), "server still handshaking");
        assert!(flights >= 4, "expected multiple flights, saw {flights}");

        // A real suite must have been negotiated.
        let suite = srv.cipher_suite();
        assert_ne!(suite, "unknown", "no cipher negotiated");
        eprintln!(
            "negotiated: {suite} | flights: {flights} | state: {}",
            srv.state_string()
        );

        // Application data, client -> server
        let plain = b"android auto application payload";
        cli.encrypt(plain, &mut cli_buf).expect("encrypt");
        let wire = cli_buf.drain_outgoing();
        assert!(!wire.is_empty(), "encrypt produced no ciphertext");
        assert_ne!(&wire[..], &plain[..], "payload not encrypted");
        let got = srv.decrypt(&wire, &mut srv_buf).expect("decrypt");
        assert_eq!(got, plain, "round-trip mismatch");

        // And server -> client, to prove both directions.
        let plain2 = b"head unit reply";
        srv.encrypt(plain2, &mut srv_buf).expect("encrypt 2");
        let wire2 = srv_buf.drain_outgoing();
        let got2 = cli.decrypt(&wire2, &mut cli_buf).expect("decrypt 2");
        assert_eq!(got2, plain2, "reverse round-trip mismatch");
    }

    /// An empty buffer must read as "no progress yet", never as an error:
    /// OpenSSL reports WANT_READ / SYSCALL, which ssl_check_failure absorbs.
    #[test]
    fn empty_membuf_is_not_an_error() {
        let Some(keys) = keys_path() else { return };
        let (mut srv, mut buf) = ssl_builder(ProxyType::HeadUnit, &keys).expect("build");
        // Nothing fed in at all — process must succeed and stay handshaking.
        let still = srv.process(&mut buf).expect("empty process must not error");
        assert!(still, "should still be handshaking with no input");
        assert!(buf.drain_outgoing().is_empty() || srv.is_handshaking());
    }

    /// A ClientHello delivered in fragments must not break the state machine.
    #[test]
    fn partial_records_are_tolerated() {
        let Some(keys) = keys_path() else { return };
        let (mut srv, mut srv_buf) = ssl_builder(ProxyType::HeadUnit, &keys).expect("server");
        let (mut cli, mut cli_buf) = ssl_builder(ProxyType::MobileDevice, &keys).expect("client");

        cli.process(&mut cli_buf).expect("client hello");
        let hello = cli_buf.drain_outgoing();
        assert!(hello.len() > 8, "no ClientHello produced");

        // feed it one byte at a time; every step must be error-free
        for b in &hello {
            srv_buf.feed_incoming(&[*b]);
            srv.process(&mut srv_buf)
                .expect("partial feed must not error");
        }
        assert!(
            !srv_buf.drain_outgoing().is_empty(),
            "server produced no response"
        );
    }
}
