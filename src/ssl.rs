//! TLS backend dispatch.
//!
//! `mitm.rs` talks to this module instead of a concrete backend. Two are
//! available and both are compiled in, selected at runtime by the
//! `tls_backend` configuration key:
//!
//!   "rustls"  (default) — modern head units; unchanged behaviour
//!   "openssl"           — legacy head units that only offer suites rustls
//!                         does not implement, e.g. TLS_RSA_WITH_AES_128_CBC_SHA
//!
//! Dispatch is an enum rather than a trait object because `process()`,
//! `encrypt()` and `decrypt()` all take `&mut SslMemBuf`; a trait would force
//! the buffer type to be erased too. `ssl_builder` always returns a matched
//! connection/buffer pair, so a mixed pair is unreachable in practice and is
//! reported as an error rather than panicking.

use crate::mitm::ProxyType;
use crate::ssl_openssl;
use crate::ssl_rustls;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Which TLS implementation to use for the MITM path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsBackend {
    Rustls,
    OpenSsl,
}

impl TlsBackend {
    /// Parse the `tls_backend` config value. Unknown values fall back to
    /// rustls so a typo cannot silently change TLS behaviour.
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "openssl" => Self::OpenSsl,
            _ => Self::Rustls,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rustls => "rustls",
            Self::OpenSsl => "openssl",
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Unified TLS error. Held as a message so it is unconditionally
/// `Send + Sync + 'static` and callers can `Box::new` it unchanged.
#[derive(Debug)]
pub struct TlsError {
    backend: &'static str,
    message: String,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.backend, self.message)
    }
}

impl std::error::Error for TlsError {}

impl TlsError {
    fn new<T: std::fmt::Display>(backend: &'static str, e: T) -> Self {
        Self {
            backend,
            message: e.to_string(),
        }
    }

    fn mismatch() -> Self {
        Self {
            backend: "dispatch",
            message: "TLS connection and memory buffer are from different backends".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// SslMemBuf
// ---------------------------------------------------------------------------

pub enum SslMemBuf {
    Rustls(ssl_rustls::SslMemBuf),
    OpenSsl(ssl_openssl::SslMemBuf),
}

impl SslMemBuf {
    pub fn feed_incoming(&mut self, data: &[u8]) {
        match self {
            Self::Rustls(b) => b.feed_incoming(data),
            Self::OpenSsl(b) => b.feed_incoming(data),
        }
    }

    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        match self {
            Self::Rustls(b) => b.drain_outgoing(),
            Self::OpenSsl(b) => b.drain_outgoing(),
        }
    }
}

// ---------------------------------------------------------------------------
// AaConnection
// ---------------------------------------------------------------------------

pub enum AaConnection {
    Rustls(ssl_rustls::AaConnection),
    OpenSsl(ssl_openssl::AaConnection),
}

impl AaConnection {
    pub fn backend(&self) -> TlsBackend {
        match self {
            Self::Rustls(_) => TlsBackend::Rustls,
            Self::OpenSsl(_) => TlsBackend::OpenSsl,
        }
    }

    /// Drive the TLS state machine one step.
    /// Returns whether the handshake is still in progress.
    pub fn process(&mut self, mem_buf: &mut SslMemBuf) -> std::result::Result<bool, TlsError> {
        match (self, mem_buf) {
            (Self::Rustls(c), SslMemBuf::Rustls(b)) => {
                c.process(b).map_err(|e| TlsError::new("rustls", e))
            }
            (Self::OpenSsl(c), SslMemBuf::OpenSsl(b)) => {
                c.process(b).map_err(|e| TlsError::new("openssl", e))
            }
            _ => Err(TlsError::mismatch()),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            Self::Rustls(c) => c.is_handshaking(),
            Self::OpenSsl(c) => c.is_handshaking(),
        }
    }

    pub fn state_string(&self) -> String {
        match self {
            Self::Rustls(c) => c.state_string(),
            Self::OpenSsl(c) => c.state_string(),
        }
    }

    pub fn cipher_suite(&self) -> &'static str {
        match self {
            Self::Rustls(c) => c.cipher_suite(),
            Self::OpenSsl(c) => c.cipher_suite(),
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), TlsError> {
        match (self, mem_buf) {
            (Self::Rustls(c), SslMemBuf::Rustls(b)) => c
                .encrypt(plaintext, b)
                .map_err(|e| TlsError::new("rustls", e)),
            (Self::OpenSsl(c), SslMemBuf::OpenSsl(b)) => c
                .encrypt(plaintext, b)
                .map_err(|e| TlsError::new("openssl", e)),
            _ => Err(TlsError::mismatch()),
        }
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, TlsError> {
        match (self, mem_buf) {
            (Self::Rustls(c), SslMemBuf::Rustls(b)) => c
                .decrypt(ciphertext, b)
                .map_err(|e| TlsError::new("rustls", e)),
            (Self::OpenSsl(c), SslMemBuf::OpenSsl(b)) => c
                .decrypt(ciphertext, b)
                .map_err(|e| TlsError::new("openssl", e)),
            _ => Err(TlsError::mismatch()),
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a TLS connection for the given proxy side using the selected backend.
pub fn ssl_builder(
    backend: TlsBackend,
    proxy_type: ProxyType,
    keys_path: &str,
) -> Result<(AaConnection, SslMemBuf)> {
    match backend {
        TlsBackend::Rustls => {
            let (conn, buf) = ssl_rustls::ssl_builder(proxy_type, keys_path)?;
            Ok((AaConnection::Rustls(conn), SslMemBuf::Rustls(buf)))
        }
        TlsBackend::OpenSsl => {
            let (conn, buf) = ssl_openssl::ssl_builder(proxy_type, keys_path)?;
            Ok((AaConnection::OpenSsl(conn), SslMemBuf::OpenSsl(buf)))
        }
    }
}
