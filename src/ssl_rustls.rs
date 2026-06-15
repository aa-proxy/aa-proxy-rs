//! rustls-based TLS backend for aa-proxy-rs.
//!
//! Replaces the openssl SslMemBuf / SslStream / ssl_builder stack.
//! Handles V1 certificates (Google Automotive Link / Android Auto) via:
//!   - client side: ResolvesClientCert resolver bypasses rustls cert parsing
//!   - server side: custom ClientCertVerifier skips version check
//!
//! Usage in mitm.rs:
//!   use crate::ssl_rustls::{AaConnection, SslMemBuf};

use crate::mitm::ProxyType;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::CertifiedKey;
use rustls::version::TLS12;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme,
};
use std::io::{Read, Write};
use std::sync::Arc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// SslMemBuf — in-memory BIO equivalent
// ---------------------------------------------------------------------------

/// In-memory TLS transport for rustls, equivalent to OpenSSL BIO_s_mem.
///
/// `incoming`: caller writes peer data here → rustls reads it via read_tls()
/// `outgoing`: rustls writes generated data here → caller drains it via drain_outgoing()
pub struct SslMemBuf {
    incoming: Vec<u8>,
    incoming_pos: usize,
    outgoing: Vec<u8>,
}

impl SslMemBuf {
    pub fn new() -> Self {
        Self {
            incoming: Vec::new(),
            incoming_pos: 0,
            outgoing: Vec::new(),
        }
    }

    /// Feed data received from the peer (stripped from AA encapsulation).
    /// Equivalent to old `write_from`.
    pub fn feed_incoming(&mut self, data: &[u8]) {
        // compact already-consumed prefix first
        if self.incoming_pos > 0 {
            self.incoming.drain(..self.incoming_pos);
            self.incoming_pos = 0;
        }
        self.incoming.extend_from_slice(data);
    }

    /// Take all data rustls generated (to be wrapped in AA encapsulation).
    /// Equivalent to old `read_to`.
    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }
}

/// rustls calls Read on SslMemBuf to consume incoming TLS bytes.
impl Read for SslMemBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = &self.incoming[self.incoming_pos..];
        if available.is_empty() {
            // No data — signal WouldBlock so rustls stops reading.
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.incoming_pos += n;
        Ok(n)
    }
}

/// rustls calls Write on SslMemBuf to emit outgoing TLS bytes.
impl Write for SslMemBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Custom certificate verifiers — accept V1 certs
// ---------------------------------------------------------------------------

fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// ServerCertVerifier that accepts any certificate, including V1.
/// Used on the HeadUnit path where we connect as a client toward the real HU.
#[derive(Debug)]
struct AaServerCertVerifier(Arc<CryptoProvider>);

impl AaServerCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(default_provider()))
    }
}

impl ServerCertVerifier for AaServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// ClientCertVerifier that accepts any client certificate, including V1.
/// Used on the MobileDevice path where we act as a TLS server toward the phone.
#[derive(Debug)]
struct AaClientCertVerifier(Arc<CryptoProvider>);

impl AaClientCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(default_provider()))
    }
}

impl ClientCertVerifier for AaClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// ResolvesServerCert that returns a pre-loaded CertifiedKey without letting
/// rustls parse and validate the certificate — V1 workaround for the server path.
/// with_single_cert() validates the cert version; with_cert_resolver() does not.
#[derive(Debug)]
struct AaServerCertResolver(Arc<CertifiedKey>);

impl AaServerCertResolver {
    fn new(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<Arc<Self>> {
        let signing_key = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)?;
        Ok(Arc::new(Self(Arc::new(CertifiedKey::new(
            vec![cert],
            signing_key,
        )))))
    }
}

impl rustls::server::ResolvesServerCert for AaServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}


/// rustls parse and validate the certificate.  This is the V1 workaround for
/// the client path: with_client_auth_cert() validates the cert version;
/// with_client_cert_resolver() does not.
#[derive(Debug)]
struct AaClientCertResolver(Arc<CertifiedKey>);

impl AaClientCertResolver {
    fn new(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<Arc<Self>> {
        let signing_key = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)?;
        Ok(Arc::new(Self(Arc::new(CertifiedKey::new(
            vec![cert],
            signing_key,
        )))))
    }
}

impl rustls::client::ResolvesClientCert for AaClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// AaConnection — unified server/client connection wrapper
// ---------------------------------------------------------------------------

/// Wraps either a rustls ServerConnection or ClientConnection.
/// Provides process() / encrypt() / decrypt() in terms of SslMemBuf so callers
/// do not need to know which side they are on.
pub enum AaConnection {
    Server(rustls::ServerConnection),
    Client(rustls::ClientConnection),
}

impl AaConnection {
    /// Drive the TLS state machine one step:
    ///   1. feed any pending incoming bytes from mem_buf into rustls
    ///   2. process packets
    ///   3. flush any outgoing bytes rustls generated into mem_buf
    ///
    /// Returns whether the handshake is still in progress.
    pub fn process(&mut self, mem_buf: &mut SslMemBuf) -> std::result::Result<bool, rustls::Error> {
        match self {
            AaConnection::Server(c) => Self::process_conn(c, mem_buf),
            AaConnection::Client(c) => Self::process_conn(c, mem_buf),
        }
    }

    fn process_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<bool, rustls::Error> {
        // Read incoming TLS bytes (WouldBlock == no data yet, not an error)
        let _ = conn.read_tls(mem_buf);
        conn.process_new_packets()?;
        conn.write_tls(&mut mem_buf.outgoing)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(conn.is_handshaking())
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            AaConnection::Server(c) => c.is_handshaking(),
            AaConnection::Client(c) => c.is_handshaking(),
        }
    }

    /// Encrypt `plaintext` and append the ciphertext to `mem_buf.outgoing`.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), rustls::Error> {
        match self {
            AaConnection::Server(c) => Self::encrypt_conn(c, plaintext, mem_buf),
            AaConnection::Client(c) => Self::encrypt_conn(c, plaintext, mem_buf),
        }
    }

    fn encrypt_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        plaintext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), rustls::Error> {
        conn.writer()
            .write_all(plaintext)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        // write_tls can only fail with io::Error from the sink — our Vec sink never fails
        let _ = conn.write_tls(&mut mem_buf.outgoing);
        Ok(())
    }

    /// Feed `ciphertext` into rustls and return the decrypted plaintext.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        mem_buf.feed_incoming(ciphertext);
        match self {
            AaConnection::Server(c) => Self::decrypt_conn(c, mem_buf),
            AaConnection::Client(c) => Self::decrypt_conn(c, mem_buf),
        }
    }

    fn decrypt_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        match conn.read_tls(mem_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(rustls::Error::General(e.to_string())),
        }
        conn.process_new_packets()?;
        let mut plaintext = Vec::new();
        match conn.reader().read_to_end(&mut plaintext) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(rustls::Error::General(e.to_string())),
        }
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Public builder
// ---------------------------------------------------------------------------

fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("cannot read cert {cert_path}: {e}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse cert {cert_path}: {e}"))?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("cannot read key {key_path}: {e}"))?;
    Ok((certs, key))
}

/// Build an `AaConnection` for the given proxy side.
///
/// SSL role mapping (identical to original openssl ssl_builder):
///   ProxyType::HeadUnit     → set_accept_state() → TLS **server** (phone connects to us)
///   ProxyType::MobileDevice → set_connect_state() → TLS **client** (we connect to HU)
pub fn ssl_builder(
    proxy_type: ProxyType,
    keys_path: &str,
) -> Result<(AaConnection, SslMemBuf)> {
    let prefix = match proxy_type {
        ProxyType::HeadUnit => "md",
        ProxyType::MobileDevice => "hu",
    };
    let cert_path = format!("{keys_path}/{prefix}_cert.pem");
    let key_path = format!("{keys_path}/{prefix}_key.pem");
    let (certs, key) = load_cert_and_key(&cert_path, &key_path)?;

    let mem_buf = SslMemBuf::new();
    let provider = default_provider();

    let conn = match proxy_type {
        ProxyType::HeadUnit => {
            // Original: set_accept_state() → SSL server
            // We talk to the phone acting as HU → we are TLS server
            let cert0 = certs.into_iter().next().ok_or("no certificate in file")?;
            let resolver = AaServerCertResolver::new(cert0, key)?;
            let config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS12])?
                .with_client_cert_verifier(AaClientCertVerifier::new())
                .with_cert_resolver(resolver);
            AaConnection::Server(rustls::ServerConnection::new(Arc::new(config))?)
        }
        ProxyType::MobileDevice => {
            // Original: set_connect_state() → SSL client
            // We talk to the HU acting as phone → we are TLS client
            let cert0 = certs.into_iter().next().ok_or("no certificate in file")?;
            let resolver = AaClientCertResolver::new(cert0, key)?;
            let config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS12])?
                .dangerous()
                .with_custom_certificate_verifier(AaServerCertVerifier::new())
                .with_client_cert_resolver(resolver);
            let server_name = "android.auto"
                .try_into()
                .map_err(|e| format!("server_name parse: {e}"))?;
            AaConnection::Client(rustls::ClientConnection::new(Arc::new(config), server_name)?)
        }
    };

    Ok((conn, mem_buf))
}
