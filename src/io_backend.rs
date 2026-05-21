//! Backend abstraction layer.
//!
//! This module centralises everything that differs between the io-uring
//! and the standard tokio backends:
//!
//! - `IoDevice` trait   — common read/write interface for both backends
//! - `NativeTcpStream`  — type alias resolving to the right TcpStream
//! - `NativeFile`       — type alias resolving to the right File type
//! - `spawn!`           — macro wrapping tokio_uring::spawn / tokio::spawn
//! - `tcp_connect!`     — macro for backend-appropriate TCP connect
//! - `tcp_listener_bind!` — macro for backend-appropriate listener bind
//! - `listener_ref!`    — macro for &mut vs & listener reference
//! - `tcp_shutdown!`    — macro for sync vs async stream shutdown
//! - `run_io_loop!`     — macro for tokio_uring::start vs runtime.block_on

#[cfg(not(feature = "io-uring"))]
use tokio::net::TcpStream as TokioTcpStream;

/// A readable/writable I/O endpoint (USB device, TCP stream, etc.).
///
/// Both backends implement this; the blanket contract is:
/// - `write_data` writes the entire buffer (best-effort; returns bytes written)
/// - `read_data`  reads up to `buf.len()` bytes; returns 0 on EOF
///
/// Each backend provides its own concrete type implementing this trait.
///
/// # Note on `async fn` in trait
/// We intentionally use `async fn` rather than `-> impl Future + Send` because
/// the io_uring backend holds `!Send` types (tokio_uring's `File`/`TcpStream`
/// wrap `Rc` internally). Adding a `Send` bound here would break that backend.
/// This trait is only used internally, so the lack of auto-trait transparency
/// is not a problem in practice.
#[allow(async_fn_in_trait)]
pub trait IoDevice {
    async fn write_data(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    async fn read_data(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// `GenericTcpStream` — abstracts `set_nodelay()` over both backend stream types
/// (`tokio_uring::net::TcpStream` and `tokio::net::TcpStream`), allowing shared
/// code to configure TCP options without knowing which backend is active.
pub trait GenericTcpStream {
    fn set_nodelay(&self, enabled: bool) -> std::io::Result<()>;
}

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! tcp_connect {
    ($addr:expr) => {
        tokio_uring::net::TcpStream::connect($addr)
    };
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! tcp_connect {
    ($addr:expr) => {
        TokioTcpStream::connect($addr)
    };
}

#[cfg(feature = "io-uring")]
pub type NativeTcpStream = tokio_uring::net::TcpStream;
#[cfg(not(feature = "io-uring"))]
pub type NativeTcpStream = TokioTcpStream;
#[cfg(feature = "io-uring")]
pub type NativeFile = tokio_uring::fs::File;
#[cfg(not(feature = "io-uring"))]
pub type NativeFile = tokio::fs::File;

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! tcp_listener_bind {
    ($port:expr) => {{
        use tokio_uring::net::TcpListener;
        let addr = format!("0.0.0.0:{}", $port).parse::<SocketAddr>().unwrap();
        Some(TcpListener::bind(addr).unwrap())
    }};
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! tcp_listener_bind {
    ($port:expr) => {{
        use tokio::net::TcpListener;
        let addr = format!("0.0.0.0:{}", $port).parse::<SocketAddr>().unwrap();
        TcpListener::bind(addr).await?
    }};
}

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! listener_ref {
    ($l:expr) => {
        &mut $l.as_mut().unwrap()
    };
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! listener_ref {
    ($l:expr) => {
        &$l
    };
}

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! tcp_shutdown {
    ($stream:expr) => {
        if let Some(s) = $stream {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    };
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! tcp_shutdown {
    ($stream:expr) => {
        if let Some(stream) = $stream {
            use tokio::io::AsyncWriteExt;
            let mut stream = stream.lock().await;
            let _ = stream.shutdown().await;
        }
    };
}

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! spawn {
    ($fut:expr) => {
        tokio_uring::spawn($fut)
    };
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! spawn {
    ($fut:expr) => {
        tokio::spawn($fut)
    };
}

#[cfg(feature = "io-uring")]
#[macro_export]
macro_rules! run_io_loop {
    ($runtime:expr, $fut:expr) => {
        let _ = tokio_uring::start($fut);
    };
}

#[cfg(not(feature = "io-uring"))]
#[macro_export]
macro_rules! run_io_loop {
    ($runtime:expr, $fut:expr) => {
        $runtime.block_on($fut)?;
    };
}
