//! `IoDevice` trait — common read/write abstraction shared by both I/O backends.
//!
//! The io_uring backend implements this for its concrete IoDevice type;
//! the tokio backend does the same. This allows `proxy()`, `transmit()`,
//! and `io_loop()` to be written once without `#[cfg]`.

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

pub trait GenericTcpStream {
    fn set_nodelay(&self, enabled: bool) -> std::io::Result<()>;
}
