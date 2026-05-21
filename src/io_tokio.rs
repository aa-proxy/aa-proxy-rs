//! Tokio-based I/O layer for aa-proxy-rs.
//!
//! Drop-in replacement for `io_uring.rs` using standard tokio async I/O,
//! for platforms without io_uring support (e.g. kernel < 5.1).

use crate::io_backend::GenericTcpStream;
use crate::io_backend::IoDevice as IoDeviceTrait;
use crate::mitm::{FRAME_TYPE_FIRST, FRAME_TYPE_MASK, HEADER_LENGTH};
use crate::proxy::BUFFER_LEN;
use crate::usb_stream::{UsbStreamRead, UsbStreamWrite};
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// I/O device abstraction for the tokio backend.
/// Each variant holds an Arc to a Send+Sync-safe wrapper using concrete types.
pub enum IoDevice {
    UsbReader(Arc<Mutex<UsbStreamRead>>),
    UsbWriter(Arc<Mutex<UsbStreamWrite>>),
    FileIo(Arc<Mutex<TokioFile>>),
    TcpRead(Arc<Mutex<OwnedReadHalf>>),
    TcpWrite(Arc<Mutex<OwnedWriteHalf>>),
}

impl IoDevice {
    pub async fn read_data(&self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        match self {
            IoDevice::UsbReader(dev) => {
                let mut d = dev.lock().await;
                d.read(buf).await
            }
            IoDevice::FileIo(file) => {
                let mut f = file.lock().await;
                f.read(buf).await
            }
            IoDevice::TcpRead(reader) => {
                let mut r = reader.lock().await;
                r.read(buf).await
            }
            IoDevice::UsbWriter(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot read from UsbWriter",
            )),
            IoDevice::TcpWrite(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot read from TcpWrite",
            )),
        }
    }

    pub async fn write_data(&self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        match self {
            IoDevice::UsbWriter(dev) => {
                let mut d = dev.lock().await;
                d.write(buf).await
            }
            IoDevice::FileIo(file) => {
                let mut f = file.lock().await;
                f.write(buf).await
            }
            IoDevice::TcpWrite(writer) => {
                let mut w = writer.lock().await;
                w.write(buf).await
            }
            IoDevice::UsbReader(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot write to UsbReader",
            )),
            IoDevice::TcpRead(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot write to TcpRead",
            )),
        }
    }
}

impl IoDeviceTrait for IoDevice {
    async fn write_data(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        IoDevice::write_data(self, buf).await
    }

    async fn read_data(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        IoDevice::read_data(self, buf).await
    }
}

impl GenericTcpStream for tokio::net::TcpStream {
    fn set_nodelay(&self, enabled: bool) -> std::io::Result<()> {
        self.set_nodelay(enabled)
    }
}

pub(crate) async fn read_input_data<D: IoDeviceTrait>(
    rbuf: &mut std::collections::VecDeque<u8>,
    obj: &mut D,
    incremental_read: bool,
) -> Result<()> {
    use anyhow::Context;
    use std::io::Write;

    let mut newdata = vec![0u8; BUFFER_LEN];
    let len;

    if incremental_read {
        // read header
        let mut header = vec![0u8; HEADER_LENGTH];
        let header_len = tokio::time::timeout(
            std::time::Duration::from_millis(15000),
            obj.read_data(&mut header),
        )
        .await
        .context("read_input_data/header: timeout")?
        .context("read_input_data/header: read error")?;
        if header_len > 0 {
            rbuf.write_all(&header[..header_len])?;
        }
        if header_len >= HEADER_LENGTH {
            // compute payload size
            let mut payload_size = (header[3] as u16 + ((header[2] as u16) << 8)) as usize;
            if (header[1] & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST {
                // header is 8 bytes; need to read 4 more bytes
                payload_size += 4;
            }
            // prepare buffer for the payload and continue normally
            let mut payload = vec![0u8; payload_size];
            let payload_len = tokio::time::timeout(
                std::time::Duration::from_millis(15000),
                obj.read_data(&mut payload),
            )
            .await
            .context("read_input_data/payload: timeout")?
            .context("read_input_data/payload: read error")?;
            if payload_len > 0 {
                rbuf.write_all(&payload[..payload_len])?;
            }
        }
        return Ok(());
    }

    len = tokio::time::timeout(
        std::time::Duration::from_millis(15000),
        obj.read_data(&mut newdata),
    )
    .await
    .context("read_input_data: timeout")?
    .context("read_input_data: read error")?;
    if len > 0 {
        rbuf.write_all(&newdata[..len])?;
    }
    Ok(())
}
