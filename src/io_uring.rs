use crate::io_backend::GenericTcpStream;
use crate::io_backend::IoDevice as IoDeviceTrait;
use crate::mitm::{FRAME_TYPE_FIRST, FRAME_TYPE_MASK, HEADER_LENGTH};
use crate::proxy::BUFFER_LEN;
use crate::usb_stream::{UsbStreamRead, UsbStreamWrite};
use anyhow::Context;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_uring::buf::BoundedBuf;
use tokio_uring::buf::BoundedBufMut;
use tokio_uring::fs::File;
use tokio_uring::net::TcpStream;
use tokio_uring::BufResult;
use tokio_uring::UnsubmittedWrite;

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// tokio_uring::fs::File and tokio_uring::net::TcpStream are using different
// read and write calls:
// File is using read_at() and write_at(),
// TcpStream is using read() and write()
//
// In our case we are reading a special unix character device for
// the USB gadget, which is not a regular file where an offset is important.
// We just use offset 0 for reading and writing, so below is a trait
// for this, to be able to use it in a generic copy() function below.
//
// We abstract them behind the Endpoint trait (used only in this backend for
// read_input_data / endpoint_reader). For the shared IoDeviceTrait used by
// proxy() and transmit(), we expose IoDevice below.

pub trait Endpoint<E> {
    #[allow(async_fn_in_trait)]
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T>;
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T>;
}

impl Endpoint<File> for File {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read_at(buf, 0).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write_at(buf, 0)
    }
}

impl Endpoint<TcpStream> for TcpStream {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read(buf).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write(buf)
    }
}

/// I/O device for the io_uring backend.
///
/// `UsbReader`/`UsbWriter` use `Rc<RefCell<>>` — no synchronisation cost,
/// safe because tokio_uring is single-threaded and each half is only ever
/// accessed from one task. `EndpointIo` and `TcpStreamIo` use the
/// tokio_uring `&self` API so plain `Rc` (no Mutex) is sufficient.
pub enum IoDevice<A: Endpoint<A>> {
    UsbReader(Rc<RefCell<UsbStreamRead>>, PhantomData<A>),
    UsbWriter(Rc<RefCell<UsbStreamWrite>>, PhantomData<A>),
    EndpointIo(Rc<A>),
    TcpStreamIo(Rc<TcpStream>),
}

impl<A: Endpoint<A>> IoDeviceTrait for IoDevice<A> {
    async fn write_data(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            IoDevice::UsbWriter(dev, _) => {
                let mut d = dev.borrow_mut();
                d.write(buf).await
            }
            IoDevice::EndpointIo(dev) => {
                let frame = buf.to_vec();
                let (res, _) = dev.write(frame).submit().await;
                res.map_err(|e| std::io::Error::other(e))
            }
            IoDevice::TcpStreamIo(dev) => {
                let frame = buf.to_vec();
                let (res, _) = dev.write(frame).submit().await;
                res.map_err(|e| std::io::Error::other(e))
            }
            IoDevice::UsbReader(_, _) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot write to UsbReader",
            )),
        }
    }

    async fn read_data(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IoDevice::UsbReader(dev, _) => {
                let mut d = dev.borrow_mut();
                d.read(buf).await
            }
            IoDevice::EndpointIo(dev) => {
                let newdata = vec![0u8; buf.len()];
                let (res, newdata) = dev.read(newdata).await;
                let n = res.map_err(|e| std::io::Error::other(e))?;
                buf[..n].copy_from_slice(&newdata[..n]);
                Ok(n)
            }
            IoDevice::TcpStreamIo(dev) => {
                let newdata = vec![0u8; buf.len()];
                let (res, newdata) = dev.read(newdata).await;
                let n = res.map_err(|e| std::io::Error::other(e))?;
                buf[..n].copy_from_slice(&newdata[..n]);
                Ok(n)
            }
            IoDevice::UsbWriter(_, _) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot read from UsbWriter",
            )),
        }
    }
}

#[cfg(feature = "io-uring")]
impl GenericTcpStream for tokio_uring::net::TcpStream {
    fn set_nodelay(&self, enabled: bool) -> std::io::Result<()> {
        self.set_nodelay(enabled)
    }
}

/// reads all available data to VecDeque
pub(crate) async fn read_input_data<A: Endpoint<A>>(
    rbuf: &mut VecDeque<u8>,
    obj: &mut IoDevice<A>,
    incremental_read: bool,
) -> Result<usize> {
    let mut newdata = vec![0u8; BUFFER_LEN];
    let mut n;
    let mut len;

    match obj {
        IoDevice::UsbReader(device, _) => {
            let mut dev = device.borrow_mut();
            let retval = dev.read(&mut newdata);
            len = retval
                .await
                .context("read_input_data: UsbReader read error")?;
        }
        IoDevice::EndpointIo(device) => {
            if incremental_read {
                // read header
                newdata = vec![0u8; HEADER_LENGTH];
                let retval = device.read(newdata);
                (n, newdata) = timeout(Duration::from_millis(15000), retval)
                    .await
                    .context("read_input_data/header: EndpointIo timeout")?;
                len = n.context("read_input_data/header: EndpointIo read error")?;

                // fill the output/read buffer with the obtained header data
                rbuf.write(&newdata.clone().slice(..len))?;

                // compute payload size
                let mut payload_size = (newdata[3] as u16 + ((newdata[2] as u16) << 8)) as usize;
                if (newdata[1] & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST {
                    // header is 8 bytes; need to read 4 more bytes
                    payload_size += 4;
                }
                // prepare buffer for the payload and continue normally
                newdata = vec![0u8; payload_size];
            }
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .context("read_input_data: EndpointIo timeout")?;
            len = n.context("read_input_data: EndpointIo read error")?;
        }
        IoDevice::TcpStreamIo(device) => {
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .context("read_input_data: TcpStreamIo timeout")?;
            len = n.context("read_input_data: TcpStreamIo read error")?;
            if len == 0 {
                // TCP EOF means the peer closed the connection; propagate as disconnect.
                return Err("read_input_data: TcpStreamIo EOF".into());
            }
        }
        _ => todo!(),
    }
    if len > 0 {
        rbuf.write(&newdata.slice(..len))?;
    }
    Ok(len)
}
