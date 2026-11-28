//! `EndpointReceiver`/`EndpointSender` (from the `usb-gadget` crate) ->
//! `AsyncRead`/`AsyncWrite` adapters, ported near-verbatim from the
//! AAWireless-rs POC's `usb.rs` (`IntoStreamReader`/`IntoSinkWriter`).
//!
//! Used by both [`crate::mtp::mtp_server`] (MTP request/response framing)
//! and [`crate::usb_functionfs`] (the Android Accessory bulk pipes) — the
//! same, POC-proven data-path code for both, rather than two separate
//! implementations.

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use std::io::Error;
use std::mem::replace;
use tokio_util::io::{CopyToBytes, SinkWriter, StreamReader};
use usb_gadget::function::custom::{EndpointReceiver, EndpointSender};

/// USB transfer size for the FunctionFS bulk pipes. Splitting every write into
/// max-packet (512 B) transfers costs one AIO submit and one UDC interrupt per 512 B of video,
/// and the usb-gadget crate recommends ~16 KiB transfers. Rounded to a multiple of the endpoint
/// max packet size. `AA_FFS_CHUNK=512` restores the old behaviour without a rebuild.
fn transfer_size(max_packet_size: usize) -> usize {
    let want = std::env::var("AA_FFS_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16384);
    let mps = max_packet_size.max(1);
    (want.max(mps) / mps) * mps
}

struct BytesPool {
    buf: BytesMut,
    pool_size: usize,
}

impl BytesPool {
    fn new(pool_size: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(pool_size),
            pool_size,
        }
    }

    fn chunk(&mut self, chunk_size: usize) -> BytesMut {
        if self.buf.capacity() < chunk_size {
            self.buf = BytesMut::with_capacity(self.pool_size.max(chunk_size));
        }
        let remaining = self.buf.split_off(chunk_size);
        replace(&mut self.buf, remaining)
    }
}

struct RecvContext {
    receiver: EndpointReceiver,
    max_packet_size: usize,
    bytes_pool: BytesPool,
}

impl RecvContext {
    fn new(receiver: EndpointReceiver, max_packet_size: usize) -> Self {
        Self {
            receiver,
            max_packet_size,
            bytes_pool: BytesPool::new(max_packet_size),
        }
    }

    async fn recv(mut self) -> std::io::Result<Option<(BytesMut, Self)>> {
        let chunk = self.bytes_pool.chunk(self.max_packet_size);
        match self.receiver.recv_async(chunk).await {
            Ok(Some(data)) => Ok(Some((data, self))),
            Ok(None) => Ok(Some((BytesMut::new(), self))),
            Err(err) => Err(std::io::Error::other(err)),
        }
    }
}

pub trait IntoStreamReader {
    fn into_stream_reader(
        self,
    ) -> std::io::Result<StreamReader<impl Stream<Item = std::io::Result<BytesMut>>, BytesMut>>;
}

impl IntoStreamReader for EndpointReceiver {
    fn into_stream_reader(
        mut self,
    ) -> std::io::Result<StreamReader<impl Stream<Item = std::io::Result<BytesMut>>, BytesMut>>
    {
        let max_packet_size = self.max_packet_size().map_err(std::io::Error::other)?;
        // Car -> dongle reads stay one max-packet per transfer. A 16 KiB read only
        // completes on a short packet, so a head unit that ends a full-packet write without a
        // zero-length packet would leave that frame stuck in the UDC until its next write (seen with a USB head-unit
        // simulator that sends no zero-length packet: 512/4096/8192-byte frames stalled > 5 s). This direction carries
        // touch, sensor and mic data only. The 16 KiB transfers stay on the write (video) side.
        let context = RecvContext::new(self, max_packet_size);

        Ok(StreamReader::new(futures::stream::try_unfold(
            context,
            |context| context.recv(),
        )))
    }
}

pub trait IntoSinkWriter {
    fn into_sink_writer(
        self,
    ) -> std::io::Result<SinkWriter<impl for<'a> Sink<&'a [u8], Error = Error>>>;
}

impl IntoSinkWriter for EndpointSender {
    fn into_sink_writer(
        mut self,
    ) -> std::io::Result<SinkWriter<impl for<'a> Sink<&'a [u8], Error = Error>>> {
        let max_packet_size = self.max_packet_size().map_err(std::io::Error::other)?;
        let xfer = transfer_size(max_packet_size);
        Ok(SinkWriter::new(CopyToBytes::new(futures::sink::unfold(
            self,
            move |mut this, mut bytes: Bytes| async move {
                let data_len = bytes.len();

                // Limit maximum USB transfer size to avoid issues with some UDCs.
                while !bytes.is_empty() {
                    let part = bytes.split_to(bytes.len().min(xfer));
                    this.send_async(part).await.map_err(std::io::Error::other)?;
                }

                // If data length aligns with the endpoint's transfer size, we need
                // to insert a zero-length packet to indicate the transfer is done.
                if data_len % max_packet_size == 0 {
                    this.flush_async().await.map_err(std::io::Error::other)?;
                    this.send_async(Bytes::new())
                        .await
                        .map_err(std::io::Error::other)?;
                }

                this.flush_async().await.map_err(std::io::Error::other)?;

                Ok::<_, Error>(this)
            },
        ))))
    }
}
