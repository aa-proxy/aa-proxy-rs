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
        Ok(SinkWriter::new(CopyToBytes::new(futures::sink::unfold(
            self,
            move |mut this, mut bytes: Bytes| async move {
                let data_len = bytes.len();

                // Limit maximum USB transfer size to avoid issues with some UDCs.
                while !bytes.is_empty() {
                    let part = bytes.split_to(bytes.len().min(max_packet_size));
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
