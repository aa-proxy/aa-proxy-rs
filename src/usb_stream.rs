use nusb::Endpoint;
use nusb::{
    transfer::{Bulk, In, Out},
    Device, Interface, MaybeFuture,
};
use simplelog::*;
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{ready, Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::sleep;

use crate::aoa::{
    AccessoryConfigurations, AccessoryDeviceInfo, AccessoryError, AccessoryInterface,
    AccessoryStrings, EndpointError,
};
use crate::config_types::UsbId;

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error(transparent)]
    WriteError(#[from] WriteError),
    #[error("no usb device found: {0}")]
    NoUsbDevice(nusb::Error),
    #[error("can't open usb handle: {0}, make sure phone is set to charging only mode")]
    CantOpenUsbHandle(nusb::Error),
    #[error("can't open usb accessory: {0}")]
    CantOpenUsbAccessory(AccessoryError),
    #[error("can't open usb accessory endpoint: {0}")]
    CantOpenUsbAccessoryEndpoint(EndpointError),
    #[error(transparent)]
    CantJoin(#[from] tokio::task::JoinError),
}

#[derive(Debug, Error)]
pub enum WriteError {
    #[error(transparent)]
    Io(#[from] io::Error),
}

use crate::io_uring::BUFFER_LEN;
const MAX_PACKET_SIZE: usize = BUFFER_LEN;
// Number of read URBs to keep queued with the USB host controller at all times.
// Keeping 8 in flight that means the controller always has a buffer ready even while
// the upper layer is busy parsing packets from the previous completion.
const MIN_PENDING_READS: usize = 8;
// Keep the HU write queue intentionally shallow so congestion propagates back to
// the phone quickly instead of accumulating large video/audio buffers locally.
const MAX_PENDING_WRITES: usize = 2;

/// Live performance counters for a single USB stream direction.
/// Updated in the hot path with `Ordering::Relaxed`; sampled by the
/// `transfer_monitor` task every 100 ms for diagnostics logging.
pub struct UsbReadCounters {
    /// Number of read URBs currently in-flight with the kernel.
    pub pending_reads: Arc<AtomicUsize>,
    /// Bytes sitting in the overflow buffer waiting for the next poll_read.
    pub cached_bytes: Arc<AtomicUsize>,
}

pub struct UsbWriteCounters {
    /// Number of write URBs currently in-flight with the kernel.
    pub pending_writes: Arc<AtomicUsize>,
}

impl UsbReadCounters {
    fn new() -> Self {
        UsbReadCounters {
            pending_reads: Arc::new(AtomicUsize::new(0)),
            cached_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl UsbWriteCounters {
    fn new() -> Self {
        UsbWriteCounters {
            pending_writes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub struct UsbStreamRead {
    pub read_queue: Endpoint<Bulk, In>,
    /// Keeps the USB interface claim alive for the lifetime of the endpoints.
    /// Dropping `Interface` releases the kernel claim; the endpoints must not
    /// outlive it, so we store it here alongside the read endpoint.
    _iface: Interface,
    /// Overflow bytes from the last URB that didn't fit into the caller's ReadBuf.
    read_buffer: Vec<u8>,
    /// Cursor into `read_buffer`: first unconsumed byte index.
    /// Using a cursor avoids O(n) Vec::drain on every cached read.
    read_buffer_pos: usize,
    /// Shared atomics updated in the hot path; cloned to `transfer_monitor`.
    pub counters: Arc<UsbReadCounters>,
}
pub struct UsbStreamWrite {
    pub write_queue: Endpoint<Bulk, Out>,
    /// Shared atomics updated in the hot path; cloned to `transfer_monitor`.
    pub counters: Arc<UsbWriteCounters>,
}

// switch a USB device to accessory mode
pub fn switch_to_accessory(info: &nusb::DeviceInfo) -> Result<(), ConnectError> {
    info!(
        "Checking USB device at 0x{:X}: {}, {}, 0x{:X} 0x{:X}",
        info.device_address(),
        info.manufacturer_string().unwrap_or("unknown"),
        info.product_string().unwrap_or("unknown"),
        info.vendor_id(),
        info.product_id()
    );

    let device = info
        .open()
        .wait()
        .map_err(ConnectError::CantOpenUsbHandle)?;
    let _configs = device
        .active_configuration()
        .map_err(|e| ConnectError::CantOpenUsbHandle(e.into()))?;

    // claim the interface
    let mut iface = device
        .detach_and_claim_interface(0)
        .wait()
        .map_err(ConnectError::CantOpenUsbHandle)?;

    let strings = AccessoryStrings::new("Android", "Android Auto", "Android Auto", "1.0", "", "")
        .map_err(|_| {
        ConnectError::CantOpenUsbHandle(nusb::Error::other("Invalid accessory settings"))
    })?;

    let protocol = iface
        .start_accessory(&strings, Duration::from_secs(1))
        .map_err(ConnectError::CantOpenUsbAccessory)?;

    info!(
        "USB device 0x{:X} switched to accessory mode with protocol 0x{:X}",
        info.device_address(),
        protocol
    );

    // close device
    drop(device);

    Ok(())
}

pub async fn new(
    wired: Option<UsbId>,
) -> Result<(Device, UsbStreamRead, UsbStreamWrite), ConnectError> {
    // switch all usb devices to accessory mode and ignore errors
    nusb::list_devices()
        .wait()
        .map_err(ConnectError::NoUsbDevice)?
        .filter(|info| {
            if let Some(id) = &wired {
                if id.vid > 0 && id.pid > 0 {
                    info.vendor_id() == id.vid && info.product_id() == id.pid
                } else if id.pid > 0 && id.vid == 0 {
                    info.product_id() == id.pid
                } else if id.vid > 0 && id.pid == 0 {
                    info.vendor_id() == id.vid
                } else {
                    true
                }
            } else {
                true
            }
        })
        .for_each(|info| {
            switch_to_accessory(&info).unwrap_or_default();
        });

    // wait for the app to open and connect
    sleep(Duration::from_secs(1)).await;

    let (device, info, iface, endpoints) = {
        let info = nusb::list_devices()
            .wait()
            .map_err(ConnectError::NoUsbDevice)?
            .find(|d| d.in_accessory_mode())
            .ok_or(nusb::Error::other(
                "No android phone found after switching to accessory. Make sure the phone is set to charging only mode.",
            ))
            .map_err(ConnectError::NoUsbDevice)?;

        let device = info
            .open()
            .wait()
            .map_err(ConnectError::CantOpenUsbHandle)?;
        let configs = device
            .active_configuration()
            .map_err(|e| ConnectError::CantOpenUsbHandle(e.into()))?;

        let iface = device
            .detach_and_claim_interface(0)
            .wait()
            .map_err(ConnectError::CantOpenUsbHandle)?;

        // find endpoints
        let endpoints = configs
            .find_endpoints()
            .map_err(ConnectError::CantOpenUsbAccessoryEndpoint)?;

        (device, info, iface, endpoints)
    };

    let read_endpoint = endpoints.endpoint_in();
    let write_endpoint = endpoints.endpoint_out();

    info!(
        "USB device 0x{:X} opened, read endpoint: 0x{:X}, write endpoint: 0x{:X}",
        info.device_address(),
        read_endpoint.address,
        write_endpoint.address
    );

    let read_queue = iface.endpoint::<Bulk, In>(read_endpoint.address).unwrap();
    let write_queue = iface.endpoint::<Bulk, Out>(write_endpoint.address).unwrap();

    Ok((
        device,
        UsbStreamRead::new(read_queue, iface),
        UsbStreamWrite::new(write_queue),
    ))
}

impl UsbStreamRead {
    pub fn new(mut read_queue: Endpoint<Bulk, In>, iface: Interface) -> Self {
        // Pre-fill the USB host controller's queue so there is never a window
        // where no read URB is pending — even before the first poll_read call.
        for _ in 0..MIN_PENDING_READS {
            let buffer = read_queue.allocate(MAX_PACKET_SIZE);
            read_queue.submit(buffer);
        }
        let counters = Arc::new(UsbReadCounters::new());
        counters.pending_reads.store(read_queue.pending(), Ordering::Relaxed);
        UsbStreamRead {
            read_queue,
            _iface: iface,
            read_buffer: Vec::with_capacity(MAX_PACKET_SIZE),
            read_buffer_pos: 0,
            counters,
        }
    }
}

impl UsbStreamWrite {
    pub fn new(write_queue: Endpoint<Bulk, Out>) -> Self {
        UsbStreamWrite {
            write_queue,
            counters: Arc::new(UsbWriteCounters::new()),
        }
    }

    /// Submit an owned buffer directly, bypassing the `AsyncWrite` trait's
    /// `&[u8]` → `buf.to_vec()` copy.  Allows up to `MAX_PENDING_WRITES`
    /// URBs to be in-flight simultaneously for better write throughput.
    pub async fn write_owned(&mut self, buf: Vec<u8>) -> io::Result<usize> {
        let len = buf.len();

        // Only wait if we're completely saturated
        while self.write_queue.pending() >= MAX_PENDING_WRITES {
            let res = self.write_queue.next_complete().await;
            if let Err(e) = res.status {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        }

        self.write_queue.submit(buf.into());
        self.counters.pending_writes.store(self.write_queue.pending(), Ordering::Relaxed);
        Ok(len)
    }
}

impl AsyncRead for UsbStreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();

        // Helper: keep MIN_PENDING_READS URBs submitted at all times so the
        // USB host controller is never starved — called from BOTH branches.
        // Also updates the shared pending_reads counter for the monitor.
        #[inline(always)]
        fn replenish(pin: &mut UsbStreamRead) {
            while pin.read_queue.pending() < MIN_PENDING_READS {
                let buf = pin.read_queue.allocate(MAX_PACKET_SIZE);
                pin.read_queue.submit(buf);
            }
            pin.counters.pending_reads.store(pin.read_queue.pending(), Ordering::Relaxed);
        }

        let cached_remaining = pin.read_buffer.len() - pin.read_buffer_pos;

        if cached_remaining == 0 {
            // Buffer fully consumed — reset cursor and reuse the allocation.
            pin.read_buffer.clear();
            pin.read_buffer_pos = 0;
            pin.counters.cached_bytes.store(0, Ordering::Relaxed);

            // Ensure the pipeline is primed before we wait.
            replenish(pin);

            // Wait for the next completed URB.
            let res = ready!(pin.read_queue.poll_next_complete(cx));

            // Replenish immediately after reaping so the controller always
            // has work queued by the time we return to the caller.
            replenish(pin);

            // Propagate transfer errors (e.g. device disconnect) instead of
            // silently returning Ok(()) with zero bytes.
            if let Err(e) = res.status {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
            }

            // Copy as much as fits into the caller's ReadBuf.
            let unfilled = buf.initialize_unfilled();
            let copy_len = std::cmp::min(unfilled.len(), res.buffer.len());
            unfilled[..copy_len].copy_from_slice(&res.buffer[..copy_len]);
            buf.advance(copy_len);

            // Stash any overflow for subsequent poll_read calls.
            // read_buffer_pos stays 0 — the cursor starts at the beginning.
            if res.buffer.len() > copy_len {
                pin.read_buffer.extend_from_slice(&res.buffer[copy_len..]);
                pin.counters.cached_bytes.store(pin.read_buffer.len(), Ordering::Relaxed);
            }

            Poll::Ready(Ok(()))
        } else {
            // Serve bytes from the overflow buffer accumulated in a prior poll.
            //
            // Bug fix A: replenish URBs here too.  Without this, both pending
            // URBs can complete while we drain cached data and the hardware
            // goes idle until the next is_empty branch is reached.
            replenish(pin);

            let unfilled = buf.initialize_unfilled();
            if unfilled.is_empty() {
                return Poll::Pending;
            }

            // Bug fix B: advance a cursor instead of Vec::drain.
            // drain(..n) is O(n) — it shifts every remaining byte left.
            // Moving a usize index is O(1) and reuses the same allocation.
            let copy_len = std::cmp::min(unfilled.len(), cached_remaining);
            let src_start = pin.read_buffer_pos;
            unfilled[..copy_len]
                .copy_from_slice(&pin.read_buffer[src_start..src_start + copy_len]);
            pin.read_buffer_pos += copy_len;
            buf.advance(copy_len);

            // Update cached bytes counter: remaining after this copy.
            let remaining = pin.read_buffer.len() - pin.read_buffer_pos;
            pin.counters.cached_bytes.store(remaining, Ordering::Relaxed);

            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for UsbStreamWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let pin = self.get_mut();
        let len = buf.len();

        // Drain completions non-blocking
        while pin.write_queue.pending() > 0 {
            match pin.write_queue.poll_next_complete(cx) {
                Poll::Ready(res) => {
                    if let Err(e) = res.status {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                    }
                }
                Poll::Pending => break,
            }
        }

        // Submit immediately while there is still explicit room in the bounded
        // USB queue; once full, return Pending to propagate backpressure.
        
        if pin.write_queue.pending() >= MAX_PENDING_WRITES {
            // Queue full - apply backpressure
            return Poll::Pending;
        }

        // Submit immediately
        pin.write_queue.submit(buf.to_vec().into());
        pin.counters.pending_writes.store(pin.write_queue.pending(), Ordering::Relaxed);
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let _pin = self.get_mut();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let pin = self.get_mut();
        pin.write_queue.cancel_all();
        Poll::Ready(Ok(()))
    }
}



