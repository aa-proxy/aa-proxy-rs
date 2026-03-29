use nusb::Endpoint;
use nusb::{
    transfer::{Bulk, In, Out},
    Device, MaybeFuture,
};
use simplelog::*;
use std::io;
use std::pin::Pin;
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

pub struct UsbStreamRead {
    pub read_queue: Endpoint<Bulk, In>,
    read_buffer: Vec<u8>,
}
pub struct UsbStreamWrite {
    pub write_queue: Endpoint<Bulk, Out>,
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
        UsbStreamRead::new(read_queue),
        UsbStreamWrite::new(write_queue),
    ))
}

impl UsbStreamRead {
    pub fn new(read_queue: Endpoint<Bulk, In>) -> Self {
        UsbStreamRead {
            read_queue,
            read_buffer: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }
}

impl UsbStreamWrite {
    pub fn new(write_queue: Endpoint<Bulk, Out>) -> Self {
        UsbStreamWrite { write_queue }
    }
}

impl AsyncRead for UsbStreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();

        // either read from local buffer or request from remote
        if pin.read_buffer.is_empty() {
            // make sure there's pending request
            if pin.read_queue.pending() == 0 {
                let buffer = pin.read_queue.allocate(MAX_PACKET_SIZE);
                pin.read_queue.submit(buffer);
            }

            // try to read from the remote
            let res = ready!(pin.read_queue.poll_next_complete(cx));

            // copy into the buffer
            // copy into poll buffer
            let copy_from_buffer = {
                let unfilled = buf.initialize_unfilled();
                let copy_from_buffer = std::cmp::min(unfilled.len(), res.buffer.len());
                unfilled[..copy_from_buffer].copy_from_slice(&res.buffer[..copy_from_buffer]);

                copy_from_buffer
            };
            buf.advance(copy_from_buffer);
            // copy the rest into local buffer
            pin.read_buffer
                .extend_from_slice(&res.buffer[copy_from_buffer..]);
            // submit new request
            let buffer = pin.read_queue.allocate(MAX_PACKET_SIZE);
            pin.read_queue.submit(buffer);
            Poll::Ready(Ok(()))
        } else {
            let copy_from_buffer = {
                let unfilled = buf.initialize_unfilled();

                // check if possible to read more
                if unfilled.is_empty() {
                    return Poll::Pending;
                }

                // first copy from local buffer
                let copy_from_buffer = std::cmp::min(unfilled.len(), pin.read_buffer.len());

                if copy_from_buffer > 0 {
                    unfilled[..copy_from_buffer]
                        .copy_from_slice(&pin.read_buffer[..copy_from_buffer]);
                    pin.read_buffer.drain(..copy_from_buffer);
                }

                copy_from_buffer
            };

            buf.advance(copy_from_buffer);

            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for UsbStreamWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let pin = self.get_mut();

        // extend to local buffer
        pin.write_queue.submit(buf.to_vec().into());
        use futures::executor::block_on;

        if pin.write_queue.pending() > 0 {
            let res = block_on(pin.write_queue.next_complete());
            match res.status {
                Ok(_) => Poll::Ready(Ok(0 /*res.data.actual_length()*/)),
                Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            }
        } else {
            Poll::Ready(Ok(0))
        }
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
