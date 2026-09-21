//! Minimal MTP server run during the "legacy" pre-`ACCESSORY_START` stage
//! (see [`crate::usb_functionfs::FfsGadget::run_mtp_stage`]).
//!
//! Ported near-verbatim from the AAWireless-rs POC's `mtp_server.rs`,
//! with permission from its author: "we are moving to a completely
//! different platform, so we're not going to do anything with Rust — you
//! can get rid of the umtprd and the f_accessory crap". The
//! `EndpointReceiver`/`EndpointSender` -> `AsyncRead`/`AsyncWrite`
//! adapters it needs (also ported from that POC, from its `usb.rs`) live
//! in [`crate::ffs_io`] — shared with the accessory-stage bulk pipes.
//!
//! This deliberately answers only enough of the MTP protocol to satisfy a
//! head unit's enumeration/probing before it sends AOA control requests
//! (`GetDeviceInfo` gets a real reply; everything else the operation
//! table below allows just gets an empty `Ok`) — it doesn't serve actual
//! files. That's exactly what the AAWireless POC does too; if some head
//! unit out there needs more than this, this is the file to extend.

use crate::ffs_io::{IntoSinkWriter, IntoStreamReader};
#[allow(unused_imports)]
// ported verbatim from the POC, which imports these but never matches on them
use crate::mtp::mtp_constants::MtpOperation::{
    CloseSession, GetDeviceInfo, GetDevicePropDesc, GetDevicePropValue, GetNumObjects,
    GetObjectHandles, GetStorageIds, GetStorageInfo, OpenSession, ResetDevice,
};
use crate::mtp::mtp_constants::{
    MtpDeviceProperty, MtpEvent, MtpFormat, MtpOperation, MtpResponse, MTP_STANDARD_VERSION,
};
use crate::mtp::mtp_packet::{MtpDataPacket, MtpRequestPacket, MtpResponsePacket};
use anyhow::Result;
use log::{debug, info};
use std::pin::pin;
use usb_gadget::function::custom::{EndpointReceiver, EndpointSender};

const NAME: &str = "<i><bright-black> mtp: </>";

// Only what's needed to look like a plausible Android/MTP device long
// enough for a head unit to move on to probing for AOA support; nothing
// here claims any real media capability, matching the POC exactly.
pub const SUPPORTED_OPERATION_CODES: &[MtpOperation] = &[GetDeviceInfo, OpenSession, CloseSession];
pub const SUPPORTED_EVENT_CODES: &[MtpEvent] = &[];
pub const PLAYBACK_FORMATS: &[MtpFormat] = &[];
pub const CAPTURE_FORMATS: &[MtpFormat] = &[];
pub const DEVICE_PROPERTIES: &[MtpDeviceProperty] = &[];

pub struct MtpServer {
    // Set but never read in the response (matches the POC — GetDeviceInfo's
    // dataset has no "friendly name" field; that's only relevant if
    // DEVICE_PROPERTIES ever grows a DeviceFriendlyName entry).
    #[allow(dead_code)]
    device_name: String,
    device_version: String,
    device_manufacturer: String,
    device_model: String,
    device_serial_number: String,
}

impl MtpServer {
    pub fn new(
        manufacturer: impl Into<String>,
        model: impl Into<String>,
        device_version: impl Into<String>,
        serial_number: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            device_manufacturer: manufacturer.into(),
            device_model: model.into(),
            device_version: device_version.into(),
            device_serial_number: serial_number.into(),
            device_name: device_name.into(),
        }
    }

    fn do_get_device_info(&mut self, data: &mut MtpDataPacket) -> MtpResponse {
        data.put_u16(MTP_STANDARD_VERSION);

        data.put_u32(6u32); // MTP Vendor Extension ID
        data.put_u16(MTP_STANDARD_VERSION);

        data.put_string("microsoft.com: 1.0; android.com: 1.0;");

        data.put_u16(0u16); // Functional Mode

        data.put_a_u16(SUPPORTED_OPERATION_CODES);
        data.put_a_u16(SUPPORTED_EVENT_CODES);
        data.put_a_u16(DEVICE_PROPERTIES);
        data.put_a_u16(CAPTURE_FORMATS);
        data.put_a_u16(PLAYBACK_FORMATS);

        data.put_string(&self.device_manufacturer);
        data.put_string(&self.device_model);
        data.put_string(&self.device_version);
        data.put_string(&self.device_serial_number);

        MtpResponse::Ok
    }

    /// Runs the MTP responder loop until the connection breaks (head unit
    /// moves on / gadget gets torn down) or a protocol error occurs. The
    /// caller (`run_mtp_stage`) races this against `ACCESSORY_START`
    /// showing up on ep0 and a timeout — it's expected to end with an
    /// error once the accessory-stage gadget replaces this one.
    pub async fn start(
        &mut self,
        receiver: EndpointReceiver,
        sender: EndpointSender,
    ) -> Result<()> {
        let mut reader = pin!(receiver.into_stream_reader()?);
        let mut writer = pin!(sender.into_sink_writer()?);

        loop {
            let request = MtpRequestPacket::read(&mut reader).await?;
            let mut data = MtpDataPacket::from(&request);
            debug!("{} request: {:?}", NAME, request);

            let response = match request.code {
                GetDeviceInfo => self.do_get_device_info(&mut data),
                OpenSession | GetNumObjects | GetStorageIds | GetStorageInfo | GetObjectHandles
                | ResetDevice | CloseSession => MtpResponse::Ok,
                _ => MtpResponse::OperationNotSupported,
            };

            let mut response = MtpResponsePacket::new(response, request.transaction_id);
            if data.has_data() {
                data.write(&mut writer).await?;
            }
            info!("{} {:?} -> {:?}", NAME, request.code, response.code);
            response.write(&mut writer).await?;
        }
    }
}
