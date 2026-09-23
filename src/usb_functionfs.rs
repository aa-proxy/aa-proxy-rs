//! FunctionFS-based USB gadget for the head-unit (HU) side.
//!
//! Replaces the old `f_accessory` kernel module + external configfs
//! `default`/`accessory` gadgets (bound/unbound via [`crate::usb_gadget`],
//! now removed) + netlink uevent listener + `/dev/usb_accessory` char
//! device + `umtprd`. All of that is gone; the whole Android Open
//! Accessory (AOA) handshake and the bulk data pipes to the head unit are
//! now implemented here, in-process, on top of real FunctionFS
//! (`usb-gadget` crate, `Custom`/FFS function).
//!
//! Credit: the FunctionFS/AOA approach and the ep0 control-request
//! handling below are adapted from a work-in-progress rewrite of
//! AAWireless (`aawireless-rs`), whose author suggested this replacement
//! and gave permission to reuse the relevant bits ("you can get rid of
//! the umtprd and the f_accessory crap").
//!
//! ## Known limitation: `io-uring` feature
//! [`EndpointReceiver`]/[`EndpointSender`] from the `usb-gadget` crate are
//! backed by Linux AIO and driven through tokio's `AsyncFd` (feature
//! `tokio`). They are bound to whatever tokio runtime was active when
//! created. `tokio_main` (where gadget setup happens) always runs on the
//! normal multi-threaded tokio runtime, so that part is fine either way.
//! But `io_loop` (the actual HU/MD data-forwarding loop) runs on a
//! *separate* `tokio_uring` runtime when the `io-uring` feature is
//! active, and polling an `AsyncFd` registered against a different
//! runtime from there is not sound. Bridging the two (e.g. via a
//! socketpair + a forwarding task living in the tokio_main runtime) is
//! possible but needs on-target testing/benchmarking before it's worth
//! shipping, so for now: **the real HU-via-USB-gadget path only works in
//! builds without the `io-uring` feature.** `main.rs` checks this at
//! startup and refuses to run the USB-gadget path otherwise (DHU/TCP
//! head-unit-emulator mode is unaffected either way).

use crate::device_info;
use crate::ffs_io::{IntoSinkWriter, IntoStreamReader};
use crate::mtp::mtp_server::MtpServer;
use anyhow::{anyhow, Context, Result};
use simplelog::*;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_util::sync::CancellationToken;
use usb_gadget::function::custom::{
    Custom, Endpoint, EndpointDirection, EndpointReceiver, EndpointSender, Event, Interface,
    OsExtCompat, TransferType,
};
use usb_gadget::function::msd::Msd;
use usb_gadget::{udcs, Class, Config, Gadget, Id, RegGadget, Strings, Udc};

// module name for logging engine (matches the style of the other modules)
const NAME: &str = "<i><bright-black> ffs: </>";

// Android Open Accessory (AOA) vendor control requests.
// See: https://source.android.com/devices/accessories/aoa
const USB_TYPE_MASK: u8 = 0x60;
const USB_TYPE_VENDOR: u8 = 0x40;
const AOA_GET_PROTOCOL: u8 = 51;
const AOA_SEND_STRING: u8 = 52;
const AOA_START: u8 = 53;
const AOA_SET_AUDIO_MODE: u8 = 58;

// Standard Google AOA accessory VID/PID (same ones the phone-side/nusb code
// in `usb_stream.rs`/`aoa.rs` already looks for).
const AOA_ACCESSORY_VID: u16 = 0x18d1;
const AOA_ACCESSORY_PID: u16 = 0x2d00;
// VID/PID used only while presenting as a generic MTP-class device in the
// "legacy" pre-switch stage, so head units that insist on seeing a
// default-then-accessory dance get one; a real (if minimal) MTP responder
// (`crate::mtp`) is served behind it — see `run_mtp_stage`.
const MTP_STAGE_VID: u16 = 0x18d1;
const MTP_STAGE_PID: u16 = 0x4ee1;

/// Read/write halves of the active accessory session, handed off to
/// `proxy::io_loop` once the AOA handshake has completed (or been given
/// up on, see `require_accessory_start`).
pub struct AccessorySession {
    pub reader: FfsRead,
    pub writer: FfsWrite,
}

/// Slot used to hand an [`AccessorySession`] from the gadget-setup code
/// (running in `tokio_main`) over to `proxy::io_loop`, replacing the old
/// "open /dev/usb_accessory after being notified" dance. The
/// `usb_accessory_ready` `Notify` is still used for the actual
/// wake-up/timing; this is just the payload.
pub type SharedAccessorySession = Arc<Mutex<Option<AccessorySession>>>;

type BoxedByteStream =
    Pin<Box<dyn futures::Stream<Item = std::io::Result<bytes::BytesMut>> + Send>>;
type BoxedByteSink = Pin<Box<dyn for<'a> futures::Sink<&'a [u8], Error = std::io::Error> + Send>>;

/// Read half of the Android Accessory bulk pipe to the head unit. Thin
/// wrapper so the type is nameable/storable (`into_stream_reader()`
/// itself returns an unnameable `impl Stream`) — the actual data path
/// (`crate::ffs_io::IntoStreamReader`) is the same POC-proven code the
/// MTP responder uses, not a separate implementation.
pub struct FfsRead {
    inner: StreamReader<BoxedByteStream, bytes::BytesMut>,
}

impl FfsRead {
    fn new(receiver: EndpointReceiver) -> std::io::Result<Self> {
        let stream: BoxedByteStream = Box::pin(receiver.into_stream_reader()?.into_inner());
        Ok(Self {
            inner: StreamReader::new(stream),
        })
    }

    /// Reads at least one byte into `buf`, returning the number of bytes
    /// read. A genuine disconnect surfaces as an `Err` here (matches the
    /// old file-based `/dev/usb_accessory` EOF-on-error convention well
    /// enough for `io_loop`'s error handling; this backend just doesn't
    /// have a real `0`-length-read EOF signal to begin with).
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).await
    }
}

/// Write half of the Android Accessory bulk pipe to the head unit. Same
/// "thin nameable wrapper around the POC-proven `ffs_io` code" idea as
/// [`FfsRead`].
pub struct FfsWrite {
    inner: SinkWriter<BoxedByteSink>,
}

impl FfsWrite {
    fn new(sender: EndpointSender) -> std::io::Result<Self> {
        let sink: BoxedByteSink = Box::pin(sender.into_sink_writer()?.into_inner());
        Ok(Self {
            inner: SinkWriter::new(sink),
        })
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf).await?;
        self.inner.flush().await?;
        Ok(n)
    }
}

struct ActiveGadget {
    // Kept alive only to hold the UDC binding; dropping it (or calling
    // `.remove()`) tears the gadget down. Never read directly.
    _gadget: RegGadget,
    ep0_cancel: CancellationToken,
    ep0_task: JoinHandle<()>,
}

impl ActiveGadget {
    async fn teardown(self) {
        self.ep0_cancel.cancel();
        let _ = self.ep0_task.await;
        // `_gadget`'s Drop unbinds from the UDC and removes it from configfs.
    }
}

/// Owns the lifecycle of the FunctionFS-based Android Accessory gadget
/// across the whole run of aa-proxy-rs: build it, wait for the head unit
/// to complete the AOA handshake, hand the resulting pipes to the proxy,
/// tear it down between sessions ("rearm"), repeat.
pub struct FfsGadget {
    legacy: bool,
    udc_name: Option<String>,
    manufacturer: String,
    product: String,
    serial: String,
    // MTP GetDeviceInfo "device version" string — same value as the old
    // umtprd.conf.in's FIRMWARE_VER (build date + git rev), not a USB
    // bcdDevice.
    firmware_version: String,
    // Backing file or block device for an optional mass-storage LUN
    // presented alongside the accessory interface (e.g. a FAT-formatted
    // disk image, or a raw partition like /dev/mmcblk0p5). `None` (the
    // default) keeps the old behavior exactly — no mass-storage function
    // is added at all.
    usb_stick: Option<PathBuf>,
    active: Option<ActiveGadget>,
}

impl FfsGadget {
    /// `legacy` mirrors the old config flag of the same name: present a
    /// generic MTP-class interface first and wait for the head unit to
    /// send AOA_START on *that* before switching to the real Android
    /// Accessory interface, for head units that need the "default then
    /// accessory" dance. When `false`, go straight to the Accessory
    /// interface (matches the old "non-legacy" behavior).
    ///
    /// `usb_stick`, when set, is the backing file or block device (e.g. a
    /// FAT-formatted disk image, or a raw partition like
    /// `/dev/mmcblk0p5`) for a USB mass-storage LUN added to the
    /// accessory gadget alongside the AOA interface, so the head unit
    /// sees a "USB stick" for the duration of the session. `None`/unset
    /// (the config default) reproduces the exact old behavior: no
    /// mass-storage function at all.
    ///
    /// Manufacturer/product/serial and the MTP-stage identity below are
    /// deliberately the exact same values the old `S92usb_gadget.in` /
    /// `umtprd.conf.in` templates used to fill in (same "aa-proxy{model}"
    /// naming, same VID/PID, same bcdDevice for the MTP-stage gadget) —
    /// this is proven, hardware-tested identity, not something to
    /// reinvent.
    pub fn new(legacy: bool, udc_name: Option<String>, usb_stick: Option<String>) -> Self {
        let model = device_info::get_sbc_model()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        let serial = read_serial_number().unwrap_or_else(|_| "0123456".to_string());
        let firmware_version = format!(
            "{}, git: {}-{}",
            env!("BUILD_DATE"),
            env!("GIT_DATE"),
            env!("GIT_HASH")
        );
        Self {
            legacy,
            udc_name,
            manufacturer: "aa-proxy".to_string(),
            product: format!("aa-proxy{model}"),
            serial,
            firmware_version,
            usb_stick: usb_stick.map(PathBuf::from),
            active: None,
        }
    }

    /// Removes any leftover USB gadgets from a previous run. Cheap/no-op
    /// if there are none; call once at startup, like the old
    /// `UsbGadgetState::init()`.
    pub fn init(&mut self) -> Result<()> {
        info!("{} 🔌 Initializing USB Manager (FunctionFS)", NAME);
        usb_gadget::remove_all().context("removing leftover USB gadgets")?;
        Ok(())
    }

    fn select_udc(&self) -> Result<Udc> {
        match &self.udc_name {
            Some(name) => udcs()
                .context("listing USB device controllers")?
                .into_iter()
                .find(|u| u.name().to_string_lossy() == name.as_str())
                .ok_or_else(|| anyhow!("configured UDC {name:?} not found")),
            None => usb_gadget::default_udc().context("no USB device controller (UDC) available"),
        }
    }

    async fn teardown_active(&mut self) {
        if let Some(active) = self.active.take() {
            active.teardown().await;
        }
    }

    /// A failed `Gadget::bind()`/`register()` can leave a partially-built
    /// gadget directory behind in configfs: registration happens in
    /// several small steps (mkdir, write descriptors, register the
    /// function...), and if it fails partway through, the crate hasn't
    /// constructed a `RegGadget` yet at that point, so there's nothing
    /// for `teardown_active()` (or that failed attempt's own `Drop`) to
    /// clean up. Left alone, these stray directories pile up across
    /// retries and can end up blocking the *next* bind attempt too, even
    /// a completely unrelated one (e.g. the accessory stage after a
    /// failed MTP stage) — so sweep them up after every failed attempt,
    /// not just between sessions.
    fn sweep_stray_gadgets(&self) {
        if let Err(e) = usb_gadget::remove_all() {
            debug!("{} 🔌 USB Manager: stray-gadget sweep: {e:#}", NAME);
        }
    }

    /// Runs the AOA handshake (optionally preceded by the MTP-class
    /// "legacy" stage) and returns the resulting bulk read/write pipes.
    ///
    /// Only the MTP stage actually waits for `ACCESSORY_START` — that's
    /// the head unit's signal to switch from the MTP-class default
    /// interface to the real accessory interface, matching the
    /// AAWireless POC. If the MTP stage never sees it:
    /// - `require_accessory_start = true`: retries a couple of times,
    ///   then gives up and returns `None` (mirrors the old
    ///   `usb_gadget_require_accessory_start` behavior).
    /// - `require_accessory_start = false`: logs a warning and goes
    ///   straight to presenting the accessory interface anyway — some
    ///   head units work fine connecting directly to it (see this
    ///   project's own README on `legacy`/direct-accessory head units).
    pub async fn enable_default_and_wait_for_accessory(
        &mut self,
        require_accessory_start: bool,
    ) -> bool {
        self.wait_for_accessory_session(require_accessory_start)
            .await
            .is_some()
    }

    /// Same as [`Self::enable_default_and_wait_for_accessory`], but
    /// returns the session itself instead of a bool, so callers can hand
    /// it off to `io_loop`.
    pub async fn wait_for_accessory_session(
        &mut self,
        require_accessory_start: bool,
    ) -> Option<AccessorySession> {
        const MTP_WAIT_TIMEOUT: Duration = Duration::from_secs(6);
        const MAX_TRIES: u32 = 2;
        // How long to wait after tearing a failed gadget down before trying
        // again. Deliberately generous (not just "a moment") — too short a
        // gap has been observed to leave old/slow UDC drivers (dwc2 on a
        // 4.4 kernel) in a stuck state after a few rapid rebind attempts.
        const RETRY_SETTLE_DELAY: Duration = Duration::from_millis(1000);

        self.teardown_active().await;
        self.sweep_stray_gadgets();

        let udc = match self.select_udc() {
            Ok(udc) => udc,
            Err(e) => {
                warn!("{} 🔌 USB Manager: {e:#}", NAME);
                return None;
            }
        };
        info!("{} 🔌 USB Manager: using UDC {:?}", NAME, udc.name());

        if self.legacy {
            let mut got_start = false;
            for try_n in 1..=MAX_TRIES {
                match self.run_mtp_stage(&udc, MTP_WAIT_TIMEOUT).await {
                    Ok(()) => {
                        got_start = true;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "{} 🔌 USB Manager: MTP stage failed (try {try_n}/{MAX_TRIES}): {e:#}",
                            NAME
                        );
                        self.teardown_active().await;
                        self.sweep_stray_gadgets();
                        // Old/slow UDC drivers (seen on a 4.4 kernel dwc2
                        // controller) can need real time to fully drop the
                        // previous gadget before a fresh bind attempt
                        // succeeds; a too-short gap here reproduced as a
                        // rapid connect/disconnect storm in dmesg that
                        // eventually left the controller stuck.
                        tokio::time::sleep(RETRY_SETTLE_DELAY).await;
                    }
                }
            }

            if !got_start {
                warn!(
                    "{} 🔌 USB Manager: no ACCESSORY_START seen in MTP stage after retries",
                    NAME
                );
                if require_accessory_start {
                    return None;
                }
                warn!(
                    "{} 🔌 USB Manager: proceeding straight to the accessory gadget anyway",
                    NAME
                );
                tokio::time::sleep(RETRY_SETTLE_DELAY).await;
            } else {
                info!("{} 🔌 USB Manager: switching to accessory gadget", NAME);
                // let the host perceive the interface change, same as the
                // 500ms settle delay the old code (and the AAWireless POC)
                // used between the MTP and accessory stages.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        match self.run_accessory_stage(&udc).await {
            Ok(session) => Some(session),
            Err(e) => {
                warn!(
                    "{} 🔌 USB Manager: failed to enable accessory gadget: {e:#}",
                    NAME
                );
                self.teardown_active().await;
                self.sweep_stray_gadgets();
                None
            }
        }
    }

    /// Tears down the current gadget and waits `cooldown` before the next
    /// session, mirroring the old `rearm_for_next_session`.
    pub async fn rearm_for_next_session(&mut self, cooldown: Duration) {
        info!(
            "{} 🔌 USB Manager: Re-arming USB gadget for next session (cooldown={}ms)",
            NAME,
            cooldown.as_millis()
        );
        self.teardown_active().await;
        if !cooldown.is_zero() {
            tokio::time::sleep(cooldown).await;
        }
    }

    /// Presents a generic MTP-class interface and runs a minimal MTP
    /// responder (`crate::mtp::mtp_server::MtpServer`, ported from the
    /// AAWireless POC) behind it, so head units that require seeing a
    /// working Android-phone-like default interface before probing for
    /// AOA support get one — same behavior as the POC, not just the same
    /// interface descriptor. Waits for the head unit to send
    /// `ACCESSORY_START` on ep0.
    async fn run_mtp_stage(&mut self, udc: &Udc, wait_timeout: Duration) -> Result<()> {
        let (mtp_ep1, mtp_ep1_dir) = EndpointDirection::host_to_device();
        let (mtp_ep2, mtp_ep2_dir) = EndpointDirection::device_to_host();
        let (_mtp_int, mtp_int_dir) = EndpointDirection::device_to_host();

        let mut builder = Custom::builder().with_interface(
            Interface::new(Class::new(0x06, 0x01, 0x01), "MTP")
                .with_endpoint(Endpoint::bulk(mtp_ep1_dir))
                .with_endpoint(Endpoint::bulk(mtp_ep2_dir))
                .with_endpoint(Endpoint::custom(mtp_int_dir, TransferType::Interrupt))
                .with_os_ext_compat(OsExtCompat::new(*b"MTP\0\0\0\0\0", [0u8; 8])),
        );
        builder.all_ctrl_recipient = true;
        builder.config0_setup = true;

        let (mut custom, handle) = builder.build();

        let mut gadget = Gadget::new(
            Class::INTERFACE_SPECIFIC,
            Id::new(MTP_STAGE_VID, MTP_STAGE_PID),
            Strings::new(&self.manufacturer, &self.product, &self.serial),
        )
        .with_config(Config::new("config").with_function(handle));
        // bcdDevice: matches the old umtprd.conf.in's `usb_dev_version 0x3008`
        // exactly (BCD-encoded — no nibble above 9), which is what the
        // hardware-tested setup reported here; the accessory-stage gadget
        // never set this explicitly, so we don't either.
        gadget.device_release = 0x3008;

        let reg = gadget.bind(udc).context("binding MTP-stage gadget")?;

        // Same manufacturer/product/serial/firmware-version the old,
        // hardware-tested umtprd.conf.in reported over MTP — deliberately
        // *not* the AAWireless POC's "Google"/"Nexus"/"1.0" placeholder
        // identity: this is the real, proven identity for this project,
        // no need to guess when we have it.
        let mut mtp_server = MtpServer::new(
            &self.manufacturer,
            &self.product,
            &self.firmware_version,
            &self.serial,
            &self.product,
        );
        let mtp_task = tokio::spawn(async move {
            if let Err(e) = mtp_server.start(mtp_ep1, mtp_ep2).await {
                debug!("{} MTP responder stopped: {e}", NAME);
            }
        });

        let deadline = tokio::time::Instant::now() + wait_timeout;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break Err(anyhow!(
                    "no ACCESSORY_START seen in MTP stage within {wait_timeout:?}"
                ));
            }

            match timeout(remaining, custom.wait_event()).await {
                Ok(Ok(())) => match custom.event() {
                    Ok(event) => {
                        if handle_ep0_event(event) {
                            break Ok(());
                        }
                    }
                    Err(e) => debug!("{} MTP stage: event() error: {e}", NAME),
                },
                Ok(Err(e)) => break Err(e).context("MTP stage: wait_event() failed"),
                Err(_) => break Err(anyhow!("timeout waiting for MTP-stage event")),
            }
        };

        mtp_task.abort();
        let _ = reg.remove();
        result
    }

    /// Binds the real Android Accessory interface (matching the AOA VID/PID
    /// the phone-side code in `aoa.rs`/`usb_stream.rs` also looks for) and
    /// returns the bulk pipes immediately. Unlike the MTP stage, this does
    /// *not* wait for `ACCESSORY_START` — matching the AAWireless POC: once
    /// a device already presents itself as the final `18d1:2d00` accessory
    /// interface, there's nothing left to negotiate on ep0 before bulk data
    /// can flow (`ACCESSORY_START` is what triggers switching *to* this
    /// interface in the first place, not something to wait for once you're
    /// already on it). A background task keeps servicing ep0 for the life
    /// of the session so the host's other control requests (there
    /// shouldn't normally be many) don't stall.
    async fn run_accessory_stage(&mut self, udc: &Udc) -> Result<AccessorySession> {
        let (ep_out, ep_out_dir) = EndpointDirection::host_to_device();
        let (ep_in, ep_in_dir) = EndpointDirection::device_to_host();

        let mut builder = Custom::builder().with_interface(
            Interface::new(
                Class::vendor_specific(0xff, 0),
                "Android Accessory Interface",
            )
            .with_endpoint(Endpoint::bulk(ep_out_dir))
            .with_endpoint(Endpoint::bulk(ep_in_dir)),
        );
        builder.all_ctrl_recipient = true;
        builder.config0_setup = true;

        let (mut custom, handle) = builder.build();

        let mut config = Config::new("config").with_function(handle);
        if let Some(path) = &self.usb_stick {
            if path.exists() {
                match Msd::new(path) {
                    Ok((_msd, msd_handle)) => {
                        config = config.with_function(msd_handle);
                        info!(
                            "{} 🔌 attaching USB mass-storage LUN: {}",
                            NAME,
                            path.display()
                        );
                    }
                    Err(e) => {
                        warn!(
                            "{} 🔌 USB Manager: failed to set up mass-storage LUN ({}): {e:#}",
                            NAME,
                            path.display()
                        );
                    }
                }
            } else {
                warn!(
                    "{} 🔌 USB Manager: configured usb_stick path not found, skipping: {}",
                    NAME,
                    path.display()
                );
            }
        }

        let gadget = Gadget::new(
            Class::INTERFACE_SPECIFIC,
            Id::new(AOA_ACCESSORY_VID, AOA_ACCESSORY_PID),
            Strings::new(&self.manufacturer, &self.product, &self.serial),
        )
        .with_config(config);

        let reg = gadget.bind(udc).context("binding accessory gadget")?;
        info!(
            "{} 🔌 accessory gadget bound (vid={:04x}, pid={:04x})",
            NAME, AOA_ACCESSORY_VID, AOA_ACCESSORY_PID
        );

        let cancel = CancellationToken::new();
        let cancel_bg = cancel.clone();
        let ep0_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_bg.cancelled() => break,
                    res = custom.wait_event() => {
                        if res.is_err() {
                            warn!("{} accessory ep0: wait_event() failed, stopping", NAME);
                            break;
                        }
                        match custom.event() {
                            Ok(event) => { handle_ep0_event(event); }
                            Err(e) => debug!("{} accessory ep0: event() error: {e}", NAME),
                        }
                    }
                }
            }
        });

        let reader = FfsRead::new(ep_out).context("setting up accessory read pipe")?;
        let writer = FfsWrite::new(ep_in).context("setting up accessory write pipe")?;
        info!("{} 🔌 accessory bulk pipes ready", NAME);

        self.active = Some(ActiveGadget {
            _gadget: reg,
            ep0_cancel: cancel,
            ep0_task,
        });

        Ok(AccessorySession { reader, writer })
    }
}

/// Same file `main.rs::get_serial_number()` reads; duplicated here (rather
/// than reused) because that one lives in the binary crate and isn't
/// visible from library modules like this one.
fn read_serial_number() -> Result<String> {
    Ok(
        std::fs::read_to_string("/sys/firmware/devicetree/base/serial-number")
            .context("reading device serial number")?
            .trim_end_matches(char::from(0))
            .trim()
            .to_string(),
    )
}

/// Handles one ep0 control-request event. Returns `true` when it was
/// `ACCESSORY_START`. Ported from the AAWireless POC's
/// `handle_control_request`.
fn handle_ep0_event(event: Event) -> bool {
    match event {
        Event::SetupDeviceToHost(req) => {
            let ctrl_req = req.ctrl_req();
            let request_type = ctrl_req.request_type;
            let request = ctrl_req.request;
            let length = ctrl_req.length;

            if (request_type & USB_TYPE_MASK) == USB_TYPE_VENDOR {
                match request {
                    AOA_GET_PROTOCOL => {
                        info!("{} received AOA GET_PROTOCOL", NAME);
                        let _ = req.send(&[0x02, 0x00]);
                    }
                    _ => {
                        // Unhandled IN/vendor request: empty response is
                        // safer than stalling, keeps the connection alive.
                        let empty = vec![0u8; length as usize];
                        let _ = req.send(&empty);
                    }
                }
            } else {
                let empty = vec![0u8; length as usize];
                let _ = req.send(&empty);
            }
        }

        Event::SetupHostToDevice(req) => {
            let ctrl_req = req.ctrl_req();
            let request_type = ctrl_req.request_type;
            let request = ctrl_req.request;
            let value = ctrl_req.value;
            let length = ctrl_req.length;

            if (request_type & USB_TYPE_MASK) == USB_TYPE_VENDOR {
                match request {
                    AOA_SEND_STRING => {
                        if let Ok(data) = req.recv_all() {
                            debug!(
                                "{} received AOA string index {value}: {}",
                                NAME,
                                String::from_utf8_lossy(&data)
                            );
                        }
                    }
                    AOA_START => {
                        let _ = req.recv_all();
                        info!("{} 🔌 received AOA start request", NAME);
                        return true;
                    }
                    AOA_SET_AUDIO_MODE => {
                        let _ = req.recv_all();
                    }
                    _ => {
                        if length > 0 {
                            let _ = req.recv_all();
                        }
                    }
                }
            } else if length > 0 {
                let _ = req.recv_all();
            }
        }

        other => {
            info!("{} ep0 event: {other:?}", NAME);
        }
    }

    false
}
