use crate::btle;
use crate::config::Action;
use crate::config::SharedConfig;
use crate::config::WifiConfig;
use crate::config::IDENTITY_NAME;
use crate::config_types::BluetoothAddressList;
use crate::sdr_ui;
use crate::web::AppState;
use anyhow::anyhow;
use backon::{ExponentialBuilder, Retryable};
use bluer::{
    rfcomm::{Profile, ProfileHandle, ReqError, Role, SocketAddr, Stream},
    Adapter, Address, Uuid,
};
use futures::StreamExt;
use simplelog::*;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::Notify;
use tokio::time::timeout;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use protobuf::Message;
use WifiInfoResponse::AccessPointType;
use WifiInfoResponse::SecurityMode;
const HEADER_LEN: usize = 4;
const STAGES: u8 = 5;
const ATTEMPTS: usize = 3;

// module name for logging engine
const NAME: &str = "<i><bright-black> bluetooth: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const AAWG_PROFILE_UUID: Uuid = Uuid::from_u128(0x4de17a0052cb11e6bdf40800200c9a66);
pub const BTLE_PROFILE_UUID: Uuid = Uuid::from_u128(0x9b3f6c10a4d2418ea2b90700300de8f4);
const HSP_HS_UUID: Uuid = Uuid::from_u128(0x0000110800001000800000805f9b34fb);
const HSP_AG_UUID: Uuid = Uuid::from_u128(0x0000111200001000800000805f9b34fb);
pub const KNOWN_DEVICES_FILE: &str = concat!(crate::base_config_dir!(), "/known_devices");

#[derive(Debug, Clone, PartialEq)]
#[repr(u16)]
#[allow(unused)]
enum MessageId {
    WifiStartRequest = 1,
    WifiInfoRequest = 2,
    WifiInfoResponse = 3,
    WifiVersionRequest = 4,
    WifiVersionResponse = 5,
    WifiConnectStatus = 6,
    WifiStartResponse = 7,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(unused)]
enum PocMessageId {
    WifiStartRequest = 1,
    WifiInfoRequest = 2,
    WifiInfoResponse = 3,
    WifiVersionRequest = 4,
    WifiVersionResponse = 5,
    WifiConnectStatus = 6,
    WifiStartResponse = 7,
}

impl PocMessageId {
    fn name(id: u16) -> &'static str {
        match id {
            1 => "WifiStartRequest",
            2 => "WifiInfoRequest",
            3 => "WifiInfoResponse",
            4 => "WifiVersionRequest",
            5 => "WifiVersionResponse",
            6 => "WifiConnectStatus",
            7 => "WifiStartResponse",
            _ => "Unknown",
        }
    }
}

struct PocFrameSniffer {
    direction: &'static str,
    buf: Vec<u8>,
}

impl PocFrameSniffer {
    fn new(direction: &'static str) -> Self {
        Self {
            direction,
            buf: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        while self.buf.len() >= HEADER_LEN {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < HEADER_LEN + len {
                break;
            }

            let message_id = u16::from_be_bytes([self.buf[2], self.buf[3]]);
            let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
            self.log_frame(message_id, &payload);
            self.buf.drain(..HEADER_LEN + len);
        }

        if self.buf.len() > 1024 * 1024 {
            warn!(
                "{} 🧪 bt-wireless-poc: {} parser buffer exceeded 1 MiB; clearing partial data",
                NAME, self.direction
            );
            self.buf.clear();
        }
    }

    fn log_frame(&self, message_id: u16, payload: &[u8]) {
        info!(
            "{} 🧪 bt-wireless-poc: {} frame id={} ({}) len={} payload={}",
            NAME,
            self.direction,
            message_id,
            PocMessageId::name(message_id),
            payload.len(),
            if payload.is_empty() {
                "<empty>".to_string()
            } else {
                hex::encode(payload)
            }
        );

        match message_id {
            x if x == PocMessageId::WifiStartRequest as u16 => {
                match WifiStartRequest::WifiStartRequest::parse_from_bytes(payload) {
                    Ok(req) => info!(
                        "{} 🧪 bt-wireless-poc: {} parsed WifiStartRequest ip={} port={}",
                        NAME,
                        self.direction,
                        req.ip_address(),
                        req.port()
                    ),
                    Err(e) => warn!(
                        "{} 🧪 bt-wireless-poc: {} failed to parse WifiStartRequest: {}",
                        NAME, self.direction, e
                    ),
                }
            }
            x if x == PocMessageId::WifiInfoResponse as u16 => {
                match WifiInfoResponse::WifiInfoResponse::parse_from_bytes(payload) {
                    Ok(info_msg) => info!(
                        "{} 🧪 bt-wireless-poc: {} parsed WifiInfoResponse ssid={} bssid={} security={:?} ap_type={:?} key_len={}",
                        NAME,
                        self.direction,
                        info_msg.ssid(),
                        info_msg.bssid(),
                        info_msg.security_mode(),
                        info_msg.access_point_type(),
                        info_msg.key().len()
                    ),
                    Err(e) => warn!(
                        "{} 🧪 bt-wireless-poc: {} failed to parse WifiInfoResponse: {}",
                        NAME, self.direction, e
                    ),
                }
            }
            _ => {}
        }
    }
}

struct PocHuConnection {
    stream: Stream,
    endpoint: String,
    _client_profile_session: Option<bluer::Session>,
    _client_profile_handle: Option<ProfileHandle>,
}

async fn relay_with_poc_logging<R, W>(
    mut reader: R,
    mut writer: W,
    direction: &'static str,
) -> Result<u64>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut sniffer = PocFrameSniffer::new(direction);
    let mut total = 0u64;
    let mut buf = vec![0u8; 4096];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            info!(
                "{} 🧪 bt-wireless-poc: {} EOF after {} bytes",
                NAME, direction, total
            );
            let _ = writer.shutdown().await;
            return Ok(total);
        }

        let chunk = &buf[..n];
        sniffer.push(chunk);
        writer.write_all(chunk).await?;
        total += n as u64;
    }
}

async fn read_poc_frame(stream: &mut Stream, direction: &'static str) -> Result<(u16, Vec<u8>)> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[0], header[1]]) as usize;
    let message_id = u16::from_be_bytes([header[2], header[3]]);
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    let mut full = header.to_vec();
    full.extend_from_slice(&payload);
    let mut sniffer = PocFrameSniffer::new(direction);
    sniffer.push(&full);
    Ok((message_id, payload))
}

async fn send_poc_frame(
    stream: &mut Stream,
    direction: &'static str,
    message_id: PocMessageId,
    payload: &[u8],
) -> Result<()> {
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(message_id as u16).to_be_bytes());
    packet.extend_from_slice(payload);

    let mut sniffer = PocFrameSniffer::new(direction);
    sniffer.push(&packet);
    stream.write_all(&packet).await?;
    Ok(())
}

fn success_status_payload() -> &'static [u8] {
    // MessageStatus::OK encoded as proto2 field #1 varint 0.
    &[0x08, 0x00]
}

pub struct Bluetooth {
    adapter: Adapter,
    handle_aa: Option<ProfileHandle>,
    btle_handle: Option<bluer::gatt::local::ApplicationHandle>,
    adv_handle: Option<bluer::adv::AdvertisementHandle>,
    current_index: usize,
    dongle_mode: bool,
}

// Create and configure the Bluetooth adapter
pub async fn init(
    btalias: Option<String>,
    advertise: bool,
    dongle_mode: bool,
    register_aa_wireless_profile: bool,
) -> Result<Bluetooth> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;

    // setting BT alias for further use
    let alias = match btalias {
        None => match get_cpu_serial_number_suffix().await {
            Ok(suffix) => format!("{}-{}", IDENTITY_NAME, suffix),
            Err(_) => String::from(IDENTITY_NAME),
        },
        Some(btalias) => btalias,
    };
    info!("{} 🥏 Bluetooth alias: <bold><green>{}</>", NAME, alias);

    info!(
        "{} 🥏 Opened bluetooth adapter <b>{}</> with address <b>{}</b>",
        NAME,
        adapter.name(),
        adapter.address().await?
    );
    adapter.set_alias(alias.clone()).await?;
    adapter.set_powered(true).await?;
    adapter.set_pairable(true).await?;

    if advertise {
        adapter.set_discoverable(true).await?;
        adapter.set_discoverable_timeout(0).await?;
    }

    // AA Wireless profile. Probe-only PoC acts as a Bluetooth client toward an HU/fake-HU,
    // so it must not also register the same UUID as a local server profile; BlueZ allows only
    // one local registration for a UUID and would otherwise fail later with "UUID already registered".
    let handle_aa = if register_aa_wireless_profile {
        let profile = Profile {
            uuid: AAWG_PROFILE_UUID,
            name: Some("AA Wireless".to_string()),
            channel: Some(8),
            role: Some(Role::Server),
            require_authentication: Some(false),
            require_authorization: Some(false),
            ..Default::default()
        };
        let handle_aa = session.register_profile(profile).await?;
        info!("{} 📱 AA Wireless Profile: registered", NAME);
        Some(handle_aa)
    } else {
        info!(
            "{} 📱 AA Wireless Profile: not registered locally because bt_wireless_poc probe mode will use client Profile registration",
            NAME
        );
        None
    };

    Ok(Bluetooth {
        adapter,
        handle_aa,
        btle_handle: None,
        adv_handle: None,
        current_index: 0,
        dongle_mode,
    })
}

pub async fn get_cpu_serial_number_suffix() -> Result<String> {
    let mut serial = String::new();
    let contents = tokio::fs::read_to_string("/sys/firmware/devicetree/base/serial-number").await?;
    let trimmed = contents.trim_end_matches(char::from(0)).trim();
    // check if we read the serial number with correct length
    if trimmed.len() >= 6 {
        serial = trimmed[trimmed.len() - 6..].to_string();
    }
    Ok(serial)
}

/// Load previously successful AA device addresses from persistent file.
pub fn load_known_devices() -> Vec<Address> {
    let path = std::path::Path::new(KNOWN_DEVICES_FILE);
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let addrs: Vec<Address> = contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<Address>() {
                Ok(addr) if addr != Address::any() => Some(addr),
                _ => {
                    warn!("{} known_devices: skipping invalid line: {}", NAME, trimmed);
                    None
                }
            }
        })
        .collect();
    if !addrs.is_empty() {
        info!(
            "{} 📋 Loaded {} known device(s) from {}",
            NAME,
            addrs.len(),
            KNOWN_DEVICES_FILE
        );
    }
    addrs
}

/// Append a device address to the known-good devices file (if not already present).
fn save_known_device(addr: Address) {
    if addr == Address::any() {
        return;
    }
    // Read existing entries to avoid duplicates
    let existing = load_known_devices();
    if existing.contains(&addr) {
        debug!("{} known_devices: {} already recorded", NAME, addr);
        return;
    }
    let addr_str = format!("{}\n", addr);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(KNOWN_DEVICES_FILE)
    {
        Ok(mut file) => {
            use std::io::Write;
            if let Err(e) = file.write_all(addr_str.as_bytes()) {
                warn!("{} known_devices: failed to write {}: {}", NAME, addr, e);
            } else {
                info!("{} 💾 Saved {} to known devices", NAME, addr);
            }
        }
        Err(e) => {
            warn!(
                "{} known_devices: failed to open file for writing: {}",
                NAME, e
            );
        }
    }
}

async fn send_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    message: impl Message,
) -> Result<usize> {
    let mut packet: Vec<u8> = vec![];
    let mut data = message.write_to_bytes()?;

    // create header: 2 bytes message length (big-endian) + 2 bytes MessageID
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(&((id.clone() as u16).to_be_bytes()));

    // append data and send
    packet.append(&mut data);

    info!(
        "{} 📨 stage #{} of {}: Sending <yellow>{:?}</> frame to phone...",
        NAME, stage, STAGES, id
    );

    // Ensure the full packet is written
    stream.write_all(&packet).await?;

    Ok(packet.len())
}

async fn read_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    started: Instant,
) -> Result<usize> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    debug!("received header bytes: {:02X?}", header);
    let elapsed = started.elapsed();

    let len: usize = u16::from_be_bytes(header[0..2].try_into()?).into();
    let message_id = u16::from_be_bytes(header[2..4].try_into()?);
    debug!("MessageID = {}, len = {}", message_id, len);

    if message_id != id.clone() as u16 {
        warn!(
            "Received data has invalid MessageID: got: {:?}, expected: {:?}",
            message_id, id
        );
    }
    info!(
        "{} 📨 stage #{} of {}: Received <yellow>{:?}</> frame from phone (⏱️ {} ms)",
        NAME,
        stage,
        STAGES,
        id,
        (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64,
    );

    // read and discard the remaining bytes
    if len > 0 {
        let mut buf = vec![0; len];
        let n = stream.read_exact(&mut buf).await?;
        debug!("remaining {} bytes: {:02X?}", n, buf);

        // analyzing WifiConnectStatus
        // this is a frame where phone cannot connect to WiFi:
        // [08, FD, FF, FF, FF, FF, FF, FF, FF, FF, 01] -> which is -i64::MAX
        // and this is where all is fine:
        // [08, 00]
        if id == MessageId::WifiConnectStatus && n >= 2 {
            if buf[1] != 0 {
                return Err("phone cannot connect to our WiFi AP...".into());
            }
        }
    }

    Ok(HEADER_LEN + len)
}

impl Bluetooth {
    pub async fn start_ble(&mut self, state: AppState, enable_btle: bool) -> Result<()> {
        // --- Start BLE GATT server first ---
        if enable_btle {
            match btle::run_btle_server(&self.adapter, state.clone()).await {
                Ok(handle) => {
                    info!("{} 🥏 BLE GATT server started successfully", NAME);
                    self.btle_handle = Some(handle);
                }
                Err(e) => {
                    error!("{} 🥏 Failed to start BLE server: {}", NAME, e);
                }
            }
        }

        // --- Prepare UUIDs ---
        let mut uuids: std::collections::BTreeSet<bluer::Uuid> = std::collections::BTreeSet::new();
        uuids.insert(BTLE_PROFILE_UUID);

        // --- BLE advertisement ---
        if !uuids.is_empty() {
            // Stop any previous advertisement first
            if let Some(handle) = self.adv_handle.take() {
                drop(handle);
            }

            let mut le_advertisement = bluer::adv::Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                service_uuids: uuids.clone(),
                discoverable: Some(true), // temporarily true for stable discovery
                local_name: Some(self.adapter.alias().await?),
                ..Default::default()
            };

            let mut adv_success = false;
            for attempt in 0..3 {
                match self.adapter.advertise(le_advertisement.clone()).await {
                    Ok(handle) => {
                        info!(
                            "{} 📣 BLE advertisement started with UUIDs (attempt {})",
                            NAME,
                            attempt + 1
                        );
                        self.adv_handle = Some(handle);
                        adv_success = true;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "{} 🥏 Advertising attempt {} failed: {}",
                            NAME,
                            attempt + 1,
                            e
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }

            if !adv_success {
                warn!(
                    "{} 🥏 Advertising with UUIDs failed, fallback to local name only",
                    NAME
                );

                // Retry only with local name
                if let Some(handle) = self.adv_handle.take() {
                    drop(handle);
                }

                le_advertisement.service_uuids = Default::default();

                for attempt in 0..3 {
                    match self.adapter.advertise(le_advertisement.clone()).await {
                        Ok(handle) => {
                            info!(
                                "{} 📣 BLE advertisement started with local name only (attempt {})",
                                NAME,
                                attempt + 1
                            );
                            self.adv_handle = Some(handle);
                            adv_success = true;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "{} 🥏 Local-name-only advertising attempt {} failed: {}",
                                NAME,
                                attempt + 1,
                                e
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }
                }

                if !adv_success {
                    error!(
                        "{} 🥏 BLE advertisement completely failed after retries",
                        NAME
                    );
                }
            }
        }

        Ok(())
    }

    async fn get_aa_profile_connection(
        &mut self,
        connect: BluetoothAddressList,
        bt_timeout: Duration,
        stopped: bool,
    ) -> Result<(Address, Stream)> {
        info!("{} ⏳ Waiting for phone to connect via bluetooth...", NAME);

        // try to connect to saved devices or provided one via command line
        if let Some(addresses_to_connect) = connect.0 {
            if !stopped {
                let adapter_cloned = self.adapter.clone();

                let addresses: Vec<Address> = if addresses_to_connect
                    .iter()
                    .any(|addr| *addr == Address::any())
                {
                    // Only use known-good devices, no fallback to all paired devices
                    let known = load_known_devices();
                    if !known.is_empty() {
                        info!("{} 🥏 Using {} known-good device(s)...", NAME, known.len());
                    } else {
                        info!("{} 🥏 No known-good devices, passively waiting for incoming connection...", NAME);
                    }
                    known
                } else {
                    addresses_to_connect
                };
                // exit if we don't have anything to connect to
                if !addresses.is_empty() {
                    info!("{} 🧲 Attempting to start an AndroidAuto session via bluetooth with the following devices, in this order: {:?}", NAME, addresses);
                    if !self.dongle_mode {
                        let try_connect_bluetooth_addresses_retry = || async {
                            let next_index = Bluetooth::try_connect_bluetooth_addresses(
                                &adapter_cloned,
                                &addresses,
                                self.current_index,
                            )
                            .await?;

                            Ok(next_index)
                        };

                        let retry_policy = ExponentialBuilder::default()
                            .with_min_delay(Duration::from_secs(1))
                            .with_max_delay(Duration::from_secs(15))
                            .without_max_times();

                        self.current_index = try_connect_bluetooth_addresses_retry
                            // Retry with exponential backoff
                            .retry(retry_policy)
                            // Sleep implementation, required if no feature has been enabled
                            .sleep(tokio::time::sleep)
                            // Notify when retrying;
                            .notify(
                                |err: &Box<dyn std::error::Error + Send + Sync + 'static>,
                                 dur: Duration| {
                                    debug!(
                                        "{} Retrying due to error: {:?} after {:?}",
                                        NAME, err, dur
                                    );
                                },
                            )
                            .await?;
                    } else {
                        for addr in addresses {
                            if let Ok(device) = adapter_cloned.device(addr) {
                                match device.name().await {
                                    Ok(Some(name)) => {
                                        if name.starts_with("AndroidAuto-") {
                                            let dev_name = format!(" (<b><blue>{}</>)", name);
                                            info!(
                                                "{} 🧲 (dongle_mode) Forcing BR/EDR device.connect() to {} {}",
                                                NAME, addr, dev_name
                                            );
                                            if let Err(e) = device.connect().await {
                                                debug!(
                                                    "{} (dongle_mode) connect() returned {:?} (ignored)",
                                                    NAME, e
                                                );
                                            }
                                        } else {
                                            debug!(
                                                "{} 🧲 (dongle_mode) skipping {} - name doesn't start with AndroidAuto-",
                                                NAME,
                                                addr
                                            );
                                        }
                                    }
                                    _ => {
                                        debug!(
                                            "{} 🧲 (dongle_mode) skipping {} - no device name available",
                                            NAME,
                                            addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let handle_aa = self
            .handle_aa
            .as_mut()
            .ok_or("AA Wireless local server profile is not registered in this mode")?;
        let req = timeout(bt_timeout, handle_aa.next())
            .await?
            .expect("received no connect request");
        info!(
            "{} 📱 AA Wireless Profile: connect from: <b>{}</>",
            NAME,
            req.device()
        );
        let addr = req.device().clone();
        let stream = req.accept()?;

        Ok((addr, stream))
    }

    async fn try_connect_bluetooth_addresses(
        adapter: &Adapter,
        addresses: &Vec<Address>,
        start_index: usize,
    ) -> Result<usize> {
        let n = addresses.len();

        // Pre-fetch device handles and names once before the attempt rounds begin.
        // This avoids redundant name lookups on every attempt.
        struct DeviceEntry {
            idx: usize,
            addr: Address,
            dev_name: String,
        }
        let mut entries: Vec<DeviceEntry> = Vec::with_capacity(n);
        for i in 0..n {
            // Calculate the actual index, taking start_index into account
            let idx = (start_index + i) % n;
            let addr = addresses[idx];
            let device = adapter.device(addr)?;

            let dev_name = match device.name().await {
                Ok(Some(name)) => format!(" (<b><blue>{}</>)", name),
                _ => String::new(),
            };
            entries.push(DeviceEntry {
                idx,
                addr,
                dev_name,
            });
        }

        // Connect in an interleaved order:
        // Each device gets one attempt per round before any device is retried,
        // so a user whose phone is device #N does not have to wait through all
        // ATTEMPTS failures on devices #0..N-1 before being tried.
        for j in 1..=ATTEMPTS {
            for entry in &entries {
                let DeviceEntry {
                    idx,
                    addr,
                    dev_name,
                } = entry;
                let device = adapter.device(*addr)?;
                info!(
                    "{} 🧲 Trying to connect to: {}{}, attempt: {}/{}",
                    NAME, addr, dev_name, j, ATTEMPTS
                );
                if let Ok(true) = device.is_paired().await {
                    match device.connect_profile(&HSP_AG_UUID).await {
                        Ok(_) => {
                            info!(
                                "{} 🔗 Successfully connected to device: {}{}",
                                NAME, addr, dev_name
                            );
                            return Ok((*idx + 1) % n);
                        }
                        Err(e) => {
                            warn!("{} 🔇 {}{}: Error connecting: {}", NAME, addr, dev_name, e)
                        }
                    }
                } else {
                    warn!(
                        "{} 🧲 Unable to connect to: {}{} device not paired",
                        NAME, addr, dev_name
                    );
                }
            }
        }
        Err(anyhow!("Unable to connect to the provided addresses").into())
    }

    async fn send_params(wifi_config: WifiConfig, stream: &mut Stream) -> Result<()> {
        use WifiInfoResponse::WifiInfoResponse;
        use WifiStartRequest::WifiStartRequest;
        let mut stage = 1;
        let mut started;

        info!("{} 📲 Sending parameters via bluetooth to phone...", NAME);
        let mut start_req = WifiStartRequest::new();
        info!(
            "{} 🛜 Sending Host IP Address: {}",
            NAME, wifi_config.ip_addr
        );
        start_req.set_ip_address(wifi_config.ip_addr);
        start_req.set_port(wifi_config.port);
        send_message(stream, stage, MessageId::WifiStartRequest, start_req).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiInfoRequest, started).await?;

        let mut info = WifiInfoResponse::new();
        info!(
            "{} 🛜 Sending Host SSID and Password: {}, {}",
            NAME, wifi_config.ssid, wifi_config.wpa_key
        );
        info.set_ssid(wifi_config.ssid);
        info.set_key(wifi_config.wpa_key);
        info.set_bssid(wifi_config.bssid);
        info.set_security_mode(SecurityMode::WPA2_PERSONAL);
        info.set_access_point_type(AccessPointType::DYNAMIC);
        stage += 1;
        send_message(stream, stage, MessageId::WifiInfoResponse, info).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiStartResponse, started).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiConnectStatus, started).await?;

        Ok(())
    }

    /// Drop HSP session here - this unregisters the profile from BlueZ.
    /// We do it explicitly with a small delay to give BlueZ time to clean up.
    async fn unregister_hsp(hsp_session: Option<bluer::Session>) {
        if let Some(sess) = hsp_session {
            info!("{} 🎧 Headset Profile (HSP): unregistering ...", NAME);
            drop(sess);
            tokio::time::sleep(Duration::from_millis(300)).await;
            info!("{} 🎧 Headset Profile (HSP): unregistered", NAME);
        }
    }

    async fn connect_hu_aa_wireless_poc(
        &self,
        hu_mac: &str,
        hu_channel: Option<u8>,
    ) -> Result<PocHuConnection> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_poc_hu_mac must be set".into());
        }

        let hu_addr: Address = hu_mac.trim().parse()?;

        if let Some(channel) = hu_channel.filter(|channel| *channel > 0) {
            let hu_socket = SocketAddr::new(hu_addr, channel);
            info!(
                "{} 🧪 bt-wireless-poc: connecting to HU RFCOMM {} (manual channel)",
                NAME, hu_socket
            );
            let stream = timeout(Duration::from_secs(15), Stream::connect(hu_socket)).await??;
            return Ok(PocHuConnection {
                stream,
                endpoint: format!("RFCOMM {}", hu_socket),
                _client_profile_session: None,
                _client_profile_handle: None,
            });
        }

        info!(
            "{} 🧪 bt-wireless-poc: HU RFCOMM channel is empty/0; using BlueZ ConnectProfile + SDP auto-discovery for {}",
            NAME, hu_addr
        );

        let session = bluer::Session::new().await?;
        let profile = Profile {
            uuid: AAWG_PROFILE_UUID,
            name: Some("AA Wireless Client PoC".to_string()),
            role: Some(Role::Client),
            require_authentication: Some(false),
            require_authorization: Some(false),
            auto_connect: Some(false),
            ..Default::default()
        };
        let mut handle = session.register_profile(profile).await?;

        let device = self.adapter.device(hu_addr)?;
        match device.uuids().await {
            Ok(Some(uuids)) if uuids.contains(&AAWG_PROFILE_UUID) => {
                info!(
                    "{} 🧪 bt-wireless-poc: HU {} advertises AA Wireless UUID {}; asking BlueZ to connect profile",
                    NAME, hu_addr, AAWG_PROFILE_UUID
                );
            }
            Ok(Some(uuids)) => {
                warn!(
                    "{} 🧪 bt-wireless-poc: HU {} UUID list does not include AA Wireless UUID {}; trying ConnectProfile anyway. UUIDs={:?}",
                    NAME, hu_addr, AAWG_PROFILE_UUID, uuids
                );
            }
            Ok(None) => {
                warn!(
                    "{} 🧪 bt-wireless-poc: HU {} UUID list is not available; trying ConnectProfile anyway",
                    NAME, hu_addr
                );
            }
            Err(e) => {
                warn!(
                    "{} 🧪 bt-wireless-poc: failed to read HU {} UUIDs: {}; trying ConnectProfile anyway",
                    NAME, hu_addr, e
                );
            }
        }

        let connect_fut = device.connect_profile(&AAWG_PROFILE_UUID);
        tokio::pin!(connect_fut);
        let mut connect_done = false;
        let mut deadline = Box::pin(tokio::time::sleep(Duration::from_secs(20)));

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    return Err(format!(
                        "timed out waiting for BlueZ AA Wireless ConnectProfile/NewConnection from HU {}",
                        hu_addr
                    ).into());
                }
                res = &mut connect_fut, if !connect_done => {
                    connect_done = true;
                    match res {
                        Ok(()) => {
                            info!(
                                "{} 🧪 bt-wireless-poc: BlueZ ConnectProfile returned OK for HU {}; waiting for NewConnection",
                                NAME, hu_addr
                            );
                        }
                        Err(e) => {
                            return Err(format!(
                                "BlueZ ConnectProfile failed for HU {} / UUID {}: {}",
                                hu_addr, AAWG_PROFILE_UUID, e
                            ).into());
                        }
                    }
                }
                req = handle.next() => {
                    let Some(req) = req else {
                        return Err("BlueZ AA Wireless client profile closed before connection".into());
                    };

                    let device_addr = req.device();
                    if device_addr != hu_addr {
                        warn!(
                            "{} 🧪 bt-wireless-poc: rejecting unexpected AA Wireless client-profile connection from {}; wanted {}",
                            NAME, device_addr, hu_addr
                        );
                        req.reject(ReqError::Rejected);
                        continue;
                    }

                    let stream = req.accept()?;
                    if !connect_done {
                        match timeout(Duration::from_secs(2), &mut connect_fut).await {
                            Ok(Ok(())) => {
                                info!(
                                    "{} 🧪 bt-wireless-poc: BlueZ ConnectProfile completed after accepting HU {}",
                                    NAME, hu_addr
                                );
                            }
                            Ok(Err(e)) => {
                                warn!(
                                    "{} 🧪 bt-wireless-poc: ConnectProfile returned error after HU {} was accepted: {}",
                                    NAME, hu_addr, e
                                );
                            }
                            Err(_) => {
                                debug!(
                                    "{} 🧪 bt-wireless-poc: ConnectProfile still pending after accepting HU {}; keeping RFCOMM stream",
                                    NAME, hu_addr
                                );
                            }
                        }
                    }
                    info!(
                        "{} 🧪 bt-wireless-poc: BlueZ accepted HU {} via AA Wireless SDP/ConnectProfile",
                        NAME, hu_addr
                    );
                    return Ok(PocHuConnection {
                        stream,
                        endpoint: format!("{} via BlueZ SDP/ConnectProfile", hu_addr),
                        _client_profile_session: Some(session),
                        _client_profile_handle: Some(handle),
                    });
                }
            }
        }
    }

    pub async fn aa_wireless_bridge_poc(
        &mut self,
        connect: BluetoothAddressList,
        hu_mac: String,
        hu_channel: Option<u8>,
        bt_timeout: Duration,
        stopped: bool,
    ) -> Result<()> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_poc_hu_mac must be set for bridge mode".into());
        }

        let hu_endpoint_hint = match hu_channel.filter(|channel| *channel > 0) {
            Some(channel) => format!("{} RFCOMM channel {}", hu_mac.trim(), channel),
            None => format!("{} AA Wireless SDP auto-discovery", hu_mac.trim()),
        };

        info!(
            "{} 🧪 bt-wireless-poc bridge: waiting for phone AA RFCOMM, then connecting to HU {}",
            NAME, hu_endpoint_hint
        );

        let (phone_addr, phone_stream) = self
            .get_aa_profile_connection(connect, bt_timeout, stopped)
            .await?;

        info!(
            "{} 🧪 bt-wireless-poc bridge: phone connected from {}; connecting to HU {}",
            NAME, phone_addr, hu_endpoint_hint
        );

        let hu_conn = self.connect_hu_aa_wireless_poc(hu_mac.trim(), hu_channel).await?;
        let hu_endpoint = hu_conn.endpoint.clone();
        info!(
            "{} 🧪 bt-wireless-poc bridge: connected to HU {}; relaying raw AA Wireless BT frames both ways",
            NAME, hu_endpoint
        );

        let PocHuConnection {
            stream: hu_stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        let (phone_read, phone_write) = phone_stream.into_split();
        let (hu_read, hu_write) = hu_stream.into_split();

        let mut phone_to_hu = tokio::spawn(relay_with_poc_logging(
            phone_read,
            hu_write,
            "PHONE -> HU",
        ));
        let mut hu_to_phone = tokio::spawn(relay_with_poc_logging(
            hu_read,
            phone_write,
            "HU -> PHONE",
        ));

        tokio::select! {
            res = &mut phone_to_hu => {
                match res {
                    Ok(Ok(bytes)) => info!("{} 🧪 bt-wireless-poc bridge: PHONE -> HU ended after {} bytes", NAME, bytes),
                    Ok(Err(e)) => warn!("{} 🧪 bt-wireless-poc bridge: PHONE -> HU error: {}", NAME, e),
                    Err(e) => warn!("{} 🧪 bt-wireless-poc bridge: PHONE -> HU task error: {}", NAME, e),
                }
                hu_to_phone.abort();
            }
            res = &mut hu_to_phone => {
                match res {
                    Ok(Ok(bytes)) => info!("{} 🧪 bt-wireless-poc bridge: HU -> PHONE ended after {} bytes", NAME, bytes),
                    Ok(Err(e)) => warn!("{} 🧪 bt-wireless-poc bridge: HU -> PHONE error: {}", NAME, e),
                    Err(e) => warn!("{} 🧪 bt-wireless-poc bridge: HU -> PHONE task error: {}", NAME, e),
                }
                phone_to_hu.abort();
            }
        }

        info!("{} 🧪 bt-wireless-poc bridge: finished", NAME);
        Ok(())
    }

    pub async fn aa_wireless_probe_poc(
        &mut self,
        hu_mac: String,
        hu_channel: Option<u8>,
        tcp_probe: bool,
    ) -> Result<()> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_poc_hu_mac must be set for probe mode".into());
        }

        let hu_conn = self.connect_hu_aa_wireless_poc(hu_mac.trim(), hu_channel).await?;
        let hu_endpoint = hu_conn.endpoint.clone();
        let PocHuConnection {
            stream: mut stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        info!(
            "{} 🧪 bt-wireless-poc probe: connected to HU {}; waiting for WifiStartRequest",
            NAME, hu_endpoint
        );

        let (message_id, payload) = read_poc_frame(&mut stream, "HU -> POC").await?;
        if message_id != PocMessageId::WifiStartRequest as u16 {
            warn!(
                "{} 🧪 bt-wireless-poc probe: first HU frame was {}, expected WifiStartRequest; continuing anyway",
                NAME, message_id
            );
        }

        let mut target_ip = String::new();
        let mut target_port = 0i32;
        if message_id == PocMessageId::WifiStartRequest as u16 {
            if let Ok(req) = WifiStartRequest::WifiStartRequest::parse_from_bytes(&payload) {
                target_ip = req.ip_address().to_string();
                target_port = req.port();
            }
        }

        send_poc_frame(
            &mut stream,
            "POC -> HU",
            PocMessageId::WifiInfoRequest,
            &[],
        )
        .await?;

        let (message_id, _payload) = read_poc_frame(&mut stream, "HU -> POC").await?;
        if message_id != PocMessageId::WifiInfoResponse as u16 {
            warn!(
                "{} 🧪 bt-wireless-poc probe: second HU frame was {}, expected WifiInfoResponse",
                NAME, message_id
            );
        }

        send_poc_frame(
            &mut stream,
            "POC -> HU",
            PocMessageId::WifiStartResponse,
            success_status_payload(),
        )
        .await?;

        if tcp_probe && !target_ip.is_empty() && target_port > 0 {
            let addr = format!("{}:{}", target_ip, target_port);
            info!(
                "{} 🧪 bt-wireless-poc probe: trying TCP probe to HU AA endpoint {}",
                NAME, addr
            );
            match timeout(Duration::from_secs(5), TcpStream::connect(addr.as_str())).await {
                Ok(Ok(_tcp)) => info!(
                    "{} 🧪 bt-wireless-poc probe: TCP probe connected to {}",
                    NAME, addr
                ),
                Ok(Err(e)) => warn!(
                    "{} 🧪 bt-wireless-poc probe: TCP probe failed to {}: {}",
                    NAME, addr, e
                ),
                Err(e) => warn!(
                    "{} 🧪 bt-wireless-poc probe: TCP probe timed out to {}: {}",
                    NAME, addr, e
                ),
            }
        }

        send_poc_frame(
            &mut stream,
            "POC -> HU",
            PocMessageId::WifiConnectStatus,
            success_status_payload(),
        )
        .await?;

        info!(
            "{} 🧪 bt-wireless-poc probe: bootstrap frames sent; keeping RFCOMM open until HU closes or 30s idle timeout",
            NAME
        );

        loop {
            match timeout(Duration::from_secs(30), read_poc_frame(&mut stream, "HU -> POC")).await {
                Ok(Ok((_id, _payload))) => continue,
                Ok(Err(e)) => {
                    info!("{} 🧪 bt-wireless-poc probe: RFCOMM ended: {}", NAME, e);
                    break;
                }
                Err(_) => {
                    info!("{} 🧪 bt-wireless-poc probe: idle timeout; closing", NAME);
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn aa_handshake(
        &mut self,
        connect: BluetoothAddressList,
        wifi_config: WifiConfig,
        tcp_start: Arc<Notify>,
        bt_timeout: Duration,
        stopped: bool,
        quick_reconnect: bool,
        bt_poweroff: bool,
        bt_sco: bool,
        bt_sco_keep_bluetooth_alive: bool,
        mut need_restart: BroadcastReceiver<Option<Action>>,
        restart_tx: BroadcastSender<Option<Action>>,
        profile_connected: Arc<AtomicBool>,
        shared_config: SharedConfig,
    ) -> Result<()> {
        if bt_poweroff {
            let _ = self.adapter.set_powered(true).await;
        }
        //
        // --- HSP PROFILE REGISTRATION ---
        //
        let mut hsp_handle = None;

        if !self.dongle_mode {
            let session = bluer::Session::new().await?;
            let profile = Profile {
                uuid: HSP_HS_UUID,
                name: Some("HSP HS".to_string()),
                require_authentication: Some(false),
                require_authorization: Some(false),
                ..Default::default()
            };

            match session.register_profile(profile).await {
                Ok(handle) => {
                    info!("{} 🎧 Headset Profile (HSP): registered", NAME);

                    // Move ownership of handle into task. Keep the old safe behavior:
                    // accept and immediately drop the HSP control stream so Android Auto
                    // Bluetooth handshakes are not affected. The SCO/eSCO audio socket is
                    // handled separately by the bt_sco listener.
                    tokio::spawn(async move {
                        let mut h = handle;
                        loop {
                            let req = match h.next().await {
                                Some(req) => req,
                                None => {
                                    warn!(
                                        "{} 🎧 Headset Profile (HSP): no more connect requests",
                                        NAME
                                    );
                                    break;
                                }
                            };

                            let device = req.device().clone();
                            info!(
                                "{} 🎧 Headset Profile (HSP): connect from <b>{}</>",
                                NAME, device
                            );

                            match req.accept() {
                                Ok(stream) => {
                                    // IMPORTANT: Do not keep the HSP RFCOMM control stream open yet.
                                    // Keeping it open without a proper HSP/HFP AT-command state machine can
                                    // make Android route the call to this Bluetooth device and then wait forever
                                    // for headset-side responses. The independent SCO/eSCO listener remains
                                    // active; the HSP control stream is accepted and immediately dropped,
                                    // preserving the old Android Auto Bluetooth behavior.
                                    if bt_sco {
                                        info!(
                                            "{} 🎧 Headset Profile (HSP): accepted from <b>{}</>, dropping control stream in SCO mode",
                                            NAME,
                                            device
                                        );
                                    }
                                    drop(stream);
                                }
                                Err(e) => {
                                    warn!(
                                        "{} 🎧 Headset Profile (HSP): accept error from <b>{}</>: {}",
                                        NAME,
                                        device,
                                        e
                                    );
                                }
                            }
                        }
                    });

                    // Keep handle for unregister
                    hsp_handle = Some(session);
                }
                Err(e) => {
                    warn!(
                        "{} 🎧 Headset Profile (HSP) registering error: {}, ignoring",
                        NAME, e
                    );
                }
            }
        }

        // Check if we're using wildcard connect before moving ownership
        let is_wildcard_connect = connect.is_wildcard();

        // Use the provided session and adapter instead of creating new ones
        let (address, mut stream) = self
            .get_aa_profile_connection(connect, bt_timeout, stopped)
            .await?;

        let phone_name = match self.adapter.device(address) {
            Ok(device) => device.name().await.ok().flatten(),
            Err(_) => None,
        };
        sdr_ui::set_current_phone_from_bt(&address.to_string(), phone_name);

        Self::send_params(wifi_config.clone(), &mut stream).await?;

        // Record this device as a known-good AA device (only when using wildcard connect)
        if is_wildcard_connect {
            save_known_device(address);
        }
        // Clear Stop flag here — after BT handshake succeeds but before the proxy loop
        // is notified. The proxy checks action_requested on every iteration; leaving Stop
        // set would cause it to kill the session immediately (~20ms).
        if stopped {
            info!("{} 🔄 User-stop cleared, phone reconnected manually", NAME);
            shared_config.write().await.action_requested = None;
        }
        tcp_start.notify_one();

        if quick_reconnect {
            // keep the bluetooth profile connection alive
            // and use it in a loop to restart handshake when necessary
            //
            // hsp_handle is moved into the task so that the HSP session stays
            // registered for the entire duration of the quick_reconnect loop.
            // It will be dropped (= unregistered from BlueZ) when the task exits.
            let hsp_session = hsp_handle.take();
            let adapter_cloned = self.adapter.clone();
            let _ = Some(tokio::spawn(async move {
                profile_connected.store(true, Ordering::Relaxed);
                loop {
                    // wait for restart notification from main loop (eg when HU disconnected)
                    let action = need_restart.recv().await;
                    if let Ok(Some(action)) = action {
                        // check if we need to stop now
                        if action == Action::Stop {
                            // attempt graceful RFCOMM shutdown then drain pending data, then disconnect
                            match stream.shutdown().await {
                                Ok(_) => debug!("{} RFCOMM stream shutdown succeeded", NAME),
                                Err(e) => warn!("{} RFCOMM stream shutdown error: {}", NAME, e),
                            }

                            // Try to drain any pending incoming data with short timeouts
                            let mut drain_buf = [0u8; 256];
                            loop {
                                match timeout(
                                    Duration::from_millis(50),
                                    stream.read(&mut drain_buf),
                                )
                                .await
                                {
                                    Ok(Ok(0)) => {
                                        debug!("{} RFCOMM drain: EOF", NAME);
                                        break;
                                    }
                                    Ok(Ok(n)) => {
                                        debug!("{} RFCOMM drained {} bytes", NAME, n);
                                        continue;
                                    }
                                    Ok(Err(e)) => {
                                        debug!("{} RFCOMM drain read error: {}", NAME, e);
                                        break;
                                    }
                                    Err(_) => {
                                        debug!("{} RFCOMM drain timeout, no more data", NAME);
                                        break;
                                    }
                                }
                            }

                            // allow controller time to finish frames
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            if let Ok(device) = adapter_cloned.device(bluer::Address(*address)) {
                                if let Err(e) = device.disconnect().await {
                                    warn!("{} device.disconnect error: {}", NAME, e);
                                }
                            }

                            break;
                        }
                    }

                    // now restart handshake with the same params
                    match Self::send_params(wifi_config.clone(), &mut stream).await {
                        Ok(_) => {
                            tcp_start.notify_one();
                            continue;
                        }
                        Err(e) => {
                            error!(
                                "{} handshake restart error: {}, doing full restart!",
                                NAME, e
                            );
                            // this break should end this task
                            break;
                        }
                    }
                }
                // we are now disconnected, redo bluetooth connection
                profile_connected.store(false, Ordering::Relaxed);
                Self::unregister_hsp(hsp_session).await;
                // main loop could now wait so send an event to restart
                let _ = restart_tx.send(None);
            }));
        } else if bt_sco && bt_sco_keep_bluetooth_alive {
            // The SCO call-audio bridge needs the phone to keep routing calls to
            // aa-proxy-rs over Bluetooth after the AA Wi-Fi bootstrap completes.
            // Normal aa-proxy-rs behavior disconnects BT here so the phone can use
            // the real HU for calls; for the bridge we instead keep the accepted
            // AA RFCOMM stream and the HSP registration alive until the AA session
            // restarts/stops.
            info!(
                "{} 🎧 bt_sco_keep_bluetooth_alive enabled; keeping Bluetooth RFCOMM/HSP alive after Wi-Fi bootstrap",
                NAME
            );

            let hsp_session = hsp_handle.take();
            let adapter_cloned = self.adapter.clone();
            let device_address = bluer::Address(*address);
            let mut keepalive_restart_rx = need_restart;

            let _ = Some(tokio::spawn(async move {
                profile_connected.store(true, Ordering::Relaxed);

                // Hold `stream` and `hsp_session` by moving them into this task.
                // We intentionally do not send any more AA Wireless frames here;
                // this is not quick_reconnect. The task only keeps BT alive while
                // the current AA session is alive, then cleans up on restart/stop.
                let mut held_stream = stream;
                let _held_hsp_session = hsp_session;

                match keepalive_restart_rx.recv().await {
                    Ok(action) => {
                        info!(
                            "{} 🎧 bt_sco keepalive ending after restart notification: {:?}",
                            NAME, action
                        );
                    }
                    Err(e) => {
                        debug!(
                            "{} 🎧 bt_sco keepalive ending because restart channel closed: {}",
                            NAME, e
                        );
                    }
                }

                match held_stream.shutdown().await {
                    Ok(_) => debug!("{} bt_sco keepalive RFCOMM shutdown succeeded", NAME),
                    Err(e) => warn!("{} bt_sco keepalive RFCOMM shutdown error: {}", NAME, e),
                }

                tokio::time::sleep(Duration::from_millis(150)).await;

                if let Ok(device) = adapter_cloned.device(device_address) {
                    if let Err(e) = device.disconnect().await {
                        warn!("{} bt_sco keepalive device.disconnect error: {}", NAME, e);
                    }
                }

                if let Some(sess) = _held_hsp_session {
                    info!("{} 🎧 Headset Profile (HSP): unregistering ...", NAME);
                    drop(sess);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    info!("{} 🎧 Headset Profile (HSP): unregistered", NAME);
                }

                if bt_poweroff {
                    let _ = adapter_cloned.set_powered(false).await;
                }

                profile_connected.store(false, Ordering::Relaxed);
            }));
        } else {
            // attempt graceful shutdown of the RFCOMM stream before disconnect
            let _ = stream.shutdown().await;
            // let some phones that have problems with handshake time to
            // finish all bluetooth frames before disconnect
            let _ = tokio::time::sleep(Duration::from_millis(150));
            // handshake complete, now disconnect the device so it should
            // connect to real HU for calls
            let device = self.adapter.device(bluer::Address(*address))?;
            let _ = device.disconnect().await;
            //
            // --- UNREGISTER HSP ---
            //
            if !self.dongle_mode {
                Self::unregister_hsp(hsp_handle.take()).await;
            }
            if bt_poweroff {
                let _ = self.adapter.set_powered(false).await;
            }
        }

        info!("{} 🚀 Bluetooth launch sequence completed", NAME);

        Ok(())
    }
}
