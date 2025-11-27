use crate::btle;
use crate::config::Action;
use crate::config::WifiConfig;
use crate::config::IDENTITY_NAME;
use crate::config_types::BluetoothAddressList;
use crate::web::AppState;
use anyhow::anyhow;
use backon::{ExponentialBuilder, Retryable};
use bluer::{
    rfcomm::{Profile, ProfileHandle, Role, Stream},
    Adapter, Address, Device, Uuid,
};
use futures::StreamExt;
use simplelog::*;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
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

// module name for logging engine
const NAME: &str = "<i><bright-black> bluetooth: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const AAWG_PROFILE_UUID: Uuid = Uuid::from_u128(0x4de17a0052cb11e6bdf40800200c9a66);
pub const BTLE_PROFILE_UUID: Uuid = Uuid::from_u128(0x9b3f6c10a4d2418ea2b90700300de8f4);
const HSP_HS_UUID: Uuid = Uuid::from_u128(0x0000110800001000800000805f9b34fb);
const HSP_AG_UUID: Uuid = Uuid::from_u128(0x0000111200001000800000805f9b34fb);
const AV_REMOTE_CONTROL_TARGET_UUID: Uuid = Uuid::from_u128(0x0000110c00001000800000805f9b34fb);
const AV_REMOTE_CONTROL_UUID: Uuid = Uuid::from_u128(0x00110e00001000800000805f9b34fb);

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

pub struct Bluetooth {
    adapter: Adapter,
    handle_aa: ProfileHandle,
    btle_handle: Option<bluer::gatt::local::ApplicationHandle>,
    adv_handle: Option<bluer::adv::AdvertisementHandle>,
}

// Create and configure the Bluetooth adapter
pub async fn init(
    btalias: Option<String>,
    advertise: bool,
    dongle_mode: bool,
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

    // AA Wireless profile
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

    if !dongle_mode {
        // Headset profile
        let profile = Profile {
            uuid: HSP_HS_UUID,
            name: Some("HSP HS".to_string()),
            require_authentication: Some(false),
            require_authorization: Some(false),
            ..Default::default()
        };
        match session.register_profile(profile).await {
            Ok(mut handle) => {
                info!("{} 🎧 Headset Profile (HSP): registered", NAME);
                // handling connection to headset profile in own task
                // it only accepts each incoming connection
                let _ = Some(tokio::spawn(async move {
                    loop {
                        let req = handle.next().await.expect("received no connect request");
                        info!(
                            "{} 🎧 Headset Profile (HSP): connect from: <b>{}</>",
                            NAME,
                            req.device()
                        );
                        let _ = req.accept();
                    }
                }));
            }
            Err(e) => {
                warn!(
                    "{} 🎧 Headset Profile (HSP) registering error: {}, ignoring",
                    NAME, e
                );
            }
        }
    }

    Ok(Bluetooth {
        adapter,
        handle_aa,
        btle_handle: None,
        adv_handle: None,
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

async fn send_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    message: impl Message,
) -> Result<usize> {
    let mut packet: Vec<u8> = vec![];
    let mut data = message.write_to_bytes()?;

    // create header: 2 bytes message length + 2 bytes MessageID
    packet.write_u16(data.len() as u16).await?;
    packet.write_u16(id.clone() as u16).await?;

    // append data and send
    packet.append(&mut data);

    info!(
        "{} 📨 stage #{} of {}: Sending <yellow>{:?}</> frame to phone...",
        NAME, stage, STAGES, id
    );

    Ok(stream.write(&packet).await?)
}

async fn read_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    started: Instant,
) -> Result<usize> {
    let mut buf = vec![0; HEADER_LEN];
    let n = stream.read_exact(&mut buf).await?;
    debug!("received {} bytes: {:02X?}", n, buf);
    let elapsed = started.elapsed();

    let len: usize = u16::from_be_bytes(buf[0..=1].try_into()?).into();
    let message_id = u16::from_be_bytes(buf[2..=3].try_into()?);
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
        dongle_mode: bool,
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
                    info!("{} 🥏 Enumerating known bluetooth devices...", NAME);
                    adapter_cloned.device_addresses().await?
                } else {
                    addresses_to_connect
                };
                // exit if we don't have anything to connect to
                if !addresses.is_empty() {
                    info!("{} 🧲 Attempting to start an AndroidAuto session via bluetooth with the following devices, in this order: {:?}", NAME, addresses);
                    let try_connect_bluetooth_addresses_retry = || {
                        Bluetooth::try_connect_bluetooth_addresses(
                            &adapter_cloned,
                            dongle_mode,
                            &addresses,
                        )
                    };

                    let retry_policy = ExponentialBuilder::default()
                        .with_min_delay(Duration::from_secs(1))
                        .with_max_delay(Duration::from_secs(15))
                        .without_max_times();

                    let _connect = try_connect_bluetooth_addresses_retry
                        // Retry with exponential backoff
                        .retry(retry_policy)
                        // Sleep implementation, required if no feature has been enabled
                        .sleep(tokio::time::sleep)
                        // Notify when retrying;
                        .notify(
                            |err: &Box<dyn std::error::Error + Send + Sync + 'static>,
                             dur: Duration| {
                                debug!("{} Retrying due to error: {:?} after {:?}", NAME, err, dur);
                            },
                        )
                        .await?;
                }
            }
        }

        let req = timeout(bt_timeout, self.handle_aa.next())
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
        dongle_mode: bool,
        addresses: &Vec<Address>,
    ) -> Result<()> {
        for addr in addresses {
            let device = adapter.device(*addr)?;
            let dev_name = match device.name().await {
                Ok(Some(name)) => format!(" (<b><blue>{}</>)", name),
                _ => String::new(),
            };
            info!("{} 🧲 Trying to connect to: {}{}", NAME, addr, dev_name);
            if let Ok(true) = adapter.device(*addr)?.is_paired().await {
                let supported_uuids = device.uuids().await?.unwrap_or_default();
                debug!(
                    "{} Discovered device {} with service UUIDs {:?}",
                    NAME, addr, &supported_uuids
                );

                if supported_uuids.contains(&AV_REMOTE_CONTROL_TARGET_UUID)
                    && supported_uuids.contains(&AV_REMOTE_CONTROL_UUID)
                {
                    if !dongle_mode {
                        match device.connect_profile(&HSP_AG_UUID).await {
                            Ok(_) => {
                                info!(
                                    "{} 🔗 Successfully connected to device: {}{}",
                                    NAME, addr, dev_name
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                warn!("{} 🔇 {}{}: Error connecting: {}", NAME, addr, dev_name, e)
                            }
                        }
                    } else {
                        match device.connect().await {
                            Ok(_) => {
                                info!(
                                    "{} 🔗 Successfully connected to device: {}{}",
                                    NAME, addr, dev_name
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                // should be handled with the following code:
                                // match e.kind {bluer::ErrorKind::ConnectionAttemptFailed} ...
                                // but the problem is that not all errors are defined in bluer,
                                // so just fallback for text-searching in error :(
                                let error_text = e.to_string();

                                if let Some(code) =
                                    error_text.splitn(2, ':').nth(1).map(|s| s.trim())
                                {
                                    if code == "br-connection-page-timeout"
                                        || code == "br-connection-canceled"
                                    {
                                        warn!(
                                            "{} 🔇 {}{}: Error connecting: {}",
                                            NAME, addr, dev_name, e
                                        );
                                        Bluetooth::cleanup_failed_bluetooth_connect(&device)
                                            .await?;
                                    } else {
                                        info!(
                                    "{} 🔗 Connection success, waiting for AA profile connection: {}{}, ignored error: {}",
                                    NAME, addr, dev_name, e
                                );
                                        return Ok(());
                                    }
                                } else {
                                    warn!("{} Unknown bluetooth error: {}", NAME, e);
                                    Bluetooth::cleanup_failed_bluetooth_connect(&device).await?;
                                }
                            }
                        }
                    }
                } else {
                    warn!("{} 🧲 Will not try to connect to: {}{} device does not have the required Android Auto device profiles", NAME, addr, dev_name);
                }
            } else {
                warn!(
                    "{} 🧲 Unable to connect to: {}{} device not paired",
                    NAME, addr, dev_name
                );
            }
        }
        Err(anyhow!("Unable to connect to the provided addresses").into())
    }

    async fn cleanup_failed_bluetooth_connect(device: &Device) -> Result<()> {
        let cleanup_delay = Duration::from_secs(2);
        let _ = timeout(cleanup_delay, device.disconnect()).await;
        debug!(
            "{} Cleaned up bluetooth connection for device: {:?}",
            NAME,
            device.name().await
        );
        Ok(())
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

    pub async fn aa_handshake(
        &mut self,
        dongle_mode: bool,
        connect: BluetoothAddressList,
        wifi_config: WifiConfig,
        tcp_start: Arc<Notify>,
        bt_timeout: Duration,
        stopped: bool,
        quick_reconnect: bool,
        mut need_restart: BroadcastReceiver<Option<Action>>,
        restart_tx: BroadcastSender<Option<Action>>,
        profile_connected: Arc<AtomicBool>,
    ) -> Result<()> {
        // Use the provided session and adapter instead of creating new ones
        let (address, mut stream) = self
            .get_aa_profile_connection(dongle_mode, connect, bt_timeout, stopped)
            .await?;
        Self::send_params(wifi_config.clone(), &mut stream).await?;
        tcp_start.notify_one();

        if quick_reconnect {
            // keep the bluetooth profile connection alive
            // and use it in a loop to restart handshake when necessary
            let adapter_cloned = self.adapter.clone();
            let _ = Some(tokio::spawn(async move {
                profile_connected.store(true, Ordering::Relaxed);
                loop {
                    // wait for restart notification from main loop (eg when HU disconnected)
                    let action = need_restart.recv().await;
                    if let Ok(Some(action)) = action {
                        // check if we need to stop now
                        if action == Action::Stop {
                            // disconnect and break
                            if let Ok(device) = adapter_cloned.device(bluer::Address(*address)) {
                                let _ = device.disconnect().await;
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
                // main loop could now wait so send an event to restart
                let _ = restart_tx.send(None);
            }));
        } else {
            // handshake complete, now disconnect the device so it should
            // connect to real HU for calls
            let device = self.adapter.device(bluer::Address(*address))?;
            let _ = device.disconnect().await;
        }

        info!("{} 🚀 Bluetooth launch sequence completed", NAME);

        Ok(())
    }
}
