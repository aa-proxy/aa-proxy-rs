use crate::WifiConfig;
use bluer::adv::Advertisement;
use bluer::{
    adv::AdvertisementHandle,
    agent::{Agent, AgentHandle},
    rfcomm::{Profile, ProfileHandle, Role, Stream},
    Adapter, Address, Uuid,
};
use futures::StreamExt;
use simplelog::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;
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

const AAWG_PROFILE_UUID: Uuid = Uuid::from_u128(0x4de17a0052cb11e6bdf40800200c9a66);
const HSP_HS_UUID: Uuid = Uuid::from_u128(0x0000110800001000800000805f9b34fb);
const HSP_AG_UUID: Uuid = Uuid::from_u128(0x0000111200001000800000805f9b34fb);
const BT_ALIAS: &str = "WirelessAADongle";

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

pub struct BluetoothState {
    adapter: Adapter,
    handle_ble: Option<AdvertisementHandle>,
    handle_aa: ProfileHandle,
    handle_hsp: Option<JoinHandle<Result<ProfileHandle>>>,
    handle_agent: AgentHandle,
    keepalive: bool,
}

pub async fn get_cpu_serial_number_suffix() -> Result<String> {
    let mut serial = String::new();
    let contents = tokio::fs::read_to_string("/sys/firmware/devicetree/base/serial-number").await?;
    // check if we read the serial number with correct length
    if contents.len() == 17 {
        serial = (&contents[10..16]).to_string();
    }
    Ok(serial)
}

async fn power_up_and_wait_for_connection(
    advertise: bool,
    btalias: Option<String>,
    connect: Option<Address>,
    keepalive: bool,
    bt_timeout: Duration,
) -> Result<(BluetoothState, Stream)> {
    // setting BT alias for further use
    let alias = match btalias {
        None => match get_cpu_serial_number_suffix().await {
            Ok(suffix) => format!("{}-{}", BT_ALIAS, suffix),
            Err(_) => String::from(BT_ALIAS),
        },
        Some(btalias) => btalias,
    };
    info!("{} 🥏 Bluetooth alias: <bold><green>{}</>", NAME, alias);

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    info!(
        "{} 🥏 Opened bluetooth adapter <b>{}</> with address <b>{}</b>",
        NAME,
        adapter.name(),
        adapter.address().await?
    );
    adapter.set_alias(alias.clone()).await?;
    adapter.set_powered(true).await?;
    adapter.set_pairable(true).await?;

    let handle_ble = if advertise {
        // Perform a Bluetooth LE advertisement
        info!("{} 📣 BLE Advertisement started", NAME);
        let le_advertisement = Advertisement {
            advertisement_type: bluer::adv::Type::Peripheral,
            service_uuids: vec![AAWG_PROFILE_UUID].into_iter().collect(),
            discoverable: Some(true),
            local_name: Some(alias),
            ..Default::default()
        };

        Some(adapter.advertise(le_advertisement).await?)
    } else {
        adapter.set_discoverable(true).await?;
        adapter.set_discoverable_timeout(0).await?;

        None
    };

    // Default agent is probably needed when pairing for the first time
    let agent = Agent::default();
    let handle_agent = session.register_agent(agent).await?;

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
    let mut handle_aa = session.register_profile(profile).await?;
    info!("{} 📱 AA Wireless Profile: registered", NAME);

    // Headset profile
    let profile = Profile {
        uuid: HSP_HS_UUID,
        name: Some("HSP HS".to_string()),
        require_authentication: Some(false),
        require_authorization: Some(false),
        ..Default::default()
    };
    let handle_hsp = match session.register_profile(profile).await {
        Ok(handle_hsp) => {
            info!("{} 🎧 Headset Profile (HSP): registered", NAME);
            Some(handle_hsp)
        }
        Err(e) => {
            warn!(
                "{} 🎧 Headset Profile (HSP) registering error: {}, ignoring",
                NAME, e
            );
            None
        }
    };

    info!("{} ⏳ Waiting for phone to connect via bluetooth...", NAME);

    // try to connect to saved devices or provided one via command line
    let connect_task: Option<JoinHandle<Result<()>>> = match connect {
        Some(address) => {
            let adapter_cloned = adapter.clone();

            Some(tokio::spawn(async move {
                let addresses = if address == Address::any() {
                    info!("{} 🥏 Enumerating known bluetooth devices...", NAME);
                    adapter_cloned.device_addresses().await?
                } else {
                    vec![address]
                };
                // exit if we don't have anything to connect to
                if addresses.is_empty() {
                    return Ok(());
                }
                loop {
                    for addr in &addresses {
                        let device = adapter_cloned.device(*addr)?;
                        let dev_name = match device.name().await {
                            Ok(Some(name)) => format!(" (<b><blue>{}</>)", name),
                            _ => String::default(),
                        };
                        info!("{} 🧲 Trying to connect to: {}{}", NAME, addr, dev_name);
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
                    }
                    sleep(Duration::from_secs(1)).await;
                }
            }))
        }
        None => None,
    };

    // handling connection to headset profile in own task
    let task_hsp = {
        if let Some(mut handle_hsp) = handle_hsp {
            Some(tokio::spawn(async move {
                let req = handle_hsp
                    .next()
                    .await
                    .expect("received no connect request");
                info!(
                    "{} 🎧 Headset Profile (HSP): connect from: <b>{}</>",
                    NAME,
                    req.device()
                );
                req.accept()?;

                Ok(handle_hsp)
            }))
        } else {
            None
        }
    };

    let req = timeout(bt_timeout, handle_aa.next())
        .await?
        .expect("received no connect request");
    info!(
        "{} 📱 AA Wireless Profile: connect from: <b>{}</>",
        NAME,
        req.device()
    );
    let stream = req.accept()?;

    // we have a connection from phone, stop connect_task
    if let Some(task) = connect_task {
        task.abort();
    }

    // generate structure with adapter and handlers for graceful shutdown later
    let state = BluetoothState {
        adapter,
        handle_ble,
        handle_aa,
        handle_hsp: task_hsp,
        handle_agent,
        keepalive,
    };

    Ok((state, stream))
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
        warn!("unexpected MessageID = {}, len = {}, ignoring", message_id, len);
        /*return Err(format!(
            "Received data has invalid MessageID: got: {:?}, expected: {:?}",
            message_id, id,
        )
        .into());*/
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

pub async fn bluetooth_stop(state: BluetoothState) -> Result<()> {
    if let Some(handle) = state.handle_ble {
        info!("{} 📣 Removing BLE advertisement", NAME);
        drop(handle);
    }
    info!("{} 🥷 Unregistering default agent", NAME);
    drop(state.handle_agent);
    info!("{} 📱 Removing AA profile", NAME);
    drop(state.handle_aa);

    // HSP profile is/was running in own task
    if let Some(handle) = state.handle_hsp {
        match timeout(Duration::from_secs_f32(2.5), handle).await {
            Ok(task_handle) => match task_handle? {
                Ok(handle_hsp) => {
                    info!("{} 🎧 Removing HSP profile", NAME);
                    drop(handle_hsp);
                }
                Err(e) => {
                    warn!("{} 🎧 HSP profile error: {}", NAME, e);
                }
            },
            Err(e) => {
                warn!("{} 🎧 Error waiting for HSP profile task: {}", NAME, e);
            }
        }
    }

    if state.keepalive {
        info!("{} 💤 Bluetooth adapter stays on", NAME);
    } else {
        state.adapter.set_powered(false).await?;
        info!("{} 💤 Bluetooth adapter powered off", NAME);
    }

    Ok(())
}

pub async fn bluetooth_setup_connection(
    advertise: bool,
    btalias: Option<String>,
    connect: Option<Address>,
    wifi_config: WifiConfig,
    tcp_start: Arc<Notify>,
    keepalive: bool,
    bt_timeout: Duration,
) -> Result<BluetoothState> {
    use WifiInfoResponse::WifiInfoResponse;
    use WifiStartRequest::WifiStartRequest;
    let mut stage = 1;
    let mut started;

    let (state, mut stream) =
        power_up_and_wait_for_connection(advertise, btalias, connect, keepalive, bt_timeout)
            .await?;

    info!("{} 📲 Sending parameters via bluetooth to phone...", NAME);
    let mut start_req = WifiStartRequest::new();
    info!(
        "{} 🛜 Sending Host IP Address: {}",
        NAME, wifi_config.ip_addr
    );
    start_req.set_ip_address(wifi_config.ip_addr);
    start_req.set_port(wifi_config.port);
    send_message(&mut stream, stage, MessageId::WifiStartRequest, start_req).await?;
    stage += 1;
    started = Instant::now();
    read_message(&mut stream, stage, MessageId::WifiInfoRequest, started).await?;

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
    send_message(&mut stream, stage, MessageId::WifiInfoResponse, info).await?;
    stage += 1;
    started = Instant::now();
    read_message(&mut stream, stage, MessageId::WifiStartResponse, started).await?;
    stage += 1;
    started = Instant::now();
    read_message(&mut stream, stage, MessageId::WifiConnectStatus, started).await?;
    tcp_start.notify_one();
    let _ = stream.shutdown().await?;

    info!("{} 🚀 Bluetooth launch sequence completed", NAME);

    Ok(state)
}
