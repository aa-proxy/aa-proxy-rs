use log::log_enabled;
use openssl::ssl::{ErrorCode, Ssl, SslContextBuilder, SslFiletype, SslMethod};
use simplelog::*;
use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;
use tokio_uring::buf::BoundedBuf;

// protobuf stuff:
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use crate::mitm::protos::*;
use crate::mitm::sensor_source_service::Sensor;
use crate::mitm::AudioStreamType::*;
use crate::mitm::SensorMessageId::*;
use crate::mitm::SensorType::*;
use protobuf::text_format::print_to_string_pretty;
use protobuf::{Enum, Message, MessageDyn};
use protos::ControlMessageType::{self, *};

use crate::config::AppConfig;
use crate::config::HexdumpLevel;
use crate::ev::RestContext;
use crate::io_uring::Endpoint;
use crate::io_uring::IoDevice;
use crate::io_uring::BUFFER_LEN;

// module name for logging engine
fn get_name(proxy_type: ProxyType) -> String {
    let proxy = match proxy_type {
        ProxyType::HeadUnit => "HU",
        ProxyType::MobileDevice => "MD",
    };
    format!("<i><bright-black> mitm/{}: </>", proxy)
}

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// message related constants:
pub const HEADER_LENGTH: usize = 4;
pub const FRAME_TYPE_FIRST: u8 = 1 << 0;
pub const FRAME_TYPE_LAST: u8 = 1 << 1;
pub const FRAME_TYPE_MASK: u8 = FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
const _CONTROL: u8 = 1 << 2;
pub const ENCRYPTED: u8 = 1 << 3;

// location for hu_/md_ private keys and certificates:
const KEYS_PATH: &str = "/etc/aa-proxy-rs";

pub struct ModifyContext {
    sensor_channel: Option<u8>,
}

#[derive(PartialEq, Copy, Clone)]
pub enum ProxyType {
    HeadUnit,
    MobileDevice,
}

/// rust-openssl doesn't support BIO_s_mem
/// This SslMemBuf is about to provide `Read` and `Write` implementations
/// to be used with `openssl::ssl::SslStream`
/// more info:
/// https://github.com/sfackler/rust-openssl/issues/1697
type LocalDataBuffer = Arc<Mutex<VecDeque<u8>>>;
#[derive(Clone)]
pub struct SslMemBuf {
    /// a data buffer that the server writes to and the client reads from
    pub server_stream: LocalDataBuffer,
    /// a data buffer that the client writes to and the server reads from
    pub client_stream: LocalDataBuffer,
}

// Read implementation used internally by OpenSSL
impl Read for SslMemBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.client_stream.lock().unwrap().read(buf)
    }
}

// Write implementation used internally by OpenSSL
impl Write for SslMemBuf {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.server_stream.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.server_stream.lock().unwrap().flush()
    }
}

// Own functions for accessing shared data
impl SslMemBuf {
    fn read_to(&mut self, buf: &mut Vec<u8>) -> std::result::Result<usize, std::io::Error> {
        self.server_stream.lock().unwrap().read_to_end(buf)
    }
    fn write_from(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.client_stream.lock().unwrap().write(buf)
    }
}

pub struct Packet {
    pub channel: u8,
    pub flags: u8,
    pub final_length: Option<u32>,
    pub payload: Vec<u8>,
}

impl Packet {
    /// payload encryption if needed
    async fn encrypt_payload(
        &mut self,
        mem_buf: &mut SslMemBuf,
        server: &mut openssl::ssl::SslStream<SslMemBuf>,
    ) -> Result<()> {
        if (self.flags & ENCRYPTED) == ENCRYPTED {
            // save plain data for encryption
            server.ssl_write(&self.payload)?;
            // read encrypted data
            let mut res: Vec<u8> = Vec::new();
            mem_buf.read_to(&mut res)?;
            self.payload = res;
        }

        Ok(())
    }

    /// payload decryption if needed
    async fn decrypt_payload(
        &mut self,
        mem_buf: &mut SslMemBuf,
        server: &mut openssl::ssl::SslStream<SslMemBuf>,
    ) -> Result<()> {
        if (self.flags & ENCRYPTED) == ENCRYPTED {
            // save encrypted data
            mem_buf.write_from(&self.payload)?;
            // read plain data
            let mut res: Vec<u8> = Vec::new();
            server.read_to_end(&mut res)?;
            self.payload = res;
        }

        Ok(())
    }

    /// composes a final frame and transmits it to endpoint device (HU/MD)
    async fn transmit<A: Endpoint<A>>(
        &self,
        device: &mut IoDevice<A>,
    ) -> std::result::Result<usize, std::io::Error> {
        let len = self.payload.len() as u16;
        let mut frame: Vec<u8> = vec![];
        frame.push(self.channel);
        frame.push(self.flags);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xff) as u8);
        if let Some(final_len) = self.final_length {
            // adding addional 4-bytes of final_len header
            frame.push((final_len >> 24) as u8);
            frame.push((final_len >> 16) as u8);
            frame.push((final_len >> 8) as u8);
            frame.push((final_len & 0xff) as u8);
        }
        match device {
            IoDevice::UsbWriter(device, _) => {
                frame.append(&mut self.payload.clone());
                let mut dev = device.borrow_mut();
                dev.write(&frame).await
            }
            IoDevice::EndpointIo(device) => {
                frame.append(&mut self.payload.clone());
                device.write(frame).submit().await.0
            }
            IoDevice::TcpStreamIo(device) => {
                frame.append(&mut self.payload.clone());
                device.write(frame).submit().await.0
            }
            _ => todo!(),
        }
    }

    /// decapsulates SSL payload and writes to SslStream
    async fn ssl_decapsulate_write(&self, mem_buf: &mut SslMemBuf) -> Result<()> {
        let message_type = u16::from_be_bytes(self.payload[0..=1].try_into()?);
        if message_type == ControlMessageType::MESSAGE_ENCAPSULATED_SSL as u16 {
            mem_buf.write_from(&self.payload[2..])?;
        }
        Ok(())
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "packet dump:\n")?;
        write!(f, " channel: {:02X}\n", self.channel)?;
        write!(f, " flags: {:02X}\n", self.flags)?;
        write!(f, " final length: {:04X?}\n", self.final_length)?;
        write!(f, " payload: {:02X?}\n", self.payload.clone().into_iter())?;

        Ok(())
    }
}

/// shows packet/message contents as pretty string for debug
pub async fn pkt_debug(
    proxy_type: ProxyType,
    hexdump: HexdumpLevel,
    hex_requested: HexdumpLevel,
    pkt: &Packet,
) -> Result<()> {
    // don't run further if we are not in Debug mode
    if !log_enabled!(Level::Debug) {
        return Ok(());
    }

    // if for some reason we have too small packet, bail out
    if pkt.payload.len() < 2 {
        return Ok(());
    }
    // message_id is the first 2 bytes of payload
    let message_id: i32 = u16::from_be_bytes(pkt.payload[0..=1].try_into()?).into();

    // trying to obtain an Enum from message_id
    let control = protos::ControlMessageType::from_i32(message_id);
    debug!("message_id = {:04X}, {:?}", message_id, control);
    if hex_requested >= hexdump {
        debug!("{} {:?} {}", get_name(proxy_type), hexdump, pkt);
    }

    // parsing data
    let data = &pkt.payload[2..]; // start of message data
    let message: &dyn MessageDyn = match control.unwrap_or(MESSAGE_UNEXPECTED_MESSAGE) {
        MESSAGE_AUTH_COMPLETE => &AuthResponse::parse_from_bytes(data)?,
        MESSAGE_SERVICE_DISCOVERY_REQUEST => &ServiceDiscoveryRequest::parse_from_bytes(data)?,
        MESSAGE_SERVICE_DISCOVERY_RESPONSE => &ServiceDiscoveryResponse::parse_from_bytes(data)?,
        MESSAGE_PING_REQUEST => &PingRequest::parse_from_bytes(data)?,
        MESSAGE_PING_RESPONSE => &PingResponse::parse_from_bytes(data)?,
        MESSAGE_NAV_FOCUS_REQUEST => &NavFocusRequestNotification::parse_from_bytes(data)?,
        MESSAGE_CHANNEL_OPEN_RESPONSE => &ChannelOpenResponse::parse_from_bytes(data)?,
        MESSAGE_CHANNEL_OPEN_REQUEST => &ChannelOpenRequest::parse_from_bytes(data)?,
        MESSAGE_AUDIO_FOCUS_REQUEST => &AudioFocusRequestNotification::parse_from_bytes(data)?,
        MESSAGE_AUDIO_FOCUS_NOTIFICATION => &AudioFocusNotification::parse_from_bytes(data)?,
        _ => return Ok(()),
    };
    // show pretty string from the message
    debug!("{}", print_to_string_pretty(message));

    Ok(())
}

/// packet modification hook
pub async fn pkt_modify_hook(
    proxy_type: ProxyType,
    pkt: &mut Packet,
    dpi: u16,
    developer_mode: bool,
    disable_media_sink: bool,
    disable_tts_sink: bool,
    remove_tap_restriction: bool,
    video_in_motion: bool,
    ev: bool,
    ctx: &mut ModifyContext,
    rest_ctx: Option<Arc<tokio::sync::Mutex<RestContext>>>,
    ev_battery_logger: Option<PathBuf>,
) -> Result<bool> {
    // if for some reason we have too small packet, bail out
    if pkt.payload.len() < 2 {
        return Ok(false);
    }

    // message_id is the first 2 bytes of payload
    let message_id: i32 = u16::from_be_bytes(pkt.payload[0..=1].try_into()?).into();
    let data = &pkt.payload[2..]; // start of message data

    // handling data on sensor channel
    if let Some(ch) = ctx.sensor_channel {
        if ch == pkt.channel {
            match protos::SensorMessageId::from_i32(message_id).unwrap_or(SENSOR_MESSAGE_ERROR) {
                SENSOR_MESSAGE_REQUEST => {
                    if let Ok(msg) = SensorRequest::parse_from_bytes(data) {
                        if msg.type_() == SensorType::SENSOR_VEHICLE_ENERGY_MODEL_DATA {
                            debug!(
                                "additional SENSOR_MESSAGE_REQUEST for {:?}, making a response with success...",
                                msg.type_()
                            );
                            let mut response = SensorResponse::new();
                            response.set_status(MessageStatus::STATUS_SUCCESS);

                            let mut payload: Vec<u8> = response.write_to_bytes()?;
                            payload.insert(0, ((SENSOR_MESSAGE_RESPONSE as u16) >> 8) as u8);
                            payload.insert(1, ((SENSOR_MESSAGE_RESPONSE as u16) & 0xff) as u8);

                            let reply = Packet {
                                channel: ch,
                                flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
                                final_length: None,
                                payload: payload,
                            };
                            *pkt = reply;

                            // start EV battery logger if neded
                            if let Some(ref path) = ev_battery_logger {
                                let _ = Command::new(path).arg("start").spawn();
                            }

                            // return true => send own reply without processing
                            return Ok(true);
                        }
                    }
                }
                SENSOR_MESSAGE_BATCH => {
                    if let Ok(mut msg) = SensorBatch::parse_from_bytes(data) {
                        if video_in_motion {
                            if !msg.driving_status_data.is_empty() {
                                // forcing status to 0 value
                                msg.driving_status_data[0].set_status(0);
                                // regenerating payload data
                                pkt.payload = msg.write_to_bytes()?;
                                pkt.payload.insert(0, (message_id >> 8) as u8);
                                pkt.payload.insert(1, (message_id & 0xff) as u8);
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        // end sensors processing
        return Ok(false);
    }

    if pkt.channel != 0 || proxy_type == ProxyType::MobileDevice {
        return Ok(false);
    }
    // trying to obtain an Enum from message_id
    let control = protos::ControlMessageType::from_i32(message_id);
    debug!("message_id = {:04X}, {:?}", message_id, control);

    // parsing data
    match control.unwrap_or(MESSAGE_UNEXPECTED_MESSAGE) {
        MESSAGE_SERVICE_DISCOVERY_RESPONSE => {
            let mut msg = ServiceDiscoveryResponse::parse_from_bytes(data)?;

            // DPI
            if dpi > 0 {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.media_sink_service.video_configs.is_empty())
                {
                msg.services
                    .retain(|svc| svc.media_sink_service.codec_resolution() == VIDEO_1920x1080);
                info!(
                    "{} <yellow>{:?}</>: best codec retained",
                    get_name(proxy_type),
                    control.unwrap(),
                );
                /*
                    // get previous/original value
                    let prev_val = svc.media_sink_service.video_configs[0].density();
                    // set new value
                    svc.media_sink_service.as_mut().unwrap().video_configs[0]
                        .set_density(dpi.into());
                    info!(
                        "{} <yellow>{:?}</>: replacing DPI[0] value: from <b>{}</> to <b>{}</>",
                        get_name(proxy_type),
                        control.unwrap(),
                        prev_val,
                        dpi
                    );
*/
                }
            }

            // disable tts sink
            if disable_tts_sink {
                while let Some(svc) = msg.services.iter_mut().find(|svc| {
                    !svc.media_sink_service.audio_configs.is_empty()
                        && svc.media_sink_service.audio_type() == AUDIO_STREAM_GUIDANCE
                }) {
                    svc.media_sink_service
                        .as_mut()
                        .unwrap()
                        .set_audio_type(AUDIO_STREAM_SYSTEM_AUDIO);
                }
                info!(
                    "{} <yellow>{:?}</>: TTS sink disabled",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            // disable media sink
            if disable_media_sink {
                msg.services
                    .retain(|svc| svc.media_sink_service.audio_type() != AUDIO_STREAM_MEDIA);
                info!(
                    "{} <yellow>{:?}</>: media sink disabled",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            // save sensor channel in context
            if ev || video_in_motion {
                if let Some(svc) = msg
                    .services
                    .iter()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    // set in local context
                    ctx.sensor_channel = Some(svc.id() as u8);
                    // set in REST server context for remote EV requests
                    if let Some(ctx) = rest_ctx {
                        let mut rest_ctx = ctx.lock().await;
                        rest_ctx.sensor_channel = Some(svc.id() as u8);
                    }
                }
            }

            // remove tap restriction by removing SENSOR_SPEED
            if remove_tap_restriction {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .retain(|s| s.sensor_type() != SENSOR_SPEED);
                }
            }

            // enabling developer mode
            if developer_mode {
                msg.set_make("Google".into());
                msg.set_model("Desktop Head Unit".into());
                info!(
                    "{} <yellow>{:?}</>: enabling developer mode",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            // EV routing features
            if ev {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    // add VEHICLE_ENERGY_MODEL_DATA sensor
                    let mut sensor = Sensor::new();
                    sensor.set_sensor_type(SENSOR_VEHICLE_ENERGY_MODEL_DATA);
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .push(sensor);

                    // set FUEL_TYPE
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .supported_fuel_types = vec![FuelType::FUEL_TYPE_ELECTRIC.into()];

                    // supported connector types
                    // FIXME: make this connectors configurable via config
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .supported_ev_connector_types =
                        vec![EvConnectorType::EV_CONNECTOR_TYPE_MENNEKES.into()];
                }
            }

            debug!(
                "{} SDR after changes: {}",
                get_name(proxy_type),
                protobuf::text_format::print_to_string_pretty(&msg)
            );

            // rewrite payload to new message contents
            pkt.payload = msg.write_to_bytes()?;
            // inserting 2 bytes of message_id at the beginning
            pkt.payload.insert(0, (message_id >> 8) as u8);
            pkt.payload.insert(1, (message_id & 0xff) as u8);
        }
        _ => return Ok(false),
    };

    Ok(false)
}

/// encapsulates SSL data into Packet
async fn ssl_encapsulate(mut mem_buf: SslMemBuf) -> Result<Packet> {
    // read SSL-generated data
    let mut res: Vec<u8> = Vec::new();
    mem_buf.read_to(&mut res)?;

    // create MESSAGE_ENCAPSULATED_SSL Packet
    let message_type = ControlMessageType::MESSAGE_ENCAPSULATED_SSL as u16;
    res.insert(0, (message_type >> 8) as u8);
    res.insert(1, (message_type & 0xff) as u8);
    Ok(Packet {
        channel: 0x00,
        flags: FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload: res,
    })
}

/// creates Ssl for HeadUnit (SSL server) and MobileDevice (SSL client)
async fn ssl_builder(proxy_type: ProxyType) -> Result<Ssl> {
    let mut ctx_builder = SslContextBuilder::new(SslMethod::tls())?;

    // for HU/headunit we need to act as a MD/mobiledevice, so load "md" key and cert
    // and vice versa
    let prefix = match proxy_type {
        ProxyType::HeadUnit => "md",
        ProxyType::MobileDevice => "hu",
    };
    ctx_builder.set_certificate_file(format!("{KEYS_PATH}/{prefix}_cert.pem"), SslFiletype::PEM)?;
    ctx_builder.set_private_key_file(format!("{KEYS_PATH}/{prefix}_key.pem"), SslFiletype::PEM)?;
    ctx_builder.check_private_key()?;
    // trusted root certificates:
    ctx_builder.set_ca_file(format!("{KEYS_PATH}/galroot_cert.pem"))?;

    ctx_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    ctx_builder.set_options(openssl::ssl::SslOptions::NO_TLSV1_3);

    let openssl_ctx = ctx_builder.build();
    let mut ssl = Ssl::new(&openssl_ctx)?;
    if proxy_type == ProxyType::HeadUnit {
        ssl.set_accept_state(); // SSL server
    } else if proxy_type == ProxyType::MobileDevice {
        ssl.set_connect_state(); // SSL client
    }

    Ok(ssl)
}

/// reads all available data to VecDeque
async fn read_input_data<A: Endpoint<A>>(
    rbuf: &mut VecDeque<u8>,
    obj: &mut IoDevice<A>,
) -> Result<()> {
    let mut newdata = vec![0u8; BUFFER_LEN];
    let n;
    match obj {
        IoDevice::UsbReader(device, _) => {
            let mut dev = device.borrow_mut();
            let retval = dev.read(&mut newdata);
            n = retval.await;
        }
        IoDevice::EndpointIo(device) => {
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .map_err(|_| -> String { format!("read_input_data: timeout") })?;
        }
        IoDevice::TcpStreamIo(device) => {
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .map_err(|_| -> String { format!("read_input_data: timeout") })?;
        }
        _ => todo!(),
    }
    let n = n?;
    if n > 0 {
        rbuf.write(&newdata.slice(..n))?;
    }
    Ok(())
}

/// main reader thread for a device
pub async fn endpoint_reader<A: Endpoint<A>>(
    mut device: IoDevice<A>,
    tx: Sender<Packet>,
) -> Result<()> {
    let mut rbuf: VecDeque<u8> = VecDeque::new();
    loop {
        read_input_data(&mut rbuf, &mut device).await?;
        // check if we have complete packet available
        loop {
            if rbuf.len() > HEADER_LENGTH {
                let channel = rbuf[0];
                let flags = rbuf[1];
                let mut header_size = HEADER_LENGTH;
                let mut final_length = None;
                let payload_size = (rbuf[3] as u16 + ((rbuf[2] as u16) << 8)) as usize;
                if rbuf.len() > 8 && (flags & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST {
                    header_size += 4;
                    final_length = Some(
                        ((rbuf[4] as u32) << 24)
                            + ((rbuf[5] as u32) << 16)
                            + ((rbuf[6] as u32) << 8)
                            + (rbuf[7] as u32),
                    );
                }
                let frame_size = header_size + payload_size;
                if rbuf.len() >= frame_size {
                    let mut frame = vec![0u8; frame_size];
                    rbuf.read_exact(&mut frame)?;
                    // we now have all header data analyzed/read, so remove
                    // the header from frame to have payload only left
                    frame.drain(..header_size);
                    let pkt = Packet {
                        channel,
                        flags,
                        final_length,
                        payload: frame,
                    };
                    // send packet to main thread for further process
                    tx.send(pkt).await?;
                    // check if we have another packet
                    continue;
                }
            }
            // no more complete packets available
            break;
        }
    }
}

/// checking if there was a true fatal SSL error
/// Note that the error may not be fatal. For example if the underlying
/// stream is an asynchronous one then `HandshakeError::WouldBlock` may
/// just mean to wait for more I/O to happen later.
fn ssl_check_failure<T>(res: std::result::Result<T, openssl::ssl::Error>) -> Result<()> {
    if let Err(err) = res {
        match err.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE | ErrorCode::SYSCALL => Ok(()),
            _ => return Err(Box::new(err)),
        }
    } else {
        Ok(())
    }
}

/// main thread doing all packet processing of an endpoint/device
pub async fn proxy<A: Endpoint<A> + 'static>(
    proxy_type: ProxyType,
    mut device: IoDevice<A>,
    bytes_written: Arc<AtomicUsize>,
    tx: Sender<Packet>,
    mut rx: Receiver<Packet>,
    mut rxr: Receiver<Packet>,
    config: AppConfig,
    rest_ctx: Option<Arc<tokio::sync::Mutex<RestContext>>>,
) -> Result<()> {
    let passthrough = !config.mitm;
    let hex_requested = config.hexdump_level;

    // in full_frames/passthrough mode we only directly pass packets from one endpoint to the other
    if passthrough {
        loop {
            // handling data from opposite device's thread, which needs to be transmitted
            if let Ok(pkt) = rx.try_recv() {
                pkt.transmit(&mut device).await?;

                // Increment byte counters for statistics
                // fixme: compute final_len for precise stats
                bytes_written.fetch_add(HEADER_LENGTH + pkt.payload.len(), Ordering::Relaxed);
            };

            // handling input data from the reader thread
            if let Ok(pkt) = rxr.try_recv() {
                tx.send(pkt).await?;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let ssl = ssl_builder(proxy_type).await?;

    let mut mem_buf = SslMemBuf {
        client_stream: Arc::new(Mutex::new(VecDeque::new())),
        server_stream: Arc::new(Mutex::new(VecDeque::new())),
    };
    let mut server = openssl::ssl::SslStream::new(ssl, mem_buf.clone())?;

    // initial phase: passing version and doing SSL handshake
    // for both HU and MD
    if proxy_type == ProxyType::HeadUnit {
        // waiting for initial version frame (HU is starting transmission)
        let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::DecryptedInput, // the packet is not encrypted
            hex_requested,
            &pkt,
        )
        .await;
        // sending to the MD
        tx.send(pkt).await?;
        // waiting for MD reply
        let pkt = rx.recv().await.ok_or("rx channel hung up")?;
        // sending reply back to the HU
        let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt).await;
        pkt.transmit(&mut device).await?;

        // doing SSL handshake
        const STEPS: u8 = 2;
        for i in 1..=STEPS {
            let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawInput, hex_requested, &pkt).await;
            pkt.ssl_decapsulate_write(&mut mem_buf).await?;
            ssl_check_failure(server.accept())?;
            info!(
                "{} 🔒 stage #{} of {}: SSL handshake: {}",
                get_name(proxy_type),
                i,
                STEPS,
                server.ssl().state_string_long(),
            );
            if server.ssl().is_init_finished() {
                info!(
                    "{} 🔒 SSL init complete, negotiated cipher: <b><blue>{}</>",
                    get_name(proxy_type),
                    server.ssl().current_cipher().unwrap().name(),
                );
            }
            let pkt = ssl_encapsulate(mem_buf.clone()).await?;
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt).await;
            pkt.transmit(&mut device).await?;
        }
    } else if proxy_type == ProxyType::MobileDevice {
        // expecting version request from the HU here...
        let pkt = rx.recv().await.ok_or("rx channel hung up")?;
        // sending to the MD
        let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt).await;
        pkt.transmit(&mut device).await?;
        // waiting for MD reply
        let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::DecryptedInput, // the packet is not encrypted
            hex_requested,
            &pkt,
        )
        .await;
        // sending reply back to the HU
        tx.send(pkt).await?;

        // doing SSL handshake
        const STEPS: u8 = 3;
        for i in 1..=STEPS {
            ssl_check_failure(server.do_handshake())?;
            info!(
                "{} 🔒 stage #{} of {}: SSL handshake: {}",
                get_name(proxy_type),
                i,
                STEPS,
                server.ssl().state_string_long(),
            );
            if server.ssl().is_init_finished() {
                info!(
                    "{} 🔒 SSL init complete, negotiated cipher: <b><blue>{}</>",
                    get_name(proxy_type),
                    server.ssl().current_cipher().unwrap().name(),
                );
            }
            if i == 3 {
                // this was the last handshake step, need to break here
                break;
            };
            let pkt = ssl_encapsulate(mem_buf.clone()).await?;
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt).await;
            pkt.transmit(&mut device).await?;

            let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawInput, hex_requested, &pkt).await;
            pkt.ssl_decapsulate_write(&mut mem_buf).await?;
        }
    }

    // main data processing/transfer loop
    let mut ctx = ModifyContext {
        sensor_channel: None,
    };
    loop {
        // handling data from opposite device's thread, which needs to be transmitted
        if let Ok(mut pkt) = rx.try_recv() {
            let handled = pkt_modify_hook(
                proxy_type,
                &mut pkt,
                config.dpi,
                config.developer_mode,
                config.disable_media_sink,
                config.disable_tts_sink,
                config.remove_tap_restriction,
                config.video_in_motion,
                config.ev,
                &mut ctx,
                rest_ctx.clone(),
                config.ev_battery_logger.clone(),
            )
            .await?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::DecryptedOutput,
                hex_requested,
                &pkt,
            )
            .await;

            if handled {
                debug!(
                    "{} pkt_modify_hook: message has been handled, sending reply packet only...",
                    get_name(proxy_type)
                );
                tx.send(pkt).await?;
            } else {
                pkt.encrypt_payload(&mut mem_buf, &mut server).await?;
                let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt).await;
                pkt.transmit(&mut device).await?;

                // Increment byte counters for statistics
                // fixme: compute final_len for precise stats
                bytes_written.fetch_add(HEADER_LENGTH + pkt.payload.len(), Ordering::Relaxed);
            }
        };

        // handling input data from the reader thread
        if let Ok(mut pkt) = rxr.try_recv() {
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawInput, hex_requested, &pkt).await;
            match pkt.decrypt_payload(&mut mem_buf, &mut server).await {
                Ok(_) => {
                    let _ = pkt_modify_hook(
                        proxy_type,
                        &mut pkt,
                        config.dpi,
                        config.developer_mode,
                        config.disable_media_sink,
                        config.disable_tts_sink,
                        config.remove_tap_restriction,
                        config.video_in_motion,
                        config.ev,
                        &mut ctx,
                        rest_ctx.clone(),
                        config.ev_battery_logger.clone(),
                    )
                    .await?;
                    let _ = pkt_debug(
                        proxy_type,
                        HexdumpLevel::DecryptedInput,
                        hex_requested,
                        &pkt,
                    )
                    .await;
                    tx.send(pkt).await?;
                }
                Err(e) => error!("decrypt_payload: {:?}", e),
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
