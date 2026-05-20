#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::ScriptRegistry;
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use crate::mitm::{
    ensure_static_media_tap_listeners, static_media_tap_aux_slot_count, MediaTapEndpointInfo,
    SharedCompanionIp, SharedMediaChannels, SharedMediaSinks, SharedMediaTapEndpoints,
    SharedServiceDiscoveryResponse,
};
use crate::web::ServerEvent;
use bytesize::ByteSize;
use core::net::SocketAddr;
use humantime::format_duration;
use mac_address::MacAddress;
use simplelog::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File as TokioFile;
use tokio::io::{self, copy_bidirectional, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::process::Command;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_uring::buf::BoundedBuf;
use tokio_uring::buf::BoundedBufMut;
use tokio_uring::fs::File;
use tokio_uring::fs::OpenOptions;
use tokio_uring::net::TcpListener;
use tokio_uring::net::TcpStream;
use tokio_uring::BufResult;
use tokio_uring::UnsubmittedWrite;
use tokio_util::sync::CancellationToken;

// module name for logging engine
const NAME: &str = "<i><bright-black> proxy: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const USB_ACCESSORY_PATH: &str = "/dev/usb_accessory";
pub const BUFFER_LEN: usize = 16 * 1024;
const TCP_CLIENT_TIMEOUT: Duration = Duration::new(30, 0);
const COMP_APP_TCP_PORT: u16 = 9999;
const COMP_APP_TCP_PORT_WS: u16 = 9998;
const COMP_APP_TCP_PORT_SWUPDATE: u16 = 9997;
// Original queue depth was 10. Keep this small to avoid queue-induced latency.
const MITM_QUEUE_CAPACITY: usize = 10;

use crate::config::{Action, SharedConfig};
use crate::config::{TCP_DHU_PORT, TCP_SERVER_PORT};
use crate::ev::spawn_ev_client_task;
use crate::ev::BatteryData;
use crate::ev::EvTaskCommand;
use crate::mitm::endpoint_reader;
use crate::mitm::proxy;
use crate::mitm::Packet;
use crate::mitm::ProxyType;
use crate::usb_stream;
use crate::usb_stream::{UsbStreamRead, UsbStreamWrite};

// tokio_uring::fs::File and tokio_uring::net::TcpStream are using different
// read and write calls:
// File is using read_at() and write_at(),
// TcpStream is using read() and write()
//
// In our case we are reading a special unix character device for
// the USB gadget, which is not a regular file where an offset is important.
// We just use offset 0 for reading and writing, so below is a trait
// for this, to be able to use it in a generic copy() function below.

pub trait Endpoint<E> {
    #[allow(async_fn_in_trait)]
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T>;
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T>;
}

impl Endpoint<File> for File {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read_at(buf, 0).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write_at(buf, 0)
    }
}

impl Endpoint<TcpStream> for TcpStream {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read(buf).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write(buf)
    }
}

pub enum IoDevice<A: Endpoint<A>> {
    UsbReader(Rc<RefCell<UsbStreamRead>>, PhantomData<A>),
    UsbWriter(Rc<RefCell<UsbStreamWrite>>, PhantomData<A>),
    EndpointIo(Rc<A>),
    TcpStreamIo(Rc<TcpStream>),
}

async fn transfer_monitor(
    stats_interval: Option<Duration>,
    usb_bytes_written: Arc<AtomicUsize>,
    tcp_bytes_written: Arc<AtomicUsize>,
    read_timeout: Duration,
    config: SharedConfig,
) -> Result<()> {
    let mut usb_bytes_out_last: usize = 0;
    let mut tcp_bytes_out_last: usize = 0;
    let mut stall_usb_bytes_last: usize = 0;
    let mut stall_tcp_bytes_last: usize = 0;
    let mut report_time = Instant::now();
    let mut stall_check = Instant::now();

    info!(
        "{} ⚙️ Showing transfer statistics: <b><blue>{}</>",
        NAME,
        match stats_interval {
            Some(d) => format_duration(d).to_string(),
            None => "disabled".to_string(),
        }
    );

    loop {
        // load current total transfer from AtomicUsize:
        let usb_bytes_out = usb_bytes_written.load(Ordering::Relaxed);
        let tcp_bytes_out = tcp_bytes_written.load(Ordering::Relaxed);

        // Stats printing
        if stats_interval.is_some() && report_time.elapsed() > stats_interval.unwrap() {
            // compute USB transfer
            usb_bytes_out_last = usb_bytes_out - usb_bytes_out_last;
            let usb_transferred_total = ByteSize::b(usb_bytes_out.try_into().unwrap());
            let usb_transferred_last = ByteSize::b(usb_bytes_out_last.try_into().unwrap());
            let usb_speed: u64 =
                (usb_bytes_out_last as f64 / report_time.elapsed().as_secs_f64()).round() as u64;
            let usb_speed = ByteSize::b(usb_speed);

            // compute TCP transfer
            tcp_bytes_out_last = tcp_bytes_out - tcp_bytes_out_last;
            let tcp_transferred_total = ByteSize::b(tcp_bytes_out.try_into().unwrap());
            let tcp_transferred_last = ByteSize::b(tcp_bytes_out_last.try_into().unwrap());
            let tcp_speed: u64 =
                (tcp_bytes_out_last as f64 / report_time.elapsed().as_secs_f64()).round() as u64;
            let tcp_speed = ByteSize::b(tcp_speed);

            info!(
                "{} {} {: >9} ({: >9}/s), {: >9} total | {} {: >9} ({: >9}/s), {: >9} total",
                NAME,
                "phone -> car 🔺",
                usb_transferred_last.to_string_as(true),
                usb_speed.to_string_as(true),
                usb_transferred_total.to_string_as(true),
                "car -> phone 🔻",
                tcp_transferred_last.to_string_as(true),
                tcp_speed.to_string_as(true),
                tcp_transferred_total.to_string_as(true),
            );

            // save values for next iteration
            report_time = Instant::now();
            usb_bytes_out_last = usb_bytes_out;
            tcp_bytes_out_last = tcp_bytes_out;
        }

        // transfer stall detection
        if stall_check.elapsed() > read_timeout {
            // compute delta since last check
            stall_usb_bytes_last = usb_bytes_out - stall_usb_bytes_last;
            stall_tcp_bytes_last = tcp_bytes_out - stall_tcp_bytes_last;

            if stall_usb_bytes_last == 0 || stall_tcp_bytes_last == 0 {
                return Err("unexpected transfer stall".into());
            }

            // save values for next iteration
            stall_check = Instant::now();
            stall_usb_bytes_last = usb_bytes_out;
            stall_tcp_bytes_last = tcp_bytes_out;
        }

        // check pending action
        let action = config.read().await.action_requested.clone();
        if let Some(action) = action {
            // check if we need to restart or reboot
            if action == Action::Reconnect {
                config.write().await.action_requested = None;
            }
            return Err(format!("action request: {:?}", action).into());
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn flatten<T>(handle: &mut JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(_) => Err("handling failed".into()),
    }
}

async fn tcp_bridge(remote_addr: &str, local_addr: &str, cancel: CancellationToken) {
    loop {
        debug!(
            "{} tcp_bridge: before connect, local={} remote={}",
            NAME, local_addr, remote_addr
        );

        let connect_result = tokio::select! {
            _ = cancel.cancelled() => {
                debug!("{} tcp_bridge: cancelled before connect ({})", NAME, remote_addr);
                return;
            }
            result = timeout(Duration::from_secs(3), TokioTcpStream::connect(remote_addr)) => result,
        };

        match connect_result {
            Err(_) => {
                debug!(
                    "{} tcp_bridge: timeout connecting to remote server {}",
                    NAME, remote_addr
                );
            }
            Ok(Err(e)) => {
                debug!(
                    "{} tcp_bridge: failed to connect to remote server {}: {}",
                    NAME, remote_addr, e
                );
            }
            Ok(Ok(mut remote)) => {
                debug!(
                    "{} tcp_bridge: remote side connected: ({})",
                    NAME, remote_addr
                );

                let local_result = tokio::select! {
                    _ = cancel.cancelled() => {
                        debug!("{} tcp_bridge: cancelled before local connect ({})", NAME, local_addr);
                        return;
                    }
                    result = timeout(Duration::from_secs(3), TokioTcpStream::connect(local_addr)) => result,
                };

                match local_result {
                    Err(_) => {
                        debug!(
                            "{} tcp_bridge: timeout connecting to local server {}",
                            NAME, local_addr
                        );
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "{} tcp_bridge: failed to connect to local server {}: {}",
                            NAME, local_addr, e
                        );
                    }
                    Ok(Ok(mut local)) => {
                        debug!(
                            "{} tcp_bridge: local side connected: ({})",
                            NAME, local_addr
                        );
                        info!("{} Connected to companion app TCP server ({}), starting bidirectional transfer...", NAME, local_addr);
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                debug!("{} tcp_bridge: cancelled during transfer ({})", NAME, remote_addr);
                                return;
                            }
                            res = copy_bidirectional(&mut remote, &mut local) => {
                                match res {
                                    Ok((from_remote, from_local)) => {
                                        debug!(
                                            "{} tcp_bridge: Connection closed: remote->local={} local->remote={}",
                                            NAME, from_remote, from_local
                                        );
                                    }
                                    Err(e) => {
                                        error!("{} Error during bidirectional copy: {}", NAME, e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Wait before retry, but bail immediately if cancelled
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("{} tcp_bridge: cancelled during retry wait ({})", NAME, remote_addr);
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

pub async fn media_tap_reverse_bridge_once(
    android_ip: IpAddr,
    endpoint: MediaTapEndpointInfo,
) -> io::Result<()> {
    let remote_addr = format!("{}:{}", android_ip, endpoint.port);
    let local_addr = format!("127.0.0.1:{}", endpoint.local_port);

    info!(
        "{} starting on-demand media reverse bridge {} ({}) remote={} local={}",
        NAME, endpoint.label, endpoint.endpoint_id, remote_addr, local_addr
    );

    let mut remote = match timeout(
        Duration::from_secs(3),
        TokioTcpStream::connect(&remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!(
                "{} media reverse bridge failed to connect remote {}: {}",
                NAME, remote_addr, e
            );
            return Err(e);
        }
        Err(e) => {
            let err = io::Error::new(
                io::ErrorKind::TimedOut,
                format!("media reverse bridge timeout connecting remote {remote_addr}: {e}"),
            );
            error!("{} {}", NAME, err);
            return Err(err);
        }
    };

    let mut local =
        match timeout(Duration::from_secs(3), TokioTcpStream::connect(&local_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!(
                    "{} media reverse bridge failed to connect local {}: {}",
                    NAME, local_addr, e
                );
                return Err(e);
            }
            Err(e) => {
                let err = io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("media reverse bridge timeout connecting local {local_addr}: {e}"),
                );
                error!("{} {}", NAME, err);
                return Err(err);
            }
        };

    info!(
        "{} on-demand media reverse bridge connected {} ({}), starting transfer",
        NAME, endpoint.label, endpoint.endpoint_id
    );

    match copy_bidirectional(&mut remote, &mut local).await {
        Ok((from_remote, from_local)) => {
            info!(
                "{} media reverse bridge closed {} ({}): remote->local={} local->remote={}",
                NAME, endpoint.label, endpoint.endpoint_id, from_remote, from_local
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "{} media reverse bridge transfer error {} ({}): {}",
                NAME, endpoint.label, endpoint.endpoint_id, e
            );
            Err(e)
        }
    }
}

/// Async lookup MAC from IPv4 using /proc/net/arp
pub async fn mac_from_ipv4(addr: SocketAddr) -> io::Result<Option<MacAddress>> {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(None),
    };

    let file = TokioFile::open("/proc/net/arp").await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    // Skip header
    lines.next_line().await?;

    while let Some(line) = lines.next_line().await? {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == ip.to_string() {
            if let Ok(mac) = cols[3].parse::<MacAddress>() {
                return Ok(Some(mac));
            }
        }
    }

    Ok(None)
}

/// Asynchronously wait for an inbound TCP connection
/// returning TcpStream of first client connected
async fn tcp_wait_for_connection(
    listener: &mut TcpListener,
    start_companion_bridges: bool,
    _media_tap_endpoints: SharedMediaTapEndpoints,
    companion_ip: SharedCompanionIp,
) -> Result<(TcpStream, SocketAddr, CancellationToken)> {
    let retval = listener.accept();
    let (stream, addr) = match timeout(TCP_CLIENT_TIMEOUT, retval)
        .await
        .map_err(|e| std::io::Error::other(e))
    {
        Ok(Ok((stream, addr))) => (stream, addr),
        Err(e) | Ok(Err(e)) => {
            error!("{} 📵 TCP server: {}, restarting...", NAME, e);
            return Err(Box::new(e));
        }
    };
    info!(
        "{} 📳 TCP server: new client connected: <b>{:?}</b>",
        NAME, addr
    );

    // One CancellationToken per session — cancelled when the session ends,
    // which stops all tcp_bridge tasks spawned for this client.
    let cancel = CancellationToken::new();

    // this is creating a reverse tcp bridge for Android.
    // Direct connection to the device side is not allowed. It is only meaningful
    // for MD/phone connections; DHU emulator clients must not start these bridges.
    if start_companion_bridges {
        if !addr.ip().is_loopback() {
            *companion_ip.write().await = Some(addr.ip());
            let c = cancel.clone();
            tokio::spawn(async move {
                info!(
                    "{} starting TCP reverse connection, Android IP: {}",
                    NAME,
                    addr.ip()
                );
                // FIXME use port configured by user for webserver
                // or ignore when webserver disabled...
                tcp_bridge(
                    &format!("{}:{}", addr.ip(), COMP_APP_TCP_PORT),
                    "127.0.0.1:80",
                    c,
                )
                .await;
            });
        } else {
            debug!(
                "{} skipping reverse tcp_bridge for localhost MD client ({})",
                NAME, addr
            );
        }

        let c = cancel.clone();
        tokio::spawn(async move {
            info!(
                "{} starting TCP reverse connection for WS, Android IP: {}",
                NAME,
                addr.ip()
            );
            // FIXME use port configured by user for webserver
            // or ignore when webserver disabled...
            tcp_bridge(
                &format!("{}:{}", addr.ip(), COMP_APP_TCP_PORT_WS),
                "127.0.0.1:80",
                c,
            )
            .await;
        });

        let c = cancel.clone();
        tokio::spawn(async move {
            info!(
                "{} starting TCP reverse connection for SWUpdate, Android IP: {}",
                NAME,
                addr.ip()
            );
            // FIXME use port configured by user for webserver
            // or ignore when webserver disabled...
            tcp_bridge(
                &format!("{}:{}", addr.ip(), COMP_APP_TCP_PORT_SWUPDATE),
                "127.0.0.1:8080",
                c,
            )
            .await;
        });

        debug!(
            "{} media reverse bridges are opened on demand through /media-taps/:endpoint_id/open",
            NAME
        );
    } else {
        debug!(
            "{} skipping companion reverse tcp_bridge for non-MD client ({})",
            NAME, addr
        );
    }

    // disable Nagle algorithm, so segments are always sent as soon as possible,
    // even if there is only a small amount of data
    stream.set_nodelay(true)?;

    Ok((stream, addr, cancel))
}

/// Connects to Android Auto Head Unit Server directly on the MD/phone side.
/// This is used only when `aa_server_tcp_addr` is set. It intentionally does
/// not start the companion reverse TCP bridges, because there is no inbound
/// phone client address in this mode.
async fn tcp_connect_to_aa_server(addr: &str) -> Result<TcpStream> {
    let addr = addr.trim();
    let socket_addr: SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid aa_server_tcp_addr {addr:?}: {e}"),
        )
    })?;

    info!(
        "{} 🛰️ MD direct TCP: connecting to Android Auto Head Unit Server at <u>{}</u>...",
        NAME, socket_addr
    );

    let stream = match timeout(TCP_CLIENT_TIMEOUT, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!(
                "{} 📵 MD direct TCP: connect failed to <u>{}</u>: {}",
                NAME, socket_addr, e
            );
            return Err(Box::new(e));
        }
        Err(e) => {
            let err = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("MD direct TCP connect timeout to {socket_addr}: {e}"),
            );
            error!("{} 📵 {}", NAME, err);
            return Err(Box::new(err));
        }
    };

    stream.set_nodelay(true)?;
    info!(
        "{} 📳 MD direct TCP: connected to Android Auto Head Unit Server at <u>{}</u>",
        NAME, socket_addr
    );

    Ok(stream)
}

pub async fn io_loop(
    need_restart: BroadcastSender<Option<Action>>,
    tcp_start: Arc<Notify>,
    config: SharedConfig,
    tx: Arc<Mutex<Option<Sender<Packet>>>>,
    sensor_channel: Arc<Mutex<Option<u8>>>,
    input_channel: Arc<Mutex<Option<u8>>>,
    last_battery: Arc<RwLock<Option<BatteryData>>>,
    last_speed: Arc<RwLock<Option<i32>>>,
    last_service_discovery_response: SharedServiceDiscoveryResponse,
    media_tap_endpoints: SharedMediaTapEndpoints,
    companion_ip: SharedCompanionIp,
    usb_connected: Arc<AtomicBool>,
    script_registry: Option<Arc<ScriptRegistry>>,
    ws_event_tx: BroadcastSender<ServerEvent>,
) -> Result<()> {
    let shared_config = config.clone();
    #[allow(unused_variables)]
    let (client_handler, ev_tx) = spawn_ev_client_task().await;

    // prepare/bind needed TCP listeners
    info!("{} 🛰️ Starting TCP server for MD...", NAME);
    let bind_addr = format!("0.0.0.0:{}", TCP_SERVER_PORT).parse().unwrap();
    let mut md_listener = Some(TcpListener::bind(bind_addr).unwrap());
    info!("{} 🛰️ MD TCP server bound to: <u>{}</u>", NAME, bind_addr);
    info!("{} 🛰️ Starting TCP server for DHU...", NAME);
    let bind_addr = format!("0.0.0.0:{}", TCP_DHU_PORT).parse().unwrap();
    let mut dhu_listener = Some(TcpListener::bind(bind_addr).unwrap());
    info!("{} 🛰️ DHU TCP server bound to: <u>{}</u>", NAME, bind_addr);

    // Shared media tap sink registry. Static tap listeners are opened immediately
    // when media_dump_base_port is configured, then SDR processing binds channels
    // to the fixed offsets as sinks become available.
    let media_tap_startup_config = config.read().await.clone();
    if media_tap_startup_config.media_dump_base_port.is_some() && !media_tap_startup_config.mitm {
        error!("<red>media_dump_base_port is set but mitm = false — media tap disabled!</>");
    }
    let persistent_media_sinks: SharedMediaSinks = Arc::new(Mutex::new(HashMap::new()));
    let startup_media_base_port = if media_tap_startup_config.mitm {
        media_tap_startup_config.media_dump_base_port
    } else {
        None
    };
    let startup_aux_tap_slots = static_media_tap_aux_slot_count(&media_tap_startup_config);
    ensure_static_media_tap_listeners(
        persistent_media_sinks.clone(),
        startup_media_base_port,
        media_tap_startup_config.media_wait_for_live_idr,
        startup_aux_tap_slots,
    )
    .await;
    let persistent_media_channels: SharedMediaChannels = Arc::new(Mutex::new(HashMap::new()));

    loop {
        // reload new config
        let config = config.read().await.clone();

        // generate Durations from configured seconds
        let stats_interval = {
            if config.stats_interval == 0 {
                None
            } else {
                Some(Duration::from_secs(config.stats_interval.into()))
            }
        };
        let read_timeout = Duration::from_secs(config.timeout_secs.into());

        let mut client_mac: Option<MacAddress> = None;
        let mut md_tcp = None;
        let mut md_usb = None;
        let mut hu_tcp = None;
        let mut hu_usb = None;
        let mut usb_used = false;
        // CancellationToken for tcp_bridge tasks spawned for this session
        let mut bridge_cancel: Option<CancellationToken> = None;

        let aa_server_tcp_addr = config.aa_server_tcp_addr.trim().to_string();
        let aa_server_tcp_enabled = !aa_server_tcp_addr.is_empty();

        if aa_server_tcp_enabled {
            // Direct Android Auto Head Unit Server mode replaces the MD/phone-side
            // USB/Bluetooth/Wi-Fi transport only. Do not connect yet: open the
            // HU/DHU side first, then create a fresh MD TCP connection immediately
            // before starting the proxy so DHU's first version frame is not sent
            // over a stale idle socket.
            info!(
                "{} 🛰️ MD direct TCP mode enabled, delaying MD connect until HU/DHU is ready: <u>{}</u>",
                NAME, aa_server_tcp_addr
            );
            usb_connected.store(false, Ordering::Relaxed);
        } else if config.wired.is_some() {
            info!("{} 💤 waiting for USB or bluetooth handshake...", NAME);

            let wired_clone = config.wired.clone();
            let usb_future = async move {
                loop {
                    if let Ok(s) = usb_stream::new(wired_clone.clone()).await {
                        return s;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };

            tokio::select! {
                usb_res = usb_future => {
                    info!("{} 🔌 USB device connected, disabling wireless...", NAME);
                    usb_connected.store(true, Ordering::Relaxed);
                    usb_used = true;
                    md_usb = Some(usb_res);
                }
                _ = tcp_start.notified() => {
                    info!("{} 🛰️ MD TCP server: listening for phone connection...", NAME);
                    if let Ok((s, ip, cancel)) = tcp_wait_for_connection(
                            &mut md_listener.as_mut().unwrap(),
                            true,
                            media_tap_endpoints.clone(),
                            companion_ip.clone(),
                        )
                        .await {
                        md_tcp = Some(s);
                        client_mac = mac_from_ipv4(ip).await.unwrap_or(None);
                        bridge_cancel = Some(cancel);
                    } else {
                        let _ = need_restart.send(None);
                        continue;
                    }
                }
            }
        } else {
            info!("{} 💤 waiting for bluetooth handshake...", NAME);
            tcp_start.notified().await;

            info!(
                "{} 🛰️ MD TCP server: listening for phone connection...",
                NAME
            );
            if let Ok((s, ip, cancel)) = tcp_wait_for_connection(
                &mut md_listener.as_mut().unwrap(),
                true,
                media_tap_endpoints.clone(),
                companion_ip.clone(),
            )
            .await
            {
                md_tcp = Some(s);
                // Get MAC address of the connected client for later disassociation
                client_mac = mac_from_ipv4(ip).await.unwrap_or(None);
                usb_connected.store(false, Ordering::Relaxed);
                bridge_cancel = Some(cancel);
            } else {
                // notify main loop to restart
                let _ = need_restart.send(None);
                continue;
            }
        }

        if config.dhu {
            info!(
                "{} 🛰️ DHU TCP server: listening for `Desktop Head Unit` connection...",
                NAME
            );
            if let Ok((s, _, _)) = tcp_wait_for_connection(
                &mut dhu_listener.as_mut().unwrap(),
                false,
                media_tap_endpoints.clone(),
                companion_ip.clone(),
            )
            .await
            {
                hu_tcp = Some(s);
            } else {
                // notify main loop to restart
                let _ = need_restart.send(None);
                continue;
            }
        } else {
            info!(
                "{} 📂 Opening USB accessory device: <u>{}</u>",
                NAME, USB_ACCESSORY_PATH
            );
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(USB_ACCESSORY_PATH)
                .await
            {
                Ok(s) => hu_usb = Some(s),
                Err(e) => {
                    error!("{} 🔴 Error opening USB accessory: {}", NAME, e);
                    // notify main loop to restart
                    let _ = need_restart.send(None);
                    continue;
                }
            }
        }

        if aa_server_tcp_enabled {
            match tcp_connect_to_aa_server(&aa_server_tcp_addr).await {
                Ok(s) => {
                    if let Ok(socket_addr) = aa_server_tcp_addr.parse::<SocketAddr>() {
                        *companion_ip.write().await = Some(socket_addr.ip());
                    }
                    md_tcp = Some(s);
                }
                Err(e) => {
                    error!(
                        "{} 🔴 MD direct TCP unavailable after HU/DHU became ready: {}",
                        NAME, e
                    );
                    let _ = need_restart.send(None);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        }

        info!("{} ♾️ Starting to proxy data between HU and MD...", NAME);
        let started = Instant::now();

        // `read` and `write` take owned buffers (more on that later), and
        // there's no "per-socket" buffer, so they actually take `&self`.
        // which means we don't need to split them into a read half and a
        // write half like we'd normally do with "regular tokio". Instead,
        // we can send a reference-counted version of it. also, since a
        // tokio-uring runtime is single-threaded, we can use `Rc` instead of
        // `Arc`.
        let file_bytes = Arc::new(AtomicUsize::new(0));
        let stream_bytes = Arc::new(AtomicUsize::new(0));

        let mut from_file;
        let mut from_stream;
        let mut reader_hu;
        let mut reader_md;
        // these will be used for cleanup
        let mut md_tcp_stream = None;
        let mut hu_tcp_stream = None;

        // MITM/proxy mpsc channels:
        // Keep enough in-flight capacity so reader tasks do not stall under bursty
        // media traffic and starve control-channel forwarding.
        let (tx_hu, rx_md): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(MITM_QUEUE_CAPACITY);
        let (tx_md, rx_hu): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(MITM_QUEUE_CAPACITY);
        let (txr_hu, rxr_md): (Sender<Packet>, Receiver<Packet>) =
            mpsc::channel(MITM_QUEUE_CAPACITY);
        let (txr_md, rxr_hu): (Sender<Packet>, Receiver<Packet>) =
            mpsc::channel(MITM_QUEUE_CAPACITY);

        // selecting I/O device for reading and writing
        // and creating desired objects for proxy functions
        let hu_r;
        let md_r;
        let hu_w;
        let md_w;
        let mut usb_dev = None;
        // MD transfer device
        if let Some(md) = md_usb {
            // MD over wired USB
            let (dev, usb_r, usb_w) = md;
            usb_dev = Some(dev);
            let usb_r = Rc::new(RefCell::new(usb_r));
            let usb_w = Rc::new(RefCell::new(usb_w));
            md_r = IoDevice::UsbReader(usb_r, PhantomData::<TcpStream>);
            md_w = IoDevice::UsbWriter(usb_w, PhantomData::<TcpStream>);
        } else {
            // MD using TCP stream (wireless)
            let md = Rc::new(md_tcp.unwrap());
            md_r = IoDevice::EndpointIo(md.clone());
            md_w = IoDevice::EndpointIo(md.clone());
            md_tcp_stream = Some(md.clone());
        }
        // HU transfer device
        if let Some(hu) = hu_usb {
            // HU connected directly via USB
            let hu = Rc::new(hu);
            hu_r = IoDevice::EndpointIo(hu.clone());
            hu_w = IoDevice::EndpointIo(hu.clone());
        } else {
            // Head Unit Emulator via TCP
            let hu = Rc::new(hu_tcp.unwrap());
            hu_r = IoDevice::TcpStreamIo(hu.clone());
            hu_w = IoDevice::TcpStreamIo(hu.clone());
            hu_tcp_stream = Some(hu.clone());
        }

        // handling battery in JSON
        if config.mitm && config.ev {
            let mut tx_lock = tx.lock().await;
            *tx_lock = Some(tx_hu.clone());
        }

        // dedicated reading threads:
        reader_hu = tokio_uring::spawn(endpoint_reader(hu_r, txr_hu, true));
        reader_md = tokio_uring::spawn(endpoint_reader(md_r, txr_md, false));
        // main processing threads:
        from_file = tokio_uring::spawn(proxy(
            ProxyType::HeadUnit,
            hu_w,
            file_bytes.clone(),
            tx_hu.clone(),
            rx_hu,
            rxr_md,
            shared_config.clone(),
            sensor_channel.clone(),
            input_channel.clone(),
            last_battery.clone(),
            last_speed.clone(),
            last_service_discovery_response.clone(),
            ev_tx.clone(),
            Some(tx_hu.clone()),
            script_registry.clone(),
            persistent_media_sinks.clone(),
            persistent_media_channels.clone(),
            media_tap_endpoints.clone(),
            ws_event_tx.clone(),
        ));
        from_stream = tokio_uring::spawn(proxy(
            ProxyType::MobileDevice,
            md_w,
            stream_bytes.clone(),
            tx_md.clone(),
            rx_md,
            rxr_hu,
            shared_config.clone(),
            sensor_channel.clone(),
            input_channel.clone(),
            last_battery.clone(),
            last_speed.clone(),
            last_service_discovery_response.clone(),
            ev_tx.clone(),
            Some(tx_md.clone()),
            script_registry.clone(),
            persistent_media_sinks.clone(),
            persistent_media_channels.clone(),
            media_tap_endpoints.clone(),
            ws_event_tx.clone(),
        ));

        // Thread for monitoring transfer
        let mut monitor = tokio::spawn(transfer_monitor(
            stats_interval,
            file_bytes,
            stream_bytes,
            read_timeout,
            shared_config.clone(),
        ));

        // Background task to interrupt wireless session if USB is plugged in
        let wired_clone = config.wired.clone();
        let mut usb_monitor = tokio::spawn(async move {
            if let Some(wired) = wired_clone {
                if !usb_used {
                    loop {
                        if usb_stream::is_present(&Some(wired.clone())) {
                            return Err("USB device detected during wireless session".into());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            let pending: std::future::Pending<Result<()>> = std::future::pending();
            pending.await
        });

        // Stop as soon as one of them errors
        let res = tokio::try_join!(
            flatten(&mut reader_hu),
            flatten(&mut reader_md),
            flatten(&mut from_file),
            flatten(&mut from_stream),
            flatten(&mut monitor),
            flatten(&mut usb_monitor)
        );
        if let Err(e) = res {
            error!("{} 🔴 Connection error: {}", NAME, e);
            if let Some(dev) = usb_dev {
                info!("{} 🔌 Resetting USB device for next try...", NAME);
                let _ = dev.reset().await;
            }
        }

        // Cancel all tcp_bridge tasks spawned for this session before cleanup
        if let Some(cancel) = bridge_cancel.take() {
            cancel.cancel();
        }
        media_tap_endpoints.write().await.clear();

        // Make sure the reference count drops to zero and the socket is
        // freed by aborting both tasks (which both hold a `Rc<TcpStream>`
        // for each direction)
        reader_hu.abort();
        reader_md.abort();
        from_file.abort();
        from_stream.abort();
        monitor.abort();
        usb_monitor.abort();

        // make sure TCP connections are closed before next connection attempts
        if let Some(stream) = md_tcp_stream {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        if let Some(stream) = hu_tcp_stream {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }

        // Disassociate a client from the WiFi AP.
        // Mainly needed when a button was used to switch to the next device,
        // or when the stop_on_disconnect option was used.
        // Otherwise, the WiFi/AA connection remains hanging and the phone
        // won't switch back to the regular WiFi.
        if let Some(mac) = client_mac {
            info!("{} disassociating WiFi client: {}", NAME, mac);

            let _ = Command::new("/usr/bin/hostapd_cli")
                .args(&["disassociate", &mac.to_string()])
                .spawn();
        }

        // set webserver context EV stuff to None
        let mut tx_lock = tx.lock().await;
        *tx_lock = None;
        let mut sc_lock = sensor_channel.lock().await;
        *sc_lock = None;
        let mut ic_lock = input_channel.lock().await;
        *ic_lock = None;
        // stop EV battery logger if neded
        if config.ev_battery_logger.is_some() {
            ev_tx.send(EvTaskCommand::Stop).await?;
        }

        info!(
            "{} ⌛ session time: {}",
            NAME,
            format_duration(started.elapsed()).to_string()
        );
        // obtain action for passing it to broadcast sender
        let action = shared_config.read().await.action_requested.clone();
        // stream(s) closed, notify main loop to restart
        let _ = need_restart.send(action);

        // Reset usb_connected so main loop can resume wireless broadcasting
        usb_connected.store(false, Ordering::Relaxed);
    }

    #[allow(unreachable_code)]
    // terminate ev client handler
    ev_tx.send(EvTaskCommand::Terminate).await?;
    client_handler.await?;
}
