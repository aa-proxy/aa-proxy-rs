use bytesize::ByteSize;
use core::net::SocketAddr;
use humantime::format_duration;
use mac_address::MacAddress;
use simplelog::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File as TokioFile;
use tokio::io::{self, copy_bidirectional, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::process::Command;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, Notify};
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

// module name for logging engine
const NAME: &str = "<i><bright-black> proxy: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const USB_ACCESSORY_PATH: &str = "/dev/usb_accessory";
// 16 KB per URB — matches the Android Open Accessory protocol maximum bulk-transfer size.
pub const BUFFER_LEN: usize = 16 * 1024;
const TCP_CLIENT_TIMEOUT: Duration = Duration::new(30, 0);
const COMP_APP_TCP_PORT: u16 = 9999;
const ACCESSORY_PENDING_OPS: usize = 1;

const TCP_BUFFER_SIZE: usize = 32 * 1024; // 32 KB
                                          // Keep only a small number of fully parsed AA packets buffered between tasks.
                                          // A slow HU should stall the phone-side reader quickly so TCP backpressure can
                                          // reach Android and trigger bitrate/resolution adaptation.
const READER_QUEUE_DEPTH: usize = 4;

use crate::config::{Action, SharedConfig};
use crate::config::{TCP_DHU_PORT, TCP_SERVER_PORT};
use crate::ev::spawn_ev_client_task;
use crate::ev::EvTaskCommand;
use crate::iperf3;
use crate::mitm::endpoint_reader;
use crate::mitm::proxy;
use crate::mitm::Packet;
use crate::mitm::ProxyType;
use crate::usb_stream;
use crate::usb_stream::{
    UsbReadCounters, UsbStreamRead, UsbStreamWrite, UsbWriteCounters, MAX_PENDING_WRITES,
    MIN_PENDING_READS,
};

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
    AccessoryIo(
        Rc<File>,
        Option<Arc<UsbReadCounters>>,
        Option<Arc<UsbWriteCounters>>,
    ),
    EndpointIo(Rc<A>),
    TcpStreamIo(Rc<TcpStream>),
}

/// Set SO_RCVBUF / SO_SNDBUF on any socket via its raw file descriptor.
/// Works for both `tokio::net::TcpStream` and `tokio_uring::net::TcpStream`
/// because both implement `AsRawFd`.
pub fn apply_tcp_buffer_sizes(fd: std::os::unix::io::RawFd) {
    use libc::{setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
    let buf_size = TCP_BUFFER_SIZE as libc::c_int;
    unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn format_usb_buffer_stats(
    usb_read_counters: Option<&Arc<UsbReadCounters>>,
    usb_write_counters: Option<&Arc<UsbWriteCounters>>,
    max_pending_reads: usize,
    max_pending_writes: usize,
    usb_backend_label: Option<&str>,
) -> String {
    match (usb_read_counters, usb_write_counters) {
        (Some(r), Some(w)) => {
            let pending_r = r.pending_reads.load(Ordering::Relaxed);
            let cached = r.cached_bytes.load(Ordering::Relaxed);
            let pending_w = w.pending_writes.load(Ordering::Relaxed);
            let queued = w.buffered_bytes.load(Ordering::Relaxed);
            let total = cached.saturating_add(queued);
            let backend = usb_backend_label.unwrap_or("unknown");
            format!(
                " | USB[{}] buf:{} (cached:{} queued:{}) urb_r:{}/{} urb_w:{}/{}",
                backend,
                ByteSize::b(total as u64).to_string_as(true),
                ByteSize::b(cached as u64).to_string_as(true),
                ByteSize::b(queued as u64).to_string_as(true),
                pending_r,
                max_pending_reads,
                pending_w,
                max_pending_writes,
            )
        }
        _ => String::new(),
    }
}

async fn transfer_monitor(
    stats_interval: Option<Duration>,
    usb_bytes_written: Arc<AtomicUsize>,
    tcp_bytes_written: Arc<AtomicUsize>,
    read_timeout: Duration,
    config: SharedConfig,
    monitor_channels: Option<[Sender<Packet>; 4]>,
    usb_read_counters: Option<Arc<UsbReadCounters>>,
    usb_write_counters: Option<Arc<UsbWriteCounters>>,
    usb_read_capacity: usize,
    usb_write_capacity: usize,
    usb_backend_label: Option<&'static str>,
) -> Result<()> {
    let mut usb_bytes_out_last: usize = 0;
    let mut tcp_bytes_out_last: usize = 0;
    let mut stall_usb_bytes_last: usize = 0;
    let mut stall_tcp_bytes_last: usize = 0;
    // Skip the very first stall check: data cannot have flowed yet during the
    // SSL handshake phase, so the initial interval would always be a false positive.
    let mut stall_first_check = true;
    let mut report_time = Instant::now();
    let mut stall_check = Instant::now();

    if let Some(interval) = stats_interval {
        info!(
            "{} ⚙️ Showing transfer statistics: <b><blue>{}</>",
            NAME,
            format_duration(interval),
        );
    }

    loop {
        let should_report = stats_interval
            .map(|interval| report_time.elapsed() > interval)
            .unwrap_or(false);
        let should_check_stall = stall_check.elapsed() > read_timeout;

        if should_report || should_check_stall {
            // load current total transfer from AtomicUsize only when the counters
            // are needed for reporting or stall detection.
            let usb_bytes_out = usb_bytes_written.load(Ordering::Relaxed);
            let tcp_bytes_out = tcp_bytes_written.load(Ordering::Relaxed);

            // Stats printing
            if should_report {
                let elapsed_secs = report_time.elapsed().as_secs_f64();

                // compute USB transfer — use a separate delta variable so
                // `usb_bytes_out_last` keeps its "total at last report" semantics.
                let usb_delta = usb_bytes_out - usb_bytes_out_last;
                let usb_transferred_total = ByteSize::b(usb_bytes_out.try_into().unwrap());
                let usb_transferred_last = ByteSize::b(usb_delta.try_into().unwrap());
                let usb_speed: u64 = (usb_delta as f64 / elapsed_secs).round() as u64;
                let usb_speed = ByteSize::b(usb_speed);

                // compute TCP transfer
                let tcp_delta = tcp_bytes_out - tcp_bytes_out_last;
                let tcp_transferred_total = ByteSize::b(tcp_bytes_out.try_into().unwrap());
                let tcp_transferred_last = ByteSize::b(tcp_delta.try_into().unwrap());
                let tcp_speed: u64 = (tcp_delta as f64 / elapsed_secs).round() as u64;
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

                // Channel queue depths: items currently queued = max_capacity - capacity.
                let ch_depths = monitor_channels
                    .as_ref()
                    .map(|channels| {
                        let ch_names = ["txr_hu", "txr_md", "tx_hu", "tx_md"];
                        channels
                            .iter()
                            .zip(ch_names.iter())
                            .map(|(s, name)| {
                                let depth = s.max_capacity() - s.capacity();
                                format!("{}:{}/{}", name, depth, s.max_capacity())
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // USB counters come from the wired phone path when active; otherwise
                // they reflect the wireless session's USB accessory operations.
                let usb_info = format_usb_buffer_stats(
                    usb_read_counters.as_ref(),
                    usb_write_counters.as_ref(),
                    usb_read_capacity,
                    usb_write_capacity,
                    usb_backend_label,
                );

                info!("{} queues: {}{}", NAME, ch_depths.join("  "), usb_info);

                // save values for next iteration
                report_time = Instant::now();
                usb_bytes_out_last = usb_bytes_out;
                tcp_bytes_out_last = tcp_bytes_out;
            }

            // transfer stall detection
            if should_check_stall {
                // compute delta since last check using dedicated variables so the
                // `stall_*_last` accumulators keep their "total at last check" semantics.
                let usb_stall_delta = usb_bytes_out - stall_usb_bytes_last;
                let tcp_stall_delta = tcp_bytes_out - stall_tcp_bytes_last;

                // The first interval covers the SSL handshake phase where the MITM
                // proxy byte counters are not yet incremented — skip it to avoid a
                // false-positive stall error before real data starts flowing.
                if stall_first_check {
                    stall_first_check = false;
                } else if usb_stall_delta == 0 || tcp_stall_delta == 0 {
                    return Err("unexpected transfer stall".into());
                }

                // save values for next iteration
                stall_check = Instant::now();
                stall_usb_bytes_last = usb_bytes_out;
                stall_tcp_bytes_last = tcp_bytes_out;
            }
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
        // Preserve panic/cancellation details so they appear in logs.
        Err(e) => Err(format!("task panicked or was cancelled: {e}").into()),
    }
}

async fn tcp_bridge(remote_addr: &str, local_addr: &str) {
    loop {
        debug!(
            "{} tcp_bridge: before connect, local={} remote={}",
            NAME, local_addr, remote_addr
        );
        match TokioTcpStream::connect(remote_addr).await {
            Ok(mut remote) => {
                debug!(
                    "{} tcp_bridge: remote side connected: ({})",
                    NAME, remote_addr
                );
                match TokioTcpStream::connect(local_addr).await {
                    Ok(mut local) => {
                        debug!(
                            "{} tcp_bridge: local side connected: ({})",
                            NAME, local_addr
                        );
                        info!("{} Connected to companion app TCP server ({}), starting bidirectional transfer...", NAME, local_addr);
                        match copy_bidirectional(&mut remote, &mut local).await {
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
                    Err(e) => {
                        debug!(
                            "{} tcp_bridge: Failed to connect to local server {}: {}",
                            NAME, local_addr, e
                        );
                    }
                }
            }
            Err(e) => {
                debug!(
                    "{} tcp_bridge: Failed to connect to remote server {}: {}",
                    NAME, remote_addr, e
                );
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
async fn tcp_wait_for_connection(listener: &mut TcpListener) -> Result<(TcpStream, SocketAddr)> {
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

    // Disable Nagle's algorithm for
    // high-throughput Android Auto video streaming.
    use std::os::unix::io::AsRawFd;
    stream.set_nodelay(true)?;
    apply_tcp_buffer_sizes(stream.as_raw_fd());

    Ok((stream, addr))
}

pub async fn io_loop(
    need_restart: BroadcastSender<Option<Action>>,
    tcp_start: Arc<Notify>,
    config: SharedConfig,
    tx: Arc<Mutex<Option<Sender<Packet>>>>,
    sensor_channel: Arc<Mutex<Option<u8>>>,
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

    if let Some(ref bindaddr) = shared_config.read().await.iperf3_server {
        match bindaddr.parse::<SocketAddr>() {
            Ok(addr) => {
                tokio_uring::spawn(async move {
                    if let Err(e) = iperf3::run_server(addr).await {
                        error!("{} iperf3 server error: {}", NAME, e);
                    }
                });

                info!("{} iperf3 server listening on {}", NAME, addr);
            }
            Err(e) => {
                error!("{} iperf3 server address/port parse: {}", NAME, e);
            }
        }
    }

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
        let stats_enabled = stats_interval.is_some();
        let read_timeout = Duration::from_secs(config.timeout_secs.into());

        // Extract the local webserver port from the bind address string (e.g. "0.0.0.0:80").
        // Used to forward companion-app connections to the correct local port.
        let webserver_port: u16 = config
            .webserver
            .as_ref()
            .and_then(|addr| addr.rsplit(':').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);

        let mut client_mac: Option<MacAddress> = None;
        let mut md_tcp = None;
        let mut md_usb = None;
        let mut hu_tcp = None;
        let mut hu_usb = None;
        // JoinHandle for the companion-app TCP reverse bridge task (wireless only).
        // Stored so it can be aborted and awaited during session cleanup.
        let mut bridge_handle: Option<tokio::task::JoinHandle<()>> = None;
        if config.wired.is_some() {
            info!(
                "{} 💤 trying to enable Android Auto mode on USB port...",
                NAME
            );
            match usb_stream::new(config.wired.clone(), stats_enabled).await {
                Err(e) => {
                    error!("{} 🔴 Enabling Android Auto: {}", NAME, e);
                    // notify main loop to restart
                    let _ = need_restart.send(None);
                    continue;
                }
                Ok(s) => {
                    md_usb = Some(s);
                }
            }
        } else {
            info!("{} 💤 waiting for bluetooth handshake...", NAME);
            tcp_start.notified().await;

            info!(
                "{} 🛰️ MD TCP server: listening for phone connection...",
                NAME
            );
            if let Ok((s, ip)) = tcp_wait_for_connection(&mut md_listener.as_mut().unwrap()).await {
                md_tcp = Some(s);
                // Get MAC address of the connected client for later disassociation
                client_mac = mac_from_ipv4(ip).await.unwrap_or(None);
                // Spawn companion-app TCP bridge only when webserver is enabled.
                // Use the configured webserver port rather than a hardcoded 80.
                if config.webserver.is_some() {
                    let comp_addr = format!("{}:{}", ip.ip(), COMP_APP_TCP_PORT);
                    let local_addr = format!("127.0.0.1:{}", webserver_port);
                    bridge_handle = Some(tokio::spawn(async move {
                        info!(
                            "{} starting TCP reverse connection, Android IP: {}",
                            NAME,
                            ip.ip()
                        );
                        tcp_bridge(&comp_addr, &local_addr).await;
                    }));
                }
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
            if let Ok((s, _)) = tcp_wait_for_connection(&mut dhu_listener.as_mut().unwrap()).await {
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
        // tx_hu/tx_md are bounded to apply end-to-end backpressure.
        // Passthrough mode avoids mutual-send deadlock by holding at most one
        // locally pending forward packet per proxy while waiting on tx.reserve().
        let (tx_hu, rx_md): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(READER_QUEUE_DEPTH);
        let (tx_md, rx_hu): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(READER_QUEUE_DEPTH);
        let (txr_hu, rxr_md): (Sender<Packet>, Receiver<Packet>) =
            mpsc::channel(READER_QUEUE_DEPTH);
        let (txr_md, rxr_hu): (Sender<Packet>, Receiver<Packet>) =
            mpsc::channel(READER_QUEUE_DEPTH);

        // Clone senders now, before they are moved into tasks, only when transfer
        // stats are enabled so queue-depth sampling stays completely disabled
        // otherwise.
        let monitor_channels =
            stats_enabled.then(|| [txr_hu.clone(), txr_md.clone(), tx_hu.clone(), tx_md.clone()]);

        // selecting I/O device for reading and writing
        // and creating desired objects for proxy functions
        let hu_r: IoDevice<File>;
        let md_r;
        let hu_w: IoDevice<File>;
        let md_w;
        let mut usb_dev = None;
        // USB perf counters — sourced from the wired phone path when active,
        // otherwise from the wireless session's USB accessory file path.
        let mut monitor_usb_read_counters: Option<Arc<UsbReadCounters>> = None;
        let mut monitor_usb_write_counters: Option<Arc<UsbWriteCounters>> = None;
        let mut monitor_usb_read_capacity = 0;
        let mut monitor_usb_write_capacity = 0;
        let mut monitor_usb_backend_label: Option<&'static str> = None;
        // MD transfer device
        if let Some(md) = md_usb {
            // MD over wired USB
            let (dev, usb_r, usb_w) = md;
            usb_dev = Some(dev);
            if stats_enabled {
                // Clone counter Arcs before the streams are moved into Rc<RefCell<>>.
                // These Arcs are Send; the Rc wrappers are not — so the monitor gets
                // the clones while the IO tasks keep the originals inside their Rc.
                monitor_usb_read_counters = usb_r.counters.clone();
                monitor_usb_write_counters = usb_w.counters.clone();
                monitor_usb_read_capacity = MIN_PENDING_READS;
                monitor_usb_write_capacity = MAX_PENDING_WRITES;
                monitor_usb_backend_label = Some("MD wired USB stream");
            }
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
        let hu_usb_active = hu_usb.is_some();
        // HU transfer device
        if let Some(hu) = hu_usb {
            // HU connected directly via USB
            let hu = Rc::new(hu);
            let accessory_read_counters = stats_enabled.then(|| {
                Arc::new(UsbReadCounters {
                    pending_reads: Arc::new(AtomicUsize::new(0)),
                    cached_bytes: Arc::new(AtomicUsize::new(0)),
                })
            });
            let accessory_write_counters = stats_enabled.then(|| {
                Arc::new(UsbWriteCounters {
                    pending_writes: Arc::new(AtomicUsize::new(0)),
                    buffered_bytes: Arc::new(AtomicUsize::new(0)),
                })
            });
            if monitor_usb_read_counters.is_none() {
                monitor_usb_read_counters = accessory_read_counters.clone();
                monitor_usb_write_counters = accessory_write_counters.clone();
                if monitor_usb_read_counters.is_some() && monitor_usb_write_counters.is_some() {
                    monitor_usb_read_capacity = ACCESSORY_PENDING_OPS;
                    monitor_usb_write_capacity = ACCESSORY_PENDING_OPS;
                    monitor_usb_backend_label = Some("HU USB accessory file");
                }
            }
            hu_r = IoDevice::AccessoryIo(
                hu.clone(),
                accessory_read_counters.clone(),
                accessory_write_counters.clone(),
            );
            hu_w = IoDevice::AccessoryIo(hu, accessory_read_counters, accessory_write_counters);
        } else {
            // Head Unit Emulator via TCP
            let hu = Rc::new(hu_tcp.unwrap());
            hu_r = IoDevice::TcpStreamIo(hu.clone());
            hu_w = IoDevice::TcpStreamIo(hu.clone());
            hu_tcp_stream = Some(hu.clone());
        }

        let md_transport = if usb_dev.is_some() {
            format!(
                "wired USB stream (nusb; urb_r cap {} urb_w cap {})",
                MIN_PENDING_READS, MAX_PENDING_WRITES
            )
        } else {
            "wireless TCP stream".to_string()
        };
        let hu_transport = if hu_usb_active {
            format!(
                "USB accessory file {} (single-op; urb_r cap {} urb_w cap {})",
                USB_ACCESSORY_PATH, ACCESSORY_PENDING_OPS, ACCESSORY_PENDING_OPS
            )
        } else {
            "DHU TCP stream".to_string()
        };
        info!(
            "{} 🔌 transport selection: MD={} | HU={}",
            NAME, md_transport, hu_transport
        );
        if stats_enabled {
            if let Some(backend) = monitor_usb_backend_label {
                info!(
                    "{} 📊 USB stats source: {} (urb_r cap {} urb_w cap {})",
                    NAME, backend, monitor_usb_read_capacity, monitor_usb_write_capacity
                );
            }
        }

        // handling battery in JSON
        if config.mitm && config.ev {
            let mut tx_lock = tx.lock().await;
            *tx_lock = Some(tx_hu.clone());
        }

        // dedicated reading threads:
        reader_hu = tokio_uring::spawn(endpoint_reader(hu_r, txr_hu, true, shared_config.clone()));
        reader_md = tokio_uring::spawn(endpoint_reader(md_r, txr_md, false, shared_config.clone()));
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
            ev_tx.clone(),
        ));
        from_stream = tokio_uring::spawn(proxy(
            ProxyType::MobileDevice,
            md_w,
            stream_bytes.clone(),
            tx_md,
            rx_md,
            rxr_hu,
            shared_config.clone(),
            sensor_channel.clone(),
            ev_tx.clone(),
        ));

        // Thread for monitoring transfer
        let mut monitor = tokio::spawn(transfer_monitor(
            stats_interval,
            file_bytes,
            stream_bytes,
            read_timeout,
            shared_config.clone(),
            monitor_channels,
            monitor_usb_read_counters,
            monitor_usb_write_counters,
            monitor_usb_read_capacity,
            monitor_usb_write_capacity,
            monitor_usb_backend_label,
        ));

        // Stop as soon as one of them errors
        let res = tokio::try_join!(
            flatten(&mut reader_hu),
            flatten(&mut reader_md),
            flatten(&mut from_file),
            flatten(&mut from_stream),
            flatten(&mut monitor)
        );
        if let Err(e) = res {
            error!("{} 🔴 Connection error: {}", NAME, e);
            if let Some(dev) = usb_dev {
                info!("{} 🔌 Resetting USB device for next try...", NAME);
                let _ = dev.reset().await;
            }
        }
        // Make sure the reference count drops to zero and the socket is
        // freed by aborting both tasks (which both hold a `Rc<TcpStream>`
        // for each direction)
        reader_hu.abort();
        reader_md.abort();
        from_file.abort();
        from_stream.abort();
        monitor.abort();

        // Abort the companion-app bridge task if it was spawned this session.
        if let Some(h) = bridge_handle.take() {
            h.abort();
            // Await so the bridge's socket is closed before we restart.
            let _ = h.await;
        }

        // Do not await these handles here: `try_join!(flatten(&mut ...))` above
        // may already have polled one of them to completion, and polling a
        // `JoinHandle` after completion panics. Aborting is enough to request
        // cancellation of the remaining tasks before we drop the handles and
        // shut down the TCP streams below.

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
    }

    #[allow(unreachable_code)]
    // terminate ev client handler
    ev_tx.send(EvTaskCommand::Terminate).await?;
    client_handler.await?;
}
