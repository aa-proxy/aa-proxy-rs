use aa_proxy_rs::bluetooth;
use aa_proxy_rs::bt_sco::{self, BtScoOptions};
use aa_proxy_rs::bt_sco_echo::BtScoEchoSettings;
use aa_proxy_rs::button::button_handler;
use aa_proxy_rs::config::SharedConfig;
use aa_proxy_rs::config::SharedConfigJson;
use aa_proxy_rs::config::WifiConfig;
use aa_proxy_rs::config::{Action, AppConfig, TCP_SERVER_PORT};
use aa_proxy_rs::crash;
use aa_proxy_rs::device_info;
use aa_proxy_rs::ev::BatteryData;
use aa_proxy_rs::led::{LedColor, LedManager, LedMode};
use aa_proxy_rs::mitm::send_byebye;
use aa_proxy_rs::mitm::OdometerData;
use aa_proxy_rs::mitm::Packet;
use aa_proxy_rs::mitm::SharedCompanionIp;
use aa_proxy_rs::mitm::SharedMediaTapEndpoints;
use aa_proxy_rs::mitm::SharedServiceDiscoveryResponse;
use aa_proxy_rs::mitm::TirePressureData;
use aa_proxy_rs::proxy::io_loop;
use aa_proxy_rs::run_io_loop;
#[cfg(feature = "wasm-scripting")]
use aa_proxy_rs::script_wasm::start_wasm_engine;
#[cfg(feature = "wasm-scripting")]
use aa_proxy_rs::script_wasm::{ScriptParameters, ScriptRegistry};
#[cfg(feature = "wasm-scripting")]
use aa_proxy_rs::wasm_config::WasmConfigStore;
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use aa_proxy_rs::usb_gadget::uevent_listener;
use aa_proxy_rs::usb_gadget::UsbGadgetState;
use aa_proxy_rs::web;
use aa_proxy_rs::web::ServerEvent;
use clap::Parser;
use humantime::format_duration;
use simplelog::*;
use std::os::unix::fs::PermissionsExt;
use time::macros::format_description;

use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

use std::net::SocketAddr;
use tokio::sync::RwLock;

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// module name for logging engine
const NAME: &str = "<i><bright-black> main: </>";
const HOSTAPD_CONF_IN: &str = "/etc/hostapd.conf.in";
const HOSTAPD_CONF_OUT: &str = "/var/run/hostapd.conf";
const DNSMASQ_CONF_IN: &str = "/etc/dnsmasq.conf.in";
const DNSMASQ_CONF_OUT: &str = "/var/run/dnsmasq.conf";
const INTERFACES_IN: &str = "/etc/network/interfaces.in";
const INTERFACES_OUT: &str = "/var/run/interfaces";
const UMTPRD_CONF_IN: &str = "/etc/umtprd/umtprd.conf.in";
const UMTPRD_CONF_OUT: &str = "/var/run/umtprd.conf";
const GADGET_INIT_IN: &str = "/etc/S92usb_gadget.in";
const GADGET_INIT_OUT: &str = "/var/run/S92usb_gadget";
const REBOOT_CMD: &str = "/sbin/reboot";

/// AndroidAuto wired/wireless proxy
#[derive(Parser, Debug)]
#[clap(version, long_about = None, about = format!(
    "🛸 aa-proxy-rs, build: {}, git: {}-{}",
    env!("BUILD_DATE"),
    env!("GIT_DATE"),
    env!("GIT_HASH")
))]
struct Args {
    /// Config file path
    #[clap(
        short,
        long,
        value_parser,
        default_value = concat!(aa_proxy_rs::base_config_dir!(), "/config.toml")
    )]
    config: PathBuf,

    /// Generate system config and exit
    #[clap(short, long)]
    generate_system_config: bool,
    /// Generate hostapd config and exit
    #[clap(short = 'o', long)]
    generate_hostapd: bool,
}

fn init_wifi_config(cfg: &AppConfig) -> Result<WifiConfig> {
    let mut ip_addr = format!("{}.1", cfg.wlan_subnet);

    // Get UP interface and IP
    for ifa in netif::up()? {
        match ifa.name() {
            val if val == cfg.iface => {
                debug!("Found interface: {:?}", ifa);

                // IPv4 Address contains None scope_id, while IPv6 contains Some
                if ifa.scope_id().is_none() {
                    ip_addr = ifa.address().to_string();
                    break;
                }
            }
            _ => (),
        }
    }

    let bssid = mac_address::mac_address_by_name(&cfg.iface)?
        .ok_or("No MAC address found")?
        .to_string();

    Ok(WifiConfig {
        ip_addr,
        port: TCP_SERVER_PORT,
        ssid: cfg.ssid.clone(),
        bssid,
        wpa_key: cfg.wpa_passphrase.clone(),
    })
}

fn logging_init(debug: bool, disable_console_debug: bool, log_path: &PathBuf) {
    let conf = ConfigBuilder::new()
        .set_time_format_custom(format_description!(
            "[year]-[month]-[day], [hour]:[minute]:[second].[subsecond digits:3]"
        ))
        .set_write_log_enable_colors(true)
        .build();

    let mut loggers = vec![];

    let requested_level = if debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let console_logger: Box<dyn SharedLogger> = TermLogger::new(
        {
            if disable_console_debug {
                LevelFilter::Info
            } else {
                requested_level
            }
        },
        conf.clone(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );
    loggers.push(console_logger);

    let mut logfile_error: Option<String> = None;
    let logfile = OpenOptions::new().create(true).append(true).open(&log_path);
    match logfile {
        Ok(logfile) => {
            loggers.push(WriteLogger::new(requested_level, conf, logfile));
        }
        Err(e) => {
            logfile_error = Some(format!(
                "Error creating/opening log file: {:?}: {:?}",
                log_path, e
            ));
        }
    }

    CombinedLogger::init(loggers).expect("Cannot initialize logging subsystem");
    if logfile_error.is_some() {
        error!("{} {}", NAME, logfile_error.unwrap());
        warn!("{} Will do console logging only...", NAME);
    }
}

async fn enable_usb_if_present(usb: &mut Option<UsbGadgetState>, accessory_started: Arc<Notify>) {
    if let Some(ref mut usb) = usb {
        usb.enable_default_and_wait_for_accessory(accessory_started)
            .await;
    }
}

async fn action_handler(config: &mut SharedConfig) {
    // check pending action
    let action = config.read().await.action_requested.clone();
    if let Some(action) = action {
        // check if we need to reboot
        if action == Action::Reboot {
            config.write().await.action_requested = None;
            info!("{} 🔁 Rebooting now!", NAME);
            let _ = Command::new(REBOOT_CMD).spawn();
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    }
}

async fn clean_disconnect_and_exit(
    tx: Arc<Mutex<Option<Sender<Packet>>>>,
    config: SharedConfig,
    reason: &str,
) -> ! {
    info!("{} {}: initiating clean disconnect", NAME, reason);

    if let Some(sender) = tx.lock().await.clone() {
        if let Err(e) = send_byebye(sender).await {
            warn!("{} {}: ByeBye send failed: {}", NAME, reason, e);
        }
        // Give the BYEBYE exchange a short head start before forcing reconnect.
        tokio::time::sleep(Duration::from_millis(200)).await;
    } else {
        info!("{} {}: no active session tx, skipping ByeBye", NAME, reason);
    }

    // Trigger normal io_loop teardown (TCP shutdown + USB reset + context cleanup).
    config.write().await.action_requested = Some(Action::Reconnect);

    // Wait for io_loop cleanup to clear the active tx context, but don't hang forever.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if tx.lock().await.is_none() {
            break;
        }
        if Instant::now() >= deadline {
            warn!(
                "{} {}: teardown did not complete before deadline, exiting anyway",
                NAME, reason
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!("{} {}: exiting process after teardown", NAME, reason);
    std::process::exit(0);
}

async fn tokio_main(
    config: SharedConfig,
    config_json: SharedConfigJson,
    restart_tx: BroadcastSender<Option<Action>>,
    tcp_start: Arc<Notify>,
    config_file: PathBuf,
    tx: Arc<Mutex<Option<Sender<Packet>>>>,
    sensor_channel: Arc<Mutex<Option<u8>>>,
    input_channel: Arc<Mutex<Option<u8>>>,
    last_battery_data: Arc<RwLock<Option<BatteryData>>>,
    last_odometer_data: Arc<RwLock<Option<OdometerData>>>,
    last_speed: Arc<RwLock<Option<i32>>>,
    last_service_discovery_response: SharedServiceDiscoveryResponse,
    media_tap_endpoints: SharedMediaTapEndpoints,
    companion_ip: SharedCompanionIp,
    last_tire_pressure_data: Arc<RwLock<Option<TirePressureData>>>,
    led_support: bool,
    button_support: bool,
    profile_connected: Arc<AtomicBool>,
    usb_connected: Arc<AtomicBool>,
    ws_event_tx: broadcast::Sender<ServerEvent>,
    script_registry: Option<Arc<ScriptRegistry>>,
) -> Result<()> {
    let accessory_started = Arc::new(Notify::new());
    let accessory_started_cloned = accessory_started.clone();
    let state = web::AppState {
        config: config.clone(),
        config_json: config_json.clone(),
        config_file: config_file.into(),
        tx: tx.clone(),
        sensor_channel,
        input_channel,
        last_battery_data,
        last_odometer_data,
        last_speed,
        last_service_discovery_response,
        media_tap_endpoints,
        companion_ip: companion_ip.clone(),
        last_tire_pressure_data,
        ws_event_tx,
        script_registry,
    };

    // Handle process-exit signals with a protocol-clean teardown.
    let tx_signal = tx.clone();
    let config_signal = config.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("{} signal handler init failed (SIGTERM): {}", NAME, e);
                    return;
                }
            };
            let mut sigquit = match signal(SignalKind::quit()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("{} signal handler init failed (SIGQUIT): {}", NAME, e);
                    return;
                }
            };

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("{} received Ctrl+C/SIGINT, attempting clean disconnect...", NAME);
                }
                _ = sigterm.recv() => {
                    info!("{} received SIGTERM, attempting clean disconnect...", NAME);
                }
                _ = sigquit.recv() => {
                    info!("{} received SIGQUIT, attempting clean disconnect...", NAME);
                }
            }
        }

        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("{} received Ctrl+C, attempting clean disconnect...", NAME);
            }
        }

        clean_disconnect_and_exit(tx_signal, config_signal, "signal exit").await;
    });

    // LED support
    let mut led_manager = if led_support {
        Some(LedManager::new(100))
    } else {
        None
    };

    let mut cfg = config.read().await.clone();
    let aa_server_tcp_enabled = !cfg.aa_server_tcp_addr.trim().is_empty();
    if aa_server_tcp_enabled {
        info!(
            "{} 🛰️ Android Auto Head Unit Server direct TCP mode enabled: <u>{}</u>",
            NAME,
            cfg.aa_server_tcp_addr.trim()
        );
    }

    if cfg.bt_sco {
        match bt_sco::spawn(BtScoOptions {
            bridge_aa_media_pcm: cfg.bt_sco_media_bridge,
            bridge_ring_capacity: cfg.bt_sco_media_bridge_ring_capacity,
            media_resampler: cfg.bt_sco_media_bridge_resampler,
            bridge_sco_uplink_pcm: cfg.bt_sco_mic_bridge,
            sco_uplink_ring_capacity: cfg.bt_sco_mic_uplink_ring_capacity,
            echo_settings: BtScoEchoSettings {
                control: cfg.bt_sco_mic_echo_control,
                mic_gain_percent: cfg.bt_sco_mic_gain_percent,
                duck_threshold: cfg.bt_sco_mic_duck_threshold,
                duck_percent: cfg.bt_sco_mic_duck_percent,
                duck_hold_ms: cfg.bt_sco_mic_duck_hold_ms,
            },
        }) {
            Ok(_) => {
                info!(
                    "{} Bluetooth SCO listener started, media_bridge={}, mic_bridge={}",
                    NAME, cfg.bt_sco_media_bridge, cfg.bt_sco_mic_bridge
                );
            }
            Err(e) => {
                warn!("{} Bluetooth SCO listener failed to start: {}", NAME, e);
            }
        }
    }

    if let Some(ref bindaddr) = cfg.webserver {
        // preparing AppState and starting webserver
        let app = web::app(state.clone().into());

        match bindaddr.parse::<SocketAddr>() {
            Ok(addr) => {
                let server = hyper::Server::bind(&addr).serve(app.into_make_service());

                // run webserver in separate task
                tokio::spawn(async move {
                    if let Err(e) = server.await {
                        error!("{} webserver starting error: {}", NAME, e);
                    }
                });

                info!("{} webserver running at http://{addr}/", NAME);
            }
            Err(e) => {
                error!("{} webserver address/port parse: {}", NAME, e);
            }
        }
    }

    let wifi_config = init_wifi_config(&cfg)
        .map_err(|e| {
            error!("{} WiFi config init failed: {}", NAME, e);
            e
        })
        .ok();
    let mut usb = None;
    if !cfg.dhu {
        if cfg.legacy {
            // start uevent listener in own task
            std::thread::spawn(|| uevent_listener(accessory_started_cloned));
        }
        usb = Some(UsbGadgetState::new(cfg.legacy, cfg.udc.clone()));
    }

    if button_support {
        // spawn a background task for button events
        let mut config_cloned = config.clone();
        let _ = tokio::spawn(async move {
            if let Err(e) = button_handler(&mut config_cloned).await {
                error!("{} button_handler: {}", NAME, e);
            }
        });
    }

    // spawn a background task for reboot detection
    let mut config_cloned = config.clone();
    let _ = tokio::spawn(async move {
        loop {
            action_handler(&mut config_cloned).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });

    // initial bluetooth setup
    let mut bluetooth = None;
    if aa_server_tcp_enabled {
        info!(
            "{} 🛰️ Skipping Bluetooth AA setup because aa_server_tcp_addr is set",
            NAME
        );
    } else {
        let proxy_mode = cfg.bt_wireless_proxy_mode.trim().to_ascii_lowercase();
        let bt_proxy_probe_only = cfg.bt_wireless_proxy && proxy_mode == "probe";
        let register_aa_wireless_profile = !bt_proxy_probe_only;
        if bt_proxy_probe_only {
            info!(
                "{} 🧪 bt_wireless_proxy probe mode: skipping local AA Wireless server profile registration to avoid UUID collision",
                NAME
            );
        }

        loop {
            match bluetooth::init(
                cfg.btalias.clone(),
                cfg.advertise,
                cfg.dongle_mode,
                register_aa_wireless_profile,
            )
            .await
            {
                Ok(result) => {
                    bluetooth = Some(result);
                    break;
                }
                Err(e) => {
                    error!("{} Fatal error in Bluetooth setup: {}", NAME, e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        if cfg.bt_wireless_proxy {
            if let Some(ref mut bluetooth) = bluetooth {
                if let Err(e) = bluetooth
                    .register_phone_like_sdp_profiles(
                        cfg.bt_wireless_proxy_phone_like_sdp_profiles,
                        &cfg.bt_wireless_proxy_phone_like_sdp_profile_set,
                    )
                    .await
                {
                    warn!("{} bt_wireless_proxy phone-like SDP registration failed: {}", NAME, e);
                }
            }
        }

        if let Some(ref mut bluetooth) = bluetooth {
            if let Err(e) = bluetooth
                .start_companion_bt(state.clone(), cfg.enable_companion_bt)
                .await
            {
                warn!("{} Error starting Companion Classic BT: {}", NAME, e);
            }
        }

        // bt_wireless_proxy needs the configured HU paired/trusted before the USB/phone flow.
        // If the HU is not paired yet, open a short BlueZ agent window that only accepts the
        // configured HU MAC, then continue once it is trusted.
        if cfg.bt_wireless_proxy && !cfg.bt_wireless_proxy_hu_mac.trim().is_empty() {
            if let Some(ref mut bluetooth) = bluetooth {
                loop {
                    match bluetooth
                        .ensure_hu_pairing_agent(
                            &cfg.bt_wireless_proxy_hu_mac,
                            cfg.bt_wireless_proxy_pairing_window_secs,
                            cfg.bt_wireless_proxy_phone_like_pairing,
                            &cfg.bt_wireless_proxy_phone_like_pairing_alias,
                            &cfg.bt_wireless_proxy_phone_like_pairing_class,
                        )
                        .await
                    {
                        Ok(()) => break,
                        Err(e) => {
                            warn!(
                                "{} bt_wireless_proxy HU pairing window failed: {}; retrying before USB/phone flow",
                                NAME, e
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    // main connection loop
    let change_usb_order = cfg.change_usb_order;
    let mut need_restart = restart_tx.subscribe();
    loop {
        if let Some(ref mut leds) = led_manager {
            leds.set_led(LedColor::Green, LedMode::Heartbeat).await;
        }
        if let Some(ref mut usb) = usb {
            if let Err(e) = usb.init() {
                error!("{} 🔌 USB init error: {}", NAME, e);
            }
        }

        if change_usb_order {
            enable_usb_if_present(&mut usb, accessory_started.clone()).await;
        }

        // run only if not handling this in handshake task
        let aa_server_tcp_enabled = !cfg.aa_server_tcp_addr.trim().is_empty();
        if aa_server_tcp_enabled {
            // Direct MD TCP mode does not use the Bluetooth/Wi-Fi AA handshake.
            // io_loop will connect to aa_server_tcp_addr after the HU/DHU side is ready.
        } else if cfg.bt_wireless_proxy {
            if let Some(ref mut bluetooth) = bluetooth {
                let proxy_mode = cfg.bt_wireless_proxy_mode.trim().to_ascii_lowercase();
                let result = if proxy_mode == "probe" {
                    bluetooth
                        .aa_wireless_probe_proxy(
                            cfg.bt_wireless_proxy_hu_mac.clone(),
                            cfg.bt_wireless_proxy_hu_channel,
                            cfg.bt_wireless_proxy_tcp_probe,
                        )
                        .await
                } else if proxy_mode == "car-wifi-mitm" || proxy_mode == "wifi-mitm" {
                    bluetooth
                        .aa_wireless_car_wifi_mitm_proxy(
                            cfg.connect.clone(),
                            bluetooth::CarWifiMitmProxyOptions {
                                hu_mac: cfg.bt_wireless_proxy_hu_mac.clone(),
                                hu_channel: cfg.bt_wireless_proxy_hu_channel,
                                rendezvous_mode: cfg.bt_wireless_proxy_rendezvous_mode.clone(),
                                iface: cfg.iface.clone(),
                                join_cmd: cfg.bt_wireless_proxy_car_wifi_join_cmd.clone(),
                                auto_join: cfg.bt_wireless_proxy_car_wifi_auto_join,
                                join_control: cfg.bt_wireless_proxy_wifi_join_control.clone(),
                                keep_ap: cfg.bt_wireless_proxy_car_wifi_keep_ap,
                                sta_iface: cfg.bt_wireless_proxy_car_wifi_sta_iface.clone(),
                                ap_iface: cfg.bt_wireless_proxy_car_wifi_ap_iface.clone(),
                                rewrite_ip: cfg.bt_wireless_proxy_rewrite_ip.clone(),
                                listen_port: cfg.bt_wireless_proxy_listen_port,
                                use_version_projection_fallback: cfg.bt_wireless_proxy_use_version_projection_fallback,
                                wpactrl_socket_timeout: Duration::from_secs(cfg.bt_wireless_proxy_wpactrl_socket_timeout_secs.max(1)),
                                wifi_association_timeout: Duration::from_secs(cfg.bt_wireless_proxy_wifi_association_timeout_secs.max(1)),
                                dhcp_timeout: Duration::from_secs(cfg.bt_wireless_proxy_dhcp_timeout_secs.max(1)),
                                hu_first_connect: cfg.bt_wireless_proxy_hu_first_connect,
                                hu_first_wait_phone_timeout: Duration::from_secs(cfg.bt_wireless_proxy_hu_first_wait_phone_secs.max(1)),
                                bt_timeout: Duration::from_secs(cfg.bt_timeout_secs.into()),
                                stopped: cfg.action_requested == Some(Action::Stop),
                            },
                        )
                        .await
                } else {
                    bluetooth
                        .aa_wireless_bridge_proxy(
                            cfg.connect.clone(),
                            cfg.bt_wireless_proxy_hu_mac.clone(),
                            cfg.bt_wireless_proxy_hu_channel,
                            Duration::from_secs(cfg.bt_timeout_secs.into()),
                            cfg.action_requested == Some(Action::Stop),
                        )
                        .await
                };

                if let Err(e) = result {
                    error!("{} bt_wireless_proxy error: {}", NAME, e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            } else {
                warn!(
                    "{} bt_wireless_proxy requested but Bluetooth was not initialized; restart after clearing aa_server_tcp_addr",
                    NAME
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        } else if let Some(ref wifi_conf) = wifi_config {
            if !usb_connected.load(Ordering::Relaxed)
                && (!(cfg.quick_reconnect && profile_connected.load(Ordering::Relaxed))
                    || cfg.action_requested == Some(Action::Stop))
            {
                if let Some(ref mut bluetooth) = bluetooth {
                    // bluetooth handshake
                    if let Err(e) = bluetooth
                        .aa_handshake(
                            cfg.connect.clone(),
                            wifi_conf.clone(),
                            tcp_start.clone(),
                            Duration::from_secs(cfg.bt_timeout_secs.into()),
                            cfg.action_requested == Some(Action::Stop),
                            cfg.quick_reconnect,
                            cfg.bt_poweroff,
                            cfg.bt_sco,
                            cfg.bt_sco_keep_bluetooth_alive,
                            restart_tx.subscribe(),
                            restart_tx.clone(),
                            profile_connected.clone(),
                        )
                        .await
                    {
                        error!("{} bluetooth AA handshake error: {}", NAME, e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                } else {
                    warn!(
                        "{} Bluetooth AA handshake requested but Bluetooth was not initialized; restart after clearing aa_server_tcp_addr",
                        NAME
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
        }

        if !change_usb_order {
            enable_usb_if_present(&mut usb, accessory_started.clone()).await;
        }

        // inform via LED about successful connection
        if let Some(ref mut leds) = led_manager {
            leds.set_led(LedColor::Blue, LedMode::On).await;
        }
        // wait for restart notification
        let _ = need_restart.recv().await;
        if !(cfg.quick_reconnect && profile_connected.load(Ordering::Relaxed)) {
            info!(
                "{} 📵 TCP/USB connection closed or not started, trying again...",
                NAME
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        } else {
            info!(
                "{} 📵 TCP/USB connection closed or not started, quick restart...",
                NAME
            );
        }

        // TODO: make proper main loop with cancelation
        // re-read config
        cfg = config.read().await.clone();
    }
}

/// Returns the full device serial number from Device Tree
pub fn get_serial_number() -> Result<String> {
    Ok(
        fs::read_to_string("/sys/firmware/devicetree/base/serial-number")?
            .trim_end_matches(char::from(0))
            .trim()
            .to_string(),
    )
}

fn render_template(template: &str, vars: &[(&str, &str)]) -> String {
    let mut output = template.to_string();
    for (key, value) in vars {
        let placeholder = format!("{{{{{}}}}}", key);
        output = output.replace(&placeholder, value);
    }
    output
}

fn generate_hostapd_conf(config: AppConfig) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, HOSTAPD_CONF_IN
    );

    // Technically for IEEE802.11g we have to use g but AFAIK b is fine.
    let hostapd_mode = if config.band == "5" || config.band == "6" {
        "a"
    } else {
        "g"
    };

    let template = fs::read_to_string(HOSTAPD_CONF_IN)?;

    // Eventually: For 6 GHz, we will need more options like opclass.
    let rendered = render_template(
        &template,
        &[
            ("HW_MODE", hostapd_mode),
            ("BE_MODE", if config.wifi_version >= 7 { "1" } else { "0" }),
            ("AX_MODE", if config.wifi_version >= 6 { "1" } else { "0" }),
            ("AC_MODE", if config.wifi_version >= 5 { "1" } else { "0" }),
            ("N_MODE", if config.wifi_version >= 4 { "1" } else { "0" }),
            ("COUNTRY_CODE", &config.country_code),
            ("CHANNEL", &config.channel.to_string()),
            ("SSID", &config.ssid),
            ("WPA_PASSPHRASE", &config.wpa_passphrase),
        ],
    );

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, HOSTAPD_CONF_OUT
    );
    fs::write(HOSTAPD_CONF_OUT, rendered)
}

fn generate_network_conf(config: &AppConfig, input: &str, output: &str) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, input
    );

    let template = fs::read_to_string(input)?;
    let rendered = render_template(&template, &[("WLAN_SUBNET", &config.wlan_subnet)]);

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, output
    );
    fs::write(output, rendered)
}

fn generate_usb_strings(input: &str, output: &str) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, input
    );

    let template = fs::read_to_string(input)?;

    let rendered = render_template(
        &template,
        &[
            (
                "MODEL",
                &device_info::get_sbc_model()
                    .map_or(String::new(), |model| format!(" ({})", model)),
            ),
            (
                "SERIAL",
                &get_serial_number().unwrap_or("0123456".to_string()),
            ),
            (
                "FIRMWARE_VER",
                &format!(
                    "{}, git: {}-{}",
                    env!("BUILD_DATE"),
                    env!("GIT_DATE"),
                    env!("GIT_HASH")
                ),
            ),
        ],
    );

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, output
    );
    fs::write(output, rendered)
}

fn main() -> Result<()> {
    let started = Instant::now();

    // CLI arguments
    let args = Args::parse();

    // parse config
    let config = match AppConfig::load(args.config.clone()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "Failed to start aa-proxy-rs due to invalid configuration in: {}.  Error:\n{}",
                args.config.display(),
                e
            );
            std::process::exit(1);
        }
    };
    let config_json = AppConfig::load_config_json().expect("Invalid embedded config.json");

    crash::install_panic_handler(config.crash_dir.clone(), config.crash_handler_enabled);

    logging_init(config.debug, config.disable_console_debug, &config.logfile);
    info!(
        "🛸 <b><blue>aa-proxy-rs</> is starting, build: {}, git: {}-{}",
        env!("BUILD_DATE"),
        env!("GIT_DATE"),
        env!("GIT_HASH")
    );

    // generate system configs from template and exit
    if args.generate_system_config {
        generate_usb_strings(UMTPRD_CONF_IN, UMTPRD_CONF_OUT)
            .expect("error generating config from template");
        generate_network_conf(&config, DNSMASQ_CONF_IN, DNSMASQ_CONF_OUT)
            .expect("error generating config from template");
        generate_network_conf(&config, INTERFACES_IN, INTERFACES_OUT)
            .expect("error generating config from template");

        generate_usb_strings(GADGET_INIT_IN, GADGET_INIT_OUT)
            .expect("error generating config from template");
        // make a script executable
        info!(
            "{} 🚀 Making script executable: <bold><green>{}</>",
            NAME, GADGET_INIT_OUT
        );
        let mut perms = fs::metadata(GADGET_INIT_OUT)?.permissions();
        perms.set_mode(0o755); // rwxr-xr-x
        fs::set_permissions(GADGET_INIT_OUT, perms)?;

        return Ok(());
    }
    // generate hostapd config from template and exit
    if args.generate_hostapd {
        generate_hostapd_conf(config).expect("error generating config from template");
        return Ok(());
    }

    // show SBC model
    let mut led_support = false;
    let mut button_support = false;
    if let Ok(model) = device_info::get_sbc_model() {
        info!("{} 📟 host device: <bold><blue>{}</>", NAME, model);
        if model.starts_with("AAWireless") {
            led_support = true;
            button_support = true;
        }
    }

    // Log which I/O backend is active
    #[cfg(feature = "io-uring")]
    info!("⚙️ I/O backend: <b><green>io_uring</> (kernel async I/O)");
    #[cfg(not(feature = "io-uring"))]
    info!("⚙️ I/O backend: <b><yellow>tokio async</> (standard async I/O)");

    // check and display config
    if args.config.exists() {
        info!(
            "{} ⚙️ config loaded from file: {}",
            NAME,
            args.config.display()
        );
    } else {
        warn!(
            "{} ⚙️ config file: {} doesn't exist, defaults used",
            NAME,
            args.config.display()
        );
    }
    debug!("{} ⚙️ startup configuration: {:#?}", NAME, config);

    if let Some(ref wired) = config.wired {
        info!(
            "{} 🔌 enabled wired USB connection with {:04X?}",
            NAME, wired
        );
    }
    info!(
        "{} 📜 Log file path: <b><green>{}</>",
        NAME,
        config.logfile.display()
    );
    info!(
        "{} 💥 Panic reports: <b><green>{}</> dir=<b><green>{}</>",
        NAME,
        if config.crash_handler_enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.crash_dir.display()
    );
    info!(
        "{} 🖼️ SDR UI overrides: <b><green>{}</> file=<b><green>{}</> autocreate={}",
        NAME,
        if config.sdr_ui_override_enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.sdr_ui_override_file.display(),
        config.sdr_ui_override_autocreate_profiles
    );
    if config.startup_delay > 0 {
        thread::sleep(Duration::from_secs(config.startup_delay.into()));
        info!(
            "{} 💤 Startup delayed by <b><blue>{}</> seconds",
            NAME, config.startup_delay
        );
    }

    // notify for syncing threads
    let (restart_tx, _) = broadcast::channel(1);
    let tcp_start = Arc::new(Notify::new());
    let tcp_start_cloned = tcp_start.clone();
    #[cfg(feature = "wasm-scripting")]
    let wasm_hooks_dir = config.wasm_hooks_dir.clone();
    let config = Arc::new(RwLock::new(config));
    let config_json = Arc::new(RwLock::new(config_json));
    let config_cloned = config.clone();
    let tx = Arc::new(Mutex::new(None));
    let tx_cloned = tx.clone();
    let sensor_channel = Arc::new(Mutex::new(None));
    let sensor_channel_cloned = sensor_channel.clone();
    let input_channel = Arc::new(Mutex::new(None));
    let input_channel_cloned = input_channel.clone();
    let profile_connected = Arc::new(AtomicBool::new(false));
    let last_battery_data = Arc::new(RwLock::new(None));
    let last_battery_data_cloned = last_battery_data.clone();
    let last_odometer_data = Arc::new(RwLock::new(None));
    let last_speed: Arc<RwLock<Option<i32>>> = Arc::new(RwLock::new(None));
    let last_speed_cloned = last_speed.clone();
    let last_service_discovery_response = Arc::new(RwLock::new(None));
    let last_service_discovery_response_cloned = last_service_discovery_response.clone();
    let media_tap_endpoints: SharedMediaTapEndpoints = Arc::new(RwLock::new(Vec::new()));
    let media_tap_endpoints_cloned = media_tap_endpoints.clone();
    let companion_ip: SharedCompanionIp = Arc::new(RwLock::new(None));
    let companion_ip_cloned = companion_ip.clone();
    let last_tire_pressure_data = Arc::new(RwLock::new(None));
    let usb_connected = Arc::new(AtomicBool::new(false));
    let usb_connected_cloned = usb_connected.clone();
    let (ws_event_tx, _ws_event_rx) = broadcast::channel(256);
    let ws_event_tx_cloned = ws_event_tx.clone();

    // build and spawn main tokio runtime
    let mut runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    let restart_tx_cloned = restart_tx.clone();
    let profile_connected_cloned = profile_connected.clone();

    #[cfg(feature = "wasm-scripting")]
    let wasm_config_store = Arc::new(WasmConfigStore::load_default());

    #[cfg(feature = "wasm-scripting")]
    let script_parameters = ScriptParameters {
        ws_event_tx: ws_event_tx.clone(),
        wasm_config_store,
        config: config.clone(),
    };
    #[cfg(feature = "wasm-scripting")]
    let script_registry = start_wasm_engine(
        &mut runtime,
        wasm_hooks_dir.to_string_lossy().into_owned(),
        script_parameters,
    )
    .ok();
    #[cfg(not(feature = "wasm-scripting"))]
    let script_registry = None;
    let script_registry_cloned = script_registry.clone();

    runtime.spawn(async move {
        tokio_main(
            config_cloned,
            config_json.clone(),
            restart_tx_cloned,
            tcp_start,
            args.config.clone(),
            tx_cloned,
            sensor_channel_cloned,
            input_channel_cloned,
            last_battery_data_cloned,
            last_odometer_data,
            last_speed_cloned,
            last_service_discovery_response_cloned,
            media_tap_endpoints_cloned,
            companion_ip_cloned,
            last_tire_pressure_data,
            led_support,
            button_support,
            profile_connected_cloned,
            usb_connected_cloned,
            ws_event_tx_cloned,
            script_registry_cloned,
        )
        .await
    });

    // start tokio_uring runtime simultaneously
    run_io_loop!(
        runtime,
        io_loop(
            restart_tx,
            tcp_start_cloned,
            config,
            tx,
            sensor_channel,
            input_channel,
            last_battery_data,
            last_speed,
            last_service_discovery_response,
            media_tap_endpoints,
            companion_ip,
            usb_connected,
            script_registry.clone(),
            ws_event_tx.clone(),
        )
    );

    info!(
        "🚩 aa-proxy-rs terminated, running time: {}",
        format_duration(started.elapsed()).to_string()
    );

    Ok(())
}
