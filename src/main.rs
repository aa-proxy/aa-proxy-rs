mod aoa;
mod bluetooth;
mod config;
mod ev;
mod io_uring;
mod mitm;
mod usb_gadget;
mod usb_stream;
mod web;

use crate::config::SharedConfig;
use crate::config::SharedConfigJson;
use crate::config::WifiConfig;
use crate::config::{Action, AppConfig};
use crate::config::{DEFAULT_WLAN_ADDR, TCP_SERVER_PORT};
use crate::mitm::Packet;
use bluetooth::bluetooth_setup_connection;
use bluetooth::bluetooth_stop;
use clap::Parser;
use humantime::format_duration;
use io_uring::io_loop;
use simple_config_parser::Config;
use simplelog::*;
use usb_gadget::uevent_listener;
use usb_gadget::UsbGadgetState;

use std::fs;
use std::fs::OpenOptions;
use std::io::Result;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

use std::net::SocketAddr;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use flate2::read::GzDecoder;

// module name for logging engine
const NAME: &str = "<i><bright-black> main: </>";
const HOSTAPD_CONF_IN: &str = "/etc/hostapd.conf.in";
const HOSTAPD_CONF_OUT: &str = "/var/run/hostapd.conf";
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
        default_value = "/etc/aa-proxy-rs/config.toml"
    )]
    config: PathBuf,

    /// Generate system config and exit
    #[clap(short, long)]
    generate_system_config: bool,
}

fn init_wifi_config(iface: &str, hostapd_conf: PathBuf) -> WifiConfig {
    let mut ip_addr = String::from(DEFAULT_WLAN_ADDR);

    // Get UP interface and IP
    for ifa in netif::up().unwrap() {
        match ifa.name() {
            val if val == iface => {
                debug!("Found interface: {:?}", ifa);
                // IPv4 Address contains None scope_id, while IPv6 contains Some
                match ifa.scope_id() {
                    None => {
                        ip_addr = ifa.address().to_string();
                        break;
                    }
                    _ => (),
                }
            }
            _ => (),
        }
    }

    let bssid = mac_address::mac_address_by_name(iface)
        .unwrap()
        .unwrap()
        .to_string();

    // Create a new config from hostapd.conf
    let hostapd = Config::new().file(hostapd_conf).unwrap();

    // read SSID and WPA_KEY
    let ssid = &hostapd.get_str("ssid").unwrap();
    let wpa_key = &hostapd.get_str("wpa_passphrase").unwrap();

    WifiConfig {
        ip_addr,
        port: TCP_SERVER_PORT,
        ssid: ssid.into(),
        bssid,
        wpa_key: wpa_key.into(),
    }
}

fn logging_init(debug: bool, disable_console_debug: bool, log_path: &PathBuf) {
    let conf = ConfigBuilder::new()
        .set_time_format("%F, %H:%M:%S%.3f".to_string())
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

async fn action_handler(config: &mut SharedConfig) -> Result<()> {
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

    Ok(())
}

async fn tokio_main(
    mut config: SharedConfig,
    config_json: SharedConfigJson,
    need_restart: Arc<Notify>,
    tcp_start: Arc<Notify>,
    config_file: PathBuf,
    tx: Arc<Mutex<Option<Sender<Packet>>>>,
    sensor_channel: Arc<Mutex<Option<u8>>>,
) -> Result<()> {
    let accessory_started = Arc::new(Notify::new());
    let accessory_started_cloned = accessory_started.clone();

    if let Some(ref bindaddr) = config.read().await.webserver {
        // preparing AppState and starting webserver
        let state = web::AppState {
            config: config.clone(),
            config_json: config_json.clone(),
            config_file: config_file.into(),
            tx,
            sensor_channel,
        };
        let app = web::app(state.into());

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

    let wifi_conf = {
        if !config.read().await.wired.is_some() {
            Some(init_wifi_config(
                &config.read().await.iface,
                config.read().await.hostapd_conf.clone(),
            ))
        } else {
            None
        }
    };
    let mut usb = None;
    if !config.read().await.dhu {
        if config.read().await.legacy {
            // start uevent listener in own task
            std::thread::spawn(|| uevent_listener(accessory_started_cloned));
        }
        usb = Some(UsbGadgetState::new(
            config.read().await.legacy,
            config.read().await.udc.clone(),
        ));
    }

    let change_usb_order = config.read().await.change_usb_order;
    loop {
        // check if we need to reboot
        action_handler(&mut config).await?;

        if let Some(ref mut usb) = usb {
            if let Err(e) = usb.init() {
                error!("{} 🔌 USB init error: {}", NAME, e);
            }
        }

        let mut bt_stop = None;

        if change_usb_order {
            enable_usb_if_present(&mut usb, accessory_started.clone()).await;
        }

        if let Some(ref wifi_conf) = wifi_conf {
            loop {
                // check if we need to reboot
                action_handler(&mut config).await?;

                match bluetooth_setup_connection(
                    config.read().await.advertise,
                    config.read().await.dongle_mode,
                    config.read().await.btalias.clone(),
                    config.read().await.connect,
                    wifi_conf.clone(),
                    tcp_start.clone(),
                    config.read().await.keepalive,
                    Duration::from_secs(config.read().await.bt_timeout_secs.into()),
                )
                .await
                {
                    Ok(state) => {
                        // we're ready, gracefully shutdown bluetooth in task
                        bt_stop = Some(tokio::spawn(async move { bluetooth_stop(state).await }));
                        break;
                    }
                    Err(e) => {
                        error!("{} Bluetooth error: {}", NAME, e);
                        info!("{} Trying to recover...", NAME);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }

        if !change_usb_order {
            enable_usb_if_present(&mut usb, accessory_started.clone()).await;
        }

        if let Some(bt_stop) = bt_stop {
            // wait for bluetooth stop properly
            let _ = bt_stop.await;
        }

        // wait for restart
        need_restart.notified().await;

        // check if we need to reboot
        action_handler(&mut config).await?;

        // TODO: make proper main loop with cancelation
        info!(
            "{} 📵 TCP/USB connection closed or not started, trying again...",
            NAME
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Returns the SBC model string (currently supports only Raspberry Pi)
pub fn get_sbc_model() -> Result<String> {
    fs::read_to_string("/sys/firmware/devicetree/base/model")
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

    let template = fs::read_to_string(HOSTAPD_CONF_IN)?;

    let rendered = render_template(
        &template,
        &[
            ("HW_MODE", &config.hw_mode),
            ("AC_MODE", {
                if config.hw_mode == "a" {
                    "1"
                } else {
                    "0"
                }
            }),
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

const REQUIRED: [&str; 4] = [
    "CONFIG_USB_CONFIGFS_UEVENT",
    "CONFIG_USB_CONFIGFS_F_ACC",
    "CONFIG_BT_RFCOMM",
    "CONFIG_BT_RFCOMM_TTY",
];

pub fn check_kernel_config(path: &str) -> bool {
    match File::open(path) {
        Ok(file) => {
            let decoder = GzDecoder::new(file);
            let reader = BufReader::new(decoder);

            let mut config: HashMap<String, String> = HashMap::new();
            for line in reader.lines().flatten() {
                if let Some((key, val)) = line.split_once('=') {
                    config.insert(key.trim().to_string(), val.trim().to_string());
                }
            }

            let mut missing = Vec::new();
            for &key in &REQUIRED {
                match config.get(key).map(|s| s.as_str()) {
                    Some("y") | Some("m") => {}
                    _ => missing.push(key.to_string()),
                }
            }

            if missing.is_empty() {
                info!("✅ All required kernel configs are enabled.");
                true
            } else {
                error!("❌ Missing kernel configs: {:?}", missing);
                false
            }
        }
        Err(e) => {
            warn!("⚠️ Failed to open {}: {}", path, e);
            false
        }
    }
}

fn main() {
    let started = Instant::now();

    // CLI arguments
    let args = Args::parse();

    // parse config
    let config = AppConfig::load(args.config.clone()).unwrap();
    let config_json = AppConfig::load_config_json().expect("Invalid embedded config.json");

    logging_init(config.debug, config.disable_console_debug, &config.logfile);
    info!(
        "🛸 <b><blue>aa-proxy-rs</> is starting, build: {}, git: {}-{}",
        env!("BUILD_DATE"),
        env!("GIT_DATE"),
        env!("GIT_HASH")
    );

    check_kernel_config("/proc/config.gz");

    // generate system configs from template and exit
    if args.generate_system_config {
        generate_hostapd_conf(config).expect("error generating config from template");
        return;
    }

    // show SBC model
    if let Ok(model) = get_sbc_model() {
        info!("{} 📟 SBC model: <bold><blue>{}</>", NAME, model);
    }


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

    // notify for syncing threads
    let need_restart = Arc::new(Notify::new());
    let need_restart_cloned = need_restart.clone();
    let tcp_start = Arc::new(Notify::new());
    let tcp_start_cloned = tcp_start.clone();
    let config = Arc::new(RwLock::new(config));
    let config_json = Arc::new(RwLock::new(config_json));
    let config_cloned = config.clone();
    let tx = Arc::new(Mutex::new(None));
    let tx_cloned = tx.clone();
    let sensor_channel = Arc::new(Mutex::new(None));
    let sensor_channel_cloned = sensor_channel.clone();

    // build and spawn main tokio runtime
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.spawn(async move {
        tokio_main(
            config_cloned,
            config_json.clone(),
            need_restart,
            tcp_start,
            args.config.clone(),
            tx_cloned,
            sensor_channel_cloned,
        )
        .await
    });

    // start tokio_uring runtime simultaneously
    let _ = tokio_uring::start(io_loop(
        need_restart_cloned,
        tcp_start_cloned,
        config,
        tx,
        sensor_channel,
    ));

    info!(
        "🚩 aa-proxy-rs terminated, running time: {}",
        format_duration(started.elapsed()).to_string()
    );
}
