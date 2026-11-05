use crate::web::ServerEvent;
use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;
use shell_words;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::Sender;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::{sleep, Duration};

// protobuf stuff:
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use crate::ev::protos::*;
use crate::ev::SensorMessageId::*;
use crate::mitm::Packet;
use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};
use protobuf::Message;

use serde::{Deserialize, Serialize};

pub static FORD_EV_MODEL: &[u8] = include_bytes!("protos/ford_ev_model.bin");
pub const EV_MODEL_FILE: &str = concat!(crate::base_config_dir!(), "/ev_model.bin");

// module name for logging engine
const NAME: &str = "<i><bright-black> ev: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Deserialize, Serialize)]
pub struct BatteryData {
    pub battery_level_percentage: Option<f32>,
    pub battery_level_wh: Option<u64>,
    pub battery_capacity_wh: Option<u64>,
    pub reference_air_density: Option<f32>,
    pub external_temp_celsius: Option<f32>,
}

#[derive(Debug)]
pub enum EvTaskCommand {
    Start(String), // command line: executable path plus arguments as one string
    Stop,
    Terminate,
}

fn scale_percent_to_value(percent: f32, max_value: u64) -> u64 {
    let scaled = (percent as f64 / 100.0) * max_value as f64;
    scaled.round() as u64
}

type SharedPacketSender = Arc<Mutex<Option<Sender<Packet>>>>;
type SharedSensorChannel = Arc<Mutex<Option<u8>>>;

fn validate_battery_data(data: &BatteryData) -> std::result::Result<(), String> {
    if let Some(level) = data.battery_level_percentage {
        if !level.is_finite() || !(0.0..=100.0).contains(&level) {
            return Err(format!(
                "battery_level_percentage out of range: {level} (expected 0.0-100.0)"
            ));
        }
    } else if data.battery_level_wh.is_none() {
        return Err("Either `battery_level_percentage` or `battery_level_wh` has to be set".into());
    }
    Ok(())
}

fn battery_from_topic(event: &ServerEvent) -> std::result::Result<Option<BatteryData>, String> {
    if event.topic != "battery" {
        return Ok(None);
    }
    let data: BatteryData = serde_json::from_str(&event.payload).map_err(|e| e.to_string())?;
    validate_battery_data(&data)?;
    Ok(Some(data))
}

/// Common input path for POST /battery and the process-wide battery topic.
pub async fn receive_battery_data(
    data: BatteryData,
    tx: &SharedPacketSender,
    sensor_channel: &SharedSensorChannel,
    last_battery_data: Arc<RwLock<Option<BatteryData>>>,
) -> std::result::Result<(), String> {
    validate_battery_data(&data)?;
    info!("{} Received battery data: {:?}", NAME, data);
    let channel = *sensor_channel.lock().await;
    let sender = tx.lock().await.clone();
    match (channel, sender) {
        (Some(ch), Some(sender)) => {
            if let Err(e) = send_ev_data(sender, ch, data, last_battery_data).await {
                error!("{} EV model error: {}", NAME, e);
            }
        }
        _ => warn!("{} Not sending packet because no sensor channel yet", NAME),
    }
    Ok(())
}

/// Subscribe before hooks start so on-create events are also received.
pub fn spawn_battery_topic_collector(
    mut events: broadcast::Receiver<ServerEvent>,
    tx: SharedPacketSender,
    sensor_channel: SharedSensorChannel,
    last_battery_data: Arc<RwLock<Option<BatteryData>>>,
) {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => match battery_from_topic(&event) {
                    Ok(Some(data)) => {
                        if let Err(e) = receive_battery_data(
                            data,
                            &tx,
                            &sensor_channel,
                            last_battery_data.clone(),
                        )
                        .await
                        {
                            warn!("{} rejected battery topic: {}", NAME, e);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => warn!("{} rejected battery topic: {}", NAME, e),
                },
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    warn!("{} battery topic collector skipped {} events", NAME, count);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// EV sensor batch data send
pub async fn send_ev_data(
    tx: Sender<Packet>,
    sensor_ch: u8,
    batt: BatteryData,
    last_battery: Arc<RwLock<Option<BatteryData>>>,
) -> Result<()> {
    // obtain binary model data
    let model_path: PathBuf = PathBuf::from(EV_MODEL_FILE);
    let data = if fs::try_exists(&model_path).await? {
        // reading model from file
        fs::read(&model_path).await?
    } else {
        // default initial sample Ford data
        FORD_EV_MODEL.to_vec()
    };

    // parse
    let mut msg = SensorBatch::parse_from_bytes(&data)?;

    // apply our changes
    if let Some(capacity_wh) = batt.battery_capacity_wh {
        msg.energy_model_control[0]
            .u1
            .as_mut()
            .unwrap()
            .u4
            .as_mut()
            .unwrap()
            .u1 = capacity_wh;
    }
    if let Some(level_wh) = batt.battery_level_wh {
        msg.energy_model_control[0]
            .u1
            .as_mut()
            .unwrap()
            .u3
            .as_mut()
            .unwrap()
            .u1 = level_wh;
    }
    if let Some(level) = batt.battery_level_percentage {
        msg.energy_model_control[0]
            .u1
            .as_mut()
            .unwrap()
            .u3
            .as_mut()
            .unwrap()
            .u1 = scale_percent_to_value(level, msg.energy_model_control[0].u1.u4.u1);
    }
    if let Some(reference_air_density) = batt.reference_air_density {
        msg.energy_model_control[0].u1.as_mut().unwrap().u6 = reference_air_density;
    }
    if let Some(external_temp_celsius) = batt.external_temp_celsius {
        msg.energy_model_control[0].u1.as_mut().unwrap().u7 = external_temp_celsius;
    }

    // creating back binary data for sending
    let mut payload: Vec<u8> = msg.write_to_bytes()?;
    // add SENSOR header
    payload.insert(0, ((SENSOR_MESSAGE_BATCH as u16) >> 8) as u8);
    payload.insert(1, ((SENSOR_MESSAGE_BATCH as u16) & 0xff) as u8);

    let pkt = Packet {
        channel: sensor_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload: payload,
    };
    tx.send(pkt).await?;
    info!("{} injecting ENERGY_MODEL_DATA packet...", NAME);

    // let the overlay templates use the battery values
    crate::overlay_vars::update_battery(&batt);

    // save last battery state
    *last_battery.write().await = Some(batt);

    Ok(())
}

pub async fn spawn_ev_client_task() -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Sender<EvTaskCommand>,
) {
    let (tx, mut rx) = mpsc::channel::<EvTaskCommand>(10);

    let handle = tokio::spawn(async move {
        let mut child: Option<Child> = None;

        while let Some(cmd) = rx.recv().await {
            match cmd {
                EvTaskCommand::Start(cmd_line) => {
                    if child.is_some() {
                        info!("{} process already running.", NAME);
                    } else {
                        match shell_words::split(&cmd_line) {
                            Ok(tokens) if !tokens.is_empty() => {
                                let program = &tokens[0];
                                let args = &tokens[1..];
                                info!("{} starting process: {} {:?}", NAME, program, args);

                                let process = Command::new(program)
                                    .args(args)
                                    .spawn()
                                    .expect("Failed to start process");

                                child = Some(process);
                            }
                            Ok(_) => {
                                info!("{} empty command string, nothing to run.", NAME);
                            }
                            Err(e) => {
                                error!("{} failed to parse command: {:?}", NAME, e);
                            }
                        }
                    }
                }

                EvTaskCommand::Stop => {
                    if let Some(mut proc) = child.take() {
                        if let Some(pid) = proc.id() {
                            info!("{} sending SIGTERM to process {}", NAME, pid);
                            let _ = nix_kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                            sleep(Duration::from_secs(2)).await;

                            match proc.try_wait() {
                                Ok(Some(status)) => {
                                    info!("{} process exited with status: {:?}", NAME, status);
                                }
                                Ok(None) => {
                                    info!("{} process still running, sending SIGKILL...", NAME);
                                    let _ = nix_kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                                    let _ = proc.wait().await;
                                    info!("{} process killed.", NAME);
                                }
                                Err(e) => {
                                    error!("{} error checking process status: {:?}", NAME, e);
                                }
                            }
                        } else {
                            info!("{} process has no PID (already exited?)", NAME);
                        }
                    } else {
                        info!("{} no process to stop.", NAME);
                    }
                }

                EvTaskCommand::Terminate => {
                    info!("{} terminating task...", NAME);
                    if let Some(mut proc) = child.take() {
                        if let Some(pid) = proc.id() {
                            let _ = nix_kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                            let _ = proc.wait().await;
                        }
                    }
                    break;
                }
            }
        }

        info!("{} task finished.", NAME);
    });

    (handle, tx)
}

#[cfg(test)]
mod battery_topic_tests {
    use super::*;
    use tokio::time::timeout;

    fn event(topic: &str, payload: &str) -> ServerEvent {
        ServerEvent {
            topic: topic.into(),
            payload: payload.into(),
        }
    }

    #[test]
    fn only_battery_is_decoded() {
        assert!(battery_from_topic(&event("other", "not json"))
            .unwrap()
            .is_none());
        let data = battery_from_topic(&event("battery", r#"{"battery_level_percentage":75}"#))
            .unwrap()
            .unwrap();
        assert_eq!(data.battery_level_percentage, Some(75.0));
        assert!(
            battery_from_topic(&event("battery", r#"{"battery_level_wh":12000}"#))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn invalid_topic_data_uses_the_http_validation() {
        for payload in [
            "not json",
            "null",
            "{}",
            r#"{"battery_level_percentage":-1}"#,
            r#"{"battery_level_percentage":101}"#,
            r#"{"battery_level_percentage":"75"}"#,
        ] {
            assert!(
                battery_from_topic(&event("battery", payload)).is_err(),
                "{payload}"
            );
        }
        let mut data: BatteryData =
            serde_json::from_str(r#"{"battery_level_percentage":75}"#).unwrap();
        data.battery_level_percentage = Some(f32::NAN);
        assert!(validate_battery_data(&data).is_err());
    }

    #[tokio::test]
    async fn topic_reaches_the_real_ev_model_sender_once() {
        let (events, rx) = broadcast::channel(16);
        let (packets, mut packet_rx) = mpsc::channel(16);
        let last = Arc::new(RwLock::new(None));
        spawn_battery_topic_collector(
            rx,
            Arc::new(Mutex::new(Some(packets))),
            Arc::new(Mutex::new(Some(7))),
            last.clone(),
        );
        events
            .send(event(
                "battery",
                r#"{"battery_level_percentage":75,"battery_capacity_wh":50000}"#,
            ))
            .unwrap();
        let packet = timeout(Duration::from_secs(2), packet_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.channel, 7);
        assert_eq!(
            &packet.payload[..2],
            &(SENSOR_MESSAGE_BATCH as u16).to_be_bytes()
        );
        let model = SensorBatch::parse_from_bytes(&packet.payload[2..]).unwrap();
        assert_eq!(model.energy_model_control[0].u1.u3.u1, 37500);
        timeout(Duration::from_secs(2), async {
            loop {
                if last.read().await.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            last.read().await.as_ref().unwrap().battery_level_percentage,
            Some(75.0)
        );
        assert!(packet_rx.try_recv().is_err());
    }
}
