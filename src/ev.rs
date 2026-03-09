use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;
use shell_words;
use simplelog::*;
use std::path::PathBuf;
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

// protobuf stuff:
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use crate::ev::protos::*;
use crate::ev::SensorMessageId::*;
use crate::mitm::Packet;
use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};
use protobuf::Message;

use serde::Deserialize;

pub static FORD_EV_MODEL: &[u8] = include_bytes!("protos/ford_ev_model.bin");
pub const EV_MODEL_FILE: &str = "/etc/aa-proxy-rs/ev_model.bin";

// module name for logging engine
const NAME: &str = "<i><bright-black> ev: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Deserialize)]
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

/// EV sensor batch data send
pub async fn send_ev_data(tx: Sender<Packet>, sensor_ch: u8, batt: BatteryData) -> Result<()> {
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
