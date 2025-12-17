use crate::config::Action;
use crate::config::SharedConfig;
use evdev::{Device, EventType, KeyCode};
use simplelog::*;
use std::time::Duration;
use tokio::time::{sleep, Instant};

const BUTTON_DEVICE: &str = "/dev/input/by-path/platform-gpio-keys-event";
const KEY_CODE: KeyCode = KeyCode::KEY_F15;
const PRESS_TIMEOUT: Duration = Duration::from_millis(1000);

// module name for logging engine
const NAME: &str = "<i><bright-black> button: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn button_handler(config: &mut SharedConfig) -> Result<()> {
    let dev = Device::open(BUTTON_DEVICE)?;

    let mut pressed = false;
    let mut presses: u32 = 0;
    let mut deadline: Option<Instant> = None;

    let mut events = dev.into_event_stream()?;
    loop {
        tokio::select! {
            ev = events.next_event() => {
                let ev = ev?;
                if ev.event_type() == EventType::KEY && ev.code() == KEY_CODE.code() {
                    match ev.value() {
                        1 => { // key down
                            pressed = true;
                            deadline = Some(Instant::now() + PRESS_TIMEOUT);
                            info!("{} Key down", NAME);
                        }
                        0 if pressed => { // key up
                            pressed = false;
                            presses += 1;
                            deadline = Some(Instant::now() + PRESS_TIMEOUT);
                            info!("{} Key up ({presses})", NAME);
                        }
                        _ => {}
                    }
                }
            }

            _ = sleep_until(deadline) => {
                if let Some(_) = deadline.take() {
                    handle_timeout(config,pressed, presses).await?;
                    pressed = false;
                    presses = 0;
                }
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    if let Some(t) = deadline {
        sleep(t.saturating_duration_since(Instant::now())).await;
    } else {
        futures::future::pending::<()>().await;
    }
}

async fn handle_timeout(config: &mut SharedConfig, pressed: bool, presses: u32) -> Result<()> {
    if pressed {
        handle_long_press(config).await?;
    } else {
        handle_short_press(config, presses).await?;
    }

    Ok(())
}

async fn handle_short_press(config: &mut SharedConfig, presses: u32) -> Result<()> {
    match presses {
        1 => handle_action(config, "single_press").await?,
        2 => handle_action(config, "double_press").await?,
        3 => handle_action(config, "triple_press").await?,
        _ => handle_action(config, "default").await?,
    }

    Ok(())
}

async fn handle_long_press(config: &mut SharedConfig) -> Result<()> {
    handle_action(config, "long_press").await?;

    Ok(())
}

async fn handle_action(config: &mut SharedConfig, action: &str) -> Result<()> {
    info!("{} Executing action: {action}", NAME);
    match action {
        "single_press" => {
            // try next device using Reconnect action
            config.write().await.action_requested = Some(Action::Reconnect);
            info!("{} 🔁 Button pressed - reconnecting now!", NAME);
        }
        _ => (),
    }

    Ok(())
}
