use simplelog::*;
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
pub enum LedMode {
    On,
    Heartbeat,
}

// module name for logging engine
const NAME: &str = "<i><bright-black> led: </>";

/// Connection status shown on the LED. AAWireless RGB LEDs only distinguish
/// waiting/connected (kept as is); a single LED shows every status with its own pattern.
#[derive(Clone, Copy, PartialEq)]
pub enum LedStatus {
    /// Bluetooth/Wi-Fi handshake in progress: heartbeat
    Waiting,
    /// Handshake done, USB being set up: slow blink
    Connecting,
    /// Session running: steady on
    Connected,
    /// Last connection attempt failed, retrying: fast blink
    Error,
}

#[derive(Clone, Copy)]
pub enum LedColor {
    Red,
    Green,
    Blue,
    Yellow,
    White,
    Purple,
}

struct LedState {
    color: LedColor,
    mode: LedMode,
}

/// sysfs name of the single status LED, declared in the board device tree
/// with `label = "aa-proxy"` (boards without such a LED simply don't have it)
const SINGLE_LED_NAME: &str = "aa-proxy";

pub struct LedManager {
    brightness: u8, // 1–100
    single: bool,   // one mono LED instead of the RGB trio
    status: Option<LedStatus>, // last status applied (single LED only)
    state: LedState,
    override_enabled: bool,
    override_state: Option<LedState>,
}

impl LedManager {
    pub fn new(brightness: u8) -> Self {
        LedManager {
            brightness: brightness.clamp(1, 100),
            single: false,
            status: None,
            state: LedState {
                color: LedColor::Red,
                mode: LedMode::On,
            },
            override_enabled: false,
            override_state: None,
        }
    }

    /// Manager for the single `aa-proxy` LED, `None` if the board doesn't have it.
    /// Color is ignored: heartbeat means waiting, steady on means connected.
    pub fn new_single(brightness: u8) -> Option<Self> {
        let path = Path::new("/sys/class/leds").join(SINGLE_LED_NAME);
        if !path.exists() {
            info!(
                "{} 💡 no <b>{}</> LED found, LED feedback disabled",
                NAME,
                path.display()
            );
            return None;
        }
        info!("{} 💡 single LED detected: <b>{}</>", NAME, path.display());
        let mut manager = Self::new(brightness);
        manager.single = true;
        Some(manager)
    }

    pub async fn set_status(&mut self, status: LedStatus) {
        if !self.single {
            match status {
                LedStatus::Connected => self.set_led(LedColor::Blue, LedMode::On).await,
                _ => self.set_led(LedColor::Green, LedMode::Heartbeat).await,
            }
            return;
        }
        // same status again (retry loop): don't restart the blink pattern
        if self.status == Some(status) {
            return;
        }
        self.status = Some(status);
        if !self.override_enabled {
            self.apply_single(status).await;
        }
    }

    async fn apply_single(&self, status: LedStatus) {
        let (trigger, blink_ms) = match status {
            LedStatus::Waiting => ("heartbeat", None),
            LedStatus::Connecting => ("timer", Some((500, 500))),
            LedStatus::Connected => ("default-on", None),
            LedStatus::Error => ("timer", Some((100, 100))),
        };
        self.write_led(SINGLE_LED_NAME, trigger, self.brightness).await;
        // delay_* only exist once the timer trigger is active
        if let Some((on_ms, off_ms)) = blink_ms {
            let base_path = format!("/sys/class/leds/{}", SINGLE_LED_NAME);
            let _ = write_to_file(format!("{}/delay_on", base_path), &on_ms.to_string()).await;
            let _ = write_to_file(format!("{}/delay_off", base_path), &off_ms.to_string()).await;
        }
    }

    pub async fn set_led(&mut self, color: LedColor, mode: LedMode) {
        self.state = LedState { color, mode };
        if !self.override_enabled {
            self.apply_led(color, mode).await;
        }
    }

    pub async fn override_led(&mut self, color: LedColor, mode: LedMode) {
        self.override_enabled = true;
        self.override_state = Some(LedState { color, mode });
        self.apply_led(color, mode).await;
    }

    pub async fn clear_override(&mut self) {
        self.override_enabled = false;
        if let (true, Some(status)) = (self.single, self.status) {
            self.apply_single(status).await;
            return;
        }
        self.apply_led(self.state.color, self.state.mode).await;
    }

    async fn apply_led(&self, color: LedColor, mode: LedMode) {
        let trigger = match mode {
            LedMode::On => "default-on",
            LedMode::Heartbeat => "heartbeat",
        };

        let led_off = "none";

        if self.single {
            self.write_led(SINGLE_LED_NAME, trigger, self.brightness).await;
            return;
        }

        match color {
            LedColor::Red => {
                self.write_led("rgb-red", trigger, self.brightness).await;
                self.write_led("rgb-green", led_off, 0).await;
                self.write_led("rgb-blue", led_off, 0).await;
            }
            LedColor::Green => {
                self.write_led("rgb-red", led_off, 0).await;
                self.write_led("rgb-green", trigger, self.brightness).await;
                self.write_led("rgb-blue", led_off, 0).await;
            }
            LedColor::Blue => {
                self.write_led("rgb-red", led_off, 0).await;
                self.write_led("rgb-green", led_off, 0).await;
                self.write_led("rgb-blue", trigger, self.brightness).await;
            }
            LedColor::Yellow => {
                self.write_led("rgb-red", trigger, self.brightness).await;
                self.write_led("rgb-green", trigger, self.brightness).await;
                self.write_led("rgb-blue", led_off, 0).await;
            }
            LedColor::White => {
                self.write_led("rgb-red", trigger, self.brightness).await;
                self.write_led("rgb-green", trigger, self.brightness).await;
                self.write_led("rgb-blue", trigger, self.brightness).await;
            }
            LedColor::Purple => {
                self.write_led("rgb-red", trigger, self.brightness).await;
                self.write_led("rgb-green", led_off, 0).await;
                self.write_led("rgb-blue", trigger, self.brightness).await;
            }
        }
    }

    async fn write_led(&self, led_name: &str, trigger: &str, brightness: u8) {
        let base_path = format!("/sys/class/leds/{}", led_name);

        // Write trigger
        let _ = write_to_file(format!("{}/trigger", base_path), trigger).await;

        // Read max brightness
        let max_brightness_str = read_from_file(format!("{}/max_brightness", base_path)).await;
        let max_brightness: u32 = max_brightness_str.trim().parse().unwrap_or(255);

        // Calculate and write brightness
        let scaled_brightness =
            ((brightness as f32 / 100.0) * max_brightness as f32).round() as u32;
        let _ = write_to_file(
            format!("{}/brightness", base_path),
            &scaled_brightness.to_string(),
        )
        .await;
    }
}

async fn write_to_file<P: AsRef<Path>>(path: P, data: &str) -> tokio::io::Result<()> {
    if let Ok(mut file) = OpenOptions::new().write(true).open(path.as_ref()).await {
        let _ = file.write_all(data.as_bytes()).await;
    }
    Ok(())
}

async fn read_from_file<P: AsRef<Path>>(path: P) -> String {
    if let Ok(mut file) = File::open(path).await {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).await.is_ok() {
            return contents;
        }
    }
    "255".to_string()
}
