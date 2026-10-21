//! Live data for the overlay text templates.
//!
//! The `"text"` of the overlay may contain `{{name}}` placeholders that are replaced with live
//! vehicle/system data every time the overlay file is polled, for example
//! `"SoC: {{battery_level_percentage}}%"`.
//!
//! Syntax: `{{ name }}`, `{{ name:N }}` (N decimals, 0-6) and `{{ name | fallback }}` (shown when
//! the value is not available), combined as `{{ name:N | fallback }}`. See the README for the list
//! of names.
//!
//! Data comes from two places, both only collected while the overlay is enabled:
//! - the websocket event bus (`ServerEvent`): the latest payload of every topic is remembered
//!   (`speed`, `odometer`, `tpms`, `vehicle_energy_forecast`, topics sent to `/raw-topic-data`,
//!   by the companion app or by scripts, ...),
//! - battery data (`/battery` and the head unit fuel data), which is not published on the bus.
//!
//! Substituted text values are HTML-escaped, so data coming from the network can never inject
//! markup into the overlay.

use crate::ev::BatteryData;
use crate::web::ServerEvent;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Maximum number of distinct websocket topics remembered (topics can be created from the network).
const MAX_WS_TOPICS: usize = 64;
/// Payloads longer than this are ignored.
const MAX_WS_PAYLOAD_BYTES: usize = 4096;
/// Vehicle speed older than this is treated as unavailable (the car stopped sending it).
const SPEED_MAX_AGE: Duration = Duration::from_secs(5);
/// Upper bound of the expanded text.
const MAX_EXPANDED_BYTES: usize = 8192;
/// Upper bound of a single substituted text value (in characters).
const MAX_VALUE_CHARS: usize = 256;
/// Upper bound of placeholders expanded in one text.
const MAX_PLACEHOLDERS: usize = 256;

const KPA_PER_PSI: f64 = 6.894_757_293_168_361;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Num(f64),
    Text(String),
}

#[derive(Default)]
struct BatteryValues {
    level_percentage: Option<f32>,
    level_wh: Option<u64>,
    capacity_wh: Option<u64>,
    reference_air_density: Option<f32>,
    external_temp_celsius: Option<f32>,
}

struct WsEntry {
    payload: String,
    updated: Instant,
}

#[derive(Default)]
struct Store {
    battery: BatteryValues,
    ws: HashMap<String, WsEntry>,
}

static STORE: LazyLock<Mutex<Store>> = LazyLock::new(|| Mutex::new(Store::default()));

impl Store {
    fn merge_battery(&mut self, b: &BatteryData) {
        // A new POST may carry only some of the fields: keep the last known value of the others.
        if b.battery_level_percentage.is_some() {
            self.battery.level_percentage = b.battery_level_percentage;
        }
        if b.battery_level_wh.is_some() {
            self.battery.level_wh = b.battery_level_wh;
        }
        if b.battery_capacity_wh.is_some() {
            self.battery.capacity_wh = b.battery_capacity_wh;
        }
        if b.reference_air_density.is_some() {
            self.battery.reference_air_density = b.reference_air_density;
        }
        if b.external_temp_celsius.is_some() {
            self.battery.external_temp_celsius = b.external_temp_celsius;
        }
    }

    fn set_ws(&mut self, topic: &str, payload: &str, now: Instant) {
        if payload.len() > MAX_WS_PAYLOAD_BYTES || topic.is_empty() || topic.len() > 128 {
            return;
        }
        if !self.ws.contains_key(topic) && self.ws.len() >= MAX_WS_TOPICS {
            return;
        }
        self.ws.insert(
            topic.to_string(),
            WsEntry {
                payload: payload.to_string(),
                updated: now,
            },
        );
    }
}

/// Remembers the latest battery values (called when battery data is received).
pub fn update_battery(data: &BatteryData) {
    if !crate::overlay::overlay_enabled() {
        return;
    }
    if let Ok(mut store) = STORE.lock() {
        store.merge_battery(data);
    }
}

/// Remembers the latest payload of a websocket event topic.
pub fn record_ws_event(ev: &ServerEvent) {
    if !crate::overlay::overlay_enabled() {
        return;
    }
    if let Ok(mut store) = STORE.lock() {
        store.set_ws(&ev.topic, &ev.payload, Instant::now());
    }
}

/// Spawns the task that feeds the store from the websocket event bus.
pub fn spawn_ws_collector(mut rx: broadcast::Receiver<ServerEvent>) {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => record_ws_event(&ev),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Expands all `{{...}}` placeholders in `text` using the current live data.
pub fn expand_current(text: &str) -> String {
    match STORE.lock() {
        Ok(store) => expand_with(&store, Instant::now(), text),
        Err(_) => text.to_string(),
    }
}

fn expand_with(store: &Store, now: Instant, text: &str) -> String {
    expand_templates(text, &|name| lookup(store, now, name))
}

// ============================================================================
// LOOKUP
// ============================================================================

fn fresh(store: &Store, topic: &str, now: Instant, max_age: Option<Duration>) -> Option<String> {
    let e = store.ws.get(topic)?;
    if let Some(max) = max_age {
        if now.saturating_duration_since(e.updated) > max {
            return None;
        }
    }
    Some(e.payload.clone())
}

fn json_f64(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().filter(|f| f.is_finite())
}

fn lookup(store: &Store, now: Instant, name: &str) -> Option<Value> {
    match name {
        // --- battery (POST /battery and head unit fuel data) ---
        "battery_level_percentage" => {
            let b = &store.battery;
            if let Some(p) = b.level_percentage {
                return Some(Value::Num(p as f64));
            }
            // not sent directly: derive it from the energy values if both are known
            match (b.level_wh, b.capacity_wh) {
                (Some(l), Some(c)) if c > 0 => Some(Value::Num(l as f64 * 100.0 / c as f64)),
                _ => None,
            }
        }
        "battery_level_wh" => store.battery.level_wh.map(|v| Value::Int(v as i64)),
        "battery_capacity_wh" => store.battery.capacity_wh.map(|v| Value::Int(v as i64)),
        "reference_air_density" => store
            .battery
            .reference_air_density
            .map(|v| Value::Num(v as f64)),
        "external_temp_celsius" => store
            .battery
            .external_temp_celsius
            .map(|v| Value::Num(v as f64)),

        // --- vehicle speed (topic `speed`, in 1/1000 m/s) ---
        "speed_ms" | "speed_kmh" | "speed_mph" => {
            let raw = fresh(store, "speed", now, Some(SPEED_MAX_AGE))?;
            let ms = raw.trim().parse::<f64>().ok()? / 1000.0;
            Some(Value::Num(match name {
                "speed_ms" => ms,
                "speed_kmh" => ms * 3.6,
                _ => ms * 2.236_936_292_054_402,
            }))
        }

        // --- odometer (topic `odometer`, in 0.1 km) ---
        "odometer_km" | "trip_km" => {
            let raw = fresh(store, "odometer", now, None)?;
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            let key = if name == "odometer_km" {
                "kms"
            } else {
                "trip_kms"
            };
            json_f64(v.get(key)?).map(|e1| Value::Num(e1 / 10.0))
        }

        // --- tire pressure (topic `tpms`, in 0.01 kPa) ---
        n if n.starts_with("tire_pressure_") => {
            let rest = &n["tire_pressure_".len()..];
            let (pos, unit) = rest.split_once('_')?;
            let idx = match pos {
                "fl" => 0,
                "fr" => 1,
                "rl" => 2,
                "rr" => 3,
                _ => return None,
            };
            let raw = fresh(store, "tpms", now, None)?;
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            let kpa = json_f64(v.get("tire_pressures")?.get(idx)?)? / 100.0;
            match unit {
                "kpa" => Some(Value::Num(kpa)),
                "bar" => Some(Value::Num(kpa / 100.0)),
                "psi" => Some(Value::Num(kpa / KPA_PER_PSI)),
                _ => None,
            }
        }

        // --- EV range estimate (topic `vehicle_energy_forecast`) ---
        "range_km" => {
            let raw = fresh(store, "vehicle_energy_forecast", now, None)?;
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            let m = json_f64(v.get("distance_to_empty")?.get("distance_meters")?)?;
            Some(Value::Num(m / 1000.0))
        }

        // --- clock (device local time) ---
        "time" => Some(Value::Text(
            chrono::Local::now().format("%H:%M").to_string(),
        )),
        "time_sec" => Some(Value::Text(
            chrono::Local::now().format("%H:%M:%S").to_string(),
        )),
        "date" => Some(Value::Text(
            chrono::Local::now().format("%Y-%m-%d").to_string(),
        )),

        // --- any websocket topic: ws.<topic>[.<json path>] ---
        n if n.starts_with("ws.") => lookup_ws(store, &n[3..]),

        _ => None,
    }
}

/// `topic` or `topic.path.to.field` (JSON object keys / array indexes) of the latest payload.
fn lookup_ws(store: &Store, path: &str) -> Option<Value> {
    // topics may contain dots themselves: use the longest matching topic
    let topic = store
        .ws
        .keys()
        .filter(|t| path == t.as_str() || path.starts_with(&format!("{}.", t)))
        .max_by_key(|t| t.len())?;
    let payload = &store.ws.get(topic)?.payload;
    let rest = path[topic.len()..].trim_start_matches('.');

    if rest.is_empty() {
        return Some(parse_scalar(payload));
    }

    let mut cur: serde_json::Value = serde_json::from_str(payload).ok()?;
    for seg in rest.split('.') {
        cur = match cur {
            serde_json::Value::Object(mut m) => m.remove(seg)?,
            serde_json::Value::Array(mut a) => {
                let i: usize = seg.parse().ok()?;
                if i >= a.len() {
                    return None;
                }
                a.swap_remove(i)
            }
            _ => return None,
        };
    }
    match cur {
        serde_json::Value::Null => None,
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Some(Value::Int(i)),
            None => n.as_f64().filter(|f| f.is_finite()).map(Value::Num),
        },
        serde_json::Value::String(s) => Some(Value::Text(s)),
        other => Some(Value::Text(other.to_string())),
    }
}

fn parse_scalar(s: &str) -> Value {
    let t = s.trim();
    if let Ok(i) = t.parse::<i64>() {
        return Value::Int(i);
    }
    match t.parse::<f64>() {
        Ok(f) if f.is_finite() => Value::Num(f),
        _ => Value::Text(s.to_string()),
    }
}

// ============================================================================
// TEMPLATE ENGINE
// ============================================================================

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn format_value(v: &Value, decimals: Option<usize>) -> String {
    match v {
        Value::Int(i) => match decimals {
            Some(n) => format!("{:.*}", n, *i as f64),
            None => i.to_string(),
        },
        Value::Num(f) => match decimals {
            Some(n) => format!("{:.*}", n, f),
            None => {
                // up to one decimal, without a trailing ".0"
                let s = format!("{:.1}", f);
                s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
            }
        },
        Value::Text(t) => {
            let truncated: String = t.chars().take(MAX_VALUE_CHARS).collect();
            escape_html(&truncated)
        }
    }
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Replaces every `{{ name[:decimals][ | fallback] }}` in `text`. Unknown or unavailable values
/// give the fallback (or an empty string); a malformed placeholder is left untouched.
pub fn expand_templates(text: &str, resolve: &dyn Fn(&str) -> Option<Value>) -> String {
    if !text.contains("{{") {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut count = 0usize;

    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let inner = &after[..end];
        let (spec, fallback) = match inner.split_once('|') {
            Some((s, f)) => (s, Some(f.trim())),
            None => (inner, None),
        };
        let (name, decimals) = match spec.split_once(':') {
            Some((n, d)) => (n.trim(), d.trim().parse::<usize>().ok().map(|d| d.min(6))),
            None => (spec.trim(), None),
        };

        if !is_valid_name(name) || count >= MAX_PLACEHOLDERS {
            // not a placeholder: keep it as it is
            out.push_str(&rest[start..start + 2 + end + 2]);
        } else {
            count += 1;
            match resolve(name) {
                Some(v) => out.push_str(&format_value(&v, decimals)),
                None => out.push_str(fallback.unwrap_or("")),
            }
        }
        rest = &after[end + 2..];

        if out.len() > MAX_EXPANDED_BYTES {
            break;
        }
    }
    out.push_str(rest);

    if out.len() > MAX_EXPANDED_BYTES {
        let mut cut = MAX_EXPANDED_BYTES;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(topics: &[(&str, &str)]) -> (Store, Instant) {
        let now = Instant::now();
        let mut s = Store::default();
        for (t, p) in topics {
            s.set_ws(t, p, now);
        }
        (s, now)
    }

    fn batt(pct: Option<f32>, wh: Option<u64>, cap: Option<u64>) -> BatteryData {
        BatteryData {
            battery_level_percentage: pct,
            battery_level_wh: wh,
            battery_capacity_wh: cap,
            reference_air_density: None,
            external_temp_celsius: None,
        }
    }

    #[test]
    fn plain_text_is_unchanged() {
        let (s, now) = store_with(&[]);
        assert_eq!(
            expand_with(&s, now, "no placeholders {x}"),
            "no placeholders {x}"
        );
    }

    #[test]
    fn battery_percentage_and_formatting() {
        let (mut s, now) = store_with(&[]);
        s.merge_battery(&batt(Some(63.456), None, None));
        assert_eq!(
            expand_with(&s, now, "SoC {{battery_level_percentage}}%"),
            "SoC 63.5%"
        );
        assert_eq!(
            expand_with(&s, now, "{{ battery_level_percentage : 0 }}"),
            "63"
        );
        assert_eq!(
            expand_with(&s, now, "{{battery_level_percentage:2}}"),
            "63.46"
        );
    }

    #[test]
    fn battery_fields_are_merged_and_percentage_is_derived() {
        let (mut s, now) = store_with(&[]);
        s.merge_battery(&batt(None, Some(25_000), Some(100_000)));
        assert_eq!(expand_with(&s, now, "{{battery_level_percentage}}"), "25");
        s.merge_battery(&batt(None, Some(50_000), None)); // capacity is kept
        assert_eq!(expand_with(&s, now, "{{battery_level_percentage}}"), "50");
        assert_eq!(expand_with(&s, now, "{{battery_capacity_wh}}"), "100000");
    }

    #[test]
    fn missing_values_use_fallback_or_empty() {
        let (s, now) = store_with(&[]);
        assert_eq!(expand_with(&s, now, "[{{speed_kmh|--}}]"), "[--]");
        assert_eq!(expand_with(&s, now, "[{{speed_kmh}}]"), "[]");
        assert_eq!(expand_with(&s, now, "[{{no_such_name | n/a }}]"), "[n/a]");
    }

    #[test]
    fn speed_units_and_staleness() {
        let (s, now) = store_with(&[("speed", "25000")]); // 25 m/s
        assert_eq!(expand_with(&s, now, "{{speed_ms}}"), "25");
        assert_eq!(expand_with(&s, now, "{{speed_kmh:0}}"), "90");
        assert_eq!(expand_with(&s, now, "{{speed_mph:1}}"), "55.9");
        let later = now + SPEED_MAX_AGE + Duration::from_secs(1);
        assert_eq!(expand_with(&s, later, "{{speed_kmh|--}}"), "--");
    }

    #[test]
    fn odometer_tires_and_range() {
        let (s, now) = store_with(&[
            ("odometer", r#"{"kms":123456,"trip_kms":null}"#),
            ("tpms", r#"{"tire_pressures":[230,235,240,245]}"#.replace("230", "23000").replace("235", "23500").replace("240", "24000").replace("245", "24500").as_str()),
            (
                "vehicle_energy_forecast",
                r#"{"distance_to_empty":{"distance_meters":187500,"arrival_battery_energy_wh":null}}"#,
            ),
        ]);
        assert_eq!(expand_with(&s, now, "{{odometer_km}}"), "12345.6");
        assert_eq!(expand_with(&s, now, "[{{trip_km|-}}]"), "[-]");
        assert_eq!(expand_with(&s, now, "{{tire_pressure_fl_kpa:0}}"), "230");
        assert_eq!(expand_with(&s, now, "{{tire_pressure_fr_bar:2}}"), "2.35");
        assert_eq!(expand_with(&s, now, "{{tire_pressure_rl_psi:1}}"), "34.8");
        assert_eq!(expand_with(&s, now, "{{range_km}}"), "187.5");
    }

    #[test]
    fn generic_ws_topics_and_json_paths() {
        let (s, now) = store_with(&[
            ("gear", "D"),
            ("engine.temp", r#"{"coolant":{"c":92.4},"cells":[3.1,3.2]}"#),
            ("count", "42"),
        ]);
        assert_eq!(expand_with(&s, now, "{{ws.gear}}"), "D");
        assert_eq!(expand_with(&s, now, "{{ws.count}}"), "42");
        assert_eq!(expand_with(&s, now, "{{ws.engine.temp.coolant.c}}"), "92.4");
        assert_eq!(expand_with(&s, now, "{{ws.engine.temp.cells.1}}"), "3.2");
        assert_eq!(
            expand_with(&s, now, "[{{ws.engine.temp.cells.9|x}}]"),
            "[x]"
        );
        assert_eq!(expand_with(&s, now, "[{{ws.unknown|x}}]"), "[x]");
    }

    #[test]
    fn text_values_are_html_escaped() {
        let (s, now) = store_with(&[("evil", "<b>x</b> & <font color=red>")]);
        assert_eq!(
            expand_with(&s, now, "{{ws.evil}}"),
            "&lt;b&gt;x&lt;/b&gt; &amp; &lt;font color=red&gt;"
        );
    }

    #[test]
    fn malformed_placeholders_are_kept() {
        let (s, now) = store_with(&[]);
        assert_eq!(
            expand_with(&s, now, "a {{ unterminated"),
            "a {{ unterminated"
        );
        assert_eq!(expand_with(&s, now, "{{bad name!}}"), "{{bad name!}}");
        assert_eq!(expand_with(&s, now, "{{}}"), "{{}}");
    }

    #[test]
    fn limits_are_enforced() {
        let (mut s, now) = store_with(&[]);
        for i in 0..(MAX_WS_TOPICS + 10) {
            s.set_ws(&format!("t{i}"), "1", now);
        }
        assert_eq!(s.ws.len(), MAX_WS_TOPICS);
        s.set_ws("t0", &"x".repeat(MAX_WS_PAYLOAD_BYTES + 1), now);
        assert_eq!(s.ws.get("t0").unwrap().payload, "1");

        let long = "{{ws.t1}}".repeat(5000);
        assert!(expand_with(&s, now, &long).len() <= MAX_EXPANDED_BYTES);
    }

    #[test]
    fn clock_values_have_expected_shape() {
        let (s, now) = store_with(&[]);
        let t = expand_with(&s, now, "{{time}}");
        assert_eq!(t.len(), 5);
        assert_eq!(&t[2..3], ":");
        assert_eq!(expand_with(&s, now, "{{date}}").len(), 10);
    }
}
