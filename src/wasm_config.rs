use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde_json::{json, Number, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use toml_edit::{value, DocumentMut, Item, Table};

pub const WASM_CONFIG_FILE: &str = "/etc/aa-proxy-rs/wasm-config.toml";
pub const WASM_CONFIG_KEY_PREFIX: &str = "wasm.";

#[derive(Clone, Debug)]
pub struct WasmConfigStore {
    path: PathBuf,
    values: Arc<RwLock<IndexMap<String, IndexMap<String, Value>>>>,
}

impl Default for WasmConfigStore {
    fn default() -> Self {
        Self::load_default()
    }
}

impl WasmConfigStore {
    pub fn load_default() -> Self {
        Self::load_from_path(WASM_CONFIG_FILE)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let values = match fs::read_to_string(&path) {
            Ok(raw) => parse_values(&raw).unwrap_or_else(|err| {
                log::warn!(
                    "[wasm] failed to parse wasm config file {}: {err:#}",
                    path.display()
                );
                IndexMap::new()
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => IndexMap::new(),
            Err(err) => {
                log::warn!(
                    "[wasm] failed to read wasm config file {}: {err}",
                    path.display()
                );
                IndexMap::new()
            }
        };

        Self {
            path,
            values: Arc::new(RwLock::new(values)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get_json(&self, script_id: &str, name: &str) -> Option<Value> {
        let values = self.values.read().ok()?;
        values.get(script_id)?.get(name).cloned()
    }

    pub fn get_raw(&self, script_id: &str, name: &str) -> Option<String> {
        self.get_json(script_id, name)
            .map(|value| json_value_to_string(&value))
    }

    pub fn ensure_default(&self, script_id: &str, name: &str, default_value: Value) -> Result<()> {
        let mut values = self.values.write().expect("wasm config lock poisoned");
        let script_values = values.entry(script_id.to_string()).or_default();

        if script_values.contains_key(name) {
            return Ok(());
        }

        script_values.insert(name.to_string(), default_value);
        self.save_locked(&values)
    }

    pub fn set_json(&self, script_id: &str, name: &str, value: Value) -> Result<()> {
        let mut values = self.values.write().expect("wasm config lock poisoned");
        values
            .entry(script_id.to_string())
            .or_default()
            .insert(name.to_string(), value);
        self.save_locked(&values)
    }

    fn save_locked(&self, values: &IndexMap<String, IndexMap<String, Value>>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("[wasm] creating wasm config directory {}", parent.display())
            })?;
        }

        let mut doc = DocumentMut::new();

        for (script_id, script_values) in values {
            let mut table = Table::new();

            for (key, value) in script_values {
                table[key.as_str()] = json_to_toml_item(value);
            }

            doc[script_id.as_str()] = Item::Table(table);
        }

        fs::write(&self.path, doc.to_string())
            .with_context(|| format!("[wasm] writing wasm config file {}", self.path.display()))
    }
}

pub fn script_id_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script");

    let mut result = String::with_capacity(stem.len());

    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            result.push(ch);
        } else {
            result.push('_');
        }
    }

    if result.is_empty() {
        "script".to_string()
    } else {
        result
    }
}

pub fn wasm_config_key(script_id: &str, name: &str) -> String {
    format!("{WASM_CONFIG_KEY_PREFIX}{script_id}.{name}")
}

pub fn parse_wasm_config_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix(WASM_CONFIG_KEY_PREFIX)?;
    let mut parts = rest.splitn(2, '.');
    let script_id = parts.next()?;
    let name = parts.next()?;

    if script_id.is_empty() || name.is_empty() {
        None
    } else {
        Some((script_id, name))
    }
}

pub fn parse_config_value(typ: &str, raw: &str) -> Value {
    match typ {
        "boolean" => raw
            .parse::<bool>()
            .map(Value::Bool)
            .unwrap_or(Value::Bool(false)),
        "integer" => raw
            .parse::<i64>()
            .map(|v| json!(v))
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        "float" => raw
            .parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(raw.to_string())),
        _ => Value::String(raw.to_string()),
    }
}

pub fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => v.clone(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn parse_values(raw: &str) -> Result<IndexMap<String, IndexMap<String, Value>>> {
    let doc = raw
        .parse::<DocumentMut>()
        .context("[wasm] parsing wasm config toml")?;

    let mut result = IndexMap::new();

    for (script_id, item) in doc.iter() {
        let Some(table) = item.as_table() else {
            continue;
        };

        let mut script_values = IndexMap::new();

        for (key, item) in table.iter() {
            if let Some(value) = toml_item_to_json(item) {
                script_values.insert(key.to_string(), value);
            }
        }

        if !script_values.is_empty() {
            result.insert(script_id.to_string(), script_values);
        }
    }

    Ok(result)
}

fn toml_item_to_json(item: &Item) -> Option<Value> {
    let value = item.as_value()?;

    if let Some(v) = value.as_bool() {
        return Some(Value::Bool(v));
    }

    if let Some(v) = value.as_integer() {
        return Some(json!(v));
    }

    if let Some(v) = value.as_float() {
        return Number::from_f64(v).map(Value::Number);
    }

    if let Some(v) = value.as_str() {
        return Some(Value::String(v.to_string()));
    }

    None
}

fn json_to_toml_item(value_json: &Value) -> Item {
    match value_json {
        Value::Bool(v) => value(*v),
        Value::Number(v) => {
            if let Some(i) = v.as_i64() {
                value(i)
            } else if let Some(u) = v.as_u64() {
                if let Ok(i) = i64::try_from(u) {
                    value(i)
                } else if let Some(f) = v.as_f64() {
                    value(f)
                } else {
                    value(v.to_string())
                }
            } else if let Some(f) = v.as_f64() {
                value(f)
            } else {
                value(v.to_string())
            }
        }
        Value::String(v) => value(v.as_str()),
        Value::Null => value(""),
        Value::Array(_) | Value::Object(_) => value(value_json.to_string()),
    }
}
