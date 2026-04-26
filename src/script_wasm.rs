use crate::web::ServerEvent;
use anyhow::{Context, Result};
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use simplelog::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::config::AppConfig;
use crate::mitm::ModifyContext;
use crate::mitm::Packet;

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "packet-hook"
    });
}

use self::bindings::aa::packet::host;
use self::bindings::aa::packet::types::{
    ConfigView, Decision, ModifyContext as WasmModifyContext, Packet as WasmPacket, ProxyType,
};
use self::bindings::PacketHook;

pub fn start_wasm_engine(
    runtime: &mut Runtime,
    hook_dir: String,
    script_parameters: ScriptParameters,
) -> Result<Arc<ScriptRegistry>> {
    let script_registry = Arc::new(ScriptRegistry::new(script_parameters));
    script_registry.reload_dir(&hook_dir);

    let errs: Vec<(std::path::PathBuf, String)> = script_registry.list_errors();
    for (path, err) in errs {
        error!(
            "[wasm] initial wasm script load error [{}]: {}",
            path.display(),
            err
        );
    }

    info!(
        "[wasm] initial loaded wasm script count={}",
        script_registry.list_scripts().len()
    );

    let (watch_tx, mut watch_rx) = mpsc::unbounded_channel();

    let mut wasm_watcher = recommended_watcher(move |res: notify::Result<notify::Event>| {
        let _ = watch_tx.send(res);
    })?;

    wasm_watcher
        .watch(std::path::Path::new(&hook_dir), RecursiveMode::NonRecursive)
        .map_err(|e| anyhow::anyhow!("[wasm] failed to watch {}: {}", hook_dir, e))?;

    let script_registry_for_watch = script_registry.clone();
    runtime.spawn(async move {
        while let Some(res) = watch_rx.recv().await {
            match res {
                Ok(event) => match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        script_registry_for_watch.reload_dir(&hook_dir);

                        let errs: Vec<(std::path::PathBuf, String)> =
                            script_registry_for_watch.list_errors();
                        for (path, err) in errs {
                            error!("[wasm] script load error [{}]: {}", path.display(), err);
                        }

                        info!(
                            "[wasm] loaded wasm script count={}",
                            script_registry_for_watch.list_scripts().len()
                        );
                    }
                    _ => {}
                },
                Err(err) => {
                    error!("[wasm] watcher error: {}", err);
                }
            }
        }
    });

    let script_registry_for_tick = script_registry.clone();
    runtime.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            script_registry_for_tick.tick_all();
        }
    });

    Ok(script_registry)
}

#[derive(Clone, Debug)]
pub struct ScriptEffects {
    pub replacement: Option<host::Packet>,
    pub packets: Vec<host::Packet>,
    pub script_parameters: ScriptParameters,
}

impl ScriptEffects {
    pub fn new(script_parameters: ScriptParameters) -> Self {
        Self {
            replacement: None,
            packets: Vec::new(),
            script_parameters,
        }
    }
}
pub struct ScriptState {
    pub effects: ScriptEffects,
    pub limits: StoreLimits,
}

#[derive(Clone, Debug)]
pub struct ScriptParameters {
    pub ws_event_tx: BroadcastSender<ServerEvent>,
}

impl ScriptState {
    fn new(script_parameters: ScriptParameters) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(5 * 1024 * 1024)
            .instances(16)
            .memories(4)
            .tables(8)
            .table_elements(512)
            .build();

        Self {
            effects: ScriptEffects::new(script_parameters),
            limits,
        }
    }
}

impl host::Host for ScriptState {
    fn replace_current(&mut self, pkt: host::Packet) {
        self.effects.replacement = Some(pkt);
    }

    fn send(&mut self, pkt: host::Packet) {
        self.effects.packets.push(pkt);
    }

    fn info(&mut self, msg: String) {
        log::info!("[wasm] {}", msg);
    }

    fn error(&mut self, msg: String) {
        log::error!("[wasm] {}", msg);
    }

    fn send_ws_event(&mut self, topic: String, payload: String) -> bool {
        match self
            .effects
            .script_parameters
            .ws_event_tx
            .send(ServerEvent { topic, payload })
        {
            Ok(_) => true,
            Err(err) => {
                log::warn!("[wasm] failed to send websocket event from wasm host: {err}");
                false
            }
        }
    }

    fn rest_call(&mut self, method: String, path: String, body: String) -> String {
        rest_call_blocking(method, path, body)
    }

    fn rest_call_async(&mut self, method: String, path: String, body: String) -> String {
        let request_id = uuid::Uuid::new_v4().to_string();

        let tx = self.effects.script_parameters.ws_event_tx.clone();
        let request_id_for_task = request_id.clone();

        std::thread::spawn(move || {
            let result_payload = rest_call_blocking(method.clone(), path.clone(), body);

            let payload = serde_json::json!({
                "requestId": request_id_for_task,
                "method": method,
                "path": path,
                "result": result_payload,
            })
            .to_string();

            let _ = tx.send(ServerEvent {
                topic: SCRIPT_REST_RESULT_TOPIC.to_string(),
                payload,
            });
        });

        request_id
    }

    fn rest_result_topic(&mut self) -> String {
        SCRIPT_REST_RESULT_TOPIC.to_string()
    }
}

pub struct WasmScriptEngine {
    engine: Engine,
    component: Component,
    linker: Linker<ScriptState>,
    pub path: PathBuf,
    script_parameters: ScriptParameters,
}

impl WasmScriptEngine {
    pub fn load(
        component_path: impl AsRef<Path>,
        script_parameters: ScriptParameters,
    ) -> Result<Self> {
        let mut cfg = Config::new();
        cfg.async_support(false);
        cfg.wasm_component_model(true);
        cfg.epoch_interruption(true);

        let engine = Engine::new(&cfg)?;
        let path = component_path.as_ref().to_path_buf();

        let component = Component::from_file(&engine, &path)
            .with_context(|| format!("[wasm] loading wasm component {}", path.display()))?;

        let mut linker = Linker::<ScriptState>::new(&engine);
        bindings::aa::packet::host::add_to_linker::<ScriptState, HasSelf<ScriptState>>(
            &mut linker,
            |s| s,
        )?;

        Ok(Self {
            engine,
            component,
            linker,
            path,
            script_parameters,
        })
    }

    pub async fn modify_packet(
        &self,
        ctx: WasmModifyContext,
        pkt: WasmPacket,
        cfg: ConfigView,
    ) -> Result<(Decision, ScriptEffects)> {
        let mut store = Store::new(
            &self.engine,
            ScriptState::new(self.script_parameters.clone()),
        );
        store.limiter(|state| &mut state.limits);
        store.set_epoch_deadline(100);

        let bindings =
            PacketHook::instantiate_async(&mut store, &self.component, &self.linker).await?;

        let decision = bindings
            .call_modify_packet(&mut store, &ctx, &pkt, cfg)
            .with_context(|| format!("[wasm] running wasm script {}", self.path.display()))?;

        Ok((decision, store.data().effects.clone()))
    }

    pub async fn ws_script_handler(
        &self,
        topic: String,
        payload: String,
    ) -> Result<(String, ScriptEffects)> {
        let mut store = Store::new(
            &self.engine,
            ScriptState::new(self.script_parameters.clone()),
        );
        store.limiter(|state: &mut ScriptState| &mut state.limits);
        store.set_epoch_deadline(1000);

        let bindings =
            PacketHook::instantiate_async(&mut store, &self.component, &self.linker).await?;

        let payload = bindings
            .call_ws_script_handler(&mut store, &topic, &payload)
            .with_context(|| format!("[wasm] running wasm script {}", self.path.display()))?;

        Ok((payload, store.data().effects.clone()))
    }

    pub fn tick_epoch(&self) {
        self.engine.increment_epoch();
    }
}

#[derive(Clone)]
pub struct LoadedScript {
    pub path: PathBuf,
    pub engine: Arc<WasmScriptEngine>,
}

#[derive(Clone)]
pub struct ScriptRegistry {
    inner: Arc<RwLock<ScriptRegistryInner>>,
}

struct ScriptRegistryInner {
    scripts: Vec<LoadedScript>,
    errors: HashMap<PathBuf, String>,
    script_parameters: ScriptParameters,
}

impl ScriptRegistryInner {
    fn new(script_parameters: ScriptParameters) -> Self {
        Self {
            scripts: Vec::new(),
            errors: HashMap::new(),
            script_parameters,
        }
    }
}

impl ScriptRegistry {
    pub fn new(script_parameters: ScriptParameters) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ScriptRegistryInner::new(script_parameters))),
        }
    }

    pub fn reload_dir(&self, dir: impl AsRef<Path>) {
        let script_parameters = {
            let g = self.inner.read().unwrap();
            g.script_parameters.clone()
        };

        let dir = dir.as_ref();
        let mut scripts = Vec::<LoadedScript>::new();
        let mut errors = HashMap::<PathBuf, String>::new();

        let entries = match fs::read_dir(dir) {
            Ok(v) => v,
            Err(e) => {
                errors.insert(dir.to_path_buf(), format!("[wasm] read_dir failed: {e}"));
                let mut g = self.inner.write().unwrap();
                g.scripts.clear();
                g.errors = errors;
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let is_wasm = path.extension().and_then(|s| s.to_str()) == Some("wasm");
            if !is_wasm {
                continue;
            }

            match WasmScriptEngine::load(&path, script_parameters.clone()) {
                Ok(engine) => {
                    log::info!("[wasm] loaded wasm script: {}", path.display());
                    scripts.push(LoadedScript {
                        path: path.clone(),
                        engine: Arc::new(engine),
                    });
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    log::error!(
                        "[wasm] failed to load wasm script {}: {}",
                        path.display(),
                        msg
                    );
                    errors.insert(path.clone(), msg);
                }
            }
        }

        scripts.sort_by(|a, b| a.path.cmp(&b.path));

        let mut g = self.inner.write().unwrap();
        g.scripts = scripts;
        g.errors = errors;
    }

    pub fn list_scripts(&self) -> Vec<LoadedScript> {
        self.inner.read().unwrap().scripts.clone()
    }

    pub fn list_errors(&self) -> Vec<(PathBuf, String)> {
        self.inner
            .read()
            .unwrap()
            .errors
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn tick_all(&self) {
        for script in self.list_scripts() {
            script.engine.tick_epoch();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ScriptProxyType {
    HeadUnit,
    MobileDevice,
}

const SCRIPT_REST_RESULT_TOPIC: &str = "script.rest.result";

fn rest_call_blocking(method: String, path: String, body: String) -> String {
    let path = path.trim();

    //Whitelist calls
    match (method.as_str(), path) {
        ("POST", "/battery")
        | ("POST", "/odometer")
        | ("POST", "/tire-pressure")
        | ("POST", "/inject_event")
        | ("POST", "/inject_rotary")
        | ("GET", "/speed")
        | ("GET", "/battery-status")
        | ("GET", "/odometer-status")
        | ("GET", "/tire-pressure-status") => {}

        _ => {
            return format!(
                r#"{{"ok":false,"status":403,"error":"route not allowed from script: {} {}"}}"#,
                method, path
            );
        }
    }

    let url = format!("http://127.0.0.1{}", path);

    let result = match method.as_str() {
        "GET" => ureq::get(&url).call(),

        "POST" => ureq::post(&url)
            .set("content-type", "application/json")
            .send_string(&body),

        _ => {
            return r#"{"ok":false,"status":405,"error":"unsupported method"}"#.to_string();
        }
    };

    match result {
        Ok(response) => {
            let status = response.status();

            let text = response.into_string().unwrap_or_else(|err| {
                format!(
                    r#"{{"ok":false,"error":"failed to read response: {}"}}"#,
                    err
                )
            });

            format!(
                r#"{{"ok":true,"status":{},"body":{}}}"#,
                status,
                serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_string())
            )
        }

        Err(err) => {
            log::warn!("wasm rest_call failed: {err}");

            format!(
                r#"{{"ok":false,"status":500,"error":{}}}"#,
                serde_json::to_string(&err.to_string())
                    .unwrap_or_else(|_| "\"request failed\"".to_string())
            )
        }
    }
}

pub fn to_wasm_modify_context(ctx: &ModifyContext) -> WasmModifyContext {
    WasmModifyContext {
        sensor_channel: ctx.sensor_channel,
        nav_channel: ctx.nav_channel,
        audio_channels: ctx.audio_channels.clone(),
    }
}

pub fn to_wasm_packet(proxy_type: ScriptProxyType, pkt: &Packet) -> Result<WasmPacket> {
    let message_id = if pkt.payload.len() >= 2 {
        u16::from_be_bytes([pkt.payload[0], pkt.payload[1]])
    } else {
        0
    };

    Ok(WasmPacket {
        proxy_type: match proxy_type {
            ScriptProxyType::HeadUnit => ProxyType::HeadUnit,
            ScriptProxyType::MobileDevice => ProxyType::MobileDevice,
        },
        channel: pkt.channel,
        packet_flags: pkt.flags,
        final_length: pkt.final_length,
        message_id,
        payload: pkt.payload.clone(),
    })
}

pub fn from_wasm_packet(pkt: WasmPacket) -> Packet {
    Packet {
        channel: pkt.channel,
        flags: pkt.packet_flags,
        final_length: pkt.final_length,
        payload: pkt.payload,
    }
}

pub fn apply_wasm_packet(dst: &mut Packet, src: WasmPacket) {
    dst.channel = src.channel;
    dst.flags = src.packet_flags;
    dst.final_length = src.final_length;
    dst.payload = src.payload;
}

pub fn to_wasm_cfg(cfg: &AppConfig) -> ConfigView {
    ConfigView {
        audio_max_unacked: cfg.audio_max_unacked as u32,
        remove_tap_restriction: cfg.remove_tap_restriction,
        video_in_motion: cfg.video_in_motion,
        developer_mode: cfg.developer_mode,
        ev: cfg.ev,
        waze_lht_workaround: cfg.waze_lht_workaround,
    }
}
