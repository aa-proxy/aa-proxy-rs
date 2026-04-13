use anyhow::{Context, Result};
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use simplelog::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Runtime;
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

pub fn start_wasm_engine(runtime: &mut Runtime, hook_dir: &str) -> Result<Arc<ScriptRegistry>> {
    let script_registry = Arc::new(ScriptRegistry::new());
    script_registry.reload_dir("/data/wasm-hooks");

    let errs: Vec<(std::path::PathBuf, String)> = script_registry.list_errors();
    for (path, err) in errs {
        error!(
            "initial wasm script load error [{}]: {}",
            path.display(),
            err
        );
    }

    info!(
        "initial loaded wasm script count={}",
        script_registry.list_scripts().len()
    );

    let (watch_tx, mut watch_rx) = mpsc::unbounded_channel();

    let mut wasm_watcher = recommended_watcher(move |res: notify::Result<notify::Event>| {
        let _ = watch_tx.send(res);
    })
    .expect("failed to create wasm watcher");

    wasm_watcher
        .watch(
            std::path::Path::new("/data/wasm-hooks"),
            RecursiveMode::NonRecursive,
        )
        .expect("failed to watch /data/wasm-hooks");

    let script_registry_for_watch = script_registry.clone();
    runtime.spawn(async move {
        while let Some(res) = watch_rx.recv().await {
            match res {
                Ok(event) => match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        script_registry_for_watch.reload_dir("/data/wasm-hooks");

                        let errs: Vec<(std::path::PathBuf, String)> =
                            script_registry_for_watch.list_errors();
                        for (path, err) in errs {
                            error!("wasm script load error [{}]: {}", path.display(), err);
                        }

                        info!(
                            "loaded wasm script count={}",
                            script_registry_for_watch.list_scripts().len()
                        );
                    }
                    _ => {}
                },
                Err(err) => {
                    error!("wasm watcher error: {}", err);
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

#[derive(Clone, Debug, Default)]
pub struct ScriptEffects {
    pub replacement: Option<host::Packet>,
    pub packets: Vec<host::Packet>,
}

pub struct ScriptState {
    pub effects: ScriptEffects,
    pub limits: StoreLimits,
}

impl ScriptState {
    fn new() -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(5 * 1024 * 1024)
            .instances(16)
            .memories(4)
            .tables(8)
            .table_elements(512)
            .build();

        Self {
            effects: ScriptEffects::default(),
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
}

pub struct WasmScriptEngine {
    engine: Engine,
    component: Component,
    linker: Linker<ScriptState>,
    pub path: PathBuf,
}

impl WasmScriptEngine {
    pub fn load(component_path: impl AsRef<Path>) -> Result<Self> {
        let mut cfg = Config::new();
        cfg.async_support(false);
        cfg.wasm_component_model(true);
        cfg.epoch_interruption(true);

        let engine = Engine::new(&cfg)?;
        let path = component_path.as_ref().to_path_buf();

        let component = Component::from_file(&engine, &path)
            .with_context(|| format!("loading wasm component {}", path.display()))?;

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
        })
    }

    pub async fn run(
        &self,
        ctx: WasmModifyContext,
        pkt: WasmPacket,
        cfg: ConfigView,
    ) -> Result<(Decision, ScriptEffects)> {
        let mut store = Store::new(&self.engine, ScriptState::new());
        store.limiter(|state| &mut state.limits);
        store.set_epoch_deadline(1);

        let bindings =
            PacketHook::instantiate_async(&mut store, &self.component, &self.linker).await?;

        let decision = bindings
            .call_modify_packet(&mut store, &ctx, &pkt, cfg)
            .with_context(|| format!("running wasm script {}", self.path.display()))?;

        Ok((decision, store.data().effects.clone()))
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

#[derive(Clone, Default)]
pub struct ScriptRegistry {
    inner: Arc<RwLock<ScriptRegistryInner>>,
}

#[derive(Default)]
struct ScriptRegistryInner {
    scripts: Vec<LoadedScript>,
    errors: HashMap<PathBuf, String>,
}

impl ScriptRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reload_dir(&self, dir: impl AsRef<Path>) {
        let dir = dir.as_ref();
        let mut scripts = Vec::<LoadedScript>::new();
        let mut errors = HashMap::<PathBuf, String>::new();

        let entries = match fs::read_dir(dir) {
            Ok(v) => v,
            Err(e) => {
                errors.insert(dir.to_path_buf(), format!("read_dir failed: {e}"));
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

            match WasmScriptEngine::load(&path) {
                Ok(engine) => {
                    log::info!("loaded wasm script: {}", path.display());
                    scripts.push(LoadedScript {
                        path: path.clone(),
                        engine: Arc::new(engine),
                    });
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    log::error!("failed to load wasm script {}: {}", path.display(), msg);
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
