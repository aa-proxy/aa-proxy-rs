use crate::config::{AppConfig, ConfigJson, ConfigValue, ConfigValues, SharedConfig};
use crate::mitm::ModifyContext;
use crate::mitm::Packet;
use crate::vendor_ext::rest_call_blocking;
use crate::wasm_config::{
    json_value_to_string, parse_config_value, parse_wasm_config_key, script_id_from_path,
    wasm_config_key, WasmConfigStore,
};
use crate::web::ServerEvent;
use anyhow::{Context, Result};
use indexmap::IndexMap;
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use serde_json::Value;
use simplelog::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::{broadcast::Sender as BroadcastSender, mpsc, Mutex};
use wasmtime::component::{Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Default host-side WASM hooks root. The active value comes from AppConfig::wasm_hooks_dir.
pub const WASM_HOOKS_DIR: &str = crate::config::DEFAULT_WASM_HOOKS_DIR;

/// Stable guest-visible mount path. Each script sees only its own private host folder here.
const GUEST_WASM_HOOKS_DIR: &str = ".";

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "packet-hook"
    });
}

use self::bindings::aa::packet::host;
use self::bindings::aa::packet::types::{
    ConfigView, CustomConfigSection, Decision, ModifyContext as WasmModifyContext,
    Packet as WasmPacket, ProxyType,
};
use self::bindings::PacketHook;

pub fn start_wasm_engine(
    runtime: &mut Runtime,
    hook_dir: String,
    script_parameters: ScriptParameters,
) -> Result<Arc<ScriptRegistry>> {
    let hook_dir = PathBuf::from(hook_dir);
    fs::create_dir_all(&hook_dir)
        .with_context(|| format!("[wasm] failed to create hooks dir {}", hook_dir.display()))?;

    let script_registry = Arc::new(ScriptRegistry::new(script_parameters));

    let old_scripts = script_registry.reload_dir(&hook_dir);
    runtime.block_on(destroy_loaded_scripts(old_scripts));

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
        .watch(&hook_dir, RecursiveMode::NonRecursive)
        .map_err(|e| anyhow::anyhow!("[wasm] failed to watch {}: {}", hook_dir.display(), e))?;

    let script_registry_for_watch = script_registry.clone();
    let hook_dir_for_watch = hook_dir.clone();
    runtime.spawn(async move {
        let _wasm_watcher = wasm_watcher;
        while let Some(res) = watch_rx.recv().await {
            let triggered = match res {
                Ok(event) => matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) && (event.paths.is_empty()
                    || event.paths.iter().any(|p| {
                        p.extension().map(|e| e == "wasm").unwrap_or(false)
                    })),
                Err(err) => {
                    error!("[wasm] watcher error: {}", err);
                    false
                }
            };

            if !triggered {
                continue;
            }

            // Drain any further events that arrive within the debounce window so
            // a multi-write transfer (e.g. scp) only causes a single reload.
            while let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(WASM_RELOAD_DEBOUNCE_MS),
                watch_rx.recv(),
            )
            .await
            {}

            let old_scripts = script_registry_for_watch.reload_dir(&hook_dir_for_watch);
            destroy_loaded_scripts(old_scripts).await;

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
    });

    let script_registry_for_tick = script_registry.clone();
    runtime.spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_millis(WASM_EPOCH_TICK_INTERVAL_MS));
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

const WASM_EPOCH_TICK_INTERVAL_MS: u64 = 10;
const WASM_RELOAD_DEBOUNCE_MS: u64 = 500;

#[derive(Clone, Copy, Debug)]
struct EffectiveScriptLimits {
    memory_limit_mb: u32,
    instance_limit: u32,
    memory_count_limit: u32,
    table_limit: u32,
    table_elements_limit: u32,
    packet_epoch_deadline: u64,
    lifecycle_epoch_deadline: u64,
}

impl EffectiveScriptLimits {
    fn from_config(cfg: &AppConfig) -> Self {
        Self {
            memory_limit_mb: cfg.wasm_script_memory_limit_mb.max(1),
            instance_limit: cfg.wasm_script_instance_limit.max(1),
            memory_count_limit: cfg.wasm_script_memory_count_limit.max(1),
            table_limit: cfg.wasm_script_table_limit.max(1),
            table_elements_limit: cfg.wasm_script_table_elements_limit.max(1),
            packet_epoch_deadline: cfg.wasm_script_packet_epoch_deadline.max(1),
            lifecycle_epoch_deadline: cfg.wasm_script_lifecycle_epoch_deadline.max(1),
        }
    }

    async fn read(config: &SharedConfig) -> Self {
        let cfg = config.read().await;
        Self::from_config(&cfg)
    }

    fn to_store_limits(self) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size((self.memory_limit_mb as usize).saturating_mul(1024 * 1024))
            .instances(self.instance_limit as usize)
            .memories(self.memory_count_limit as usize)
            .tables(self.table_limit as usize)
            .table_elements(self.table_elements_limit as usize)
            .build()
    }
}

pub struct ScriptState {
    pub effects: ScriptEffects,
    pub limits: StoreLimits,
    pub script_id: String,
    pub wasi_ctx: WasiCtx,
    pub resource_table: ResourceTable,
}

impl ScriptState {
    fn new(
        script_parameters: ScriptParameters,
        script_id: String,
        limits: EffectiveScriptLimits,
        hooks_dir: &Path,
    ) -> Self {
        let mut wasi_builder = WasiCtxBuilder::new();

        let real_script_hooks_dir = script_private_hooks_dir(hooks_dir, &script_id)
            .unwrap_or_else(|| hooks_dir.join("unknown"));

        match fs::create_dir_all(&real_script_hooks_dir) {
            Ok(_) => {
                if let Err(err) = wasi_builder.preopened_dir(
                    &real_script_hooks_dir,
                    GUEST_WASM_HOOKS_DIR,
                    DirPerms::READ,
                    FilePerms::READ,
                ) {
                    log::warn!(
                        "[wasm] failed to preopen real dir {} as guest dir {} for script {}: {}",
                        real_script_hooks_dir.display(),
                        GUEST_WASM_HOOKS_DIR,
                        script_id,
                        err
                    );
                }
            }
            Err(err) => {
                log::warn!(
                    "[wasm] failed to create script hooks dir {}; hot reload file access disabled for script {}: {}",
                    real_script_hooks_dir.display(),
                    script_id,
                    err
                );
            }
        }

        Self {
            effects: ScriptEffects::new(script_parameters),
            limits: limits.to_store_limits(),
            script_id,
            wasi_ctx: wasi_builder.build(),
            resource_table: ResourceTable::new(),
        }
    }

    fn reset_effects(&mut self) {
        self.effects = ScriptEffects::new(self.effects.script_parameters.clone());
    }
}

#[derive(Clone, Debug)]
pub struct ScriptParameters {
    pub ws_event_tx: BroadcastSender<ServerEvent>,
    pub wasm_config_store: Arc<WasmConfigStore>,
    pub config: SharedConfig,
}

impl WasiView for ScriptState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
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
        rest_call_blocking(method, path, body, true)
    }

    fn rest_call_async(&mut self, method: String, path: String, body: String) -> String {
        let request_id = uuid::Uuid::new_v4().to_string();

        let tx = self.effects.script_parameters.ws_event_tx.clone();
        let request_id_for_task = request_id.clone();

        std::thread::spawn(move || {
            let result_payload = rest_call_blocking(method.clone(), path.clone(), body, true);

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

    fn get_config(&mut self, name: String) -> Option<String> {
        self.effects
            .script_parameters
            .wasm_config_store
            .get_raw(&self.script_id, &name)
    }
}

struct LiveScript {
    store: Store<ScriptState>,
    bindings: PacketHook,
}

fn run_sync_wasm_call<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

fn script_private_hooks_dir(hooks_dir: &Path, script_id: &str) -> Option<PathBuf> {
    let stem = Path::new(script_id).file_stem().and_then(|s| s.to_str())?;

    let safe_stem: String = stem
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();

    if safe_stem.is_empty() {
        None
    } else {
        Some(hooks_dir.join(safe_stem))
    }
}

pub struct WasmScriptEngine {
    engine: Engine,
    component: Component,
    linker: Linker<ScriptState>,
    pub path: PathBuf,
    script_id: String,
    hooks_dir: PathBuf,
    script_parameters: ScriptParameters,
    live: Mutex<Option<LiveScript>>,
    closed: AtomicBool,
}

impl WasmScriptEngine {
    async fn ensure_live<'a>(
        &'a self,
        live: &'a mut Option<LiveScript>,
        limits: EffectiveScriptLimits,
    ) -> Result<&'a mut LiveScript> {
        if self.closed.load(Ordering::Acquire) {
            anyhow::bail!("[wasm] script is destroyed: {}", self.path.display());
        }

        if live.is_none() {
            let mut store = Store::new(
                &self.engine,
                ScriptState::new(
                    self.script_parameters.clone(),
                    self.script_id.clone(),
                    limits,
                    &self.hooks_dir,
                ),
            );

            store.limiter(|state| &mut state.limits);
            store.set_epoch_deadline(limits.lifecycle_epoch_deadline);

            let bindings =
                PacketHook::instantiate_async(&mut store, &self.component, &self.linker).await?;

            run_sync_wasm_call(|| {
                bindings
                    .call_on_create(&mut store)
                    .with_context(|| format!("[wasm] running on-create {}", self.path.display()))
            })?;

            *live = Some(LiveScript { store, bindings });
        }

        Ok(live.as_mut().unwrap())
    }

    pub fn load(
        component_path: impl AsRef<Path>,
        script_parameters: ScriptParameters,
        hooks_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut cfg = Config::new();
        cfg.async_support(false);
        cfg.wasm_component_model(true);
        cfg.epoch_interruption(true);

        let engine = Engine::new(&cfg)?;
        let path = component_path.as_ref().to_path_buf();
        let script_id = script_id_from_path(&path);
        let hooks_dir = hooks_dir.as_ref().to_path_buf();

        let component = Component::from_file(&engine, &path)
            .with_context(|| format!("[wasm] loading wasm component {}", path.display()))?;

        let mut linker = Linker::<ScriptState>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        bindings::aa::packet::host::add_to_linker::<ScriptState, HasSelf<ScriptState>>(
            &mut linker,
            |s| s,
        )?;

        Ok(Self {
            engine,
            component,
            linker,
            path,
            script_id,
            hooks_dir,
            script_parameters,
            live: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    pub fn script_id(&self) -> &str {
        &self.script_id
    }

    async fn effective_limits(&self) -> EffectiveScriptLimits {
        EffectiveScriptLimits::read(&self.script_parameters.config).await
    }

    fn apply_store_limits(live: &mut LiveScript, limits: EffectiveScriptLimits) {
        live.store.data_mut().limits = limits.to_store_limits();
    }

    pub async fn custom_configs(&self) -> Result<Vec<CustomConfigSection>> {
        let limits = self.effective_limits().await;
        let mut live_guard = self.live.lock().await;
        let live = self.ensure_live(&mut live_guard, limits).await?;

        Self::apply_store_limits(live, limits);
        live.store.data_mut().reset_effects();
        live.store
            .set_epoch_deadline(limits.lifecycle_epoch_deadline);

        let sections = run_sync_wasm_call(|| {
            live.bindings
                .call_custom_configs(&mut live.store)
                .with_context(|| format!("[wasm] running custom-configs {}", self.path.display()))
        })?;

        for section in &sections {
            for entry in &section.values {
                let default_value = parse_config_value(&entry.typ, &entry.default_value);
                if let Err(err) = self.script_parameters.wasm_config_store.ensure_default(
                    &self.script_id,
                    &entry.name,
                    default_value,
                ) {
                    log::warn!(
                        "[wasm] failed to persist default config {}.{}: {err:#}",
                        self.script_id,
                        entry.name
                    );
                }
            }
        }

        Ok(sections)
    }

    pub async fn on_config_changed(&self, name: String, value: Value) -> Result<()> {
        let limits = self.effective_limits().await;
        let mut live_guard = self.live.lock().await;
        let live = self.ensure_live(&mut live_guard, limits).await?;

        Self::apply_store_limits(live, limits);
        live.store.data_mut().reset_effects();
        live.store
            .set_epoch_deadline(limits.lifecycle_epoch_deadline);

        let value = json_value_to_string(&value);
        run_sync_wasm_call(|| {
            live.bindings
                .call_on_config_changed(&mut live.store, &name, &value)
                .with_context(|| {
                    format!("[wasm] running on-config-changed {}", self.path.display())
                })
        })?;

        Ok(())
    }

    pub async fn modify_packet(
        &self,
        ctx: WasmModifyContext,
        pkt: WasmPacket,
        cfg: ConfigView,
    ) -> Result<(Decision, ScriptEffects)> {
        let limits = self.effective_limits().await;
        let mut live_guard = self.live.lock().await;
        let live = self.ensure_live(&mut live_guard, limits).await?;

        Self::apply_store_limits(live, limits);
        live.store.data_mut().reset_effects();
        live.store.set_epoch_deadline(limits.packet_epoch_deadline);

        let decision = run_sync_wasm_call(|| {
            live.bindings
                .call_modify_packet(&mut live.store, &ctx, &pkt, cfg)
                .with_context(|| format!("[wasm] running wasm script {}", self.path.display()))
        })?;

        Ok((decision, live.store.data().effects.clone()))
    }

    pub async fn ws_script_handler(
        &self,
        topic: String,
        payload: String,
    ) -> Result<(String, ScriptEffects)> {
        let limits = self.effective_limits().await;
        let mut live_guard = self.live.lock().await;
        let live = self.ensure_live(&mut live_guard, limits).await?;

        Self::apply_store_limits(live, limits);
        live.store.data_mut().reset_effects();
        live.store
            .set_epoch_deadline(limits.lifecycle_epoch_deadline);

        let payload = run_sync_wasm_call(|| {
            live.bindings
                .call_ws_script_handler(&mut live.store, &topic, &payload)
                .with_context(|| format!("[wasm] running wasm script {}", self.path.display()))
        })?;

        Ok((payload, live.store.data().effects.clone()))
    }

    pub async fn destroy(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);

        let limits = self.effective_limits().await;
        let mut live_guard = self.live.lock().await;

        if let Some(mut live) = live_guard.take() {
            Self::apply_store_limits(&mut live, limits);
            live.store.data_mut().reset_effects();
            live.store
                .set_epoch_deadline(limits.lifecycle_epoch_deadline);

            run_sync_wasm_call(|| {
                live.bindings
                    .call_on_destroy(&mut live.store)
                    .with_context(|| format!("[wasm] running on-destroy {}", self.path.display()))
            })?;
        }

        Ok(())
    }

    pub fn tick_epoch(&self) {
        self.engine.increment_epoch();
    }
}

async fn destroy_loaded_scripts(scripts: Vec<LoadedScript>) {
    for script in scripts {
        if let Err(err) = script.engine.destroy().await {
            error!(
                "[wasm] script destroy error [{}]: {err:#}",
                script.path.display()
            );
        } else {
            info!("[wasm] destroyed wasm script: {}", script.path.display());
        }
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

    pub async fn destroy_all(&self) {
        let old_scripts = {
            let mut g = self.inner.write().unwrap();
            std::mem::take(&mut g.scripts)
        };

        destroy_loaded_scripts(old_scripts).await;
    }

    pub fn reload_dir(&self, dir: impl AsRef<Path>) -> Vec<LoadedScript> {
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
                let old_scripts = std::mem::take(&mut g.scripts);
                g.errors = errors;

                return old_scripts;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let is_wasm = path.extension().and_then(|s| s.to_str()) == Some("wasm");
            if !is_wasm {
                continue;
            }

            match WasmScriptEngine::load(&path, script_parameters.clone(), dir) {
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
        let old_scripts = std::mem::replace(&mut g.scripts, scripts);
        g.errors = errors;

        old_scripts
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

    pub async fn append_custom_config_sections(&self, config_json: &mut ConfigJson) {
        for script in self.list_scripts() {
            let script_id = script.engine.script_id().to_string();
            let sections = match script.engine.custom_configs().await {
                Ok(sections) => sections,
                Err(err) => {
                    log::warn!(
                        "[wasm] custom-configs failed [{}]: {err:#}",
                        script.path.display()
                    );
                    continue;
                }
            };

            for section in sections {
                let mut values = IndexMap::new();

                for entry in section.values {
                    values.insert(
                        wasm_config_key(&script_id, &entry.name),
                        ConfigValue {
                            typ: entry.typ,
                            description: entry.description,
                            values: entry.values,
                            ..Default::default()
                        },
                    );
                }

                if !values.is_empty() {
                    config_json.titles.push(ConfigValues {
                        title: format!("WASM: {}", section.title),
                        values,
                        ..Default::default()
                    });
                }
            }
        }
    }

    pub async fn append_custom_config_values(&self, root: &mut Value) {
        let Some(obj) = root.as_object_mut() else {
            return;
        };

        for script in self.list_scripts() {
            let script_id = script.engine.script_id().to_string();
            let sections = match script.engine.custom_configs().await {
                Ok(sections) => sections,
                Err(err) => {
                    log::warn!(
                        "[wasm] custom-configs failed [{}]: {err:#}",
                        script.path.display()
                    );
                    continue;
                }
            };

            for section in sections {
                for entry in section.values {
                    let full_key = wasm_config_key(&script_id, &entry.name);
                    let value = script
                        .engine
                        .script_parameters
                        .wasm_config_store
                        .get_json(&script_id, &entry.name)
                        .unwrap_or_else(|| parse_config_value(&entry.typ, &entry.default_value));

                    obj.insert(full_key, value);
                }
            }
        }
    }

    pub async fn update_custom_config_entry(&self, full_key: &str, value: Value) -> Result<()> {
        let (script_id, name) = parse_wasm_config_key(full_key)
            .with_context(|| format!("invalid wasm config key: {full_key}"))?;
        let script_id = script_id.to_string();
        let name = name.to_string();

        let script = self
            .list_scripts()
            .into_iter()
            .find(|script| script.engine.script_id() == script_id.as_str())
            .with_context(|| format!("unknown wasm script config namespace: {script_id}"))?;

        script.engine.script_parameters.wasm_config_store.set_json(
            &script_id,
            &name,
            value.clone(),
        )?;

        script.engine.on_config_changed(name, value).await
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ScriptProxyType {
    HeadUnit,
    MobileDevice,
}

const SCRIPT_REST_RESULT_TOPIC: &str = "script.rest.result";

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
