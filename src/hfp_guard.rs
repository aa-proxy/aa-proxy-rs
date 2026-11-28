//! Hands-free guard (AA_HFP_GUARD=1).
//!
//! Some head units break incoming calls when the phone plays its ringtone in-band (the phone opens the
//! call audio link while it is still ringing): Ford SYNC 3 on its default "SYNC ringtone" lets the
//! caller hear nothing from the car's microphone, while outgoing calls work. Its own workaround
//! ("Use Phone Ringtone") is reset by the car at every drive, and Android 17 no longer offers the
//! developer option that turned in-band ringing off.
//!
//! Android turns in-band ringing off for every hands-free device whenever more than one is connected
//! (HeadsetService.updateInbandRinging: +BSIR: 0 to all of them). So from the Bluetooth bootstrap on
//! the dongle stays connected to the phone as a second, silent hands-free unit for the whole session,
//! and tells Android with its sink audio policy (AT+ANDROID=SINKAUDIOPOLICY,2,2,2, Android 14+, stored
//! per device by the phone) that it must never become the active device, never take a call and never
//! get in-band ringing. Calls keep using the car's own hands-free link and no audio reaches the dongle
//! (it has no SCO listener, so a stray audio connection is refused by BlueZ).
//!
//! A phone that refuses the policy (older Android) is disconnected at once and left alone: without
//! the policy the dongle could become the phone's call device.
use crate::config::Action;
use bluer::rfcomm::{Profile, ReqError, Stream};
use bluer::{Adapter, Address, Uuid};
use futures::StreamExt;
use simplelog::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::time::{sleep, timeout};

const NAME: &str = "<i><bright-black> hfp-guard: </>";
const HFP_HF_UUID: Uuid = Uuid::from_u128(0x0000111e_0000_1000_8000_00805f9b34fb);
const HFP_AG_UUID: Uuid = Uuid::from_u128(0x0000111f_0000_1000_8000_00805f9b34fb);
const POLICY_CMD: &str = "AT+ANDROID=SINKAUDIOPOLICY,2,2,2";

/// The guard runs only when the environment asks for it (set AA_HFP_GUARD=1).
pub fn enabled() -> bool {
    std::env::var("AA_HFP_GUARD")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Start the guard for `addr` (the phone that just did the AA bootstrap). It ends when the AA session
/// restarts or stops (`restart`), which drops the hands-free link and unregisters the profile.
static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn spawn(adapter: Adapter, addr: Address, mut restart: BroadcastReceiver<Option<Action>>) {
    // one guard at a time: a bootstrap that failed and is retried keeps the guard it already started
    if RUNNING.swap(true, Ordering::SeqCst) {
        debug!("{} already running", NAME);
        return;
    }
    tokio::spawn(async move {
        let adapter2 = adapter.clone();
        tokio::select! {
            _ = run(adapter, addr) => {}
            r = restart.recv() => {
                info!("{} ending with the AA session ({:?})", NAME, r.ok().flatten());
            }
        }
        // The link, its profile and stream are gone here. Disconnect the phone as aa-proxy-rs does after
        // the bootstrap: the next session's handshake then starts from the same state (a phone still
        // connected kept its old AA Wireless RFCOMM and reset the first handshake attempts, seen on the
        // bench).
        if let Ok(device) = adapter2.device(addr) {
            let _ = timeout(Duration::from_secs(2), device.disconnect()).await;
        }
        RUNNING.store(false, Ordering::SeqCst);
    });
}

enum End {
    /// the link closed or failed: try again later
    Retry(String),
    /// the phone refused the policy: never connect again in this session
    Refused(String),
}

async fn run(adapter: Adapter, addr: Address) {
    // started with the bootstrap (the phone has just opened its AA Wireless RFCOMM): let the Wi-Fi
    // credentials exchange go first, it takes ~0.1 s
    sleep(Duration::from_secs(2)).await;
    let session = match bluer::Session::new().await {
        Ok(s) => s,
        Err(e) => {
            warn!("{} no BlueZ session: {}", NAME, e);
            return;
        }
    };
    let profile = Profile {
        uuid: HFP_HF_UUID,
        name: Some("Hands-Free".to_string()),
        version: Some(0x0107),
        features: Some(0),
        require_authentication: Some(false),
        require_authorization: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    };
    let mut handle = match session.register_profile(profile).await {
        Ok(h) => h,
        Err(e) => {
            warn!("{} registering the hands-free profile failed: {}", NAME, e);
            return;
        }
    };
    info!("{} hands-free profile registered, connecting to {}", NAME, addr);
    let mut backoff = Duration::from_secs(5);
    loop {
        let device = match adapter.device(addr) {
            Ok(d) => d,
            Err(e) => {
                warn!("{} {}: {}", NAME, addr, e);
                return;
            }
        };
        // our connect and a connection the phone makes itself both arrive on `handle`
        let connect = tokio::spawn(async move {
            timeout(Duration::from_secs(20), device.connect_profile(&HFP_AG_UUID)).await
        });
        let req = match timeout(Duration::from_secs(25), handle.next()).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                warn!("{} profile closed by BlueZ", NAME);
                return;
            }
            Err(_) => {
                let why = match connect.await {
                    Ok(Ok(Err(e))) => e.to_string(),
                    Ok(Err(_)) => "connect timed out".to_string(),
                    _ => "no connection".to_string(),
                };
                info!("{} no hands-free link ({}), again in {:?}", NAME, why, backoff);
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        };
        if req.device() != addr {
            info!("{} rejecting {} (not the session's phone)", NAME, req.device());
            req.reject(ReqError::Rejected);
            continue;
        }
        let stream = match req.accept() {
            Ok(s) => s,
            Err(e) => {
                warn!("{} accept failed: {}", NAME, e);
                sleep(backoff).await;
                continue;
            }
        };
        let _ = connect.await;
        match hold(stream, &mut handle).await {
            End::Refused(why) => {
                warn!("{} {}: guard off for this session (calls stay on the car)", NAME, why);
                // the stream is dropped here: the phone sees the hands-free unit leave
                return;
            }
            End::Retry(why) => {
                info!("{} hands-free link ended ({}), again in {:?}", NAME, why, backoff);
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

/// Send one AT command and collect the phone's lines up to OK / ERROR (5 s).
async fn at(stream: &mut Stream, buf: &mut String, cmd: &str) -> Result<(bool, Vec<String>), String> {
    stream
        .write_all(format!("{}\r", cmd).as_bytes())
        .await
        .map_err(|e| format!("write {}: {}", cmd, e))?;
    let mut lines = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        while let Some(line) = take_line(buf) {
            if line == "OK" {
                return Ok((true, lines));
            }
            if line.starts_with("ERROR") || line.starts_with("+CME ERROR") {
                lines.push(line);
                return Ok((false, lines));
            }
            lines.push(line);
        }
        let mut chunk = [0u8; 256];
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Err(format!("{}: link closed", cmd)),
            Ok(Ok(n)) => buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
            Ok(Err(e)) => return Err(format!("{}: {}", cmd, e)),
            Err(_) => return Err(format!("{}: no answer in 5 s", cmd)),
        }
    }
}

/// The next complete, non-empty line in `buf` (the phone frames them as \r\n...\r\n).
fn take_line(buf: &mut String) -> Option<String> {
    loop {
        let end = buf.find(|c| c == '\r' || c == '\n')?;
        let line = buf[..end].trim().to_string();
        buf.drain(..=end);
        if !line.is_empty() {
            return Some(line);
        }
    }
}

async fn hold(mut stream: Stream, handle: &mut bluer::rfcomm::ProfileHandle) -> End {
    let mut buf = String::new();
    // service level connection as a hands-free unit with no optional features (no codec
    // negotiation, no three-way calling), then the sink audio policy
    for cmd in ["AT+BRSF=0", "AT+CIND=?", "AT+CIND?", "AT+CMER=3,0,0,1"] {
        match at(&mut stream, &mut buf, cmd).await {
            Ok((true, lines)) => {
                if cmd == "AT+BRSF=0" {
                    info!("{} phone features {:?}", NAME, lines);
                }
            }
            Ok((false, lines)) => return End::Retry(format!("{} refused: {:?}", cmd, lines)),
            Err(e) => return End::Retry(e),
        }
    }
    match at(&mut stream, &mut buf, POLICY_CMD).await {
        Ok((true, _)) => info!(
            "{} connected as a silent second hands-free unit: never active, no calls, no in-band ringing; \
             the phone now turns in-band ringing off for the car",
            NAME
        ),
        Ok((false, lines)) => return End::Refused(format!("phone refused the sink audio policy {:?}", lines)),
        Err(e) => return End::Retry(e),
    }
    // idle: the phone's unsolicited results are only logged (+BSIR = its in-band ringing state)
    let mut chunk = [0u8; 256];
    loop {
        tokio::select! {
            r = stream.read(&mut chunk) => match r {
                Ok(0) => return End::Retry("closed by the phone".to_string()),
                Ok(n) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    while let Some(line) = take_line(&mut buf) {
                        if line.starts_with("+BSIR") || line == "RING" {
                            info!("{} phone: {}", NAME, line);
                        } else {
                            debug!("{} phone: {}", NAME, line);
                        }
                    }
                }
                Err(e) => return End::Retry(e.to_string()),
            },
            req = handle.next() => match req {
                // one link per session: a second one (the phone reconnecting) is refused
                Some(req) => req.reject(ReqError::Rejected),
                None => return End::Retry("profile closed by BlueZ".to_string()),
            },
        }
    }
}
