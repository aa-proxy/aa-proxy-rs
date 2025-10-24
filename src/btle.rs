use crate::bluetooth::BTLE_PROFILE_UUID;
use crate::config::{Action, AppConfig};
use crate::ev::{send_ev_data, BatteryData, EV_MODEL_FILE};
use crate::web::{AppState, CERT_DEST_DIR};
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use bluer::Adapter;
use flate2::read::GzDecoder;
use flate2::{
    write::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use simplelog::*;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug)]
struct Request {
    m: String,
    pt: String,
    b: Option<String>,
    #[serde(default)]
    p: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Response {
    s: u16,
    pt: String,
    b: Option<String>,
}

const FINISH_SIGNAL: u32 = u32::MAX;
pub const SERVICE_UUID_16: &str = "2fbe6";
const CHAR_UUID: &str = "2fbe6aa1-844b-41fa-9d03-fd4453a88c36";
// module name for logging engine
const NAME: &str = "<i><bright-black> ble: </>";

fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(Vec::new()); // Correct!
    decoder.write_all(data).unwrap();
    decoder.finish().unwrap()
}

pub async fn run_btle_server(
    adapter: &Adapter,
    state: AppState,
) -> bluer::Result<bluer::gatt::local::ApplicationHandle> {
    debug!("{} 🥏 BLE Starting", NAME);
    debug!(
        "{} 🥏 BLE Started alias: <bold><green>{}</>",
        NAME,
        adapter.name()
    );

    // Re-try registration loop but recreate the app+control each attempt.
    // Returns (app_handle, char_control) so caller can spawn the control consumer.
    let (app_handle, char_control) = loop {
        // create fresh control handle + char handle for this attempt
        let (new_char_control, new_char_handle) = bluer::gatt::local::characteristic_control();

        // build the Application using the freshly-created char handle
        let app = Application {
            services: vec![Service {
                //uuid: Uuid::parse_str(SERVICE_UUID_128).unwrap(),
                uuid: BTLE_PROFILE_UUID,
                primary: true,
                characteristics: vec![Characteristic {
                    uuid: Uuid::parse_str(CHAR_UUID).unwrap(),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Io,
                        ..Default::default()
                    }),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: new_char_handle,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        match adapter.serve_gatt_application(app).await {
            Ok(h) => {
                debug!("GATT registered successfully");
                // move `new_char_control` out so caller can use it
                break (h, new_char_control);
            }
            Err(e) => {
                error!("serve_gatt_application failed: {}. retrying in 1s", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                // loop continues, app and new_char_control are dropped and we create fresh ones
            }
        }
    };

    debug!("{} 🥏 GATT server running", NAME);

    let mut char_control = char_control;

    tokio::spawn(async move {
        debug!("{} 🥏 char_control task starting", NAME);

        let mut reader_opt = None;
        let mut writer_opt = None;
        let mut buf: Vec<u8> = Vec::new();

        loop {
            match char_control.next().await {
                Some(evt) => {
                    debug!("{} 🥏 Event received: {:?}", NAME, evt);

                    match evt {
                        bluer::gatt::local::CharacteristicControlEvent::Write(req) => {
                            debug!("{} 🥏 Got Write event (mtu={})", NAME, req.mtu());
                            match req.accept() {
                                Ok(reader) => {
                                    debug!(
                                        "{} 🥏 Accepted write request (reader mtu={})",
                                        NAME,
                                        reader.mtu()
                                    );
                                    reader_opt = Some(reader);
                                }
                                Err(e) => {
                                    error!("{} 🥏 Failed to accept write: {}", NAME, e);
                                }
                            }
                        }

                        bluer::gatt::local::CharacteristicControlEvent::Notify(notifier) => {
                            debug!(
                                "{} 🥏 Got Notify subscription event (mtu={})",
                                NAME,
                                notifier.mtu()
                            );
                            writer_opt = Some(notifier);
                        }
                    }

                    // Drain available reads
                    if let Some(reader) = reader_opt.as_mut() {
                        let mut tmp = vec![0u8; reader.mtu().max(20)];
                        loop {
                            match reader.read(&mut tmp).await {
                                Ok(0) => {
                                    warn!("{} 🥏 Reader returned 0 bytes (EOF?)", NAME);
                                    reader_opt = None;
                                    break;
                                }
                                Ok(n) => {
                                    debug!("{} 🥏 Read {} bytes from client (drain)", NAME, n);
                                    buf.extend_from_slice(&tmp[..n]);

                                    // Debug print tail
                                    if buf.len() > 64 {
                                        let tail = &buf[buf.len() - 64..];
                                        debug!(
                                            "{} 🥏 Buffer tail (hex): {}",
                                            NAME,
                                            hex::encode(tail)
                                        );
                                    } else {
                                        debug!("{} 🥏 Buffer (hex): {}", NAME, hex::encode(&buf));
                                    }

                                    // Check for finish marker at end
                                    while buf.len() >= 4 {
                                        let len = buf.len();
                                        let last4 = &buf[len - 4..];
                                        if u32::from_le_bytes(last4.try_into().unwrap())
                                            == FINISH_SIGNAL
                                        {
                                            // Found finish. Remove marker and process request.
                                            buf.truncate(len - 4);
                                            debug!("{} 🥏 Finish marker detected; total payload {} bytes", NAME, buf.len());

                                            // Decompress & parse safely
                                            let parsed_req = match std::panic::catch_unwind(|| {
                                                decrypt_and_parse(&buf)
                                            }) {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    error!("{} 🥏 Failed to decompress/parse request: {:?}", NAME, e);
                                                    buf.clear();
                                                    break;
                                                }
                                            };

                                            debug!("{} 🥏 Parsed request: {:?}", NAME, parsed_req);

                                            // Build response (may use blocking inside craft_response; it already blocks internally)
                                            let resp =
                                                craft_response(&parsed_req, state.clone()).await;
                                            let data = match serde_json::to_vec(&resp) {
                                                Ok(d) => d,
                                                Err(e) => {
                                                    error!(
                                                        "{} 🥏 Failed to serialize response: {}",
                                                        NAME, e
                                                    );
                                                    buf.clear();
                                                    break;
                                                }
                                            };
                                            let compressed = compress_data(&data);

                                            // Send response if we have a writer (notify subscription)
                                            if let Some(writer) = writer_opt.as_mut() {
                                                debug!("{} 🥏 Writing {} compressed bytes back (writer mtu={})", NAME, compressed.len(), writer.mtu());
                                                for c in compressed.chunks(writer.mtu() - 4) {
                                                    match writer.write_all(c).await {
                                                        Ok(_) => debug!(
                                                            "{} 🥏 wrote chunk {} bytes",
                                                            NAME,
                                                            c.len()
                                                        ),
                                                        Err(e) => {
                                                            error!(
                                                                "{} 🥏 Error writing chunk: {}",
                                                                NAME, e
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }
                                                match writer
                                                    .write_all(&FINISH_SIGNAL.to_le_bytes())
                                                    .await
                                                {
                                                    Ok(_) => debug!(
                                                        "{} 🥏 Finish marker written to client",
                                                        NAME
                                                    ),
                                                    Err(e) => error!(
                                                        "{} 🥏 Error writing finish marker: {}",
                                                        NAME, e
                                                    ),
                                                }
                                            } else {
                                                warn!("{} 🥏 No notifier/writer attached, cannot send response", NAME);
                                            }

                                            // Clear buffer after handling request
                                            buf.clear();
                                            break;
                                        } else {
                                            // No finish marker yet
                                            break;
                                        }
                                    }
                                    // continue draining loop
                                }
                                Err(e) => {
                                    error!("{} 🥏 Error reading from BLE client: {}", NAME, e);
                                    reader_opt = None;
                                    break;
                                }
                            }
                        } // end drain loop
                    } // end if reader_opt
                }

                None => {
                    debug!("{} 🥏 char_control.next() returned None - control stream closed; exiting task", NAME);
                    break;
                }
            } // end match char_control.next()
        } // end outer loop

        debug!("{} 🥏 char_control task ended", NAME);
    });

    Ok(app_handle)
}

fn decrypt_and_parse(buf: &[u8]) -> Request {
    let dec = decompress_data(buf);
    serde_json::from_slice(&dec).unwrap()
}

// FIXME below function should use/translate direct requests to main webserver
// REWRITE THIS !!!
async fn craft_response(req: &Request, state: AppState) -> Response {
    {
        let cfg_guard = state.config.read().await;
        let expected_password = cfg_guard.ble_password.clone();

        // Only enforce password if config has one
        if !expected_password.is_empty() {
            match &req.p {
                Some(provided_password) if provided_password == &expected_password => {
                    // ✅ Password OK, continue
                }
                Some(_) => {
                    info!("{} 🥏 Invalid BLE password from request", NAME);
                    return Response {
                        s: 403,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"password mismatch\" }".to_string()),
                    };
                }
                None => {
                    info!("{} 🥏 Missing BLE password in request", NAME);
                    return Response {
                        s: 403,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"missing password\" }".to_string()),
                    };
                }
            }
        } else {
            debug!("{} 🥏 Password check skipped (empty ble_password)", NAME);
        }
    }

    // same match, but use .await where needed
    match req.pt.as_str() {
        "/get-config-data" => {
            // async read instead of blocking
            let cfg_guard = state.config_json.read().await;
            let cfg_str = serde_json::to_string(&*cfg_guard).unwrap_or_default();

            debug!("{} 🥏 /get-config-data response: {}", NAME, cfg_str);

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some(cfg_str),
            }
        }
        "/get-config" => {
            // async read instead of blocking
            let cfg_guard = state.config.read().await;
            let cfg_str = serde_json::to_string(&*cfg_guard).unwrap_or_default();

            debug!("{} 🥏 /get-config response: {}", NAME, cfg_str);

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some(cfg_str),
            }
        }
        "/update-config" => {
            // ensure there is a body
            let body = match req.b.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /update-config - missing body", NAME);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"missing body\" }".to_string()),
                    };
                }
            };

            // parse JSON string into AppConfig
            let parsed_cfg: AppConfig = match serde_json::from_str(&body) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("{} 🥏 /update-config - failed to parse JSON: {}", NAME, e);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some(
                            "{ \"status\": 0, \"msg\": \"failed to parse JSON\"  }".to_string(),
                        ),
                    };
                }
            };

            // write to shared config and persist
            {
                let mut cfg = state.config.write().await;
                *cfg = parsed_cfg; // consumes parsed_cfg
                                   // keep your existing save call; if save returns a Result you might want to handle it
                cfg.save((&state.config_file).to_path_buf());
            }

            debug!(
                "{} 🥏 /update-config response: {}",
                NAME,
                "{ \"status\": 1 }".to_string()
            );

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            }
        }
        "/update-hex-model" => {
            // ensure there is a body
            let body = match req.b.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /update-hex-model - missing body", NAME);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"missing body\" }".to_string()),
                    };
                }
            };
            // decode into Vec<u8>
            let binary_data = match hex::decode(body) {
                Ok(data) => data,
                Err(_err) => {
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"failed to parse\" }".to_string()),
                    }
                }
            };

            // save to model file
            let path: PathBuf = PathBuf::from(EV_MODEL_FILE);
            if let Err(err) = tokio::fs::write(&path, &binary_data).await {
                error!("write failed: {}", err);
                return Response {
                    s: 400,
                    pt: req.pt.clone(),
                    b: Some("{ \"status\": 0, \"msg\": \"failed to write\" }".to_string()),
                };
            }
            return Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            };
        }
        "/battery" => {
            // ensure there is a body
            let body = match req.b.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /battery - missing body", NAME);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"missing body\" }".to_string()),
                    };
                }
            };

            // parse JSON string into AppConfig
            let data: BatteryData = match serde_json::from_str(&body) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("{} 🥏 /battery - failed to parse JSON: {}", NAME, e);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"failed to parse JSON\" }".to_string()),
                    };
                }
            };

            match data.battery_level_percentage {
                Some(level) => {
                    if level < 0.0 || level > 100.0 {
                        return Response {
                            s: 400,
                            pt: req.pt.clone(),
                            b: Some("{ \"status\": 0, \"msg\": \"battery_level_percentage out of range\" }".to_string()),
                        };
                    }
                }
                None => {
                    if data.battery_level_wh.is_none() {
                        return Response {
                            s: 400,
                            pt: req.pt.clone(),
                            b: Some("{ \"status\": 0, \"msg\": \"Either battery_level_percentage or battery_level_wh has to be set\" }".to_string()),
                        };
                    }
                }
            }

            debug!("{} Received battery data: {:?}", NAME, data);

            if let Some(ch) = *state.sensor_channel.lock().await {
                if let Some(tx) = state.tx.lock().await.clone() {
                    if let Err(e) = send_ev_data(tx.clone(), ch, data).await {
                        error!("{} EV model error: {}", NAME, e);
                        return Response {
                            s: 400,
                            pt: req.pt.clone(),
                            b: Some("{ \"status\": 0, \"msg\": \"ev model error\" }".to_string()),
                        };
                    }
                }
            } else {
                warn!("{} Not sending packet because no sensor channel yet", NAME);
                return Response {
                    s: 400,
                    pt: req.pt.clone(),
                    b: Some("{ \"status\": 0, \"msg\": \"Not sending packet because no sensor channel yet\" }".to_string()),
                };
            }
            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            }
        }
        "/restart" => {
            state.config.write().await.action_requested = Some(Action::Reconnect);

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            }
        }
        "/reboot" => {
            state.config.write().await.action_requested = Some(Action::Reboot);

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            }
        }
        "/update-certs" => {
            let body = match req.b.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /update-certs - missing body", NAME);
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"missing body\" }".to_string()),
                    };
                }
            };

            // Read request body into bytes
            let body_bytes = match hyper::body::to_bytes(body).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"parse error\" }".to_string()),
                    };
                }
            };

            // temp dir
            let extract_to = Path::new("/tmp");

            // Clean up previous unpack (optional but clean)
            let old_path = extract_to.join("aa-proxy-rs");
            if fs::metadata(&old_path).await.is_ok() {
                if let Err(_) = fs::remove_dir_all(&old_path).await {
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"clean error\" }".to_string()),
                    };
                }
            }

            // Prepare GZIP decoder over the byte buffer
            let decompressed = GzDecoder::new(Cursor::new(body_bytes));
            let mut archive = Archive::new(decompressed);

            // Unpack archive directly into /tmp
            if let Err(_) = archive.unpack(extract_to) {
                return Response {
                    s: 400,
                    pt: req.pt.clone(),
                    b: Some("{ \"status\": 0, \"msg\": \"unpack error\" }".to_string()),
                };
            }

            // Iterate over extracted files
            let mut valid_files = vec![];
            let certs_dir = Path::new("/tmp/aa-proxy-rs");

            let mut entries = match fs::read_dir(&certs_dir).await {
                Ok(e) => e,
                Err(_) => {
                    return Response {
                        s: 400,
                        pt: req.pt.clone(),
                        b: Some("{ \"status\": 0, \"msg\": \"read error\" }".to_string()),
                    };
                }
            };

            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let filename = match path.file_name().and_then(|f| f.to_str()) {
                    Some(name) => name,
                    None => continue,
                };

                // Accept only .pem files
                if filename.ends_with(".pem") {
                    valid_files.push((path.clone(), filename.to_string()));
                }
            }

            if valid_files.is_empty() {
                return Response {
                    s: 400,
                    pt: req.pt.clone(),
                    b: Some("{ \"status\": 0, \"msg\": \"files not valid\" }".to_string()),
                };
            }

            // Copy valid .pem files to destination
            for (src_path, filename) in valid_files {
                let dest_path = Path::new(CERT_DEST_DIR).join(filename);
                match fs::copy(&src_path, &dest_path).await {
                    Ok(_) => {}
                    Err(_) => {
                        return Response {
                            s: 400,
                            pt: req.pt.clone(),
                            b: Some("{ \"status\": 0, \"msg\": \"save error\" }".to_string()),
                        };
                    }
                }
            }

            Response {
                s: 200,
                pt: req.pt.clone(),
                b: Some("{ \"status\": 1 }".to_string()),
            }
        }
        _ => Response {
            s: 404,
            pt: req.pt.clone(),
            b: Some("Unknown method".to_string()),
        },
    }
}
