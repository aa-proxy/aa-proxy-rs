use bluer::gatt::local::{
    Application, Characteristic, CharacteristicWrite, CharacteristicNotify,
    Service, CharacteristicWriteMethod, CharacteristicNotifyMethod
};
use bluer::Adapter;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use flate2::{write::{ZlibEncoder, ZlibDecoder}, Compression};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use simplelog::*;
use crate::bluetooth::AAWG_PROFILE_UUID;
use crate::config::AppConfig;
use crate::ev::EV_MODEL_FILE;
use crate::web::AppState;

#[derive(Deserialize, Serialize, Debug)]
struct Request {
    method: String,
    path: String,
    body: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Response {
    status: u16,
    path: String,
    body: Option<String>,
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
    let mut decoder = ZlibDecoder::new(Vec::new());  // Correct!
    decoder.write_all(data).unwrap();
    decoder.finish().unwrap()
}

pub async fn run_btle_server(
    adapter: &Adapter,
    state: AppState
) -> bluer::Result<bluer::gatt::local::ApplicationHandle> {
    info!("{} 🥏 BLE Starting", NAME);
    info!("{} 🥏 BLE Started alias: <bold><green>{}</>", NAME, adapter.name());

    // Re-try registration loop but recreate the app+control each attempt.
    // Returns (app_handle, char_control) so caller can spawn the control consumer.
    let (app_handle, char_control) = loop {
        // create fresh control handle + char handle for this attempt
        let (new_char_control, new_char_handle) = bluer::gatt::local::characteristic_control();

        // build the Application using the freshly-created char handle
        let app = Application {
            services: vec![Service {
                //uuid: Uuid::parse_str(SERVICE_UUID_128).unwrap(),
                uuid: AAWG_PROFILE_UUID,
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
                info!("GATT registered successfully");
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
    //let app_handle = adapter.serve_gatt_application(app).await?;
    info!("{} 🥏 GATT server running", NAME);

    let mut char_control = char_control;

    tokio::spawn(async move {
        info!("{} 🥏 char_control task starting", NAME);
    
        let mut reader_opt = None;
        let mut writer_opt = None;
        let mut buf: Vec<u8> = Vec::new();
    
        loop {
            match char_control.next().await {
                Some(evt) => {
                    info!("{} 🥏 Event received: {:?}", NAME, evt);
    
                    match evt {
                        bluer::gatt::local::CharacteristicControlEvent::Write(req) => {
                            info!("{} 🥏 Got Write event (mtu={})", NAME, req.mtu());
                            match req.accept() {
                                Ok(reader) => {
                                    info!("{} 🥏 Accepted write request (reader mtu={})", NAME, reader.mtu());
                                    reader_opt = Some(reader);
                                }
                                Err(e) => {
                                    error!("{} 🥏 Failed to accept write: {}", NAME, e);
                                }
                            }
                        }
    
                        bluer::gatt::local::CharacteristicControlEvent::Notify(notifier) => {
                            info!("{} 🥏 Got Notify subscription event (mtu={})", NAME, notifier.mtu());
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
                                    info!("{} 🥏 Read {} bytes from client (drain)", NAME, n);
                                    buf.extend_from_slice(&tmp[..n]);
    
                                    // Debug print tail
                                    if buf.len() > 64 {
                                        let tail = &buf[buf.len() - 64..];
                                        info!("{} 🥏 Buffer tail (hex): {}", NAME, hex::encode(tail));
                                    } else {
                                        info!("{} 🥏 Buffer (hex): {}", NAME, hex::encode(&buf));
                                    }
    
                                    // Check for finish marker at end
                                    while buf.len() >= 4 {
                                        let len = buf.len();
                                        let last4 = &buf[len - 4..];
                                        if u32::from_le_bytes(last4.try_into().unwrap()) == FINISH_SIGNAL {
                                            // Found finish. Remove marker and process request.
                                            buf.truncate(len - 4);
                                            info!("{} 🥏 Finish marker detected; total payload {} bytes", NAME, buf.len());
    
                                            // Decompress & parse safely
                                            let parsed_req = match std::panic::catch_unwind(|| decrypt_and_parse(&buf)) {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    error!("{} 🥏 Failed to decompress/parse request: {:?}", NAME, e);
                                                    buf.clear();
                                                    break;
                                                }
                                            };
    
                                            info!("{} 🥏 Parsed request: {:?}", NAME, parsed_req);
    
                                            // Build response (may use blocking inside craft_response; it already blocks internally)
                                            let resp = craft_response(&parsed_req, state.clone()).await;
                                            let data = match serde_json::to_vec(&resp) {
                                                Ok(d) => d,
                                                Err(e) => {
                                                    error!("{} 🥏 Failed to serialize response: {}", NAME, e);
                                                    buf.clear();
                                                    break;
                                                }
                                            };
                                            let compressed = compress_data(&data);
    
                                            // Send response if we have a writer (notify subscription)
                                            if let Some(writer) = writer_opt.as_mut() {
                                                info!("{} 🥏 Writing {} compressed bytes back (writer mtu={})", NAME, compressed.len(), writer.mtu());
                                                for c in compressed.chunks(writer.mtu().max(20)) {
                                                    match writer.write_all(c).await {
                                                        Ok(_) => info!("{} 🥏 wrote chunk {} bytes", NAME, c.len()),
                                                        Err(e) => {
                                                            error!("{} 🥏 Error writing chunk: {}", NAME, e);
                                                            break;
                                                        }
                                                    }
                                                }
                                                match writer.write_all(&FINISH_SIGNAL.to_le_bytes()).await {
                                                    Ok(_) => info!("{} 🥏 Finish marker written to client", NAME),
                                                    Err(e) => error!("{} 🥏 Error writing finish marker: {}", NAME, e),
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
                    info!("{} 🥏 char_control.next() returned None - control stream closed; exiting task", NAME);
                    break;
                }
            } // end match char_control.next()
        } // end outer loop
    
        info!("{} 🥏 char_control task ended", NAME);
    });

    Ok(app_handle)
}



fn decrypt_and_parse(buf: &[u8]) -> Request {
    let dec = decompress_data(buf);
    serde_json::from_slice(&dec).unwrap()
}

async fn craft_response(req: &Request, state: AppState) -> Response {
    // same match, but use .await where needed
    match req.path.as_str() {
        "/hello" => Response { status: 200, path: req.path.clone(), body: Some("Hello from Rust server!".to_string()) },
        "/echo"  => Response { status: 200, path: req.path.clone(), body: req.body.clone() },
        "/get-config-data" => {
            // async read instead of blocking
            let cfg_guard = state.config_json.read().await;
            let cfg_str = serde_json::to_string(&*cfg_guard).unwrap_or_default();

            info!("{} 🥏 /get-config-data response: {}", NAME, cfg_str);

            Response { status: 200, path: req.path.clone(), body: Some(cfg_str) }
        }
        "/get-config" => {
            // async read instead of blocking
            let cfg_guard = state.config.read().await;
            let cfg_str = serde_json::to_string(&*cfg_guard).unwrap_or_default();

            info!("{} 🥏 /get-config response: {}", NAME, cfg_str);

            Response { status: 200, path: req.path.clone(), body: Some(cfg_str) }
        }
        "/update-config" => {
            // ensure there is a body
            let body = match req.body.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /update-config - missing body", NAME);
                    return Response {
                        status: 400,
                        path: req.path.clone(),
                        body: None,
                    };
                }
            };

            // parse JSON string into AppConfig
            let parsed_cfg: AppConfig = match serde_json::from_str(&body) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("{} 🥏 /update-config - failed to parse JSON: {}", NAME, e);
                    return Response {
                        status: 400,
                        path: req.path.clone(),
                        body: Some("{ \"status\": 0 }".to_string()),
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

            info!("{} 🥏 /update-config response: {}", NAME, "{ \"status\": 1 }".to_string());

            Response {
                status: 200,
                path: req.path.clone(),
                body: Some("{ \"status\": 1 }".to_string()),
            }
        }
        "/update-hex-model" => {
            // ensure there is a body
            let body = match req.body.clone() {
                Some(b) => b,
                None => {
                    error!("{} 🥏 /update-hex-model - missing body", NAME);
                    return Response {
                        status: 400,
                        path: req.path.clone(),
                        body: None,
                    }
                }
            };
            // decode into Vec<u8>
            let binary_data = match hex::decode(body) {
                Ok(data) => data,
                Err(_err) => {
                    return Response {
                        status: 400,
                        path: req.path.clone(),
                        body: Some("{ \"status\": 0 }".to_string()),
                    }
                }
            };

            // save to model file
            let path: PathBuf = PathBuf::from(EV_MODEL_FILE);
            if let Err(err) = tokio::fs::write(&path, &binary_data).await {
                error!("write failed: {}", err);
                return Response { status: 400, path: req.path.clone(), body: Some("{ \"status\": 0 }".to_string()) };
            }
            return Response { status: 200, path: req.path.clone(), body: Some("{ \"status\": 1 }".to_string()) };
        }
        _ => Response { status: 404, path: req.path.clone(), body: Some("Unknown method".to_string()) },
    }
}
