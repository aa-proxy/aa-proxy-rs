use crate::io_uring::apply_tcp_buffer_sizes;
use serde::Deserialize;
use serde_json::{json, Value};
use simplelog::*;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_uring::buf::BoundedBuf;
use tokio_uring::net::{TcpListener, TcpStream};

const NAME: &str = "<i><bright-black> iperf3: </>";
const COOKIE_SIZE: usize = 37;
const PARAM_EXCHANGE: u8 = 9;
const CREATE_STREAMS: u8 = 10;
const TEST_START: u8 = 1;
const TEST_RUNNING: u8 = 2;
const TEST_END: u8 = 4;
const EXCHANGE_RESULTS: u8 = 13;
const DISPLAY_RESULTS: u8 = 14;
const IPERF_DONE: u8 = 16;
const DEFAULT_STREAM_LEN: usize = 128 * 1024;
const MAX_PARALLEL_STREAMS: usize = 8;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Deserialize)]
struct ClientParams {
    tcp: Option<bool>,
    reverse: Option<bool>,
    parallel: Option<usize>,
    len: Option<usize>,
}

#[derive(Debug)]
struct StreamResult {
    id: usize,
    bytes: Arc<AtomicU64>,
}

pub async fn run_server(bind_addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)?;
    info!("{} listening on {}", NAME, bind_addr);

    loop {
        let (ctrl_stream, peer) = listener.accept().await?;
        if let Err(e) = handle_session(&listener, ctrl_stream, peer).await {
            error!("{} session with {} failed: {}", NAME, peer, e);
        }
    }
}

async fn handle_session(
    listener: &TcpListener,
    ctrl_stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    tune_stream(&ctrl_stream)?;

    let cookie = read_exact_vec(&ctrl_stream, COOKIE_SIZE).await?;
    write_u8(&ctrl_stream, PARAM_EXCHANGE).await?;

    let params: ClientParams = serde_json::from_slice(&read_json_bytes(&ctrl_stream).await?)?;
    if params.tcp == Some(false) {
        return Err("temporary server currently supports only iperf3 TCP mode".into());
    }

    let reverse = params.reverse.unwrap_or(false);
    let parallel = params.parallel.unwrap_or(1).clamp(1, MAX_PARALLEL_STREAMS);
    let buf_len = params.len.unwrap_or(DEFAULT_STREAM_LEN).max(1024);

    info!(
        "{} accepted control session from {}: reverse={}, parallel={}, len={}",
        NAME, peer, reverse, parallel, buf_len
    );

    write_u8(&ctrl_stream, CREATE_STREAMS).await?;
    let mut streams = Vec::with_capacity(parallel);
    for id in 1..=parallel {
        let (data_stream, data_peer) = listener.accept().await?;
        tune_stream(&data_stream)?;
        let data_cookie = read_exact_vec(&data_stream, COOKIE_SIZE).await?;
        if data_cookie != cookie {
            return Err(format!("unexpected data-stream cookie from {}", data_peer).into());
        }
        streams.push((id, data_stream));
    }

    write_u8(&ctrl_stream, TEST_START).await?;
    write_u8(&ctrl_stream, TEST_RUNNING).await?;

    let started_at = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(parallel);
    let mut results = Vec::with_capacity(parallel);

    for (id, stream) in streams {
        let bytes = Arc::new(AtomicU64::new(0));
        results.push(StreamResult {
            id,
            bytes: bytes.clone(),
        });
        handles.push(tokio_uring::spawn(run_stream(
            stream,
            buf_len,
            reverse,
            bytes,
            stop.clone(),
        )));
    }

    let state = read_u8(&ctrl_stream).await?;
    if state != TEST_END {
        return Err(format!("unexpected iperf3 control state: {}", state).into());
    }

    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.await;
    }

    write_u8(&ctrl_stream, EXCHANGE_RESULTS).await?;
    let _client_results = read_json_bytes(&ctrl_stream).await?;
    let results_json = build_results_json(&results, started_at.elapsed().as_secs_f64());
    write_json_bytes(&ctrl_stream, &serde_json::to_vec(&results_json)?).await?;
    write_u8(&ctrl_stream, DISPLAY_RESULTS).await?;

    let state = read_u8(&ctrl_stream).await?;
    if state != IPERF_DONE {
        return Err(format!("unexpected final iperf3 control state: {}", state).into());
    }

    let _ = ctrl_stream.shutdown(Shutdown::Both);
    info!("{} completed session from {}", NAME, peer);
    Ok(())
}

async fn run_stream(
    stream: TcpStream,
    buf_len: usize,
    reverse: bool,
    bytes: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    if reverse {
        let mut buf = vec![0u8; buf_len];
        while !stop.load(Ordering::Relaxed) {
            let (res, slice) = stream.write_all(buf.slice(..)).await;
            buf = slice.into_inner();
            res?;
            bytes.fetch_add(buf_len as u64, Ordering::Relaxed);
        }
        Ok(())
    } else {
        let mut buf = vec![0u8; buf_len];
        loop {
            let (res, next_buf) = stream.read(buf).await;
            buf = next_buf;
            let n = res?;
            if n == 0 {
                break;
            }
            bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(())
    }
}

fn build_results_json(results: &[StreamResult], seconds: f64) -> Value {
    let streams: Vec<Value> = results
        .iter()
        .map(|stream| {
            json!({
                "id": stream.id,
                "bytes": stream.bytes.load(Ordering::Relaxed),
                "retransmits": 0,
                "jitter": 0,
                "errors": 0,
                "packets": 0,
                "start_time": 0,
                "end_time": seconds,
            })
        })
        .collect();

    json!({
        "cpu_util_total": 0,
        "cpu_util_user": 0,
        "cpu_util_system": 0,
        "sender_has_retransmits": 1,
        "congestion_used": "unknown",
        "streams": streams,
    })
}

async fn read_exact_vec(stream: &TcpStream, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;

    while filled < len {
        let (res, slice) = stream.read(buf.slice(filled..)).await;
        buf = slice.into_inner();
        let n = res?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "iperf3 control stream closed early",
            ));
        }
        filled += n;
    }

    Ok(buf)
}

async fn read_u8(stream: &TcpStream) -> io::Result<u8> {
    Ok(read_exact_vec(stream, 1).await?[0])
}

async fn write_u8(stream: &TcpStream, value: u8) -> io::Result<()> {
    let (res, _) = stream.write_all(vec![value]).await;
    res
}

async fn read_json_bytes(stream: &TcpStream) -> io::Result<Vec<u8>> {
    let len = u32::from_be_bytes(read_exact_vec(stream, 4).await?.try_into().unwrap()) as usize;
    read_exact_vec(stream, len).await
}

async fn write_json_bytes(stream: &TcpStream, payload: &[u8]) -> io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    let (res, _) = stream.write_all(Vec::from(len)).await;
    res?;
    let (res, _) = stream.write_all(payload.to_vec()).await;
    res
}

fn tune_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    apply_tcp_buffer_sizes(stream.as_raw_fd());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_json_contains_streams() {
        let results = vec![StreamResult {
            id: 1,
            bytes: Arc::new(AtomicU64::new(1234)),
        }];
        let json = build_results_json(&results, 5.0);
        assert_eq!(json["streams"][0]["id"], 1);
        assert_eq!(json["streams"][0]["bytes"], 1234);
    }
}
