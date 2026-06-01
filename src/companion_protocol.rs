use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const COMPANION_BT_UUID: &str = "3f0d2c8e-7e7e-4f38-8c98-6a7a4d94c001";

pub const COMPANION_APP_VERSION: u8 = 0x01;
pub const COMPANION_OP_PING: u8 = 0x02;
pub const COMPANION_OP_GET_STATUS: u8 = 0x03;
pub const COMPANION_OP_ECHO: u8 = 0x04;
pub const COMPANION_OP_REST_CALL: u8 = 0x05;
pub const COMPANION_OP_REST_CALL_SYNC: u8 = 0x06;
pub const COMPANION_OP_SUBSCRIBE_TOPIC_EVENT: u8 = 0x07;
pub const COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT: u8 = 0x08;
pub const COMPANION_OP_ON_SCRIPT_EVENT: u8 = 0x09;

pub const COMPANION_OP_PONG: u8 = 0x81;
pub const COMPANION_OP_STATUS: u8 = 0x82;
pub const COMPANION_OP_ECHO_REPLY: u8 = 0x83;
pub const COMPANION_OP_REST_CALL_REPLY: u8 = 0x85;
pub const COMPANION_OP_REST_CALL_RESULT: u8 = 0x86;
pub const COMPANION_OP_ON_TOPIC_EVENT: u8 = 0x87;
pub const COMPANION_OP_ERROR: u8 = 0xFF;

const HEADER_LEN: usize = 10;
const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
pub struct CompanionFrame {
    pub version: u8,
    pub op: u8,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

impl CompanionFrame {
    pub fn new(op: u8, request_id: u64, payload: Vec<u8>) -> Self {
        Self {
            version: COMPANION_APP_VERSION,
            op,
            request_id,
            payload,
        }
    }
}

pub async fn read_frame<R>(reader: &mut R) -> Result<CompanionFrame>
where
    R: AsyncRead + Unpin,
{
    let frame_len = reader.read_u32_le().await? as usize;
    if frame_len < HEADER_LEN {
        return Err(format!("companion frame too short: {}", frame_len).into());
    }
    if frame_len > MAX_FRAME_LEN {
        return Err(format!("companion frame too large: {}", frame_len).into());
    }

    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let version = header[0];
    if version != COMPANION_APP_VERSION {
        return Err(format!(
            "unsupported companion protocol version: {} expected {}",
            version, COMPANION_APP_VERSION
        )
        .into());
    }

    let op = header[1];
    let request_id = u64::from_le_bytes(header[2..10].try_into()?);
    let payload_len = frame_len - HEADER_LEN;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(CompanionFrame {
        version,
        op,
        request_id,
        payload,
    })
}

pub async fn write_frame<W>(writer: &mut W, frame: &CompanionFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame_len = HEADER_LEN
        .checked_add(frame.payload.len())
        .ok_or("companion frame length overflow")?;
    if frame_len > MAX_FRAME_LEN {
        return Err(format!("companion frame too large: {}", frame_len).into());
    }

    writer.write_u32_le(frame_len as u32).await?;
    writer.write_u8(frame.version).await?;
    writer.write_u8(frame.op).await?;
    writer.write_all(&frame.request_id.to_le_bytes()).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;
    Ok(())
}
