//! MTP container (header/request/response/data) framing.
//!
//! Ported near-verbatim from the AAWireless-rs POC (`mtp_packet.rs`), with
//! permission from its author.

use crate::mtp::mtp_constants::{
    MtpContainerType, MtpOperation, MtpResponse, MTP_BUFFER_SIZE, MTP_CONTAINER_HEADER_SIZE,
    MTP_STRING_MAX_CHARACTER_NUMBER,
};
use anyhow::{anyhow, Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use num_enum::TryFromPrimitive;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncReadExt, AsyncWrite};

#[derive(Debug, Clone)]
pub struct MtpHeader {
    length: u32,
    container_type: MtpContainerType,
    container_code: u16,
    transaction_id: u32,
}

impl MtpHeader {
    pub fn new(
        length: u32,
        container_type: MtpContainerType,
        container_code: u16,
        transaction_id: u32,
    ) -> MtpHeader {
        Self {
            length: MTP_CONTAINER_HEADER_SIZE + length,
            container_type,
            container_code,
            transaction_id,
        }
    }

    pub async fn read<R: AsyncRead + Unpin>(transport: &mut R) -> Result<MtpHeader> {
        let mut header_bytes = BytesMut::zeroed(12);
        let read = transport.read_exact(&mut header_bytes).await?;

        if read < MTP_CONTAINER_HEADER_SIZE as usize {
            return Err(anyhow!("MTP packet smaller than container header"));
        }

        MtpHeader::try_from(header_bytes)
    }

    pub fn data_length(&self) -> u32 {
        self.length - MTP_CONTAINER_HEADER_SIZE
    }
}

impl TryFrom<BytesMut> for MtpHeader {
    type Error = Error;

    fn try_from(mut value: BytesMut) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            length: value.get_u32_le(),
            container_type: MtpContainerType::try_from(value.get_u16_le())?,
            container_code: value.get_u16_le(),
            transaction_id: value.get_u32_le(),
        })
    }
}

impl From<MtpHeader> for BytesMut {
    fn from(header: MtpHeader) -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.put_u32_le(header.length);
        bytes.put_u16_le(u16::from(header.container_type));
        bytes.put_u16_le(header.container_code);
        bytes.put_u32_le(header.transaction_id);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct MtpRequestResponsePacket<T>
where
    T: Clone + Copy + Into<u16> + TryFromPrimitive<Primitive = u16>,
{
    pub code: T,
    pub transaction_id: u32,
    parameters: Vec<u32>,
}

pub type MtpRequestPacket = MtpRequestResponsePacket<MtpOperation>;

pub type MtpResponsePacket = MtpRequestResponsePacket<MtpResponse>;

impl<T> MtpRequestResponsePacket<T>
where
    T: Clone + Copy + Into<u16> + TryFromPrimitive<Primitive = u16>,
{
    pub fn new(code: T, transaction_id: u32) -> Self {
        Self {
            code,
            transaction_id,
            parameters: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn parameter(&self, index: usize) -> Result<u32> {
        if index >= self.parameters.len() {
            return Err(anyhow!("Invalid index {}", index));
        }

        Ok(self.parameters[index])
    }

    #[allow(dead_code)]
    pub fn add_parameter(&mut self, value: u32) -> Result<()> {
        if self.parameters.len() > 4 {
            return Err(anyhow!("Too many parameters"));
        }

        self.parameters.push(value);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    pub async fn read<R: AsyncRead + Unpin>(transport: &mut R) -> Result<MtpRequestPacket> {
        let header = MtpHeader::read(transport).await?;
        let mut bytes = BytesMut::zeroed(header.data_length() as usize);
        transport.read_exact(&mut bytes).await?;
        let mut buf = bytes.freeze();

        let mut request =
            MtpRequestPacket::new(header.container_code.try_into()?, header.transaction_id);
        request.parameters.clear();
        while buf.remaining() != 0 {
            request.parameters.push(buf.get_u32_le());
        }

        Ok(request)
    }

    pub async fn write(&mut self, transport: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        let mut out: BytesMut = MtpHeader::new(
            (self.parameters.len() * 4) as u32,
            MtpContainerType::Response,
            self.code.into(),
            self.transaction_id,
        )
        .into();

        let bytes = BytesMut::zeroed(self.parameters.len() * 4);
        out.extend_from_slice(&bytes);
        transport.write_all(&out).await?;
        transport.flush().await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MtpDataPacket {
    code: MtpOperation,
    transaction_id: u32,
    buffer: BytesMut,
}

impl From<MtpRequestPacket> for MtpDataPacket {
    fn from(packet: MtpRequestPacket) -> Self {
        MtpDataPacket::new(packet.code, packet.transaction_id)
    }
}

impl From<&MtpRequestPacket> for MtpDataPacket {
    fn from(packet: &MtpRequestPacket) -> Self {
        MtpDataPacket::new(packet.code, packet.transaction_id)
    }
}

impl MtpDataPacket {
    pub fn new(code: MtpOperation, transaction_id: u32) -> Self {
        Self {
            code,
            transaction_id,
            buffer: BytesMut::with_capacity(MTP_BUFFER_SIZE),
        }
    }

    pub fn has_data(&self) -> bool {
        !self.buffer.is_empty()
    }

    #[allow(dead_code)]
    pub fn put_i8<T: Into<i8>>(&mut self, value: T) {
        self.buffer.put_i8(value.into());
    }

    pub fn put_u8<T: Into<u8>>(&mut self, value: T) {
        self.buffer.put_u8(value.into());
    }

    #[allow(dead_code)]
    pub fn put_i16<T: Into<i16>>(&mut self, value: T) {
        self.buffer.put_i16_le(value.into());
    }

    pub fn put_u16<T: Into<u16>>(&mut self, value: T) {
        self.buffer.put_u16_le(value.into());
    }

    #[allow(dead_code)]
    pub fn put_i32<T: Into<i32>>(&mut self, value: T) {
        self.buffer.put_i32_le(value.into());
    }

    pub fn put_u32<T: Into<u32>>(&mut self, value: T) {
        self.buffer.put_u32_le(value.into());
    }

    #[allow(dead_code)]
    pub fn put_i64<T: Into<i64>>(&mut self, value: T) {
        self.buffer.put_i64_le(value.into());
    }

    #[allow(dead_code)]
    pub fn put_u64<T: Into<u64>>(&mut self, value: T) {
        self.buffer.put_u64_le(value.into());
    }

    #[allow(dead_code)]
    pub fn put_i128<T: Into<i128>>(&mut self, value: T) {
        self.buffer.put_i128_le(value.into());
    }

    #[allow(dead_code)]
    pub fn put_u128<T: Into<u128>>(&mut self, value: T) {
        self.buffer.put_u128_le(value.into());
    }

    fn put_array<T: Copy>(&mut self, values: &[T], mut write_one: impl FnMut(&mut Self, T)) {
        self.put_u32(values.len() as u32);

        for &value in values {
            write_one(self, value);
        }
    }

    #[allow(dead_code)]
    pub fn put_empty_array(&mut self) {
        self.put_u32(0u32);
    }

    #[allow(dead_code)]
    pub fn put_a_i8<T: Copy + Into<i8>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_i8);
    }

    #[allow(dead_code)]
    pub fn put_a_u8<T: Copy + Into<u8>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_u8);
    }

    #[allow(dead_code)]
    pub fn put_a_i16<T: Copy + Into<i16>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_i16);
    }

    pub fn put_a_u16<T: Copy + Into<u16>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_u16);
    }

    #[allow(dead_code)]
    pub fn put_a_i32<T: Copy + Into<i32>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_i32);
    }

    #[allow(dead_code)]
    pub fn put_a_u32<T: Copy + Into<u32>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_u32);
    }

    #[allow(dead_code)]
    pub fn put_a_i64<T: Copy + Into<i64>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_i64);
    }

    #[allow(dead_code)]
    pub fn put_a_u64<T: Copy + Into<u64>>(&mut self, values: &[T]) {
        self.put_array(values, Self::put_u64);
    }

    pub fn put_string(&mut self, s: &str) {
        let utf16: Vec<u16> = s
            .encode_utf16()
            .take(MTP_STRING_MAX_CHARACTER_NUMBER)
            .collect();

        if utf16.is_empty() {
            self.put_u8(0);
            return;
        }

        self.put_u8((utf16.len() + 1) as u8);

        for ch in utf16 {
            self.put_u16(ch);
        }

        self.put_u16(0u16);
    }

    pub async fn write(&mut self, transport: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        let mut out: BytesMut = MtpHeader::new(
            self.buffer.len() as u32,
            MtpContainerType::Data,
            self.code.into(),
            self.transaction_id,
        )
        .into();
        out.extend_from_slice(&self.buffer);
        transport.write_all(&out).await?;
        transport.flush().await?;

        Ok(())
    }
}
