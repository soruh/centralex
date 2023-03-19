use std::fmt::Debug;

use anyhow::bail;
use bytemuck::{Pod, Zeroable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{ReadHalf, WriteHalf},
};

pub const REJECT_OOP: &[u8; 6] = b"\x04\x04oop\x00";
pub const REJECT_TIMEOUT: &[u8; 10] = b"\x04\x08timeout\x00";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Ping = 0x00,
    DynIpUpdate = 0x01,
    DynIpUpdateResponse = 0x02,
    End = 0x03,
    Reject = 0x04,
    RemConnect = 0x81,
    RemConfirm = 0x82,
    RemCall = 0x83,
    RemAck = 0x84,
    Unknown(u8),
    Error = 0xff,
}

#[allow(clippy::enum_glob_use)]
impl PacketKind {
    #[must_use]
    fn from_u8(raw: u8) -> Self {
        use PacketKind::*;

        match raw {
            0x00 => Ping,
            0x01 => DynIpUpdate,
            0x02 => DynIpUpdateResponse,
            0x03 => End,
            0x04 => Reject,
            0x81 => RemConnect,
            0x82 => RemConfirm,
            0x83 => RemCall,
            0x84 => RemAck,
            0xff => Error,
            kind => Unknown(kind),
        }
    }

    #[must_use]
    pub fn raw(&self) -> u8 {
        use PacketKind::*;

        match self {
            Ping => 0,
            DynIpUpdate => 0x01,
            DynIpUpdateResponse => 0x02,
            End => 0x03,
            Reject => 0x04,
            RemConnect => 0x81,
            RemConfirm => 0x82,
            RemCall => 0x83,
            RemAck => 0x84,
            Error => 0xff,

            Unknown(value) => *value,
        }
    }
}

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Header {
    pub kind: u8,
    pub length: u8,
}

#[derive(Default, Clone)]
pub struct Packet {
    pub header: Header,
    pub data: Vec<u8>,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = &self.data;

        let str_data = std::str::from_utf8(&data[..data.len().saturating_sub(1)]).ok();

        let data = if let Some(str_data) = str_data.as_ref() {
            str_data as &dyn Debug
        } else {
            &data as &dyn Debug
        };

        f.debug_struct("Packet")
            .field("kind", &PacketKind::from_u8(self.header.kind))
            .field("data", &data)
            .finish()
    }
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RemConnect {
    pub number: u32,
    pub pin: u16,
}

impl Packet {
    pub async fn peek_packet_kind(stream: &mut ReadHalf<'_>) -> std::io::Result<PacketKind> {
        Self::peek_packet_kind_raw(stream)
            .await
            .map(PacketKind::from_u8)
    }

    pub async fn peek_packet_kind_raw(stream: &mut ReadHalf<'_>) -> std::io::Result<u8> {
        let mut kind = 0;
        let n = stream.peek(std::slice::from_mut(&mut kind)).await?;

        if n == 1 {
            Ok(kind)
        } else {
            Err(std::io::ErrorKind::UnexpectedEof.into())
        }
    }

    pub async fn recv_into_cancelation_safe(
        &mut self,
        stream: &mut ReadHalf<'_>,
    ) -> std::io::Result<()> {
        // Makes sure all data is available before reading
        let header_bytes = bytemuck::bytes_of_mut(&mut self.header);
        stream.peek(header_bytes).await?;
        self.data.resize(self.header.length as usize + 2, 0);
        stream.peek(&mut self.data).await?;

        // All data is available. Read the data
        self.recv_into(stream).await
    }

    pub async fn recv_into(&mut self, stream: &mut ReadHalf<'_>) -> std::io::Result<()> {
        let header_bytes = bytemuck::bytes_of_mut(&mut self.header);

        stream.read_exact(header_bytes).await?;

        self.data.resize(self.header.length as usize, 0);

        stream.read_exact(&mut self.data).await?;

        Ok(())
    }

    pub async fn send(&self, stream: &mut WriteHalf<'_>) -> std::io::Result<()> {
        stream.write_all(bytemuck::bytes_of(&self.header)).await?;
        stream.write_all(&self.data).await?;
        Ok(())
    }

    #[must_use]
    pub fn kind(&self) -> PacketKind {
        PacketKind::from_u8(self.header.kind)
    }

    pub fn as_rem_connect(&self) -> anyhow::Result<RemConnect> {
        if self.kind() != PacketKind::RemConnect {
            bail!("Unexpected Packet: {:?} expected RemConnect", self.kind());
        }

        if self.data.len() < 6 {
            bail!(
                "Too little data for RemConnect. Need at least 6 Bytes got {}",
                self.data.len()
            );
        }

        Ok(RemConnect {
            number: u32::from_le_bytes(self.data[..4].try_into()?),
            pin: u16::from_le_bytes(self.data[4..6].try_into()?),
        })
    }
}
