use std::{ffi::CString, mem::discriminant};

use anyhow::bail;
use bytemuck::{Pod, Zeroable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{ReadHalf, WriteHalf},
};

pub const fn reject_static<const N: usize>(message: &[u8; N]) -> [u8; N + 2] {
    let mut pkg = [0u8; N + 2];
    pkg[0] = 4;
    pkg[1] = message.len() as u8;
    let mut i = 0;
    while i < message.len() {
        pkg[i + 2] = message[i];
        i += 1;
    }
    pkg
}

pub const REJECT_OCC: &[u8; 6] = b"\x04\x04occ\x00";
pub const REJECT_NC: &[u8; 5] = b"\x04\x03nc\x00";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Unknown(u8),
    DynIpUpdate = 0x01,
    DynIpUpdateResponse = 0x02,
    End = 0x03,
    Reject = 0x04,
    RemConnect = 0x81,
    RemConfirm = 0x82,
    RemCall = 0x83,
    RemAck = 0x84,
    Error = 0xff,
}

impl PacketKind {
    fn from_u8(raw: u8) -> Self {
        use PacketKind::*;

        match raw {
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

    fn kind(&self) -> u8 {
        use PacketKind::*;

        match self {
            Unknown(value) => *value,
            DynIpUpdate => 0x01,
            DynIpUpdateResponse => 0x02,
            End => 0x03,
            Reject => 0x04,
            RemConnect => 0x81,
            RemConfirm => 0x82,
            RemCall => 0x83,
            RemAck => 0x84,
            Error => 0xff,
        }
    }
}

#[derive(Default, Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Header {
    pub kind: u8,
    pub length: u8,
}

#[derive(Debug, Default, Clone)]
pub struct Packet {
    pub header: Header,
    pub data: Vec<u8>,
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

    pub async fn recv(stream: &mut ReadHalf<'_>) -> std::io::Result<Packet> {
        let mut packet = Packet::default();
        packet.recv_into(stream).await?;
        Ok(packet)
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

pub async fn dyn_ip_update(number: u32, pin: u16, port: u16) -> anyhow::Result<std::net::Ipv4Addr> {
    let mut packet = Packet::default();
    packet.header = Header {
        kind: PacketKind::DynIpUpdate.kind(),
        length: 8,
    };

    packet.data.clear();
    packet.data.reserve(packet.header.length as usize);
    packet.data.extend_from_slice(&number.to_le_bytes());
    packet.data.extend_from_slice(&pin.to_le_bytes());
    packet.data.extend_from_slice(&port.to_le_bytes());

    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", 11811)).await?;

    let (mut reader, mut writer) = socket.split();

    packet.send(&mut writer).await?;

    packet.recv_into(&mut reader).await?;

    match packet.kind() {
        PacketKind::DynIpUpdateResponse => Ok(<[u8; 4]>::try_from(packet.data)
            .map_err(|err| {
                anyhow::anyhow!(
                    "too little data for ip address. Need 4 bytes got {}",
                    err.len()
                )
            })?
            .into()),
        PacketKind::Error => {
            let first_zero = packet
                .data
                .iter()
                .enumerate()
                .find_map(|(i, x)| (*x == 0).then_some(i));

            bail!(
                "{}",
                std::str::from_utf8(
                    first_zero
                        .map(|i| &packet.data[..i])
                        .unwrap_or(&packet.data),
                )?
            )
        }

        _ => bail!("server returned unexpected packet"),
    }
}
