use std::net::SocketAddr;

use anyhow::bail;
use tracing::debug;

use crate::packets::{Header, Packet, PacketKind};

/// # Errors
/// - the dyn ip server returns a malformed response or is unreachable
/// - the authentication fails
pub async fn dyn_ip_update(
    server: &SocketAddr,
    number: u32,
    pin: u16,
    port: u16,
) -> anyhow::Result<std::net::Ipv4Addr> {
    debug!(%number, %port, "starting dyn ip update");

    let mut packet = Packet {
        header: Header {
            kind: PacketKind::DynIpUpdate.raw(),
            length: 8,
        },
        data: Vec::new(),
    };

    packet.data.clear();
    packet.data.reserve(packet.header.length as usize);
    packet.data.extend_from_slice(&number.to_le_bytes());
    packet.data.extend_from_slice(&pin.to_le_bytes());
    packet.data.extend_from_slice(&port.to_le_bytes());

    let mut socket = tokio::net::TcpStream::connect(server).await?;

    let (mut reader, mut writer) = socket.split();

    packet.send(&mut writer).await?;

    packet.recv_into(&mut reader).await?;

    let result = match packet.kind() {
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
                std::str::from_utf8(first_zero.map_or(&packet.data, |i| &packet.data[..i]),)?
            )
        }

        _ => bail!("server returned unexpected packet"),
    };

    debug!(?result, "finished dyn ip update");

    result
}
