use anyhow::{bail, Context};
use std::{net::SocketAddr, time::Instant};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, trace};

use crate::{
    auth::dyn_ip_update,
    constants::{AUTH_TIMEOUT, CALL_ACK_TIMEOUT, CALL_TIMEOUT, PING_TIMEOUT, SEND_PING_INTERVAL},
    packets::{Header, Packet, PacketKind, RemConnect, REJECT_OOP, REJECT_TIMEOUT},
    ports::{PortHandler, PortStatus},
    Config, HandlerMetadata,
};

pub async fn connection_handler(
    config: &Config,
    handler_metadata: &mut HandlerMetadata,
    port_handler: &Mutex<PortHandler>,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let addr = stream.peer_addr()?;

    let (mut reader, mut writer) = stream.split();

    let mut packet = Packet::default();

    match timeout(AUTH_TIMEOUT, packet.recv_into_cancelation_safe(&mut reader)).await {
        Ok(res) => res?,
        Err(_) => {
            writer.write_all(REJECT_TIMEOUT).await?;
            return Ok(());
        }
    }

    let RemConnect { number, pin } = packet.as_rem_connect()?;

    handler_metadata.number = Some(number);

    let mut authenticated = false;
    let port = loop {
        let mut updated_server = false;

        let port = port_handler
            .lock()
            .await
            .allocate_port_for_number(config, number);

        let Some(port) = port else {
            writer.write_all(REJECT_OOP).await?;
            return Ok(());
        };

        // make sure the client is authenticated before opening any ports
        if !authenticated {
            let _ip = dyn_ip_update(&config.dyn_ip_server, number, pin, port)
                .await
                .context("dy-ip update")?;
            authenticated = true;
            updated_server = true;
        }

        let mut port_handler = port_handler.lock().await;

        let listener = if let Some((listener, _packet)) = port_handler.stop_rejector(port).await {
            Ok(listener)
        } else {
            TcpListener::bind((config.listen_addr.ip(), port)).await
        };

        match listener {
            Ok(listener) => {
                // make sure that if we have an error, we still have access
                // to the listener in the error handler.
                handler_metadata.listener = Some(listener);

                // if we authenticated a client for a port we then failed to open
                // we need to update the server here once a port that can be opened
                // has been found
                if !updated_server {
                    let _ip = dyn_ip_update(&config.dyn_ip_server, number, pin, port)
                        .await
                        .context("dy-ip update")?;
                }

                port_handler.register_update();
                port_handler
                    .port_state
                    .entry(port)
                    .or_default()
                    .new_state(PortStatus::Idle);

                handler_metadata.port = Some(port);

                break port;
            }
            Err(_err) => {
                port_handler.mark_port_error(number, port);
                continue;
            }
        };
    };

    info!(%addr, number, port, "authenticated");

    let listener = handler_metadata.listener.as_mut().unwrap(); // we only break from the loop if this is set

    packet.header = Header {
        kind: PacketKind::RemConfirm.raw(),
        length: 0,
    };
    packet.data.clear();
    packet.send(&mut writer).await?;

    #[derive(Debug)]
    enum Result {
        Caller {
            packet: Packet,
            stream: TcpStream,
            addr: SocketAddr,
        },
        Packet {
            packet: Packet,
        },
    }

    let mut last_ping_sent_at = Instant::now();
    let mut last_ping_received_at = Instant::now();

    let result = loop {
        trace!(
            seconds = SEND_PING_INTERVAL
                .saturating_sub(last_ping_sent_at.elapsed())
                .as_secs(),
            "next ping in"
        );
        trace!(
            seconds = PING_TIMEOUT
                .saturating_sub(last_ping_received_at.elapsed())
                .as_secs(),
            "timeout in",
        );

        let send_next_ping_in = SEND_PING_INTERVAL.saturating_sub(last_ping_sent_at.elapsed());
        let next_ping_expected_in = PING_TIMEOUT.saturating_sub(last_ping_received_at.elapsed());

        select! {
            caller = listener.accept() => {
                let (stream, addr) = caller?;
                break Result::Caller { packet, stream, addr }
            },
            _ = Packet::peek_packet_kind(&mut reader) => {
                packet.recv_into(&mut reader).await?;

                if packet.kind() == PacketKind::Ping {
                    trace!("received ping");
                    last_ping_received_at = Instant::now();
                } else {
                    break Result::Packet { packet }
                }
            },
            _ = sleep(send_next_ping_in) => {
                trace!("sending ping");
                writer.write_all(bytemuck::bytes_of(& Header { kind: PacketKind::Ping.raw(), length: 0 })).await?;
                last_ping_sent_at = Instant::now();
            }
            _ = sleep(next_ping_expected_in) => {
                writer.write_all(REJECT_TIMEOUT).await?;
                return Ok(());
            }
        }
    };

    let (mut client, mut packet) = match result {
        Result::Packet { mut packet } => {
            if matches!(packet.kind(), PacketKind::End | PacketKind::Reject) {
                info!(?packet, "got disconnect packet");

                if packet.kind() == PacketKind::End {
                    packet.header.kind = PacketKind::Reject.raw();
                    packet.data.clear();
                    packet.data.extend_from_slice(b"nc\0");
                    packet.header.length = packet.data.len() as u8;
                }

                port_handler.lock().await.start_rejector(
                    port,
                    handler_metadata
                        .listener
                        .take()
                        .expect("tried to start rejector twice"),
                    packet,
                )?;
                return Ok(());
            } else {
                bail!("unexpected packet: {:?}", packet.kind())
            }
        }
        Result::Caller {
            mut packet,
            stream,
            addr,
        } => {
            info!(%addr, "got caller from");

            packet.data.clear();
            /* The I-Telex Clients can't handle data in this packet due to a bug
            match addr.ip() {
                IpAddr::V4(addr) => packet.data.extend_from_slice(&addr.octets()),
                IpAddr::V6(addr) => packet.data.extend_from_slice(&addr.octets()),
            }
            */
            packet.header = Header {
                kind: PacketKind::RemCall.raw(),
                length: packet.data.len() as u8,
            };

            packet.send(&mut writer).await?;

            (stream, packet)
        }
    };

    match timeout(
        CALL_ACK_TIMEOUT,
        packet.recv_into_cancelation_safe(&mut reader),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            writer.write_all(REJECT_TIMEOUT).await?;
            return Ok(());
        }
    }

    match packet.kind() {
        PacketKind::End | PacketKind::Reject => {
            port_handler.lock().await.start_rejector(
                port,
                handler_metadata
                    .listener
                    .take()
                    .expect("tried to start rejector twice"),
                packet,
            )?;

            return Ok(());
        }

        PacketKind::RemAck => {
            packet.header = Header {
                kind: PacketKind::Reject.raw(),
                length: 4,
            };
            packet.data.clear();
            packet.data.extend_from_slice(b"occ");
            packet.data.push(0);

            {
                let mut port_handler = port_handler.lock().await;

                port_handler.register_update();
                port_handler
                    .port_state
                    .entry(port)
                    .or_default()
                    .new_state(PortStatus::InCall);

                port_handler.start_rejector(
                    port,
                    handler_metadata
                        .listener
                        .take()
                        .expect("tried to start rejector twice"),
                    packet,
                )?;
            }

            stream.set_nodelay(true)?;
            client.set_nodelay(true)?;

            let _ = timeout(
                CALL_TIMEOUT,
                tokio::io::copy_bidirectional(stream, &mut client),
            )
            .await;

            {
                let mut port_handler = port_handler.lock().await;

                port_handler.register_update();
                port_handler
                    .port_state
                    .entry(port)
                    .or_default()
                    .new_state(PortStatus::Disconnected);

                port_handler
                    .change_rejector(port, |packet| {
                        packet.data.clear();
                        packet.data.extend_from_slice(b"nc");
                        packet.data.push(0);
                        packet.header = Header {
                            kind: PacketKind::Reject.raw(),
                            length: packet.data.len() as u8,
                        };
                    })
                    .await?;
            }

            return Ok(());
        }

        kind => bail!("unexpected packet: {:?}", kind),
    }
}
