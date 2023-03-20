use eyre::eyre;
use std::{net::SocketAddr, time::Instant};
use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
    select,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, instrument, trace};

use crate::{
    auth::dyn_ip_update,
    constants::{AUTH_TIMEOUT, CALL_ACK_TIMEOUT, CALL_TIMEOUT, PING_TIMEOUT, SEND_PING_INTERVAL},
    packets::{Header, Packet, PacketKind, RemConnect, REJECT_OOP, REJECT_TIMEOUT},
    ports::{PortHandler, PortStatus},
    Config, HandlerMetadata,
};

/// # Errors
/// - the client authentication fails
#[instrument(skip(config, port_handler, handler_metadata))]
async fn authenticate(
    config: &Config,
    port_handler: &Mutex<PortHandler>,
    handler_metadata: &mut HandlerMetadata,
    number: u32,
    pin: u16,
) -> eyre::Result<Option<u16>> {
    let mut authenticated = false;
    loop {
        let mut updated_server = false;

        let port = port_handler
            .lock()
            .await
            .allocate_port_for_number(config, number);

        let Some(port) = port else {
            return Ok(None);
        };

        // make sure the client is authenticated before opening any ports
        if !authenticated {
            let _ip = dyn_ip_update(&config.dyn_ip_server, number, pin, port).await?;
            authenticated = true;
            updated_server = true;
        }

        let mut port_handler = port_handler.lock().await;

        let listener = if let Some((listener, _packet)) = port_handler.stop_rejector(port).await {
            Ok(listener)
        } else {
            TcpListener::bind((config.listen_addr.ip(), port)).await
        };

        if let Ok(listener) = listener {
            // make sure that if we have an error, we still have access
            // to the listener in the error handler.
            handler_metadata.listener = Some(listener);

            // if we authenticated a client for a port we then failed to open
            // we need to update the server here once a port that can be opened
            // has been found
            if !updated_server {
                let _ip = dyn_ip_update(&config.dyn_ip_server, number, pin, port).await?;
            }

            port_handler.register_update();
            port_handler
                .port_state
                .entry(port)
                .or_default()
                .new_state(PortStatus::Idle);

            handler_metadata.port = Some(port);

            break Ok(Some(port));
        }

        port_handler.mark_port_error(number, port);
    }
}

#[derive(Debug)]
enum IdleResult {
    Caller {
        packet: Packet,
        stream: TcpStream,
        addr: SocketAddr,
    },
    Disconnect {
        packet: Packet,
    },
}

#[instrument(skip(listener, reader, writer, packet))]
async fn idle(
    listener: &mut TcpListener,
    mut packet: Packet,
    reader: &mut ReadHalf<'_>,
    writer: &mut WriteHalf<'_>,
) -> eyre::Result<Option<IdleResult>> {
    let mut last_ping_sent_at = Instant::now();
    let mut last_ping_received_at = Instant::now();

    loop {
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
                break Ok(Some(IdleResult::Caller { packet, stream, addr }))
            },
            _ = Packet::peek_packet_kind(reader) => {
                packet.recv_into(reader).await?;

                if packet.kind() == PacketKind::Ping {
                    trace!("received ping");
                    last_ping_received_at = Instant::now();
                } else {
                    break Ok(Some(IdleResult::Disconnect { packet }))
                }
            },
            _ = sleep(send_next_ping_in) => {
                trace!("sending ping");
                writer.write_all(bytemuck::bytes_of(& Header { kind: PacketKind::Ping.raw(), length: 0 })).await?;
                last_ping_sent_at = Instant::now();
            }
            _ = sleep(next_ping_expected_in) => {

                writer.write_all(REJECT_TIMEOUT).await?;
                break Ok(None);
            }
        }
    }
}

#[instrument(skip(port_handler, handler_metadata, writer))]
async fn notify_or_disconnect(
    result: IdleResult,
    handler_metadata: &mut HandlerMetadata,
    port_handler: &Mutex<PortHandler>,
    port: u16,
    writer: &mut WriteHalf<'_>,
) -> eyre::Result<Option<(TcpStream, Packet)>> {
    match result {
        IdleResult::Disconnect { mut packet } => {
            if matches!(packet.kind(), PacketKind::End | PacketKind::Reject) {
                info!(?packet, "got disconnect packet");

                packet.header.kind = PacketKind::Reject.raw();

                if packet.data.is_empty() {
                    packet.data.extend_from_slice(b"nc\0");
                    packet.header.length = packet.data.len().try_into().unwrap();
                }

                port_handler.lock().await.start_rejector(
                    port,
                    handler_metadata
                        .listener
                        .take()
                        .expect("tried to start rejector twice"),
                    packet,
                );
                Ok(None)
            } else {
                Err(eyre!("unexpected packet: {:?}", packet.kind()))
            }
        }
        IdleResult::Caller {
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
                length: packet.data.len().try_into().unwrap(), // ip addresses are less then 255 bytes long
            };

            packet.send(writer).await?;

            Ok(Some((stream, packet)))
        }
    }
}

fn print_addr(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map_or_else(|_| "?".to_owned(), |addr| format!("{addr}"))
}

#[instrument(skip(packet, port_handler, handler_metadata, caller, client), fields(client_addr = print_addr(client), caller_addr = print_addr(caller)))]
async fn connect(
    mut packet: Packet,
    port_handler: &Mutex<PortHandler>,
    port: u16,
    handler_metadata: &mut HandlerMetadata,
    client: &mut TcpStream,
    caller: &mut TcpStream,
) -> eyre::Result<()> {
    info!(
        client_addr = print_addr(client),
        caller_addr = print_addr(caller),
        "connecting clients"
    );

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
        );
    }

    client.set_nodelay(true)?;
    caller.set_nodelay(true)?;

    let _ = timeout(CALL_TIMEOUT, tokio::io::copy_bidirectional(client, caller)).await;

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
                    length: packet.data.len().try_into().unwrap(),
                };
            })
            .await?;
    }

    Ok(())
}

/// # Errors
/// - the connection to the client or the caller is interupted
/// - the clients sends unexpected or malformed packets
/// - accepting a tcp connection fails
/// - settings tcp socket properties fails
/// - the client authentication fails
#[instrument(skip_all)]
pub async fn handler(
    client: &mut TcpStream,
    addr: SocketAddr,
    config: &Config,
    handler_metadata: &mut HandlerMetadata,
    port_handler: &Mutex<PortHandler>,
) -> eyre::Result<()> {
    let (mut reader, mut writer) = client.split();

    let mut packet = Packet::default();

    let Ok(res) = timeout(AUTH_TIMEOUT, packet.recv_into_cancelation_safe(&mut reader)).await else {
        writer.write_all(REJECT_TIMEOUT).await?;
        return Ok(());
    };
    res?;

    let RemConnect { number, pin } = packet.as_rem_connect()?;

    handler_metadata.number = Some(number);

    let Some(port) = authenticate(config, port_handler, handler_metadata, number, pin).await? else {
        writer.write_all(REJECT_OOP).await?;
        return Ok(());
    };

    info!(%addr, number, port, "authenticated");

    let Some(listener) = handler_metadata.listener.as_mut() else {
        unreachable!("client sucessfully authenticated but did not set handler_metadata.listener");
    };

    packet.header = Header {
        kind: PacketKind::RemConfirm.raw(),
        length: 0,
    };
    packet.data.clear();
    packet.send(&mut writer).await?;

    let Some(idle_result) = idle(
        listener,
        packet,
        &mut reader,
        &mut writer,
    ).await? else {
        return Ok(());
    };

    let Some((mut caller, mut packet)) = notify_or_disconnect(idle_result, handler_metadata, port_handler, port, &mut writer).await? else {
        return Ok(());
   };

    let notify_at = Instant::now();

    loop {
        let recv = timeout(
            CALL_ACK_TIMEOUT.saturating_sub(notify_at.elapsed()),
            packet.recv_into_cancelation_safe(&mut reader),
        );

        let Ok(res) = recv.await else {
           writer.write_all(REJECT_TIMEOUT).await?;
           return Ok(());
       };
        res?;

        match packet.kind() {
            PacketKind::Ping => {}
            PacketKind::End | PacketKind::Reject => {
                port_handler.lock().await.start_rejector(
                    port,
                    handler_metadata
                        .listener
                        .take()
                        .expect("tried to start rejector twice"),
                    packet,
                );

                return Ok(());
            }

            PacketKind::RemAck => {
                connect(
                    packet,
                    port_handler,
                    port,
                    handler_metadata,
                    client,
                    &mut caller,
                )
                .await?;

                return Ok(());
            }

            kind => return Err(eyre!("unexpected packet: {:?}", kind)),
        }
    }
}
