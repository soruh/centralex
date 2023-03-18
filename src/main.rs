use std::{
    fmt::Debug,
    fs::File,
    io::BufReader,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context};
use debug_server::debug_server;
use futures::Future;
use packets::{Header, Packet, RemConnect};
use serde::{Deserialize, Deserializer};
use time::format_description::OwnedFormatItem;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
    sync::Mutex,
    time::{sleep, timeout, Instant},
};
use tracing::{debug, error, info, warn, Level};

use crate::packets::{dyn_ip_update, PacketKind, REJECT_OOP, REJECT_TIMEOUT};
use crate::ports::{AllowedPorts, PortHandler, PortStatus};

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const PORT_RETRY_TIME: Duration = Duration::from_secs(15 * 60);
const PORT_OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(1 * 60 * 60);
const PING_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_PING_INTERVAL: Duration = Duration::from_secs(20);

const CACHE_STORE_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(feature = "debug_server")]
mod debug_server;
mod packets;
mod ports;

type Port = u16;
type Number = u32;
type UnixTimestamp = u64;

#[derive(Debug, Deserialize)]
pub struct Config {
    allowed_ports: AllowedPorts,
    #[serde(deserialize_with = "parse_socket_addr")]
    listen_addr: SocketAddr,
    #[serde(deserialize_with = "parse_socket_addr")]
    dyn_ip_server: SocketAddr,
    #[cfg(feature = "debug_server")]
    #[serde(deserialize_with = "maybe_parse_socket_addr")]
    #[serde(default)]
    debug_server_addr: Option<SocketAddr>,

    #[serde(deserialize_with = "parse_time_format")]
    time_format: OwnedFormatItem,

    #[serde(deserialize_with = "parse_log_level")]
    log_level: Level,
}

fn parse_log_level<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Level, D::Error> {
    use serde::de::Error;

    String::deserialize(deserializer)?
        .parse()
        .map_err(|err| D::Error::custom(err))
}

fn parse_time_format<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<OwnedFormatItem, D::Error> {
    use serde::de::Error;

    time::format_description::parse_owned::<2>(&String::deserialize(deserializer)?)
        .map_err(|err| D::Error::custom(err))
}

fn maybe_parse_socket_addr<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SocketAddr>, D::Error> {
    use serde::de::Error;

    Option::<String>::deserialize(deserializer)?
        .map(|s| {
            Ok::<_, D::Error>(
                s.to_socket_addrs()
                    .map_err(|err| D::Error::custom(err))?
                    .next()
                    .ok_or_else(|| D::Error::invalid_length(0, &"one or more"))?,
            )
        })
        .transpose()
}

fn parse_socket_addr<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SocketAddr, D::Error> {
    use serde::de::Error;

    let addr = String::deserialize(deserializer)?
        .to_socket_addrs()
        .map_err(|err| D::Error::custom(err))?
        .next()
        .ok_or_else(|| D::Error::invalid_length(0, &"one or more"))?;

    Ok(addr)
}

impl Config {
    fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        info!("loading config");
        Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
    }
}

#[cfg(not(feature = "tokio_console"))]
#[track_caller]
fn spawn<T: Send + 'static>(
    _name: &str,
    future: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::spawn(future)
}

#[cfg(feature = "tokio_console")]
#[track_caller]
fn spawn<T: Send + 'static>(
    name: &str,
    future: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::task::Builder::new()
        .name(name)
        .spawn(future)
        .unwrap_or_else(|err| panic!("failed to spawn {name:?}: {err:?}"))
}

static TIME_ZONE_OFFSET: once_cell::sync::OnceCell<time::UtcOffset> =
    once_cell::sync::OnceCell::new();

static TIME_FORMAT: once_cell::sync::OnceCell<OwnedFormatItem> = once_cell::sync::OnceCell::new();

fn main() -> anyhow::Result<()> {
    let config = Arc::new(Config::load("config.json")?);

    if config.allowed_ports.is_empty() {
        panic!("no allowed ports");
    }

    TIME_FORMAT.set(config.time_format.clone()).unwrap();

    TIME_ZONE_OFFSET
        .set(time::UtcOffset::local_offset_at(
            time::OffsetDateTime::UNIX_EPOCH,
        )?)
        .unwrap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            {
                use tracing_subscriber::prelude::*;
                use tracing_subscriber::*;

                // build a `Subscriber` by combining layers with a
                // `tracing_subscriber::Registry`:
                let registry = tracing_subscriber::registry();

                #[cfg(feature = "tokio_console")]
                let registry = registry.with(
                    console_subscriber::ConsoleLayer::builder()
                        .retention(Duration::from_secs(60))
                        .init(),
                );

                registry
                    .with(
                        fmt::layer()
                            .with_target(false)
                            .with_timer(fmt::time::OffsetTime::new(
                                *TIME_ZONE_OFFSET.get().unwrap(),
                                TIME_FORMAT.get().unwrap(),
                            ))
                            .with_filter(filter::LevelFilter::from_level(config.log_level)),
                    )
                    .init();
            }

            let cache_path = PathBuf::from("cache.json");

            let (change_sender, mut change_receiver) = tokio::sync::watch::channel(Instant::now());

            let mut port_handler = PortHandler::load_or_default(&cache_path, change_sender);
            port_handler.update_allowed_ports(&config.allowed_ports);

            let port_handler = Arc::new(Mutex::new(port_handler));

            {
                let port_handler = port_handler.clone();
                spawn("cache daemon", async move {
                    let mut last_store = Instant::now() - 2 * CACHE_STORE_INTERVAL;
                    let mut change_timeout = None;
                    loop {
                        if let Some(change_timeout) = change_timeout.take() {
                            tokio::time::timeout(change_timeout, change_receiver.changed())
                                .await
                                .unwrap_or(Ok(()))
                        } else {
                            change_receiver.changed().await
                        }
                        .expect("failed to wait for cache changes");

                        let time_since_last_store = last_store.elapsed();

                        if time_since_last_store > CACHE_STORE_INTERVAL {
                            let port_handler = port_handler.lock().await;

                            last_store = Instant::now();
                            if let Err(err) = port_handler.store(&cache_path) {
                                error!("failed to store cache: {err:?}");
                            }
                        } else {
                            change_timeout = Some(CACHE_STORE_INTERVAL - time_since_last_store);
                        }
                    }
                });
            }

            #[cfg(feature = "debug_server")]
            if let Some(listen_addr) = config.debug_server_addr {
                warn!(%listen_addr, "debug server listening");
                spawn(
                    "debug server",
                    debug_server(listen_addr, port_handler.clone()),
                );
            }

            let listener = TcpListener::bind(config.listen_addr).await?;
            warn!(
                listen_addr = %config.listen_addr,
                "centralex server listening"
            );

            while let Ok((mut stream, addr)) = listener.accept().await {
                info!(%addr, "new connection");

                let port_handler = port_handler.clone();
                let config = config.clone();

                let mut handler_metadata = HandlerMetadata::default();

                spawn(&format!("connection to {addr}"), async move {
                    use futures::future::FutureExt;

                    let res = std::panic::AssertUnwindSafe(connection_handler(
                        &config,
                        &mut handler_metadata,
                        &port_handler,
                        &mut stream,
                    ))
                    .catch_unwind()
                    .await;

                    let error = match res {
                        Err(err) => {
                            let err = err
                                .downcast::<String>()
                                .map(|err| *err)
                                .unwrap_or_else(|_| "?".to_owned());

                            Some(format!("panic at: {err}"))
                        }
                        Ok(Err(err)) => Some(err.to_string()),
                        Ok(Ok(())) => None,
                    };

                    if let Some(error) = error {
                        error!(%addr, %error, "Client had an error");

                        let mut packet = Packet::default();

                        packet.data.extend_from_slice(error.as_bytes());
                        packet.data.truncate((u8::MAX - 1) as usize);
                        packet.data.push(0);
                        packet.header = Header {
                            kind: PacketKind::Error.raw(),
                            length: packet.data.len() as u8,
                        };

                        let (_, mut writer) = stream.split();
                        let _ = packet.send(&mut writer).await;
                    }

                    if let Some(port) = handler_metadata.port {
                        let mut port_handler = port_handler.lock().await;

                        if let Some(port_state) = port_handler.port_state.get_mut(&port) {
                            port_state.new_state(PortStatus::Disconnected);
                            port_handler.register_update();
                        }

                        if let Some(listener) = handler_metadata.listener.take() {
                            let res = port_handler.start_rejector(
                                port,
                                listener,
                                Packet {
                                    header: Header {
                                        kind: PacketKind::Reject.raw(),
                                        length: 3,
                                    },
                                    data: b"nc\0".to_vec(),
                                },
                            );

                            if let Err(error) = res {
                                error!(%port, %error, "failed to start rejector");
                            }
                        }
                    }

                    sleep(Duration::from_secs(3)).await;
                    let _ = stream.shutdown().await;
                });
            }

            Ok(())
        })
}

#[derive(Debug, Default)]
struct HandlerMetadata {
    number: Option<Number>,
    port: Option<Port>,
    listener: Option<TcpListener>,
}

async fn connection_handler(
    config: &Config,
    handler_metadata: &mut HandlerMetadata,
    port_handler: &Mutex<PortHandler>,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
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

        info!(port, "allocated port");

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
        debug!(
            seconds = SEND_PING_INTERVAL
                .saturating_sub(last_ping_sent_at.elapsed())
                .as_secs(),
            "next ping in"
        );
        debug!(
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
                    debug!("received ping");
                    last_ping_received_at = Instant::now();
                } else {
                    break Result::Packet { packet }
                }
            },
            _ = sleep(send_next_ping_in) => {
                debug!("sending ping");
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
            if matches!(
                packet.kind(),
                packets::PacketKind::End | packets::PacketKind::Reject
            ) {
                info!(?packet, "got disconnect packet");

                if packet.kind() == packets::PacketKind::End {
                    packet.header.kind = packets::PacketKind::Reject.raw();
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
