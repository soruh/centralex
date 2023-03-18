use std::{
    fmt::Debug,
    fs::File,
    io::BufReader,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use debug_server::debug_server;
use futures::Future;
use packets::{Header, Packet};
use serde::{Deserialize, Deserializer};
use time::format_description::OwnedFormatItem;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::Mutex,
    time::{sleep, Instant},
};
use tracing::{error, info, warn, Level};

use crate::{
    client::connection_handler,
    ports::{AllowedPorts, PortHandler, PortStatus},
};
use crate::{constants::CACHE_STORE_INTERVAL, packets::PacketKind};

pub mod auth;
pub mod client;
pub mod constants;
#[cfg(feature = "debug_server")]
pub mod debug_server;
pub mod packets;
pub mod ports;

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

    // we need to get this while still single threaded
    // as getting the time zone offset in a multithreaded programm
    // is UB in some environments
    TIME_ZONE_OFFSET
        .set(time::UtcOffset::current_local_offset()?)
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
                let registry = registry.with(console_subscriber::spawn());

                registry
                    .with(
                        fmt::layer()
                            .with_target(true)
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
pub struct HandlerMetadata {
    number: Option<Number>,
    port: Option<Port>,
    listener: Option<TcpListener>,
}
