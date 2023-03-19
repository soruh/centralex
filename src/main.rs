#![warn(clippy::pedantic)]
// #![allow(clippy::missing_errors_doc)]

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
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{sleep, Instant},
};
use tracing::{error, info, warn, Level};

use crate::packets::PacketKind;
use crate::ports::{cache_daemon, AllowedList, PortHandler, PortStatus};

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
    allowed_ports: AllowedList,

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
        .map_err(D::Error::custom)
}

fn parse_time_format<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<OwnedFormatItem, D::Error> {
    use serde::de::Error;

    time::format_description::parse_owned::<2>(&String::deserialize(deserializer)?)
        .map_err(D::Error::custom)
}

fn maybe_parse_socket_addr<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SocketAddr>, D::Error> {
    use serde::de::Error;

    Option::<String>::deserialize(deserializer)?
        .map(|s| {
            s.to_socket_addrs()
                .map_err(D::Error::custom)?
                .next()
                .ok_or_else(|| D::Error::invalid_length(0, &"one or more"))
        })
        .transpose()
}

fn parse_socket_addr<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SocketAddr, D::Error> {
    use serde::de::Error;

    let addr = String::deserialize(deserializer)?
        .to_socket_addrs()
        .map_err(D::Error::custom)?
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

fn setup_tracing(config: &Config) {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{filter, fmt};

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
                .with_filter(filter::LevelFilter::from_level(config.log_level))
                .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target().starts_with("centralex")
                })),
        )
        .init();
}

async fn connection_handler(
    mut stream: TcpStream,
    addr: SocketAddr,
    config: Arc<Config>,
    port_handler: Arc<Mutex<PortHandler>>,
) {
    use futures::future::FutureExt;

    let mut handler_metadata = HandlerMetadata::default();

    let res = std::panic::AssertUnwindSafe(client::handler(
        &mut stream,
        addr,
        &config,
        &mut handler_metadata,
        &port_handler,
    ))
    .catch_unwind()
    .await;

    let error = match res {
        Err(err) => {
            let err = err
                .downcast::<String>()
                .map_or_else(|_| "?".to_owned(), |err| *err);

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
            length: packet.data.len().try_into().unwrap(), // this will never fail, as we just truncated the vector
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
            port_handler.start_rejector(
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
        }
    }

    sleep(Duration::from_secs(3)).await;
    let _ = stream.shutdown().await;
}

fn main() -> anyhow::Result<()> {
    let config = Arc::new(Config::load("config.json")?);

    assert!(!config.allowed_ports.is_empty(), "no allowed ports");

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
        .block_on(tokio_main(config))
}

async fn tokio_main(config: Arc<Config>) -> anyhow::Result<()> {
    setup_tracing(&config);

    let cache_path = PathBuf::from("cache.json");

    let (change_sender, change_receiver) = tokio::sync::watch::channel(Instant::now());

    let mut port_handler = PortHandler::load_or_default(&cache_path, change_sender);
    port_handler.update_allowed_ports(&config.allowed_ports);

    let port_handler = Arc::new(Mutex::new(port_handler));

    spawn(
        "cache daemon",
        cache_daemon(port_handler.clone(), cache_path, change_receiver),
    );

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

    while let Ok((stream, addr)) = listener.accept().await {
        info!(%addr, "new connection");

        spawn(
            &format!("connection to {addr}"),
            connection_handler(stream, addr, config.clone(), port_handler.clone()),
        );
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct HandlerMetadata {
    number: Option<Number>,
    port: Option<Port>,
    listener: Option<TcpListener>,
}
