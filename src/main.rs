#![feature(generic_const_exprs)]
#![allow(unused)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Debug,
    fs::File,
    future::Future,
    io::{BufReader, BufWriter},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use packets::{reject_static, Header, Packet, RemConnect};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    select,
    task::JoinHandle,
    time::Instant,
};

use crate::packets::dyn_ip_update;

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(15);
const TIMEOUT_DELAY: Duration = Duration::from_secs(35);
const PORT_TIMEOUT: Duration = Duration::from_secs(60);
const PORT_RETRY_TIME: Duration = Duration::from_secs(60); // 10 *

const BIND_IP: &str = "0.0.0.0";

mod packets;

type Port = u16;
type Number = u32;
type UnixTimestamp = u64;

#[derive(Default, Debug, Serialize, Deserialize)]
struct Config {
    allowed_ports: AllowedPorts,
}

impl Config {
    fn load(db: &Path) -> std::io::Result<Self> {
        println!("loading config");
        Ok(serde_json::from_reader(BufReader::new(File::open(db)?))?)
    }

    fn load_or_default(db: &Path) -> std::io::Result<Self> {
        match Self::load(db) {
            Ok(db) => Ok(db),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err),
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct PortHandler {
    #[serde(skip)]
    last_update: Option<Instant>,

    #[serde(skip)]
    port_guards: HashMap<Port, PortGuard>,

    allowed_ports: AllowedPorts,

    free_ports: HashSet<Port>,
    errored_ports: BTreeSet<(UnixTimestamp, Port)>,
    allocated_ports: HashMap<Number, Port>,
    port_status: HashMap<Port, PortStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PortStatus {}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
struct AllowedPorts(Vec<Range<u16>>);

impl AllowedPorts {
    fn is_allowed(&self, port: Port) -> bool {
        self.0.iter().any(|range| range.contains(&port))
    }
}

impl PortHandler {
    fn register_update(&mut self) {
        self.last_update = Some(Instant::now());
    }

    fn store(&self, db: &Path) -> anyhow::Result<()> {
        println!("storing database");
        serde_json::to_writer(BufWriter::new(File::create(db)?), self)?;
        Ok(())
    }

    fn load(db: &Path) -> std::io::Result<Self> {
        println!("loading database");
        Ok(serde_json::from_reader(BufReader::new(File::open(db)?))?)
    }

    fn load_or_default(db: &Path) -> std::io::Result<Self> {
        match Self::load(db) {
            Ok(db) => Ok(db),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err),
        }
    }

    fn update_allowed_ports(&mut self, allowed_ports: &AllowedPorts) {
        self.register_update();

        self.allowed_ports = allowed_ports.clone();

        self.free_ports.clear();
        self.free_ports
            .extend(self.allowed_ports.0.iter().cloned().flatten());

        self.free_ports.shrink_to_fit(); // we are at the maximum number of ports we'll ever reach

        self.errored_ports
            .retain(|(_, port)| self.allowed_ports.is_allowed(*port));

        self.allocated_ports
            .retain(|_, port| self.allowed_ports.is_allowed(*port));

        self.free_ports.retain(|port| {
            self.allocated_ports
                .iter()
                .find(|(_, allocated_port)| *allocated_port == port)
                .is_none()
                && self
                    .errored_ports
                    .iter()
                    .find(|(_, errored_port)| errored_port == port)
                    .is_none()
        });
    }

    fn start_port_guard<'fut, Fut, Func>(&mut self, port: Port, listener: TcpListener, f: Func)
    where
        Fut: Future<Output = ()> + Send + 'fut,
        Func: FnOnce(&'_ mut TcpListener) -> Fut + Send + 'static,
    {
        assert!(self
            .port_guards
            .insert(port, PortGuard::start(listener, f))
            .is_none());
    }

    fn start_rejector(&mut self, port: Port, listener: TcpListener, packet: Packet) {
        assert!(self
            .port_guards
            .insert(
                port,
                PortGuard::start(listener, move |listener: &mut TcpListener| async move {
                    loop {
                        if let Ok((mut socket, _)) = listener.accept().await {
                            let (_, mut writer) = socket.split();
                            let _ = packet.send(&mut writer).await;
                        }
                    }
                })
            )
            .is_none());
    }
}

struct PortGuard {
    listener: Arc<tokio::sync::Mutex<TcpListener>>,
    handle: JoinHandle<()>,
}

impl Debug for PortGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortGuard").finish()
    }
}

impl PortGuard {
    fn start<'fut, Fut>(
        listener: TcpListener,
        f: impl FnOnce(&mut TcpListener) -> Fut + Send + 'static,
    ) -> Self
    where
        Fut: Future<Output = ()> + Send + 'fut,
    {
        let mut listener = Arc::new(tokio::sync::Mutex::new(listener));

        let handle = {
            let listener = listener.clone();

            tokio::spawn(async move {
                let mut lock = listener.lock().await;
                f(&mut *lock).await;
            })
        };

        Self { listener, handle }
    }

    async fn stop(mut self) -> TcpListener {
        self.handle.abort();
        let _ = self.handle.await;
        Arc::try_unwrap(self.listener).unwrap().into_inner()
    }
}

impl PortHandler {
    fn allocate_port_for_number(&mut self, number: Number) -> Option<Port> {
        if let Some(port) = self.allocated_ports.get(&number) {
            return Some(*port);
        }

        let port = if let Some(&port) = self.free_ports.iter().next() {
            self.register_update();
            self.free_ports.remove(&port);
            port
        } else {
            self.try_recover_port()?
        };

        assert!(self.allocated_ports.insert(number, port).is_none());
        Some(port)
    }

    fn try_recover_port(&mut self) -> Option<Port> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let mut recovered_port = None;

        self.errored_ports = std::mem::take(&mut self.errored_ports)
            .into_iter()
            .filter_map(|(mut timestamp, mut port)| {
                if recovered_port.is_none()
                    && now.saturating_sub(Duration::from_secs(timestamp)) >= PORT_RETRY_TIME
                {
                    println!(
                        " trying port: {port} at -{:?}",
                        Duration::from_secs(now.as_secs())
                            .saturating_sub(Duration::from_secs(timestamp))
                    );

                    match std::net::TcpListener::bind((BIND_IP, port)) {
                        Ok(_) => {
                            recovered_port = Some((timestamp, port));
                            return None;
                        }
                        Err(_) => timestamp = now.as_secs(),
                    }
                } else {
                    println!(
                        "skipped port: {port} at -{:?}",
                        Duration::from_secs(now.as_secs())
                            .saturating_sub(Duration::from_secs(timestamp))
                    );
                }

                Some((timestamp, port))
            })
            .collect();

        if let Some((_, port)) = recovered_port {
            println!("recovered_port: {port}");
            return Some(port);
        }

        None // TODO
    }

    fn mark_port_error(&mut self, number: Number, port: Port) {
        self.register_update();

        self.errored_ports.insert((
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            port,
        ));

        self.allocated_ports.remove(&number);
        self.free_ports.remove(&port);
    }

    fn open_port(&mut self, port: Port) -> Option<TcpListener> {
        todo!()
    }

    fn close_port_for(&mut self, number: Number, listener: TcpListener) -> anyhow::Result<()> {
        todo!()
    }
}

async fn connection_handler(
    port_handler: Arc<Mutex<PortHandler>>,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.split();

    let mut packet = Packet::recv(&mut reader).await?;

    let RemConnect { number, pin } = packet.as_rem_connect()?;

    let (port, listener) = loop {
        let port = port_handler
            .lock()
            .unwrap()
            .allocate_port_for_number(number);

        println!("allocated port: {:?}", port);

        let Some(port) = port else {
            writer.write_all(&reject_static(b"oop")).await?;
            return Ok(());
        };

        let ip = dyn_ip_update(number, pin, port).await?;

        let listener = TcpListener::bind((BIND_IP, port)).await;

        let listener = match listener {
            Ok(listener) => break (port, listener),
            Err(err) => {
                port_handler.lock().unwrap().mark_port_error(number, port);
                // tokio::time::sleep(Duration::from_millis(300)).await;
                continue;
            }
        };
    };

    #[derive(Debug)]
    enum Foo {
        Caller { stream: TcpStream, addr: SocketAddr },
        Packet { packet: Packet },
    }

    let result = select! {
        kind = Packet::peek_packet_kind(&mut reader) => {
            packet.recv_into(&mut reader).await?;
            Foo::Packet { packet }
        },
        caller = listener.accept() => {
            let (stream, addr) = caller?;
            Foo::Caller { stream, addr }
        },
    };

    dbg!(&result);

    match result {
        Foo::Caller { stream, addr } => todo!(),
        Foo::Packet { mut packet } => {
            match packet.kind() {
                packets::PacketKind::End => {
                    packet.header = Header { kind: 3, length: 0 };
                    packet.data.clear();
                }
                packets::PacketKind::Reject => {}

                kind => bail!("unexpected packet: {kind:?}"),
            }
            port_handler
                .lock()
                .unwrap()
                .start_rejector(port, listener, packet);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load_or_default("config.json".as_ref())?;

    if config.allowed_ports.0.is_empty() {
        panic!("no allowed ports");
    }

    let db_path = PathBuf::from("db.json");

    let mut port_handler = PortHandler::load_or_default(&db_path)?;
    port_handler.update_allowed_ports(&config.allowed_ports);

    let port_handler = Arc::new(Mutex::new(port_handler));

    {
        let port_handler = port_handler.clone();
        tokio::spawn(async move {
            let mut last_store = None;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let port_handler = port_handler.lock().unwrap();

                if let Some(last_update) = port_handler.last_update {
                    let should_store = last_store
                        .map(|last_store| last_update > last_store)
                        .unwrap_or(true);

                    if should_store {
                        last_store = Some(last_update);
                        port_handler.store(&db_path).unwrap();
                    }
                }
            }
        });
    }

    let listener = TcpListener::bind(("127.0.0.1", 11812)).await?;

    while let Ok((mut stream, addr)) = listener.accept().await {
        println!("connection from {addr}");

        let port_handler = port_handler.clone();

        tokio::spawn(async move {
            if let Err(err) = connection_handler(port_handler, &mut stream).await {
                println!("client at {addr} had an error: {err}");

                let mut packet = Packet::default();

                packet.data.extend_from_slice(err.to_string().as_bytes());
                packet.data.truncate(0xfe);
                packet.data.push(0);
                packet.header = Header {
                    kind: 0xff,
                    length: packet.data.len() as u8,
                };

                let (_, mut writer) = stream.split();
                let _ = packet.send(&mut writer).await;
            }
        });
    }

    Ok(())
}
