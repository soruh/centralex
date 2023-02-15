// #![allow(unused)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Debug,
    fs::File,
    io::{BufReader, BufWriter},
    net::{IpAddr, SocketAddr},
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail};
use packets::{Header, Packet, RemConnect};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, Instant},
};

use crate::packets::{dyn_ip_update, PacketKind, REJECT_OOP, REJECT_TIMEOUT};

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const PORT_RETRY_TIME: Duration = Duration::from_secs(15 * 60);
const PORT_OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(1 * 60 * 60);
const PING_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_PING_INTERVAL: Duration = Duration::from_secs(20);

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
    fn load(cache: &Path) -> std::io::Result<Self> {
        println!("loading config");
        Ok(serde_json::from_reader(BufReader::new(File::open(cache)?))?)
    }

    fn load_or_default(cache: &Path) -> std::io::Result<Self> {
        match Self::load(cache) {
            Ok(cache) => Ok(cache),
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

    #[serde(skip)]
    port_state: HashMap<Port, PortState>,
}

#[derive(Default, Debug)]
struct PortState {
    last_change: UnixTimestamp,
    status: PortStatus,
}

impl PortState {
    fn new_state(&mut self, status: PortStatus) {
        self.last_change = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.status = status;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PortStatus {
    Disconnected,
    Idle,
    InCall,
}

impl Default for PortStatus {
    fn default() -> Self {
        Self::Disconnected
    }
}

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

    fn store(&self, cache: &Path) -> anyhow::Result<()> {
        println!("storing database");
        serde_json::to_writer(BufWriter::new(File::create(cache)?), self)?;
        Ok(())
    }

    fn load(cache: &Path) -> std::io::Result<Self> {
        println!("loading database");
        Ok(serde_json::from_reader(BufReader::new(File::open(cache)?))?)
    }

    fn load_or_default(cache: &Path) -> Self {
        Self::load(cache).unwrap_or(Self::default())
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

    fn start_rejector(
        &mut self,
        port: Port,
        listener: TcpListener,
        packet: Packet,
    ) -> anyhow::Result<()> {
        println!("starting rejector: for port {port} with packet {packet:?}");

        let port_guard = PortGuard::start(listener, packet);

        assert!(
            self.port_guards.insert(port, port_guard).is_none(),
            "Tried to start rejector that is already running.
            This should have been impossible since it requires two listeners on the same port."
        );
        Ok(())
    }

    async fn stop_rejector(&mut self, port: Port) -> Option<(TcpListener, Packet)> {
        println!("stopping rejector: for port {port}");

        Some(self.port_guards.remove(&port)?.stop().await)
    }

    async fn change_rejector(
        &mut self,
        port: Port,
        f: impl FnOnce(&mut Packet),
    ) -> anyhow::Result<()> {
        let (listener, mut packet) = self
            .stop_rejector(port)
            .await
            .ok_or_else(|| anyhow!("tried to stop rejector that is not running"))?;

        f(&mut packet);

        self.start_rejector(port, listener, packet)
    }
}

struct PortGuard {
    state: Arc<(Mutex<TcpListener>, Packet)>,
    handle: JoinHandle<()>,
}

impl Debug for PortGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortGuard").finish()
    }
}

impl PortGuard {
    fn start(listener: TcpListener, packet: Packet) -> Self {
        let state = Arc::new((Mutex::new(listener), packet));

        let handle = {
            let state = state.clone();

            tokio::spawn(async move {
                let (listener, packet) = state.as_ref();

                let listener = listener.lock().await;

                loop {
                    if let Ok((mut socket, _)) = listener.accept().await {
                        let (_, mut writer) = socket.split();
                        let _ = packet.send(&mut writer).await;
                    }
                }
            })
        };

        Self { state, handle }
    }
    async fn stop(self) -> (TcpListener, Packet) {
        self.handle.abort();
        let _ = self.handle.await;
        let (listener, packet) = Arc::try_unwrap(self.state).unwrap();
        (listener.into_inner(), packet)
    }
}

impl PortHandler {
    fn allocate_port_for_number(&mut self, number: Number) -> Option<Port> {
        if let Some(port) = self.allocated_ports.get(&number) {
            let already_connected = self
                .port_state
                .get(port)
                .map(|state| state.status != PortStatus::Disconnected)
                .unwrap_or(false);

            return if already_connected { None } else { Some(*port) };
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
            .filter_map(|(mut timestamp, port)| {
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
            self.register_update();
            println!("recovered_port: {port}");
            return Some(port);
        }

        let removable_entry = self.allocated_ports.iter().find(|(_, port)| {
            self.port_state
                .get(port)
                .map(|port_state| {
                    dbg!(port_state).status == PortStatus::Disconnected
                        && dbg!(now.saturating_sub(Duration::from_secs(port_state.last_change)))
                            >= PORT_OWNERSHIP_TIMEOUT
                })
                .unwrap_or(true)
        });

        dbg!(&removable_entry);

        if let Some((&old_number, &port)) = removable_entry {
            self.register_update();
            println!("reused port {port} which used to be allocated to {old_number} which wasn't connected in a long time");
            assert!(self.allocated_ports.remove(&old_number).is_some());
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
}

#[derive(Debug, Default)]
struct HandlerMetadata {
    number: Option<Number>,
    port: Option<Port>,
}

async fn connection_handler(
    handler_metadata: &mut HandlerMetadata,
    port_handler: &Mutex<PortHandler>,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.split();

    let mut packet = Packet::default();

    select! {
        res = packet.recv_into_cancelation_safe(&mut reader) => res?,
        _ = sleep(AUTH_TIMEOUT) => {
            writer.write_all(REJECT_TIMEOUT).await?;
            return Ok(());
        }
    }

    let RemConnect { number, pin } = packet.as_rem_connect()?;

    handler_metadata.number = Some(number);

    let mut authenticated = false;
    let (port, listener) = loop {
        let mut updated_server = false;

        let port = port_handler.lock().await.allocate_port_for_number(number);

        println!("allocated port: {:?}", port);

        let Some(port) = port else {
            writer.write_all(REJECT_OOP).await?;
            return Ok(());
        };

        if !authenticated {
            let _ip = dyn_ip_update(number, pin, port).await?;
            authenticated = true;
            updated_server = true;
        }

        let mut port_handler = port_handler.lock().await;

        let listener = if let Some((listener, _package)) = port_handler.stop_rejector(port).await {
            Ok(listener)
        } else {
            TcpListener::bind((BIND_IP, port)).await
        };

        match listener {
            Ok(listener) => {
                if !updated_server {
                    let _ip = dyn_ip_update(number, pin, port).await?;
                }

                port_handler
                    .port_state
                    .entry(port)
                    .or_default()
                    .new_state(PortStatus::Idle);

                handler_metadata.port = Some(port);

                break (port, listener);
            }
            Err(_err) => {
                port_handler.mark_port_error(number, port);
                continue;
            }
        };
    };

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
        let now = Instant::now();
        // println!("next ping in {:?}s", SEND_PING_INTERVAL.saturating_sub(now.saturating_duration_since(last_ping_sent_at)).as_secs());
        // println!("will timeout in in {:?}s", PING_TIMEOUT.saturating_sub(now.saturating_duration_since(last_ping_received_at)).as_secs());

        select! {
            caller = listener.accept() => {
                let (stream, addr) = caller?;
                break Result::Caller { packet, stream, addr }
            },
            _ = Packet::peek_packet_kind(&mut reader) => {
                packet.recv_into(&mut reader).await?;

                if packet.kind() == PacketKind::Ping {
                    // println!("received ping");
                    last_ping_received_at = Instant::now();
                } else {
                    break Result::Packet { packet }
                }
            },
            _ = sleep(SEND_PING_INTERVAL.saturating_sub(now.saturating_duration_since(last_ping_sent_at))) => {
                // println!("sending ping");
                writer.write_all(bytemuck::bytes_of(& Header { kind: PacketKind::Ping.raw(), length: 0 })).await?;
                last_ping_sent_at = Instant::now();
            }
            _ = sleep(PING_TIMEOUT.saturating_sub(now.saturating_duration_since(last_ping_received_at))) => {
                writer.write_all(REJECT_TIMEOUT).await?;
                return Ok(());
            }
        }
    };

    let (mut client, mut packet) = match result {
        Result::Packet { packet } => {
            if matches!(
                packet.kind(),
                packets::PacketKind::End | packets::PacketKind::Reject
            ) {
                println!("got disconnect packet: {packet:?}");

                port_handler
                    .lock()
                    .await
                    .start_rejector(port, listener, packet)?;
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
            println!("got caller from: {addr}");

            packet.data.clear();
            match addr.ip() {
                IpAddr::V4(addr) => packet.data.extend_from_slice(&addr.octets()),
                IpAddr::V6(addr) => packet.data.extend_from_slice(&addr.octets()),
            }
            packet.header = Header {
                kind: PacketKind::RemCall.raw(),
                length: packet.data.len() as u8,
            };

            packet.send(&mut writer).await?;

            (stream, packet)
        }
    };

    select! {
        res = packet.recv_into_cancelation_safe(&mut reader) => res?,
        _ = sleep(CALL_ACK_TIMEOUT) => {
            writer.write_all(REJECT_TIMEOUT).await?;
            return Ok(());
        }
    }

    match packet.kind() {
        PacketKind::End | PacketKind::Reject => {
            port_handler
                .lock()
                .await
                .start_rejector(port, listener, packet)?;

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

                port_handler.start_rejector(port, listener, packet)?;
            }

            select! {
                _ = tokio::io::copy_bidirectional(stream, &mut client) => {}
                _ = sleep(CALL_TIMEOUT) => {}
            }

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load_or_default("config.json".as_ref())?;

    if config.allowed_ports.0.is_empty() {
        panic!("no allowed ports");
    }

    let cache_path = PathBuf::from("cache.json");

    let mut port_handler = PortHandler::load_or_default(&cache_path);
    port_handler.update_allowed_ports(&config.allowed_ports);

    let port_handler = Arc::new(Mutex::new(port_handler));

    {
        let port_handler = port_handler.clone();
        tokio::spawn(async move {
            let mut last_store = None;
            loop {
                sleep(Duration::from_secs(1)).await;

                let port_handler = port_handler.lock().await;

                if let Some(last_update) = port_handler.last_update {
                    let should_store = last_store
                        .map(|last_store| last_update > last_store)
                        .unwrap_or(true);

                    if should_store {
                        last_store = Some(last_update);
                        port_handler.store(&cache_path).unwrap();
                    }
                }
            }
        });
    }

    let listener = TcpListener::bind(("0.0.0.0", 11820)).await?;

    while let Ok((mut stream, addr)) = listener.accept().await {
        println!("connection from {addr}");

        let port_handler = port_handler.clone();

        let mut handler_metadata = HandlerMetadata::default();

        tokio::spawn(async move {
            let res = connection_handler(&mut handler_metadata, &port_handler, &mut stream).await;

            if let Err(err) = res {
                println!("client at {addr} had an error: {err}");

                let mut packet = Packet::default();

                packet.data.extend_from_slice(err.to_string().as_bytes());
                packet.data.truncate(0xfe);
                packet.data.push(0);
                packet.header = Header {
                    kind: PacketKind::Error.raw(),
                    length: packet.data.len() as u8,
                };

                let (_, mut writer) = stream.split();
                let _ = packet.send(&mut writer).await;
            }

            // if let Some(number) = handler_metadata.number {
            //
            // }

            if let Some(port) = handler_metadata.port {
                if let Some(port_state) = port_handler.lock().await.port_state.get_mut(&port) {
                    port_state.new_state(PortStatus::Disconnected);
                }
            }

            sleep(Duration::from_secs(3)).await;
            let _ = stream.shutdown().await;
        });
    }

    Ok(())
}
