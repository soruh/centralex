use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::{Debug, Display},
    fs::File,
    io::{BufReader, BufWriter},
    ops::RangeInclusive,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle, time::Instant};

use crate::{
    packets::Packet, Config, Number, Port, UnixTimestamp, PORT_OWNERSHIP_TIMEOUT, PORT_RETRY_TIME,
};

#[derive(Default, Serialize, Deserialize)]
pub struct PortHandler {
    #[serde(skip)]
    pub last_update: Option<Instant>,

    #[serde(skip)]
    port_guards: HashMap<Port, Rejector>,

    allowed_ports: AllowedPorts,

    #[serde(skip)]
    free_ports: HashSet<Port>,
    errored_ports: BTreeSet<(UnixTimestamp, Port)>,
    allocated_ports: HashMap<Number, Port>,

    pub port_state: HashMap<Port, PortState>,
}

#[derive(Hash, PartialEq, Eq)]
struct DisplayAsDebug<T: Display>(T);
impl<T: Display> Debug for DisplayAsDebug<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn duration_in_hours(duration: Duration) -> String {
    let seconds_elapsed = duration.as_secs();

    let hours = seconds_elapsed / (60 * 60);
    let minutes = (seconds_elapsed / 60) % 60;
    let seconds = seconds_elapsed % 60;

    match (hours > 0, minutes > 0) {
        (true, _) => format!("{hours}h {minutes}min {seconds}s"),
        (false, true) => format!("{minutes}min {seconds}s"),
        _ => format!("{:.0?}", duration),
    }
}

fn format_instant(instant: Instant) -> String {
    let when = duration_in_hours(instant.elapsed()) + " ago";

    #[cfg(feature = "chrono")]
    let when = (|| -> anyhow::Result<_> {
        use chrono::{Local, TimeZone};

        let date = Local
            .timestamp_opt(
                (SystemTime::now().duration_since(UNIX_EPOCH)? - instant.elapsed())
                    .as_secs()
                    .try_into()?,
                0,
            )
            .latest()
            .ok_or(anyhow!("invalid update timestamp"))?
            .format("%Y-%m-%d %H:%M:%S");

        Ok(format!("{date} ({when})"))
    })()
    .unwrap_or(when);

    when
}

fn instant_from_timestamp(timestamp: UnixTimestamp) -> Instant {
    Instant::now() - UNIX_EPOCH.elapsed().unwrap() + Duration::from_secs(timestamp)
}

impl Debug for PortHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SHOW_N_FREE_PORTS: usize = 20;

        let last_update = self
            .last_update
            .map(|last_update| Cow::from(format_instant(last_update)))
            .unwrap_or(Cow::from("?"));

        let mut free_ports = self
            .free_ports
            .iter()
            .take(SHOW_N_FREE_PORTS)
            .map(|x| DisplayAsDebug(x.to_string()))
            .collect::<Vec<_>>();

        if let Some(n_not_shown) = self.free_ports.len().checked_sub(SHOW_N_FREE_PORTS) {
            if n_not_shown > 0 {
                free_ports.push(DisplayAsDebug(format!("[{n_not_shown} more]")));
            }
        }

        let errored_ports = self
            .errored_ports
            .iter()
            .rev()
            .map(|&(since, port)| {
                DisplayAsDebug(format!(
                    "{port:5}: {}",
                    format_instant(instant_from_timestamp(since))
                ))
            })
            .collect::<Vec<_>>();

        f.debug_struct("PortHandler")
            .field("last_update", &DisplayAsDebug(last_update))
            .field("port_guards", &self.port_guards)
            .field("allowed_ports", &self.allowed_ports.0)
            .field("free_ports", &free_ports)
            .field("errored_ports", &errored_ports)
            .field("allocated_ports", &self.allocated_ports)
            .field("port_state", &self.port_state)
            .finish()
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct PortState {
    last_change: UnixTimestamp,
    #[serde(skip)]
    status: PortStatus,
}

impl Debug for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortState")
            .field(
                "last_change",
                &DisplayAsDebug(format_instant(instant_from_timestamp(self.last_change))),
            )
            .field("status", &self.status)
            .finish()
    }
}

impl PortState {
    pub fn new_state(&mut self, status: PortStatus) {
        self.last_change = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.status = status;
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum PortStatus {
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
pub struct AllowedPorts(Vec<RangeInclusive<u16>>);

impl AllowedPorts {
    pub fn is_allowed(&self, port: Port) -> bool {
        self.0.iter().any(|range| range.contains(&port))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PortHandler {
    pub fn status_string(&self) -> String {
        format!("{self:#?}")
    }

    pub fn register_update(&mut self) {
        self.last_update = Some(Instant::now());
    }

    pub fn store(&self, cache: &Path) -> anyhow::Result<()> {
        println!("storing database");
        let temp_file = cache.with_extension(".temp");

        serde_json::to_writer(BufWriter::new(File::create(&temp_file)?), self)?;
        std::fs::rename(temp_file, cache)?;

        Ok(())
    }

    pub fn load(cache: &Path) -> std::io::Result<Self> {
        println!("loading database");
        Ok(serde_json::from_reader(BufReader::new(File::open(cache)?))?)
    }

    pub fn load_or_default(cache: &Path) -> Self {
        Self::load(cache).unwrap_or_else(|err| {
            println!("failed to parse cache file at {cache:?} using empty cache. error: {err}");
            Self::default()
        })
    }

    pub fn update_allowed_ports(&mut self, allowed_ports: &AllowedPorts) {
        self.register_update();

        self.allowed_ports = allowed_ports.clone();

        self.free_ports.clear(); // remove all ports
        self.free_ports
            .extend(self.allowed_ports.0.iter().cloned().flatten()); // add allowed ports

        self.free_ports.shrink_to_fit(); // we are at the maximum number of ports we'll ever reach

        self.errored_ports
            .retain(|(_, port)| self.allowed_ports.is_allowed(*port)); // remove errored ports that are no longer allowed

        self.allocated_ports
            .retain(|_, port| self.allowed_ports.is_allowed(*port)); // remove allocated ports that are no longer allowed

        self.port_state
            .retain(|port, _| self.allowed_ports.is_allowed(*port)); // remove port states that are no longer allowed

        self.free_ports.retain(|port| {
            let is_allocted = self
                .allocated_ports
                .iter()
                .find(|(_, allocated_port)| *allocated_port == port)
                .is_some();

            let is_errored = self
                .errored_ports
                .iter()
                .find(|(_, errored_port)| errored_port == port)
                .is_some();

            !(is_allocted || is_errored)
        });
    }

    pub fn start_rejector(
        &mut self,
        port: Port,
        listener: TcpListener,
        packet: Packet,
    ) -> anyhow::Result<()> {
        println!("starting rejector: for port {port} with {packet:?}");

        let port_guard = Rejector::start(listener, packet);

        assert!(
            self.port_guards.insert(port, port_guard).is_none(),
            "Tried to start rejector that is already running.
            This should have been impossible since it requires two listeners on the same port."
        );
        Ok(())
    }

    pub async fn stop_rejector(&mut self, port: Port) -> Option<(TcpListener, Packet)> {
        println!("stopping rejector: for port {port}");

        Some(self.port_guards.remove(&port)?.stop().await)
    }

    pub async fn change_rejector(
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

struct Rejector {
    state: Arc<(Mutex<TcpListener>, Packet)>,
    handle: JoinHandle<()>,
}

impl Debug for Rejector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortGuard")
            .field("message", &self.state.1)
            .finish()
    }
}

impl Rejector {
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
    pub fn allocate_port_for_number(&mut self, config: &Config, number: Number) -> Option<Port> {
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
            self.try_recover_port(config)?
        };

        assert!(self.allocated_ports.insert(number, port).is_none());
        Some(port)
    }

    fn try_recover_port(&mut self, config: &Config) -> Option<Port> {
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

                    match std::net::TcpListener::bind((config.listen_addr.ip(), port)) {
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

    pub fn mark_port_error(&mut self, number: Number, port: Port) {
        println!("registering an error on port {port} for number {number}");
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
        self.port_state.remove(&port);
    }
}
