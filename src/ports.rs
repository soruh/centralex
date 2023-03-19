use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::{Debug, Display},
    fs::File,
    io::{BufReader, BufWriter},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{watch::Receiver, Mutex},
    task::JoinHandle,
    time::Instant,
};
use tracing::{debug, error, info, warn};

use crate::{
    constants::{CACHE_STORE_INTERVAL, PORT_OWNERSHIP_TIMEOUT, PORT_RETRY_TIME},
    packets::Packet,
    spawn, Config, Number, Port, UnixTimestamp, TIME_FORMAT, TIME_ZONE_OFFSET,
};

#[derive(Default, Serialize, Deserialize)]
pub struct PortHandler {
    #[serde(skip)]
    pub last_update: Option<Instant>,

    #[serde(skip)]
    pub change_sender: Option<tokio::sync::watch::Sender<Instant>>,

    #[serde(skip)]
    port_guards: HashMap<Port, Rejector>,

    allowed_ports: AllowedList,

    #[serde(skip)]
    free_ports: HashSet<Port>,
    errored_ports: BTreeSet<(UnixTimestamp, Port)>,
    allocated_ports: HashMap<Number, Port>,

    pub port_state: HashMap<Port, PortState>,
}

pub async fn cache_daemon(
    port_handler: Arc<Mutex<PortHandler>>,
    cache_path: PathBuf,
    mut change_receiver: Receiver<Instant>,
) {
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

        if time_since_last_store >= CACHE_STORE_INTERVAL {
            let port_handler = port_handler.lock().await;

            last_store = Instant::now();
            if let Err(err) = port_handler.store(&cache_path) {
                error!("failed to store cache: {err:?}");
            }
        } else {
            change_timeout = Some(CACHE_STORE_INTERVAL - time_since_last_store);
        }
    }
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
        _ => format!("{duration:.0?}"),
    }
}

fn format_instant(instant: Instant) -> String {
    let when = duration_in_hours(instant.elapsed()) + " ago";

    (|| -> anyhow::Result<_> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)? - instant.elapsed();
        let date = time::OffsetDateTime::from_unix_timestamp(
            timestamp.as_secs().try_into().expect("timestamp overflow"),
        )?
        .to_offset(*TIME_ZONE_OFFSET.get().unwrap())
        .format(TIME_FORMAT.get().unwrap())?;

        Ok(format!("{date} ({when})"))
    })()
    .unwrap_or(when)
}

fn instant_from_timestamp(timestamp: UnixTimestamp) -> Instant {
    Instant::now() - UNIX_EPOCH.elapsed().unwrap() + Duration::from_secs(timestamp)
}

impl Debug for PortHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SHOW_N_FREE_PORTS: usize = 10;

        let last_update = self
            .last_update
            .map(|last_update| Cow::from(format_instant(last_update)))
            .unwrap_or(Cow::from("?"));

        let mut free_ports = self.free_ports.iter().copied().collect::<Vec<u16>>();

        free_ports.sort_unstable();

        let mut free_ports = free_ports
            .into_iter()
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

        let mut allocated_ports = self
            .allocated_ports
            .iter()
            .map(|(&number, &port)| {
                #[derive(Debug)]
                #[allow(dead_code)]
                struct State {
                    state: PortStatus,
                    number: u32,
                    port: u16,
                    last_change: DisplayAsDebug<String>,
                }

                let state = &self.port_state[&port];

                State {
                    state: state.status,
                    number,
                    port,
                    last_change: DisplayAsDebug(format_instant(instant_from_timestamp(
                        state.last_change,
                    ))),
                }
            })
            .collect::<Vec<_>>();

        allocated_ports.sort_unstable_by(|a, b| {
            a.state.cmp(&b.state).then(
                self.port_state[&a.port]
                    .last_change
                    .cmp(&self.port_state[&b.port].last_change)
                    .reverse(),
            )
        });

        writeln!(f, "last update: {last_update}")?;
        writeln!(f, "rejectors: {:#?}", self.port_guards)?;
        writeln!(f, "allowed ports: {:?}", self.allowed_ports.0)?;
        writeln!(f, "free ports: {free_ports:?}")?;

        writeln!(f, "errored ports: {errored_ports:#?}")?;
        writeln!(f, "allocated ports: {allocated_ports:#?}")?;

        Ok(())
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
            .expect("timestamp overflow")
            .as_secs();

        self.status = status;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, PartialOrd, Ord)]
pub enum PortStatus {
    InCall,
    Idle,
    Disconnected,
}

impl Default for PortStatus {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct AllowedList(Vec<RangeInclusive<u16>>);

impl AllowedList {
    #[must_use]
    pub fn is_allowed(&self, port: Port) -> bool {
        self.0.iter().any(|range| range.contains(&port))
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PortHandler {
    #[must_use]
    pub fn status_string(&self) -> String {
        format!("{self:#?}\n")
    }

    pub fn register_update(&mut self) {
        let now = Instant::now();
        self.last_update = Some(now);
        self.change_sender
            .as_ref()
            .expect("PortHandler is missing it's change_sender")
            .send(now)
            .expect("failed to notify cache writer");
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn store(&self, cache: &Path) -> std::io::Result<()> {
        debug!("storing cache");
        let temp_file = cache.with_extension(".temp");

        serde_json::to_writer(BufWriter::new(File::create(&temp_file)?), self)?;
        std::fs::rename(temp_file, cache)?;

        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn load(
        cache: &Path,
        change_sender: tokio::sync::watch::Sender<Instant>,
    ) -> std::io::Result<Self> {
        info!("loading cache");
        let mut cache: Self = serde_json::from_reader(BufReader::new(File::open(cache)?))?;
        cache.change_sender = Some(change_sender);
        Ok(cache)
    }

    #[must_use]
    pub fn load_or_default(
        path: &Path,
        change_sender: tokio::sync::watch::Sender<Instant>,
    ) -> Self {
        Self::load(path, change_sender).unwrap_or_else(|error| {
            error!(?path, %error, "failed to parse cache file");
            Self::default()
        })
    }

    pub fn update_allowed_ports(&mut self, allowed_ports: &AllowedList) {
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
                .any(|(_, allocated_port)| allocated_port == port);

            let is_errored = self
                .errored_ports
                .iter()
                .any(|(_, errored_port)| errored_port == port);

            !(is_allocted || is_errored)
        });
    }

    pub fn start_rejector(&mut self, port: Port, listener: TcpListener, packet: Packet) {
        info!(port, ?packet, "starting rejector");

        let port_guard = Rejector::start(listener, packet);

        if self.port_guards.insert(port, port_guard).is_some() {
            unreachable!("Tried to start rejector that is already running. This should have been impossible since it requires two listeners on the same port.");
        }
    }

    pub async fn stop_rejector(&mut self, port: Port) -> Option<(TcpListener, Packet)> {
        info!(port, "stopping rejector");

        Some(self.port_guards.remove(&port)?.stop().await)
    }

    /// # Errors
    /// - the rejector must be running
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

        self.start_rejector(port, listener, packet);

        Ok(())
    }
}

struct Rejector {
    state: Arc<(Mutex<TcpListener>, Packet)>,
    handle: JoinHandle<()>,
}

impl Debug for Rejector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rejector")
            .field("message", &self.state.1)
            .finish()
    }
}

impl Rejector {
    fn start(listener: TcpListener, packet: Packet) -> Self {
        let port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
        let state = Arc::new((Mutex::new(listener), packet));

        let handle = {
            let state = state.clone();

            spawn(&format!("rejector for port {port}",), async move {
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
        let port = if let Some(port) = self.allocated_ports.get(&number) {
            let already_connected = self
                .port_state
                .get(port)
                .map_or(false, |state| state.status != PortStatus::Disconnected);

            if already_connected {
                None
            } else {
                Some(*port)
            }
        } else {
            let port = if let Some(&port) = self.free_ports.iter().next() {
                self.register_update();
                self.free_ports.remove(&port);
                port
            } else {
                self.try_recover_port(config)?
            };

            if self.allocated_ports.insert(number, port).is_some() {
                unreachable!("allocated port twice");
            }
            Some(port)
        };

        if let Some(port) = port {
            info!(port, "allocated port");
        }

        port
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
                    info!(
                        port,
                        last_try = ?Duration::from_secs(now.as_secs()).saturating_sub(Duration::from_secs(timestamp)),
                        "retrying errored port",
                    );

                    match std::net::TcpListener::bind((config.listen_addr.ip(), port)) {
                        Ok(_) => {
                            recovered_port = Some((timestamp, port));
                            return None;
                        }
                        Err(_) => timestamp = now.as_secs(),
                    }
                } else {
                    info!(
                        port,
                        last_try = ?Duration::from_secs(now.as_secs()).saturating_sub(Duration::from_secs(timestamp)),
                        "skipped retrying errored port",
                    );
                }

                Some((timestamp, port))
            })
            .collect();

        if let Some((_, port)) = recovered_port {
            self.register_update();
            info!(port, "recovered port");
            return Some(port);
        }

        let removable_entry = self.allocated_ports.iter().find(|(_, port)| {
            self.port_state.get(port).map_or(true, |port_state| {
                port_state.status == PortStatus::Disconnected
                    && now.saturating_sub(Duration::from_secs(port_state.last_change))
                        >= PORT_OWNERSHIP_TIMEOUT
            })
        });

        if let Some((&old_number, &port)) = removable_entry {
            self.register_update();
            info!(port, old_number, "reused port");
            assert!(self.allocated_ports.remove(&old_number).is_some());
            return Some(port);
        }

        None // TODO
    }

    pub fn mark_port_error(&mut self, number: Number, port: Port) {
        warn!(port, number, "registering an error on");
        self.register_update();

        self.errored_ports.insert((
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("timestamp overflow")
                .as_secs(),
            port,
        ));

        self.allocated_ports.remove(&number);
        self.free_ports.remove(&port);
        self.port_state.remove(&port);
    }
}
