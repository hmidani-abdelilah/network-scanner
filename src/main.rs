use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::OpenOptions,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, OnceLock,
    },
    time::{Duration, Instant},
};

use egui::{Color32, RichText};
use ipnetwork::Ipv4Network;
use pnet::{
    datalink::{self, Channel, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};
use serde::Serialize;
use tokio::{net::TcpSocket, runtime::Runtime, sync::mpsc as async_mpsc, task::JoinSet};

const MAX_ADDRESSES: u32 = 4096;
const MAX_PORTS: usize = 256;
const TCP_CONCURRENCY: usize = 256;
const ARP_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Serialize)]
struct Device {
    status: String,
    ip_address: Ipv4Addr,
    mac_address: String,
    vendor: String,
    open_ports: String,
}

enum Event {
    Device(Device),
    Status(String),
    Progress(Progress),
    Capture(CaptureState),
    Finished(Result<(), String>),
}

#[derive(Clone, Copy, Default)]
struct Progress {
    completed: usize,
    total: usize,
    discovery_done: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SortBy {
    #[default]
    Ip,
    Vendor,
    OpenPorts,
}

impl Device {
    fn matches(&self, query: &str, open_only: bool) -> bool {
        if open_only && self.open_ports.is_empty() {
            return false;
        }
        query.is_empty()
            || [
                &self.status,
                &self.mac_address,
                &self.vendor,
                &self.open_ports,
            ]
            .iter()
            .any(|value| value.to_lowercase().contains(query))
            || self.ip_address.to_string().contains(query)
    }

    fn port_count(&self) -> usize {
        if self.open_ports.is_empty() {
            0
        } else {
            self.open_ports.split(',').count()
        }
    }
}

#[derive(Clone)]
struct Link {
    interface: NetworkInterface,
    address: Ipv4Network,
    mac: MacAddr,
}

fn links() -> Vec<Link> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|interface| {
            let mut result = Vec::new();
            if let Some(mac) = interface.mac.filter(|mac| !mac.is_zero()) {
                for address in &interface.ips {
                    if let ipnetwork::IpNetwork::V4(address) = address {
                        result.push(Link {
                            interface: interface.clone(),
                            address: *address,
                            mac,
                        });
                    }
                }
            }
            result
        })
        .collect()
}

fn parse_subnet(input: &str) -> Result<Ipv4Network, String> {
    let network: Ipv4Network = input
        .trim()
        .parse()
        .map_err(|_| "Enter an IPv4 CIDR, for example 192.168.1.0/24.".to_string())?;
    if network.prefix() < 20 {
        return Err(format!(
            "Use a /20 or smaller range (at most {MAX_ADDRESSES} addresses)."
        ));
    }
    Ipv4Network::new(network.network(), network.prefix()).map_err(|e| e.to_string())
}

fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut ports = std::collections::BTreeSet::new();
    let number = |text: &str| -> Result<u16, String> {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("Invalid port '{}': use numbers 1–65535.", text.trim()))
    };
    for value in input.split(',') {
        let (start, end) = if let Some((start, end)) = value.trim().split_once('-') {
            (number(start)?, number(end)?)
        } else {
            let port = number(value)?;
            (port, port)
        };
        if start > end {
            return Err(format!("Reversed port range: {value}"));
        }
        if usize::from(end - start) + 1 > MAX_PORTS {
            return Err(format!("Specify at most {MAX_PORTS} distinct ports."));
        }
        ports.extend(start..=end);
        if ports.len() > MAX_PORTS {
            return Err(format!("Specify at most {MAX_PORTS} distinct ports."));
        }
    }
    Ok(ports.into_iter().collect())
}

fn choose_link(
    network: Ipv4Network,
    available: Vec<Link>,
    selected: Option<&str>,
) -> Result<Link, String> {
    available.into_iter()
        .filter(|link| selected.is_none_or(|name| link.interface.name == name))
        .filter(|link| link.address.contains(network.network()) && link.address.contains(network.broadcast()))
        .max_by_key(|link| link.address.prefix())
        .ok_or_else(|| "No matching active interface covers this subnet. Choose an interface on the directly connected IPv4 LAN.".into())
}

fn default_subnet(link: &Link) -> String {
    let network = Ipv4Network::new(link.address.ip(), link.address.prefix().max(24)).unwrap();
    format!("{}/{}", network.network(), network.prefix())
}

fn targets(network: Ipv4Network, local: Ipv4Network) -> Vec<Ipv4Addr> {
    network
        .iter()
        .filter(|ip| {
            (network.prefix() >= 31 || (*ip != network.network() && *ip != network.broadcast()))
                && (local.prefix() >= 31 || (*ip != local.network() && *ip != local.broadcast()))
        })
        .collect()
}

type VendorTable<'a> = HashMap<(u8, u64), &'a str>;

fn parse_vendors(data: &str) -> VendorTable<'_> {
    data.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (prefix, name) = line.split_once('\t')?;
            if !matches!(prefix.len(), 6 | 7 | 9) || name.trim().is_empty() {
                return None;
            }
            Some((
                (
                    prefix.len() as u8 * 4,
                    u64::from_str_radix(prefix, 16).ok()?,
                ),
                name,
            ))
        })
        .collect()
}

fn vendor_table() -> &'static VendorTable<'static> {
    static TABLE: OnceLock<VendorTable<'static>> = OnceLock::new();
    TABLE.get_or_init(|| parse_vendors(include_str!("../data/vendors.tsv")))
}

fn lookup_vendor<'a>(mac: MacAddr, table: &VendorTable<'a>) -> &'a str {
    if mac.is_zero() || mac.0 & 1 != 0 {
        return "Not a device MAC";
    }
    if mac.0 & 2 != 0 {
        return "Private MAC (vendor unavailable)";
    }
    let value = u64::from_be_bytes([0, 0, mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]);
    // MA-S/IAB and MA-M assignments take precedence over their parent OUI.
    for bits in [36, 28, 24] {
        if let Some(name) = table.get(&(bits, value >> (48 - bits))) {
            return name;
        }
    }
    "Not in IEEE database"
}

fn vendor(mac: MacAddr) -> &'static str {
    lookup_vendor(mac, vendor_table())
}

#[derive(Clone, Debug)]
enum CaptureState {
    Unchecked,
    Checking,
    Ready,
    Denied(String),
    Unavailable(String),
}

fn capture_error(error: io::Error) -> CaptureState {
    let message = format!("Cannot open packet capture: {error}");
    if error.kind() == io::ErrorKind::PermissionDenied {
        CaptureState::Denied(message)
    } else {
        CaptureState::Unavailable(message)
    }
}

fn capture_config() -> datalink::Config {
    datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        write_timeout: Some(Duration::from_millis(100)),
        read_buffer_size: 65536,
        promiscuous: false,
        ..Default::default()
    }
}

fn open_capture(link: &Link) -> Result<Channel, CaptureState> {
    match datalink::channel(&link.interface, capture_config()).map_err(capture_error)? {
        channel @ Channel::Ethernet(_, _) => Ok(channel),
        _ => Err(CaptureState::Unavailable(
            "This interface does not support Ethernet ARP.".into(),
        )),
    }
}

fn check_capture(link: &Link) -> CaptureState {
    // Opening and immediately dropping the channel sends no packets.
    match open_capture(link) {
        Ok(_) => CaptureState::Ready,
        Err(state) => state,
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn linux_capture_command() -> Option<String> {
    let executable = std::env::current_exe().ok()?;
    Some(format!(
        "sudo setcap cap_net_raw=ep {}",
        shell_quote(executable.to_str()?)
    ))
}

fn arp_request(source: MacAddr, source_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
    let mut bytes = [0u8; 42];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut bytes).unwrap();
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source);
        ethernet.set_ethertype(EtherTypes::Arp);
    }
    let mut arp = MutableArpPacket::new(&mut bytes[14..]).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(source);
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target);
    bytes
}

fn arp_reply(
    bytes: &[u8],
    link: &Link,
    allowed: &HashSet<Ipv4Addr>,
) -> Option<(Ipv4Addr, MacAddr)> {
    let ethernet = EthernetPacket::new(bytes)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(ethernet.payload())?;
    let ip = arp.get_sender_proto_addr();
    let mac = arp.get_sender_hw_addr();
    if arp.get_operation() != ArpOperations::Reply
        || arp.get_hardware_type() != ArpHardwareTypes::Ethernet
        || arp.get_protocol_type() != EtherTypes::Ipv4
        || arp.get_hw_addr_len() != 6
        || arp.get_proto_addr_len() != 4
        || arp.get_target_proto_addr() != link.address.ip()
        || arp.get_target_hw_addr() != link.mac
        || ethernet.get_source() != mac
        || mac.is_zero()
        || mac.0 & 1 != 0
        || !allowed.contains(&ip)
    {
        return None;
    }
    Some((ip, mac))
}

// pnet reads are blocking: run the whole ARP phase on Tokio's blocking pool.
// A separate sender keeps capture running while requests are transmitted.
fn discover(
    link: Link,
    addresses: Vec<Ipv4Addr>,
    hosts: async_mpsc::UnboundedSender<(Ipv4Addr, MacAddr)>,
    events: mpsc::Sender<Event>,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let (mut tx, mut rx) = match open_capture(&link) {
        Ok(Channel::Ethernet(tx, rx)) => {
            let _ = events.send(Event::Capture(CaptureState::Ready));
            (tx, rx)
        }
        Ok(_) => unreachable!("open_capture only returns Ethernet channels"),
        Err(state) => {
            let message = match &state {
                CaptureState::Denied(message) => {
                    format!("{message}. Grant packet-capture access and restart the application.")
                }
                CaptureState::Unavailable(message) => message.clone(),
                _ => unreachable!(),
            };
            let _ = events.send(Event::Capture(state));
            return Err(message);
        }
    };
    let allowed: HashSet<_> = addresses.iter().copied().collect();
    let mut seen = HashSet::new();
    if allowed.contains(&link.address.ip()) {
        seen.insert(link.address.ip());
        let _ = hosts.send((link.address.ip(), link.mac));
    }
    let stop_sender = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let sender_link = &link;
        let sender_cancel = &cancel;
        let sender_stop = &stop_sender;
        let sender = scope.spawn(move || {
            let result = (|| {
                for _ in 0..2 {
                    for &ip in &addresses {
                        if sender_cancel.load(Ordering::Relaxed)
                            || sender_stop.load(Ordering::Relaxed)
                        {
                            return Ok(());
                        }
                        if ip == sender_link.address.ip() {
                            continue;
                        }
                        let packet = arp_request(sender_link.mac, sender_link.address.ip(), ip);
                        tx.send_to(&packet, None)
                            .ok_or_else(|| "ARP transmit buffer unavailable.".to_string())?
                            .map_err(|e| format!("ARP transmit failed: {e}"))?;
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                Ok(())
            })();
            let _ = done_tx.send(());
            result
        });
        let mut finish_at = None;
        let capture_result = loop {
            if cancel.load(Ordering::Relaxed) {
                break Ok(());
            }
            if finish_at.is_none() && !matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty))
            {
                finish_at = Some(Instant::now() + ARP_GRACE);
            }
            if finish_at.is_some_and(|end| Instant::now() >= end) {
                break Ok(());
            }
            match rx.next() {
                Ok(bytes) => {
                    if let Some((ip, mac)) = arp_reply(bytes, &link, &allowed) {
                        if seen.insert(ip) && hosts.send((ip, mac)).is_err() {
                            break Ok(());
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => break Err(format!("ARP capture failed: {e}")),
            }
        };
        stop_sender.store(true, Ordering::Relaxed);
        let sent = sender
            .join()
            .map_err(|_| "ARP sender thread panicked.".to_string())?;
        capture_result.and(sent)
    })
}

struct HostProgress {
    device: Device,
    open: Vec<u16>,
    remaining: usize,
}

async fn scan(
    network: Ipv4Network,
    link: Link,
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
    events: mpsc::Sender<Event>,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let source_ip = link.address.ip();
    let _ = events.send(Event::Status(format!(
        "Scanning {} via {} ({})…",
        network,
        link.interface.name,
        link.address.ip()
    )));
    let addresses = targets(network, link.address);
    let (host_tx, mut host_rx) = async_mpsc::unbounded_channel();
    let arp_cancel = cancel.clone();
    let arp_events = events.clone();
    let arp = tokio::task::spawn_blocking(move || {
        discover(link, addresses, host_tx, arp_events, arp_cancel)
    });
    let mut hosts = BTreeMap::<Ipv4Addr, HostProgress>::new();
    let mut pending = VecDeque::new();
    let mut probes = JoinSet::new();
    let mut discovery_done = false;
    let mut completed = 0;
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        while probes.len() < concurrency {
            let Some((ip, port)) = pending.pop_front() else {
                break;
            };
            probes.spawn(async move {
                let result = tokio::time::timeout(timeout, async {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::from((source_ip, 0)))?;
                    socket.connect(SocketAddr::from((ip, port))).await
                })
                .await;
                (ip, port, matches!(result, Ok(Ok(_))))
            });
        }
        if discovery_done && probes.is_empty() && pending.is_empty() {
            break;
        }
        tokio::select! {
            host = host_rx.recv(), if !discovery_done => {
                match host {
                    Some((ip, mac)) => {
                        let device = Device {
                            status: if ports.is_empty() { "Up" } else { "Up • scanning ports" }.into(),
                            ip_address: ip, mac_address: mac.to_string(), vendor: vendor(mac).into(),
                            open_ports: String::new(),
                        };
                        let _ = events.send(Event::Device(device.clone()));
                        hosts.insert(ip, HostProgress { device, open: Vec::new(), remaining: ports.len() });
                        pending.extend(ports.iter().map(|&port| (ip, port)));
                    }
                    None => discovery_done = true,
                }
            }
            result = probes.join_next(), if !probes.is_empty() => {
                match result {
                    Some(Ok((ip, port, open))) => {
                        let host = hosts.get_mut(&ip).expect("probe belongs to discovered host");
                        host.remaining -= 1;
                        completed += 1;
                        if open {
                            host.open.push(port);
                            host.open.sort_unstable();
                            host.device.open_ports = host.open.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
                        }
                        if host.remaining == 0 { host.device.status = "Up".into(); }
                        if open || host.remaining == 0 { let _ = events.send(Event::Device(host.device.clone())); }
                    }
                    Some(Err(e)) => {
                        cancel.store(true, Ordering::Relaxed);
                        probes.abort_all();
                        let _ = arp.await;
                        return Err(format!("TCP worker failed: {e}"));
                    }
                    None => {}
                }
            }
            _ = ticker.tick() => {
                let _ = events.send(Event::Progress(Progress {
                    completed, total: hosts.len() * ports.len(), discovery_done,
                }));
            }
        }
    }
    let _ = events.send(Event::Progress(Progress {
        completed,
        total: hosts.len() * ports.len(),
        discovery_done,
    }));
    probes.abort_all();
    let result = arp.await.map_err(|e| format!("ARP worker failed: {e}"))?;
    if cancel.load(Ordering::Relaxed) {
        for host in hosts.values_mut().filter(|h| h.remaining > 0) {
            host.device.status = "Up • ports incomplete".into();
            let _ = events.send(Event::Device(host.device.clone()));
        }
    }
    result
}

fn export_csv(path: &str, devices: &BTreeMap<Ipv4Addr, Device>) -> Result<(), String> {
    // create_new prevents silently overwriting an existing file.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.trim())
        .map_err(|e| {
            format!("Cannot create CSV: {e}. Choose a new filename if it already exists.")
        })?;
    let mut writer = csv::Writer::from_writer(file);
    for device in devices.values() {
        writer.serialize(device).map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

struct ScannerApp {
    runtime: Option<Runtime>,
    subnet: String,
    ports: String,
    export_path: String,
    devices: BTreeMap<Ipv4Addr, Device>,
    receiver: Option<mpsc::Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    active: bool,
    message: String,
    error: Option<String>,
    interfaces: Vec<Link>,
    selected_interface: Option<String>,
    timeout_ms: u64,
    concurrency: usize,
    search: String,
    open_only: bool,
    sort_by: SortBy,
    descending: bool,
    progress: Progress,
    started: Option<Instant>,
    elapsed: Duration,
    notice: Option<String>,
    export_receiver: Option<mpsc::Receiver<Result<String, String>>>,
    capture_state: CaptureState,
    capture_key: Option<(String, Ipv4Addr)>,
    capture_receiver: Option<mpsc::Receiver<CaptureState>>,
}

impl ScannerApp {
    fn new(runtime: Runtime) -> Self {
        let interfaces = links();
        let subnet = interfaces
            .first()
            .map(default_subnet)
            .unwrap_or_else(|| "192.168.1.0/24".into());
        Self {
            runtime: Some(runtime),
            subnet,
            ports: "22, 80, 443".into(),
            export_path: "scan-results.csv".into(),
            devices: BTreeMap::new(),
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
            active: false,
            message: "Ready".into(),
            error: None,
            interfaces,
            selected_interface: None,
            timeout_ms: 700,
            concurrency: TCP_CONCURRENCY,
            search: String::new(),
            open_only: false,
            sort_by: SortBy::default(),
            descending: false,
            progress: Progress::default(),
            started: None,
            elapsed: Duration::ZERO,
            notice: None,
            export_receiver: None,
            capture_state: CaptureState::Unchecked,
            capture_key: None,
            capture_receiver: None,
        }
    }

    fn refresh_capture(&mut self) {
        if self.active {
            return;
        }
        let link = match parse_subnet(&self.subnet).and_then(|network| {
            choose_link(
                network,
                self.interfaces.clone(),
                self.selected_interface.as_deref(),
            )
        }) {
            Ok(link) => link,
            Err(message) => {
                self.capture_key = None;
                self.capture_receiver = None;
                self.capture_state = CaptureState::Unavailable(message);
                return;
            }
        };
        let key = (link.interface.name.clone(), link.address.ip());
        if self.capture_key.as_ref() == Some(&key) {
            return;
        }
        self.capture_key = Some(key);
        self.capture_state = CaptureState::Checking;
        let (tx, rx) = mpsc::channel();
        self.capture_receiver = Some(rx);
        self.runtime.as_ref().unwrap().spawn_blocking(move || {
            let _ = tx.send(check_capture(&link));
        });
    }

    fn start(&mut self) -> Result<(), String> {
        let subnet = parse_subnet(&self.subnet)?;
        let ports = parse_ports(&self.ports)?;
        let link = choose_link(subnet, links(), self.selected_interface.as_deref())?;
        self.capture_key = Some((link.interface.name.clone(), link.address.ip()));
        // The actual scan owns capture status; discard any earlier preflight result.
        self.capture_receiver = None;
        self.capture_state = CaptureState::Checking;
        let timeout = Duration::from_millis(self.timeout_ms);
        let concurrency = self.concurrency;
        let (tx, rx) = mpsc::channel();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let runtime = self
            .runtime
            .as_ref()
            .expect("runtime exists until app drop");
        runtime.spawn(async move {
            // Supervise the task so unexpected panics also release the UI state.
            let scan_tx = tx.clone();
            let result = tokio::spawn(scan(
                subnet,
                link,
                ports,
                timeout,
                concurrency,
                scan_tx,
                cancel,
            ))
            .await
            .unwrap_or_else(|e| Err(format!("Scan task failed: {e}")));
            let _ = tx.send(Event::Finished(result));
        });
        self.receiver = Some(rx);
        self.devices.clear();
        self.progress = Progress::default();
        self.started = Some(Instant::now());
        self.elapsed = Duration::ZERO;
        self.notice = None;
        self.active = true;
        self.error = None;
        self.message = "Opening ARP interface…".into();
        Ok(())
    }

    fn poll(&mut self) {
        if let Some(receiver) = &self.capture_receiver {
            match receiver.try_recv() {
                Ok(state) => {
                    self.capture_state = state;
                    self.capture_receiver = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.capture_state = CaptureState::Unavailable(
                        "Capture check failed unexpectedly. Retry the check.".into(),
                    );
                    self.capture_receiver = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(receiver) = &self.export_receiver {
            match receiver.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(notice) => self.notice = Some(notice),
                        Err(error) => self.error = Some(error),
                    }
                    self.export_receiver = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.error = Some("CSV export worker disconnected.".into());
                    self.export_receiver = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.active {
            if let Some(started) = self.started {
                self.elapsed = started.elapsed();
            }
        }
        let Some(receiver) = &self.receiver else {
            return;
        };
        // Cap processing per frame to keep a busy network from starving painting.
        for _ in 0..1024 {
            match receiver.try_recv() {
                Ok(Event::Device(device)) => {
                    self.devices.insert(device.ip_address, device);
                }
                Ok(Event::Status(message)) => self.message = message,
                Ok(Event::Progress(progress)) => self.progress = progress,
                Ok(Event::Capture(state)) => self.capture_state = state,
                Ok(Event::Finished(result)) => {
                    self.active = false;
                    self.message = if self.cancel.load(Ordering::Relaxed) {
                        "Scan cancelled"
                    } else {
                        "Scan complete"
                    }
                    .into();
                    if let Err(error) = result {
                        self.message = "Scan failed".into();
                        self.error = Some(error);
                    }
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.active {
                        self.active = false;
                        self.error = Some("Scan worker disconnected unexpectedly.".into());
                    }
                    break;
                }
            }
        }
        if !self.active {
            self.receiver = None;
        }
    }
}

const ACCENT: Color32 = Color32::from_rgb(56, 189, 174);
const MUTED: Color32 = Color32::from_rgb(148, 163, 184);
const COLUMN_WIDTHS: [f32; 5] = [175.0, 130.0, 165.0, 225.0, 230.0];

fn configure_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(17, 24, 39);
    visuals.window_fill = Color32::from_rgb(23, 32, 48);
    visuals.selection.bg_fill = Color32::from_rgb(21, 94, 89);
    visuals.widgets.active.bg_fill = Color32::from_rgb(21, 128, 118);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(42, 58, 78);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    ctx.set_style(style);
}

fn statistic(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::none()
        .fill(Color32::from_rgb(25, 35, 52))
        .rounding(8.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_min_width(130.0);
            ui.label(RichText::new(label).size(11.0).color(MUTED));
            ui.label(RichText::new(value).size(25.0).strong().color(ACCENT));
        });
}

impl ScannerApp {
    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(RichText::new("SCAN SETTINGS").size(12.0).color(MUTED));
        ui.add_space(8.0);
        ui.add_enabled_ui(!self.active, |ui| {
            ui.label("Network interface");
            let previous = self.selected_interface.clone();
            egui::ComboBox::from_id_source("interface")
                .width(230.0)
                .selected_text(self.selected_interface.as_deref().unwrap_or("Automatic"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.selected_interface, None, "Automatic");
                    let mut seen = HashSet::new();
                    for link in &self.interfaces {
                        if seen.insert(&link.interface.name) {
                            ui.selectable_value(
                                &mut self.selected_interface,
                                Some(link.interface.name.clone()),
                                format!("{} · {}", link.interface.name, link.address.ip()),
                            );
                        }
                    }
                });
            if previous != self.selected_interface {
                if let Some(link) = self.interfaces.iter().find(|link| {
                    self.selected_interface
                        .as_ref()
                        .is_some_and(|name| name == &link.interface.name)
                }) {
                    self.subnet = default_subnet(link);
                }
            }
            if ui.small_button("Refresh interfaces").clicked() {
                self.interfaces = links();
                self.capture_key = None;
            }
            ui.add_space(8.0);
            ui.label("Target subnet");
            ui.add(
                egui::TextEdit::singleline(&mut self.subnet)
                    .desired_width(f32::INFINITY)
                    .hint_text("192.168.1.0/24"),
            );
            ui.label("TCP ports");
            ui.add(
                egui::TextEdit::singleline(&mut self.ports)
                    .desired_width(f32::INFINITY)
                    .hint_text("22, 80, 443, 8000-8010"),
            );
            ui.horizontal(|ui| {
                if ui.small_button("Common").clicked() {
                    self.ports = "22, 53, 80, 139, 443, 445, 3389, 8080".into();
                }
                if ui.small_button("Web").clicked() {
                    self.ports = "80, 443, 8000, 8080, 8443".into();
                }
                if ui.small_button("ARP only").clicked() {
                    self.ports.clear();
                }
            });
            ui.add_space(8.0);
            egui::CollapsingHeader::new("Performance settings").show(ui, |ui| {
                ui.label("TCP timeout (ms)");
                ui.add(egui::Slider::new(&mut self.timeout_ms, 100..=3000));
                ui.label("Concurrent connections");
                ui.add(egui::Slider::new(&mut self.concurrency, 16..=512));
                ui.small("Longer timeouts help on slower networks.");
            });
        });
        ui.add_space(14.0);
        if ui
            .add_enabled(
                !self.active,
                egui::Button::new(
                    RichText::new("Start scan")
                        .strong()
                        .color(Color32::from_rgb(10, 30, 35)),
                )
                .fill(ACCENT)
                .min_size(egui::vec2(ui.available_width(), 40.0)),
            )
            .clicked()
        {
            if let Err(error) = self.start() {
                self.error = Some(error);
            }
        }
        if self.active
            && ui
                .add_enabled(
                    !self.cancel.load(Ordering::Relaxed),
                    egui::Button::new("Stop scan").min_size(egui::vec2(ui.available_width(), 32.0)),
                )
                .clicked()
        {
            self.cancel.store(true, Ordering::Relaxed);
            self.message = "Cancelling…".into();
        }
        ui.add_space(16.0);
        ui.separator();
        ui.label(RichText::new("EXPORT RESULTS").size(12.0).color(MUTED));
        ui.add(egui::TextEdit::singleline(&mut self.export_path).desired_width(f32::INFINITY));
        if ui
            .add_enabled(
                !self.devices.is_empty() && self.export_receiver.is_none(),
                egui::Button::new(if self.export_receiver.is_some() {
                    "Exporting…"
                } else {
                    "Export all to CSV"
                }),
            )
            .clicked()
        {
            let devices = self.devices.clone();
            let path = self.export_path.clone();
            let (tx, rx) = mpsc::channel();
            self.export_receiver = Some(rx);
            self.notice = None;
            self.runtime.as_ref().unwrap().spawn_blocking(move || {
                let result = export_csv(&path, &devices)
                    .map(|()| format!("Exported {} devices to {}", devices.len(), path));
                let _ = tx.send(result);
            });
        }
        ui.small("Exports all discovered devices, including hidden results. Existing files are preserved.");
        ui.add_space(16.0);
        match &self.capture_state {
            CaptureState::Ready => {
                ui.colored_label(ACCENT, "Packet capture ready");
            }
            CaptureState::Unchecked | CaptureState::Checking => {
                ui.label("Checking packet capture…");
            }
            CaptureState::Denied(message) => {
                ui.colored_label(Color32::LIGHT_RED, "Packet capture access denied");
                ui.small(message);
                if cfg!(target_os = "linux") {
                    ui.small("Grant CAP_NET_RAW to this executable, then close and reopen the app. The GUI can run as your normal user.");
                    if let Some(command) = linux_capture_command() {
                        if ui.button("Copy permission fix").clicked() {
                            ui.output_mut(|output| output.copied_text = command);
                            self.notice = Some("Command copied. Run it in a terminal, then restart this application.".into());
                        }
                    }
                } else if cfg!(target_os = "windows") {
                    ui.small("Install Npcap with WinPcap compatibility and allow capture access, or run as administrator.");
                } else {
                    ui.small("Allow access to the BPF capture devices or run with suitable capture privileges.");
                }
            }
            CaptureState::Unavailable(message) => {
                ui.colored_label(Color32::LIGHT_RED, "Packet capture unavailable");
                ui.small(message);
                if cfg!(target_os = "windows") {
                    ui.small("Check the Npcap installation and adapter status.");
                }
            }
        }
        if ui
            .add_enabled(
                !self.active && self.capture_receiver.is_none(),
                egui::Button::new("Recheck capture access"),
            )
            .clicked()
        {
            self.interfaces = links();
            self.capture_key = None;
        }
        ui.small("Vendor lookup: offline IEEE registry. Private MAC addresses do not reveal their manufacturer.");
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            statistic(ui, "DEVICES ONLINE", self.devices.len().to_string());
            statistic(
                ui,
                "OPEN PORTS",
                self.devices
                    .values()
                    .map(Device::port_count)
                    .sum::<usize>()
                    .to_string(),
            );
            statistic(
                ui,
                "ELAPSED",
                format!(
                    "{}:{:02}",
                    self.elapsed.as_secs() / 60,
                    self.elapsed.as_secs() % 60
                ),
            );
        });
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if self.active {
                ui.spinner();
            }
            ui.label(&self.message);
        });
        if self.active || self.started.is_some() {
            let p = self.progress;
            let ratio = if p.total > 0 {
                p.completed as f32 / p.total as f32
            } else if p.discovery_done {
                1.0
            } else {
                0.0
            };
            ui.add(egui::ProgressBar::new(ratio).fill(ACCENT).text(format!(
                "TCP probes: {} / {}{}",
                p.completed,
                p.total,
                if p.discovery_done || !self.active {
                    ""
                } else {
                    " · discovering hosts"
                }
            )));
        }
        if let Some(error) = self.error.clone() {
            egui::Frame::none()
                .fill(Color32::from_rgb(65, 30, 39))
                .inner_margin(10.0)
                .rounding(6.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(Color32::LIGHT_RED, error);
                        if ui.small_button("Dismiss").clicked() {
                            self.error = None;
                        }
                    });
                });
        }
        if let Some(notice) = &self.notice {
            ui.colored_label(ACCENT, notice);
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .desired_width(245.0)
                    .hint_text("Search IP, MAC, vendor or port…"),
            );
            ui.checkbox(&mut self.open_only, "Has open ports");
            egui::ComboBox::from_id_source("sort")
                .selected_text(match self.sort_by {
                    SortBy::Ip => "IP address",
                    SortBy::Vendor => "Vendor",
                    SortBy::OpenPorts => "Open port count",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.sort_by, SortBy::Ip, "IP address");
                    ui.selectable_value(&mut self.sort_by, SortBy::Vendor, "Vendor");
                    ui.selectable_value(&mut self.sort_by, SortBy::OpenPorts, "Open port count");
                });
            ui.checkbox(&mut self.descending, "Descending");
        });
        let query = self.search.trim().to_lowercase();
        let mut rows: Vec<_> = self
            .devices
            .values()
            .filter(|device| device.matches(&query, self.open_only))
            .collect();
        rows.sort_by(|a, b| {
            let order = match self.sort_by {
                SortBy::Ip => a.ip_address.cmp(&b.ip_address),
                SortBy::Vendor => a
                    .vendor
                    .cmp(&b.vendor)
                    .then(a.ip_address.cmp(&b.ip_address)),
                SortBy::OpenPorts => a
                    .port_count()
                    .cmp(&b.port_count())
                    .then(a.ip_address.cmp(&b.ip_address)),
            };
            if self.descending {
                order.reverse()
            } else {
                order
            }
        });
        ui.label(
            RichText::new(format!(
                "{} of {} devices · Right-click a row to copy",
                rows.len(),
                self.devices.len()
            ))
            .color(MUTED)
            .size(12.0),
        );
        ui.separator();
        if rows.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.heading(if self.devices.is_empty() {
                    if self.active {
                        "Listening for devices…"
                    } else {
                        "No devices discovered"
                    }
                } else {
                    "No matching devices"
                });
                ui.label(if self.devices.is_empty() {
                    "Choose your LAN subnet and start a scan."
                } else {
                    "Try another search or disable the open-port filter."
                });
            });
            return;
        }
        egui::ScrollArea::horizontal()
            .id_source("table_horizontal")
            .show(ui, |ui| {
                ui.set_min_width(COLUMN_WIDTHS.iter().sum::<f32>() + 40.0);
                ui.horizontal(|ui| {
                    for (header, width) in [
                        "STATUS",
                        "IP ADDRESS",
                        "MAC ADDRESS",
                        "VENDOR",
                        "OPEN PORTS",
                    ]
                    .into_iter()
                    .zip(COLUMN_WIDTHS)
                    {
                        ui.add_sized(
                            [width, 24.0],
                            egui::Label::new(RichText::new(header).size(11.0).color(MUTED)),
                        );
                    }
                });
                egui::ScrollArea::vertical()
                    .id_source("table_vertical")
                    .auto_shrink([false, false])
                    .show_rows(ui, 28.0, rows.len(), |ui, range| {
                        for index in range {
                            let device = rows[index];
                            let row = ui.horizontal(|ui| {
                                let rect = egui::Rect::from_min_size(
                                    ui.cursor().min,
                                    egui::vec2(ui.available_width(), 28.0),
                                );
                                if index % 2 == 0 {
                                    ui.painter().rect_filled(
                                        rect,
                                        3.0,
                                        Color32::from_rgb(24, 34, 50),
                                    );
                                }
                                let ip = device.ip_address.to_string();
                                let cells: [&str; 5] = [
                                    &device.status,
                                    &ip,
                                    &device.mac_address,
                                    &device.vendor,
                                    if device.open_ports.is_empty() {
                                        "—"
                                    } else {
                                        &device.open_ports
                                    },
                                ];
                                for (column, (text, width)) in
                                    cells.into_iter().zip(COLUMN_WIDTHS).enumerate()
                                {
                                    let color = if column == 0 {
                                        ACCENT
                                    } else {
                                        ui.visuals().text_color()
                                    };
                                    ui.add_sized(
                                        [width, 28.0],
                                        egui::Label::new(RichText::new(text).color(color))
                                            .truncate(),
                                    )
                                    .on_hover_text(text);
                                }
                            });
                            ui.interact(
                                row.response.rect,
                                ui.id().with(device.ip_address),
                                egui::Sense::click(),
                            )
                            .context_menu(|ui| {
                                for (label, value) in [
                                    ("Copy IP address", device.ip_address.to_string()),
                                    ("Copy MAC address", device.mac_address.clone()),
                                    ("Copy open ports", device.open_ports.clone()),
                                ] {
                                    if ui.button(label).clicked() {
                                        ui.output_mut(|output| output.copied_text = value);
                                        ui.close_menu();
                                    }
                                }
                            });
                        }
                    });
            });
    }
}

impl eframe::App for ScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.refresh_capture();
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("NETWORK / SCANNER").size(21.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(if self.active {
                            "● SCANNING"
                        } else {
                            "● READY"
                        })
                        .color(ACCENT),
                    );
                });
            });
            ui.label(RichText::new("Local network discovery & service visibility").color(MUTED));
            ui.add_space(8.0);
        });
        egui::SidePanel::left("settings")
            .resizable(false)
            .exact_width(280.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.controls(ui));
            });
        egui::CentralPanel::default().show(ctx, |ui| self.results(ui));
        if self.active || self.export_receiver.is_some() || self.capture_receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}

impl Drop for ScannerApp {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        // A driver that ignores read_timeout must not freeze window shutdown.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn main() -> eframe::Result<()> {
    if std::env::args().any(|arg| arg == "--check-capture") {
        let Some(link) = links().into_iter().next() else {
            eprintln!("No active IPv4 Ethernet/Wi-Fi interface found.");
            std::process::exit(1);
        };
        match check_capture(&link) {
            CaptureState::Ready => {
                println!(
                    "Packet capture ready on {} ({}).",
                    link.interface.name,
                    link.address.ip()
                );
                return Ok(());
            }
            state => {
                eprintln!("{state:?}");
                std::process::exit(if matches!(state, CaptureState::Denied(_)) {
                    2
                } else {
                    1
                });
            }
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize Tokio runtime");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 800.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Network Scanner",
        options,
        Box::new(move |cc| {
            configure_theme(&cc.egui_ctx);
            Ok(Box::new(ScannerApp::new(runtime)))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_lookup_uses_longest_assignment_and_handles_private_macs() {
        let table = parse_vendors(
            "001122\tLarge vendor\n0011223\tMedium vendor\n001122334\tSmall vendor\n",
        );
        assert_eq!(
            lookup_vendor(MacAddr(0, 0x11, 0x22, 0x33, 0x44, 0x55), &table),
            "Small vendor"
        );
        assert_eq!(
            lookup_vendor(MacAddr(0, 0x11, 0x22, 0x3F, 0, 0), &table),
            "Medium vendor"
        );
        assert_eq!(
            lookup_vendor(MacAddr(0, 0x11, 0x22, 0x40, 0, 0), &table),
            "Large vendor"
        );
        assert_eq!(
            lookup_vendor(MacAddr(2, 0x11, 0x22, 0x33, 0, 0), &table),
            "Private MAC (vendor unavailable)"
        );
        assert_eq!(
            lookup_vendor(MacAddr(4, 0x11, 0x22, 0x33, 0, 0), &table),
            "Not in IEEE database"
        );
        assert_eq!(lookup_vendor(MacAddr::zero(), &table), "Not a device MAC");
        assert_eq!(
            lookup_vendor(MacAddr::broadcast(), &table),
            "Not a device MAC"
        );
    }

    #[test]
    fn bundled_vendor_registry_is_complete_and_resolves_real_assignments() {
        let data = include_str!("../data/vendors.tsv");
        let table = vendor_table();
        assert!(table.len() > 50_000);
        assert_eq!(
            table.len(),
            data.lines().filter(|line| !line.starts_with('#')).count()
        );
        assert_eq!(vendor(MacAddr(0, 3, 0x93, 1, 2, 3)), "Apple, Inc.");
        assert!(vendor(MacAddr(0, 0, 0xF0, 1, 2, 3)).contains("Samsung"));
    }

    #[test]
    fn capture_errors_distinguish_missing_permissions_from_adapter_errors() {
        assert!(matches!(
            capture_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            CaptureState::Denied(_)
        ));
        assert!(matches!(
            capture_error(io::Error::from(io::ErrorKind::NotFound)),
            CaptureState::Unavailable(_)
        ));
        assert!(matches!(
            capture_error(io::Error::from(io::ErrorKind::Other)),
            CaptureState::Unavailable(_)
        ));
    }

    #[test]
    fn permission_command_quotes_shell_metacharacters_as_literal_path() {
        assert_eq!(
            shell_quote("/tmp/a b/$(id)`id`'scanner"),
            "'/tmp/a b/$(id)`id`'\"'\"'scanner'"
        );
    }

    fn test_link() -> Link {
        Link {
            interface: NetworkInterface {
                name: "test".into(),
                description: String::new(),
                index: 1,
                mac: Some(MacAddr(0, 1, 2, 3, 4, 5)),
                ips: Vec::new(),
                flags: 0,
            },
            address: "192.168.1.10/24".parse().unwrap(),
            mac: MacAddr(0, 1, 2, 3, 4, 5),
        }
    }

    #[test]
    fn inputs_are_validated_and_normalized() {
        assert_eq!(
            parse_subnet("192.168.1.42/24").unwrap().to_string(),
            "192.168.1.0/24"
        );
        for invalid in ["::1/128", "invalid", "10.0.0.0/8"] {
            assert!(parse_subnet(invalid).is_err());
        }
        assert_eq!(parse_ports("443, 22,80,22").unwrap(), vec![22, 80, 443]);
        assert!(parse_ports("").unwrap().is_empty());
        assert_eq!(parse_ports("22, 80-82, 81").unwrap(), vec![22, 80, 81, 82]);
        assert_eq!(parse_ports("1-256, 128-256").unwrap().len(), MAX_PORTS);
        assert!(parse_ports("1-256, 443").is_err());
        assert_eq!(parse_ports("65535-65535").unwrap(), vec![65535]);
        for invalid in ["0", "65536", "80,", "80-22", "1-65535", "22-23-24"] {
            assert!(parse_ports(invalid).is_err());
        }
    }

    #[test]
    fn interface_selection_respects_explicit_choice_and_subnet() {
        let broad = test_link();
        let mut narrow = broad.clone();
        narrow.interface.name = "secondary".into();
        narrow.address = "192.168.1.130/25".parse().unwrap();
        let network = "192.168.1.160/28".parse().unwrap();
        let available = vec![broad.clone(), narrow];
        assert_eq!(
            choose_link(network, available.clone(), None)
                .unwrap()
                .interface
                .name,
            "secondary"
        );
        assert_eq!(
            choose_link(network, available.clone(), Some("test"))
                .unwrap()
                .address,
            broad.address
        );
        assert!(choose_link(network, available.clone(), Some("missing")).is_err());
        assert!(choose_link(
            "192.168.1.0/24".parse().unwrap(),
            available,
            Some("secondary")
        )
        .is_err());
    }

    #[test]
    fn result_filters_match_devices_and_open_ports() {
        let mut device = Device {
            status: "Up".into(),
            ip_address: Ipv4Addr::new(192, 168, 1, 42),
            mac_address: "00:03:93:01:02:03".into(),
            vendor: "Apple".into(),
            open_ports: "22, 443".into(),
        };
        for query in ["apple", "192.168.1.42", "00:03:93", "443"] {
            assert!(device.matches(query, true));
        }
        assert!(!device.matches("cisco", false));
        assert_eq!(device.port_count(), 2);
        device.open_ports.clear();
        assert!(!device.matches("", true));
        assert!(device.matches("", false));
        assert_eq!(device.port_count(), 0);
    }

    #[test]
    fn large_result_table_only_paints_visible_rows() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut app = ScannerApp::new(runtime);
        for index in 0..4096u32 {
            let ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 0, 0, 0)) + index);
            app.devices.insert(
                ip,
                Device {
                    status: "Up".into(),
                    ip_address: ip,
                    mac_address: "00:03:93:01:02:03".into(),
                    vendor: "Apple".into(),
                    open_ports: "22, 443".into(),
                },
            );
        }
        let ctx = egui::Context::default();
        configure_theme(&ctx);
        for width in [900.0, 1320.0] {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 800.0),
                )),
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| {
                egui::SidePanel::left("settings")
                    .exact_width(280.0)
                    .show(ctx, |ui| app.controls(ui));
                egui::CentralPanel::default().show(ctx, |ui| app.results(ui));
            });
            assert!(!output.shapes.is_empty());
            assert!(
                output.shapes.len() < 1000,
                "offscreen rows should not be painted"
            );
        }
    }

    #[test]
    fn host_ranges_handle_point_to_point_and_single_host() {
        let local = test_link().address;
        assert_eq!(targets("192.168.1.0/24".parse().unwrap(), local).len(), 254);
        assert_eq!(targets("192.168.1.20/31".parse().unwrap(), local).len(), 2);
        assert_eq!(targets("192.168.1.20/32".parse().unwrap(), local).len(), 1);
        assert!(targets("192.168.1.255/32".parse().unwrap(), local).is_empty());
    }

    #[test]
    fn request_has_valid_ethernet_and_arp_fields() {
        let link = test_link();
        let target = Ipv4Addr::new(192, 168, 1, 20);
        let bytes = arp_request(link.mac, link.address.ip(), target);
        let ethernet = EthernetPacket::new(&bytes).unwrap();
        assert_eq!(ethernet.get_destination(), MacAddr::broadcast());
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);
        let arp = ArpPacket::new(ethernet.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_proto_addr(), link.address.ip());
        assert_eq!(arp.get_sender_hw_addr(), link.mac);
        assert_eq!(arp.get_target_proto_addr(), target);
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
    }

    #[test]
    fn reply_filter_rejects_unrelated_and_truncated_packets() {
        let link = test_link();
        let remote_ip = Ipv4Addr::new(192, 168, 1, 20);
        let remote_mac = MacAddr(0, 3, 0x93, 1, 2, 3);
        let allowed = HashSet::from([remote_ip]);
        let mut bytes = arp_request(remote_mac, remote_ip, link.address.ip());
        {
            let mut arp = MutableArpPacket::new(&mut bytes[14..]).unwrap();
            arp.set_operation(ArpOperations::Reply);
            arp.set_target_hw_addr(link.mac);
        }
        assert_eq!(
            arp_reply(&bytes, &link, &allowed),
            Some((remote_ip, remote_mac))
        );
        assert_eq!(arp_reply(&bytes[..20], &link, &allowed), None);
        assert_eq!(arp_reply(&bytes, &link, &HashSet::new()), None);
        MutableArpPacket::new(&mut bytes[14..])
            .unwrap()
            .set_target_proto_addr(Ipv4Addr::LOCALHOST);
        assert_eq!(arp_reply(&bytes, &link, &allowed), None);
    }

    #[test]
    fn csv_round_trips_port_lists_and_refuses_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "network-scanner-test-{}-{}.csv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let device = Device {
            status: "Up".into(),
            ip_address: Ipv4Addr::LOCALHOST,
            mac_address: "00:03:93:01:02:03".into(),
            vendor: "Apple".into(),
            open_ports: "22, 443".into(),
        };
        let devices = BTreeMap::from([(device.ip_address, device)]);
        export_csv(path.to_str().unwrap(), &devices).unwrap();
        assert!(export_csv(path.to_str().unwrap(), &devices).is_err());
        let mut reader = csv::Reader::from_path(&path).unwrap();
        assert_eq!(reader.headers().unwrap().get(0), Some("status"));
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(record.get(4), Some("22, 443"));
        drop(reader);
        std::fs::remove_file(path).unwrap();
    }
}
