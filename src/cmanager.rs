use std::net::{SocketAddrV4, Ipv4Addr};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::fmt::Write;
use std::convert;
use std::ops::{Index, IndexMut};
use std::mem;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};
use e2d2::utils;

use eui48::MacAddress;
use separator::Separatable;
use timer_wheel::{TimerWheel, MILLIS_TO_CYCLES};
use {EngineConfig, MessageFrom, PipelineId, Timeouts};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    LastAck,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpControls {
    SentSyn = 0,
    SentSynAck = 1,
    SentSynAck2 = 2,
    SentFin = 3,
    SentFinAck = 4,
    SentFinAck2 = 5,
    SentAck = 6,
    RecvSyn = 7,
    RecvSynAck = 8,
    RecvSynAck2 = 9,
    RecvFin = 10,
    RecvFinAck = 11,
    RecvFinAck2 = 12,
    RecvAck = 13,
    RecvRst = 14,
    Unexpected = 15,
    Count = 16,
}

impl convert::From<usize> for TcpControls {
    fn from(i: usize) -> TcpControls {
        match i {
            0 => TcpControls::SentSyn,
            1 => TcpControls::SentSynAck,
            2 => TcpControls::SentSynAck2,
            3 => TcpControls::SentFin,
            4 => TcpControls::SentFinAck,
            5 => TcpControls::SentFinAck2,
            6 => TcpControls::SentAck,
            7 => TcpControls::RecvSyn,
            8 => TcpControls::RecvSynAck,
            9 => TcpControls::RecvSynAck2,
            10 => TcpControls::RecvFin,
            11 => TcpControls::RecvFinAck,
            12 => TcpControls::RecvFinAck2,
            13 => TcpControls::RecvAck,
            14 => TcpControls::RecvRst,
            15 => TcpControls::Unexpected,
            16 => TcpControls::Count,
            _ => TcpControls::SentSyn,
        }
    }
}

impl fmt::Display for TcpControls {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        write!(&mut output, "{:?}", self)?;
        write!(f, "{:12}", output)
    }
}

#[derive(Debug, Clone)]
pub struct TcpCounter {
    counter: [usize; TcpControls::Count as usize],
}

impl TcpCounter {
    pub fn new() -> TcpCounter {
        TcpCounter {
            counter: [0; TcpControls::Count as usize],
        }
    }
}

impl Index<TcpControls> for TcpCounter {
    type Output = usize;

    fn index(&self, tcp_control: TcpControls) -> &usize {
        &self.counter[tcp_control as usize]
    }
}

impl IndexMut<TcpControls> for TcpCounter {
    fn index_mut(&mut self, tcp_control: TcpControls) -> &mut usize {
        &mut self.counter[tcp_control as usize]
    }
}

impl fmt::Display for TcpCounter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Tcp Counters: ",)?;
        for i in 0..TcpControls::Count as usize {
            writeln!(f, "{:12} = {:6}", TcpControls::from(i), self.counter[i])?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
    pub server_id: String,
    pub index: usize,
}

pub trait UserData: Send + Sync + 'static {
    fn ref_userdata(&self) -> &Any;
    fn mut_userdata(&mut self) -> &mut Any;
    fn init(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    FinClient = 2, // i.e. engine
    FinServer = 3, // i.e. DUT
    RstServer = 4,
    MaxCauses = 5,
}

#[derive(Clone)]
pub struct ConRecord {
    pub port: u16,
    pub sock: Option<SocketAddrV4>,
    c_count: usize,
    c_state: [TcpState; 8],
    s_count: usize,
    s_state: [TcpState; 8],
    stamps: [u64; 8],
    pub server_index: usize,
    release_cause: ReleaseCause,
}

impl ConRecord {
    #[inline]
    fn init(&mut self, port: u16, sock: Option<SocketAddrV4>) {
        self.port = port;
        self.c_count = 1;
        self.s_count = 1;
        self.c_state[0] = TcpState::Closed;
        self.s_state[0] = TcpState::Closed;
        self.server_index = 0;
        self.sock = sock;
    }
    #[inline]
    pub fn c_released(&mut self, cause: ReleaseCause) {
        self.release_cause = cause;
    }
    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    fn new() -> ConRecord {
        ConRecord {
            server_index: 0,
            release_cause: ReleaseCause::Unknown,
            // we are using an Array, not Vec for the state history, the latter eats too much performance
            c_count: 0,
            c_state: [TcpState::Closed; 8],
            s_count: 0,
            s_state: [TcpState::Closed; 8],
            stamps: [0; 8],
            port: 0u16,
            sock: None,
        }
    }

    #[inline]
    pub fn push_c_state(&mut self, state: TcpState) {
        self.c_state[self.c_count] = state;
        self.stamps[self.c_count] = utils::rdtsc_unsafe();
        self.c_count += 1;
    }

    #[inline]
    pub fn push_s_state(&mut self, state: TcpState) {
        self.s_state[self.s_count] = state;
        //self.s_stamps[self.c_count] = utils::rdtsc_unsafe();
        self.s_count += 1;
    }
    #[inline]
    pub fn last_c_state(&self) -> &TcpState {
        &self.c_state[self.c_count - 1]
    }

    #[inline]
    pub fn c_states(&self) -> &[TcpState] {
        &self.c_state[0..self.c_count]
    }

    #[inline]
    pub fn last_s_state(&self) -> &TcpState {
        &self.s_state[self.s_count - 1]
    }

    #[inline]
    pub fn s_states(&self) -> &[TcpState] {
        &self.s_state[0..self.s_count]
    }

    pub fn elapsed_since_synsent(&self) -> Vec<u64> {
        let synsent = self.stamps[1];
        if self.c_count >= 3 {
            self.stamps[2..self.c_count].iter().map(|stamp| stamp - synsent).collect()
        } else {
            vec![]
        }
    }
}

impl fmt::Display for ConRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(port={}, {:?}/{:?}, {:?}, {}, {:?})",
            self.port,
            self.c_states(),
            self.s_states(),
            self.release_cause,
            self.stamps[1].separated_string(),
            self.elapsed_since_synsent()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone)]
pub struct Connection {
    pub con_rec: ConRecord,
    pub c_seqn: u32,        // client side sequence no towards DUT
    pub s_seqn: u32,        // server side sequence no towards DUT
    pub dut_mac: MacHeader, // server side mac, i.e. mac of DUT
}

impl Connection {
    #[inline]
    fn initialize(&mut self, sock: Option<SocketAddrV4>, port: u16) {
        self.c_seqn = 0;
        self.s_seqn = 0;
        self.dut_mac = MacHeader::default();
        self.con_rec.init(port, sock);
    }

    fn new() -> Connection {
        Connection {
            c_seqn: 0,
            s_seqn: 0,
            dut_mac: MacHeader::default(),
            con_rec: ConRecord::new(),
        }
    }

    #[inline]
    pub fn c_con_established(&mut self) {
        self.con_rec.push_c_state(TcpState::Established);
    }

    #[inline]
    pub fn s_con_established(&mut self) {
        self.con_rec.push_s_state(TcpState::Established);
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.con_rec.push_c_state(TcpState::SynSent);
        //self.con_rec.s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn p_port(&self) -> u16 {
        self.con_rec.port
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.con_rec.port != 0
    }

    #[inline]
    pub fn set_p_port(&mut self, port: u16) {
        self.con_rec.port = port;
    }

    #[inline]
    pub fn get_dut_sock(&self) -> Option<&SocketAddrV4> {
        self.con_rec.sock.as_ref()
    }

    #[inline]
    pub fn set_dut_sock(&mut self, dut_sock: SocketAddrV4) {
        self.con_rec.sock = Some(dut_sock);
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(s-port={}, {:?})",
            self.p_port(),
            self.con_rec.c_states(),
            //self.con_rec.s_states(),
        )
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

#[allow(dead_code)]
pub struct ConnectionManager {
    con_records: Vec<ConRecord>,
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    sock2port: HashMap<SocketAddrV4, u16>,
    timeouts: Timeouts,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tx: Sender<MessageFrom>,
    tcp_port_base: u16,
    special_port: u16, // e.g. used as a listen port, not assigned by create
    ip: u32,    // ip address to use for connections of this manager
}

impl ConnectionManager {
    pub fn new(
        pipeline_id: PipelineId,
        pci: CacheAligned<PortQueue>,
        engine_config: &EngineConfig,
        l4flow: &L4Flow,
        tx: Sender<MessageFrom>,
    ) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        let cm = ConnectionManager {
            con_records: Vec::with_capacity(100000),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            sock2port: HashMap::with_capacity((!port_mask + 1) as usize),
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            timeouts: Timeouts::default_or_some(&engine_config.timeouts),
            pci,
            pipeline_id,
            tx,
            tcp_port_base,
            special_port: max_tcp_port,
            ip,
        };
        // we use the port with # max_tcp_port for returning traffic to us, do not add it to free_ports
        debug!(
            "created ConnectionManager {} for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            cm.free_ports.front().unwrap(),
            cm.free_ports.back().unwrap(),
        );
        cm
    }

    #[inline]
    fn get_mut_con(&mut self, p: &u16) -> &mut Connection {
        &mut self.port2con[(p - self.tcp_port_base) as usize]
    }

    pub fn owns_tcp_port(&self, tcp_port: u16) -> bool {
        tcp_port & self.pci.port.get_tcp_dst_port_mask() == self.tcp_port_base
    }

    #[inline]
    pub fn tcp_port_base(&self) -> u16 {
        self.tcp_port_base
    }

    #[inline]
    pub fn special_port(&self) -> u16 {
        self.special_port
    }

    pub fn get_mut_by_port(&mut self, port: u16) -> Option<&mut Connection> {
        if self.owns_tcp_port(port) {
            let c = self.get_mut_con(&port);
            // check if c has a port != 0 assigned
            // otherwise it is released, as we keep released connections
            // and just mark them as unused by assigning port 0
            if c.p_port() != 0 {
                Some(c)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_mut_by_sock(&mut self, sock: &SocketAddrV4) -> Option<&mut Connection> {
        let port = self.sock2port.get(sock);
        if port.is_some() {
            Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize])
        } else {
            None
        }
    }

    pub fn get_mut_or_insert(&mut self, sock: SocketAddrV4, _wheel: &mut TimerWheel<u16>) -> Option<&mut Connection> {
        {
            // we borrow sock2port here !
            let port = self.sock2port.get(&sock);
            if port.is_some() {
                return Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize]);
            }
        }
        // now we are free to borrow sock2port mutably
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            //let now;
            {
                let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
                assert_eq!(cc.p_port(), 0);
                cc.initialize(Some(sock), port);
                //now = cc.con_rec.c_syn_recv;
                debug!("tcp flow for {} created on port {:?}", sock, port);
            }
            //if self.timeouts.established.unwrap() < wheel.get_max_timeout_cycles() {
            //    wheel.schedule(&(now + self.timeouts.established.unwrap()*MILLIS_TO_CYCLES), port);
            //}
            self.sock2port.insert(sock, port);
            Some(self.get_mut_con(&port))
        } else {
            warn!("out of ports");
            None
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<u16>) {
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        self.timeout(port.unwrap());
                        port = drain.next();
                    }
                    if !more {
                        break;
                    }
                }
                (None, more) => if !more {
                    break;
                },
            }
        }
    }

    #[inline]
    fn timeout(&mut self, port: u16) {
        {
            let c = self.get_mut_con(&port);
            if c.in_use() {
                c.con_rec.c_released(ReleaseCause::Timeout);
                c.con_rec.push_c_state(TcpState::Closed);
            }
        }
        self.release_port(port);
    }

    // create a new connection, if out of resources return None
    pub fn create(&mut self) -> Option<&mut Connection> {
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            {
                let cc = self.get_mut_con(&port);
                assert_eq!(cc.p_port(), 0);
                cc.initialize(None, port);
                //debug!("tcp flow created on port {:?}", port);
            }
            Some(self.get_mut_con(&port))
        } else {
            warn!("out of ports");
            None
        }
    }

    pub fn release_port(&mut self, port: u16) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.con_records.push(c.con_rec.clone());
            self.free_ports.push_back(port);
            assert_eq!(port, c.p_port());
            c.set_p_port(0u16); // this indicates an unused connection,
                                // we keep unused connection in port2con table
        }
    }

    // pushes all uncompleted connections to the connection record store
    pub fn record_uncompleted(&mut self) {
        let c_records = &mut self.con_records;
        self.port2con.iter().for_each(|c| {
            if c.p_port() != 0 {
                c_records.push(c.con_rec.clone());
            }
        });
    }

    #[allow(dead_code)]
    pub fn dump_records(&mut self) {
        info!("{}: {:6} closed connections", self.pipeline_id, self.con_records.len());
        self.con_records.iter().enumerate().for_each(|(i, c)| debug!("{:6}: {}", i, c));
        info!(
            "{}: {:6} open connections",
            self.pipeline_id,
            self.port2con.iter().filter(|c| c.p_port() != 0).collect::<Vec<_>>().len()
        );
        self.port2con.iter().enumerate().for_each(|(i, c)| {
            if c.p_port() != 0 {
                info!("{:6}: {}", i, c.con_rec)
            }
        });
    }

    pub fn fetch_c_records(&mut self) -> Vec<ConRecord> {
        mem::replace(&mut self.con_records, Vec::with_capacity(100000)) // we are "moving" the con_records out, and replace it with a new one
    }

    #[allow(dead_code)]
    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            self.release_port(*p);
        })
    }
}
