use std::net::{SocketAddrV4, Ipv4Addr};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
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
use timer_wheel::{TimerWheel};
use { PipelineId,};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    Closing,
    FinWait2,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpRole {
    Client,
    Server,
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
    PassiveClose = 2,
    ActiveClose = 3,
    PassiveRst = 4,
    ActiveRst = 5,
    MaxCauses = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CData {
    // connection data sent as first payload packet
    pub reply_socket: SocketAddrV4,
    pub client_port: u16,

}

#[derive(Clone)]
pub struct ConRecord {
    pub role: TcpRole,
    pub port: u16,
    pub sock: Option<SocketAddrV4>,
    state_count: usize,
    state: [TcpState; 8],
    stamps: [u64; 8],
    pub payload_packets: usize,
    pub server_index: usize,
    release_cause: ReleaseCause,
}

impl ConRecord {
    #[inline]
    fn init(&mut self, role: TcpRole, port: u16, sock: Option<&SocketAddrV4>) {
        self.port = port;
        self.state_count = 1;
        if role == TcpRole::Client {
            self.state[0] = TcpState::Closed;
        } else {
            self.state[0] = TcpState::Listen;
        }
        self.server_index = 0;
        self.sock = if sock.is_some() { Some(*sock.unwrap()) } else { None };
        self.role=role;
    }

    #[inline]
    pub fn released(&mut self, cause: ReleaseCause) {
        self.release_cause = cause;
    }

    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    fn new() -> ConRecord {
        ConRecord {
            role: TcpRole::Client,
            server_index: 0,
            release_cause: ReleaseCause::Unknown,
            // we are using an Array, not Vec for the state history, the latter eats too much performance
            state_count: 0,
            state: [TcpState::Closed; 8],
            stamps: [0; 8],
            port: 0u16,
            sock: None,
            payload_packets: 0,
        }
    }

    #[inline]
    pub fn push_state(&mut self, state: TcpState) {
        self.state[self.state_count] = state;
        self.stamps[self.state_count] = utils::rdtsc_unsafe();
        self.state_count += 1;
    }

    #[inline]
    pub fn last_state(&self) -> &TcpState {
        &self.state[self.state_count - 1]
    }

    #[inline]
    pub fn states(&self) -> &[TcpState] {
        &self.state[0..self.state_count]
    }

    pub fn elapsed_since_synsent_or_synrecv(&self) -> Vec<u64> {
        //let synsent = self.stamps[1];
        if self.state_count >= 3 {
            let vals= self.stamps[1..self.state_count].iter();
            let next_vals = self.stamps[1..self.state_count].iter().skip(1);
            //self.stamps[2..self.state_count].iter().map(|stamp| stamp - synsent).collect()
            vals.zip(next_vals).map(|(cur,next)| next-cur ).collect()
        } else {
            vec![]
        }
    }
}

impl fmt::Display for ConRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?}, port={}, {:?}, {:?}, {}, {:?})",
            self.role,
            self.port,
            self.states(),
            self.release_cause,
            self.stamps[1].separated_string(),
            self.elapsed_since_synsent_or_synrecv()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone)]
pub struct Connection {
    pub con_rec: ConRecord,
    pub seqn_nxt: u32,    // next client side sequence no towards DUT
    pub seqn_una: u32,    // oldest unacknowledged sequence no
    pub ackn_nxt: u32,    // current ack no towards DUT (expected seqn)
    pub dut_mac: MacHeader, // server side mac, i.e. mac of DUT
}

impl Connection {
    #[inline]
    fn initialize(&mut self, sock: Option<&SocketAddrV4>, port: u16, role: TcpRole) {
        self.seqn_nxt = 0;
        self.seqn_una = 0;
        self.ackn_nxt = 0;
        self.dut_mac = MacHeader::default();
        self.con_rec.init(role, port, sock);
    }

    fn new() -> Connection {
        Connection {
            seqn_nxt: 0, //next seqn towards DUT
            seqn_una: 0, // acked by DUT
            ackn_nxt: 0, //next ackn towards DUT
            dut_mac: MacHeader::default(),
            con_rec: ConRecord::new(),
        }
    }

    fn new_with_sock(sock: &SocketAddrV4, role: TcpRole) -> Connection {
        let mut connection= Connection::new();
        connection.initialize(Some(sock), 0, role);
        connection
    }

    #[inline]
    pub fn con_established(&mut self) {
        self.con_rec.push_state(TcpState::Established);
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.con_rec.push_state(TcpState::SynSent);
        //self.con_rec.s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.con_rec.port
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.con_rec.port != 0
    }

    #[inline]
    pub fn set_port(&mut self, port: u16) {
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
            self.port(),
            self.con_rec.states(),
            //self.con_rec.s_states(),
        )
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManagerC {
    con_records: Vec<ConRecord>,
    free_ports: VecDeque<u16>,
    ready: VecDeque<u16>,  // ports of connections with data to send and in state Established when enqueued
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tcp_port_base: u16,
    special_port: u16, // e.g. used as a listen port, not assigned by create
    ip: u32,    // ip address to use for connections of this manager
}


const MAX_CONNECTIONS:usize = 0xFFFF as usize;

impl ConnectionManagerC {
    pub fn new(
        pipeline_id: PipelineId,
        pci: CacheAligned<PortQueue>,
        l4flow: &L4Flow,
    ) -> ConnectionManagerC {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        let cm = ConnectionManagerC {
            con_records: Vec::with_capacity(MAX_CONNECTIONS),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            ready: VecDeque::with_capacity(MAX_CONNECTIONS),    // connections which became Established (but may not longer be)
            pci,
            pipeline_id,
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


    // create a new connection, if out of resources return None
    pub fn create(&mut self, role: TcpRole) -> Option<&mut Connection> {
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            {
                let cc = self.get_mut_con(&port);
                assert_eq!(cc.port(), 0);
                cc.initialize(None, port, role);
                //debug!("tcp flow created on port {:?}", port);
            }
            Some(self.get_mut_con(&port))
        } else {
            warn!("out of ports");
            None
        }
    }

    pub fn owns_tcp_port(&self, tcp_port: u16) -> bool {
        tcp_port & self.pci.port.get_tcp_dst_port_mask() == self.tcp_port_base
    }

    #[inline]
    pub fn tcp_port_base(&self) -> u16 {
        self.tcp_port_base
    }

    #[inline]
    pub fn ip(&self) -> u32 {
        self.ip
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
            if c.port() != 0 {
                Some(c)
            } else {
                None
            }
        } else {
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
                c.con_rec.released(ReleaseCause::Timeout);
                c.con_rec.push_state(TcpState::Closed);
            }
        }
        self.release_port(port);
    }


    pub fn release_port(&mut self, port: u16) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.con_records.push(c.con_rec.clone());
            self.free_ports.push_back(port);
            assert_eq!(port, c.port());
            c.set_port(0u16); // this indicates an unused connection,
                                // we keep unused connection in port2con table
        }
    }

    // pushes all uncompleted connections to the connection record store
    pub fn record_uncompleted(&mut self) {
        let c_records = &mut self.con_records;
        self.port2con.iter().for_each(|c| {
            if c.port() != 0 {
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
            self.port2con.iter().filter(|c| c.port() != 0).collect::<Vec<_>>().len()
        );
        self.port2con.iter().enumerate().for_each(|(i, c)| {
            if c.port() != 0 {
                info!("{:6}: {}", i, c.con_rec)
            }
        });
    }

    pub fn fetch_c_records(&mut self) -> Vec<ConRecord> {
        mem::replace(&mut self.con_records, Vec::with_capacity(MAX_CONNECTIONS)) // we are "moving" the con_records out, and replace it with a new one
    }

    #[inline]
    pub fn set_ready_connection(&mut self, port: u16)  {
        self.ready.push_back(port);
    }

    #[inline]
    pub fn ready_connections(&self) -> usize { self.ready.len() }

    pub fn get_ready_connection(&mut self) -> Option<&mut Connection> {
        let mut port_result=None;
        while port_result.is_none() {
            match self.ready.pop_front() {
                Some(port) => {
                    let c=&self.port2con[(port - self.tcp_port_base) as usize];
                    if c.port() !=0 && *c.con_rec.last_state()==TcpState::Established {
                        port_result=Some(port)
                    }
                },
                None => break, // ready queue is empty
            };
        }
        // borrow checker forces us this two-step way, cannot mutably borrow connection directly
        if let Some(port)=port_result {
            Some(&mut self.port2con[(port - self.tcp_port_base) as usize])
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            self.release_port(*p);
        })
    }
}


pub struct ConnectionManagerS {
    con_records: Vec<ConRecord>,
    connections: HashMap<SocketAddrV4, Box<Connection>>,
}


impl ConnectionManagerS {
    pub fn new() -> ConnectionManagerS {
        let cm = ConnectionManagerS {
            con_records: Vec::with_capacity(MAX_CONNECTIONS),
            connections: HashMap::with_capacity(MAX_CONNECTIONS),
        };
        cm
    }

    pub fn insert_new(&mut self, sock: &SocketAddrV4,) -> Option<Box<Connection>> {
        self.connections.insert(*sock, Box::new(Connection::new_with_sock(sock, TcpRole::Server)))
    }

    pub fn insert(&mut self, sock: &SocketAddrV4, connection: Box<Connection>) -> Option<Box<Connection>> {
        self.connections.insert(*sock, connection)
    }


    pub fn get_mut(&mut self, sock: &SocketAddrV4) -> Option<&mut Box<Connection>> {
        self.connections.get_mut(sock)
    }


    pub fn release_sock(&mut self, sock: &SocketAddrV4) {
        let c = self.connections.remove(sock);
        // only if it is in use, i.e. it has been not released already
        if c.is_some() {
            self.con_records.push(c.unwrap().con_rec.clone());
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<SocketAddrV4>) {
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut sock = drain.next();
                    while sock.is_some() {
                        self.timeout(&sock.unwrap());
                        sock = drain.next();
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
    fn timeout(&mut self, sock: &SocketAddrV4) {
        {
            let mut c = self.get_mut(sock);
            if c.is_some() {
                c.as_mut().unwrap().con_rec.released(ReleaseCause::Timeout);
                c.unwrap().con_rec.push_state(TcpState::Closed);
            }
        }
        self.release_sock(sock);
    }


    // pushes all uncompleted connections to the connection record store
    pub fn record_uncompleted(&mut self) {
        let c_records = &mut self.con_records;
        self.connections.values().for_each(|c| {
            c_records.push(c.con_rec.clone());
        });
    }


    pub fn fetch_c_records(&mut self) -> Vec<ConRecord> {
        mem::replace(&mut self.con_records, Vec::with_capacity(MAX_CONNECTIONS)) // we are "moving" the con_records out, and replace it with a new one
    }


}
