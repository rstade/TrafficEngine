use std::net::{Ipv4Addr};
use std::collections::{VecDeque, BTreeMap};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};
//use e2d2::utils;

use netfcts::timer_wheel::TimerWheel;
use PipelineId;
use uuid::Uuid;
use netfcts::tcp_common::*;
use netfcts::ConRecord;

#[derive(Clone)]
pub struct Connection {
    pub con_rec: ConRecord,
    /// next client side sequence no towards DUT
    pub seqn_nxt: u32,
    /// oldest unacknowledged sequence no
    pub seqn_una: u32,
    /// current ack no towards DUT (expected seqn)
    pub ackn_nxt: u32,
    pub dut_mac: MacHeader, // server side mac, i.e. mac of DUT
}

impl Connection {
    #[inline]
    fn initialize(&mut self, sock: Option<&(u32,u16)>, port: u16, role: TcpRole) {
        self.seqn_nxt = 0;
        self.seqn_una = 0;
        self.ackn_nxt = 0;
        self.dut_mac = MacHeader::default();
        self.con_rec.init(role, port, sock);
    }

    #[inline]
    fn new() -> Connection {
        Connection {
            seqn_nxt: 0, //next seqn towards DUT
            seqn_una: 0, // acked by DUT
            ackn_nxt: 0, //next ackn towards DUT
            dut_mac: MacHeader::default(),
            con_rec: ConRecord::new(),
        }
    }

    #[inline]
    pub fn con_established(&mut self) {
        self.con_rec.push_state(TcpState::Established);
    }

    #[allow(dead_code)]
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
    pub fn get_dut_sock(&self) -> Option<&(u32, u16)> {
        self.con_rec.sock.as_ref()
    }

    #[inline]
    pub fn set_dut_sock(&mut self, dut_sock: (u32, u16)) {
        self.con_rec.sock = Some(dut_sock);
    }

    #[inline]
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) -> Option<Uuid> {
        mem::replace(&mut self.con_rec.uuid, uuid)
    }

    #[inline]
    pub fn get_uuid(&self) -> &Option<Uuid> {
        &self.con_rec.uuid
    }

    #[inline]
    pub fn make_uuid(&mut self) -> &Uuid {
        self.con_rec.uuid = Some(Uuid::new_v4());
        self.con_rec.uuid.as_ref().unwrap()
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
    c_record_store: Vec<ConRecord>,
    free_ports: VecDeque<u16>,
    ready: VecDeque<u16>,
    // ports of connections with data to send and in state Established when enqueued
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>,
    // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tcp_port_base: u16,
    special_port: u16,
    // e.g. used as a listen port, not assigned by create
    ip: u32, // ip address to use for connections of this manager
}

const MAX_CONNECTIONS: usize = 0xFFFF as usize;

impl ConnectionManagerC {
    pub fn new(pipeline_id: PipelineId, pci: CacheAligned<PortQueue>, l4flow: &L4Flow) -> ConnectionManagerC {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        let mut store = Vec::with_capacity(MAX_CONNECTIONS);
        store.push(ConRecord::new());
        store.pop(); // warming the Vec up! obviously when storing the first element in a Vec expensive initialization code runs
        let cm = ConnectionManagerC {
            c_record_store: store,
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            free_ports: ((if tcp_port_base == 0 { 1 } else { tcp_port_base })..max_tcp_port).collect(), // port 0 is reserved and not usable for us
            ready: VecDeque::with_capacity(MAX_CONNECTIONS), // connections which became Established (but may not longer be)
            pci,
            pipeline_id,
            tcp_port_base,
            special_port: max_tcp_port,
            ip,
        };
        // we use the port with # max_tcp_port for returning traffic to us, do not add it to free_ports
        info!(
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
                let sock = (self.ip, port);
                let cc = self.get_mut_con(&port);
                assert_eq!(cc.port(), 0);
                cc.initialize(Some(&sock), port, role);
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
            self.c_record_store.push(c.con_rec.clone());
            self.free_ports.push_back(port);
            assert_eq!(port, c.port());
            c.set_port(0u16); // this indicates an unused connection,
            // we keep unused connection in port2con table
        }
    }

    // pushes all uncompleted connections to the connection record store
    pub fn record_uncompleted(&mut self) {
        let c_records = &mut self.c_record_store;
        self.port2con.iter().for_each(|c| {
            if c.port() != 0 {
                c_records.push(c.con_rec.clone());
            }
        });
    }

    #[allow(dead_code)]
    pub fn dump_records(&mut self) {
        info!("{}: {:6} closed connections", self.pipeline_id, self.c_record_store.len());
        self.c_record_store
            .iter()
            .enumerate()
            .for_each(|(i, c)| debug!("{:6}: {}", i, c));
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
        mem::replace(&mut self.c_record_store, Vec::with_capacity(MAX_CONNECTIONS)) // we are "moving" the con_records out, and replace it with a new one
    }

    #[inline]
    pub fn set_ready_connection(&mut self, port: u16) {
        self.ready.push_back(port);
    }

    #[inline]
    pub fn ready_connections(&self) -> usize {
        self.ready.len()
    }

    pub fn get_ready_connection(&mut self) -> Option<&mut Connection> {
        let mut port_result = None;
        while port_result.is_none() {
            match self.ready.pop_front() {
                Some(port) => {
                    let c = &self.port2con[(port - self.tcp_port_base) as usize];
                    if c.port() != 0 && *c.con_rec.last_state() == TcpState::Established {
                        port_result = Some(port)
                    }
                }
                None => break, // ready queue is empty
            };
        }
        // borrow checker forces us this two-step way, cannot mutably borrow connection directly
        if let Some(port) = port_result {
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

pub struct Sock2Index {
    sock_tree: BTreeMap<u32, usize>,
    port_maps: Vec<Box<[u16; 0xFFFF]>>,
    free_maps: VecDeque<usize>,
}

impl<'a> Sock2Index {
    pub fn new() -> Sock2Index {
        Sock2Index {
            sock_tree: BTreeMap::new(),
            port_maps: vec![Box::new([0; 0xFFFF]); 8],
            free_maps: (0..8).collect(),
        }
    }

    #[inline]
    pub fn get(&self, sock: &(u32,u16)) -> Option<&u16> {
        let ip = sock.0;
        let port = sock.1;
        let port_map = self.sock_tree.get(&ip);
        match port_map {
            None => None,
            Some(port_map) => match self.port_maps[*port_map][port as usize] {
                0 => None,
                _ => Some(&self.port_maps[*port_map][port as usize] ),
            },
        }
    }

    #[inline]
    pub fn insert(&mut self, sock: (u32,u16), index: u16) {
        let ip = sock.0;
        let is_new_ip = self.sock_tree.get(&ip).is_none();
        if is_new_ip {
            let free_map_ix=self.free_maps.pop_front().expect("currently only 8 IP source addresses are supported");
            self.sock_tree.insert(ip, free_map_ix);
        }
        let port_map_ix = self.sock_tree.get(&ip).unwrap();
        self.port_maps[*port_map_ix][sock.1 as usize] = index;
    }

    #[inline]
    pub fn remove(&mut self, sock: &(u32,u16)) -> Option<u16> {
        let port_map_ix = self.sock_tree.get(&sock.0);
        if port_map_ix.is_none() {
            return None;
        } else {
            let pm_ix = **port_map_ix.as_ref().unwrap();
            let old = self.port_maps[pm_ix][sock.1 as usize];
            self.port_maps[pm_ix][sock.1 as usize]= 0;
            match old {
                0 => None,
                _ => Some(old),
            }
        }
    }

    pub fn values(&'a self) -> Vec<u16> {
        self.sock_tree.values().flat_map(|i| {
            self.port_maps[*i as usize].iter().filter(|ix| **ix != 0).map(|ix| *ix).collect::<Vec<u16>>()
        }).collect()
    }
}

pub struct ConnectionManagerS {
    c_record_store: Vec<ConRecord>,
    sock2index: Sock2Index,
    connections: Vec<Connection>,
    free_slots: VecDeque<usize>,
}

impl ConnectionManagerS {
    pub fn new() -> ConnectionManagerS {
        let mut store = Vec::with_capacity(MAX_CONNECTIONS);
        store.push(ConRecord::new());
        store.pop(); // warming the Vec up! obviously when storing the first element in a Vec expensive initialization code runs
        ConnectionManagerS {
            c_record_store: store,
            sock2index: Sock2Index::new(),
            connections: vec![Connection::new(); MAX_CONNECTIONS],
            free_slots: (1..MAX_CONNECTIONS).collect(), // we use index 0 to indicate unused slots
        }
    }

    pub fn get_mut(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        let index = self.sock2index.get(sock);
        if index.is_some() {
            Some(&mut self.connections[*index.unwrap() as usize])
        } else {
            None
        }
    }

    pub fn get_mut_or_insert(&mut self, sock: &(u32,u16)) -> Option<&mut Connection> {
        {
            let index = self.sock2index.get(sock);
            if index.is_some() {
                return Some(&mut self.connections[*index.unwrap() as usize]);
            }
        }
        // create
        let index = self.free_slots.pop_front();
        if index.is_some() {
            //self.sock2index.insert(*sock, index.unwrap());
            self.sock2index.insert(*sock, index.unwrap() as u16);
            let c = &mut self.connections[index.unwrap()];
            c.initialize(Some(sock), 0, TcpRole::Server);
            Some(c)
        } else {
            None // out of resources
        }
    }

    pub fn insert(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        let index = self.free_slots.pop_front();
        if index.is_some() {
            self.sock2index.insert(*sock, index.unwrap() as u16);
            let c = &mut self.connections[index.unwrap()];
            c.initialize(Some(sock), 0, TcpRole::Server);
            Some(c)
        } else {
            None // out of resources
        }
    }

    pub fn release_sock(&mut self, sock: &(u32,u16)) {
        // only if it is in use, i.e. it has been not released already
        let index = self.sock2index.remove(&sock);
        if index.is_some() {
            let mut c = self.connections[index.unwrap() as usize].clone();
            if c.get_uuid().is_none() {
                c.make_uuid();
            }
            self.c_record_store.push(c.con_rec.clone());
            self.free_slots.push_back(index.unwrap() as usize);
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<(u32,u16)>) {
        trace!("release_timeouts");
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
    fn timeout(&mut self, sock: &(u32, u16)) {
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
        let c_records = &mut self.c_record_store;
        let connections = &self.connections;
        for index in self.sock2index.values() {
            let mut c = connections[index as usize].clone();
            if c.get_uuid().is_none() {
                c.make_uuid();
            }
            c_records.push(c.con_rec.clone());
        };
    }

    pub fn fetch_c_records(&mut self) -> Vec<ConRecord> {
        mem::replace(&mut self.c_record_store, Vec::with_capacity(MAX_CONNECTIONS)) // we are "moving" the con_records out, and replace it with a new one
    }
}
