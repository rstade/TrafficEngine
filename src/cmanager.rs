use std::net::Ipv4Addr;
use std::collections::{VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;
use std::cell::RefCell;
use std::rc::Rc;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};
use e2d2::utils;

use netfcts::timer_wheel::TimerWheel;
use PipelineId;

use netfcts::tcp_common::*;
use netfcts::RecordStore;
use netfcts::utils::shuffle_ports;

#[derive(Clone)]
pub struct Connection {
    con_rec: Option<usize>,
    /// next client side sequence no towards DUT
    pub seqn_nxt: u32,
    /// oldest unacknowledged sequence no
    pub seqn_una: u32,
    /// current ack no towards DUT (expected seqn)
    pub ackn_nxt: u32,
    pub dut_mac: MacHeader, // server side mac, i.e. mac of DUT
    store: Rc<RefCell<RecordStore>>
}

impl Connection {
    #[inline]
    fn initialize(&mut self, sock: Option<(u32, u16)>, port: u16, role: TcpRole) {
        self.seqn_nxt = 0;
        self.seqn_una = 0;
        self.ackn_nxt = 0;
        self.dut_mac = MacHeader::default();
        self.con_rec = Some(self.store.borrow_mut().get_unused_slot());
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().init(role, port, sock);
    }

    #[inline]
    fn new(store: Rc<RefCell<RecordStore>>) -> Connection {
        Connection {
            seqn_nxt: 0, //next seqn towards DUT
            seqn_una: 0, // acked by DUT
            ackn_nxt: 0, //next ackn towards DUT
            dut_mac: MacHeader::default(),
            con_rec: None,
            store,
        }
    }


    #[inline]
    pub fn con_established(&mut self) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().push_state(TcpState::Established);
    }

    #[allow(dead_code)]
    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().push_state(TcpState::SynSent);
        //self.con_rec().s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().port
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.port() != 0
    }

    #[inline]
    pub fn server_index(&self) -> usize {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().server_index
    }

    #[inline]
    pub fn set_server_index(&mut self, index: usize) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().server_index=index
    }

    #[inline]
    pub fn payload_packets(&self) -> usize {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().payload_packets
    }

    #[inline]
    pub fn increment_payload_packets(&self) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().payload_packets+=1
    }

    #[inline]
    pub fn last_state(&self) -> TcpState {
        *self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().last_state()
    }

    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().states().to_vec()
    }

    #[inline]
    pub fn push_state(&self, state: TcpState) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().push_state(state)
    }

    #[inline]
    pub fn released(&self, cause: ReleaseCause) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().released(cause)
    }

    #[inline]
    pub fn set_port(&mut self, port: u16) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().port = port;
    }

    #[inline]
    pub fn get_dut_sock(&self) -> Option<(u32, u16)> {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().sock
    }

    #[inline]
    pub fn set_dut_sock(&mut self, dut_sock: (u32, u16)) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().sock = Some(dut_sock);
    }

    #[inline]
    pub fn set_uid(&mut self, uid: u64) {
        self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().set_uid(uid);
    }

    #[inline]
    pub fn get_uid(&self) -> u64 {
        self.store.borrow().get(self.con_rec.expect("connection has no ConRecord")).unwrap().uid()
    }

}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(s-port={}, {:?})",
            self.port(),
            self.store.borrow_mut().get_mut(self.con_rec.expect("connection has no ConRecord")).unwrap().states(),
            //self.con_rec().s_states(),
        )
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManagerC {
    c_record_store: Rc<RefCell<RecordStore>>,
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
const MAX_RECORDS: usize = 0x3FFFF as usize;

impl ConnectionManagerC {
    pub fn new(pipeline_id: PipelineId, pci: CacheAligned<PortQueue>, l4flow: &L4Flow) -> ConnectionManagerC {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        let store= Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let cm = ConnectionManagerC {
            c_record_store: store.clone(),
            port2con: vec![Connection::new(store); (!port_mask + 1) as usize],
            // port 0 is reserved and not usable for us, ports are shuffled for better load sharing in DUTs
            // max_tcp_port itself is reserved for the server side for listening
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                VecDeque::<u16>::from(vec)
            },
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
                cc.initialize(Some(sock), port, role);
            }
            Some(self.get_mut_con(&port))
        } else {
            warn!("out of ports");
            None
        }
    }

    #[inline]
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
                (None, more) => {
                    if !more {
                        break;
                    }
                }
            }
        }
    }

    #[inline]
    fn timeout(&mut self, port: u16) {
        {
            let c = self.get_mut_con(&port);
            if c.in_use() {
                c.released(ReleaseCause::Timeout);
                c.push_state(TcpState::Closed);
            }
        }
        self.release_port(port);
    }

    pub fn release_port(&mut self, port: u16) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.free_ports.push_front(port);
            assert_eq!(port, c.port());
            c.set_port(0u16); // this indicates an unused connection,
            // we keep unused connection in port2con table
        }
    }

    #[allow(dead_code)]
    pub fn dump_records(&mut self) {
        info!("{}: {:6} closed connections", self.pipeline_id, self.c_record_store.borrow().len());
        self.c_record_store
            .borrow()
            .iter()
            .enumerate()
            .for_each(|(i, c)| debug!("{:6}: {}", i, c));
        info!(
            "{}: {:6} open connections",
            self.pipeline_id,
            self.port2con.iter().filter(|c| c.port() != 0).collect::<Vec<_>>().len()
        );
        /*
        self.port2con.iter().enumerate().for_each(|(i, c)| {
            if c.port() != 0 {
                // info!("{:6}: {}", i, c.con_rec())
            }
        });
        */
    }

    pub fn fetch_c_records(&mut self) -> Option<RecordStore> {
        // we are "moving" the con_records out, and replace it with a new one
        let new_store= Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let new_store_clone = Rc::clone(&new_store);
        let store=mem::replace(&mut self.c_record_store, new_store);
        for mut c in &mut self.port2con {
            c.store= Rc::clone(&new_store_clone)
        }
        let strong_count= Rc::strong_count(&store);
        let unwrapped= Rc::try_unwrap(store);
        if unwrapped.is_ok() {
            Some(unwrapped.unwrap().into_inner())
        }
        else {
            error!("cm_s.fetch_c_records: strong_count= { }" , strong_count);
            None
        }
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
                    if c.port() != 0 && c.last_state() == TcpState::Established {
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

use netfcts::utils::Sock2Index as Sock2Index;
use netfcts::utils::TimeAdder;

pub struct ConnectionManagerS {
    c_record_store: Rc<RefCell<RecordStore>>,
    sock2index: Sock2Index,
    connections: Vec<Connection>,
    free_slots: VecDeque<usize>,
}

impl ConnectionManagerS {
    pub fn new() -> ConnectionManagerS {
        let store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        ConnectionManagerS {
            c_record_store: store.clone(),
            sock2index: Sock2Index::new(),
            connections: vec![Connection::new(store); MAX_CONNECTIONS],
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

    pub fn get_mut_or_insert(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
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
            c.initialize(Some(*sock), 0, TcpRole::Server);
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
            c.initialize(Some(*sock), 0, TcpRole::Server);
            Some(c)
        } else {
            None // out of resources
        }
    }

    pub fn release_sock(&mut self, sock: &(u32, u16), time_adder: Option<&mut TimeAdder>) {
        // only if it is in use, i.e. it has been not released already
        let index = self.sock2index.remove(&sock);
        self.free_slots.push_front(index.unwrap() as usize);
        if time_adder.is_some() {
            # [cfg(feature = "profiling")]
                time_adder.unwrap().add_stamp(utils::rdtsc_unsafe());
        }
    }



    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<(u32, u16)>) {
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
                (None, more) => {
                    if !more {
                        break;
                    }
                }
            }
        }
    }

    #[inline]
    fn timeout(&mut self, sock: &(u32, u16)) {
        {
            let c = self.get_mut(sock);
            if c.is_some() {
                let c= c.unwrap();
                c.released(ReleaseCause::Timeout);
                c.push_state(TcpState::Closed);
            }
        }
        self.release_sock(sock, None);
    }

    pub fn fetch_c_records(&mut self) -> Option<RecordStore> {
        // we are "moving" the con_records out, and replace it with a new one
        let new_store= Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let new_store_clone = Rc::clone(&new_store);
        let store=mem::replace(&mut self.c_record_store, new_store);
        for mut c in &mut self.connections {
            c.store= Rc::clone(&new_store_clone)
        }
        let strong_count= Rc::strong_count(&store);
        let unwrapped= Rc::try_unwrap(store);
        if unwrapped.is_ok() {
            Some(unwrapped.unwrap().into_inner())
        }
        else {
            error!("cm_s.fetch_c_records: strong_count= { }" , strong_count);
            None
        }
    }
}
