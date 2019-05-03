use std::net::Ipv4Addr;
use std::collections::VecDeque;
//use std::collections::HashMap;
//use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering, };
use std::fmt;
use std::mem;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use e2d2::interface::{PortQueue, L4Flow};
use netfcts::timer_wheel::TimerWheel;
use PipelineId;

use netfcts::tcp_common::*;
use netfcts::conrecord::{ConRecord, HasTcpState};
use netfcts::utils::shuffle_ports;
use netfcts::{RecordStore, ConRecordOperations};
use netfcts::recstore::TEngineStore;


//#[repr(align(64))]
#[derive(Debug)]
pub struct Connection {
    record: Option<Box<DetailedRecord>>,
    pub wheel_slot_and_index: (u16, u16),
    /// next client side sequence no towards DUT
    pub seqn_nxt: u32,
    // oldest unacknowledged sequence no
    //    pub seqn_una: u32,
    /// current ack no towards DUT (expected seqn)
    pub ackn_nxt: u32,
    /// either our IP, if we are client, or IP of DUT if we are server
    client_ip: u32,
    sent_payload_packets: u16,
    recv_payload_packets: u16,
    /// either our port, if we are client, or port of DUT if we are server
    client_port: u16,
    server_index: u8,
    state: TcpState,
}

const ERR_NO_CON_RECORD: &str = "connection has no ConRecord";

impl Connection {
    #[inline]
    fn initialize(&mut self, client_sock: Option<(u32, u16)>, role: TcpRole) {
        self.seqn_nxt = 0;
        //self.seqn_una = 0;
        self.ackn_nxt = 0;
        let s = client_sock.unwrap_or((0, 0));
        self.client_ip = s.0;
        self.client_port = s.1;
        self.wheel_slot_and_index = (0, 0);
        self.server_index = 0;
        self.sent_payload_packets = 0;
        self.recv_payload_packets = 0;
        self.state = tcp_start_state(role);
    }

    #[inline]
    fn initialize_with_details(&mut self, sock: Option<(u32, u16)>, role: TcpRole, store: Rc<RefCell<TEngineStore>>) {
        self.initialize(sock, role);
        if self.record.is_none() {
            self.record = Some(Box::new(DetailedRecord::new(store)));
        } else {
            self.record.as_mut().unwrap().re_new(store);
        }
        self.record.as_mut().unwrap().initialize(sock, role);
    }

    #[inline]
    fn new() -> Connection {
        Connection {
            seqn_nxt: 0, //next seqn towards DUT
            //seqn_una: 0, // acked by DUT
            ackn_nxt: 0, //next ackn towards DUT
            wheel_slot_and_index: (0, 0),
            client_port: 0,
            client_ip: 0,
            server_index: 0,
            sent_payload_packets: 0,
            recv_payload_packets: 0,
            record: None,
            state: TcpState::Listen,
        }
    }

    #[inline]
    pub fn push_state(&mut self, state: TcpState) {
        if self.record.is_some() {
            self.record.as_mut().unwrap().push_state(state)
        }
        self.state = state;
    }

    #[inline]
    pub fn state(&self) -> TcpState {
        self.state
    }

    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        if self.record.is_some() {
            self.record.as_ref().unwrap().states()
        } else {
            Vec::new()
        }
    }

    #[inline]
    pub fn sock(&self) -> Option<(u32, u16)> {
        let s = (self.client_ip, self.client_port);
        if self.in_use() {
            Some(s)
        } else {
            None
        }
    }

    #[inline]
    pub fn set_sock(&mut self, s: (u32, u16)) {
        self.client_ip = s.0;
        self.client_port = s.1;
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.client_port
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.client_port != 0
    }

    #[inline]
    pub fn server_index(&self) -> usize {
        self.server_index as usize
    }

    #[inline]
    pub fn set_server_index(&mut self, index: usize) {
        if self.record.is_some() {
            self.record.as_mut().unwrap().set_server_index(index)
        }
        self.server_index = index as u8;
    }


    #[inline]
    pub fn set_release_cause(&mut self, cause: ReleaseCause) {
        if self.record.is_some() {
            self.record.as_mut().unwrap().set_release_cause(cause)
        }
    }

    #[inline]
    pub fn inc_sent_payload_pkts(&mut self) -> usize {
        if self.record.is_some() {
            self.record.as_mut().unwrap().inc_sent_payload_pkts();
        };
        self.sent_payload_packets += 1;
        self.sent_payload_packets as usize
    }

    #[inline]
    pub fn inc_recv_payload_pkts(&mut self) -> usize {
        if self.record.is_some() {
            self.record.as_mut().unwrap().inc_recv_payload_pkts();
        };
        self.recv_payload_packets += 1;
        self.recv_payload_packets as usize
    }

    #[inline]
    pub fn sent_payload_pkts(&self) -> usize {
        self.sent_payload_packets as usize
    }

    #[inline]
    pub fn recv_payload_pkts(&self) -> usize {
        self.recv_payload_packets as usize
    }

    #[inline]
    fn release(&mut self) {
        self.client_port = 0;
        if self.record.is_some() {
            self.record.as_mut().unwrap().release();
        }
    }


    #[inline]
    pub fn set_uid(&mut self, uid: u64) {
        if self.record.is_some() {
            self.record.as_mut().unwrap().set_uid(uid);
        }
    }

    #[inline]
    pub fn uid(&self) -> u64 {
        if self.record.is_some() {
            self.record.as_ref().unwrap().get_uid()
        } else {
            0
        }
    }
}

impl<'a> Clone for Connection {
    fn clone(&self) -> Self {
        Connection::new()
    }
}

pub struct DetailedRecord {
    con_rec: Option<usize>,
    store: Option<Rc<RefCell<TEngineStore>>>,
}


impl DetailedRecord {
    #[inline]
    fn initialize(&mut self, client_sock: Option<(u32, u16)>, role: TcpRole) {
        self.store().borrow_mut().get_mut(self.con_rec()).init(role, 0, client_sock);
    }

    fn new(store: Rc<RefCell<TEngineStore>>) -> DetailedRecord {
        let con_rec = store.borrow_mut().get_next_slot();
        DetailedRecord {
            con_rec: Some(con_rec),
            store: Some(store),
        }
    }

    fn re_new(&mut self, store: Rc<RefCell<TEngineStore>>) {
        let con_rec = store.borrow_mut().get_next_slot();
        self.con_rec = Some(con_rec);
        self.store = Some(store);
    }

    #[inline]
    pub fn push_state(&mut self, state: TcpState) {
        self.store().borrow_mut().get_mut(self.con_rec()).push_state(state);
    }

    #[inline]
    fn release(&mut self) {
        //trace!("releasing con record on port {}", self.port());
        self.con_rec = None;
        self.store = None;
    }
}


impl fmt::Debug for DetailedRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "DetailedRecord= {:?}", self.store().borrow().get(self.con_rec()))
    }
}


impl ConRecordOperations<TEngineStore> for DetailedRecord {
    #[inline]
    fn store(&self) -> &Rc<RefCell<TEngineStore>> {
        self.store.as_ref().unwrap()
    }

    #[inline]
    fn con_rec(&self) -> usize {
        self.con_rec.expect(ERR_NO_CON_RECORD)
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.store.is_some()
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Connection(sock={:?}, state={:?})", self.sock(), self.state(),)
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct ConnectionManagerC {
    c_record_store: Option<Rc<RefCell<RecordStore<ConRecord>>>>,
    free_ports: VecDeque<u16>,
    ready: VecDeque<u16>,
    /// min number of free ports
    min_free_ports: usize,
    // ports of connections with data to send and in state Established when enqueued
    port2con: Vec<Connection>,
    pci: PortQueue,
    // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tcp_port_base: u16,
    available_ports_count: usize,
    // e.g. used as a listen port, not assigned by create
    listen_port: u16,
    ip: u32,
    // ip address to use for connections of this manager
    /// with or without recording of connections
    detailed_records: bool,
}

const MAX_CONNECTIONS: usize = 0xFFFF as usize;
const MAX_RECORDS: usize = 0x3FFFF as usize;

impl ConnectionManagerC {
    pub fn new(pipeline_id: PipelineId, pci: PortQueue, l4flow: &L4Flow, detailed_records: bool) -> ConnectionManagerC {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        let store = if detailed_records {
            Some(Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS))))
        } else {
            None
        };
        let avail_ports;
        let cm = ConnectionManagerC {
            c_record_store: store,
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            // port 0 is reserved and not usable for us, ports are shuffled for better load sharing in DUTs
            // max_tcp_port itself is reserved for the server side for listening
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                //let vec = (if tcp_port_base == 0 { 1 } else { tcp_port_base }.. max_tcp_port - 1).collect();
                avail_ports = vec.len();
                VecDeque::<u16>::from(vec)
            },
            available_ports_count: avail_ports,
            ready: VecDeque::with_capacity(MAX_CONNECTIONS), // connections which became Established (but may not longer be)
            min_free_ports: !port_mask as usize + 1,
            pci,
            pipeline_id,
            tcp_port_base,
            listen_port: max_tcp_port,
            ip,
            detailed_records,
        };
        // we use the port max_tcp_port for returning traffic to us, do not add it to free_ports
        info!(
            "created ConnectionManager {} for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            cm.pci.port_id(),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            if tcp_port_base == 0 { 1 } else { tcp_port_base },
            max_tcp_port - 1,
        );
        cm
    }

    #[inline]
    pub fn max_concurrent_connections(&self) -> usize {
        //        (!self.pci.port.get_tcp_dst_port_mask() - (if self.tcp_port_base == 0 { 1 } else { 0 })) as usize
        self.available_ports_count - self.min_free_ports
    }

    #[inline]
    pub fn concurrent_connections(&self) -> usize {
        self.available_ports_count - self.free_ports.len()
    }

    #[inline]
    pub fn available_ports_count(&self) -> usize {
        self.available_ports_count
    }


    #[inline]
    fn get_mut_con(&mut self, p: &u16) -> &mut Connection {
        &mut self.port2con[(p - self.tcp_port_base) as usize]
    }

    // create a new connection, if out of resources return None
    #[inline]
    pub fn create(&mut self, role: TcpRole) -> Option<&mut Connection> {
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            {
                let sock = (self.ip, port);
                if self.detailed_records {
                    let store = Rc::clone(self.c_record_store.as_ref().unwrap());
                    self.get_mut_con(&port).initialize_with_details(Some(sock), role, store);
                } else {
                    self.get_mut_con(&port).initialize(Some(sock), role);
                }
            }
            self.min_free_ports = cmp::min(self.min_free_ports, self.free_ports.len());
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
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    #[inline]
    pub fn get_mut_by_port(&mut self, port: u16) -> Option<&mut Connection> {
        if self.owns_tcp_port(port) {
            let c = self.get_mut_con(&port);
            // check if c is in use
            if c.in_use() {
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
                        let p = port.unwrap();
                        if p != 0 {
                            self.timeout(p);
                        }
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
        // the borrow checker makes things a little bit cumbersome:
        let mut in_use = false;
        {
            let c = self.get_mut_con(&port);
            if c.in_use() {
                in_use = true;
                c.set_release_cause(ReleaseCause::Timeout);
                c.push_state(TcpState::Closed);
                debug!("timing out port {} at {:?}", port, c.wheel_slot_and_index);
                // now we release the connection inline (cannot call self.release)
                c.release();
            }
        }
        if in_use {
            self.free_ports.push_back(port);
        }
    }

    #[inline]
    pub fn release(&mut self, port: u16, wheel: &mut TimerWheel<u16>) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.free_ports.push_back(port);
            c.release();
            //remove port from timer wheel by overwriting it
            let old = wheel.replace(c.wheel_slot_and_index, 0);
            assert_eq!(old.unwrap(), port);
            // we keep unused connection in port2con table
        }
    }

    #[allow(dead_code)]
    pub fn dump_records(&mut self) {
        if self.c_record_store.is_some() {
            info!(
                "{}: {:6} closed connections",
                self.pipeline_id,
                self.c_record_store.as_ref().unwrap().borrow().len()
            );
            self.c_record_store
                .as_ref()
                .unwrap()
                .borrow()
                .iter()
                .enumerate()
                .for_each(|(i, c)| debug!("{:6}: {}", i, c));
            info!(
                "{}: {:6} open connections",
                self.pipeline_id,
                self.port2con.iter().filter(|c| c.port() != 0).collect::<Vec<_>>().len()
            );
        }
        /*
        self.port2con.iter().enumerate().for_each(|(i, c)| {
            if c.port() != 0 {
                // info!("{:6}: {}", i, c.con_rec())
            }
        });
        */
    }

    pub fn fetch_c_records(&mut self) -> Option<RecordStore<ConRecord>> {
        // we are "moving" the con_records out, and replace it with a new one
        if self.c_record_store.is_some() {
            let new_store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
            let store = mem::replace(self.c_record_store.as_mut().unwrap(), new_store);
            let strong_count = Rc::strong_count(&store);
            debug!("cm_s.fetch_c_records: strong_count= { }", strong_count);
            if strong_count > 1 {
                for c in &mut self.port2con {
                    c.release();
                }
            }
            let unwrapped = Rc::try_unwrap(store);
            if unwrapped.is_ok() {
                Some(unwrapped.unwrap().into_inner())
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn set_ready_connection(&mut self, port: u16, ready_flag: &Arc<AtomicBool>) {
        self.ready.push_back(port);
        // if this is the first ready connection, we restart the injector, avoid accessing Atomic unnecessarily
        if self.ready_connections() == 1 {
            ready_flag.store(true, Ordering::SeqCst);
        }
    }

    #[inline]
    pub fn ready_connections(&self) -> usize {
        self.ready.len()
    }

    #[inline]
    pub fn get_ready_connection(&mut self) -> Option<&mut Connection> {
        let mut port_result = None;
        while port_result.is_none() {
            match self.ready.pop_front() {
                Some(port) => {
                    let c = &self.port2con[(port - self.tcp_port_base) as usize];
                    //trace!("found ready connection {}", if c.in_use() { c.port() } else { 0 });
                    if c.in_use() && c.state() == TcpState::Established {
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
}

use netfcts::utils::Sock2Index as Sock2Index;
use std::cmp;

pub struct ConnectionManagerS {
    c_record_store: Option<Rc<RefCell<RecordStore<ConRecord>>>>,
    sock2index: Sock2Index,
    //sock2index: HashMap<(u32,u16), u16>,
    //sock2index: BTreeMap<(u32,u16), u16>,
    connections: Vec<Connection>,
    free_slots: VecDeque<usize>,
}

impl ConnectionManagerS {
    pub fn new(detailed_records: bool) -> ConnectionManagerS {
        let store = if detailed_records {
            Some(Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS))))
        } else {
            None
        };
        ConnectionManagerS {
            c_record_store: store,
            sock2index: Sock2Index::new(),
            //sock2index: HashMap::with_capacity(MAX_CONNECTIONS),
            //sock2index: BTreeMap::new(),
            connections: vec![Connection::new(); MAX_CONNECTIONS],
            free_slots: (1..MAX_CONNECTIONS).collect(), // we use index 0 to indicate unused slots
        }
    }

    #[inline]
    pub fn get_mut(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        let index = self.sock2index.get(sock);
        if index.is_some() {
            Some(&mut self.connections[*index.unwrap() as usize])
        } else {
            None
        }
    }

    #[inline]
    pub fn get_mut_or_insert(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        {
            let index = self.sock2index.get(sock);
            if index.is_some() {
                return Some(&mut self.connections[*index.unwrap() as usize]);
            }
        }
        // create
        self.insert(sock)
    }

    #[inline]
    pub fn insert(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        let index = self.free_slots.pop_front();
        if index.is_some() {
            self.sock2index.insert(*sock, index.unwrap() as u16);
            let c = &mut self.connections[index.unwrap()];
            if self.c_record_store.is_some() {
                c.initialize_with_details(
                    Some(*sock),
                    TcpRole::Server,
                    Rc::clone(&self.c_record_store.as_ref().unwrap()),
                );
            } else {
                c.initialize(Some(*sock), TcpRole::Server)
            }
            Some(c)
        } else {
            None // out of resources
        }
    }

    #[inline]
    pub fn release(&mut self, sock: &(u32, u16), wheel: &mut TimerWheel<(u32, u16)>) {
        let index = self.sock2index.remove(sock);
        if index.is_some() {
            let c = &mut self.connections[index.unwrap() as usize];
            if c.in_use() {
                self.free_slots.push_back(index.unwrap() as usize);
                //remove port from timer wheel by overwriting it
                let old = wheel.replace(c.wheel_slot_and_index, (0, 0));
                assert_eq!(old.unwrap(), *sock);
            }
            c.release();
            // we keep unused connection in port2con table
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<(u32, u16)>) {
        //trace!("cm server side: release_timeouts");
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut sock = drain.next();
                    while sock.is_some() {
                        let s = sock.unwrap();
                        if s.1 != 0 {
                            self.timeout(&s);
                        }
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
        // the borrow checker makes things a little bit cumbersome:
        let mut in_use = false;
        {
            let opt_c = self.get_mut(sock);
            if let Some(c) = opt_c {
                in_use = c.in_use();
                if in_use {
                    c.set_release_cause(ReleaseCause::Timeout);
                    c.push_state(TcpState::Closed);
                    c.release();
                }
            }
        }
        if in_use {
            let index = self.sock2index.remove(sock);
            self.free_slots.push_back(index.unwrap() as usize);
        }
    }

    pub fn fetch_c_records(&mut self) -> Option<RecordStore<ConRecord>> {
        if self.c_record_store.is_some() {
            // we are "moving" the con_records out, and replace it with a new one
            let new_store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
            let store = mem::replace(self.c_record_store.as_mut().unwrap(), new_store);
            let strong_count = Rc::strong_count(&store);
            debug!("cm_s.fetch_c_records: strong_count= { }", strong_count);
            if strong_count > 1 {
                for c in &mut self.connections {
                    c.release();
                }
            }
            let unwrapped = Rc::try_unwrap(store);
            if unwrapped.is_ok() {
                Some(unwrapped.unwrap().into_inner())
            } else {
                None
            }
        } else {
            None
        }
    }
}
