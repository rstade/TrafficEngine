use std::net::Ipv4Addr;
use std::collections::VecDeque;
//use std::collections::HashMap;
//use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;
use std::cell::RefCell;
use std::rc::Rc;

use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};

use netfcts::timer_wheel::TimerWheel;
use PipelineId;

use netfcts::tcp_common::*;
use netfcts::{RecordStore, ConRecord, ConRecordOperations, HasTcpState };
use netfcts::utils::shuffle_ports;

pub type TEngineStore = RecordStore<ConRecord>;

#[derive(Clone)]
pub struct Connection {
    con_rec: Option<usize>,
    store: Option<Rc<RefCell<TEngineStore>>>,
    pub wheel_slot_and_index: (u16, u16),
    /// next client side sequence no towards DUT
    pub seqn_nxt: u32,
    /// oldest unacknowledged sequence no
    pub seqn_una: u32,
    /// current ack no towards DUT (expected seqn)
    pub ackn_nxt: u32,
}

const ERR_NO_CON_RECORD: &str = "connection has no ConRecord";

impl Connection {
    #[inline]
    fn initialize(
        &mut self,
        sock: Option<(u32, u16)>,
        port: u16,
        role: TcpRole,
        store: Rc<RefCell<RecordStore<ConRecord>>>,
    ) {
        self.seqn_nxt = 0;
        self.seqn_una = 0;
        self.ackn_nxt = 0;
        self.wheel_slot_and_index = (0, 0);
        self.con_rec = Some(store.borrow_mut().get_unused_slot());
        self.store = Some(store);
        self.store
            .as_ref()
            .unwrap()
            .borrow_mut()
            .get_mut(self.con_rec())
            .unwrap()
            .init(role, port, sock);
    }

    #[inline]
    fn new() -> Connection {
        Connection {
            seqn_nxt: 0, //next seqn towards DUT
            seqn_una: 0, // acked by DUT
            ackn_nxt: 0, //next ackn towards DUT
            wheel_slot_and_index: (0, 0),
            con_rec: None,
            store: None,
        }
    }
}

impl ConRecordOperations<TEngineStore> for Connection {
    #[inline]
    fn store(&self) -> &Rc<RefCell<TEngineStore>> {
        self.store.as_ref().unwrap()
    }

    #[inline]
    fn con_rec(&self) -> usize {
        self.con_rec.expect(ERR_NO_CON_RECORD)
    }

    #[inline]
    fn release_conrec(&mut self) {
        //trace!("releasing con record on port {}", self.port());
        self.con_rec = None;
        self.store = None;
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.store.is_some()
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(s-port={}, {:?})",
            self.port(),
            self.store()
                .borrow_mut()
                .get_mut(self.con_rec.expect("connection has no ConRecord"))
                .unwrap()
                .states(),
            //self.con_rec().s_states(),
        )
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManagerC {
    c_record_store: Rc<RefCell<RecordStore<ConRecord>>>,
    free_ports: VecDeque<u16>,
    ready: VecDeque<u16>,
    /// min number of free ports
    min_free_ports: usize,
    // ports of connections with data to send and in state Established when enqueued
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>,
    // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tcp_port_base: u16,
    // e.g. used as a listen port, not assigned by create
    listen_port: u16,
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
        let store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let cm = ConnectionManagerC {
            c_record_store: store.clone(),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            // port 0 is reserved and not usable for us, ports are shuffled for better load sharing in DUTs
            // max_tcp_port itself is reserved for the server side for listening
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                //let vec = (if tcp_port_base == 0 { 1 } else { tcp_port_base }.. max_tcp_port - 1).collect();
                VecDeque::<u16>::from(vec)
            },
            ready: VecDeque::with_capacity(MAX_CONNECTIONS), // connections which became Established (but may not longer be)
            min_free_ports: !port_mask as usize + 1,
            pci,
            pipeline_id,
            tcp_port_base,
            listen_port: max_tcp_port,
            ip,
        };
        // we use the port max_tcp_port for returning traffic to us, do not add it to free_ports
        info!(
            "created ConnectionManager {} for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            if tcp_port_base == 0 { 1 } else { tcp_port_base },
            max_tcp_port - 1,
        );
        cm
    }

    #[inline]
    pub fn max_concurrent_connections(&self) -> usize {
        (!self.pci.port.get_tcp_dst_port_mask() - (if self.tcp_port_base == 0 { 1 } else { 0 })) as usize
            - self.min_free_ports
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
                let store = Rc::clone(&self.c_record_store);
                self.get_mut_con(&port).initialize(Some(sock), port, role, store);
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
                c.release_conrec();
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
            self.free_ports.push_front(port);
            c.release_conrec();
            //remove port from timer wheel by overwriting it
            let old = wheel.replace(c.wheel_slot_and_index, 0);
            assert_eq!(old.unwrap(), port);
            // we keep unused connection in port2con table
        }
    }

    #[allow(dead_code)]
    pub fn dump_records(&mut self) {
        info!(
            "{}: {:6} closed connections",
            self.pipeline_id,
            self.c_record_store.borrow().len()
        );
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

    pub fn fetch_c_records(&mut self) -> Option<RecordStore<ConRecord>> {
        // we are "moving" the con_records out, and replace it with a new one
        let new_store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let store = mem::replace(&mut self.c_record_store, new_store);
        let strong_count = Rc::strong_count(&store);
        debug!("cm_s.fetch_c_records: strong_count= { }", strong_count);
        if strong_count > 1 {
            for c in &mut self.port2con {
                c.release_conrec();
            }
        }
        let unwrapped = Rc::try_unwrap(store);
        if unwrapped.is_ok() {
            Some(unwrapped.unwrap().into_inner())
        } else {
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
                    trace!("found ready connection {}", if c.in_use() { c.port() } else { 0 });
                    if c.in_use() && c.last_state() == TcpState::Established {
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
    c_record_store: Rc<RefCell<RecordStore<ConRecord>>>,
    sock2index: Sock2Index,
    //sock2index: HashMap<(u32,u16), u16>,
    //sock2index: BTreeMap<(u32,u16), u16>,
    connections: Vec<Connection>,
    free_slots: VecDeque<usize>,
}

impl ConnectionManagerS {
    pub fn new() -> ConnectionManagerS {
        let store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        ConnectionManagerS {
            c_record_store: store.clone(),
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
            c.initialize(Some(*sock), 0, TcpRole::Server, Rc::clone(&self.c_record_store));
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
                self.free_slots.push_front(index.unwrap() as usize);
                //remove port from timer wheel by overwriting it
                let old = wheel.replace(c.wheel_slot_and_index, (0, 0));
                assert_eq!(old.unwrap(), *sock);
            }
            c.release_conrec();
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
                    c.release_conrec();
                }
            }
        }
        if in_use {
            let index = self.sock2index.remove(sock);
            self.free_slots.push_front(index.unwrap() as usize);
        }
    }

    pub fn fetch_c_records(&mut self) -> Option<RecordStore<ConRecord>> {
        // we are "moving" the con_records out, and replace it with a new one
        let new_store = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let store = mem::replace(&mut self.c_record_store, new_store);
        let strong_count = Rc::strong_count(&store);
        debug!("cm_s.fetch_c_records: strong_count= { }", strong_count);
        if strong_count > 1 {
            for c in &mut self.connections {
                c.release_conrec();
            }
        }
        let unwrapped = Rc::try_unwrap(store);
        if unwrapped.is_ok() {
            Some(unwrapped.unwrap().into_inner())
        } else {
            None
        }
    }
}
