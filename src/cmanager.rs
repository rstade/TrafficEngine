use std::time::{Duration, Instant};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::any::Any;
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue};

use eui48::MacAddress;
use {MessageFrom, PipelineId};
use timer_wheel::TimerWheel;
use {Configuration, Timeouts};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    FinWait,
    LastAck,
    Closed,
}

#[derive(Debug, Clone)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
    pub server_id: String,
}

pub trait UserData: Send + Sync + 'static {
    fn ref_userdata(&self) -> &Any;
    fn mut_userdata(&mut self) -> &mut Any;
    fn init(&mut self);
}

#[derive(Clone, Copy, Debug)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    FinClient = 2,
    FinServer = 3,
    RstServer = 4,
    MaxCauses = 5,
}

#[derive(Clone)]
pub struct ConRecord {
    pub p_port: u16,
    pub client_sock: SocketAddrV4,
    pub pipeline_id: PipelineId,
    /// timestamp of SYN
    pub c_syn_recv: Instant,
    /// timestamp of client Ack in 3way handshake
    pub c_ack_recv: Instant,
    /// timestamp of SYN towards server in 3way handshake
    pub s_syn_sent: Instant,
    /// timestamp of Ack towards server in 3way handshake
    pub s_ack_sent: Instant,
    /// holding time
    pub con_hold: Duration,
    pub c_state: TcpState,
    pub s_state: TcpState,
    pub server_id: String,
    release_cause: ReleaseCause,
}

impl ConRecord {
    fn init(&mut self, proxy_sport: u16, client_sock: SocketAddrV4) {
        self.c_syn_recv = Instant::now();
        self.c_ack_recv = self.c_syn_recv;
        self.s_syn_sent = self.c_syn_recv;
        self.s_ack_sent = self.c_syn_recv;
        self.p_port = proxy_sport;
        self.client_sock = client_sock;
        self.c_state = TcpState::Listen;
        self.s_state = TcpState::Closed;
        self.server_id.clear();
    }
    #[inline]
    pub fn c_released(&mut self, cause: ReleaseCause) {
        self.con_hold = self.c_syn_recv.elapsed();
        self.release_cause = cause;
    }
    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    fn new(pipeline_id: PipelineId) -> ConRecord {
        ConRecord {
            client_sock: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            c_syn_recv: Instant::now(),
            c_ack_recv: Instant::now(),
            s_syn_sent: Instant::now(),
            s_ack_sent: Instant::now(),
            con_hold: Duration::default(),
            c_state: TcpState::Listen,
            s_state: TcpState::Closed,
            server_id: String::new(),
            release_cause: ReleaseCause::Unknown,
            p_port: 0u16,
            pipeline_id,
        }
    }
}

pub struct Connection {
    pub payload: Box<Vec<u8>>,
    pub server: Option<L234Data>,
    pub userdata: Option<Box<UserData>>,
    //Box makes the trait object sizeable
    pub client_mac: MacHeader,
    pub con_rec: ConRecord,
    /// c_seqn is seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    pub c_seqn: u32,
    /// number of bytes inserted by proxy in connection from client to server
    pub c2s_inserted_bytes: usize,
}

impl Connection {
    fn initialize(&mut self, client_sock: SocketAddrV4, proxy_sport: u16) {
        self.payload.clear();
        self.server = None;
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_seqn = 0;
        self.c2s_inserted_bytes = 0;
        self.con_rec.init(proxy_sport, client_sock);
    }

    fn new(pipeline_id: PipelineId) -> Connection {
        Connection {
            payload: Box::new(Vec::with_capacity(1500)),
            server: None,
            userdata: None,
            client_mac: MacHeader::default(),
            c_seqn: 0,
            c2s_inserted_bytes: 0,
            con_rec: ConRecord::new(pipeline_id),
        }
    }

    #[inline]
    pub fn client_con_established(&mut self) {
        self.con_rec.c_state = TcpState::Established;
        self.con_rec.c_ack_recv = Instant::now();
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.con_rec.s_state = TcpState::SynReceived;
        self.con_rec.s_syn_sent = Instant::now();
    }

    #[inline]
    pub fn server_con_established(&mut self) {
        self.con_rec.s_state = TcpState::Established;
        self.con_rec.s_ack_sent = Instant::now();
    }

    #[inline]
    pub fn p_port(&self) -> u16 {
        self.con_rec.p_port
    }

    #[inline]
    pub fn set_p_port(&mut self, port: u16) {
        self.con_rec.p_port = port;
    }

    #[inline]
    pub fn get_client_sock(&self) -> &SocketAddrV4 {
        &self.con_rec.client_sock
    }

    #[inline]
    pub fn set_client_sock(&mut self, client_sock: SocketAddrV4) {
        self.con_rec.client_sock = client_sock;
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(s-port={}, {:?}/{:?})",
            self.p_port(),
            self.con_rec.c_state,
            self.con_rec.s_state
        )
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Connection::new(self.con_rec.pipeline_id.clone())
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManager {
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    timeouts: Timeouts,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    me: L234Data,
    tcp_port_base: u16,
}

fn get_tcp_port_base_by_manager_count(pci: &CacheAligned<PortQueue>, count: u16) -> u16 {
    let port_mask = pci.port.get_tcp_dst_port_mask();
    debug!("port_mask= {}", port_mask);
    port_mask - count * (!port_mask + 1)
}

impl ConnectionManager {
    pub fn new(pipeline_id: PipelineId, pci: CacheAligned<PortQueue>, me: L234Data, me_config: Configuration) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let tcp_port_base: u16 = get_tcp_port_base_by_manager_count(&pci, old_manager_count);
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        // program the NIC to send all flows for our owned ports to our rx queue
        pci.port.add_fdir_filter(pci.rxq() as u16, me.ip, tcp_port_base).unwrap();
        let mut cm = ConnectionManager {
            port2con: vec![Connection::new(pipeline_id.clone()); (!port_mask + 1) as usize],
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            timeouts: Timeouts::default_or_some(&me_config.engine.timeouts),
            pci,
            me,
            tcp_port_base,
        };
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        //        cm.spawn_maintenance_thread();
        debug!(
            "created ConnectionManager {} for port {}, rxq {} and tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
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
    //fn tcp_port_mask(&self) -> u16 { self.tcp_port_mask }

    /*fn get(&self, key: &CKey) -> Option<&Connection> {
        match *key {
            CKey::Port(p) => {
                if self.owns_tcp_port(p) {
                    self.port2con.get(&p)
                } else {
                    None
                }
            }
            CKey::Socket(s) => {
                let port = self.sock2port.get(&s);
                if port.is_some() {
                    self.port2con.get(&port.unwrap())
                } else {
                    None
                }
            }
        }
    }
    */

    pub fn get_mut(&mut self, port: u16) -> Option<&mut Connection> {
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

    fn get_timeouts(&mut self, now: &Instant, wheel: &mut TimerWheel<u16>) -> Vec<u16> {
        let mut con_timeouts: Vec<u16> = Vec::new();
        let resolution = wheel.get_resolution();
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        //self.check_timeout(&port.unwrap());
                        let p = port.unwrap();
                        let timeout = self.timeouts.established.unwrap_or(200);
                        let c = self.get_mut_con(&p);
                        if *now - c.con_rec.c_syn_recv >= Duration::from_millis(timeout) - resolution {
                            if c.con_rec.s_state < TcpState::Established {
                                c.con_rec.c_released(ReleaseCause::Timeout);
                                con_timeouts.push(p);
                            }
                        } else {
                            warn!(
                                "incomplete timeout: s_state = {:?}, syn_received = {:?}, now ={:?}",
                                c.con_rec.s_state, c.con_rec.c_syn_recv, now,
                            );
                        }
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
        con_timeouts
    }

    // create a new connection, if out of resources return None
    pub fn create(&mut self, wheel: &mut TimerWheel<u16>) -> Option<&mut Connection> {
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            let now;
            {
                let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
                assert_eq!(cc.p_port(), 0);
                let s = SocketAddrV4::new(Ipv4Addr::from(self.me.ip), port);
                cc.initialize(s, port);
                now = cc.con_rec.c_syn_recv;
                debug!("tcp flow created on port {:?}", port);
            }
            let port_vec = self.get_timeouts(&now, wheel);
            if self.timeouts.established.unwrap() < wheel.get_max_timeout_millis() {
                wheel.schedule(&(now + Duration::from_millis(self.timeouts.established.unwrap())), port);
            }
            self.release_ports(port_vec);
            Some(self.get_mut_con(&port))
        } else {
            warn!("out of ports");
            None
        }
    }

    pub fn release_port(&mut self, proxy_port: u16) -> Option<ConRecord> {
        let c = &mut self.port2con[(proxy_port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.p_port() != 0 {
            let con_rec = c.con_rec.clone();
            self.free_ports.push_back(proxy_port);
            assert_eq!(proxy_port, c.p_port());
            c.set_p_port(0u16); // this indicates an unused connection,
                                // we keep unused connection in port2con table
            Some(con_rec)
        } else {
            None
        }
    }

    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            self.release_port(*p);
        });
    }

    pub fn send_all_c_records(&self, tx: &Sender<MessageFrom>) {
        for c in &self.port2con {
            if c.p_port() != 0 {
                tx.send(MessageFrom::CRecord(c.con_rec.clone())).unwrap();
            }
        }
    }
}

/*

impl Drop for ConnectionManager {
    fn drop(&mut self) { self.send_all_c_records(); }
}
*/
