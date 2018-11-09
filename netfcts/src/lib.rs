extern crate uuid;
extern crate eui48;
extern crate e2d2;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate ipnet;
extern crate separator;

pub mod tcp_common;
pub mod tasks;
pub mod timer_wheel;
pub mod comm;

use std::process::Command;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;

use ipnet::Ipv4Net;
use uuid::Uuid;
use separator::Separatable;

use e2d2::allocators::CacheAligned;
use e2d2::interface::{PortQueue, FlowDirector, PortType, PmdPort};
use e2d2::scheduler::NetBricksContext;
use e2d2::utils;

use tcp_common::{TcpRole, TcpState, ReleaseCause};


#[derive(Clone)]
pub struct ConRecord {
    pub role: TcpRole,
    pub port: u16,
    pub sock: Option<SocketAddrV4>,
    pub uuid: Option<Uuid>,
    state_count: usize,
    state: [TcpState; 8],
    stamps: [u64; 8],
    pub payload_packets: usize,
    pub server_index: usize,
    release_cause: ReleaseCause,
}

impl ConRecord {
    #[inline]
    pub fn init(&mut self, role: TcpRole, port: u16, sock: Option<&SocketAddrV4>) {
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
        if self.role == TcpRole::Client { self.uuid= Some(Uuid::new_v4()); } // server connections get the uuid from associated client connection if any
    }

    #[inline]
    pub fn released(&mut self, cause: ReleaseCause) {
        self.release_cause = cause;
    }

    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    pub fn new() -> ConRecord {
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
            uuid: None,
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
    pub fn get_stamp(&self, i: usize) -> Option<u64> {
        if i < self.state_count && i > 0 { Some(self.stamps[i]) } else { None }
    }

    #[inline]
    pub fn get_last_stamp(&self) -> Option<u64> {
        if self.state_count > 1 { Some(self.stamps[self.state_count-1]) } else { None }
    }

    #[inline]
    pub fn get_first_stamp(&self) -> Option<u64> {
        if self.state_count > 1 { Some(self.stamps[1]) } else { None }
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


pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_kni(kni_name: &str, ip_net: &Ipv4Net, mac_address: &String, kni_netns: &String, ip_address_count: usize) {
    let ip_addr_first= ip_net.addr();
    let prefix_len= ip_net.prefix_len();


    debug!("setup_kni");
    //# ip link set dev vEth1 address XX:XX:XX:XX:XX:XX
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "address", mac_address])
        .output()
        .expect("failed to assign MAC address to kni i/f");
    let reply = output.stderr;

    debug!(
        "assigning MAC addr {} to {}: {}, {}",
        mac_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    //# ip netns add nskni
    let output = Command::new("ip")
        .args(&["netns", "add", kni_netns])
        .output()
        .expect("failed to create namespace for kni i/f");
    let reply = output.stderr;

    debug!(
        "creating network namespace {}: {}, {}",
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // ip link set dev vEth1 netns nskni
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "netns", kni_netns])
        .output()
        .expect("failed to move kni i/f to namespace");
    let reply = output.stderr;

    debug!(
        "moving kni i/f {} to namesapce {}: {}, {}",
        kni_name,
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );
    for i in 0..ip_address_count {
        // e.g. ip netns exec nskni ip addr add w.x.y.z/24 dev vEth1
        let ip_net = Ipv4Net::new(Ipv4Addr::from(u32::from(ip_addr_first) + i as u32), prefix_len).unwrap().to_string();
        let output = Command::new("ip")
            .args(&["netns", "exec", kni_netns, "ip", "addr", "add", &ip_net, "dev", kni_name])
            .output()
            .expect("failed to assign IP address to kni i/f");
        let reply = output.stderr;
        debug!(
            "assigning IP addr {} to {}: {}, {}",
            ip_net,
            kni_name,
            output.status,
            String::from_utf8_lossy(&reply)
        );
    }
    // e.g. ip netns exec nskni ip link set dev vEth1 up
    let output1 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "link", "set", "dev", kni_name, "up"])
        .output()
        .expect("failed to set kni i/f up");
    let reply1 = output1.stderr;
    debug!(
        "ip netns exec {} ip link set dev {} up: {}, {}",
        kni_netns,
        kni_name,
        output1.status,
        String::from_utf8_lossy(&reply1)
    );
    // e.g. ip netns exec nskni ip addr show dev vEth1
    let output2 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "addr", "show", "dev", kni_name])
        .output()
        .expect("failed to show IP address of kni i/f");
    let reply2 = output2.stdout;
    info!("show IP addr: {}\n {}", output.status, String::from_utf8_lossy(&reply2));
}


#[derive(Deserialize, Clone, Copy, PartialEq)]
pub enum FlowSteeringMode {
    Port,
    // default
    Ip,
}

fn get_tcp_port_base(port: &PmdPort , count: u16) -> u16 {
    let port_mask = port.get_tcp_dst_port_mask();
    port_mask - count * (!port_mask + 1)
}


pub fn initialize_flowdirector(context:&NetBricksContext, steering_mode: FlowSteeringMode, ipnet: &Ipv4Net) -> HashMap<i32, Arc<FlowDirector>> {
    let mut fdir_map: HashMap<i32, Arc<FlowDirector>>= HashMap::new();
    for port in  context.ports.values() {
        if *port.port_type() == PortType::Dpdk {
            // initialize flow director on port, cannot do this in parallel from multiple threads
            let mut flowdir= FlowDirector::new(port.clone());
            let ip_addr_first = ipnet.addr();
            for (i, core) in context.active_cores.iter().enumerate() {
                match context.rx_queues.get(&core) {    // retrieve all rx queues for this core
                    Some(set) => match set.iter().last() {  // select one (should be the only one)
                        Some(queue) => {
                            match steering_mode {
                                FlowSteeringMode::Ip => {
                                    let dst_ip= u32::from(ip_addr_first) + i as u32 +1;
                                    let dst_port = port.get_tcp_dst_port_mask();
                                    debug!("set fdir filter on port {} for rfs mode IP: queue= {}, ip= {}, port base = {}",
                                           port.port_id(),
                                           queue.rxq(),
                                           Ipv4Addr::from(dst_ip),
                                           dst_port,
                                    );
                                    flowdir.add_fdir_filter(
                                        queue.rxq(),
                                        dst_ip,
                                        dst_port,
                                    ).unwrap();
                                }
                                FlowSteeringMode::Port => {
                                    let dst_ip= u32::from(ip_addr_first);
                                    let dst_port= get_tcp_port_base(port, i as u16);
                                    debug!("set fdir filter on port {} for rfs mode Port: queue= {}, ip= {}, port base = {}",
                                           port.port_id(),
                                           queue.rxq(),
                                           Ipv4Addr::from(dst_ip),
                                           dst_port,
                                    );
                                    flowdir.add_fdir_filter(
                                        queue.rxq(),
                                        dst_ip,
                                        dst_port,
                                    ).unwrap();
                                }
                            }
                        }
                        None => (),
                    }
                    None => (),
                }
            }
            fdir_map.insert(port.port_id(), Arc::new(flowdir));
        }
    }
    fdir_map
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
