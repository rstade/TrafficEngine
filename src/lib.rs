#![feature(box_syntax)]
#![feature(integer_atomics)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate rand;
extern crate toml;
extern crate separator;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate ipnet;
extern crate uuid;
extern crate serde;
extern crate bincode;
extern crate serde_json;

#[macro_use]
extern crate error_chain;

pub mod nftraffic;
pub mod run_test;
pub use cmanager::{Connection, CData, L234Data, ReleaseCause, UserData, ConRecord, TcpRole, TcpState, TcpCounter, TcpControls};

pub mod errors;
mod cmanager;
mod timer_wheel;
mod tasks;

use ipnet::Ipv4Net;
use eui48::MacAddress;
use uuid::Uuid;
use separator::Separatable;

use e2d2::native::zcsi::*;
use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::interface::PortQueue;
use e2d2::interface::*;

use errors::*;
use nftraffic::*;
use tasks::*;

use std::fs::File;
use std::io::Read;
use std::any::Any;
use std::net::Ipv4Addr;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::ptr;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::RecvTimeoutError;
use std::fmt;
use std::str::FromStr;
use std::process::Command;

#[derive(Deserialize, Clone, Copy, PartialEq)]
pub enum FlowSteeringMode {
    Port,
    // default
    Ip,
}

#[derive(Deserialize)]
struct Config {
    trafficengine: Configuration,
}

#[derive(Deserialize, Clone)]
pub struct Configuration {
    pub targets: Vec<TargetConfig>,
    pub engine: EngineConfig,
    pub test_size: Option<usize>,
}


impl Configuration {
    pub fn flow_steering_mode(&self) -> FlowSteeringMode {
        self.engine.flow_steering.unwrap_or(FlowSteeringMode::Port)
    }
}

#[derive(Deserialize, Clone)]
pub struct EngineConfig {
    pub flow_steering: Option<FlowSteeringMode>,
    pub namespace: String,
    pub mac: String,
    pub ipnet: String,
    pub timeouts: Option<Timeouts>,
    pub port: u16,
}

impl EngineConfig {
    pub fn get_l234data(&self) -> L234Data {
        L234Data {
            mac: MacAddress::parse_str(&self.mac).unwrap(),
            ip: u32::from(self.ipnet.parse::<Ipv4Net>().unwrap().addr()),
            port: self.port,
            server_id: "Engine".to_string(),
            index: 0,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct TargetConfig {
    pub id: String,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddress>,
    pub linux_if: Option<String>,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct Timeouts {
    established: Option<u64>, // in millis
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts { established: Some(200) }
    }
}

impl Timeouts {
    pub fn default_or_some(timeouts: &Option<Timeouts>) -> Timeouts {
        let mut t = Timeouts::default();
        if timeouts.is_some() {
            let timeouts = timeouts.clone().unwrap();
            if timeouts.established.is_some() {
                t.established = timeouts.established;
            }
        }
        t
    }
}

pub fn read_config(filename: &str) -> Result<Configuration> {
    let mut toml_str = String::new();
    let _ = File::open(filename)
        .and_then(|mut f| f.read_to_string(&mut toml_str))
        .chain_err(|| E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)))?;

    info!("toml configuration:\n {}", toml_str);

    let config: Config = match toml::from_str(&toml_str) {
        Ok(value) => value,
        Err(err) => return Err(err.into()),
    };

    match config.trafficengine.engine.ipnet.parse::<Ipv4Net>() {
        Ok(_) => match config.trafficengine.engine.mac.parse::<MacAddress>() {
            Ok(_) => Ok(config.trafficengine),
            Err(e) => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

struct MyData {
    c2s_count: usize,
    s2c_count: usize,
    avg_latency: f64,
}

impl MyData {
    fn new() -> MyData {
        MyData {
            c2s_count: 0,
            s2c_count: 0,
            avg_latency: 0.0f64,
        }
    }

    fn init(&mut self) {
        self.c2s_count = 0;
        self.s2c_count = 0;
        self.avg_latency = 0.0f64;
    }
}

// using the container makes compiler happy wrt. to static lifetime for the mydata content
pub struct Container {
    mydata: MyData,
}

impl UserData for Container {
    #[inline]
    fn ref_userdata(&self) -> &Any {
        &self.mydata
    }

    fn mut_userdata(&mut self) -> &mut Any {
        &mut self.mydata
    }

    fn init(&mut self) {
        self.mydata.init();
    }
}

impl Container {
    pub fn new() -> Box<Container> {
        Box::new(Container { mydata: MyData::new() })
    }
}

pub fn get_mac_from_ifname(ifname: &str) -> Result<MacAddress> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    fs::File::open(iface).map_err(|e| e.into()).and_then(|mut f| {
        f.read_to_string(&mut macaddr)
            .map_err(|e| e.into())
            .and_then(|_| MacAddress::parse_str(&macaddr.lines().next().unwrap_or("")).map_err(|e| e.into()))
    })
}

pub fn get_mac_string_from_ifname(ifname: &str) -> Result<String> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    fs::File::open(iface).map_err(|e| e.into()).and_then(|mut f| {
        f.read_to_string(&mut macaddr)
            .map_err(|e| e.into())
            .and_then(|_| Ok(macaddr.lines().next().unwrap_or("").to_string()))
    })
}

pub fn print_hard_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_soft_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_xstatistics(port_id: u16) -> i32 {
    let len;
    unsafe {
        len = rte_eth_xstats_get_names_by_id(port_id, ptr::null(), 0, ptr::null());
        if len < 0 {
            return len;
        }
        let xstats_names = vec![
            RteEthXstatName {
                name: [0; RTE_ETH_XSTATS_NAME_SIZE],
            };
            len as usize
        ];
        let ids = vec![0u64; len as usize];
        if len != rte_eth_xstats_get_names_by_id(port_id, xstats_names.as_ptr(), len as u32, ptr::null()) {
            return -1;
        };
        let values = vec![0u64; len as usize];

        if len != rte_eth_xstats_get_by_id(port_id, ptr::null(), values.as_ptr(), 0 as u32) {
            return -1;
        }

        for i in 0..len as usize {
            rte_eth_xstats_get_id_by_name(port_id, xstats_names[i].to_ptr(), &ids[i]);
            {
                println!("{}, {}: {}", i, xstats_names[i].to_str().unwrap(), values[i]);
            }
        }
    }
    len
}

pub fn setup_pipelines(
    core: i32,
    no_packets: usize,
    ports: HashSet<CacheAligned<PortQueue>>,
    sched: &mut StandaloneScheduler,
    engine_config: &EngineConfig,
    servers: Vec<L234Data>,
    flowdirector_map: HashMap<i32, Arc<FlowDirector>>,
    tx: Sender<MessageFrom>,
) {
    let mut kni: Option<&CacheAligned<PortQueue>> = None;
    let mut pci: Option<&CacheAligned<PortQueue>> = None;
    for port in &ports {
        debug!(
            "setup_pipeline on core {}: port {} --  {} rxq {} txq {}",
            core,
            port.port,
            port.port.mac_address(),
            port.rxq(),
            port.txq(),
        );
        if port.port.is_kni() {
            kni = Some(port);
        } else {
            pci = Some(port);
        }
    }

    if pci.is_none() {
        panic!("need at least one pci port");
    }

    // kni receive queue is served on the first core (i.e. rxq==0)

    if kni.is_none() && is_kni_core(pci.unwrap()) {
        // we need a kni i/f for queue 0
        panic!("need one kni port for queue 0");
    }

    let uuid = Uuid::new_v4();
    let name = String::from("KniHandleRequest");

    if is_kni_core(pci.unwrap()) {
        sched.add_runnable(
            Runnable::from_task(
                uuid,
                name,
                KniHandleRequest {
                    kni_port: kni.unwrap().port.clone(),
                    last_tick: 0,
                },
            ).move_ready(), // this task must be ready from the beginning to enable managing the KNI i/f
        );
    }

    setup_generator(
        core,
        no_packets,
        pci.unwrap(),
        kni.unwrap(),
        sched,
        engine_config,
        servers,
        flowdirector_map,
        tx
    );
}

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PipelineId {
    pub core: u16,
    pub port_id: u16,
    pub rxq: u16,
}

impl fmt::Display for PipelineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<c{}, p{}, rx{}>", self.core, self.port_id, self.rxq)
    }
}

#[derive(Debug)]
pub enum TaskType {
    TcpGenerator = 0,
    Pipe2Kni = 1,
    Pipe2Pci = 2,
    TickGenerator = 3,
    NoTaskTypes = 4, // for iteration over TaskType
}

pub enum MessageFrom {
    Channel(PipelineId, Sender<MessageTo>),
    Established(PipelineId, ConRecord),
    GenTimeStamp(PipelineId, &'static str, usize, u64, u64),
    StartEngine(Sender<MessageTo>),
    Task(PipelineId, Uuid, TaskType),
    PrintPerformance(Vec<i32>), // performance of tasks on cores selected by indices
    Counter(PipelineId, TcpCounter, TcpCounter),
    CRecords(PipelineId, Vec<ConRecord>, Vec<ConRecord>), // pipeline_id, client, server
    FetchCounter, // triggers fetching of counters from pipelines
    FetchCRecords,
    Exit, // exit recv thread
}

pub enum MessageTo {
    FetchCounter, // fetch counters from pipeline
    FetchCRecords,
    Counter(PipelineId, TcpCounter, TcpCounter),
    CRecords(PipelineId, Vec<ConRecord>, Vec<ConRecord>),
    StartGenerator,
    Exit, // exit recv thread
}


fn get_tcp_port_base(port: &PmdPort , count: u16) -> u16 {
    let port_mask = port.get_tcp_dst_port_mask();
    port_mask - count * (!port_mask + 1)
}


pub fn initialize_flowdirector(context:&NetBricksContext, configuration: &Configuration) -> HashMap<i32, Arc<FlowDirector>> {
    let mut fdir_map: HashMap<i32, Arc<FlowDirector>>= HashMap::new();
    for port in  context.ports.values() {
        if *port.port_type() == PortType::Dpdk {
            // initialize flow director on port, cannot do this in parallel from multiple threads
            let mut flowdir= FlowDirector::new(port.clone());
            let ip_address = &configuration.engine.ipnet;
            let ip_addr_first = Ipv4Net::from_str(ip_address).unwrap().addr();
            for (i, core) in context.active_cores.iter().enumerate() {
                match context.rx_queues.get(&core) {    // retrieve all rx queues for this core
                    Some(set) => match set.iter().last() {  // select one (should be the only one)
                        Some(queue) => {
                            match configuration.flow_steering_mode() {
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

pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_kni(kni_name: &str, configuration: &Configuration, ip_address_count: usize) {
    let ip_address=&configuration.engine.ipnet;
    let ip_addr_first= Ipv4Net::from_str(ip_address).unwrap().addr();
    let prefix_len= Ipv4Net::from_str(ip_address).unwrap().prefix_len();
    let mac_address = &configuration.engine.mac;
    let kni_netns= &configuration.engine.namespace;


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


pub fn spawn_recv_thread(mrx: Receiver<MessageFrom>, mut context: NetBricksContext, configuration: Configuration) {
    /*
        mrx: receiver for messages from all the pipelines running
    */
    let _handle = thread::spawn(move || {
        let mut senders = HashMap::new();
        let mut tasks: Vec<Vec<(PipelineId, Uuid)>> = Vec::with_capacity(TaskType::NoTaskTypes as usize);
        let mut start_tsc: HashMap<(PipelineId, &'static str), u64> = HashMap::new();
        let mut reply_to_main = None;

        let l234data: Vec<L234Data> = configuration
            .targets
            .iter()
            .enumerate()
            .map(|(i, srv_cfg)| L234Data {
                mac: srv_cfg
                    .mac
                    .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
                ip: u32::from(srv_cfg.ip),
                port: srv_cfg.port,
                server_id: srv_cfg.id.clone(),
                index: i,
            }).collect();

        for _t in 0..TaskType::NoTaskTypes as usize {
            tasks.push(Vec::<(PipelineId, Uuid)>::with_capacity(16));
        }
        // start execution of pipelines
        context.execute_schedulers();

        // set up kni: this requires the executable KniHandleRequest to run (serving rte_kni_handle_request)
        debug!("Number of PMD ports: {}", PmdPort::num_pmd_ports());
        for port in context.ports.values() {
            debug!(
                "port {}:{} -- mac_address= {}",
                port.port_type(),
                port.port_id(),
                port.mac_address()
            );
            if port.is_kni() {
                setup_kni(
                    port.linux_if().unwrap(),
                    &configuration,
                    if configuration.flow_steering_mode() == FlowSteeringMode::Ip { context.active_cores.len() +1 } else { 1 },
                );
            }
        }

        // communicate with schedulers:

        loop {
            match mrx.recv_timeout(Duration::from_millis(10)) {
                Ok(MessageFrom::Channel(pipeline_id, sender)) => {
                    debug!("got sender from {}", pipeline_id);
                    //sender.send(MessageTo::Hello).unwrap();  receiver not active currently, so we comment it out
                    senders.insert(pipeline_id, sender);
                }
                Ok(MessageFrom::PrintPerformance(indices)) => {
                    for i in &indices {
                        context
                            .scheduler_channels
                            .get(i)
                            .unwrap()
                            .send(SchedulerCommand::GetPerformance)
                            .unwrap();
                    }
                }
                Ok(MessageFrom::Exit) => {
                    // stop all tasks on all schedulers
                    for s in context.scheduler_channels.values() {
                        s.send(SchedulerCommand::SetTaskStateAll(false)).unwrap();
                    }

                    print_hard_statistics(1u16);

                    for port in context.ports.values() {
                        println!("Port {}:{}", port.port_type(), port.port_id());
                        port.print_soft_statistics();
                    }
                    println!("terminating TrafficEngine ...");
                    context.stop();
                    break;
                }
                Ok(MessageFrom::Established(pipe, con_record)) => {
                    info!(
                        // "pipe {}: Established -> {}, c-sock={},  s-setup = {:6} us",
                        "pipe {}: {} -> {} ",
                        pipe,
                        con_record,
                        l234data[con_record.server_index].server_id,
                    );
                }
                Ok(MessageFrom::StartEngine(reply_channel)) => {
                    debug!("starting generator tasks");
                    reply_to_main = Some(reply_channel);
                    for s in &context.scheduler_channels {
                        s.1.send(SchedulerCommand::SetTaskStateAll(true)).unwrap();
                    }
                }
                Ok(MessageFrom::Task(pipeline_id, uuid, task_type)) => {
                    debug!("{}: task uuid= {}, type={:?}", pipeline_id, uuid, task_type);
                    tasks[task_type as usize].push((pipeline_id, uuid));
                }
                Ok(MessageFrom::GenTimeStamp(pipeline_id, item, count, tsc0, tsc1)) => {
                    debug!(
                        "pipe {}: GenTimeStamp for item {} -> count= {}, tsc0= {}, tsc1= {}",
                        pipeline_id,
                        item,
                        count,
                        tsc0.separated_string(),
                        tsc1.separated_string(),
                    );
                    if count == 0 {
                        start_tsc.insert((pipeline_id, item), tsc0);
                    } else {
                        let diff = tsc0 - start_tsc.get(&(pipeline_id.clone(), item)).unwrap();
                        info!(
                            "pipe {}: item= {}, count= {}, elapsed= {} cy, per count= {} cy",
                            pipeline_id,
                            item,
                            count,
                            diff.separated_string(),
                            diff / count as u64,
                        );
                    };
                }
                Ok(MessageFrom::Counter(pipeline_id, tcp_counter_to, tcp_counter_from)) => {
                    debug!("{}: received Counter", pipeline_id);
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from))
                            .unwrap();
                    };
                }
                Ok(MessageFrom::FetchCounter) => {
                    for (_p, s) in &senders {
                        s.send(MessageTo::FetchCounter).unwrap();
                    }
                }
                Ok(MessageFrom::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server))
                            .unwrap();
                    };
                }
                Ok(MessageFrom::FetchCRecords) => {
                    for (_p, s) in &senders {
                        s.send(MessageTo::FetchCRecords).unwrap();
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("error receiving from MessageFrom channel: {}", e);
                    break;
                }
            };
            match context.reply_receiver.as_ref().unwrap().recv_timeout(Duration::from_millis(10)) {
                Ok(SchedulerReply::PerformanceData(core, map)) => {
                    for d in map {
                        info!(
                            "{:2}: {:20} {:>15} count= {:12}",
                            core,
                            (d.1).0,
                            (d.1).1.separated_string(),
                            (d.1).2.separated_string(),
                        )
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("error receiving from SchedulerReply channel: {}", e);
                    break;
                }
            }
        }
        info!("exiting recv thread ...");
    });
}
