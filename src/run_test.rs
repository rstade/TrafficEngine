extern crate ctrlc;
extern crate e2d2;
extern crate ipnet;
extern crate bincode;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::env;
use std::time::Duration;
use std::thread;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, Shutdown, Ipv4Addr};
use std::sync::mpsc::channel;
use std::sync::mpsc::RecvTimeoutError;
use std::collections::{HashSet, HashMap};
use std::io::{Read, Write, BufWriter};
use std::str::FromStr;
use std::error::Error;
use std::fs::File;
use std::vec::Vec;
use std::process;

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::{PortQueue, PortType};
use e2d2::scheduler::{initialize_system, NetBricksContext};
use e2d2::scheduler::StandaloneScheduler;
use e2d2::allocators::CacheAligned;

use ipnet::Ipv4Net;
use env_logger;
//use serde_json;
use separator::Separatable;
use netfcts::{initialize_flowdirector, FlowSteeringMode};
use uuid::Uuid;

use read_config;
use netfcts::system::get_mac_from_ifname;
use netfcts::io::print_counters;
use setup_pipelines;
use {CData, L234Data};
use {MessageFrom, MessageTo};
use spawn_recv_thread;
use netfcts::errors::*;
use log;
use ReleaseCause;
use {TcpState, TcpStatistics};

use netfcts::system::SystemData;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestType {
    Client,
    Server,
}

// we use this function for the integration tests
pub fn run_test(test_type: TestType) {
    env_logger::init();

    info!("Testing TrafficEngine in mode {:?} ..", test_type);
    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    let mut f = File::open("./tests/toml_file.txt").expect("file not found");
    let mut toml_file = String::new();
    f.read_to_string(&mut toml_file)
        .expect("something went wrong reading ./tests/toml_file.txt");

    let log_level_rte = if log_enabled!(log::Level::Debug) {
        RteLogLevel::RteLogDebug
    } else {
        RteLogLevel::RteLogInfo
    };
    unsafe {
        rte_log_set_global_level(log_level_rte);
        rte_log_set_level(RteLogtype::RteLogtypePmd, log_level_rte);
        info!("dpdk log global level: {}", rte_log_get_global_level());
        info!("dpdk log level for PMD: {}", rte_log_get_level(RteLogtype::RteLogtypePmd));
    }

    let system_data = SystemData::detect();

    let configuration = read_config(toml_file.trim()).unwrap();

    if configuration.test_size.is_none() {
        error!("missing parameter 'test_size' in configuration file {}", toml_file.trim());
        process::exit(1);
    };

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_e) => false,
        }
    }

    if !am_root() {
        error!(
            " ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\n\
             Do not run 'cargo test' as root."
        );
        process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    }).expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["proxyengine", "-f", toml_file.trim()]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut netbricks_configuration = read_matches(&matches, &opts);

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

    fn check_system(context: NetBricksContext) -> Result<NetBricksContext> {
        for port in context.ports.values() {
            if port.port_type() == &PortType::Dpdk {
                debug!("Supported filters on port {}:", port.port_id());
                for i in RteFilterType::RteEthFilterNone as i32 + 1..RteFilterType::RteEthFilterMax as i32 {
                    let result = unsafe { rte_eth_dev_filter_supported(port.port_id() as u16, RteFilterType::from(i)) };
                    debug!("{0: <30}: {1: >5}", RteFilterType::from(i), result);
                }
            }
        }
        Ok(context)
    }

    match initialize_system(&mut netbricks_configuration)
        .map_err(|e| e.into())
        .and_then(|ctxt| check_system(ctxt))
    {
        Ok(mut context) => {
            let flowdirector_map = initialize_flowdirector(
                &context,
                configuration.flow_steering_mode(),
                &Ipv4Net::from_str(&configuration.engine.ipnet).unwrap(),
            );
            unsafe {
                fdir_get_infos(1u16);
            }
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let configuration_cloned = configuration.clone();
            let mtx_clone = mtx.clone();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        configuration_cloned.test_size.unwrap(),
                        p,
                        s,
                        &configuration_cloned.engine,
                        l234data.clone(),
                        flowdirector_map.clone(),
                        mtx_clone.clone(),
                        system_data.clone(),
                    );
                },
            ));

            // this is quick and dirty and just for testing purposes:
            let port_mask = u16::from_be(netbricks_configuration.ports[0].fdir_conf.unwrap().mask.dst_port_mask);
            let rx_queues = context.rx_queues.len() as u16;
            let rfs_mode = configuration.flow_steering_mode();
            let cores = context.active_cores.clone();
            debug!("rx_queues = { }, port mask = 0x{:x}", rx_queues, port_mask);

            // start the controller
            spawn_recv_thread(mrx, context, configuration.clone());

            // give threads some time to do initialization work
            thread::sleep(Duration::from_millis(1000 as u64));

            if test_type == TestType::Client {
                // set up servers
                for server in configuration.targets {
                    let target_port = server.port; // moved into thread
                    let target_ip = server.ip;
                    let id = server.id;
                    thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
                        Ok(listener1) => {
                            debug!("bound server {} to {}:{}", id, target_ip, target_port);
                            for stream in listener1.incoming() {
                                let mut stream = stream.unwrap();
                                let mut buffer = [0u8; 256];
                                debug!("{} received connection from: {}", id, stream.peer_addr().unwrap());
                                let nr_bytes = stream
                                    .read(&mut buffer[..])
                                    .expect(&format!("cannot read from stream {}", stream.peer_addr().unwrap()));
                                let cdata: CData =
                                    bincode::deserialize(&buffer[0..nr_bytes]).expect("cannot deserialize cdata");
                                //serde_json::from_slice(&buffer[0..nr_bytes]).expect("cannot deserialize CData");
                                //let socket=Box::new(bincode::deserialize::<SocketAddrV4>(&buffer).expect("cannot deserialize SocketAddrV4"));
                                debug!("{} received {:?} from: {}", id, cdata, stream.peer_addr().unwrap())
                            }
                        }
                        _ => {
                            panic!("failed to bind server {} to {}:{}", id, target_ip, target_port);
                        }
                    });
                }

                thread::sleep(Duration::from_millis(1000 as u64)); // wait for the servers
            }
            // start generator
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();
            thread::sleep(Duration::from_millis(1000 as u64));

            if test_type == TestType::Server {
                let timeout = Duration::from_millis(1000 as u64);
                for ntry in 0..configuration.test_size.unwrap() as u16 {
                    let mut target_socket;
                    if rfs_mode == FlowSteeringMode::Port {
                        let target_port = 0xFFFF - (!port_mask + 1) * (ntry % rx_queues);
                        target_socket =
                            SocketAddr::from((configuration.engine.ipnet.parse::<Ipv4Net>().unwrap().addr(), target_port));
                        debug!("try {}: connecting to port 0x{:x}", ntry, target_port);
                    } else {
                        let target_ip = Ipv4Addr::from(
                            u32::from(configuration.engine.ipnet.parse::<Ipv4Net>().unwrap().addr())
                                + (ntry % rx_queues) as u32
                                + 1,
                        );
                        target_socket = SocketAddr::from((target_ip, 0xFFFF));
                    }

                    match TcpStream::connect_timeout(&target_socket, timeout) {
                        Ok(mut stream) => {
                            debug!("test connection {}: TCP connect to engine successful", ntry);
                            stream.set_write_timeout(Some(timeout)).unwrap();
                            stream.set_read_timeout(Some(timeout)).unwrap();
                            let cdata = CData::new(
                                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080),
                                0xFFFF,
                                Some(Uuid::new_v4()),
                            );
                            //let json_string = serde_json::to_string(&cdata).expect("cannot serialize cdata");
                            //stream.write(json_string.as_bytes()).expect("cannot write to stream");
                            let bin_vec = bincode::serialize(&cdata).expect("cannot serialize cdata");
                            stream.write(&bin_vec).expect("cannot write to stream");
                            match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                                Ok(_) => {
                                    debug!("successfully send {} stars", ntry);
                                    /* let mut buf = [0u8; 256];
                                            match stream.read(&mut buf[..]) {
                                                Ok(_) => {
                                                    info!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap())
                                                }
                                                _ => {
                                                    panic!("timeout on connection {} while waiting for answer", ntry);
                                                }
                                            };
                                            */
                                }
                                _ => {
                                    panic!("error when writing to test connection {}", ntry);
                                }
                            }
                            stream.shutdown(Shutdown::Both).unwrap();
                        }
                        _ => {
                            panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(1000 as u64));
            mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
            thread::sleep(Duration::from_millis(100 as u64));
            //main loop
                /* println!("press ctrl-c to terminate proxy ...");
                while running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                }
                */
            mtx.send(MessageFrom::FetchCounter).unwrap();
            mtx.send(MessageFrom::FetchCRecords).unwrap();

            let mut tcp_counters_to = HashMap::new();
            let mut tcp_counters_from = HashMap::new();
            let mut con_records = HashMap::new();

            loop {
                match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, rx_tx_stats)) => {
                        print_counters(&pipeline_id, &tcp_counter_to, &tcp_counter_from, &rx_tx_stats);
                        tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                        tcp_counters_from.insert(pipeline_id, tcp_counter_from);
                    }
                    Ok(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                        con_records.insert(pipeline_id, (c_records_client, c_records_server));
                    }
                    Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
                    Err(RecvTimeoutError::Timeout) => {
                        break;
                    }
                    Err(e) => {
                        error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                        break;
                    }
                }
            }

            let mut file = match File::create("c_records.txt") {
                Err(why) => panic!("couldn't create c_records.txt: {}", why.description()),
                Ok(file) => file,
            };
            let mut f = BufWriter::new(file);

            if test_type == TestType::Server {
                for (p, (_, c_records)) in &con_records {
                    debug!("Pipeline {}:", p);
                    if c_records.len() > 0 {
                        let mut completed_count = 0;
                        let mut min = c_records.iter().last().unwrap();
                        let mut max = min;
                        c_records.iter().enumerate().for_each(|(i, c)| {
                            let line = format!("{:6}: {}\n", i, c);
                            f.write_all(line.as_bytes()).expect("cannot write c_records");
                            if c.get_release_cause() == ReleaseCause::ActiveClose
                                && c.states().last().unwrap() == &TcpState::Closed
                            {
                                completed_count += 1
                            }
                            if c.get_first_stamp().unwrap_or(u64::max_value())
                                < min.get_first_stamp().unwrap_or(u64::max_value())
                            {
                                min = c
                            }
                            if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                                max = c
                            }
                            if i == (c_records.len() - 1)
                                && min.get_first_stamp().is_some()
                                && max.get_last_stamp().is_some()
                            {
                                let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                                info!(
                                    "total used cycles= {}, per connection = {}",
                                    total.separated_string(),
                                    (total / (i as u64 + 1)).separated_string()
                                );
                            }
                        });
                        assert_eq!(completed_count, tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn]);
                        assert_eq!(
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn],
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck]
                        );
                        assert_eq!(
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck],
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSynAck2]
                        );
                        assert_eq!(
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFin],
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFinAck]
                        );
                        assert_eq!(
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFinAck],
                            tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFinAck2]
                        );
                    }
                }
            }
            if test_type == TestType::Client {
                for (p, (c_records, _)) in &con_records {
                    let mut completed_count = 0;
                    info!("Pipeline {}:", p);
                    f.write_all(format!("Pipeline {}:", p).as_bytes())
                        .expect("cannot write c_records");
                    c_records.iter().enumerate().for_each(|(i, c)| {
                        let line = format!("{:6}: {}\n", i, c);
                        f.write_all(line.as_bytes()).expect("cannot write c_records");
                        if c.get_release_cause() == ReleaseCause::PassiveClose
                            && c.states().last().unwrap() == &TcpState::Closed
                        {
                            completed_count += 1
                        };
                    });
                    assert_eq!(completed_count, tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSyn]);
                }
            }

            f.flush().expect("cannot flush BufWriter");

            mtx.send(MessageFrom::Exit).unwrap();
            thread::sleep(Duration::from_millis(2000));

            debug!("terminating TrafficEngine");
            process::exit(0);
        }
        Err(ref e) => {
            error!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                debug!("Backtrace: {:?}", backtrace);
            }
            process::exit(1);
        }
    }
}
