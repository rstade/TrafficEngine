extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
extern crate eui48;
extern crate ipnet;
extern crate separator;
extern crate netfcts;
extern crate bincode;

// Logging
#[macro_use]
extern crate log;
extern crate traffic_lib;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PortType, PmdPort, Pdu, HeaderStack};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{NetBricksContext, StandaloneScheduler, initialize_system};
use e2d2::utils;

use netfcts::initialize_flowdirector;
use netfcts::comm::{MessageFrom, MessageTo};
use netfcts::comm::PipelineId;
use netfcts::system::SystemData;
use netfcts::system::get_mac_from_ifname;
use netfcts::io::print_tcp_counters;
use netfcts::{ConRecord, HasTcpState, HasConData};
#[cfg(feature = "profiling")]
use netfcts::io::print_rx_tx_counters;
use netfcts::tcp_common::{CData, tcp_payload_size};
use netfcts::strip_payload;

use traffic_lib::{read_config, setup_pipelines, Connection};

use traffic_lib::L234Data;
use traffic_lib::spawn_recv_thread;
use traffic_lib::ReleaseCause;
use traffic_lib::TcpState;
use traffic_lib::TEngineStore;

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::str::FromStr;
use std::io::{Write, BufWriter};
use std::error::Error;
use std::fs::File;
use std::net::{SocketAddrV4, Ipv4Addr};
use std::mem;
use std::cmp;

use bincode::serialize_into;
use separator::Separatable;
use ipnet::Ipv4Net;


pub fn main() {
    env_logger::init();
    info!("Starting TrafficEngine ..");

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

    // read config file name from command line
    let args: Vec<String> = env::args().collect();
    let config_file;
    if args.len() > 1 {
        config_file = args[1].clone();
    } else {
        println!("try 'trafficengine <toml configuration file>'\n");
        std::process::exit(1);
    }

    let configuration = read_config(&config_file).unwrap();

    // number of payloads sent, after which the connection is closed
    let fin_by_client = configuration.engine.fin_by_client.unwrap_or(1000);
    let _fin_by_server = configuration.engine.fin_by_server.unwrap_or(1);

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
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
        .expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["trafficengine", "-f", &config_file]
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
        })
        .collect();

    fn check_system(context: NetBricksContext) -> e2d2::common::Result<NetBricksContext> {
        for port in context.ports.values() {
            if port.port_type() == &PortType::Dpdk {
                debug!("Supported filters on port {}:", port.port_id());
                for i in RteFilterType::RteEthFilterNone as i32 + 1..RteFilterType::RteEthFilterMax as i32 {
                    let result = unsafe { rte_eth_dev_filter_supported(port.port_id() as u16, RteFilterType::from(i)) };
                    debug!(
                        "{:<50}: {}(rc={})",
                        RteFilterType::from(i),
                        if result == 0 { "supported" } else { "not supported" },
                        result
                    );
                }
            }
        }
        Ok(context)
    }

    let fin_by_client_clone = fin_by_client.clone();
    let f_set_payload = Box::new(
        move |p: &mut Pdu, c: &mut Connection, b_fin: &mut bool| {
            let pp = c.sent_payload_pkts();
            if pp < 1 {
                // this is the first payload packet sent by client, headers are already prepared with client and server addresses and ports
                let src_port = p.headers().tcp(2).src_port();
                let sz;
                let mut buf = [0u8; 16];
                {
                    let ip=p.headers_mut().ip_mut(1);
                    let sock = SocketAddrV4::new(Ipv4Addr::from(ip.src()), src_port);
                    let cdata = CData::new(&sock, c.port(), c.uid());
                    serialize_into(&mut buf[..], &cdata).expect("cannot serialize");
                    //let buf = serialize(&cdata).unwrap();
                    sz = buf.len();
                    let ip_sz = ip.length();
                    ip.set_length(ip_sz + sz as u16);
                }
                p.add_to_payload_tail(sz).expect("insufficient tail room");
                p.copy_payload_from_u8_slice(&buf, 2); // 2 -> tcp_payload
                return tcp_payload_size(p);
            } else if pp == fin_by_client_clone && c.state() < TcpState::CloseWait {
                strip_payload(p);
                *b_fin = true;
                return 0;
            } else if pp < fin_by_client_clone && c.state() < TcpState::CloseWait {
                strip_payload(p);
                let stamp = utils::rdtsc_unsafe();
                let buf = stamp.to_be_bytes();
                let ip_sz = p.headers().ip(1).length();
                p.add_to_payload_tail(buf.len()).expect("insufficient tail room for u64");
                p.headers_mut().ip_mut(1).set_length(ip_sz + buf.len() as u16);
                p.copy_payload_from_u8_slice(&buf, 2); // 2 -> tcp_payload
                return tcp_payload_size(p);
            }
            return 0;
        },
    );

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
                context.start_schedulers();

                let (mtx, mrx) = channel::<MessageFrom<TEngineStore>>();
                let (reply_mtx, reply_mrx) = channel::<MessageTo<TEngineStore>>();

                let config_cloned = configuration.clone();
                let system_data_cloned = system_data.clone();
                let mtx_clone = mtx.clone();
                let nr_connections = config_cloned.test_size.expect("please specify test_size");

                context.add_pipeline_to_run_tx_buffered(Box::new(
                    move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(
                            core,
                            nr_connections, // no of connections to generate per pipeline
                            pmd_ports,
                            s,
                            &config_cloned.engine,
                            l234data.clone(),
                            flowdirector_map.clone(),
                            mtx_clone.clone(),
                            system_data_cloned.clone(),
                            f_set_payload.clone(),
                        );
                    },
                ));

                let cores = context.active_cores.clone();

                // start the controller
                spawn_recv_thread(mrx, context, configuration.clone());

                // give threads some time to do initialization work
                thread::sleep(Duration::from_millis(1000 as u64));

                // start generator
                mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();

                //main loop
                println!("press ctrl-c to terminate TrafficEngine ...");
                while running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                }

                mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
                thread::sleep(Duration::from_millis(100 as u64));
                mtx.send(MessageFrom::FetchCounter).unwrap();
                if configuration.engine.detailed_records.unwrap_or(false) {
                    mtx.send(MessageFrom::FetchCRecords).unwrap();
                }

                let mut tcp_counters_to = HashMap::new();
                let mut tcp_counters_from = HashMap::new();
                let mut start_stop_stamps: HashMap<PipelineId, (u64, u64)> = HashMap::new();
                let mut con_records_s = Vec::with_capacity(64);
                let mut con_records_c = Vec::with_capacity(64);

                loop {
                    match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
                        Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, _rx_tx_stats)) => {
                            print_tcp_counters(&pipeline_id, &tcp_counter_to, &tcp_counter_from);
                            #[cfg(feature = "profiling")]
                                print_rx_tx_counters(&pipeline_id, &_rx_tx_stats.unwrap());
                            tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                            tcp_counters_from.insert(pipeline_id, tcp_counter_from);
                        }
                        Ok(MessageTo::CRecords(pipeline_id, Some(c_records_client), Some(c_records_server))) => {
                            con_records_c.push((pipeline_id.clone(), c_records_client));
                            con_records_s.push((pipeline_id, c_records_server));
                        }
                        Ok(MessageTo::TimeStamps(p, t_start, t_stop)) => {
                            start_stop_stamps.insert(p.clone(), (t_start, t_stop));
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

                info!(
                    "Connection record sizes = {} + {}",
                    mem::size_of::<Connection>(),
                    mem::size_of::<ConRecord>()
                );

                info!(
                    "Pdu size = {}, HeaderStack size = {}",
                    mem::size_of::<Pdu>(),
                    mem::size_of::<HeaderStack>(),
                );

                if start_stop_stamps.len() > 0 {
                    println!("\nperformance data derived from time stamps sent by pipelines:");
                    let mut min_t: u64 = 0;
                    let mut max_t: u64 = 0;
                    for (p, (t_start, t_stop)) in &start_stop_stamps {
                        if min_t == 0 {
                            min_t = *t_start
                        } else {
                            min_t = cmp::min(min_t, *t_start)
                        }
                        if max_t == 0 {
                            max_t = *t_stop
                        } else {
                            max_t = cmp::max(max_t, *t_stop)
                        }
                        let per_connection = (*t_stop - *t_start) / nr_connections as u64;
                        let cps = system_data.cpu_clock / per_connection;
                        println!(
                            "{} cycles used= {}, per connection = {}, cps= {}",
                            p,
                            (t_stop - t_start).separated_string(),
                            per_connection,
                            cps
                        );
                    }

                    let stats = RteEthStats::new();
                    let retval;
                    unsafe {
                        retval = rte_eth_stats_get(1u16, &stats as *const RteEthStats);
                    }
                    if retval != 0 {
                        panic!("rte_eth_stats_get failed");
                    }

                    let per_connection = (max_t - min_t) / nr_connections as u64 / start_stop_stamps.len() as u64;
                    let per_packet = (max_t - min_t) / (stats.ipackets + stats.opackets) / start_stop_stamps.len() as u64;
                    println!(
                        "cyles over all pipes = {}, per connection = {}, cps = {}, pps= {}",
                        (max_t - min_t).separated_string(),
                        per_connection,
                        system_data.cpu_clock / per_connection,
                        system_data.cpu_clock / per_packet,
                    );
                }

                if configuration.engine.detailed_records.unwrap_or(false) {
                    println!("\nperformance data derived from connection records:");
                    let mut file = match File::create("c_records.txt") {
                        Err(why) => panic!("couldn't create c_records.txt: {}", why.description()),
                        Ok(file) => file,
                    };
                    let mut f = BufWriter::new(file);

                    //we are searching for the most extreme time stamps over all pipes
                    let mut min_total;
                    let mut max_total;
                    let mut total_connections = 0;
                    {
                        let cc = &(con_records_c[0].1);
                        min_total = cc.iter().last().unwrap().clone();
                        max_total = min_total.clone();
                    }

                    // a hash map of all server side records by uuid
                    let mut by_uuid = HashMap::with_capacity(con_records_s[0].1.len() * con_records_s.len());
                    let mut completed_count_s = 0;
                    for (_p, c_records_server) in &mut con_records_s {
                        c_records_server.iter().enumerate().for_each(|(_i, c)| {
                            if c.release_cause() == ReleaseCause::ActiveClose && c.states().last().unwrap() == &TcpState::Closed
                            {
                                completed_count_s += 1
                            };
                            by_uuid.insert(c.uid(), c);
                        });
                    }

                    for (p, c_records_client) in &mut con_records_c {
                        f.write_all(format!("Pipeline {}:\n", p).as_bytes())
                            .expect("cannot write c_records");
                        let mut completed_count_c = 0;
                        c_records_client.sort_by(|a, b| a.port().cmp(&b.port()));
                        if c_records_client.len() > 0 {
                            total_connections += c_records_client.len();
                            let mut min = c_records_client.iter().last().unwrap();
                            let mut max = min;
                            c_records_client.iter().enumerate().for_each(|(i, c)| {
                                let uuid = c.uid();
                                let c_server = by_uuid.remove(&uuid);
                                let line = format!("{:6}: {}\n", i, c);
                                f.write_all(line.as_bytes()).expect("cannot write c_records");
                                if c_server.is_some() {
                                    let c_server = c_server.unwrap();
                                    let line = format!(
                                        "        ({:?}, {:21}, {:6}, {:3}, {:7}, {:7}, {:?}, {:?}, +{}, {:?})\n",
                                        c_server.role(),
                                        if c_server.sock().0 != 0 {
                                            let s = c_server.sock();
                                            SocketAddrV4::new(Ipv4Addr::from(s.0), s.1).to_string()
                                        } else {
                                            "none".to_string()
                                        },
                                        c_server.port(),
                                        c_server.server_index(),
                                        c_server.sent_payload_packets(),
                                        c_server.recv_payload_packets(),
                                        c_server.states(),
                                        c_server.release_cause(),
                                        (c_server.get_first_stamp().unwrap() - c.get_first_stamp().unwrap()).separated_string(),
                                        c_server
                                            .deltas_to_base_stamp()
                                            .iter()
                                            .map(|u| u.separated_string())
                                            .collect::<Vec<_>>(),
                                    );
                                    f.write_all(line.as_bytes()).expect("cannot write c_records");
                                }
                                if (c.release_cause() == ReleaseCause::PassiveClose
                                    || c.release_cause() == ReleaseCause::ActiveClose)
                                    && c.states().last().unwrap() == &TcpState::Closed
                                {
                                    completed_count_c += 1
                                }
                                if c.get_first_stamp().unwrap_or(u64::max_value())
                                    < min.get_first_stamp().unwrap_or(u64::max_value())
                                {
                                    min = c
                                }
                                if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                                    max = c
                                }
                                if i == (c_records_client.len() - 1)
                                    && min.get_first_stamp().is_some()
                                    && max.get_last_stamp().is_some()
                                {
                                    let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                                    println!(
                                        "{} total used cycles = {}, per connection = {}",
                                        p,
                                        total.separated_string(),
                                        (total / (i as u64 + 1)).separated_string()
                                    );
                                }
                            });
                            if min.get_first_stamp().unwrap_or(u64::max_value())
                                < min_total.get_first_stamp().unwrap_or(u64::max_value())
                            {
                                min_total = min.clone()
                            }
                            if max.get_last_stamp().unwrap_or(0) > max_total.get_last_stamp().unwrap_or(0) {
                                max_total = max.clone()
                            }
                        }

                        println!("{} completed client connections = {}", p, completed_count_c);
                    }

                    println!("total completed server connections = {}", completed_count_s);

                    println!("unbound server-side connections = {}", by_uuid.len());
                    by_uuid.iter().enumerate().for_each(|(i, (_, c))| {
                        debug!("{:6}: {}", i, c);
                    });


                    if min_total.get_first_stamp().is_some() && max_total.get_last_stamp().is_some() {
                        let total = max_total.get_last_stamp().unwrap() - min_total.get_first_stamp().unwrap();
                        println!(
                            "max used cycles over all pipelines = {}, per connection = {} ({} cps)",
                            total.separated_string(),
                            (total / (total_connections as u64)).separated_string(),
                            system_data.cpu_clock / (total / (total_connections as u64 + 1)),
                        );
                    }

                    f.flush().expect("cannot flush BufWriter");
                }

                mtx.send(MessageFrom::Exit).unwrap();

                thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                std::process::exit(0);
            }
            Err(ref e) => {
                error!("Error: {}", e);
                std::process::exit(1);
            }
        }
}
