extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
extern crate eui48;
extern crate ipnet;
extern crate separator;
extern crate netfcts;

// Logging
#[macro_use]
extern crate log;
extern crate traffic_lib;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PortType, PortQueue};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{initialize_system, NetBricksContext, StandaloneScheduler};
use e2d2::allocators::CacheAligned;

use netfcts::initialize_flowdirector;
use netfcts::comm::{MessageFrom, MessageTo};
use netfcts::system::SystemData;

use traffic_lib::{get_mac_from_ifname, read_config, setup_pipelines};
use traffic_lib::errors::*;
use traffic_lib::L234Data;
use traffic_lib::spawn_recv_thread;
use traffic_lib::ReleaseCause;
use traffic_lib::TcpState;

use std::collections::{HashSet, HashMap};
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
    }).expect("error setting Ctrl-C handler");

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
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let config_cloned = configuration.clone();
            let system_data_cloned = system_data.clone();
            let mtx_clone = mtx.clone();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        config_cloned.test_size.unwrap(), // no of packets to generate per pipeline
                        p,
                        s,
                        &config_cloned.engine,
                        l234data.clone(),
                        flowdirector_map.clone(),
                        mtx_clone.clone(),
                        system_data_cloned.clone(),
                    );
                },
            ));

            let cores = context.active_cores.clone();

            // start the controller
            spawn_recv_thread(mrx, context, configuration);

            // give threads some time to do initialization work
            thread::sleep(Duration::from_millis(1000 as u64));

            // start generator
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();
            let mut pipeline_completed_count=0;

            while pipeline_completed_count < cores.len() {
                match reply_mrx.recv_timeout(Duration::from_millis(20000)) {
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from)) => {
                        info!("{}: to DUT {}", pipeline_id, tcp_counter_to);
                        info!("{}: from DUT {}", pipeline_id, tcp_counter_from);
                        pipeline_completed_count+=1
                    }
                    Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
                    Err(RecvTimeoutError::Timeout) => {
                        warn!("Timeout while waiting for pipelines");
                        break;
                    }
                    Err(e) => {
                        error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                        break;
                    }
                }
            }

            thread::sleep(Duration::from_millis(1000 as u64));

            mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
            thread::sleep(Duration::from_millis(100 as u64));
            mtx.send(MessageFrom::FetchCounter).unwrap();
            mtx.send(MessageFrom::FetchCRecords).unwrap();

            let mut tcp_counters_to = HashMap::new();
            let mut tcp_counters_from = HashMap::new();
            let mut con_records_s = Vec::with_capacity(64);
            let mut con_records_c = Vec::with_capacity(64);

            loop {
                match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from)) => {
                        info!("{}: to DUT {}", pipeline_id, tcp_counter_to);
                        info!("{}: from DUT {}", pipeline_id, tcp_counter_from);
                        tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                        tcp_counters_from.insert(pipeline_id, tcp_counter_from);
                    }
                    Ok(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                        con_records_c.push((pipeline_id.clone(), c_records_client));
                        con_records_s.push((pipeline_id, c_records_server));
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

            //we are searching for the most extreme time stamps over all pipes
            let mut min_total;
            let mut max_total;
            let mut total_connections = 0;
            {
                let cc = &(con_records_c[0].1);
                min_total = cc.last().unwrap().clone();
                max_total = min_total.clone();
            }

            // a hash map of all server side records by uuid
            let mut by_uuid = HashMap::with_capacity(con_records_s[0].1.len()*con_records_s.len());
            let mut completed_count_s = 0;
            for (p, c_records_server) in &mut con_records_s {
                c_records_server.iter().enumerate().for_each(|(_i, c)| {
                    if c.get_release_cause() == ReleaseCause::ActiveClose && c.states().last().unwrap() == &TcpState::Closed
                        {
                            completed_count_s += 1
                        };
                    by_uuid.insert(c.uuid.unwrap(), c);
                });
            }

            for (p, c_records_client) in &mut con_records_c {
                //let mut vec_client: Vec<_> = c_records_client.iter().collect();
                let mut completed_count_c = 0;
                c_records_client.sort_by(|a, b| a.port.cmp(&b.port));

                if c_records_client.len() > 0 {
                    total_connections += c_records_client.len();
                    let mut min = c_records_client.iter().last().unwrap();
                    let mut max = min;
                    c_records_client.iter().enumerate().for_each(|(i, c)| {
                        let uuid = c.uuid.as_ref().unwrap();
                        let c_server = by_uuid.remove(uuid);
                        let line = format!("{:6}: {}\n", i, c);
                        f.write_all(line.as_bytes()).expect("cannot write c_records");
                        if c_server.is_some() {
                            let c_server = c_server.unwrap();
                            let line = format!(
                                "        ({:?}, sock={:21}, port={}, {:?}, {:?}, +{}, {:?})\n",
                                c_server.role,
                                if c_server.sock.is_some() {
                                    c_server.sock.unwrap().to_string()
                                } else {
                                    "none".to_string()
                                },
                                c_server.port,
                                c_server.states(),
                                c_server.get_release_cause(),
                                (c_server.get_first_stamp().unwrap() - c.get_first_stamp().unwrap()).separated_string(),
                                c_server
                                    .deltas_since_synsent_or_synrecv()
                                    .iter()
                                    .map(|u| u.separated_string())
                                    .collect::<Vec<_>>(),
                            );
                            f.write_all(line.as_bytes()).expect("cannot write c_records");
                        }
                        if c.get_release_cause() == ReleaseCause::PassiveClose
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
                            info!(
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

                info!("{} completed client connections = {}", p, completed_count_c);
            }

            info!("total completed server connections = {}", completed_count_s);

            info!("unbound server-side connections ({})", by_uuid.len());
            by_uuid.iter().enumerate().for_each(|(i, (_, c))| {
                debug!("{:6}: {}", i, c);
            });


            if min_total.get_first_stamp().is_some() && max_total.get_last_stamp().is_some() {
                let total = max_total.get_last_stamp().unwrap() - min_total.get_first_stamp().unwrap();
                info!(
                    "total used cycles for all pipelines = {}, per connection = {} ({} cps)",
                    total.separated_string(),
                    (total / (total_connections as u64)).separated_string(),
                    system_data.cpu_clock/(total / (total_connections as u64 + 1)),
                );
            }

            f.flush().expect("cannot flush BufWriter");

            mtx.send(MessageFrom::Exit).unwrap();

            thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
            std::process::exit(0);
        }
        Err(ref e) => {
            error!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                debug!("Backtrace: {:?}", backtrace);
            }
            std::process::exit(1);
        }
    }
}
