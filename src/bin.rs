extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
extern crate eui48;
extern crate ipnet;
// Logging
#[macro_use]
extern crate log;
extern crate traffic_lib;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PortType, PortQueue};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{initialize_system, NetBricksContext, StandaloneScheduler};
use e2d2::allocators::CacheAligned;

use traffic_lib::{get_mac_from_ifname, print_hard_statistics, read_config, setup_pipelines};
use traffic_lib::errors::*;
use traffic_lib::L234Data;
use traffic_lib::{MessageFrom,};
use traffic_lib::spawn_recv_thread;

use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;


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
        .map(|srv_cfg| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            //server_id: srv_cfg.id.clone(),
        })
        .collect();

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

                print_hard_statistics(1u16);
                context.start_schedulers();

                let (mtx, mrx) = channel::<MessageFrom>();

                let config_cloned = configuration.clone();
                let mtx_clone = mtx.clone();

                context.add_pipeline_to_run(
                    Box::new(move |core: i32,
                                   p: HashSet<CacheAligned<PortQueue>>,
                                   s: &mut StandaloneScheduler| {
                        setup_pipelines(core,
                                        512u32, // no of batches to generate per pipeline
                                        p,
                                        s,
                                        &config_cloned,
                                        l234data.clone(),
                                        mtx_clone.clone());
                    })
                );

                // start the controller
                spawn_recv_thread(mrx, context, configuration);

                // give threads some time to do initialization work
                thread::sleep(Duration::from_millis(1000 as u64));

                // start generator
                mtx.send(MessageFrom::StartEngine).unwrap();

                thread::sleep(Duration::from_millis(1000 as u64));
                //main loop
                println!("press ctrl-c to terminate proxy ...");
                while running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                }

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
