extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
// Logging
#[macro_use]
extern crate log;
extern crate traffic_lib;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PmdPort, PortType, PortQueue};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{initialize_system, NetBricksContext, StandaloneScheduler};
use e2d2::allocators::CacheAligned;

use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use traffic_lib::{get_mac_from_ifname, print_hard_statistics, read_proxy_config, setup_pipelines};
use traffic_lib::Connection;
use traffic_lib::Container;
use traffic_lib::errors::*;
use traffic_lib::L234Data;
use traffic_lib::MessageFrom;
use traffic_lib::nftcp::setup_kni;
use traffic_lib::spawn_recv_thread;

pub fn main() {
    env_logger::init();
    info!("Starting ProxyEngine ..");

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
        println!("try 'proxy_engine <toml configuration file>'\n");
        std::process::exit(1);
    }

    let proxy_config = read_proxy_config(&config_file).unwrap();

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

    let args: Vec<String> = vec!["proxyengine", "-f", &config_file]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut configuration = read_matches(&matches, &opts);

    //  let (tx, rx) = channel::<TcpEvent>();

    let l234data: Vec<L234Data> = proxy_config
        .servers
        .iter()
        .map(|srv_cfg| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
        })
        .collect();

    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let remainder = c.get_client_sock().port().rotate_right(1) as usize % l234data.len();
        c.server = Some(l234data[remainder].clone());
        // info!("selecting {}", proxy_config_cloned.servers[remainder].id);
        // initialize userdata
        if let Some(_) = c.userdata {
            c.userdata.as_mut().unwrap().init();
        } else {
            c.userdata = Some(Container::new());
        }
    };

    // this is the closure, which may modify the payload of client to server packets in a TCP connection
    let f_process_payload_c_s = |_c: &mut Connection, _payload: &mut [u8], _tailroom: usize| {
        /*
        if let IResult::Done(_, c_tag) = parse_tag(payload) {
            let userdata: &mut MyData = &mut c.userdata
                .as_mut()
                .unwrap()
                .mut_userdata()
                .downcast_mut()
                .unwrap();
            userdata.c2s_count += payload.len();
            debug!(
                "c->s (tailroom { }, {:?}): {:?}",
                tailroom,
                userdata,
                c_tag,
            );
        }

        unsafe {
            let payload_sz = payload.len(); }
            let p_payload= payload[0] as *mut u8;
            process_payload(p_payload, payload_sz, tailroom);
        } */
    };

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

    match initialize_system(&mut configuration)
        .map_err(|e| e.into())
        .and_then(|ctxt| check_system(ctxt))
        {
            Ok(mut context) => {
                print_hard_statistics(1u16);
                context.start_schedulers();

                let (mtx, mrx) = channel::<MessageFrom>();

                let proxy_config_cloned = proxy_config.clone();
                let boxed_fss = Arc::new(f_select_server);
                let boxed_fpp = Arc::new(f_process_payload_c_s);

                let mtx_clone = mtx.clone();

                context.add_pipeline_to_run(
                    Box::new(move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(core, p, s, &proxy_config_cloned, boxed_fss.clone(), boxed_fpp.clone(), mtx_clone.clone());
                    }
                    )
                );

                spawn_recv_thread(mrx);
                context.execute();

                // set up kni
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
                            &proxy_config.proxy.ipnet,
                            &proxy_config.proxy.mac,
                            &proxy_config.proxy.namespace,
                        );
                    }
                }
                //main loop
                println!("press ctrl-c to terminate proxy ...");
                while running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                }
                print_hard_statistics(1u16);

                for port in context.ports.values() {
                    println!("Port {}:{}", port.port_type(), port.port_id());
                    port.print_soft_statistics();
                }
                println!("terminating ProxyEngine ...");
                mtx.send(MessageFrom::Exit).unwrap();
                thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
                context.stop();
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
