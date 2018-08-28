extern crate ctrlc;
extern crate e2d2;
extern crate traffic_lib;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::env;
use std::time::Duration;
use std::thread;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::collections::{HashSet};

use ipnet::Ipv4Net;

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::PmdPort;
use e2d2::interface::PortQueue;
use e2d2::scheduler::initialize_system;
use e2d2::scheduler::StandaloneScheduler;
use e2d2::allocators::CacheAligned;

use traffic_lib::Connection;
use traffic_lib::nftcp::setup_kni;
use traffic_lib::read_proxy_config;
use traffic_lib::get_mac_from_ifname;
use traffic_lib::print_hard_statistics;
use traffic_lib::setup_pipelines;
use traffic_lib::Container;
use traffic_lib::L234Data;
use traffic_lib::MessageFrom;
use traffic_lib::spawn_recv_thread;

#[test]
fn delayed_binding_proxy() {
    env_logger::init();
    info!("Testing client to server connections of ProxyEngine ..");
    let toml_file = "tests/test_proxy.toml";

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

    let proxy_config = read_proxy_config(toml_file).unwrap();

    if proxy_config.queries.is_none() {
        error!("missing parameter 'queries' in configuration file");
        std::process::exit(1);
    };

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_e) => false,
        }
    }

    if !am_root() {
        error!(" ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\nDo not run 'cargo test' as root.");
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    }).expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["proxyengine", "-f", toml_file]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut configuration = read_matches(&matches, &opts);

    let l234data: Vec<L234Data> = proxy_config
        .servers
        .iter()
        .map(|srv_cfg| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or(get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
        })
        .collect();

    let proxy_config_cloned = proxy_config.clone();

    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let s = String::from_utf8(c.payload.to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data.len();
        c.server = Some(l234data[remainder].clone());
        info!("selecting {}", proxy_config_cloned.servers[remainder].id);
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

    match initialize_system(&mut configuration) {
        Ok(mut context) => {
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom>();

            let proxy_config_cloned = proxy_config.clone();
            let mtx_clone=mtx.clone();
            let boxed_fss = Arc::new(f_select_server);
            let boxed_fpp = Arc::new(f_process_payload_c_s);

            context.add_pipeline_to_run(
                Box::new(move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                setup_pipelines(core, p, s, &proxy_config_cloned, boxed_fss.clone(), boxed_fpp.clone(), mtx_clone.clone());}
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

            // set up servers
            for server in proxy_config.servers {
                let target_port = server.port; // moved into thread
                let target_ip = server.ip;
                let id = server.id;
                thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
                    Ok(listener1) => {
                        debug!("bound server {} to {}:{}", id, target_ip, target_port);
                        for stream in listener1.incoming() {
                            let mut stream = stream.unwrap();
                            let mut buf = [0u8; 256];
                            stream.read(&mut buf[..]).unwrap();
                            debug!("server {} received: {}", id, String::from_utf8(buf.to_vec()).unwrap());
                            stream.write(&format!("Thank You from {}", id).to_string().into_bytes()).unwrap();
                        }
                    }
                    _ => {
                        panic!("failed to bind server {} to {}:{}", id, target_ip, target_port);
                    }
                });
            }

            thread::sleep(Duration::from_millis(2000 as u64)); // wait for the servers

            // emulate clients

            let timeout = Duration::from_millis(1000 as u64);

            for ntry in 0..proxy_config.queries.unwrap() {
                match TcpStream::connect_timeout(
                    &SocketAddr::from((proxy_config.proxy.ipnet.parse::<Ipv4Net>().unwrap().addr(), proxy_config.proxy.port)),
                    timeout,
                ) {
                    Ok(mut stream) => {
                        debug!("test connection {}: TCP connect to proxy successful", ntry);
                        stream.set_write_timeout(Some(timeout)).unwrap();
                        stream.set_read_timeout(Some(timeout)).unwrap();
                        match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                            Ok(_) => {
                                debug!("successfully send {} stars", ntry);
                                let mut buf = [0u8; 256];
                                match stream.read(&mut buf[..]) {
                                    Ok(_) => info!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap()),
                                    _ => {
                                        panic!("timeout on connection {} while waiting for answer", ntry);
                                    }
                                };
                            }
                            _ => {
                                panic!("error when writing to test connection {}", ntry);
                            }
                        }
                    }
                    _ => {
                        panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                    }
                }
            }

            thread::sleep(Duration::from_millis(500)); // Sleep for a bit
            print_hard_statistics(1u16);
            for port in context.ports.values() {
                println!("Port {}:{}", port.port_type(), port.port_id());
                port.print_soft_statistics();
            }

            info!("terminating ProxyEngine ...");
            mtx.send(MessageFrom::Exit).unwrap();
            thread::sleep(Duration::from_millis(200));
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
