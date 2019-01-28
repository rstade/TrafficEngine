#![feature(box_syntax)]
extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
extern crate eui48;
extern crate ipnet;
extern crate separator;
extern crate netfcts;
extern crate uuid;

// Logging
#[macro_use]
extern crate log;
extern crate traffic_lib;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PortType, PortQueue,};
use e2d2::headers::{MacHeader, NullHeader};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{initialize_system, NetBricksContext, StandaloneScheduler, Scheduler, Runnable};
use e2d2::allocators::CacheAligned;
use e2d2::operators::{ReceiveBatch, Batch, TransformBatch, ParsedBatch};

use netfcts::comm::{MessageFrom, MessageTo};
use netfcts::errors::*;
use netfcts::ConRecord;

use traffic_lib::{read_config,};

use traffic_lib::spawn_recv_thread;

use std::collections::{HashSet};
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::fs::File;

use uuid::Uuid;
use std::io::Read;


pub fn nf_macswap<T: 'static + Batch<Header = NullHeader>>(
    parent: T,
) -> TransformBatch<MacHeader, ParsedBatch<MacHeader, T>> {
    parent.parse::<MacHeader>().transform(box move |pkt| {
        assert!(pkt.refcnt() == 1);
        let hdr = pkt.get_mut_header();
        hdr.swap_addresses();
    })
}


fn test<S>(ports: HashSet<CacheAligned<PortQueue>>, sched: &mut S, _core: i32)
    where
        S: Scheduler + Sized,
{
    for port in &ports {
        if !port.port.is_kni() { println!("Receiving port {}", port);}
    }

    let pipelines: Vec<_> = ports
        .iter()
        .filter(|p| !p.port.is_kni())
        .map(|port| nf_macswap(ReceiveBatch::new(port.clone())).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        let uuid = Uuid::new_v4();
        let name = String::from("pipeline");
        sched.add_runnable(Runnable::from_task(uuid, name, pipeline).move_ready());
    }
}

#[test]
pub fn macswap() {
    env_logger::init();
    info!("Starting MacSwap ..");

    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    let mut f = File::open("./tests/toml_file.txt").expect("file not found");
    let mut toml_file = String::new();
    f.read_to_string(&mut toml_file)
        .expect("something went wrong reading toml_file.txt");

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

    let configuration = read_config(&toml_file.trim()).unwrap();

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

    let args: Vec<String> = vec!["trafficengine", "-f", &toml_file.trim()]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut netbricks_configuration = read_matches(&matches, &opts);

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
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom<ConRecord>>();
            let (reply_mtx, _reply_mrx) = channel::<MessageTo<ConRecord>>();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    test(
                        p,
                        s,
                        core,
                    );
                },
            ));

            // start the controller
            spawn_recv_thread(mrx, context, configuration);

            // give threads some time to do initialization work
            thread::sleep(Duration::from_millis(1000 as u64));

            // start generator
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();

            thread::sleep(Duration::from_millis(1000 as u64));

            //main loop
            println!("press ctrl-c to terminate MacSwap ...");
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
