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

use e2d2::interface::{ PortQueue,};
use e2d2::scheduler::{ StandaloneScheduler, Scheduler, Runnable};
use e2d2::allocators::CacheAligned;
use e2d2::operators::{ReceiveBatch, Batch, TransformBatch};

use netfcts::comm::{MessageFrom};
use netfcts::RunTime;

use traffic_lib::Configuration;
use std::collections::{HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use std::fs::File;
use std::process;

use uuid::Uuid;
use std::io::Read;

pub fn nf_macswap<T: 'static + Batch>(parent: T) -> TransformBatch<T> {
    parent.transform(box move |pkt| {
        assert_eq!(pkt.refcnt(), 1);
        let hdr = pkt.headers_mut().mac_mut(0);
        hdr.swap_addresses();
    })
}


fn test<S>(ports: HashSet<CacheAligned<PortQueue>>, sched: &mut S, _core: i32)
where
    S: Scheduler + Sized,
{
    for port in &ports {
        if port.port.is_physical() {
            println!("Receiving port {}", port);
        }
    }

    let pipelines: Vec<_> = ports
        .iter()
        .filter(|p| p.port.is_physical())
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
    info!("Starting MacSwap ..");

    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    let mut f = File::open("./tests/toml_file.txt").expect("file not found");
    let mut toml_file = String::new();
    f.read_to_string(&mut toml_file)
        .expect("something went wrong reading ./tests/toml_file.txt");

    let mut run_time: RunTime<Configuration> = match RunTime::init_with_toml_file(&toml_file) {
        Ok(run_time) => run_time,
        Err(err) => panic!("failed to initialize RunTime {}", err),
    };

    // setup flowdirector for physical ports:
    run_time.setup_flowdirector().expect("failed to setup flowdirector");

    let run_configuration = &run_time.run_configuration.clone();

    if run_configuration.engine_configuration.test_size.is_none() {
        error!("missing parameter 'test_size' in configuration file {}", toml_file.trim());
        process::exit(1);
    };


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");


    run_time.start_schedulers().expect("cannot start schedulers");

    run_time
        .add_pipeline_to_run(Box::new(
            move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| test(p, s, core),
        ))
        .expect("cannot install pipelines");

    // start the controller
    run_time.start();

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000 as u64));

    let (mtx, _reply_mrx) = run_time.get_main_channel().expect("cannot get main channel");
    // start generator
    mtx.send(MessageFrom::StartEngine).unwrap();

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
