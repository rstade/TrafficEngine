extern crate ctrlc;
extern crate e2d2;
extern crate ipnet;
extern crate bincode;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, Shutdown, Ipv4Addr};
use std::sync::mpsc::RecvTimeoutError;
use std::collections::HashMap;
use std::io::{Read, Write, BufWriter};
use std::error::Error;
use std::fs::File;
use std::vec::Vec;
use std::process;
use std::u64;

use bincode::{serialize_into};

use e2d2::interface::{ PmdPort, Pdu, FlowSteeringMode};
use e2d2::scheduler::StandaloneScheduler;
use e2d2::utils;

use separator::Separatable;
use netfcts::RunTime;
use netfcts::comm::PipelineId;
use netfcts::conrecord::HasTcpState;
use netfcts::system::get_mac_from_ifname;
use netfcts::io::print_tcp_counters;
#[cfg(feature = "profiling")]
use netfcts::io::print_rx_tx_counters;
use netfcts::strip_payload;
use netfcts::tcp_common::tcp_payload_size;

use setup_pipelines;
use {CData, L234Data, Connection, Configuration};
use {MessageFrom, MessageTo};
use ReleaseCause;
use {TcpState, TcpStatistics};


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestType {
    Client,
    Server,
}

// we use this function for the integration tests
pub fn run_test(test_type: TestType) {
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

    // number of payloads sent, after which the connection is closed
    let fin_by_client = run_configuration.engine_configuration.engine.fin_by_client.unwrap_or(1000);
    let _fin_by_server = run_configuration.engine_configuration.engine.fin_by_server.unwrap_or(1);


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");

    let l234data: Vec<L234Data> = run_configuration
        .engine_configuration
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

    let fin_by_client_clone = fin_by_client.clone();
    let f_set_payload = Box::new(
        move |p: &mut Pdu, c: &mut Connection, _unused: Option<CData>, b_fin: &mut bool| {
            let pp = c.sent_payload_pkts();
            if pp < 1 {
                // this is the first payload packet sent by client, headers are already prepared with client and server addresses and ports
                let sock = SocketAddrV4::new(Ipv4Addr::from(p.headers().ip(1).src()), p.headers().tcp(2).src_port());
                let cdata = CData::new(sock, c.port(), c.uid());
                let mut buf = [0u8; 16];
                serialize_into(&mut buf[..], &cdata).expect("cannot serialize");
                //let buf = serialize(&cdata).unwrap();
                let sz = buf.len();
                let ip_sz = p.headers().ip(1).length();
                p.add_to_payload_tail(sz).expect("insufficient tail room");
                p.headers_mut().ip_mut(1).set_length(ip_sz + sz as u16);
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

    run_time.start_schedulers().expect("cannot start schedulers");

    let run_time_cloned = run_configuration.clone();

    run_time
        .install_pipeline_on_cores(Box::new(
            move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                setup_pipelines(
                    core,
                    pmd_ports,
                    s,
                    run_time_cloned.clone(),
                    l234data.clone(),
                    f_set_payload.clone(),
                );
            },
        ))
        .expect("cannot install pipelines");

    let mut pci = None;
    let mut kni = None;

    for port in run_time
        .context()
        .expect("no context")
        .ports
        .values()
        .filter(|p| p.is_physical() && p.flow_steering_mode().is_some())
    {
        // note down pci and kni ifaces
        if pci.is_some() {
            error!("the test may not work with more than one physical dpdk port");
        } else {
            pci = Some(port.clone());
            kni = Some(
                run_time
                    .context()
                    .unwrap()
                    .ports
                    .get(port.kni_name().unwrap())
                    .unwrap()
                    .clone(),
            );
            assert!(kni.is_some());
        }
    }

    // this is quick and dirty and just for testing purposes:
    let port_mask = u16::from_be(
        run_configuration.netbricks_configuration.ports[0]
            .fdir_conf
            .unwrap()
            .mask
            .dst_port_mask,
    );
    let rx_queues = pci.as_ref().unwrap().rx_cores.as_ref().unwrap().len() as u16;
    let rfs_mode = pci.as_ref().unwrap().flow_steering_mode().unwrap_or(FlowSteeringMode::Port);
    let cores = run_time.context().unwrap().active_cores.clone();
    debug!("rx_queues = { }, port mask = 0x{:x}", rx_queues, port_mask);

    // start the controller
    run_time.start();

    // give threads some time to do initialization work
    thread::sleep(Duration::from_millis(1000 as u64));

    if test_type == TestType::Client {
        // set up servers
        for server in run_configuration.engine_configuration.targets.clone() {
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
                        let cdata: CData = bincode::deserialize(&buffer[0..nr_bytes]).expect("cannot deserialize cdata");
                        //serde_json::from_slice(&buffer[0..nr_bytes]).expect("cannot deserialize CData");
                        //let socket=Box::new(bincode::deserialize::<SocketAddrV4>(&buffer).expect("cannot deserialize SocketAddrV4"));
                        debug!("{} received {:?} from: {}", id, cdata, stream.peer_addr().unwrap());
                        stream.write(&"Thank you".as_bytes()).expect("cannot write to stream");
                        for i in 1..fin_by_client {
                            stream
                                .read(&mut buffer[..])
                                .expect(&format!("cannot read from stream at try {}", i + 1));
                            stream
                                .write(&format!("Thank you, {} times", i + 1).as_bytes())
                                .expect("cannot write to stream");
                        }
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

    let (mtx, reply_mrx) = run_time.get_main_channel().expect("cannot get main channel");
    mtx.send(MessageFrom::StartEngine).unwrap();
    thread::sleep(Duration::from_millis(2000 as u64));

    if test_type == TestType::Server {
        let timeout = Duration::from_millis(1000 as u64);
        for ntry in 0..run_configuration.engine_configuration.test_size.unwrap() as u16 {
            let target_socket;
            if rfs_mode == FlowSteeringMode::Port {
                let target_port = 0xFFFF - (!port_mask + 1) * (ntry % rx_queues);
                target_socket = SocketAddr::from((kni.as_ref().unwrap().ip_addr().unwrap(), target_port));
                debug!("try {}: connecting to port 0x{:x}", ntry, target_port);
            } else {
                let target_ip =
                    Ipv4Addr::from(u32::from(kni.as_ref().unwrap().ip_addr().unwrap()) + (ntry % rx_queues) as u32 + 1);
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
                        utils::rdtsc_unsafe(),
                    );
                    //let json_string = serde_json::to_string(&cdata).expect("cannot serialize cdata");
                    //stream.write(json_string.as_bytes()).expect("cannot write to stream");
                    let bin_vec = bincode::serialize(&cdata).expect("cannot serialize cdata");
                    stream.write(&bin_vec).expect("cannot write to stream");
                    let mut buffer = [0u8; 1500];
                    stream
                        .read(&mut buffer[..])
                        .expect("did not receive reply from server to cdata");
                    match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                        Ok(_) => {
                            debug!("successfully send {} stars", ntry);
                        }
                        _ => {
                            panic!("error when writing to test connection {}", ntry);
                        }
                    }
                    stream
                        .read(&mut buffer[..])
                        .expect("did not receive reply from server to my stars");
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


    mtx.send(MessageFrom::FetchCounter).unwrap();
    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        mtx.send(MessageFrom::FetchCRecords).unwrap();
    }


    let mut tcp_counters_to = HashMap::new();
    let mut tcp_counters_from = HashMap::new();
    let mut con_records = HashMap::new();
    let mut start_stop_stamps: HashMap<PipelineId, (u64, u64)> = HashMap::new();

    loop {
        match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
            Ok(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, _rx_tx_stats)) => {
                print_tcp_counters(&pipeline_id, &tcp_counter_to, &tcp_counter_from);
                #[cfg(feature = "profiling")]
                print_rx_tx_counters(&pipeline_id, &_rx_tx_stats.unwrap());
                tcp_counters_to.insert(pipeline_id.clone(), tcp_counter_to);
                tcp_counters_from.insert(pipeline_id, tcp_counter_from);
            }
            Ok(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                con_records.insert(pipeline_id, (c_records_client, c_records_server));
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

    if run_configuration
        .engine_configuration
        .engine
        .detailed_records
        .unwrap_or(false)
    {
        let file = match File::create("c_records.txt") {
            Err(why) => panic!("couldn't create c_records.txt: {}", why.description()),
            Ok(file) => file,
        };
        let mut f = BufWriter::new(file);

        assert_ne!(con_records.len(), 0);
        if test_type == TestType::Server {
            for (p, (_, c_records)) in &con_records {
                match c_records {
                    Some(c_records) if c_records.len() > 0 => {
                        let mut completed_count = 0;
                        let mut min = c_records.iter().last().unwrap();
                        let mut max = min;
                        c_records.iter().enumerate().for_each(|(i, c)| {
                            let line = format!("{:6}: {}\n", i, c);
                            f.write_all(line.as_bytes()).expect("cannot write c_records");
                            if c.states().last().unwrap() == &TcpState::Closed {
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
                        println!("{} completed connections = {}", p, completed_count);
                        assert_eq!(completed_count, tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn]);
                    }
                    _ => (),
                }
            }
        }

        if test_type == TestType::Client {
            for (p, (c_records, _)) in &con_records {
                let mut completed_count = 0;
                info!("Pipeline {}:", p);
                f.write_all(format!("Pipeline {}:\n", p).as_bytes())
                    .expect("cannot write c_records");
                c_records.as_ref().unwrap().iter().enumerate().for_each(|(i, c)| {
                    let line = format!("{:6}: {}\n", i, c);
                    f.write_all(line.as_bytes()).expect("cannot write c_records");
                    if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                        && c.states().last().unwrap() == &TcpState::Closed
                    {
                        completed_count += 1
                    };
                });
                println!("{} completed connections = {}", p, completed_count);
                assert_eq!(completed_count, tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSyn]);
            }
        }

        f.flush().expect("cannot flush BufWriter");
    }
    if test_type == TestType::Server {
        for (p, _) in &tcp_counters_from {
            assert_eq!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSyn],
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck]
            );
            assert_eq!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentSynAck],
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvSynAck2]
            );
            assert!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFin]
                    + tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvFinPssv]
                    <= tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentAck4Fin]
            );
            assert!(
                tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFinPssv]
                    + tcp_counters_from.get(&p).unwrap()[TcpStatistics::SentFin]
                    <= tcp_counters_from.get(&p).unwrap()[TcpStatistics::RecvAck4Fin]
            );
        }
    } else {
        for (p, _) in &tcp_counters_to {
            assert_eq!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSyn],
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSynAck2]
            );
            assert_eq!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentSynAck2],
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvSynAck]
            );
            assert!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvFin]
                    + tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvFinPssv]
                    <= tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentAck4Fin]
            );
            assert!(
                tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentFinPssv]
                    + tcp_counters_to.get(&p).unwrap()[TcpStatistics::SentFin]
                    <= tcp_counters_to.get(&p).unwrap()[TcpStatistics::RecvAck4Fin]
            );
        }
    }
    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(2000));
    println!("PASSED");
    debug!("terminating TrafficEngine");
    process::exit(0);
}
