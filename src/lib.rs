#![feature(box_syntax)]
#![feature(integer_atomics)]
#![feature(trait_alias)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate toml;
extern crate separator;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate uuid;
extern crate serde;
extern crate bincode;
extern crate serde_json;
extern crate netfcts;
extern crate ipnet;
extern crate core;

pub mod nftraffic;
pub mod run_test;
mod cmanager;

pub use netfcts::tcp_common::{CData, L234Data, ReleaseCause, UserData, TcpRole, TcpState, TcpCounter, TcpStatistics};
pub use netfcts::ConRecord;
pub use cmanager::{TEngineStore, Connection};

use eui48::MacAddress;
use uuid::Uuid;
use separator::Separatable;

use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::scheduler::*;
use e2d2::interface::{FlowDirector, PmdPort, Pdu, };

use nftraffic::*;
use netfcts::tasks::*;
use netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use netfcts::system::SystemData;
use netfcts::{setup_kernel_interfaces, new_port_queues_for_core, physical_ports_for_core};
use netfcts::io::print_hard_statistics;

use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::RecvTimeoutError;

pub trait FnPayload =
    Fn(&mut Pdu, &mut Connection, Option<CData>, &mut bool) -> usize + Sized + Send + Sync + Clone + 'static;

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


#[derive(Deserialize, Clone)]
pub struct EngineConfig {
    pub timeouts: Option<Timeouts>,
    pub port: u16,
    pub cps_limit: Option<u64>,
    pub max_open: Option<usize>,
    pub detailed_records: Option<bool>,
    pub fin_by_client: Option<usize>,
    pub fin_by_server: Option<usize>,
}

impl EngineConfig {
    pub fn cps_limit(&self) -> u64 {
        self.cps_limit.unwrap_or(10000000)
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

pub fn read_config(filename: &str) -> e2d2::common::errors::Result<Configuration> {
    let mut toml_str = String::new();
    if File::open(filename)
        .and_then(|mut f| f.read_to_string(&mut toml_str))
        .is_err()
    {
        return Err(E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)));
    }

    info!("toml configuration:\n {}", toml_str);

    let config: Config = match toml::from_str(&toml_str) {
        Ok(value) => value,
        Err(err) => return Err(err.into()),
    };

    Ok(config.trafficengine)

    /*
    match config.trafficengine.engine.ipnet.parse::<Ipv4Net>() {
        Ok(_) => match config.trafficengine.engine.mac.parse::<MacAddress>() {
            Ok(_) => Ok(config.trafficengine),
            Err(e) => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
    */
}

pub fn setup_pipelines<FPL>(
    core: i32,
    no_packets: usize,
    pmd_ports: HashMap<String, Arc<PmdPort>>,
    sched: &mut StandaloneScheduler,
    engine_config: &EngineConfig,
    servers: Vec<L234Data>,
    flowdirector_map: HashMap<u16, Arc<FlowDirector>>,
    tx: Sender<MessageFrom<TEngineStore>>,
    system_data: SystemData,
    f_set_payload: Box<FPL>,
) where
    FPL: FnPayload,
{
    for pmd_port in physical_ports_for_core(core, &pmd_ports) {
        debug!("setup_pipelines for {} on core {}:", pmd_port.name(), core);
        let mut kni_port = None;
        if pmd_port.kni_name().is_some() {
            kni_port = pmd_ports.get(pmd_port.kni_name().unwrap());
        }
        let (pci, kni) = new_port_queues_for_core(core, &pmd_port, kni_port);
        if pci.is_some() {
            debug!(
                "pmd_port= {}, rxq= {}",
                pci.as_ref().unwrap().port_queue.port,
                pci.as_ref().unwrap().port_queue.rxq()
            );
        } else {
            debug!("pmd_port= None");
        }

        if kni.is_some() {
            debug!(
                "associated kni= {}, rxq= {}",
                kni.as_ref().unwrap().port,
                kni.as_ref().unwrap().rxq()
            );
        } else {
            debug!("associated kni= None");
        }

        let uuid = Uuid::new_v4();
        let name = String::from("KniHandleRequest");

        // Kni request handler runs on first core of the associated pci port (rxq == 0)
        if pci.is_some()
            && kni.is_some()
            && kni.as_ref().unwrap().port.is_native_kni()
            && pci.as_ref().unwrap().port_queue.rxq() == 0
        {
            sched.add_runnable(
                Runnable::from_task(
                    uuid,
                    name,
                    KniHandleRequest {
                        kni_port: kni.as_ref().unwrap().port.clone(),
                        last_tick: 0,
                    },
                )
                .move_ready(), // this task must be ready from the beginning to enable managing the KNI i/f
            );
        }

        if pci.is_some() && kni.is_some() {
            setup_generator(
                core,
                no_packets,
                pci.unwrap(),
                kni.unwrap(),
                sched,
                engine_config,
                servers.clone(),
                &flowdirector_map,
                &tx,
                system_data.clone(),
                f_set_payload.clone(),
            );
        }
    }
}


pub fn spawn_recv_thread(mrx: Receiver<MessageFrom<TEngineStore>>, mut context: NetBricksContext) {
    /*
        mrx: receiver for messages from all the pipelines running
    */
    let _handle = thread::spawn(move || {
        let mut senders = HashMap::new();
        let mut tasks: Vec<Vec<(PipelineId, Uuid)>> = Vec::with_capacity(TaskType::NoTaskTypes as usize);
        let mut reply_to_main = None;

        for _t in 0..TaskType::NoTaskTypes as usize {
            tasks.push(Vec::<(PipelineId, Uuid)>::with_capacity(16));
        }
        // start execution of pipelines
        context.execute_schedulers();

        setup_kernel_interfaces(&context);

        // communicate with schedulers:

        loop {
            match mrx.recv_timeout(Duration::from_millis(10)) {
                Ok(MessageFrom::StartEngine(reply_channel)) => {
                    debug!("starting generator tasks");
                    reply_to_main = Some(reply_channel);
                    for s in &context.scheduler_channels {
                        s.1.send(SchedulerCommand::SetTaskStateAll(true)).unwrap();
                    }
                }
                Ok(MessageFrom::Channel(pipeline_id, sender)) => {
                    debug!("got sender from {}", pipeline_id);
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
                Ok(MessageFrom::Task(pipeline_id, uuid, task_type)) => {
                    debug!("{}: task uuid= {}, type={:?}", pipeline_id, uuid, task_type);
                    tasks[task_type as usize].push((pipeline_id, uuid));
                }
                Ok(MessageFrom::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, tx_counter)) => {
                    debug!("{}: received Counter", pipeline_id);
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::Counter(pipeline_id, tcp_counter_to, tcp_counter_from, tx_counter))
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
                Ok(MessageFrom::TimeStamps(p, t0, t1)) => {
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::TimeStamps(p, t0, t1))
                            .unwrap();
                    };
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("error receiving from MessageFrom channel: {}", e);
                    break;
                }
                //m => warn!("unknown Result: {:?}", m),
            };
            match context
                .reply_receiver
                .as_ref()
                .unwrap()
                .recv_timeout(Duration::from_millis(10))
            {
                Ok(SchedulerReply::PerformanceData(core, map)) => {
                    for d in map {
                        info!(
                            "{:2}: {:20} {:>15} count= {:12}, queue length= {}",
                            core,
                            (d.1).0,
                            (d.1).1.separated_string(),
                            (d.1).2.separated_string(),
                            (d.1).3
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
