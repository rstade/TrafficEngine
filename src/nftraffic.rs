//use e2d2::operators::{ReceiveBatch, Batch, merge, merge_with_selector};
use e2d2::operators::{ReceiveBatch, Batch, merge_auto, SchedulingPolicy};
use e2d2::scheduler::{Runnable, Scheduler, StandaloneScheduler};
use e2d2::allocators::CacheAligned;
use e2d2::headers::{IpHeader, MacHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::queues::{new_mpsc_queue_pair, new_mpsc_queue_pair_with_size};
use e2d2::headers::EndOffset;
use e2d2::common::EmptyMetadata;
use e2d2::utils;

use std::sync::mpsc::{Sender, channel};
use std::sync::Arc;
use std::net::{SocketAddrV4, Ipv4Addr};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

use uuid::Uuid;
//use serde_json;
use bincode::{serialize, deserialize};
use separator::Separatable;

use netfcts::tcp_common::{TcpState, TcpStatistics, TcpCounter, TcpRole, CData, L234Data, ReleaseCause};
use cmanager::{Connection, ConnectionManagerC, ConnectionManagerS};
use EngineConfig;
use netfcts::system::SystemData;
#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;
use netfcts::is_kni_core;
use {PipelineId, MessageFrom, MessageTo, TaskType, Timeouts};
use netfcts::tasks::{PRIVATE_ETYPE_PACKET, PRIVATE_ETYPE_TIMER, ETYPE_IPV4};
use netfcts::tasks::{private_etype, PacketInjector, TickGenerator, install_task};
use netfcts::timer_wheel::TimerWheel;
use netfcts::HeaderState;
use netfcts::prepare_checksum_and_ttl;
use netfcts::set_header;
use netfcts::remove_tcp_options;
use netfcts::make_reply_packet;
use TEngineStore;

const MIN_FRAME_SIZE: usize = 60;

const TIMER_WHEEL_RESOLUTION_MS: u64 = 10;
const TIMER_WHEEL_SLOTS: usize = 1001;
const TIMER_WHEEL_SLOT_CAPACITY: usize = 2500;
const SEQN_SHIFT: usize = 4;

pub fn setup_generator(
    core: i32,
    nr_connections: usize, //# of connections to setup per pipeline
    pci: &CacheAligned<PortQueue>,
    kni: &CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    engine_config: &EngineConfig,
    servers: Vec<L234Data>,
    flowdirector_map: HashMap<i32, Arc<FlowDirector>>,
    tx: Sender<MessageFrom<TEngineStore>>,
    system_data: SystemData,
) {
    let mut me = engine_config.get_l234data();
    let l4flow_for_this_core = flowdirector_map.get(&pci.port.port_id()).unwrap().get_flow(pci.rxq());
    me.ip = l4flow_for_this_core.ip; // in case we use destination IP address for flow steering

    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port.port_id() as u16,
        rxq: pci.rxq(),
    };
    debug!("enter setup_generator {}", pipeline_id);

    let detailed_records = engine_config.detailed_records.unwrap_or(false);
    let mut cm_c = ConnectionManagerC::new(pipeline_id.clone(), pci.clone(), l4flow_for_this_core, detailed_records);
    let mut cm_s = ConnectionManagerS::new(detailed_records);

    let mut timeouts = Timeouts::default_or_some(&engine_config.timeouts);
    let max_open = engine_config.max_open.unwrap_or(cm_c.no_available_ports());

    let mut wheel_c = TimerWheel::new(
        TIMER_WHEEL_SLOTS,
        system_data.cpu_clock * TIMER_WHEEL_RESOLUTION_MS / 1000,
        TIMER_WHEEL_SLOT_CAPACITY,
    );
    let mut wheel_s = TimerWheel::new(
        TIMER_WHEEL_SLOTS,
        system_data.cpu_clock * TIMER_WHEEL_RESOLUTION_MS / 1000,
        TIMER_WHEEL_SLOT_CAPACITY,
    );
    debug!(
        "{} wheel cycle= {} millis, cpu-clock= {}",
        pipeline_id,
        wheel_c.get_max_timeout_cycles() * 1000 / system_data.cpu_clock,
        system_data.cpu_clock,
    );

    // check that we do not overflow the wheel:
    if timeouts.established.is_some() {
        let timeout = timeouts.established.unwrap();
        if timeout > wheel_c.get_max_timeout_cycles() {
            warn!(
                "timeout defined in configuration file overflows timer wheel: reset to {} millis",
                wheel_c.get_max_timeout_cycles() * 1000 / system_data.cpu_clock
            );
            timeouts.established = Some(wheel_c.get_max_timeout_cycles());
        }
    }


    // setting up a a reverse message channel between this pipeline and the main program thread
    debug!("{} setting up reverse channel", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo<TEngineStore>>();
    // we send the transmitter to the remote receiver of our messages
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();

    // forwarding frames coming from KNI to PCI, if we are the kni core
    if is_kni_core(pci) {
        let forward2pci = ReceiveBatch::new(kni.clone()).parse::<MacHeader>().send(pci.clone());
        let uuid = Uuid::new_v4();
        let name = String::from("Kni2Pci");
        sched.add_runnable(Runnable::from_task(uuid, name, forward2pci).move_ready());
    }
    let thread_id = format!("<c{}, rx{}>: ", core, pci.rxq());
    let tx_clone = tx.clone();
    let mut counter_to = TcpCounter::new();
    let mut start_stamp: u64 = 0;
    let mut stop_stamp: u64 = 0;
    let mut counter_from = TcpCounter::new();

    struct HoldingTime {
        // in cycles
        sum: u64,
        count: u64,
        max: u64,
        at: u64,
    }

    impl HoldingTime {
        fn new() -> HoldingTime {
            HoldingTime {
                sum: 0,
                count: 0,
                max: 0,
                at: 0,
            }
        }

        #[inline]
        fn add_hold(&mut self, start_low28bit: u32) {
            let mut now = (utils::rdtscp_unsafe() & 0x000000000FFFFFFF) as u32;
            if now <= start_low28bit {
                // at least one overflow
                now += 0x10000000;
            }
            let h = (now - start_low28bit) as u64;
            self.sum += h;
            self.count += 1;
            if h > self.max {
                self.max = h;
                self.at = self.count;
            }
        }

        #[inline]
        fn mean(&self) -> u64 {
            if self.count > 0 { self.sum / self.count } else { 0 }
        }

        #[inline]
        fn max_at(&self) -> (u64, u64) {
            (self.max, self.at)
        }
    }

    let mut hold = HoldingTime::new();

    #[cfg(feature = "profiling")]
        let mut rx_tx_stats = Vec::with_capacity(10000);

    // we create SYN and Payload packets and merge them with the upstream coming from the pci i/f
    // the destination port of the created tcp packets is used as discriminator in the pipeline (dst_port 1 is for SYN packet generation)

    let (syn_producer, syn_consumer) = new_mpsc_queue_pair_with_size(64);
    let injector_uuid = install_task(
        sched,
        "SynInjector",
        PacketInjector::new(
            syn_producer,
            &me,
            0,
            system_data.cpu_clock / engine_config.cps_limit() * 32,
            1u16,
        )
            .set_start_delay(system_data.cpu_clock / 100),
    );
    tx.send(MessageFrom::Task(pipeline_id.clone(), injector_uuid, TaskType::TcpGenerator))
        .unwrap();
    let syn_injector_ready_flag = sched.get_ready_flag(&injector_uuid).unwrap();


    let (payload_producer, payload_consumer) = new_mpsc_queue_pair_with_size(64);
    let injector_uuid = install_task(
        sched,
        "PayloadInjector",
        PacketInjector::new(
            payload_producer,
            &me,
            0,
            system_data.cpu_clock / engine_config.cps_limit() * 32,
            2u16,
        )
            .set_start_delay(system_data.cpu_clock / 100),
    );
    tx.send(MessageFrom::Task(pipeline_id.clone(), injector_uuid, TaskType::TcpGenerator))
        .unwrap();
    let payload_injector_ready_flag = sched.get_ready_flag(&injector_uuid).unwrap();

    // set up the generator producing timer tick packets with our private EtherType
    let (producer_timerticks, consumer_timerticks) = new_mpsc_queue_pair();
    let tick_generator = TickGenerator::new(producer_timerticks, &me, system_data.cpu_clock / 100); // 10 ms
    assert!(wheel_c.resolution() >= tick_generator.tick_length());
    let wheel_tick_reduction_factor = wheel_c.resolution() / tick_generator.tick_length();
    let mut ticks = 0;
    let uuid_task = install_task(sched, "TickGenerator", tick_generator);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_task, TaskType::TickGenerator))
        .unwrap();

    let receive_pci = ReceiveBatch::new(pci.clone());
    let l2_input_stream = merge_auto(
        vec![
            syn_consumer.compose(),
            payload_consumer.compose(),
            consumer_timerticks.set_urgent().compose(),
            //l2groups.get_group(1).unwrap().compose(),
            receive_pci.compose(),
        ],
        SchedulingPolicy::LongestQueue,
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI
    let rxq = pci.rxq();
    let csum_offload = pci.port.csum_offload();
    #[cfg(feature = "profiling")]
        let tx_stats = pci.tx_stats();
    #[cfg(feature = "profiling")]
        let rx_stats = pci.rx_stats();
    let uuid_l4groupby = Uuid::new_v4();
    let uuid_l4groupby_clone = uuid_l4groupby.clone();
    let pipeline_id_clone = pipeline_id.clone();

    #[cfg(feature = "profiling")]
        let sample_size = nr_connections as u64 / 2;
    #[cfg(feature = "profiling")]
        let mut time_adders = [
        TimeAdder::new("cmanager_c", sample_size * 2),
        TimeAdder::new_with_warm_up("s_recv_syn", sample_size, 100),
        TimeAdder::new("s_recv_syn_ack2", sample_size),
        TimeAdder::new("s_recv_payload", sample_size),
        TimeAdder::new("c_sent_syn", sample_size),
        TimeAdder::new("c_sent_payload", sample_size),
        TimeAdder::new("c_recv_syn_ack", sample_size),
        TimeAdder::new("c_recv_fin", sample_size),
        TimeAdder::new("s_recv_fin", sample_size),
        TimeAdder::new("c_release_con", sample_size),
        TimeAdder::new("s_release_con", sample_size),
        TimeAdder::new("cmanager_s", sample_size),
    ];

    let group_by_closure = box move |p_mac: &mut Packet<MacHeader, EmptyMetadata>| {
        // this is the major closure for TCP processing

        let now = || utils::rdtsc_unsafe().separated_string();

        let _syn_injector_start = || {
            debug!("{} (re-)starting the injector at {}", thread_id, now());
            syn_injector_ready_flag.store(true, Ordering::SeqCst);
        };

        let syn_injector_stop = || {
            debug!("{}: stopping the injector at {}", thread_id, now());
            syn_injector_ready_flag.store(false, Ordering::SeqCst);
        };

        let syn_injector_runs = || syn_injector_ready_flag.load(Ordering::SeqCst);

        let payload_injector_start = || {
            debug!("{} (re-)starting the injector at {}", thread_id, now());
            payload_injector_ready_flag.store(true, Ordering::SeqCst);
        };

        let payload_injector_stop = || {
            debug!("{}: stopping the injector at {}", thread_id, now());
            payload_injector_ready_flag.store(false, Ordering::SeqCst);
        };

        let payload_injector_runs = || payload_injector_ready_flag.load(Ordering::SeqCst);


        /*
        #[inline]
        pub fn tcpip_payload_size<M: Sized + Send>(p: &Packet<TcpHeader, M>) -> u16 {
            let iph = p.get_pre_header().unwrap();
            // payload size = ip total length - ip header length -tcp header length
            iph.length() - (iph.ihl() as u16) * 4u16 - (p.get_header().data_offset() as u16) * 4u16
        }
        */


        #[inline]
        fn syn_received<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, c: &mut Connection, h: &mut HeaderState) {
            c.push_state(TcpState::SynReceived);
            c.set_sock((h.ip.src(), h.tcp.src_port()));
            // debug!("checksum in = {:X}",p.get_header().checksum());
            remove_tcp_options(p, h);
            make_reply_packet(h, 1);
            //generate seq number:
            c.seqn_nxt = (utils::rdtsc_unsafe() << 8) as u32;
            h.tcp.set_seq_num(c.seqn_nxt);
            c.ackn_nxt = h.tcp.ack_num();
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            prepare_checksum_and_ttl(p, h);
            trace!("(SYN-)ACK to client, L3: { }, L4: { }", h.ip, h.tcp);
        }

        #[inline]
        fn synack_received<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, c: &mut Connection, h: &mut HeaderState) {
            make_reply_packet(h, 1);
            c.ackn_nxt = h.tcp.ack_num();
            h.tcp.unset_syn_flag();
            h.tcp.set_seq_num(c.seqn_nxt);
            prepare_checksum_and_ttl(p, h);
        }

        #[inline]
        fn strip_payload<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, h: &mut HeaderState) {
            let ip_sz = h.ip.length();
            let payload_len = ip_sz as usize - h.tcp.offset() - h.ip.ihl() as usize * 4;
            h.ip.set_length(ip_sz - payload_len as u16);
            p.trim_payload_size(payload_len);
        }

        #[inline]
        fn s_reply_with_fin<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, c: &mut Connection, h: &mut HeaderState) {
            make_reply_packet(h, 0);
            c.ackn_nxt = h.tcp.ack_num();
            h.tcp.set_seq_num(c.seqn_nxt);
            h.tcp.unset_psh_flag();
            h.tcp.set_fin_flag();
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            strip_payload(p, h);
            prepare_checksum_and_ttl(p, h);
        }

        #[inline]
        fn generate_syn<M: Sized + Send>(
            p: &mut Packet<TcpHeader, M>,
            c: &mut Connection,
            h: &mut HeaderState,
            me: &L234Data,
            servers: &Vec<L234Data>,
            pipeline_id: &PipelineId,
            syn_counter: &mut usize,
        ) {
            h.mac.set_etype(0x0800); // overwrite private ethertype tag
            c.set_server_index(*syn_counter as usize % servers.len());
            set_header(&servers[c.server_index()], c.port(), h, &me.mac, me.ip);

            //generate seq number:
            c.seqn_nxt = (utils::rdtsc_unsafe() << SEQN_SHIFT) as u32;
            h.tcp.set_seq_num(c.seqn_nxt);
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            h.tcp.set_syn_flag();
            h.tcp.set_window_size(5840); // 4* MSS(1460)
            h.tcp.set_ack_num(0u32);
            h.tcp.unset_ack_flag();
            h.tcp.unset_psh_flag();
            prepare_checksum_and_ttl(p, h);

            *syn_counter += 1;
            if *syn_counter % 1000 == 0 {
                debug!("{}: sent {} SYNs", pipeline_id, *syn_counter);
            }
        }

        #[inline]
        fn make_payload_packet<M: Sized + Send>(
            p: &mut Packet<TcpHeader, M>,
            c: &mut Connection,
            h: &mut HeaderState,
            me: &L234Data,
            servers: &Vec<L234Data>,
            payload: &[u8],
        ) {
            h.mac.set_etype(0x0800); // overwrite private ethertype tag
            set_header(&servers[c.server_index()], c.port(), h, &me.mac, me.ip);
            let sz = payload.len();
            let ip_sz = h.ip.length();
            p.add_to_payload_tail(sz).expect("insufficient tail room");
            h.ip.set_length(ip_sz + sz as u16);
            h.tcp.set_seq_num(c.seqn_nxt);
            h.tcp.unset_syn_flag();
            h.tcp.set_window_size(5840); // 4* MSS(1460)
            h.tcp.set_ack_num(c.ackn_nxt);
            h.tcp.set_ack_flag();
            h.tcp.set_psh_flag();
            c.seqn_nxt = c.seqn_nxt.wrapping_add(sz as u32);
            p.copy_payload_from_u8_slice(payload);
            if p.data_len() < MIN_FRAME_SIZE {
                let n_padding_bytes = MIN_FRAME_SIZE - p.data_len();
                debug!("padding with {} 0x0 bytes", n_padding_bytes);
                p.add_padding(n_padding_bytes);
            }
            prepare_checksum_and_ttl(p, h);
        }

        #[inline]
        fn passive_close<M: Sized + Send>(
            p: &mut Packet<TcpHeader, M>,
            c: &mut Connection,
            h: &mut HeaderState,
            thread_id: &String,
            counter: &mut TcpCounter,
        ) {
            debug!(
                "{} passive close on src/dst-port {}/{} in state {:?}",
                thread_id,
                h.tcp.src_port(),
                c.port(),
                c.state(),
            );
            c.set_release_cause(ReleaseCause::PassiveClose);
            counter[TcpStatistics::RecvFin] += 1;
            c.push_state(TcpState::LastAck);
            make_reply_packet(h, 1);
            c.ackn_nxt = h.tcp.ack_num();
            h.tcp.set_ack_flag();
            h.tcp.set_seq_num(c.seqn_nxt);
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            prepare_checksum_and_ttl(p, h);
            counter[TcpStatistics::SentFinPssv] += 1;
            counter[TcpStatistics::SentAck4Fin] += 1;
        };

        #[inline]
        fn active_close<M: Sized + Send>(
            p: &mut Packet<TcpHeader, M>,
            c: &mut Connection,
            h: &mut HeaderState,
            counter: &mut TcpCounter,
            state: &TcpState,
        ) -> bool {
            let mut tcp_closed = false;
            if h.tcp.ack_flag() && h.tcp.ack_num() == c.seqn_nxt {
                // we got a FIN+ACK as a receipt to a sent FIN (engine closed connection)
                debug!(
                    "active close: received FIN+ACK-reply from DUT {:?}:{:?}",
                    h.ip.src(),
                    h.tcp.src_port()
                );
                counter[TcpStatistics::RecvFinPssv] += 1;
                counter[TcpStatistics::RecvAck4Fin] += 1;
                c.push_state(TcpState::Closed);
                tcp_closed = true;
            } else {
                // no ACK
                debug!(
                    "active close: received FIN-reply from DUT {:?}/{:?}",
                    h.ip.src(),
                    h.tcp.src_port()
                );
                counter[TcpStatistics::RecvFinPssv] += 1;
                counter[TcpStatistics::RecvAck4Fin] += 1;
                if *state == TcpState::FinWait1 {
                    c.push_state(TcpState::Closing);
                } else if *state == TcpState::FinWait2 {
                    c.push_state(TcpState::Closed);
                    tcp_closed = true
                }
            }
            make_reply_packet(h, 1);
            h.tcp.unset_fin_flag();
            h.tcp.set_ack_flag();
            c.ackn_nxt = h.tcp.ack_num();
            h.tcp.set_seq_num(c.seqn_nxt);
            if h.tcp_payload_len() > 0 {
                strip_payload(p, h);
            }
            prepare_checksum_and_ttl(p, h);
            counter[TcpStatistics::SentAck4Fin] += 1;
            tcp_closed
        };

        // *****  the closure starts here with processing

        #[cfg(feature = "profiling")]
            let timestamp_entry = utils::rdtsc_unsafe();

        let pipeline_ip = cm_c.ip();
        let tcp_port_base = cm_c.tcp_port_base();

        // we must operate on a clone of the borrowed packet, as we want to move it.
        // we release the clone within this closure, we do not care about mbuf refcount
        let p_mac = p_mac.clone_without_ref_counting();
        let b_private_etype = private_etype(&p_mac.get_header().etype());
        if !b_private_etype {
            let header = p_mac.get_header();
            if header.dst != me.mac && !header.dst.is_multicast() && !header.dst.is_broadcast() {
                debug!("{} from pci: discarding because mac unknown: {} ", thread_id, &header);
                return 0;
            }
            if header.etype() != 0x0800 && !b_private_etype {
                // everything other than Ipv4 or our own packets we send to KNI, i.e. group 2
                return 2;
            }
        }
        let p_ip = p_mac.parse_header::<IpHeader>();
        if !b_private_etype {
            let iph = p_ip.get_header();
            // everything other than TCP, and everything not addressed to us we send to KNI, i.e. group 2
            if iph.protocol() != 6 || iph.dst() != pipeline_ip && iph.dst() != me.ip {
                return 2;
            }
        }
        let p = &mut p_ip.parse_header::<TcpHeader>();
        let mut group_index = 0usize; // the index of the group to be returned, default 0: dump packet
        if csum_offload {
            p.set_tcp_ipv4_checksum_tx_offload();
        }

        // converting to raw pointer avoids to borrow mutably from p
        let mut hs = HeaderState {
            ip: unsafe { &mut *(p.get_mut_pre_header().unwrap() as *mut IpHeader) },
            mac: unsafe { &mut *(p.get_mut_pre_pre_header().unwrap() as *mut MacHeader) },
            tcp: unsafe { &mut *(p.get_mut_header() as *mut TcpHeader) },
        };

        let src_sock = (hs.ip.src(), hs.tcp.src_port());

        //check ports
        if !b_private_etype && hs.tcp.dst_port() != me.port && hs.tcp.dst_port() < tcp_port_base {
            return 2;
        }

        // if set by the following tcp state machine,
        // the port/connection becomes released/ready afterwards
        // this is cumbersome, but we must make the  borrow checker happy
        let mut b_release_connection_c = false;
        let mut b_release_connection_s = false;
        let mut ready_connection = None;
        let server_listen_port = cm_c.listen_port();

        // check if we got a packet from generator
        match (hs.mac.etype(), hs.tcp.dst_port()) {
            // SYN injection
            (PRIVATE_ETYPE_PACKET, 1) => {
                if counter_to[TcpStatistics::SentSyn] == 0 {
                    start_stamp = utils::rdtscp_unsafe()
                }
                if counter_to[TcpStatistics::SentSyn] < nr_connections {
                    if cm_c.concurrent_connections() < max_open {
                        if let Some(c) = cm_c.create(TcpRole::Client) {
                            generate_syn(
                                p,
                                c,
                                &mut hs,
                                &me,
                                &servers,
                                &pipeline_id_clone,
                                &mut counter_to[TcpStatistics::SentSyn],
                            );
                            c.push_state(TcpState::SynSent);
                            c.wheel_slot_and_index =
                                wheel_c.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                            group_index = 1;
                            #[cfg(feature = "profiling")]
                                time_adders[4].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                        }
                    }
                } else {
                    if syn_injector_runs() {
                        syn_injector_stop();
                    }
                }
            }
            // payload injection
            (PRIVATE_ETYPE_PACKET, 2) => {
                let mut cdata = CData::new(SocketAddrV4::new(Ipv4Addr::from(cm_c.ip()), cm_c.listen_port()), 0, 0);
                //trace!("{} payload injection packet received", thread_id);
                if let Some(c) = cm_c.get_ready_connection() {
                    cdata.client_port = c.port();
                    cdata.uuid = c.uid();
                    trace!("{} sending payload on port {}", thread_id, cdata.client_port);
                    let bin_vec = serialize(&cdata).unwrap();
                    make_payload_packet(p, c, &mut hs, &me, &servers, &bin_vec);
                    counter_to[TcpStatistics::Payload] += 1;
                    group_index = 1;
                    #[cfg(feature = "profiling")]
                        time_adders[5].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                } else {
                    if payload_injector_runs() {
                        payload_injector_stop();
                    }
                }
            }
            (PRIVATE_ETYPE_PACKET, _) => {
                error!("received unknown dst port from PacketInjector");
            }
            (PRIVATE_ETYPE_TIMER, _) => {
                ticks += 1;
                match rx.try_recv() {
                    Ok(MessageTo::FetchCounter) => {
                        #[cfg(feature = "profiling")]
                            tx_clone
                            .send(MessageFrom::Counter(
                                pipeline_id_clone.clone(),
                                counter_to.clone(),
                                counter_from.clone(),
                                Some(rx_tx_stats.clone()),
                            ))
                            .unwrap();
                        #[cfg(not(feature = "profiling"))]
                            tx_clone
                            .send(MessageFrom::Counter(
                                pipeline_id_clone.clone(),
                                counter_to.clone(),
                                counter_from.clone(),
                                None,
                            ))
                            .unwrap();
                        info!(
                            "{} max concurrent client connections= {}, mean holding time = {}, max holding time = {} @ {}",
                            thread_id,
                            cm_c.max_concurrent_connections(),
                            hold.mean(),
                            hold.max_at().0,
                            hold.max_at().1
                        )
                    }
                    Ok(MessageTo::FetchCRecords) => {
                        trace!("{} got FetchCrecords", thread_id);
                        tx_clone
                            .send(MessageFrom::CRecords(
                                pipeline_id_clone.clone(),
                                cm_c.fetch_c_records(),
                                cm_s.fetch_c_records(),
                            ))
                            .unwrap();
                    }
                    _ => {}
                }
                // check if we are ready and both time stamps are set:
                if start_stamp > 0 && stop_stamp > 0 {
                    tx_clone
                        .send(MessageFrom::TimeStamps(pipeline_id_clone.clone(), start_stamp, stop_stamp))
                        .unwrap();
                    // so we  do not send again:
                    start_stamp = 0;
                }
                // check for timeouts
                if ticks % wheel_tick_reduction_factor == 0 {
                    cm_c.release_timeouts(&utils::rdtsc_unsafe(), &mut wheel_c);
                    cm_s.release_timeouts(&utils::rdtsc_unsafe(), &mut wheel_s);
                }
                #[cfg(feature = "profiling")]
                    {
                        let tx_stats_now = tx_stats.stats.load(Ordering::Relaxed);
                        let rx_stats_now = rx_stats.stats.load(Ordering::Relaxed);
                        // only save changes
                        if rx_tx_stats.last().is_none()
                            || tx_stats_now != rx_tx_stats.last().unwrap().2
                            || rx_stats_now != rx_tx_stats.last().unwrap().1
                        {
                            rx_tx_stats.push((utils::rdtsc_unsafe(), rx_stats_now, tx_stats_now));
                        }
                    }
            }
            (ETYPE_IPV4, dst_port) if dst_port == server_listen_port => {
                //server side
                let mut opt_c = if hs.tcp.syn_flag() {
                    debug!(
                        "{} got SYN with src = {:?} on server listen port 0x{:x}",
                        thread_id, src_sock, server_listen_port
                    );
                    counter_from[TcpStatistics::RecvSyn] += 1;
                    let c = cm_s.get_mut_or_insert(&src_sock);
                    #[cfg(feature = "profiling")]
                        time_adders[11].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                    c
                } else {
                    cm_s.get_mut(&src_sock)
                };

                match opt_c {
                    None => warn!("no state for this packet on server port"),
                    Some(mut c) => {
                        let old_s_state = c.state().clone();
                        //check seqn
                        if old_s_state != TcpState::Listen && hs.tcp.seq_num() != c.ackn_nxt {
                            let diff = hs.tcp.seq_num() as i64 - c.ackn_nxt as i64;
                            if diff > 0 {
                                warn!(
                                    "{} unexpected seqn (packet loss?) in state {:?}, seqn differs by {}",
                                    thread_id, old_s_state, diff
                                );
                            } else {
                                debug!("{} state= {:?}, diff= {}, tcp= {}", thread_id, old_s_state, diff, hs.tcp);
                            }
                        } else if hs.tcp.syn_flag() {
                            // check flags
                            if old_s_state == TcpState::Listen {
                                // replies with a SYN-ACK to client:
                                syn_received(p, c, &mut hs);
                                c.set_server_index(rxq as usize); // we misuse this field for the queue number
                                c.wheel_slot_and_index = wheel_s.schedule(
                                    &(timeouts.established.unwrap() * system_data.cpu_clock / 1000),
                                    c.sock().unwrap(),
                                );
                                counter_from[TcpStatistics::SentSynAck] += 1;
                                group_index = 1;
                                #[cfg(feature = "profiling")]
                                    time_adders[1].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                            } else {
                                warn!("{} received SYN in state {:?}", thread_id, c.states());
                            }
                        } else if hs.tcp.fin_flag() {
                            trace!("received FIN");
                            //TODO a FIN packet may have payload, we need to handle this correctly
                            if old_s_state >= TcpState::FinWait1 {
                                if active_close(p, c, &mut hs, &mut counter_from, &old_s_state) {
                                    b_release_connection_s = true;
                                }
                                group_index = 1;
                            } else {
                                // DUT wants to close connection
                                passive_close(p, c, &mut hs, &thread_id, &mut counter_from);
                                group_index = 1;
                            }
                            #[cfg(feature = "profiling")]
                                time_adders[8].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                        } else if hs.tcp.rst_flag() {
                            trace!("received RST");
                            counter_from[TcpStatistics::RecvRst] += 1;
                            c.push_state(TcpState::Closed);
                            c.set_release_cause(ReleaseCause::PassiveRst);
                            // release connection in the next block
                            b_release_connection_s = true;
                        } else if hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_nxt {
                            match old_s_state {
                                TcpState::SynReceived => {
                                    c.push_state(TcpState::Established);
                                    counter_from[TcpStatistics::RecvSynAck2] += 1;
                                    debug!("{} connection from DUT ({:?}) established", thread_id, src_sock);
                                    #[cfg(feature = "profiling")]
                                        time_adders[2].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                                }
                                TcpState::LastAck => {
                                    // received final ack in passive close
                                    trace!("received final ACK in passive close");
                                    counter_from[TcpStatistics::RecvAck4Fin] += 1;
                                    c.push_state(TcpState::Closed);
                                    c.set_release_cause(ReleaseCause::PassiveClose);
                                    // release connection in the next block
                                    b_release_connection_s = true;
                                }
                                TcpState::FinWait1 => c.push_state(TcpState::FinWait2),
                                TcpState::Closing => {
                                    c.push_state(TcpState::Closed);
                                    b_release_connection_s = true;
                                }
                                _ => (),
                            }
                        }

                        // process payload
                        if old_s_state >= TcpState::Established && hs.tcp_payload_len() > 0 {
                            if c.payload_packets() == 0 {
                                //first payload packet
                                if detailed_records {
                                    match deserialize::<CData>(p.get_payload()) {
                                        Ok(cdata) => {
                                            let uuid = cdata.uuid;
                                            debug!("{} received payload {:?}", thread_id, cdata);
                                            c.set_uid(uuid);
                                        }
                                        _ => (),
                                    }
                                }
                                if old_s_state == TcpState::Established {
                                    s_reply_with_fin(p, &mut c, &mut hs);
                                    counter_from[TcpStatistics::SentFin] += 1;
                                    c.set_release_cause(ReleaseCause::ActiveClose);
                                    c.push_state(TcpState::FinWait1);
                                }
                                counter_from[TcpStatistics::Payload] += 1;
                                c.increment_payload_packets();
                                group_index = 1;
                            } else {
                                c.ackn_nxt = hs.tcp.seq_num().wrapping_add(hs.tcp_payload_len() as u32);
                            }
                            #[cfg(feature = "profiling")]
                                time_adders[3].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                        }
                    }
                }
            }
            (ETYPE_IPV4, client_port) => {
                // client side
                // check that flow steering worked:
                if !cm_c.owns_tcp_port(client_port) {
                    error!("flow steering failed {}", hs.tcp);
                }
                let mut c = cm_c.get_mut_by_port(client_port);
                #[cfg(feature = "profiling")]
                    time_adders[0].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                match c {
                    None => {
                        warn!(
                            "{} @ {} engine has no state for port {} ({}-{}), sending to KNI i/f",
                            thread_id,
                            utils::rdtsc_unsafe().separated_string(),
                            client_port,
                            hs.ip,
                            hs.tcp,
                            //Ipv4Addr::from(hs.ip.dst()),
                            // hs.tcp.dst_port(),
                        );
                        // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                        group_index = 2;
                    }
                    Some(mut c) => {
                        //debug!("incoming packet for connection {}", c);
                        let old_c_state = c.state().clone();

                        //check seqn
                        if old_c_state != TcpState::SynSent && hs.tcp.seq_num() != c.ackn_nxt {
                            let diff = hs.tcp.seq_num() as i64 - c.ackn_nxt as i64;
                            if diff > 0 {
                                warn!(
                                    "{} unexpected sequence number (packet loss?) in state {:?}, seqn differs by {}",
                                    thread_id, old_c_state, diff
                                );
                            } else {
                                debug!("{} state= {:?}, diff= {}, tcp= {}", thread_id, old_c_state, diff, hs.tcp);
                            }
                        } else if hs.tcp.ack_flag() && hs.tcp.syn_flag() {
                            group_index = 1;
                            counter_to[TcpStatistics::RecvSynAck] += 1;
                            if old_c_state == TcpState::SynSent {
                                c.push_state(TcpState::Established);
                                ready_connection = Some(c.port());
                                debug!(
                                    "{} connection for port {} to DUT ({:?}) established ",
                                    thread_id,
                                    c.port(),
                                    src_sock
                                );
                                synack_received(p, &mut c, &mut hs);
                                counter_to[TcpStatistics::SentSynAck2] += 1;
                            } else if old_c_state == TcpState::Established {
                                synack_received(p, &mut c, &mut hs);
                                counter_to[TcpStatistics::SentSynAck2] += 1;
                            } else {
                                warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_c_state);
                                group_index = 0;
                            } // ignore the SynAck
                        } else if hs.tcp.fin_flag() {
                            if old_c_state >= TcpState::FinWait1 {
                                active_close(p, c, &mut hs, &mut counter_to, &old_c_state);
                                group_index = 1;
                            } else {
                                passive_close(p, c, &mut hs, &thread_id, &mut counter_to);
                                group_index = 1;
                            }
                            #[cfg(feature = "profiling")]
                                time_adders[7].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                        } else if hs.tcp.rst_flag() {
                            counter_to[TcpStatistics::RecvRst] += 1;
                            c.push_state(TcpState::Closed);
                            c.set_release_cause(ReleaseCause::PassiveRst);
                            // release connection in the next block
                            b_release_connection_c = true;
                        } else if old_c_state == TcpState::LastAck && hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_nxt {
                            counter_to[TcpStatistics::RecvAck4Fin] += 1;
                            if counter_to[TcpStatistics::RecvAck4Fin] == nr_connections {
                                stop_stamp = utils::rdtscp_unsafe()
                            }
                            hold.add_hold(c.seqn_nxt >> SEQN_SHIFT);
                            c.push_state(TcpState::Closed);
                            c.set_release_cause(ReleaseCause::PassiveClose);
                            // release connection in the next block
                            b_release_connection_c = true;
                        } else if hs.tcp.ack_flag() {
                            // ACKs to payload packets
                        } else {
                            counter_to[TcpStatistics::Unexpected] += 1;
                            warn!(
                                "{} unexpected TCP packet on port {} in client state {:?}, sending to KNI i/f: {}",
                                thread_id,
                                hs.tcp.dst_port(),
                                c.states(),
                                hs.tcp,
                            );
                            group_index = 2;
                        }
                    }
                }
            }
            (_, _) => assert!(false), // should never happen
        }

        // here we check if we shall release the connection state,
        // need this cumbersome way because of borrow checker for the connection managers
        if b_release_connection_s {
            cm_s.release(&src_sock, &mut wheel_s);
            #[cfg(feature = "profiling")]
                time_adders[10].add_diff(utils::rdtscp_unsafe() - timestamp_entry);
        }
        if b_release_connection_c {
            cm_c.release(hs.tcp.dst_port(), &mut wheel_c);
            #[cfg(feature = "profiling")]
                time_adders[9].add_diff(utils::rdtscp_unsafe() - timestamp_entry);
        }
        if let Some(sport) = ready_connection {
            trace!("{} connection on port {} is ready", thread_id, sport);
            cm_c.set_ready_connection(sport);
            // if this is the first ready connection, we restart the injector, avoid accessing Atomic unnecessarily
            if cm_c.ready_connections() == 1 {
                payload_injector_start();
            }
            #[cfg(feature = "profiling")]
                time_adders[6].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
        }
        group_index
    };

    // process TCP traffic addressed to Proxy
    let mut l4groups = l2_input_stream.parse::<MacHeader>().group_by(
        3,
        group_by_closure,
        sched,
        "L4-Groups".to_string(),
        uuid_l4groupby_clone,
    );

    let pipe2kni = l4groups.get_group(2).unwrap().send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap().compose();
    let l4dumpflow = l4groups.get_group(0).unwrap().filter(box move |_| false).compose();
    let pipe2pci = merge_auto(vec![l4pciflow, l4dumpflow], SchedulingPolicy::LongestQueue).send(pci.clone());

    let uuid_pipe2kni = install_task(sched, "Pipe2Kni", pipe2kni);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();

    let uuid_pipe2pic = install_task(sched, "Pipe2Pci", pipe2pci);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pic, TaskType::Pipe2Pci))
        .unwrap();
}
