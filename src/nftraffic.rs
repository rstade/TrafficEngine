use e2d2::operators::{ReceiveBatch, Batch, merge_auto, SchedulingPolicy};
use e2d2::scheduler::{Runnable, Scheduler, StandaloneScheduler};
use e2d2::allocators::CacheAligned;
use e2d2::interface::*;
use e2d2::queues::{new_mpsc_queue_pair, new_mpsc_queue_pair_with_size};
use e2d2::utils;

use std::sync::mpsc::channel;
use std::sync::atomic::Ordering;
use std::net::{Ipv4Addr, SocketAddrV4};

use uuid::Uuid;
use bincode::{ deserialize};
use separator::Separatable;

use netfcts::tcp_common::{TcpState, TcpStatistics, TcpCounter, TcpRole, CData, L234Data, ReleaseCause, tcp_payload_size};
use cmanager::{Connection, ConnectionManagerC, ConnectionManagerS};
use ::{Configuration};
#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;
use {PipelineId, MessageFrom, MessageTo, TaskType};
use netfcts::utils::Timeouts;
use netfcts::tasks::{PRIVATE_ETYPE_PACKET, PRIVATE_ETYPE_TIMER, ETYPE_IPV4};
use netfcts::tasks::{private_etype, PacketInjector, TickGenerator, install_task};
use netfcts::timer_wheel::TimerWheel;
use netfcts::{prepare_checksum_and_ttl, RunConfiguration};
use netfcts::set_header;
use netfcts::remove_tcp_options;
use netfcts::{make_reply_packet, strip_payload};
use netfcts::recstore::TEngineStore;

use FnPayload;
use std::convert::TryFrom;


const MIN_FRAME_SIZE: usize = 60;

const TIMER_WHEEL_RESOLUTION_MS: u64 = 10;
const TIMER_WHEEL_SLOTS: usize = 1002;
const TIMER_WHEEL_SLOT_CAPACITY: usize = 2500;
const SEQN_SHIFT: usize = 4;

pub fn setup_generator<FPL>(
    core: i32,
    pci: CacheAligned<PortQueueTxBuffered>,
    kni: CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    run_configuration: RunConfiguration<Configuration, TEngineStore>,
    servers: Vec<L234Data>,
    f_set_payload: Box<FPL>,
) where
    FPL: FnPayload,
{
    let mut me: L234Data = TryFrom::try_from(kni.port.net_spec().as_ref().unwrap().clone()).unwrap();
    let l4flow_for_this_core = run_configuration
        .flowdirector_map
        .get(&pci.port_queue.port_id())
        .unwrap()
        .get_flow(pci.port_queue.rxq());
    me.ip = l4flow_for_this_core.ip; // in case we use destination IP address for flow steering
    let engine_config = &run_configuration.engine_configuration.engine;
    let system_data = run_configuration.system_data.clone();
    me.port = engine_config.port;

    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port_queue.port_id() as u16,
        rxq: pci.port_queue.rxq(),
    };
    debug!("enter setup_generator {}", pipeline_id);

    let tx = run_configuration.remote_sender.clone();

    let detailed_records = engine_config.detailed_records.unwrap_or(false);
    let mut cm_c = ConnectionManagerC::new(
        pipeline_id.clone(),
        pci.port_queue.clone(),
        l4flow_for_this_core,
        detailed_records,
    );
    let mut cm_s = ConnectionManagerS::new(detailed_records);

    let mut timeouts = Timeouts::default_or_some(&engine_config.timeouts);
    let max_open = engine_config.max_open.unwrap_or(cm_c.available_ports_count());
    let _fin_by_client = engine_config.fin_by_client.unwrap_or(1000);
    let fin_by_server = engine_config.fin_by_server.unwrap_or(1);

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
    info!(
        "{} wheel cycle= {} millis, cpu-clock= {}",
        pipeline_id,
        wheel_c.get_max_timeout_cycles() * 1000 / system_data.cpu_clock,
        system_data.cpu_clock,
    );

    // check that we do not overflow the wheel:
    if timeouts.established.is_some() {
        let timeout = timeouts.established.unwrap();
        if timeout > wheel_c.get_max_timeout_cycles() - wheel_c.resolution() / 2 {
            warn!(
                "timeout defined in configuration file overflows timer wheel: reset to {} millis",
                wheel_c.get_max_timeout_cycles() * 1000 / system_data.cpu_clock - TIMER_WHEEL_RESOLUTION_MS / 2
            );
            timeouts.established = Some(wheel_c.get_max_timeout_cycles() - wheel_c.resolution() / 2);
        }
    }


    // setting up a a reverse message channel between this pipeline and the main program thread
    debug!("{} setting up reverse channel", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo<TEngineStore>>();
    // we send the transmitter to the remote receiver of our messages
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();

    let forward2pci = ReceiveBatch::new(kni.clone()).send(pci.clone());
    let uuid = Uuid::new_v4();
    let name = String::from("Kni2Pci");
    sched.add_runnable(Runnable::from_task(uuid, name, forward2pci).move_ready());

    let thread_id = format!("<c{}, rx{}>: ", core, pci.port_queue.rxq());
    let tx_clone = tx.clone();
    let mut counter_c = TcpCounter::new();
    let mut start_stamp: u64 = 0;
    let mut stop_stamp: u64 = 0;
    let mut counter_s = TcpCounter::new();

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
            if self.count > 0 {
                self.sum / self.count
            } else {
                0
            }
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
            box syn_consumer,
            box payload_consumer,
            box consumer_timerticks.set_urgent(),
            box receive_pci,
        ],
        SchedulingPolicy::LongestQueue,
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI
    let rxq = pci.port_queue.rxq();
    let csum_offload = pci.port_queue.port.csum_offload();
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

    let group_by_closure = box move |pdu: &mut Pdu| {
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

        let _payload_injector_start = || {
            debug!("{} (re-)starting the injector at {}", thread_id, now());
            payload_injector_ready_flag.store(true, Ordering::SeqCst);
        };

        let payload_injector_stop = || {
            debug!("{}: stopping the injector at {}", thread_id, now());
            payload_injector_ready_flag.store(false, Ordering::SeqCst);
        };

        let payload_injector_runs = || payload_injector_ready_flag.load(Ordering::SeqCst);

        #[inline]
        fn syn_received(p: &mut Pdu, c: &mut Connection) {
            c.push_state(TcpState::SynReceived);
            let client_ip = p.headers().ip(1).src();
            // debug!("checksum in = {:X}",p.get_header().checksum());
            remove_tcp_options(p);
            make_reply_packet(p, 1);
            //generate seq number:
            c.seqn_nxt = (utils::rdtsc_unsafe() << 8) as u32;
            {
                let tcp = p.headers_mut().tcp_mut(2);
                tcp.set_seq_num(c.seqn_nxt);
                c.ackn_nxt = tcp.ack_num();
                c.set_sock((client_ip, tcp.dst_port()));
            }
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            prepare_checksum_and_ttl(p);
            //trace!("(SYN-)ACK to client, L3: { }, L4: { }", h.ip, h.tcp);
        }

        #[inline]
        fn synack_received(p: &mut Pdu, c: &mut Connection) {
            make_reply_packet(p, 1);
            {
                let tcp = p.headers_mut().tcp_mut(2);
                c.ackn_nxt = tcp.ack_num();
                tcp.unset_syn_flag();
                tcp.set_seq_num(c.seqn_nxt);
            }
            prepare_checksum_and_ttl(p);
        }

        /// sends payload of p to client, if b_fin is true, sets FIN flag
        #[inline]
        fn s_reply_with_payload(p: &mut Pdu, c: &mut Connection, b_fin: bool) {
            make_reply_packet(p, 0);
            {
                let tcp = p.headers_mut().tcp_mut(2);
                c.ackn_nxt = tcp.ack_num();
                tcp.set_seq_num(c.seqn_nxt);
                tcp.unset_psh_flag();
                if b_fin {
                    tcp.set_fin_flag();
                }
            }
            let payload_sz = tcp_payload_size(p);
            c.seqn_nxt = c.seqn_nxt.wrapping_add(payload_sz as u32 + if b_fin { 1 } else { 0 });
            //if b_fin && h.tcp_payload_len()==0 { c.seqn_nxt = c.seqn_nxt.wrapping_add(1); }
            prepare_checksum_and_ttl(p);
        }

        #[inline]
        fn generate_syn(
            p: &mut Pdu,
            c: &mut Connection,
            me: &L234Data,
            servers: &Vec<L234Data>,
            pipeline_id: &PipelineId,
            syn_counter: &mut usize,
        ) {
            p.headers_mut().mac_mut(0).set_etype(0x0800); // overwrite private ethertype tag
            c.set_server_index(*syn_counter as usize % servers.len());
            set_header(&servers[c.server_index()], c.port(), p, &me.mac, me.ip);

            //generate seq number:
            c.seqn_nxt = (utils::rdtsc_unsafe() << SEQN_SHIFT) as u32;
            {
                let htcp = p.headers_mut().tcp_mut(2);
                htcp.set_seq_num(c.seqn_nxt);
                c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
                htcp.set_syn_flag();
                htcp.set_window_size(5840); // 4* MSS(1460)
                htcp.set_ack_num(0u32);
                htcp.unset_ack_flag();
                htcp.unset_psh_flag();
            }
            prepare_checksum_and_ttl(p);

            *syn_counter += 1;
            if *syn_counter % 1000 == 0 {
                debug!("{}: sent {} SYNs", pipeline_id, *syn_counter);
            }
        }

        #[inline]
        fn generate_fin(p: &mut Pdu, c: &mut Connection, me: &L234Data, servers: &Vec<L234Data>) {
            p.headers_mut().mac_mut(0).set_etype(0x0800); // overwrite private ethertype tag
            set_header(&servers[c.server_index()], c.port(), p, &me.mac, me.ip);
            {
                let tcp = p.headers_mut().tcp_mut(2);
                tcp.set_seq_num(c.seqn_nxt);
                c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
                tcp.set_fin_flag();
                tcp.unset_syn_flag();
                tcp.set_window_size(5840); // 4* MSS(1460)
                tcp.set_ack_num(c.ackn_nxt);
                tcp.set_ack_flag();
                tcp.unset_psh_flag();
            }
            prepare_checksum_and_ttl(p)
        }

        #[inline]
        fn prepare_payload_packet(c: &mut Connection, p: &mut Pdu, me: &L234Data, servers: &Vec<L234Data>) {
            p.headers_mut().mac_mut(0).set_etype(0x0800); // overwrite private ethertype tag
            set_header(&servers[c.server_index()], c.port(), p, &me.mac, me.ip);
            let tcp = p.headers_mut().tcp_mut(2);
            tcp.set_seq_num(c.seqn_nxt);
            tcp.unset_syn_flag();
            tcp.set_window_size(5840); // 4* MSS(1460)
            tcp.set_ack_num(c.ackn_nxt);
            tcp.set_ack_flag();
            tcp.set_psh_flag();
        }

        #[inline]
        fn passive_close(p: &mut Pdu, c: &mut Connection, thread_id: &String, counter: &mut TcpCounter) {
            debug!(
                "{} passive close on src/dst-port {}/{} in state {:?}",
                thread_id,
                p.headers().tcp(2).src_port(),
                p.headers().tcp(2).dst_port(),
                c.state(),
            );
            c.set_release_cause(ReleaseCause::PassiveClose);
            counter[TcpStatistics::RecvFin] += 1;
            c.push_state(TcpState::LastAck);
            make_reply_packet(p, 1);
            {
                let tcp = p.headers_mut().tcp_mut(2);
                c.ackn_nxt = tcp.ack_num();
                tcp.set_ack_flag();
                tcp.set_seq_num(c.seqn_nxt);
            }
            c.seqn_nxt = c.seqn_nxt.wrapping_add(1);
            strip_payload(p);
            prepare_checksum_and_ttl(p);
            counter[TcpStatistics::SentFinPssv] += 1;
            counter[TcpStatistics::SentAck4Fin] += 1;
        };

        #[inline]
        fn active_close(p: &mut Pdu, c: &mut Connection, counter: &mut TcpCounter, state: &TcpState) -> bool {
            let mut tcp_closed = false;
            {
                let tcp = p.headers_mut().tcp_mut(2);
                if tcp.ack_flag() && tcp.ack_num() == c.seqn_nxt {
                    // we got a FIN+ACK as a receipt to a sent FIN (engine closed connection)
                    /*
                    debug!(
                        "active close: received FIN+ACK-reply from DUT {:?}:{:?}",
                        p.stack().ip(1).src(),
                        tcp.src_port()
                    );
                    */
                    counter[TcpStatistics::RecvFinPssv] += 1;
                    c.push_state(TcpState::Closed);
                    tcp_closed = true;
                } else {
                    // no ACK
                    /*
                    debug!(
                        "active close: received FIN-reply from DUT {:?}/{:?}",
                        p.stack().ip(1).src(),
                        p.stack().tcp(2).src_port()
                    );
                    */
                    counter[TcpStatistics::RecvFinPssv] += 1;
                    if *state == TcpState::FinWait1 {
                        c.push_state(TcpState::Closing);
                    } else if *state == TcpState::FinWait2 {
                        c.push_state(TcpState::Closed);
                        tcp_closed = true
                    }
                }
            }
            make_reply_packet(p, 1);
            {
                let tcp = p.headers_mut().tcp_mut(2);
                tcp.unset_fin_flag();
                tcp.set_ack_flag();
                c.ackn_nxt = tcp.ack_num();
                tcp.set_seq_num(c.seqn_nxt);
            }
            strip_payload(p);
            prepare_checksum_and_ttl(p);
            counter[TcpStatistics::SentAck4Fin] += 1;
            tcp_closed
        };

        #[inline]
        ///increments ack4fin counter, checks for stop_stamp and updates holding time counter
        fn recv_ack4fin(
            c: &mut Connection,
            counter: &mut usize,
            nr_connections: usize,
            stop_stamp: &mut u64,
            hold: &mut HoldingTime,
        ) {
            *counter += 1;
            if *counter == nr_connections {
                *stop_stamp = utils::rdtscp_unsafe()
            }
            hold.add_hold(c.seqn_nxt >> SEQN_SHIFT);
        }

        // *****  the closure starts here with processing

        #[cfg(feature = "profiling")]
        let timestamp_entry = utils::rdtsc_unsafe();

        let c_recv_payload = |p: &mut Pdu, c: &mut Connection| {
            let mut b_fin = false;
            f_set_payload(p, c, None, &mut b_fin);
            if !b_fin {
                c.inc_sent_payload_pkts();
                p.headers_mut().tcp_mut(2).set_seq_num(c.seqn_nxt);
                let payload_sz = tcp_payload_size(p);
                c.seqn_nxt = c.seqn_nxt.wrapping_add(payload_sz as u32);
                make_reply_packet(p, 0);
                p.headers_mut().tcp_mut(2).set_ack_num(c.ackn_nxt);
                prepare_checksum_and_ttl(p);
            } else {
                generate_fin(p, c, &me, &servers);
                c.set_release_cause(ReleaseCause::ActiveClose);
                c.push_state(TcpState::FinWait1);
            }
            b_fin
        };

        let pipeline_ip = cm_c.ip();
        let tcp_port_base = cm_c.tcp_port_base();
        let b_private_etype;
        {
            let mac_header = pdu.headers().mac(0);
            b_private_etype = private_etype(&mac_header.etype());
            if !b_private_etype {
                if mac_header.dst != me.mac && !mac_header.dst.is_multicast() && !mac_header.dst.is_broadcast() {
                    debug!("{} from pci: discarding because mac unknown: {} ", thread_id, mac_header);
                    return 0;
                }
                if mac_header.etype() != 0x0800 && !b_private_etype {
                    // everything other than Ipv4 or our own packets we send to KNI, i.e. group 2
                    return 2;
                }
            }
        }

        {
            let ip_header = pdu.headers().ip(1);
            if !b_private_etype {
                // everything other than TCP, and everything not addressed to us we send to KNI, i.e. group 2
                if ip_header.protocol() != 6 || ip_header.dst() != pipeline_ip && ip_header.dst() != me.ip {
                    return 2;
                }
            }
        }

        if csum_offload {
            pdu.set_tcp_ipv4_checksum_tx_offload();
        }
        let mut group_index = 0usize; // the index of the group to be returned, default 0: dump packet

        let src_sock = (pdu.headers().ip(1).src(), pdu.headers().tcp(2).src_port());
        let dst_sock = (pdu.headers().ip(1).dst(), pdu.headers().tcp(2).dst_port());

        //check ports
        if !b_private_etype && pdu.headers().tcp(2).dst_port() != me.port && pdu.headers().tcp(2).dst_port() < tcp_port_base
        {
            return 2;
        }

        // if set by the following tcp state machine,
        // the port/connection becomes released/ready afterwards
        // this is cumbersome, but we must make the  borrow checker happy
        let mut b_release_connection_c = false;
        let mut b_release_connection_s = false;
        let mut ready_connection = None;
        let server_listen_port = cm_c.listen_port();

        let nr_connections = run_configuration.engine_configuration.test_size.unwrap_or(128);
        // check if we got a packet from generator
        match (pdu.headers().mac(0).etype(), pdu.headers().tcp(2).dst_port()) {
            // SYN injection
            (PRIVATE_ETYPE_PACKET, 1) => {
                if counter_c[TcpStatistics::SentSyn] == 0 {
                    start_stamp = utils::rdtscp_unsafe();
                }
                if counter_c[TcpStatistics::SentSyn] < nr_connections {
                    //info!("syn= {}, ack= {}, open= {}", counter_c[TcpStatistics::SentSyn], counter_c[TcpStatistics::RecvSynAck], cm_c.concurrent_connections());
                    //assert!(counter_c[TcpStatistics::SentSyn]- counter_c[TcpStatistics::RecvSynAck] <= max_open);
                    if cm_c.concurrent_connections() < max_open {
                        if let Some(c) = cm_c.create(TcpRole::Client) {
                            generate_syn(
                                pdu,
                                c,
                                &me,
                                &servers,
                                &pipeline_id_clone,
                                &mut counter_c[TcpStatistics::SentSyn],
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
                //let mut ready_connection = None;
                if let Some(c) = cm_c.get_ready_connection() {
                    prepare_payload_packet(c, pdu, &me, &servers);
                    let mut b_fin = false;
                    cdata.client_port = c.port();
                    cdata.uuid = c.uid();
                    f_set_payload(pdu, c, Some(cdata), &mut b_fin);
                    /*
                    let pp = c.sent_payload_pkts();
                    if pp < 1 {
                        cdata.client_port = c.port();
                        cdata.uuid = c.uid();
                        //trace!("{} client: sending payload on port {}", thread_id, cdata.client_port);
                        let mut buf = [0u8;16];
                        serialize_into(& mut buf[..], &cdata).expect("cannot serialize");
                        //let buf = serialize(&cdata).unwrap();
                        make_payload_packet(&mut pdu, c, &mut hs, &me, &servers, &buf);
                        c.inc_sent_payload_pkts();
                        counter_c[TcpStatistics::SentPayload] += 1;
                        // requeue
                        ready_connection = Some(c.port());
                        group_index = 1;
                    } else if pp == fin_by_client && c.state() < TcpState::CloseWait {
                        generate_fin(&mut pdu, c, &mut hs, &me, &servers, &mut counter_c[TcpStatistics::SentFin]);
                        c.set_release_cause(ReleaseCause::ActiveClose);
                        c.push_state(TcpState::FinWait1);
                        group_index = 1;
                    }
                    */
                    if !b_fin {
                        c.inc_sent_payload_pkts();
                        counter_c[TcpStatistics::SentPayload] += 1;
                        c.seqn_nxt = c.seqn_nxt.wrapping_add(tcp_payload_size(pdu) as u32);
                        if pdu.data_len() < MIN_FRAME_SIZE {
                            let n_padding_bytes = MIN_FRAME_SIZE - pdu.data_len();
                            debug!("padding with {} 0x0 bytes", n_padding_bytes);
                            pdu.increase_payload_size(n_padding_bytes);
                        }
                        prepare_checksum_and_ttl(pdu);
                        // requeue
                        // ready_connection = Some(c.port());
                        group_index = 1;
                    } else {
                        generate_fin(pdu, c, &me, &servers);
                        counter_c[TcpStatistics::SentFin] += 1;
                        c.set_release_cause(ReleaseCause::ActiveClose);
                        c.push_state(TcpState::FinWait1);
                        group_index = 1;
                    }
                    #[cfg(feature = "profiling")]
                    time_adders[5].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                } else {
                    if payload_injector_runs() {
                        payload_injector_stop();
                    }
                }
                //if let Some(port) = ready_connection {
                //    cm_c.set_ready_connection(port, &payload_injector_ready_flag);
                //}
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
                                counter_c.clone(),
                                counter_s.clone(),
                                Some(rx_tx_stats.clone()),
                            ))
                            .unwrap();
                        #[cfg(not(feature = "profiling"))]
                        tx_clone
                            .send(MessageFrom::Counter(
                                pipeline_id_clone.clone(),
                                counter_c.clone(),
                                counter_s.clone(),
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
                        //trace!("{} got FetchCrecords", thread_id);
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
                //
                // **** server side ****
                //
                let opt_c = if pdu.headers().tcp(2).syn_flag() {
                    debug!(
                        "{} server: got SYN with src = {:?} on server listen port 0x{:x}",
                        thread_id, src_sock, server_listen_port
                    );
                    counter_s[TcpStatistics::RecvSyn] += 1;
                    let c = cm_s.get_mut_or_insert(&src_sock);
                    #[cfg(feature = "profiling")]
                    time_adders[11].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                    c
                } else {
                    cm_s.get_mut(&src_sock)
                };

                match opt_c {
                    None => warn!(
                        "no state for this packet on server port: src_sock= {:?}, tcp = {:?} ",
                        src_sock,
                        pdu.headers().tcp(2)
                    ),
                    Some(mut c) => {
                        let old_s_state = c.state().clone();
                        //check seqn
                        if old_s_state != TcpState::Listen && pdu.headers().tcp(2).seq_num() != c.ackn_nxt {
                            let diff = pdu.headers().tcp(2).seq_num() as i64 - c.ackn_nxt as i64;
                            if diff > 0 {
                                warn!(
                                    "{} server: unexpected seqn (packet loss?) in state {:?}, seqn differs by {}\ntcp = {}",
                                    thread_id,
                                    old_s_state,
                                    diff,
                                    pdu.headers().tcp(2)
                                );
                            } else {
                                debug!(
                                    "{} server: state= {:?}, diff= {}, tcp= {}",
                                    thread_id,
                                    old_s_state,
                                    diff,
                                    pdu.headers().tcp(2)
                                );
                            }
                        } else {
                            // process payload
                            let payload_sz = tcp_payload_size(pdu);
                            let b_payload = old_s_state >= TcpState::Established && payload_sz > 0;
                            if b_payload {
                                counter_s[TcpStatistics::RecvPayload] += 1;
                                c.inc_recv_payload_pkts();
                                //trace!("server: got payload, count= {}", c.recv_payload_pkts());
                                if c.recv_payload_pkts() == 1 && detailed_records {
                                    //first payload packet
                                    match deserialize::<CData>(pdu.get_payload(2)) {
                                        Ok(cdata) => {
                                            let uuid = cdata.uuid;
                                            debug!("{} server: received payload {:?}", thread_id, cdata);
                                            c.set_uid(uuid);
                                        }
                                        _ => (),
                                    }
                                }
                                c.ackn_nxt = pdu.headers().tcp(2).seq_num().wrapping_add(payload_sz as u32);
                            }

                            if pdu.headers().tcp(2).syn_flag() {
                                // check flags
                                if old_s_state == TcpState::Listen {
                                    // replies with a SYN-ACK to client:
                                    syn_received(pdu, c);
                                    c.set_server_index(rxq as usize); // we misuse this field for the queue number
                                    c.wheel_slot_and_index = wheel_s.schedule(
                                        &(timeouts.established.unwrap() * system_data.cpu_clock / 1000),
                                        c.sock().unwrap(),
                                    );
                                    counter_s[TcpStatistics::SentSynAck] += 1;
                                    group_index = 1;
                                    #[cfg(feature = "profiling")]
                                    time_adders[1].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                                } else {
                                    warn!("{} received SYN in state {:?}", thread_id, c.states());
                                }
                            } else if pdu.headers().tcp(2).fin_flag() {
                                //trace!("server: received FIN");
                                if old_s_state >= TcpState::FinWait1 {
                                    if active_close(pdu, c, &mut counter_s, &old_s_state) {
                                        b_release_connection_s = true;
                                    }
                                    if pdu.headers().tcp(2).ack_flag() && pdu.headers().tcp(2).ack_num() == c.seqn_nxt {
                                        counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    }
                                    group_index = 1;
                                } else {
                                    // DUT wants to close connection
                                    passive_close(pdu, c, &thread_id, &mut counter_s);
                                    group_index = 1;
                                }
                                #[cfg(feature = "profiling")]
                                time_adders[8].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                            } else if pdu.headers().tcp(2).rst_flag() {
                                //trace!("server: received RST");
                                counter_s[TcpStatistics::RecvRst] += 1;
                                c.push_state(TcpState::Closed);
                                c.set_release_cause(ReleaseCause::PassiveRst);
                                // release connection in the next block
                                b_release_connection_s = true;
                            } else if pdu.headers().tcp(2).ack_flag() && pdu.headers().tcp(2).ack_num() == c.seqn_nxt {
                                match old_s_state {
                                    TcpState::SynReceived => {
                                        c.push_state(TcpState::Established);
                                        counter_s[TcpStatistics::RecvSynAck2] += 1;
                                        debug!("{} server: connection from DUT ({:?}) established", thread_id, src_sock);
                                        #[cfg(feature = "profiling")]
                                        time_adders[2].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                                    }
                                    TcpState::LastAck => {
                                        // received final ack in passive close
                                        //trace!("server: received final ACK in passive close");
                                        counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                        c.push_state(TcpState::Closed);
                                        c.set_release_cause(ReleaseCause::PassiveClose);
                                        // release connection in the next block
                                        b_release_connection_s = true;
                                    }
                                    TcpState::FinWait1 => {
                                        c.push_state(TcpState::FinWait2);
                                        counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                    }
                                    TcpState::Closing => {
                                        c.push_state(TcpState::Closed);
                                        counter_s[TcpStatistics::RecvAck4Fin] += 1;
                                        b_release_connection_s = true;
                                    }
                                    _ => (),
                                }
                            }

                            if b_payload && old_s_state == TcpState::Established {
                                let b_fin = c.recv_payload_pkts() >= fin_by_server;
                                if b_fin {
                                    //trace!("server: reply with payload and FIN");
                                    counter_s[TcpStatistics::SentFin] += 1;
                                    c.set_release_cause(ReleaseCause::ActiveClose);
                                    c.push_state(TcpState::FinWait1);
                                } else {
                                    //trace!("server: reply with payload");
                                }
                                // sets also c.ackn_nxt
                                s_reply_with_payload(pdu, &mut c, b_fin);
                                counter_s[TcpStatistics::SentPayload] += 1;
                                c.inc_sent_payload_pkts();
                                group_index = 1;
                            }
                        }

                        #[cfg(feature = "profiling")]
                        time_adders[3].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                    }
                }
            }

            (ETYPE_IPV4, client_port) => {
                //
                // **** client side ****
                //
                // check that flow steering worked:
                if !cm_c.owns_tcp_port(client_port) {
                    error!("flow steering failed {}", pdu.headers().tcp(2));
                }
                let c = cm_c.get_mut_by_port(client_port);
                #[cfg(feature = "profiling")]
                time_adders[0].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                match c {
                    None => {
                        warn!(
                            "{} @ {} client: engine has no state for port {} ({}-{}), sending to KNI i/f",
                            thread_id,
                            utils::rdtsc_unsafe().separated_string(),
                            client_port,
                            pdu.headers().ip(1),
                            pdu.headers().tcp(2),
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
                        if old_c_state != TcpState::SynSent && pdu.headers().tcp(2).seq_num() != c.ackn_nxt {
                            let diff = pdu.headers().tcp(2).seq_num() as i64 - c.ackn_nxt as i64;
                            if diff > 0 {
                                warn!(
                                    "{} client: unexpected sequence number (packet loss?) in state {:?}, seqn differs by {}\ntcp = { }",
                                    thread_id, old_c_state, diff, pdu.headers().tcp(2)
                                );
                            } else {
                                debug!(
                                    "{} state= {:?}, diff= {}, tcp= {}",
                                    thread_id,
                                    old_c_state,
                                    diff,
                                    pdu.headers().tcp(2)
                                );
                            }
                        } else {
                            //check for payload
                            let payload_sz = tcp_payload_size(pdu);
                            let b_payload = old_c_state >= TcpState::Established && payload_sz > 0;
                            if b_payload {
                                counter_c[TcpStatistics::RecvPayload] += 1;
                                c.inc_recv_payload_pkts();
                                //trace!("client: got payload, count= {}", c.sent_payload_pkts());
                                c.ackn_nxt = pdu.headers().tcp(2).seq_num().wrapping_add(payload_sz as u32);
                            }

                            if pdu.headers().tcp(2).ack_flag() && pdu.headers().tcp(2).syn_flag() {
                                group_index = 1;
                                counter_c[TcpStatistics::RecvSynAck] += 1;
                                if old_c_state == TcpState::SynSent {
                                    c.push_state(TcpState::Established);
                                    ready_connection = Some(c.port());
                                    debug!(
                                        "{} client: connection for port {} to DUT ({:?}) established ",
                                        thread_id,
                                        c.port(),
                                        src_sock
                                    );
                                    synack_received(pdu, &mut c);
                                    counter_c[TcpStatistics::SentSynAck2] += 1;
                                } else if old_c_state == TcpState::Established {
                                    synack_received(pdu, &mut c);
                                    counter_c[TcpStatistics::SentSynAck2] += 1;
                                } else {
                                    warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_c_state);
                                    group_index = 0;
                                } // ignore the SynAck
                            } else if pdu.headers().tcp(2).fin_flag() {
                                if old_c_state >= TcpState::FinWait1 {
                                    if pdu.headers().tcp(2).ack_flag() && pdu.headers().tcp(2).ack_num() == c.seqn_nxt {
                                        recv_ack4fin(
                                            c,
                                            &mut counter_c[TcpStatistics::RecvAck4Fin],
                                            nr_connections,
                                            &mut stop_stamp,
                                            &mut hold,
                                        );
                                    }
                                    if active_close(pdu, c, &mut counter_c, &old_c_state) {
                                        b_release_connection_c = true;
                                    }
                                    group_index = 1;
                                } else {
                                    passive_close(pdu, c, &thread_id, &mut counter_c);
                                    group_index = 1;
                                }
                                #[cfg(feature = "profiling")]
                                time_adders[7].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
                            } else if pdu.headers().tcp(2).rst_flag() {
                                counter_c[TcpStatistics::RecvRst] += 1;
                                c.push_state(TcpState::Closed);
                                c.set_release_cause(ReleaseCause::PassiveRst);
                                // release connection in the next block
                                b_release_connection_c = true;
                            } else if pdu.headers().tcp(2).ack_flag() && pdu.headers().tcp(2).ack_num() == c.seqn_nxt {
                                match old_c_state {
                                    TcpState::LastAck => {
                                        //trace!("received final ACK in passive close");
                                        recv_ack4fin(
                                            c,
                                            &mut counter_c[TcpStatistics::RecvAck4Fin],
                                            nr_connections,
                                            &mut stop_stamp,
                                            &mut hold,
                                        );
                                        c.push_state(TcpState::Closed);
                                        c.set_release_cause(ReleaseCause::PassiveClose);
                                        // release connection in the next block
                                        b_release_connection_c = true;
                                    }
                                    TcpState::FinWait1 => {
                                        c.push_state(TcpState::FinWait2);
                                        recv_ack4fin(
                                            c,
                                            &mut counter_c[TcpStatistics::RecvAck4Fin],
                                            nr_connections,
                                            &mut stop_stamp,
                                            &mut hold,
                                        );
                                    }
                                    TcpState::Closing => {
                                        c.push_state(TcpState::Closed);
                                        recv_ack4fin(
                                            c,
                                            &mut counter_c[TcpStatistics::RecvAck4Fin],
                                            nr_connections,
                                            &mut stop_stamp,
                                            &mut hold,
                                        );
                                        b_release_connection_c = true;
                                    }
                                    TcpState::Established if b_payload => {
                                        if !c_recv_payload(pdu, c) {
                                            counter_c[TcpStatistics::SentPayload] += 1;
                                        } else {
                                            counter_c[TcpStatistics::SentFin] += 1;
                                        }
                                        group_index = 1;
                                    }
                                    _ => (),
                                }
                            } else if b_payload && old_c_state == TcpState::Established {
                                if !c_recv_payload(pdu, c) {
                                    counter_c[TcpStatistics::SentPayload] += 1;
                                } else {
                                    counter_c[TcpStatistics::SentFin] += 1;
                                }
                                group_index = 1;
                            } else if !pdu.headers().tcp(2).ack_flag() {
                                counter_c[TcpStatistics::Unexpected] += 1;
                                warn!(
                                    "{} unexpected TCP packet on port {} in client state {:?}, sending to KNI i/f: {}",
                                    thread_id,
                                    pdu.headers().tcp(2).dst_port(),
                                    c.states(),
                                    pdu.headers().tcp(2),
                                );
                                group_index = 2;
                            }
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
            debug!("releasing client connection on port {}", dst_sock.1);
            cm_c.release(dst_sock.1, &mut wheel_c);
            #[cfg(feature = "profiling")]
            time_adders[9].add_diff(utils::rdtscp_unsafe() - timestamp_entry);
        }
        if let Some(sport) = ready_connection {
            //trace!("{} connection on port {} is ready", thread_id, sport);
            cm_c.set_ready_connection(sport, &payload_injector_ready_flag);
            #[cfg(feature = "profiling")]
            time_adders[6].add_diff(utils::rdtsc_unsafe() - timestamp_entry);
        }
        group_index
    };

    // process TCP traffic addressed to Proxy
    let mut l4groups = l2_input_stream.group_by(3, group_by_closure, sched, "L4-Groups".to_string(), uuid_l4groupby_clone);

    let pipe2kni = l4groups.get_group(2).unwrap().send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap();
    let l4dumpflow = l4groups.get_group(0).unwrap().drop();
    let pipe2pci = merge_auto(vec![box l4pciflow, box l4dumpflow], SchedulingPolicy::LongestQueue).send(pci.clone());

    let uuid_pipe2kni = install_task(sched, "Pipe2Kni", pipe2kni);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();

    let uuid_pipe2pic = install_task(sched, "Pipe2Pci", pipe2pci);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pic, TaskType::Pipe2Pci))
        .unwrap();
}
