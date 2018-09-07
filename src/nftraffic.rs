use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::native::zcsi::rte_kni_handle_request;
use e2d2::headers::{NullHeader, IpHeader, MacHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::utils::{finalize_checksum, ipv4_extract_flow};
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::headers::EndOffset;
use e2d2::common::EmptyMetadata;
use e2d2::utils;
use e2d2::native::zcsi::{ mbuf_alloc_bulk, MBuf};

use std::sync::Arc;
use std::cmp::min;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::ops::BitAnd;

use eui48::MacAddress;
use ipnet::Ipv4Net;
use uuid::Uuid;

use rand;
use cmanager::*;
use Configuration;
use {PipelineId, MessageFrom, MessageTo, TaskType};
use std::sync::mpsc::SyncSender;

const MIN_FRAME_SIZE: usize = 60; // without fcs

pub struct KniHandleRequest {
    pub kni_port: Arc<PmdPort>,
}

impl Executable for KniHandleRequest {
    fn execute(&mut self) -> u32 {
        unsafe {
            rte_kni_handle_request(self.kni_port.get_kni());
        }
        1
    }
}

pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_kni(kni_name: &str, ip_address: &str, mac_address: &str, kni_netns: &str) {
    debug!("setup_kni");
    //# ip link set dev vEth1 address XX:XX:XX:XX:XX:XX
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "address", mac_address])
        .output()
        .expect("failed to assign MAC address to kni i/f");
    let reply = output.stderr;

    debug!(
        "assigning MAC addr {} to {}: {}, {}",
        mac_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    //# ip netns add nskni
    let output = Command::new("ip")
        .args(&["netns", "add", kni_netns])
        .output()
        .expect("failed to create namespace for kni i/f");
    let reply = output.stderr;

    debug!(
        "creating network namespace {}: {}, {}",
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // ip link set dev vEth1 netns nskni
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "netns", kni_netns])
        .output()
        .expect("failed to move kni i/f to namespace");
    let reply = output.stderr;

    debug!(
        "moving kni i/f {} to namesapce {}: {}, {}",
        kni_name,
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // e.g. ip netns exec nskni ip addr add w.x.y.z/24 dev vEth1
    let output = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "addr", "add", ip_address, "dev", kni_name])
        .output()
        .expect("failed to assign IP address to kni i/f");
    let reply = output.stderr;
    debug!(
        "assigning IP addr {} to {}: {}, {}",
        ip_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );
    // e.g. ip netns exec nskni ip link set dev vEth1 up
    let output1 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "link", "set", "dev", kni_name, "up"])
        .output()
        .expect("failed to set kni i/f up");
    let reply1 = output1.stderr;
    debug!(
        "ip netns exec {} ip link set dev {} up: {}, {}",
        kni_netns,
        kni_name,
        output1.status,
        String::from_utf8_lossy(&reply1)
    );
    // e.g. ip netns exec nskni ip addr show dev vEth1
    let output2 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "addr", "show", "dev", kni_name])
        .output()
        .expect("failed to show IP address of kni i/f");
    let reply2 = output2.stdout;
    info!("show IP addr: {}\n {}", output.status, String::from_utf8_lossy(&reply2));
}

pub struct PacketInjector {
    mac: MacHeader,
    ip: IpHeader,
    tcp: TcpHeader,
    packet_prototype: Packet<TcpHeader, EmptyMetadata>,
    producer: MpscProducer,
    tx: Sender<MessageFrom>,
    no_batches: u32,
    sent_batches: u32,
    used_cycles: Vec<u64>,
    pipeline_id: PipelineId,
}


pub const PRIVATE_ETYPE_TAG: u16 = 0x08FF;

impl PacketInjector {
    // by setting no_batches=0 batch creation is unlimited
    pub fn new(
        producer: MpscProducer,
        hd_src_data: &L234Data,
        no_batches: u32,
        pipeline_id: PipelineId,
        tx: Sender<MessageFrom>,
    ) -> PacketInjector {
        let mut mac = MacHeader::new();
        mac.src = hd_src_data.mac.clone();
        mac.set_etype(PRIVATE_ETYPE_TAG); // mark this through an unused ethertype as an internal frame, will be re-written later in the pipeline
        let mut ip = IpHeader::new();
        ip.set_src(u32::from(hd_src_data.ip));
        ip.set_ttl(128);
        ip.set_version(4);
        ip.set_protocol(6); //tcp
        ip.set_ihl(5);
        ip.set_length(40);
        ip.set_flags(0x2); // DF=1, MF=0 flag: don't fragment
        let mut tcp = TcpHeader::new();
        tcp.set_syn_flag();
        tcp.set_src_port(hd_src_data.port);
        tcp.set_data_offset(5);
        let packet_prototype = new_packet()
            .unwrap()
            .push_header(&mac)
            .unwrap()
            .push_header(&ip)
            .unwrap()
            .push_header(&tcp)
            .unwrap();

        PacketInjector {
            mac,
            ip,
            tcp,
            packet_prototype,
            producer,
            no_batches,
            sent_batches: 0,
            used_cycles: vec![0;4],
            pipeline_id,
            tx,
        }
    }

    #[inline]
    pub fn create_packet(&mut self) -> Packet<TcpHeader, EmptyMetadata> {
        //let begin = utils::rdtsc_unsafe();
        let p = unsafe { self.packet_prototype.copy() };
        //self.used_cycles += (utils::rdtsc_unsafe() - begin);
        p
    }

    #[inline]
    pub fn create_packet_from_mbuf(&mut self, mbuf: *mut MBuf) -> Packet<TcpHeader, EmptyMetadata> {
        //let begin = utils::rdtsc_unsafe();
        let p = unsafe { self.packet_prototype.copy_use_mbuf(mbuf) };
        //self.used_cycles += (utils::rdtsc_unsafe() - begin);
        p
    }
}

impl Executable for PacketInjector {
    fn execute(&mut self) -> u32 {
        let mut count = 0;
        if self.no_batches == 0 || self.sent_batches < self.no_batches {
            let begin = utils::rdtsc_unsafe();
            let mut mbuf_ptr_array= Vec::<* mut MBuf>::with_capacity(16 as usize);
            let ret = unsafe { mbuf_alloc_bulk(mbuf_ptr_array.as_mut_ptr(), 16) };
            assert_eq!(ret, 0);
            unsafe { mbuf_ptr_array.set_len(16) };
            self.used_cycles[1] += (utils::rdtsc_unsafe() - begin);
            for i in 0..16 {
                let p = self.create_packet_from_mbuf(mbuf_ptr_array[i]);
                //self.producer.enqueue_one(p);
                count += 1;
            }
            self.producer.enqueue_mbufs(&mbuf_ptr_array);
            self.sent_batches += 1;
            if self.sent_batches == self.no_batches {
                self.used_cycles[0] += (utils::rdtsc_unsafe() - begin);
                self.tx.send(MessageFrom::GenTimeStamp(
                    self.pipeline_id.clone(),
                    self.sent_batches as u64,
                    self.used_cycles[0],
                    self.used_cycles[1],
                )).unwrap();
            }
            else { self.used_cycles[0] += (utils::rdtsc_unsafe() - begin) };
        }
        count
    }
}

pub fn setup_generator(
    core: i32,
    pci: &CacheAligned<PortQueue>,
    kni: &CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    configuration: &Configuration,
    servers: Vec<L234Data>,
    tx: Sender<MessageFrom>,
) {
    let me = L234Data {
        mac: MacAddress::parse_str(&configuration.engine.mac).unwrap(),
        ip: u32::from(configuration.engine.ipnet.parse::<Ipv4Net>().unwrap().addr()),
        port: configuration.engine.port,
        //TODO change server_id to u32, performance!
        // server_id: "TrafficEngine".to_string(),
    };

    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port.port_id() as u16,
        rxq: pci.rxq(),
    };
    debug!("enter setup_generator {}", pipeline_id);

    let mut sm: ConnectionManager = ConnectionManager::new(pipeline_id.clone(), pci.clone(), me.clone(), configuration.clone());

    // setting up a a reverse message channel between this pipeline and the main program thread
    debug!("setting up reverse channel from pipeline {}", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo>();
    // we send the transmitter to the remote receiver of our messages
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();

    // forwarding frames coming from KNI to PCI, if we are the kni core
    if is_kni_core(pci) {
        let forward2pci = ReceiveBatch::new(kni.clone())
            .parse::<MacHeader>()
            //.transform(box move |p| {
            //    let ethhead = p.get_mut_header();
            //    //debug!("sending KNI frame to PCI: Eth header = { }", &ethhead);
            //})
            .send(pci.clone());
        let uuid = Uuid::new_v4();
        let name = String::from("Kni2Pci");
        sched.add_runnable(Runnable::from_task(uuid, name, forward2pci).ready());
    }
    let thread_id_0 = format!("<c{}, rx{}>: ", core, pci.rxq());
    let thread_id_1 = format!("<c{}, rx{}>: ", core, pci.rxq());
    let thread_id_2 = format!("<c{}, rx{}>: ", core, pci.rxq());

    let me_clone = me.clone();
    // only accept traffic from PCI with matching L2 address
    let l2filter_from_pci = ReceiveBatch::new(pci.clone()).parse::<MacHeader>().filter(box move |p| {
        let header = p.get_header();
        if header.dst == me_clone.mac {
            //debug!("{} from pci: found mac: {} ", thread_id_0, &header);
            true
        } else if header.dst.is_multicast() || header.dst.is_broadcast() {
            //debug!("{} from pci: multicast mac: {} ", thread_id_0, &header);
            true
        } else {
            debug!("{} from pci: discarding because mac unknown: {} ", thread_id_0, &header);
            false
        }
    });

    let tcp_min_port = sm.tcp_port_base();
    let pd_clone = me.clone();
    let uuid_l2groupby = Uuid::new_v4();
    let uuid_l2groupby_clone = uuid_l2groupby.clone();
    // group the traffic into TCP traffic addressed to Proxy (group 1),
    // and send all other traffic to KNI (group 0)
    let mut l2groups = l2filter_from_pci.group_by(
        2,
        box move |p| {
            let payload = p.get_payload();
            let ipflow = ipv4_extract_flow(payload);
            if ipflow.is_none() {
                debug!("{} not ip_flow", thread_id_1);
                0
            } else {
                let ipflow = ipflow.unwrap();
                if ipflow.dst_ip == pd_clone.ip && ipflow.proto == 6 {
                    if ipflow.dst_port == pd_clone.port || ipflow.dst_port >= tcp_min_port {
                        //debug!("{} proxy tcp flow: {}", thread_id_1, ipflow);
                        1
                    } else {
                        //debug!("{} no proxy tcp flow: {}", thread_id_1, ipflow);
                        0
                    }
                } else {
                    //debug!("{} ignored by proxy: not a tcp flow or not addressed to proxy", thread_id_1);
                    0
                }
            }
        },
        sched,
        uuid_l2groupby_clone,
    );
    // we create SYN packets and merge them with the upstream from the pci i/f
    let tx_clone = tx.clone();
    let (producer, consumer) = new_mpsc_queue_pair();
    let creator = PacketInjector::new(producer, &me, 512, pipeline_id.clone(), tx_clone.clone());
    let mut syn_counter = 0u64;
    let mut cycles: Vec<u64> = vec![0, 0, 0];

    let uuid = Uuid::new_v4();
    let name = String::from("PacketInjector");
    sched.add_runnable(Runnable::from_task(uuid, name, creator).unready());
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid, TaskType::TcpGenerator))
        .unwrap();


    let pipeline_id_clone = pipeline_id.clone();

    let l2_input_stream = merge(vec![consumer.compose(), l2groups.get_group(1).unwrap().compose()]);
    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI
    let uuid_l4groupby = Uuid::new_v4();
    let uuid_l4groupby_clone = uuid_l4groupby.clone();
    // process TCP traffic addressed to Proxy
    let mut l4groups = l2_input_stream
        .parse::<MacHeader>()
        .parse::<IpHeader>()
        .parse::<TcpHeader>()
        .group_by(
            3,
            box move |p| {
                // this is the major closure for TCP processing
                struct HeaderState<'a> {
                    mac: &'a mut MacHeader,
                    ip: &'a mut IpHeader,
                    tcp: &'a mut TcpHeader,
                    //flow: Flow,
                }

                impl<'a> HeaderState<'a> {
                    #[inline]
                    fn set_server_socket(&mut self, ip: u32, port: u16) {
                        self.ip.set_dst(ip);
                        self.tcp.set_dst_port(port);
                    }
                }

                fn do_ttl(h: &mut HeaderState) {
                    let ttl = h.ip.ttl();
                    if ttl >= 1 {
                        h.ip.set_ttl(ttl - 1);
                    }
                    h.ip.update_checksum();
                }

                fn make_reply_packet(h: &mut HeaderState) {
                    let smac = h.mac.src;
                    let dmac = h.mac.dst;
                    let sip = h.ip.src();
                    let dip = h.ip.dst();
                    let sport = h.tcp.src_port();
                    let dport = h.tcp.dst_port();
                    h.mac.set_smac(&dmac);
                    h.mac.set_dmac(&smac);
                    h.ip.set_dst(sip);
                    h.ip.set_src(dip);
                    h.tcp.set_src_port(dport);
                    h.tcp.set_dst_port(sport);
                    h.tcp.set_ack_flag();
                    let ack_num = h.tcp.seq_num().wrapping_add(1);
                    h.tcp.set_ack_num(ack_num);
                }

                #[inline]
                fn set_header(server: &L234Data, port: u16, h: &mut HeaderState, me: &L234Data) {
                    h.mac.set_dmac(&server.mac);
                    h.mac.set_smac(&me.mac);
                    h.set_server_socket(server.ip, server.port);
                    h.ip.set_src(me.ip);
                    h.tcp.set_src_port(port);
                    h.ip.update_checksum();
                }

                #[inline]
                pub fn tcpip_payload_size<M: Sized + Send>(p: &Packet<TcpHeader, M>) -> u16 {
                    let iph = p.get_pre_header().unwrap();
                    // payload size = ip total length - ip header length -tcp header length
                    iph.length() - (iph.ihl() as u16) * 4u16 - (p.get_header().data_offset() as u16) * 4u16
                }

                fn server_synack_received<M: Sized + Send>(
                    p: &mut Packet<TcpHeader, M>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    seqn_inc: u32,
                ) {
                    make_reply_packet(h);
                    h.tcp.unset_syn_flag();
                    c.c_seqn = c.c_seqn.wrapping_add(seqn_inc);
                    h.tcp.set_seq_num(c.c_seqn);
                    update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                }

                #[inline]
                fn generate_syn<M: Sized + Send>(
                    p: &mut Packet<TcpHeader, M>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    me: &L234Data,
                    servers: &Vec<L234Data>,
                    tx: &Sender<MessageFrom>,
                    pipeline_id: &PipelineId,
                    syn_counter: &mut u64,
                ) {
                    h.mac.set_etype(0x0800); // overwrite private ethertype tag
                    c.con_rec.server_id = 0;
                    set_header(&servers[0], c.p_port(), h, me);

                    //generate seq number:
                    //TODO find more efficient method than random
                    //c.c_seqn = rand::random::<u32>();  //too expensive
                    c.c_seqn = 123456;
                    h.tcp.set_seq_num(c.c_seqn);
                    h.tcp.set_syn_flag();
                    h.tcp.set_window_size(5840); // 4* MSS(1460)
                    h.tcp.set_ack_num(0u32);
                    h.tcp.unset_ack_flag();
                    h.tcp.unset_psh_flag();

                    update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                    unsafe {
                        *syn_counter += 1;
                        if syn_counter.bitand(1023u64) == 0 || *syn_counter == 1u64 {
                            tx.send(MessageFrom::GenTimeStamp(
                                pipeline_id.clone(),
                                *syn_counter,
                                utils::rdtsc_unsafe(),
                                0,
                            )).unwrap();
                        }
                        if syn_counter.bitand(8191u64) == 0 {
                            tx.send(MessageFrom::PrintPerformance(vec![pipeline_id.core as i32])).unwrap();
                        }
                    }

                    debug!("SYN packet to server - L3: {}, L4: {}", h.ip, p.get_header());
                }

                let begin = utils::rdtsc_unsafe();
                let mut group_index = 0usize; // the index of the group to be returned

                assert!(p.get_pre_header().is_some()); // we must have parsed the headers
                assert!(p.get_pre_pre_header().is_some()); // we must have parsed the headers

                // converting to raw pointer avoids to borrow mutably from p
                let mut hs = HeaderState {
                    ip: unsafe { &mut *(p.get_mut_pre_header().unwrap() as *mut IpHeader) },
                    mac: unsafe { &mut *(p.get_mut_pre_pre_header().unwrap() as *mut MacHeader) },
                    tcp: unsafe { &mut *(p.get_mut_header() as *mut TcpHeader) },
                };

                // if set by the following tcp state machine,
                // the port/connection becomes released afterwards
                // this is cumbersome, but we must make the  borrow checker happy
                let mut release_connection = None;
                // check if we got a packet from generator
                if hs.mac.etype() == PRIVATE_ETYPE_TAG {
                    let opt_c = sm.create();
                    cycles[1] += (utils::rdtsc_unsafe() - begin);
                    if opt_c.is_some() {
                        let c = opt_c.unwrap();
                        generate_syn(p, c, &mut hs, &me, &servers, &tx_clone, &pipeline_id_clone, &mut syn_counter);
                        c.con_rec.c_state = TcpState::SynSent;
                        c.con_rec.s_state = TcpState::SynReceived;
                    };
                    group_index = 1;
                    cycles[0] += (utils::rdtsc_unsafe() - begin);
                    if syn_counter.bitand(1023u64) == 0 || syn_counter == 1u64 {
                        tx_clone
                            .send(MessageFrom::GenTimeStamp(
                                pipeline_id_clone.clone(),
                                syn_counter,
                                cycles[0],
                                cycles[1],
                            )).unwrap();
                    }
                } else {
                    // check that flow steering worked:
                    assert!(sm.owns_tcp_port(hs.tcp.dst_port()));

                    let mut c = sm.get_mut(hs.tcp.dst_port());
                    if c.is_some() {
                        let mut c = c.as_mut().unwrap();
                        let mut b_unexpected = false;
                        let old_s_state = c.con_rec.s_state;
                        let old_c_state = c.con_rec.c_state;

                        if hs.tcp.ack_flag() && hs.tcp.syn_flag() {
                            group_index = 1;
                            if (c.con_rec.s_state == TcpState::SynReceived) {
                                c.server_con_established();
                                tx_clone
                                    .send(MessageFrom::Established(pipeline_id_clone.clone(), c.con_rec.clone()))
                                    .unwrap();
                                debug!(
                                    "established two-way client server connection, SYN-ACK received: L3: {}, L4: {}",
                                    hs.ip, hs.tcp
                                );
                                server_synack_received(p, &mut c, &mut hs, 1u32);
                            } else if (c.con_rec.s_state == TcpState::Established) {
                                server_synack_received(p, &mut c, &mut hs, 0u32);
                            } else {
                                group_index = 0;
                            } // ignore the SynAck
                        } else if hs.tcp.fin_flag() {
                            if c.con_rec.c_state >= TcpState::FinWait {
                                // got FIN receipt to a client initiated FIN
                                debug!("received FIN-reply from server on port {}", hs.tcp.dst_port());
                                c.con_rec.s_state = TcpState::LastAck;
                                c.con_rec.c_state = TcpState::Closed;
                            } else {
                                // server initiated TCP close
                                debug!(
                                    "server closes connection on port {}/{} in state {:?}",
                                    hs.tcp.dst_port(),
                                    c.p_port(),
                                    c.con_rec.s_state,
                                );
                                c.con_rec.s_state = TcpState::FinWait;
                            }
                        } else if hs.tcp.rst_flag() {
                            c.con_rec.s_state = TcpState::Closed;
                            c.con_rec.c_state = TcpState::Listen;
                            c.con_rec.c_released(ReleaseCause::RstServer);
                            // release connection in the next block
                            release_connection = Some(c.p_port());
                        } else if c.con_rec.c_state == TcpState::LastAck && hs.tcp.ack_flag() {
                            // received final ack from server for server initiated close
                            debug!("received final ACK for server initiated close on port { }", hs.tcp.dst_port());
                            c.con_rec.s_state = TcpState::Closed;
                            c.con_rec.c_state = TcpState::Listen;
                            c.con_rec.c_released(ReleaseCause::FinServer);
                            // release connection in the next block
                            release_connection = Some(c.p_port());
                        } else {
                            // debug!("received from server { } in c/s state {:?}/{:?} ", hs.tcp, c.con_rec.c_state, c.con_rec.s_state);
                            b_unexpected = true; //  except we revise it, see below
                        }

                        if b_unexpected {
                            warn!(
                                "{} unexpected server side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                thread_id_2,
                                hs.tcp.dst_port(),
                                c.p_port(),
                                c.con_rec.c_state,
                                c.con_rec.s_state,
                            );
                            group_index = 2;
                        }
                    } else {
                        warn!("proxy has no state on port {}, sending to KNI i/f", hs.tcp.dst_port());
                        // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                        group_index = 2;
                    }
                }

                // here we check if we shall release the connection state,
                // required because of borrow checker for the state manager sm
                if let Some(sport) = release_connection {
                    debug!("releasing port {}", sport);
                    let con_rec = sm.release_port(sport);
                    if con_rec.is_some() {
                        tx_clone
                            .send(MessageFrom::CRecord(pipeline_id_clone.clone(), con_rec.unwrap()))
                            .unwrap()
                    };
                }
                do_ttl(&mut hs);
                group_index
            },
            sched,
            uuid_l4groupby_clone,
        );

    let l2kniflow = l2groups.get_group(0).unwrap().compose();
    let l4kniflow = l4groups.get_group(2).unwrap().compose();
    let pipe2kni = merge(vec![l2kniflow, l4kniflow]).send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap().compose();
    let l4dumpflow = l4groups.get_group(0).unwrap().filter(box move |_| false).compose();
    let pipe2pci = merge(vec![l4pciflow, l4dumpflow]).send(pci.clone());
    let uuid_pipe2kni = Uuid::new_v4();
    let name = String::from("Pipe2Kni");
    sched.add_runnable(Runnable::from_task(uuid_pipe2kni, name, pipe2kni).unready());
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();
    let uuid_pipe2pci = Uuid::new_v4();
    let name = String::from("Pipe2Pci");
    sched.add_runnable(Runnable::from_task(uuid_pipe2pci, name, pipe2pci).unready());
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pci, TaskType::Pipe2Pci))
        .unwrap();
}
