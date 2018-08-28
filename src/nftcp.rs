use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::native::zcsi::rte_kni_handle_request;
use e2d2::headers::{IpHeader, MacHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::utils::{finalize_checksum, ipv4_extract_flow};
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::headers::EndOffset;

use std::sync::Arc;
use std::cmp::min;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::mpsc::{channel, Sender, TryRecvError};

use eui48::MacAddress;
use ipnet::Ipv4Net;

use rand;
use cmanager::*;
use timer_wheel::TimerWheel;
use ProxyEngineConfig;
use { PipelineId, MessageFrom, MessageTo };


const MIN_FRAME_SIZE: usize = 60; // without fcs

pub struct KniHandleRequest {
    pub kni_port: Arc<PmdPort>,
}

impl Executable for KniHandleRequest {
    fn execute(&mut self) {
        unsafe {
            rte_kni_handle_request(self.kni_port.get_kni());
        }
    }
    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
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

pub fn setup_forwarder<F1, F2>(
    core: i32,
    pci: &CacheAligned<PortQueue>,
    kni: &CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    proxy_config: &ProxyEngineConfig,
    f_select_server: Arc<F1>,
    f_process_payload_c_s: Arc<F2>,
    tx: Sender<MessageFrom>,
) where
    F1: Fn(&mut Connection) + Sized + Send + Sync + 'static,
    F2: Fn(&mut Connection, &mut [u8], usize) + Sized + Send + Sync + 'static,
{
    let pd = L234Data {
        mac: MacAddress::parse_str(&proxy_config.proxy.mac).unwrap(),
        ip: u32::from(proxy_config.proxy.ipnet.parse::<Ipv4Net>().unwrap().addr()),
        port: proxy_config.proxy.port,
        server_id: "ProxyEngine".to_string(),
    };

    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port.port_id() as u16,
        rxq: pci.rxq(),
    };
    debug!("enter setup_forwarder {}", pipeline_id);

    let mut sm: ConnectionManager = ConnectionManager::new(pipeline_id.clone(), pci.clone(), pd.clone(), proxy_config.clone());
    let mut wheel = TimerWheel::new(128, 16, 128);

    // setting up a a reverse message channel between this pipeline and the main program thread
    debug!("setting up reverse channel from pipeline {}", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo>();
    // we send the transmitter to the remote receiver of our messages
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();


    // TODO let mut statistics = ProxyMessages::new(pci.rxq() );

    // we need this queue for the delayed bindrequest
    let (producer, consumer) = new_mpsc_queue_pair();

    // forwarding frames coming from KNI to PCI, if we are the kni core
    if is_kni_core(pci) {
        let forward2pci = ReceiveBatch::new(kni.clone())
            .parse::<MacHeader>()
            //.transform(box move |p| {
            //    let ethhead = p.get_mut_header();
            //    //debug!("sending KNI frame to PCI: Eth header = { }", &ethhead);
            //})
            .send(pci.clone());
        sched.add_task(forward2pci).unwrap();
    }
    let thread_id_0 = format!("<c{}, rx{}>: ", core, pci.rxq());
    let thread_id_1 = format!("<c{}, rx{}>: ", core, pci.rxq());
    let thread_id_2 = format!("<c{}, rx{}>: ", core, pci.rxq());

    let pd_clone = pd.clone();
    // only accept traffic from PCI with matching L2 address
    let l2filter_from_pci = ReceiveBatch::new(pci.clone()).parse::<MacHeader>().filter(box move |p| {
        let header = p.get_header();
        if header.dst == pd_clone.mac {
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
    let pd_clone = pd.clone();
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
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI

    // process TCP traffic addressed to Proxy
    let mut l4groups = l2groups.get_group(1).unwrap().parse::<IpHeader>().parse::<TcpHeader>().group_by(
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

            // remove tcp options for SYN and SYN-ACK,
            // pre-requisite: no payload exists, because any payload is not shifted up
            fn remove_tcp_options<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, h: &mut HeaderState) {
                let old_offset = h.tcp.offset() as u16;
                if old_offset > 20 {
                    debug!("trimming tcp-options by { } bytes", old_offset - 20);
                    h.tcp.set_data_offset(5u8);
                    // minimum mbuf data length is 60 bytes
                    h.ip.trim_length_by(old_offset - 20u16);
                    let trim_by = min(p.data_len() - 60usize, (old_offset - 20u16) as usize);
                    p.trim_payload_size(trim_by);
                    h.ip.update_checksum();
                }
            }

            fn client_syn_received<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, c: &mut Connection, h: &mut HeaderState) {
                c.con_rec.c_state = TcpState::SynSent;
                c.con_rec.s_state = TcpState::Listen;
                c.client_mac = h.mac.clone();
                c.set_client_sock(SocketAddrV4::new(Ipv4Addr::from(h.ip.src()), h.tcp.src_port()));
                // debug!("checksum in = {:X}",p.get_header().checksum());
                remove_tcp_options(p, h);
                make_reply_packet(h);
                //generate seq number:
                c.c_seqn = rand::random::<u32>();
                h.tcp.set_seq_num(c.c_seqn);
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                // debug!("checksum recalc = {:X}",p.get_header().checksum());
                debug!("(SYN-)ACK to client, L3: { }, L4: { }", h.ip, h.tcp);
            }

            fn set_proxy2server_headers(c: &mut Connection, h: &mut HeaderState, pd: &L234Data) {
                if c.server.is_none() {
                    error!("no server set: {}", c);
                }
                h.mac.set_dmac(&c.server.as_ref().unwrap().mac);
                h.mac.set_smac(&pd.mac);
                let l2l3 = &c.server.as_ref().unwrap();
                h.set_server_socket(l2l3.ip, l2l3.port);
                h.ip.set_src(pd.ip);
                h.tcp.set_src_port(c.p_port());
            }

            fn client_to_server<M: Sized + Send, F>(
                p: &mut Packet<TcpHeader, M>,
                c: &mut Connection,
                h: &mut HeaderState,
                pd: &L234Data,
                f_process_payload: &Arc<F>,
            ) where
                F: Fn(&mut Connection, &mut [u8], usize),
            {
                let tailroom = p.get_tailroom();
                f_process_payload(c, p.get_mut_payload(), tailroom);
                let ip_client = h.ip.src();
                let port_client = h.tcp.src_port();
                set_proxy2server_headers(c, h, pd);
                h.tcp.update_checksum_incremental(port_client, c.p_port());
                h.tcp.update_checksum_incremental(pd.port, c.server.as_ref().unwrap().port);
                h.tcp.update_checksum_incremental(!finalize_checksum(ip_client), !finalize_checksum(c.server.as_ref().unwrap().ip));
                // adapt ackn of client packet
                let oldackn = h.tcp.ack_num();
                let newackn = oldackn.wrapping_sub(c.c_seqn);
                let oldseqn = h.tcp.seq_num();
                let newseqn = oldseqn.wrapping_add(c.c2s_inserted_bytes as u32);
                if c.c2s_inserted_bytes != 0 {
                    h.tcp.set_seq_num(newseqn);
                    h.tcp.update_checksum_incremental(!finalize_checksum(oldseqn), !finalize_checksum(newseqn));
                }
                h.tcp.set_ack_num(newackn);
                h.tcp.update_checksum_incremental(!finalize_checksum(oldackn), !finalize_checksum(newackn));
                //debug!("translated c->s: { }, L4: { }", p, p.get_header());
            }

            fn server_to_client<M: Sized + Send>(
                // we will need p once s->c payload inspection is required
                _p: &mut Packet<TcpHeader, M>,
                c: &mut Connection,
                h: &mut HeaderState,
                pd: &L234Data,
            ) {
                // this is the s->c part of the stable two-way connection state
                // translate packets and forward to client
                h.mac.set_dmac(&c.client_mac.src);
                h.mac.set_smac(&pd.mac);
                let ip_server = h.ip.src();
                h.ip.set_dst(u32::from(*c.get_client_sock().ip()));
                h.ip.set_src(pd.ip);
                let server_src_port = h.tcp.src_port();
                h.tcp.set_src_port(pd.port);
                h.tcp.set_dst_port(c.get_client_sock().port());
                h.tcp.update_checksum_incremental(server_src_port, pd.port);
                h.tcp.update_checksum_incremental(c.p_port(), c.get_client_sock().port());
                h.tcp.update_checksum_incremental(!finalize_checksum(ip_server), !finalize_checksum(u32::from(*c.get_client_sock().ip())));
                // adapt seqn and ackn from server packet
                let oldseqn = h.tcp.seq_num();
                let newseqn = oldseqn.wrapping_add(c.c_seqn);
                let oldackn = h.tcp.ack_num();
                let newackn = oldackn.wrapping_sub(c.c2s_inserted_bytes as u32);
                if c.c2s_inserted_bytes != 0 {
                    h.tcp.set_ack_num(newackn);
                    h.tcp.update_checksum_incremental(!finalize_checksum(oldackn), !finalize_checksum(newackn));
                }
                h.tcp.set_seq_num(newseqn);
                h.tcp.update_checksum_incremental(!finalize_checksum(oldseqn), !finalize_checksum(newseqn));
                //debug!("translated s->c: {}", p);
            }

            #[inline]
            pub fn tcpip_payload_size<M: Sized + Send>(p: &Packet<TcpHeader, M>) -> u16 {
                let iph = p.get_pre_header().unwrap();
                // payload size = ip total length - ip header length -tcp header length
                iph.length() - (iph.ihl() as u16) * 4u16 - (p.get_header().data_offset() as u16) * 4u16
            }

            fn select_server<M: Sized + Send, F>(
                p: &mut Packet<TcpHeader, M>,
                c: &mut Connection,
                h: &mut HeaderState,
                pd: &L234Data,
                f_select_server: &Arc<F>,
            ) where
                F: Fn(&mut Connection),
            {
                let payload_sz = tcpip_payload_size(p);
                {
                    // safe the payload for later
                    p.copy_payload_to_bytearray(&mut c.payload, payload_sz);
                    let old_payload_size = c.payload.len();
                    f_select_server(c);
                    // save server_id to connection record
                    c.con_rec.server_id = if c.server.is_some() {
                        c.server.as_ref().unwrap().server_id.clone()
                    } else {
                        String::from("<unselected>")
                    };

                    c.c2s_inserted_bytes = c.payload.len() - old_payload_size;
                }
                // create a SYN Packet from the current packet
                // remove payload
                h.ip.trim_length_by(payload_sz as u16);

                // 60 is the minimum data length (4 bytes FCS not included)
                let trim_by = min(p.data_len() - 60usize, payload_sz as usize);
                p.trim_payload_size(trim_by);
                c.f_seqn = h.tcp.seq_num().wrapping_sub(1);
                set_proxy2server_headers(c, h, pd);
                h.tcp.set_seq_num(c.f_seqn);
                h.tcp.set_syn_flag();
                h.tcp.set_ack_num(0u32);
                h.tcp.unset_ack_flag();
                h.tcp.unset_psh_flag();
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                debug!("SYN packet to server - L3: {}, L4: {}", h.ip, p.get_header());
            }

            fn server_synack_received<M: Sized + Send>(
                p: &mut Packet<TcpHeader, M>,
                c: &mut Connection,
                h: &mut HeaderState,
                producer: &mut MpscProducer,
            ) {
                // correction for server side seq numbers
                let delta = c.c_seqn.wrapping_sub(h.tcp.seq_num());
                c.c_seqn = delta;
                make_reply_packet(h);
                h.tcp.unset_syn_flag();
                c.f_seqn = c.f_seqn.wrapping_add(1);
                h.tcp.set_seq_num(c.f_seqn);
                //debug!("data_len= { }, p= { }",p.data_len(), p);
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                // we clone the packet and send it via the extra queue
                // before the delayed request
                // to keep them in sequence
                let p_clone = p.clone();
                debug!("last ACK of three way handshake towards server: L4: {}", p_clone.get_header());
                producer.enqueue_one(p_clone);

                if c.payload.len() > 0 {
                    //TODO handle None == out of memory
                    let mut delayed_ip = new_packet().unwrap().push_header(h.mac).unwrap().push_header(h.ip).unwrap();
                    delayed_ip.get_mut_header().set_length(h.ip.length() + c.payload.len() as u16);
                    delayed_ip.get_mut_header().update_checksum();
                    //debug!("stored payload.len()= {}, h.ip.length= {}",
                    // c.payload.len(), h.ip.length());

                    let ip_payload_size = delayed_ip.get_header().payload_size(0);
                    //debug!("ip_payload_size= {}", ip_payload_size);
                    let mut delayed_p = delayed_ip.push_header(h.tcp).unwrap();
                    delayed_p.copy_payload_from_bytearray(&c.payload);
                    {
                        let h_tcp = delayed_p.get_mut_header();
                        h_tcp.set_psh_flag();
                    }
                    if delayed_p.data_len() < MIN_FRAME_SIZE {
                        let n_padding_bytes = MIN_FRAME_SIZE - delayed_p.data_len();
                        debug!("padding with {} 0x0 bytes", n_padding_bytes);
                        delayed_p.add_padding(n_padding_bytes);
                    }
                    // let sz=delayed_p.payload_size() as u32;
                    // delayed_p.get_mut_header().set_seq_num(c.f_seqn+sz);
                    update_tcp_checksum(&mut delayed_p, ip_payload_size, h.ip.src(), h.ip.dst());
                    debug!("delayed packet: { }", delayed_p.get_header());
                    producer.enqueue_one(delayed_p);
                }
            }

            let mut group_index = 0usize; // the index of the group to be returned
            // need to clone here, as this closure must be an FnMut, not only FnOnce:
            let mut producer = producer.clone();

            assert!(p.get_pre_header().is_some()); // we must have parsed the headers

            let hs_ip;
            let hs_flow;
            let hs_mac;
            let hs_tcp;

            unsafe {
                // converting to raw pointer avoids to borrow mutably from p
                let ptr = p.get_mut_pre_header().unwrap() as *mut IpHeader;
                hs_ip = &mut *ptr;
                hs_flow = hs_ip.flow().unwrap();
                let ptr = p.get_mut_pre_pre_header().unwrap() as *mut MacHeader;
                hs_mac = &mut *ptr;
                let ptr = p.get_mut_header() as *mut TcpHeader;
                hs_tcp = &mut *ptr;
            };

            let mut hs = HeaderState {
                mac: hs_mac,
                ip: hs_ip,
                tcp: hs_tcp,
            };

            let pipe_id = pipeline_id.clone();
            loop {
                match rx.try_recv() {
                    Ok(MessageTo::Hello) => {
                        debug!("{}: got a Hello", pipe_id);
                    }
                    Ok(MessageTo::Exit) => {
                        sm.send_all_c_records(&tx);
                        debug!("{}: exiting recv task", pipe_id);
                    }
                    Err(TryRecvError::Disconnected) => {
                        error!("{}: error receiving from disconnected message channel", pipe_id);
                        break;
                    }
                    Err(TryRecvError::Empty) => break  // nothing in queue
                };
            }
            // if set by the following tcp state machine,
            // the port/connection becomes released afterwards
            // this is cumbersome, but we must make the  borrow checker happy
            let mut release_connection = None;

            if hs_flow.dst_port == pd.port {
                //debug!("client to server");
                let key = CKey::Socket(hs_flow.src_socket_addr());
                let opt_c = if hs.tcp.syn_flag() {
                    sm.get_mut_or_insert(key, &mut wheel)
                } else {
                    sm.get_mut(key)
                };

                if opt_c.is_none() {
                    debug!("illegal client request or flow or out of resources");
                } else {
                    let mut c = opt_c.unwrap();
                    // we only handle active open on client side:
                    // we reset server and client state
                    //TODO revisit this approach
                    let old_s_state = c.con_rec.s_state;
                    let old_c_state = c.con_rec.c_state;

                    if hs.tcp.syn_flag() {
                        if c.con_rec.c_state == TcpState::Listen {
                            // replies with a SYN-ACK to client:
                            client_syn_received(p, &mut c, &mut hs);
                            tx.send(MessageFrom::ClientSyn(c.con_rec.clone())).unwrap();
                            group_index = 1;
                        } else {
                            warn!("received client SYN in state {:?}/{:?}", c.con_rec.c_state, c.con_rec.s_state);
                        }
                    } else if hs.tcp.ack_flag() && c.con_rec.c_state == TcpState::SynSent {
                        c.client_con_established();
                        debug!(
                            "{} client side connection established for {:?}",
                            thread_id_2,
                            hs_flow.src_socket_addr()
                        );
                    } else if hs.tcp.ack_flag() && c.con_rec.s_state == TcpState::FinWait {
                        c.con_rec.c_state = TcpState::CloseWait;
                        c.con_rec.s_state = TcpState::Closed;
                        if hs.tcp.fin_flag() {
                            c.con_rec.c_state = TcpState::LastAck
                        }
                        debug!("{} transition to client/server state {:?}/{:?}", thread_id_2, c.con_rec.c_state, c.con_rec.s_state);
                    } else if c.con_rec.s_state == TcpState::LastAck && hs.tcp.ack_flag() {
                        // received final ack from client for client initiated close
                        debug!(
                            "received final ACK for client initiated close on port {}/{}",
                            hs.tcp.src_port(),
                            c.p_port(),
                        );
                        c.con_rec.s_state = TcpState::Listen;
                        c.con_rec.c_state = TcpState::Listen;
                        c.con_rec.c_released(ReleaseCause::FinClient);
                        // release connection in the next block after the state machine
                        release_connection = Some(c.p_port());
                        debug!("releasing connection state for {}/{}", hs.tcp.src_port(), c.p_port());
                    } else if hs.tcp.fin_flag() {
                        if c.con_rec.s_state >= TcpState::FinWait {
                            // we got a FIN as a receipt to a sent FIN (server closed connection)
                            debug!("received FIN-reply from client {:?}", hs_flow.src_socket_addr());
                            c.con_rec.c_state = TcpState::LastAck;
                            c.con_rec.s_state = TcpState::Closed;
                        } else {
                            // client wants to close connection
                            debug!(
                                "client sends FIN on port {}/{} in state {:?}/{:?}",
                                hs.tcp.src_port(),
                                c.p_port(),
                                c.con_rec.c_state,
                                c.con_rec.s_state
                            );
                            if c.con_rec.s_state >= TcpState::Established {
                                c.con_rec.c_state = TcpState::FinWait;
                            } else {
                                // in case the server connection is still not established
                                // proxy must close connection and sends Fin-Ack to client
                                make_reply_packet(&mut hs);
                                hs.tcp.set_ack_flag();
                                c.c_seqn = c.c_seqn.wrapping_add(1);
                                hs.tcp.set_seq_num(c.c_seqn);
                                //debug!("data_len= { }, p= { }",p.data_len(), p);
                                update_tcp_checksum(p, hs.ip.payload_size(0), hs.ip.src(), hs.ip.dst());
                                c.con_rec.c_state = TcpState::FinWait;
                                debug!("(FIN-)ACK to client, L3: { }, L4: { }", hs.ip, hs.tcp);
                                release_connection = Some(c.p_port());
                                debug!("releasing connection state for {}/{}", hs.tcp.src_port(), c.p_port());
                                group_index = 1;
                            }
                        }
                    } else if c.con_rec.c_state == TcpState::Established && c.con_rec.s_state == TcpState::Listen {
                        // should be the first payload packet from client
                        select_server(p, &mut c, &mut hs, &pd, &f_select_server);
                        c.con_rec.s_state = TcpState::SynReceived;
                        group_index = 1;
                    } else if c.con_rec.s_state < TcpState::SynReceived || c.con_rec.c_state < TcpState::Established {
                        warn!(
                            "{} unexpected client-side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                            thread_id_2,
                            hs.tcp.src_port(),
                            c.p_port(),
                            c.con_rec.c_state,
                            c.con_rec.s_state,
                        );
                        group_index = 2;
                    }

                    // once we established a two-way e2e-connection, we always forward the packets
                    if old_s_state >= TcpState::Established && old_c_state >= TcpState::Established {
                        client_to_server(p, &mut c, &mut hs, &pd, &f_process_payload_c_s);
                        group_index = 1;
                    }
                }
            } else {
                // should be server to client
                {
                    // debug!("looking up state for server side port { }", hs.tcp.dst_port());
                    let mut c = sm.get_mut(CKey::Port(hs.tcp.dst_port()));
                    if c.is_some() {
                        let mut c = c.as_mut().unwrap();
                        let mut b_unexpected = false;
                        let old_s_state = c.con_rec.s_state;
                        let old_c_state = c.con_rec.c_state;

                        if c.con_rec.s_state == TcpState::SynReceived && hs.tcp.ack_flag() && hs.tcp.syn_flag() {
                            c.server_con_established();
                            tx.send(MessageFrom::Established(c.con_rec.clone())).unwrap();
                            debug!("established two-way client server connection, SYN-ACK received: L3: {}, L4: {}", hs.ip, hs.tcp);
                            // TODO statistics.full_connect();
                            server_synack_received(p, &mut c, &mut hs, &mut producer);
                            group_index = 0; // packets are sent via extra queue
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
                                    c.get_client_sock().port(),
                                    c.con_rec.s_state,
                                );
                                c.con_rec.s_state = TcpState::FinWait;
                            }
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

                        // once we established a two-way e-2-e connection, we always forward server side packets
                        if old_s_state >= TcpState::Established && old_c_state >= TcpState::Established {
                            // translate packets and forward to client
                            server_to_client(p, &mut c, &mut hs, &pd);
                            group_index = 1;
                            b_unexpected = false;
                        }

                        if b_unexpected {
                            warn!(
                                "{} unexpected server side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                thread_id_2,
                                hs.tcp.dst_port(),
                                c.get_client_sock().port(),
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
            }
            // here we check if we shall release the connection state,
            // required because of borrow checker for the state manager sm
            if let Some(sport) = release_connection {
                debug!("releasing port {}", sport);
                let con_rec = sm.release_port(sport);
                if con_rec.is_some() { tx.send(MessageFrom::CRecord(con_rec.unwrap())).unwrap() };
            }
            do_ttl(&mut hs);
            group_index
        },
        sched,
    );

    let l2kniflow = l2groups.get_group(0).unwrap().compose();
    let l4kniflow = l4groups.get_group(2).unwrap().compose();
    let pipe2kni = merge(vec![l2kniflow, l4kniflow]).send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap().compose();
    let l4dumpflow = l4groups.get_group(0).unwrap().filter(box move |_| false).compose();
    let pipe2pci = merge(vec![l4pciflow, l4dumpflow]).send(pci.clone());
    sched.add_task(pipe2kni).unwrap();
    sched.add_task(pipe2pci).unwrap();
    sched.add_task(consumer.send(pci.clone())).unwrap();
}
