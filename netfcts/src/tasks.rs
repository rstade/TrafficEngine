use std::sync::Arc;
use e2d2::interface::PmdPort;
use e2d2::native::zcsi::rte_kni_handle_request;
use e2d2::common::EmptyMetadata;
use e2d2::headers::{IpHeader, MacHeader, TcpHeader};
use e2d2::interface::{Packet, new_packet};
use e2d2::queues::{MpscProducer};
use e2d2::native::zcsi::{mbuf_alloc_bulk, MBuf};
use e2d2::scheduler::{Executable, Runnable, Scheduler, StandaloneScheduler};

use tcp_common::L234Data;
use e2d2::utils;
use uuid::Uuid;

#[derive(Debug)]
pub enum TaskType {
    TcpGenerator = 0,
    Pipe2Kni = 1,
    Pipe2Pci = 2,
    TickGenerator = 3,
    NoTaskTypes = 4, // for iteration over TaskType
}

pub fn install_task<T: Executable + 'static>(
    sched: &mut StandaloneScheduler,
    task_name: &str,
    task: T,
) -> Uuid {
    let uuid = Uuid::new_v4();
    sched.add_runnable(Runnable::from_task(uuid, task_name.to_string(), task).move_unready());
    uuid
}


pub struct KniHandleRequest {
    pub kni_port: Arc<PmdPort>,
    pub last_tick: u64,
}

impl Executable for KniHandleRequest {
    fn execute(&mut self) -> u32 {
        let now = utils::rdtsc_unsafe();
        if now - self.last_tick >= 22700 * 1000 {
            unsafe {
                rte_kni_handle_request(self.kni_port.get_kni());
            };
            self.last_tick = now;
            1
        } else {
            0
        }
    }
}

pub struct PacketInjector {
    packet_prototype: Packet<TcpHeader, EmptyMetadata>,
    producer: MpscProducer,
    //    tx: Sender<MessageFrom>,
    no_packets: usize,
    sent_packets: usize,
    //    used_cycles: Vec<u64>,
    //    pipeline_id: PipelineId,
}

pub const PRIVATE_ETYPE_PACKET: u16 = 0x08FF;
pub const PRIVATE_ETYPE_TIMER: u16 = 0x08FE;

pub const INJECTOR_BATCH_SIZE: usize = 32;

impl PacketInjector {
    // by setting no_packets=0 batch creation is unlimited
    pub fn new(
        producer: MpscProducer,
        hd_src_data: &L234Data,
        no_packets: usize,
        //        pipeline_id: PipelineId,
        //        tx: Sender<MessageFrom>,
    ) -> PacketInjector {
        let mut mac = MacHeader::new();
        mac.src = hd_src_data.mac.clone();
        mac.set_etype(PRIVATE_ETYPE_PACKET); // mark this through an unused ethertype as an internal frame, will be re-written later in the pipeline
        let mut ip = IpHeader::new();
        ip.set_src(hd_src_data.ip);
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
            packet_prototype,
            producer,
            no_packets,
            sent_packets: 0,
            //            used_cycles: vec![0; 4],
            //            pipeline_id,
            //            tx,
        }
    }
    /*
    #[inline]
    pub fn create_packet(&mut self) -> Packet<TcpHeader, EmptyMetadata> {
        let p = unsafe { self.packet_prototype.copy() };
        p
    }
*/
    #[inline]
    pub fn create_packet_from_mbuf(&mut self, mbuf: *mut MBuf) -> Packet<TcpHeader, EmptyMetadata> {
        let p = unsafe { self.packet_prototype.copy_use_mbuf(mbuf) };
        p
    }
}

impl Executable for PacketInjector {
    fn execute(&mut self) -> u32 {
        let mut inserted = 0;
        // only enqeue new packets if queue has free slots for a full batch (currently we would otherwise create a memory leak)
        if (self.no_packets == 0 || self.sent_packets < self.no_packets) && self.producer.free_slots() >= INJECTOR_BATCH_SIZE {
            let mut mbuf_ptr_array = Vec::<*mut MBuf>::with_capacity(INJECTOR_BATCH_SIZE);
            let ret = unsafe { mbuf_alloc_bulk(mbuf_ptr_array.as_mut_ptr(), INJECTOR_BATCH_SIZE as u32) };
            assert_eq!(ret, 0);
            unsafe { mbuf_ptr_array.set_len(INJECTOR_BATCH_SIZE) };
            for i in 0..INJECTOR_BATCH_SIZE {
                self.create_packet_from_mbuf(mbuf_ptr_array[i]);
            }
            inserted = self.producer.enqueue_mbufs(&mbuf_ptr_array);
            self.sent_packets += inserted;
            assert_eq!(inserted, INJECTOR_BATCH_SIZE);
        }
        inserted as u32
    }
}

pub struct TickGenerator {
    packet_prototype: Packet<TcpHeader, EmptyMetadata>,
    producer: MpscProducer,
    last_tick: u64,
    tick_length: u64, // in cycles
    tick_count: u64,
}

#[allow(dead_code)]
impl TickGenerator {
    pub fn new(
        producer: MpscProducer,
        hd_src_data: &L234Data,
        tick_length_1000: u64, // in cycles/1000
    ) -> TickGenerator {
        let mut mac = MacHeader::new();
        mac.src = hd_src_data.mac.clone();
        mac.set_etype(PRIVATE_ETYPE_TIMER); // mark this through an unused ethertype as an internal frame, will be re-written later in the pipeline
        let mut ip = IpHeader::new();
        ip.set_src(hd_src_data.ip);
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
        let mut packet_prototype = new_packet()
            .unwrap()
            .push_header(&mac)
            .unwrap()
            .push_header(&ip)
            .unwrap()
            .push_header(&tcp)
            .unwrap();
        packet_prototype.add_to_payload_tail(64).unwrap();
        TickGenerator {
            packet_prototype,
            producer,
            last_tick: 0,
            tick_count: 0,
            tick_length: tick_length_1000 * 1000,
        }
    }

    #[inline]
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    #[inline]
    pub fn tick_length(&self) -> u64 {
        self.tick_length
    }
}

impl Executable for TickGenerator {
    fn execute(&mut self) -> u32 {
        let p;
        let now = utils::rdtsc_unsafe();
        if now - self.last_tick >= self.tick_length {
            unsafe {
                p = self.packet_prototype.copy();
            }
            self.producer.enqueue_one(p);
            self.last_tick = now;
            self.tick_count += 1;
            1
        } else {
            0
        }
    }
}
