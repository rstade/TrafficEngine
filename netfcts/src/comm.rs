use std::sync::mpsc::Sender;
use std::fmt;
use std::collections::HashMap;
use uuid::Uuid;
use tcp_common::TcpCounter;
use tasks::TaskType;
use ConRecord;

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PipelineId {
    pub core: u16,
    pub port_id: u16,
    pub rxq: u16,
}

impl fmt::Display for PipelineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<c{}, p{}, rx{}>", self.core, self.port_id, self.rxq)
    }
}

pub enum MessageFrom {
    Channel(PipelineId, Sender<MessageTo>),
    Established(PipelineId, ConRecord),
    GenTimeStamp(PipelineId, &'static str, usize, u64, u64),
    StartEngine(Sender<MessageTo>),
    Task(PipelineId, Uuid, TaskType),
    PrintPerformance(Vec<i32>), // performance of tasks on cores selected by indices
    Counter(PipelineId, TcpCounter, TcpCounter),
    CRecords(PipelineId, HashMap<Uuid, ConRecord>, HashMap<Uuid, ConRecord>), // pipeline_id, client, server
    FetchCounter, // triggers fetching of counters from pipelines
    FetchCRecords,
    Exit, // exit recv thread
}

pub enum MessageTo {
    FetchCounter, // fetch counters from pipeline
    FetchCRecords,
    Counter(PipelineId, TcpCounter, TcpCounter),
    CRecords(PipelineId, HashMap<Uuid, ConRecord>, HashMap<Uuid, ConRecord>),
    StartGenerator,
    Exit, // exit recv thread
}
