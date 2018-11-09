use std::any::Any;
use std::net::{SocketAddrV4,};
use std::fmt;
use std::fmt::Write;
use std::convert;
use std::ops::{Index, IndexMut};

use uuid::Uuid;
use eui48::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    Closing,
    FinWait2,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpStatistics {
    SentSyn = 0,
    SentSynAck = 1,
    SentSynAck2 = 2,
    SentFin = 3,
    SentFinAck = 4,
    SentFinAck2 = 5,
    SentAck = 6,
    RecvSyn = 7,
    RecvSynAck = 8,
    RecvSynAck2 = 9,
    RecvFin = 10,
    RecvFinAck = 11,
    RecvFinAck2 = 12,
    RecvAck = 13,
    RecvRst = 14,
    Unexpected = 15,
    Payload = 16,
    Count = 17,
}

impl convert::From<usize> for TcpStatistics {
    fn from(i: usize) -> TcpStatistics {
        match i {
            0 => TcpStatistics::SentSyn,
            1 => TcpStatistics::SentSynAck,
            2 => TcpStatistics::SentSynAck2,
            3 => TcpStatistics::SentFin,
            4 => TcpStatistics::SentFinAck,
            5 => TcpStatistics::SentFinAck2,
            6 => TcpStatistics::SentAck,
            7 => TcpStatistics::RecvSyn,
            8 => TcpStatistics::RecvSynAck,
            9 => TcpStatistics::RecvSynAck2,
            10 => TcpStatistics::RecvFin,
            11 => TcpStatistics::RecvFinAck,
            12 => TcpStatistics::RecvFinAck2,
            13 => TcpStatistics::RecvAck,
            14 => TcpStatistics::RecvRst,
            15 => TcpStatistics::Unexpected,
            16 => TcpStatistics::Payload,
            17 => TcpStatistics::Count,
            _ => TcpStatistics::Count,
        }
    }
}

impl fmt::Display for TcpStatistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        write!(&mut output, "{:?}", self)?;
        write!(f, "{:12}", output)
    }
}

#[derive(Debug, Clone)]
pub struct TcpCounter {
    counter: [usize; TcpStatistics::Count as usize],
}

impl TcpCounter {
    pub fn new() -> TcpCounter {
        TcpCounter {
            counter: [0; TcpStatistics::Count as usize],
        }
    }
}

impl Index<TcpStatistics> for TcpCounter {
    type Output = usize;

    fn index(&self, tcp_control: TcpStatistics) -> &usize {
        &self.counter[tcp_control as usize]
    }
}

impl IndexMut<TcpStatistics> for TcpCounter {
    fn index_mut(&mut self, tcp_control: TcpStatistics) -> &mut usize {
        &mut self.counter[tcp_control as usize]
    }
}

impl fmt::Display for TcpCounter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Tcp Counters: ",)?;
        for i in 0..TcpStatistics::Count as usize {
            writeln!(f, "{:12} = {:6}", TcpStatistics::from(i), self.counter[i])?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
    pub server_id: String,
    pub index: usize,
}

pub trait UserData: Send + Sync + 'static {
    fn ref_userdata(&self) -> &Any;
    fn mut_userdata(&mut self) -> &mut Any;
    fn init(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    PassiveClose = 2,
    ActiveClose = 3,
    PassiveRst = 4,
    ActiveRst = 5,
    MaxCauses = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CData {
    // connection data sent as first payload packet
    pub reply_socket: SocketAddrV4, // the socket on which the trafficengine expects the reply from the DUT
    pub client_port: u16,
    pub uuid: Option<Uuid>,

}

impl CData {
    pub fn new(reply_socket: SocketAddrV4, client_port: u16, uuid: Option<Uuid>) -> CData {
        CData {
            reply_socket,
            client_port,
            uuid,
        }
    }
}

