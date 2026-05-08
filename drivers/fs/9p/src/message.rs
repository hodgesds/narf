//! 9P Message types and serialization.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Tversion = 100, Rversion = 101,
    Tauth    = 102, Rauth    = 103,
    Tattach  = 104, Rattach  = 105,
    Terror   = 106, Rerror   = 107,
    Tflush   = 108, Rflush   = 109,
    Twalk    = 110, Rwalk    = 111,
    Topen    = 112, Ropen    = 113,
    Tcreate  = 114, Rcreate  = 115,
    Tread    = 116, Rread    = 117,
    Twrite   = 118, Rwrite   = 119,
    Tclunk   = 120, Rclunk   = 121,
    Tremove  = 122, Rremove  = 123,
    Tstat    = 124, Rstat    = 125,
    Twstat   = 126, Rwstat   = 127,
}

impl From<u8> for MsgType {
    fn from(val: u8) -> Self {
        unsafe { core::mem::transmute(val) }
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Qid {
    pub qid_type: u8,
    pub version: u32,
    pub path: u64,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MsgHeader {
    pub size: u32,
    pub msg_type: u8,
    pub tag: u16,
}

#[derive(Debug, Clone, Default)]
pub struct P9Stat {
    pub size: u16,
    pub ptype: u16,
    pub dev: u32,
    pub qid: Qid,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub muid: String,
}

impl P9Stat {
    pub fn decode(buf: &mut P9Buffer) -> Self {
        let size = buf.read_u16();
        let start_offset = buf.offset;
        let s = Self {
            size,
            ptype: buf.read_u16(),
            dev: buf.read_u32(),
            qid: buf.read_qid(),
            mode: buf.read_u32(),
            atime: buf.read_u32(),
            mtime: buf.read_u32(),
            length: buf.read_u64(),
            name: buf.read_string(),
            uid: buf.read_string(),
            gid: buf.read_string(),
            muid: buf.read_string(),
        };
        buf.offset = start_offset + size as usize;
        s
    }
}

#[derive(Debug, Clone)]
pub enum P9Msg {
    Tversion { msize: u32, version: String },
    Rversion { msize: u32, version: String },
    Rerror { ename: String },
    Tattach { fid: u32, afid: u32, uname: String, aname: String },
    Rattach { qid: Qid },
    Twalk { fid: u32, newfid: u32, wnames: Vec<String> },
    Rwalk { qids: Vec<Qid> },
    Topen { fid: u32, mode: u8 },
    Ropen { qid: Qid, iounit: u32 },
    Tcreate { fid: u32, name: String, perm: u32, mode: u8 },
    Rcreate { qid: Qid, iounit: u32 },
    Tread { fid: u32, offset: u64, count: u32 },
    Rread { data: Vec<u8> },
    Twrite { fid: u32, offset: u64, data: Vec<u8> },
    Rwrite { count: u32 },
    Tclunk { fid: u32 },
    Rclunk,
    Tremove { fid: u32 },
    Rremove,
    Tstat { fid: u32 },
    Rstat { stat: P9Stat },
}

#[derive(Debug)]
pub struct P9Buffer<'a> {
    pub data: &'a mut [u8],
    pub offset: usize,
}

impl<'a> P9Buffer<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn write_u8(&mut self, val: u8) { self.data[self.offset] = val; self.offset += 1; }
    pub fn write_u16(&mut self, val: u16) { self.data[self.offset..self.offset + 2].copy_from_slice(&val.to_le_bytes()); self.offset += 2; }
    pub fn write_u32(&mut self, val: u32) { self.data[self.offset..self.offset + 4].copy_from_slice(&val.to_le_bytes()); self.offset += 4; }
    pub fn write_u64(&mut self, val: u64) { self.data[self.offset..self.offset + 8].copy_from_slice(&val.to_le_bytes()); self.offset += 8; }
    pub fn write_string(&mut self, val: &str) {
        self.write_u16(val.len() as u16);
        self.data[self.offset..self.offset + val.len()].copy_from_slice(val.as_bytes());
        self.offset += val.len();
    }
    pub fn write_qid(&mut self, qid: &Qid) {
        self.write_u8(qid.qid_type);
        self.write_u32(qid.version);
        self.write_u64(qid.path);
    }

    pub fn read_u8(&mut self) -> u8 { let val = self.data[self.offset]; self.offset += 1; val }
    pub fn read_u16(&mut self) -> u16 { let val = u16::from_le_bytes([self.data[self.offset], self.data[self.offset + 1]]); self.offset += 2; val }
    pub fn read_u32(&mut self) -> u32 { let val = u32::from_le_bytes([self.data[self.offset], self.data[self.offset+1], self.data[self.offset+2], self.data[self.offset+3]]); self.offset += 4; val }
    pub fn read_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.offset..self.offset+8]);
        self.offset += 8;
        u64::from_le_bytes(b)
    }
    pub fn read_string(&mut self) -> String {
        let len = self.read_u16() as usize;
        let s = String::from_utf8_lossy(&self.data[self.offset..self.offset + len]).into_owned();
        self.offset += len;
        s
    }
    pub fn read_qid(&mut self) -> Qid {
        Qid { qid_type: self.read_u8(), version: self.read_u32(), path: self.read_u64() }
    }
}

impl P9Msg {
    pub fn msg_type(&self) -> MsgType {
        match self {
            P9Msg::Tversion { .. } => MsgType::Tversion,
            P9Msg::Rversion { .. } => MsgType::Rversion,
            P9Msg::Rerror { .. } => MsgType::Rerror,
            P9Msg::Tattach { .. } => MsgType::Tattach,
            P9Msg::Rattach { .. } => MsgType::Rattach,
            P9Msg::Twalk { .. } => MsgType::Twalk,
            P9Msg::Rwalk { .. } => MsgType::Rwalk,
            P9Msg::Topen { .. } => MsgType::Topen,
            P9Msg::Ropen { .. } => MsgType::Ropen,
            P9Msg::Tcreate { .. } => MsgType::Tcreate,
            P9Msg::Rcreate { .. } => MsgType::Rcreate,
            P9Msg::Tread { .. } => MsgType::Tread,
            P9Msg::Rread { .. } => MsgType::Rread,
            P9Msg::Twrite { .. } => MsgType::Twrite,
            P9Msg::Rwrite { .. } => MsgType::Rwrite,
            P9Msg::Tclunk { .. } => MsgType::Tclunk,
            P9Msg::Rclunk => MsgType::Rclunk,
            P9Msg::Tremove { .. } => MsgType::Tremove,
            P9Msg::Rremove => MsgType::Rremove,
            P9Msg::Tstat { .. } => MsgType::Tstat,
            P9Msg::Rstat { .. } => MsgType::Rstat,
        }
    }

    pub fn encode(&self, buf: &mut P9Buffer) {
        match self {
            P9Msg::Tversion { msize, version } => {
                buf.write_u32(*msize);
                buf.write_string(version);
            }
            P9Msg::Tattach { fid, afid, uname, aname } => {
                buf.write_u32(*fid);
                buf.write_u32(*afid);
                buf.write_string(uname);
                buf.write_string(aname);
            }
            P9Msg::Twalk { fid, newfid, wnames } => {
                buf.write_u32(*fid);
                buf.write_u32(*newfid);
                buf.write_u16(wnames.len() as u16);
                for name in wnames {
                    buf.write_string(name);
                }
            }
            P9Msg::Topen { fid, mode } => {
                buf.write_u32(*fid);
                buf.write_u8(*mode);
            }
            P9Msg::Tcreate { fid, name, perm, mode } => {
                buf.write_u32(*fid);
                buf.write_string(name);
                buf.write_u32(*perm);
                buf.write_u8(*mode);
            }
            P9Msg::Tread { fid, offset, count } => {
                buf.write_u32(*fid);
                buf.write_u64(*offset);
                buf.write_u32(*count);
            }
            P9Msg::Twrite { fid, offset, data } => {
                buf.write_u32(*fid);
                buf.write_u64(*offset);
                buf.write_u32(data.len() as u32);
                buf.data[buf.offset..buf.offset + data.len()].copy_from_slice(data);
                buf.offset += data.len();
            }
            P9Msg::Tclunk { fid } => {
                buf.write_u32(*fid);
            }
            P9Msg::Tremove { fid } => {
                buf.write_u32(*fid);
            }
            P9Msg::Tstat { fid } => {
                buf.write_u32(*fid);
            }
            _ => unimplemented!("Encoding for {:?}", self),
        }
    }

    pub fn decode(mtype: MsgType, buf: &mut P9Buffer) -> Self {
        match mtype {
            MsgType::Rversion => P9Msg::Rversion { msize: buf.read_u32(), version: buf.read_string() },
            MsgType::Rerror => P9Msg::Rerror { ename: buf.read_string() },
            MsgType::Rattach => P9Msg::Rattach { qid: buf.read_qid() },
            MsgType::Rwalk => {
                let n = buf.read_u16() as usize;
                let mut qids = Vec::with_capacity(n);
                for _ in 0..n { qids.push(buf.read_qid()); }
                P9Msg::Rwalk { qids }
            }
            MsgType::Ropen => P9Msg::Ropen { qid: buf.read_qid(), iounit: buf.read_u32() },
            MsgType::Rcreate => P9Msg::Rcreate { qid: buf.read_qid(), iounit: buf.read_u32() },
            MsgType::Rread => {
                let n = buf.read_u32() as usize;
                let mut data = Vec::with_capacity(n);
                data.extend_from_slice(&buf.data[buf.offset..buf.offset + n]);
                buf.offset += n;
                P9Msg::Rread { data }
            }
            MsgType::Rwrite => P9Msg::Rwrite { count: buf.read_u32() },
            MsgType::Rclunk => P9Msg::Rclunk,
            MsgType::Rremove => P9Msg::Rremove,
            MsgType::Rstat => {
                let _n = buf.read_u16();
                let stat = P9Stat::decode(buf);
                P9Msg::Rstat { stat }
            }
            _ => unimplemented!("Decoding for {:?}", mtype),
        }
    }
}
