//! 9P2000.L wire-protocol encoders / decoders.
//!
//! Reference: https://ericvh.github.io/9p-rfc/rfc9p2000.l.html
//!
//! Header: `size: u32 LE | type: u8 | tag: u16 LE` (7 bytes,
//! `size` is the total message length including itself).
//! Strings: `len: u16 LE | bytes`. qid: `type: u8 | version: u32 LE
//! | path: u64 LE` (13 bytes). All multi-byte ints are LE.

extern crate alloc;

use alloc::vec::Vec;

// ── Message-type discriminants (T = request, R = reply) ────────────

pub const T_LOPEN:   u8 = 12;
pub const R_LOPEN:   u8 = 13;
pub const T_VERSION: u8 = 100;
pub const R_VERSION: u8 = 101;
pub const T_ATTACH:  u8 = 104;
pub const R_ATTACH:  u8 = 105;
pub const T_WALK:    u8 = 110;
pub const R_WALK:    u8 = 111;
pub const T_READ:    u8 = 116;
pub const R_READ:    u8 = 117;
pub const T_CLUNK:   u8 = 120;
pub const R_CLUNK:   u8 = 121;

pub const HEADER_LEN: usize = 7;
pub const QID_LEN:    usize = 13;

/// `NOFID` per 9P2000.L for "no auth fid".
pub const NOFID: u32 = 0xFFFF_FFFF;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Short,
    BadType,
    BadSize,
    StringOverflow,
    TooManyWnames,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Qid {
    pub kind:    u8,
    pub version: u32,
    pub path:    u64,
}

impl Qid {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.path.to_le_bytes());
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < QID_LEN { return Err(DecodeError::Short); }
        let kind    = buf[0];
        let version = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let path    = u64::from_le_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        Ok((Self { kind, version, path }, QID_LEN))
    }
}

// ── helpers ────────────────────────────────────────────────────────

fn put_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_le_bytes()); }
fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_le_bytes()); }
fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    put_u16(out, s.len() as u16);
    out.extend_from_slice(s);
}

fn take<const N: usize>(buf: &[u8], off: &mut usize) -> Result<[u8; N], DecodeError> {
    if buf.len() < *off + N { return Err(DecodeError::Short); }
    let mut a = [0u8; N];
    a.copy_from_slice(&buf[*off..*off + N]);
    *off += N;
    Ok(a)
}

fn take_u16(buf: &[u8], off: &mut usize) -> Result<u16, DecodeError> {
    Ok(u16::from_le_bytes(take::<2>(buf, off)?))
}
fn take_u32(buf: &[u8], off: &mut usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(take::<4>(buf, off)?))
}
fn take_u64(buf: &[u8], off: &mut usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(take::<8>(buf, off)?))
}
fn take_str(buf: &[u8], off: &mut usize) -> Result<Vec<u8>, DecodeError> {
    let n = take_u16(buf, off)? as usize;
    if buf.len() < *off + n { return Err(DecodeError::StringOverflow); }
    let mut v = Vec::with_capacity(n);
    v.extend_from_slice(&buf[*off..*off + n]);
    *off += n;
    Ok(v)
}

/// Build a header-prefixed buffer. `body` is the message body
/// (after the 7-byte header). Returns the full wire-form Vec.
fn frame(ty: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let total = HEADER_LEN + body.len();
    let mut out = Vec::with_capacity(total);
    put_u32(&mut out, total as u32);
    out.push(ty);
    put_u16(&mut out, tag);
    out.extend_from_slice(body);
    out
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub size: u32,
    pub kind: u8,
    pub tag:  u16,
}

impl Header {
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN { return Err(DecodeError::Short); }
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if (size as usize) < HEADER_LEN { return Err(DecodeError::BadSize); }
        Ok(Self { size, kind: buf[4], tag: u16::from_le_bytes([buf[5], buf[6]]) })
    }
}

// ── Tversion (100) ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tversion {
    pub tag:     u16,
    pub msize:   u32,
    pub version: Vec<u8>,
}

impl Tversion {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + 2 + self.version.len());
        put_u32(&mut body, self.msize);
        put_str(&mut body, &self.version);
        frame(T_VERSION, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_VERSION { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let msize   = take_u32(buf, &mut off)?;
        let version = take_str(buf, &mut off)?;
        Ok(Self { tag: h.tag, msize, version })
    }
}

// ── Tattach (104) — 9P2000.L variant has trailing n_uname[4] ───────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tattach {
    pub tag:     u16,
    pub fid:     u32,
    pub afid:    u32,
    pub uname:   Vec<u8>,
    pub aname:   Vec<u8>,
    pub n_uname: u32,
}

impl Tattach {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(
            4 + 4 + 2 + self.uname.len() + 2 + self.aname.len() + 4);
        put_u32(&mut body, self.fid);
        put_u32(&mut body, self.afid);
        put_str(&mut body, &self.uname);
        put_str(&mut body, &self.aname);
        put_u32(&mut body, self.n_uname);
        frame(T_ATTACH, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_ATTACH { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let fid     = take_u32(buf, &mut off)?;
        let afid    = take_u32(buf, &mut off)?;
        let uname   = take_str(buf, &mut off)?;
        let aname   = take_str(buf, &mut off)?;
        let n_uname = take_u32(buf, &mut off)?;
        Ok(Self { tag: h.tag, fid, afid, uname, aname, n_uname })
    }
}

// ── Twalk (110) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Twalk {
    pub tag:    u16,
    pub fid:    u32,
    pub newfid: u32,
    pub wnames: Vec<Vec<u8>>,
}

impl Twalk {
    /// 9P spec caps nwname at 16 per rfc9p2000.l.html.
    pub const MAX_WNAMES: usize = 16;

    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        if self.wnames.len() > Self::MAX_WNAMES {
            return Err(DecodeError::TooManyWnames);
        }
        let mut body = Vec::new();
        put_u32(&mut body, self.fid);
        put_u32(&mut body, self.newfid);
        put_u16(&mut body, self.wnames.len() as u16);
        for n in &self.wnames { put_str(&mut body, n); }
        Ok(frame(T_WALK, self.tag, &body))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_WALK { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let fid    = take_u32(buf, &mut off)?;
        let newfid = take_u32(buf, &mut off)?;
        let n      = take_u16(buf, &mut off)? as usize;
        if n > Self::MAX_WNAMES { return Err(DecodeError::TooManyWnames); }
        let mut wnames = Vec::with_capacity(n);
        for _ in 0..n { wnames.push(take_str(buf, &mut off)?); }
        Ok(Self { tag: h.tag, fid, newfid, wnames })
    }
}

// ── Tlopen (12) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlopen {
    pub tag:   u16,
    pub fid:   u32,
    pub flags: u32,
}

impl Tlopen {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(8);
        put_u32(&mut body, self.fid);
        put_u32(&mut body, self.flags);
        frame(T_LOPEN, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_LOPEN { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let fid   = take_u32(buf, &mut off)?;
        let flags = take_u32(buf, &mut off)?;
        Ok(Self { tag: h.tag, fid, flags })
    }
}

// ── Tread (116) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tread {
    pub tag:    u16,
    pub fid:    u32,
    pub offset: u64,
    pub count:  u32,
}

impl Tread {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(16);
        put_u32(&mut body, self.fid);
        put_u64(&mut body, self.offset);
        put_u32(&mut body, self.count);
        frame(T_READ, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_READ { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let fid    = take_u32(buf, &mut off)?;
        let offset = take_u64(buf, &mut off)?;
        let count  = take_u32(buf, &mut off)?;
        Ok(Self { tag: h.tag, fid, offset, count })
    }
}

// ── Tclunk (120) ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tclunk {
    pub tag: u16,
    pub fid: u32,
}

impl Tclunk {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4);
        put_u32(&mut body, self.fid);
        frame(T_CLUNK, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != T_CLUNK { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let fid = take_u32(buf, &mut off)?;
        Ok(Self { tag: h.tag, fid })
    }
}

// ── Rversion (101) ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rversion {
    pub tag:     u16,
    pub msize:   u32,
    pub version: Vec<u8>,
}

impl Rversion {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + 2 + self.version.len());
        put_u32(&mut body, self.msize);
        put_str(&mut body, &self.version);
        frame(R_VERSION, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_VERSION { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let msize   = take_u32(buf, &mut off)?;
        let version = take_str(buf, &mut off)?;
        Ok(Self { tag: h.tag, msize, version })
    }
}

// ── Rattach (105) ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rattach {
    pub tag: u16,
    pub qid: Qid,
}

impl Rattach {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(QID_LEN);
        self.qid.encode_into(&mut body);
        frame(R_ATTACH, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_ATTACH { return Err(DecodeError::BadType); }
        let (qid, _) = Qid::decode(&buf[HEADER_LEN..])?;
        Ok(Self { tag: h.tag, qid })
    }
}

// ── Rwalk (111) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rwalk {
    pub tag:   u16,
    pub wqids: Vec<Qid>,
}

impl Rwalk {
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        if self.wqids.len() > Twalk::MAX_WNAMES {
            return Err(DecodeError::TooManyWnames);
        }
        let mut body = Vec::with_capacity(2 + self.wqids.len() * QID_LEN);
        put_u16(&mut body, self.wqids.len() as u16);
        for q in &self.wqids { q.encode_into(&mut body); }
        Ok(frame(R_WALK, self.tag, &body))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_WALK { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let n = take_u16(buf, &mut off)? as usize;
        if n > Twalk::MAX_WNAMES { return Err(DecodeError::TooManyWnames); }
        let mut wqids = Vec::with_capacity(n);
        for _ in 0..n {
            let (q, used) = Qid::decode(&buf[off..])?;
            off += used;
            wqids.push(q);
        }
        Ok(Self { tag: h.tag, wqids })
    }
}

// ── Rlopen (13) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rlopen {
    pub tag:    u16,
    pub qid:    Qid,
    pub iounit: u32,
}

impl Rlopen {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(QID_LEN + 4);
        self.qid.encode_into(&mut body);
        put_u32(&mut body, self.iounit);
        frame(R_LOPEN, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_LOPEN { return Err(DecodeError::BadType); }
        let (qid, used) = Qid::decode(&buf[HEADER_LEN..])?;
        let mut off = HEADER_LEN + used;
        let iounit = take_u32(buf, &mut off)?;
        Ok(Self { tag: h.tag, qid, iounit })
    }
}

// ── Rread (117) ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rread {
    pub tag:  u16,
    pub data: Vec<u8>,
}

impl Rread {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + self.data.len());
        put_u32(&mut body, self.data.len() as u32);
        body.extend_from_slice(&self.data);
        frame(R_READ, self.tag, &body)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_READ { return Err(DecodeError::BadType); }
        let mut off = HEADER_LEN;
        let count = take_u32(buf, &mut off)? as usize;
        if buf.len() < off + count { return Err(DecodeError::Short); }
        let mut data = Vec::with_capacity(count);
        data.extend_from_slice(&buf[off..off + count]);
        Ok(Self { tag: h.tag, data })
    }
}

// ── Rclunk (121) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rclunk { pub tag: u16 }

impl Rclunk {
    pub fn encode(&self) -> Vec<u8> {
        frame(R_CLUNK, self.tag, &[])
    }
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let h = Header::decode(buf)?;
        if h.kind != R_CLUNK { return Err(DecodeError::BadType); }
        Ok(Self { tag: h.tag })
    }
}
