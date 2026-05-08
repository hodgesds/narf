//! 9P2000 wire format codec.
//!
//! Pure-function encoder / decoder for every T-message and R-message
//! the driver exchanges. The protocol's normative layout is defined
//! in:
//! - `intro(5)` — frame format, qid, tag/fid conventions.
//! - `version(5)` — Tversion / Rversion bodies, NOTAG.
//! - `attach(5)` — Tattach / Rattach, NOFID.
//! - `walk(5)` — Twalk / Rwalk; component name validation rules.
//! - `open(5)` — Topen / Ropen; mode bits.
//! - `read(5)` / `write(5)` — Tread / Rread / Twrite / Rwrite.
//! - `clunk(5)` / `remove(5)` — Tclunk / Rclunk, Tremove / Rremove.
//! - `stat(5)` — Tstat / Rstat; the variable-length stat structure.
//! - `error(5)` — Rerror.
//! See <https://9fans.github.io/plan9port/man/man9/>.
//!
//! No GPL/LGPL 9P implementation source was consulted while writing
//! this file — algorithms are derived strictly from the man pages.

use alloc::string::String;
use alloc::vec::Vec;

/// Frame header size: `size[4] type[1] tag[2]` = 7 bytes (intro(5)).
pub const HEADER_SIZE: usize = 7;

/// "no fid" sentinel returned by Tattach when there is no auth fid
/// (attach(5)).
pub const NOFID: u32 = 0xFFFF_FFFF;

/// "no tag" sentinel for Tversion (version(5)). Real T-messages MUST
/// use a tag distinct from NOTAG.
pub const NOTAG: u16 = 0xFFFF;

/// Decoder / encoder error surface. Surfaces wire-format violations
/// (truncated frame, length-prefix overflow, unknown message type).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer ended before the requested field could be read.
    ShortBuffer,
    /// Length-prefixed string overflowed `u16::MAX` bytes (stat(5)
    /// caps strings at this length implicitly through the size[2]
    /// prefix).
    StringTooLong,
    /// Encoder ran out of room in the destination buffer.
    OutOfRoom,
    /// Header `type[1]` byte did not name a known T- or R-message.
    UnknownMsgType,
    /// More than 16 walk-name components in a single Twalk
    /// (walk(5) §"the maximum number of names in a single walk is
    /// 16").
    TooManyWalkNames,
    /// `validate_walk_name` rejected: component empty or contained
    /// `/`.
    InvalidWalkName,
}

/// 9P message-type tag byte (intro(5)).
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

impl MsgType {
    pub fn from_u8(b: u8) -> Result<Self, DecodeError> {
        match b {
            100 => Ok(MsgType::Tversion),
            101 => Ok(MsgType::Rversion),
            102 => Ok(MsgType::Tauth),
            103 => Ok(MsgType::Rauth),
            104 => Ok(MsgType::Tattach),
            105 => Ok(MsgType::Rattach),
            106 => Ok(MsgType::Terror),
            107 => Ok(MsgType::Rerror),
            108 => Ok(MsgType::Tflush),
            109 => Ok(MsgType::Rflush),
            110 => Ok(MsgType::Twalk),
            111 => Ok(MsgType::Rwalk),
            112 => Ok(MsgType::Topen),
            113 => Ok(MsgType::Ropen),
            114 => Ok(MsgType::Tcreate),
            115 => Ok(MsgType::Rcreate),
            116 => Ok(MsgType::Tread),
            117 => Ok(MsgType::Rread),
            118 => Ok(MsgType::Twrite),
            119 => Ok(MsgType::Rwrite),
            120 => Ok(MsgType::Tclunk),
            121 => Ok(MsgType::Rclunk),
            122 => Ok(MsgType::Tremove),
            123 => Ok(MsgType::Rremove),
            124 => Ok(MsgType::Tstat),
            125 => Ok(MsgType::Rstat),
            126 => Ok(MsgType::Twstat),
            127 => Ok(MsgType::Rwstat),
            _ => Err(DecodeError::UnknownMsgType),
        }
    }
}

/// 13-byte qid: `type[1] version[4] path[8]` (intro(5)).
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Qid {
    pub qid_type: u8,
    pub version: u32,
    pub path: u64,
}

/// `qid_type` constants per intro(5).
pub mod qtype {
    /// Directory.
    pub const DIR: u8 = 0x80;
    /// Append-only file.
    pub const APPEND: u8 = 0x40;
    /// Exclusive-use file.
    pub const EXCL: u8 = 0x20;
    /// Authentication file (auth(5)).
    pub const AUTH: u8 = 0x08;
    /// Plain file (zero high bits).
    pub const FILE: u8 = 0x00;
}

/// `mode` field constants (the high byte of a stat's mode field
/// mirrors the qid's type bits per stat(5)).
pub mod statmode {
    pub const DIR: u32 = 0x8000_0000;
    pub const APPEND: u32 = 0x4000_0000;
    pub const EXCL: u32 = 0x2000_0000;
    pub const AUTH: u32 = 0x0800_0000;
}

/// `Topen`/`Tcreate` mode-byte bottom 4 bits per open(5).
pub mod oflag {
    pub const READ: u8 = 0;
    pub const WRITE: u8 = 1;
    pub const RDWR: u8 = 2;
    pub const EXEC: u8 = 3;
    /// Truncate on open.
    pub const TRUNC: u8 = 0x10;
    /// Remove on close.
    pub const RCLOSE: u8 = 0x40;
}

/// Variable-length stat structure (stat(5)). Encoded as
/// `size[2] type[2] dev[4] qid[13] mode[4] atime[4] mtime[4]
/// length[8] name[s] uid[s] gid[s] muid[s]` where `size` is the
/// inclusive byte count of every field after `size` itself.
///
/// Field names mirror the spec; the rust-keyword-clashing `type`
/// and `dev` are renamed to `kernel_type` / `kernel_dev`.
#[derive(Clone, Debug, Default)]
pub struct P9Stat {
    pub kernel_type: u16,
    pub kernel_dev: u32,
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
    /// Number of body bytes the encoder will emit AFTER the leading
    /// `size[2]` field. The leading size itself encodes this count.
    /// Used by Rstat outer framing (which wraps the stat body in its
    /// own length prefix per stat(5)).
    pub fn body_len(&self) -> usize {
        // Fixed: type(2) + dev(4) + qid(13) + mode(4) + atime(4)
        //      + mtime(4) + length(8) = 39
        // Plus four length-prefixed strings: 4 * 2 + str lengths.
        39 + 4 * 2 + self.name.len() + self.uid.len() + self.gid.len() + self.muid.len()
    }

    pub fn encode(&self, w: &mut WireWrite) -> Result<(), DecodeError> {
        let body = self.body_len();
        if body > u16::MAX as usize {
            return Err(DecodeError::StringTooLong);
        }
        w.write_u16(body as u16)?;
        w.write_u16(self.kernel_type)?;
        w.write_u32(self.kernel_dev)?;
        w.write_qid(&self.qid)?;
        w.write_u32(self.mode)?;
        w.write_u32(self.atime)?;
        w.write_u32(self.mtime)?;
        w.write_u64(self.length)?;
        w.write_str(&self.name)?;
        w.write_str(&self.uid)?;
        w.write_str(&self.gid)?;
        w.write_str(&self.muid)?;
        Ok(())
    }

    pub fn decode(r: &mut WireRead) -> Result<Self, DecodeError> {
        let _size = r.read_u16()?; // size[2] — informational; we read by field
        let kernel_type = r.read_u16()?;
        let kernel_dev = r.read_u32()?;
        let qid = r.read_qid()?;
        let mode = r.read_u32()?;
        let atime = r.read_u32()?;
        let mtime = r.read_u32()?;
        let length = r.read_u64()?;
        let name = r.read_str()?;
        let uid = r.read_str()?;
        let gid = r.read_str()?;
        let muid = r.read_str()?;
        Ok(Self {
            kernel_type,
            kernel_dev,
            qid,
            mode,
            atime,
            mtime,
            length,
            name,
            uid,
            gid,
            muid,
        })
    }
}

// ── Wire I/O ────────────────────────────────────────────────────────

/// Forward iterator over a byte buffer. Reads are little-endian
/// (intro(5): all integers are little-endian on the wire).
#[derive(Debug)]
pub struct WireRead<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireRead<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.data.len() {
            return Err(DecodeError::ShortBuffer);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn read_str(&mut self) -> Result<String, DecodeError> {
        let n = self.read_u16()? as usize;
        let bytes = self.take(n)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn read_qid(&mut self) -> Result<Qid, DecodeError> {
        let qid_type = self.read_u8()?;
        let version = self.read_u32()?;
        let path = self.read_u64()?;
        Ok(Qid {
            qid_type,
            version,
            path,
        })
    }
}

/// Forward writer over a byte buffer. Same little-endian
/// convention as [`WireRead`].
#[derive(Debug)]
pub struct WireWrite<'a> {
    data: &'a mut [u8],
    pos: usize,
}

impl<'a> WireWrite<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        if self.pos + bytes.len() > self.data.len() {
            return Err(DecodeError::OutOfRoom);
        }
        self.data[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), DecodeError> {
        self.put(&[v])
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), DecodeError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), DecodeError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), DecodeError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_str(&mut self, s: &str) -> Result<(), DecodeError> {
        if s.len() > u16::MAX as usize {
            return Err(DecodeError::StringTooLong);
        }
        self.write_u16(s.len() as u16)?;
        self.put(s.as_bytes())
    }

    pub fn write_qid(&mut self, q: &Qid) -> Result<(), DecodeError> {
        self.write_u8(q.qid_type)?;
        self.write_u32(q.version)?;
        self.write_u64(q.path)
    }

    /// Patch the leading `size[4]` field after the body has been
    /// written. Used by `frame_message` to back-fill the total
    /// frame length.
    pub fn patch_u32_at(&mut self, offset: usize, v: u32) -> Result<(), DecodeError> {
        if offset + 4 > self.pos {
            return Err(DecodeError::OutOfRoom);
        }
        self.data[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
}

// ── Header + per-message helpers ───────────────────────────────────

/// Validate a single Twalk path component per walk(5).
pub fn validate_walk_name(name: &str) -> Result<(), DecodeError> {
    let n = name.len();
    if n == 0 || n > 255 {
        return Err(DecodeError::InvalidWalkName);
    }
    if name.as_bytes().contains(&b'/') {
        return Err(DecodeError::InvalidWalkName);
    }
    Ok(())
}

/// Decode the 7-byte frame header. Returns `(size, type, tag)`.
pub fn decode_header(r: &mut WireRead) -> Result<(u32, MsgType, u16), DecodeError> {
    let size = r.read_u32()?;
    let mtype = MsgType::from_u8(r.read_u8()?)?;
    let tag = r.read_u16()?;
    Ok((size, mtype, tag))
}

/// Tversion body: `msize[4] version[s]`.
pub fn encode_tversion(w: &mut WireWrite, msize: u32, version: &str) -> Result<(), DecodeError> {
    w.write_u32(msize)?;
    w.write_str(version)
}

/// Rversion body — same layout as Tversion.
#[derive(Clone, Debug)]
pub struct Rversion {
    pub msize: u32,
    pub version: String,
}

pub fn decode_rversion(r: &mut WireRead) -> Result<Rversion, DecodeError> {
    let msize = r.read_u32()?;
    let version = r.read_str()?;
    Ok(Rversion { msize, version })
}

/// Tattach body: `fid[4] afid[4] uname[s] aname[s]`.
pub fn encode_tattach(
    w: &mut WireWrite,
    fid: u32,
    afid: u32,
    uname: &str,
    aname: &str,
) -> Result<(), DecodeError> {
    w.write_u32(fid)?;
    w.write_u32(afid)?;
    w.write_str(uname)?;
    w.write_str(aname)
}

/// Twalk body: `fid[4] newfid[4] nwname[2] wname[s]*nwname`.
pub fn encode_twalk(
    w: &mut WireWrite,
    fid: u32,
    newfid: u32,
    names: &[&str],
) -> Result<(), DecodeError> {
    if names.len() > 16 {
        return Err(DecodeError::TooManyWalkNames);
    }
    for n in names {
        validate_walk_name(n)?;
    }
    w.write_u32(fid)?;
    w.write_u32(newfid)?;
    w.write_u16(names.len() as u16)?;
    for n in names {
        w.write_str(n)?;
    }
    Ok(())
}

/// Topen body: `fid[4] mode[1]`.
pub fn encode_topen(w: &mut WireWrite, fid: u32, mode: u8) -> Result<(), DecodeError> {
    w.write_u32(fid)?;
    w.write_u8(mode)
}

/// Tread body: `fid[4] offset[8] count[4]`.
pub fn encode_tread(w: &mut WireWrite, fid: u32, offset: u64, count: u32) -> Result<(), DecodeError> {
    w.write_u32(fid)?;
    w.write_u64(offset)?;
    w.write_u32(count)
}

/// Tclunk body: `fid[4]`.
pub fn encode_tclunk(w: &mut WireWrite, fid: u32) -> Result<(), DecodeError> {
    w.write_u32(fid)
}

/// Tstat body: `fid[4]`.
pub fn encode_tstat(w: &mut WireWrite, fid: u32) -> Result<(), DecodeError> {
    w.write_u32(fid)
}

/// Rread body decode. Returns the data slice as an owned Vec since
/// it crosses a buffer-lifetime boundary in most callers.
pub fn decode_rread(r: &mut WireRead) -> Result<Vec<u8>, DecodeError> {
    let count = r.read_u32()? as usize;
    let mut v = Vec::with_capacity(count);
    for _ in 0..count {
        v.push(r.read_u8()?);
    }
    Ok(v)
}

/// Rwalk body decode. Returns the qid list (one per successfully-
/// walked name).
pub fn decode_rwalk(r: &mut WireRead) -> Result<Vec<Qid>, DecodeError> {
    let n = r.read_u16()? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(r.read_qid()?);
    }
    Ok(v)
}

/// Rerror body decode: `ename[s]`.
pub fn decode_rerror(r: &mut WireRead) -> Result<String, DecodeError> {
    r.read_str()
}
