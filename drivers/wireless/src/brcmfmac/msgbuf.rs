//! `brcmfmac` Common-ring + msgbuf protocol — Stage-1 + Stage-2.
//!
//! ## Common-ring (Stage-1)
//!
//! Broadcom's PCIe FullMAC silicon exposes Wi-Fi to the host through a
//! set of fixed-layout SPSC rings in shared memory ("TCM" in the
//! firmware blob, mapped through BAR2 on the host). The dispatcher
//! state machine for each ring is a classic circular SPSC with three
//! cursors:
//!
//!   - `r_ptr` — the next slot the **consumer** will read.
//!   - `w_ptr` — the next slot the **producer** will write.
//!   - `f_ptr` — the "flushed-to-peer" cursor — `w_ptr` at the moment
//!     the producer last rang the doorbell.
//!
//! `(depth - 1)` usable slots; one slot is sacrificed to disambiguate
//! "ring empty" from "ring full" without an extra bool. The
//! implementation here mirrors Linux's `brcmf_commonring_*` family
//! (`drivers/net/wireless/broadcom/brcm80211/brcmfmac/commonring.c`,
//! v6.6, 236 lines).
//!
//! ## Ring identification
//!
//! Per `bus.h` (~L14):
//!
//! | ID | Name                              | Direction | items / item-size |
//! |---:|-----------------------------------|-----------|-------------------|
//! | 0  | H2D control submit                | host → dev| 64 × 40 bytes     |
//! | 1  | H2D RX-buffer-post submit         | host → dev| 1024 × 32 bytes   |
//! | 2  | D2H control complete              | dev → host| 64 × 24 bytes     |
//! | 3  | D2H TX complete                   | dev → host| 1024 × 24 bytes (16 pre-v7) |
//! | 4  | D2H RX complete                   | dev → host| 1024 × 40 bytes (32 pre-v7) |
//!
//! Reference (msgbuf.h ~L10..L23 for the constants below).
//!
//! ## Msgbuf (Stage-2)
//!
//! The IOCTL request / response + WL event encoding follows
//! `msgbuf.c::msgbuf_ioctl_req_hdr` and friends. Encoders and decoders
//! here are deliberately pure-data (no live silicon), so they can be
//! exercised by smoke tests without standing up a TCM mock.

#![allow(dead_code)]

use core::convert::TryInto;

// ── Ring identification (per `bus.h` ~L14) ─────────────────────────

/// `BRCMF_H2D_MSGRING_CONTROL_SUBMIT` — host-to-device IOCTL/control
/// submission queue.
pub const H2D_MSGRING_CONTROL_SUBMIT: u8 = 0;
/// `BRCMF_H2D_MSGRING_RXPOST_SUBMIT` — host posts pre-allocated RX
/// buffers here for the firmware to DMA into.
pub const H2D_MSGRING_RXPOST_SUBMIT: u8 = 1;
/// `BRCMF_D2H_MSGRING_CONTROL_COMPLETE` — device-to-host IOCTL
/// response + WL events.
pub const D2H_MSGRING_CONTROL_COMPLETE: u8 = 2;
/// `BRCMF_D2H_MSGRING_TX_COMPLETE` — device-to-host TX completion.
pub const D2H_MSGRING_TX_COMPLETE: u8 = 3;
/// `BRCMF_D2H_MSGRING_RX_COMPLETE` — device-to-host RX completion.
pub const D2H_MSGRING_RX_COMPLETE: u8 = 4;

/// Number of H2D common (non-flow) rings. `BRCMF_NROF_H2D_COMMON_MSGRINGS`.
pub const NROF_H2D_COMMON_MSGRINGS: usize = 2;
/// Number of D2H common rings. `BRCMF_NROF_D2H_COMMON_MSGRINGS`.
pub const NROF_D2H_COMMON_MSGRINGS: usize = 3;
/// Total common rings: 5 (= 2 H2D + 3 D2H).
pub const NROF_COMMON_MSGRINGS: usize = NROF_H2D_COMMON_MSGRINGS + NROF_D2H_COMMON_MSGRINGS;

// Per `msgbuf.h` ~L10..L23. Item sizes change between firmware
// versions (pre-v7 vs v7+) for the D2H TX/RX completes; the rest are
// stable.
pub const H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM: u16 = 64;
pub const H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM: u16 = 1024;
pub const D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM: u16 = 64;
pub const D2H_MSGRING_TX_COMPLETE_MAX_ITEM: u16 = 1024;
pub const D2H_MSGRING_RX_COMPLETE_MAX_ITEM: u16 = 1024;
pub const H2D_TXFLOWRING_MAX_ITEM: u16 = 512;

pub const H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE: u16 = 40;
pub const H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE: u16 = 32;
pub const D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE: u16 = 24;
pub const D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7: u16 = 16;
pub const D2H_MSGRING_TX_COMPLETE_ITEMSIZE: u16 = 24;
pub const D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7: u16 = 32;
pub const D2H_MSGRING_RX_COMPLETE_ITEMSIZE: u16 = 40;
pub const H2D_TXFLOWRING_ITEMSIZE: u16 = 48;

/// Static layout of a common ring for the per-id queries used at
/// ring-config time. The `pre_v7` flag picks the smaller item-size
/// where Broadcom shrunk it post-v7.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingLayout {
    pub id: u8,
    pub depth: u16,
    pub item_len: u16,
    pub is_h2d: bool,
}

/// Return the configured layout for a given ring id and shared-memory
/// protocol version. `pre_v7` is true if the firmware advertises shared
/// version < 7 (different TX/RX-complete item sizes).
pub const fn ring_layout(id: u8, pre_v7: bool) -> Option<RingLayout> {
    match id {
        H2D_MSGRING_CONTROL_SUBMIT => Some(RingLayout {
            id,
            depth: H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM,
            item_len: H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE,
            is_h2d: true,
        }),
        H2D_MSGRING_RXPOST_SUBMIT => Some(RingLayout {
            id,
            depth: H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM,
            item_len: H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE,
            is_h2d: true,
        }),
        D2H_MSGRING_CONTROL_COMPLETE => Some(RingLayout {
            id,
            depth: D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM,
            item_len: D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE,
            is_h2d: false,
        }),
        D2H_MSGRING_TX_COMPLETE => Some(RingLayout {
            id,
            depth: D2H_MSGRING_TX_COMPLETE_MAX_ITEM,
            item_len: if pre_v7 {
                D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7
            } else {
                D2H_MSGRING_TX_COMPLETE_ITEMSIZE
            },
            is_h2d: false,
        }),
        D2H_MSGRING_RX_COMPLETE => Some(RingLayout {
            id,
            depth: D2H_MSGRING_RX_COMPLETE_MAX_ITEM,
            item_len: if pre_v7 {
                D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7
            } else {
                D2H_MSGRING_RX_COMPLETE_ITEMSIZE
            },
            is_h2d: false,
        }),
        _ => None,
    }
}

// ── Common-ring SPSC cursor state machine ──────────────────────────
//
// Mirrors `brcmf_commonring` (commonring.h ~L9..L32). The `inited`
// + `was_full` + lock + outstanding_tx fields stay in the per-ring
// wrapper that lives in the data-path follow-up; this struct only
// covers the index dance, which is what's safely unit-testable.

#[derive(Copy, Clone, Debug)]
pub struct Ring {
    /// Next slot to be consumed.
    pub r_ptr: u16,
    /// Next slot to be produced.
    pub w_ptr: u16,
    /// Producer's `w_ptr` at the most recent doorbell-ring.
    pub f_ptr: u16,
    /// Total slots in the ring buffer.
    pub depth: u16,
    /// Bytes per slot.
    pub item_len: u16,
}

impl Ring {
    /// Construct a fresh ring with the given dimensions. Mirrors
    /// `brcmf_commonring_config` (commonring.c ~L31..L48).
    pub const fn new(depth: u16, item_len: u16) -> Self {
        Self {
            r_ptr: 0,
            w_ptr: 0,
            f_ptr: 0,
            depth,
            item_len,
        }
    }

    /// Number of slots available to the producer **without** wrapping
    /// the queue-full sentinel. Direct port of
    /// `brcmf_commonring_write_available` (commonring.c ~L68..L93)
    /// minus the cb-driven r_ptr update — that's the caller's job
    /// because we don't own the doorbell IO in the index layer.
    pub fn write_available(&self) -> u16 {
        let avail = if self.r_ptr <= self.w_ptr {
            self.depth - self.w_ptr + self.r_ptr
        } else {
            self.r_ptr - self.w_ptr
        };
        avail.saturating_sub(1)
    }

    /// Reserve a single slot for write. Returns the byte offset of the
    /// reserved slot in the backing buffer, or `None` if the ring is
    /// full. Mirrors `brcmf_commonring_reserve_for_write`
    /// (commonring.c ~L108..L139); the cb-driven r_ptr refresh is
    /// caller-managed.
    pub fn reserve_one(&mut self) -> Option<u32> {
        if self.write_available() == 0 {
            return None;
        }
        let offset = (self.w_ptr as u32) * (self.item_len as u32);
        self.w_ptr += 1;
        if self.w_ptr == self.depth {
            self.w_ptr = 0;
        }
        Some(offset)
    }

    /// Reserve a contiguous run of at most `n_items` slots. Returns
    /// `Some((byte_offset, granted))` or `None` if the ring is full.
    /// Mirrors `brcmf_commonring_reserve_for_write_multiple`
    /// (commonring.c ~L142..L178).
    pub fn reserve_multi(&mut self, n_items: u16) -> Option<(u32, u16)> {
        let avail = self.write_available();
        if avail == 0 {
            return None;
        }
        let offset = (self.w_ptr as u32) * (self.item_len as u32);
        let mut granted = core::cmp::min(n_items, avail);
        if granted + self.w_ptr > self.depth {
            granted = self.depth - self.w_ptr;
        }
        self.w_ptr += granted;
        if self.w_ptr == self.depth {
            self.w_ptr = 0;
        }
        Some((offset, granted))
    }

    /// Cancel the last `n_items` reservation. Used when the caller
    /// found mid-build that the reserved slot won't be committed.
    /// Mirrors `brcmf_commonring_write_cancel`
    /// (commonring.c ~L197..L204).
    pub fn write_cancel(&mut self, n_items: u16) {
        if self.w_ptr == 0 {
            self.w_ptr = self.depth - n_items;
        } else {
            self.w_ptr -= n_items;
        }
    }

    /// Snap `f_ptr` to `w_ptr` — the caller has finished publishing
    /// new entries and is about to ring the doorbell. Mirrors the
    /// in-`write_complete` cursor advance (commonring.c ~L181..L194)
    /// without the cb-driven doorbell IO.
    pub fn publish(&mut self) {
        if self.f_ptr > self.w_ptr {
            self.f_ptr = 0;
        }
        self.f_ptr = self.w_ptr;
    }

    /// Number of items the consumer can take in one read. Mirrors
    /// `brcmf_commonring_get_read_ptr` (commonring.c ~L207..L222)
    /// minus the cb-driven w_ptr refresh.
    pub fn read_available(&self) -> u16 {
        if self.w_ptr >= self.r_ptr {
            self.w_ptr - self.r_ptr
        } else {
            self.depth - self.r_ptr
        }
    }

    /// Return the byte offset of the next consumable item if any, else
    /// `None`. Mirrors the read-pointer derivation in
    /// `brcmf_commonring_get_read_ptr`.
    pub fn read_offset(&self) -> Option<u32> {
        if self.read_available() == 0 {
            return None;
        }
        Some((self.r_ptr as u32) * (self.item_len as u32))
    }

    /// Advance `r_ptr` by `n_items`. Mirrors
    /// `brcmf_commonring_read_complete` (commonring.c ~L225..L236)
    /// minus the cb-driven cursor write.
    pub fn read_complete(&mut self, n_items: u16) {
        self.r_ptr += n_items;
        if self.r_ptr == self.depth {
            self.r_ptr = 0;
        }
    }
}

// ── msgbuf protocol (Stage-2) ──────────────────────────────────────
//
// The msgbuf protocol is the wire format that rides the H2D/D2H
// common rings. Per `msgbuf.c` (v6.6 ~L30..L60), every message starts
// with a 7-byte common header and the message-type field selects the
// rest of the layout. The encoders/decoders below cover the IOCTL
// request, IOCTL response, and WL event paths — Stage-2's bar.

/// `MSGBUF_TYPE_*` — wire-level message type tags per `msgbuf.c` ~L30.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    GenStatus = 0x01,
    RingStatus = 0x02,
    FlowRingCreate = 0x03,
    FlowRingCreateCmplt = 0x04,
    FlowRingDelete = 0x05,
    FlowRingDeleteCmplt = 0x06,
    FlowRingFlush = 0x07,
    FlowRingFlushCmplt = 0x08,
    IoctlPtrReq = 0x09,
    IoctlPtrReqAck = 0x0A,
    IoctlRespBufPost = 0x0B,
    IoctlCmplt = 0x0C,
    EventBufPost = 0x0D,
    WlEvent = 0x0E,
    TxPost = 0x0F,
    TxStatus = 0x10,
    RxBufPost = 0x11,
    RxCmplt = 0x12,
    LpbkDmaxfer = 0x13,
    LpbkDmaxferCmplt = 0x14,
}

impl MsgType {
    /// Try to interpret a raw byte as a known `MsgType`. Returns `None`
    /// for unknown values so callers can fail safely on garbage.
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::GenStatus),
            0x02 => Some(Self::RingStatus),
            0x03 => Some(Self::FlowRingCreate),
            0x04 => Some(Self::FlowRingCreateCmplt),
            0x05 => Some(Self::FlowRingDelete),
            0x06 => Some(Self::FlowRingDeleteCmplt),
            0x07 => Some(Self::FlowRingFlush),
            0x08 => Some(Self::FlowRingFlushCmplt),
            0x09 => Some(Self::IoctlPtrReq),
            0x0A => Some(Self::IoctlPtrReqAck),
            0x0B => Some(Self::IoctlRespBufPost),
            0x0C => Some(Self::IoctlCmplt),
            0x0D => Some(Self::EventBufPost),
            0x0E => Some(Self::WlEvent),
            0x0F => Some(Self::TxPost),
            0x10 => Some(Self::TxStatus),
            0x11 => Some(Self::RxBufPost),
            0x12 => Some(Self::RxCmplt),
            0x13 => Some(Self::LpbkDmaxfer),
            0x14 => Some(Self::LpbkDmaxferCmplt),
            _ => None,
        }
    }
}

/// Common 8-byte header sitting at the front of every msgbuf message.
/// Layout per `msgbuf.c::msgbuf_common_hdr` (~L76):
///
/// ```c
/// struct msgbuf_common_hdr {
///     u8  msgtype;
///     u8  ifidx;
///     u8  flags;
///     u8  rsvd0;
///     __le32 request_id;
/// };
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommonHdr {
    pub msgtype: u8,
    pub ifidx: u8,
    pub flags: u8,
    pub request_id: u32,
}

/// Wire size of the common header. Used as the base offset for every
/// type-specific layout below.
pub const COMMON_HDR_SIZE: usize = 8;

impl CommonHdr {
    /// Encode into the first 8 bytes of `out`. Returns `None` if the
    /// buffer is too small.
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < COMMON_HDR_SIZE {
            return None;
        }
        out[0] = self.msgtype;
        out[1] = self.ifidx;
        out[2] = self.flags;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        Some(())
    }

    /// Decode from the first 8 bytes of `bytes`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < COMMON_HDR_SIZE {
            return None;
        }
        let request_id = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        Some(Self {
            msgtype: bytes[0],
            ifidx: bytes[1],
            flags: bytes[2],
            request_id,
        })
    }
}

/// 8-byte 64-bit DMA buffer-address descriptor used everywhere a
/// firmware-side pointer is shipped. Layout per
/// `msgbuf.h::msgbuf_buf_addr`:
///
/// ```c
/// struct msgbuf_buf_addr {
///     __le32 low_addr;
///     __le32 high_addr;
/// };
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BufAddr(pub u64);

impl BufAddr {
    pub const SIZE: usize = 8;

    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < Self::SIZE {
            return None;
        }
        let raw = self.0;
        out[0..4].copy_from_slice(&((raw & 0xFFFF_FFFF) as u32).to_le_bytes());
        out[4..8].copy_from_slice(&((raw >> 32) as u32).to_le_bytes());
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let low = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as u64;
        let high = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as u64;
        Some(BufAddr(low | (high << 32)))
    }
}

// ── IOCTL request (`MSGBUF_TYPE_IOCTLPTR_REQ`) ─────────────────────
//
// Layout per `msgbuf.c::msgbuf_ioctl_req_hdr` (~L84):
//
//   common_hdr (8B)
//   cmd                    u32 LE          @ 8
//   trans_id               u16 LE          @ 12
//   input_buf_len          u16 LE          @ 14
//   output_buf_len         u16 LE          @ 16
//   rsvd0[3]               u16 LE x 3      @ 18  (=18..24)
//   req_buf_addr           BufAddr (8B)    @ 24..32
//   rsvd1[2]               u32 LE x 2      @ 32..40
//
// Total 40 bytes — matches H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE.

/// Encoded form of `MSGBUF_TYPE_IOCTLPTR_REQ`. The caller is
/// responsible for getting the `input_buf_len`-byte IOCTL payload
/// into the DMA buffer referenced by `req_buf_addr` — this struct
/// only encodes the control message itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoctlReq {
    pub hdr: CommonHdr,
    pub cmd: u32,
    pub trans_id: u16,
    pub input_buf_len: u16,
    pub output_buf_len: u16,
    pub req_buf_addr: BufAddr,
}

/// Wire size of an encoded IOCTL request. Used by ring-config code to
/// double-check the H2D control-submit item size matches.
pub const IOCTL_REQ_SIZE: usize = 40;

impl IoctlReq {
    /// Encode the request to a 40-byte buffer.
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < IOCTL_REQ_SIZE {
            return None;
        }
        // Force msgtype to IoctlPtrReq even if the caller set the hdr
        // wrong — the protocol only ever encodes this struct with
        // type=0x09.
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::IoctlPtrReq as u8;
        hdr.encode(out)?;
        out[8..12].copy_from_slice(&self.cmd.to_le_bytes());
        out[12..14].copy_from_slice(&self.trans_id.to_le_bytes());
        out[14..16].copy_from_slice(&self.input_buf_len.to_le_bytes());
        out[16..18].copy_from_slice(&self.output_buf_len.to_le_bytes());
        // rsvd0[3] — zeroed.
        out[18..24].fill(0);
        self.req_buf_addr.encode(&mut out[24..32])?;
        // rsvd1[2] — zeroed.
        out[32..40].fill(0);
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IOCTL_REQ_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let cmd = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let trans_id = u16::from_le_bytes(bytes[12..14].try_into().ok()?);
        let input_buf_len = u16::from_le_bytes(bytes[14..16].try_into().ok()?);
        let output_buf_len = u16::from_le_bytes(bytes[16..18].try_into().ok()?);
        let req_buf_addr = BufAddr::decode(&bytes[24..32])?;
        Some(Self {
            hdr,
            cmd,
            trans_id,
            input_buf_len,
            output_buf_len,
            req_buf_addr,
        })
    }
}

// ── IOCTL response (`MSGBUF_TYPE_IOCTL_CMPLT`) ─────────────────────
//
// Layout per `msgbuf.c::msgbuf_ioctl_resp_hdr` (~L153):
//
//   common_hdr (8B)
//   compl_hdr             {u16 status; u16 flow_ring_id} (4B) @ 8..12
//   resp_len               u16 LE                 @ 12
//   trans_id               u16 LE                 @ 14
//   cmd                    u32 LE                 @ 16
//   rsvd0                  u32 LE                 @ 20
//
// Total 24 bytes — matches D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoctlResp {
    pub hdr: CommonHdr,
    pub status: u16,
    pub flow_ring_id: u16,
    pub resp_len: u16,
    pub trans_id: u16,
    pub cmd: u32,
}

pub const IOCTL_RESP_SIZE: usize = 24;

impl IoctlResp {
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < IOCTL_RESP_SIZE {
            return None;
        }
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::IoctlCmplt as u8;
        hdr.encode(out)?;
        out[8..10].copy_from_slice(&self.status.to_le_bytes());
        out[10..12].copy_from_slice(&self.flow_ring_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.resp_len.to_le_bytes());
        out[14..16].copy_from_slice(&self.trans_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.cmd.to_le_bytes());
        out[20..24].fill(0);
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IOCTL_RESP_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let status = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
        let flow_ring_id = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
        let resp_len = u16::from_le_bytes(bytes[12..14].try_into().ok()?);
        let trans_id = u16::from_le_bytes(bytes[14..16].try_into().ok()?);
        let cmd = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        Some(Self {
            hdr,
            status,
            flow_ring_id,
            resp_len,
            trans_id,
            cmd,
        })
    }
}

// ── WL event (`MSGBUF_TYPE_WL_EVENT`) ──────────────────────────────
//
// Layout per `msgbuf.c::msgbuf_rx_event` (~L145):
//
//   common_hdr (8B)
//   compl_hdr  (4B)                 @ 8..12
//   event_data_len u16 LE           @ 12
//   seqnum         u16 LE           @ 14
//   rsvd0[4]       u16 LE x 4       @ 16..24
//
// Total 24 bytes — same item size as IOCTL completion (they share
// the D2H control-complete ring).

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WlEvent {
    pub hdr: CommonHdr,
    pub status: u16,
    pub flow_ring_id: u16,
    pub event_data_len: u16,
    pub seqnum: u16,
}

pub const WL_EVENT_SIZE: usize = 24;

impl WlEvent {
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < WL_EVENT_SIZE {
            return None;
        }
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::WlEvent as u8;
        hdr.encode(out)?;
        out[8..10].copy_from_slice(&self.status.to_le_bytes());
        out[10..12].copy_from_slice(&self.flow_ring_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.event_data_len.to_le_bytes());
        out[14..16].copy_from_slice(&self.seqnum.to_le_bytes());
        out[16..24].fill(0);
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < WL_EVENT_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let status = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
        let flow_ring_id = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
        let event_data_len = u16::from_le_bytes(bytes[12..14].try_into().ok()?);
        let seqnum = u16::from_le_bytes(bytes[14..16].try_into().ok()?);
        Some(Self {
            hdr,
            status,
            flow_ring_id,
            event_data_len,
            seqnum,
        })
    }
}
