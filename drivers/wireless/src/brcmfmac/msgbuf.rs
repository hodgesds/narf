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

// ── TX-post descriptor (`MSGBUF_TYPE_TX_POST`) ──────────────────────
//
// Layout per `msgbuf.c::msgbuf_tx_msghdr` and Linux
// `brcmfmac/core.c::brcmf_netdev_start_xmit` (~L293).
//
// The host builds a TxPost entry for every Ethernet frame it wants to
// transmit; the firmware drains these from the flow-ring, DMAs the
// frame payload out of the host-side buffer (described by `data_buf`),
// and delivers a TxStatus back through D2H_MSGRING_TX_COMPLETE.
//
//   common_hdr (8B)             @ 0
//   metadata_buf_addr BufAddr   @ 8..16   (set to 0 — metadata unused)
//   data_buf_addr     BufAddr   @ 16..24  (DMA address of frame data)
//   metadata_len      u16 LE    @ 24
//   data_len          u16 LE    @ 26
//   rsvd[4]           u32 LE×4  @ 28..44  (compat padding to 48 bytes)
//
// Total 48 bytes — matches `H2D_TXFLOWRING_ITEMSIZE`.
//
// Reference: Linux `brcmfmac/msgbuf.c::brcmf_msgbuf_txflow`
// (~L640..L700, v6.6).

/// Wire size of an encoded TxPost descriptor.
pub const TX_POST_SIZE: usize = 48;

/// Per-frame TX descriptor posted to a flow-ring.
///
/// The actual frame bytes live in the DMA buffer at `data_buf_addr`;
/// only the address + length are carried here. `metadata_buf_addr`
/// is left as zero (metadata feature not used in the baseline path).
///
/// Reference: Linux `brcmfmac/msgbuf.c::msgbuf_tx_msghdr` (~L97).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxPost {
    pub hdr: CommonHdr,
    pub metadata_buf_addr: BufAddr,
    pub data_buf_addr: BufAddr,
    pub metadata_len: u16,
    pub data_len: u16,
}

impl TxPost {
    /// Encode to a 48-byte buffer. Returns `None` if the buffer is too
    /// small.
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < TX_POST_SIZE {
            return None;
        }
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::TxPost as u8;
        hdr.encode(out)?;
        self.metadata_buf_addr.encode(&mut out[8..16])?;
        self.data_buf_addr.encode(&mut out[16..24])?;
        out[24..26].copy_from_slice(&self.metadata_len.to_le_bytes());
        out[26..28].copy_from_slice(&self.data_len.to_le_bytes());
        out[28..TX_POST_SIZE].fill(0);
        Some(())
    }

    /// Decode from a 48-byte buffer.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TX_POST_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let metadata_buf_addr = BufAddr::decode(&bytes[8..16])?;
        let data_buf_addr = BufAddr::decode(&bytes[16..24])?;
        let metadata_len = u16::from_le_bytes(bytes[24..26].try_into().ok()?);
        let data_len = u16::from_le_bytes(bytes[26..28].try_into().ok()?);
        Some(Self {
            hdr,
            metadata_buf_addr,
            data_buf_addr,
            metadata_len,
            data_len,
        })
    }
}

// ── TX-status (D2H TX complete) ─────────────────────────────────────
//
// Layout per `msgbuf.c::msgbuf_tx_status` (~L115, v6.6).
//
//   common_hdr (8B)   @ 0
//   compl_hdr  (4B)   @ 8..12  (status u16 + flow_ring_id u16)
//   msg_type   u8     @ 12
//   tx_status  u8     @ 13
//   rsvd       u16    @ 14..16
//
// Total 16 bytes (pre-v7 item size for D2H TX complete).
// v7+ pads to 24 bytes; we model the 24-byte form here.
//   rsvd[2]    u32×2  @ 16..24
//
// Reference: `msgbuf.c` (~L115), `msgbuf.h` `D2H_MSGRING_TX_COMPLETE_ITEMSIZE`.

/// Wire size of an encoded TxStatus (v7+ 24-byte form).
pub const TX_STATUS_SIZE: usize = 24;

/// Per-frame TX completion from firmware to host.
///
/// When the firmware finishes transmitting (or drops) a frame that was
/// posted via [`TxPost`], it delivers one of these through
/// `D2H_MSGRING_TX_COMPLETE`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxStatus {
    pub hdr: CommonHdr,
    pub status: u16,
    pub flow_ring_id: u16,
    /// Firmware-side TX status code. 0 = success.
    pub tx_status: u8,
}

impl TxStatus {
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < TX_STATUS_SIZE {
            return None;
        }
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::TxStatus as u8;
        hdr.encode(out)?;
        out[8..10].copy_from_slice(&self.status.to_le_bytes());
        out[10..12].copy_from_slice(&self.flow_ring_id.to_le_bytes());
        out[12] = MsgType::TxStatus as u8;
        out[13] = self.tx_status;
        out[14..TX_STATUS_SIZE].fill(0);
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TX_STATUS_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let status = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
        let flow_ring_id = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
        let tx_status = bytes[13];
        Some(Self {
            hdr,
            status,
            flow_ring_id,
            tx_status,
        })
    }
}

// ── RX-complete (D2H RX complete) ───────────────────────────────────
//
// Layout per `msgbuf.c::msgbuf_rx_complete` (~L126, v6.6).
//
//   common_hdr (8B)         @ 0
//   compl_hdr  (4B)         @ 8..12
//   rx_status_0 u16 LE      @ 12   (RSSI in high byte, status bits in low)
//   rx_status_1 u16 LE      @ 14
//   data_offset u8          @ 16   (bytes from start of DMA buf to 802.11)
//   data_len    u16 LE      @ 17
//   rsvd                    @ 19..40
//
// Total 40 bytes (v7+ form). Pre-v7 is 32 bytes; the extra 8 bytes are
// reserved padding.
//
// Reference: Linux `msgbuf.c` (~L126..L143) +
// `brcmf_rx_frame` in `core.c` (~L502..L560).

/// Wire size of an encoded RxComplete (v7+ 40-byte form).
pub const RX_COMPLETE_SIZE: usize = 40;

/// Per-frame RX completion from firmware to host.
///
/// Firmware posts one of these for every inbound frame. The actual
/// frame payload sits in the DMA buffer that was previously posted
/// via `RxBufPost` (ring id `H2D_MSGRING_RXPOST_SUBMIT`); `data_offset`
/// tells the host where the 802.11 payload starts in that buffer.
///
/// References: Linux `msgbuf.c::msgbuf_rx_complete` (~L126),
/// `core.c::brcmf_rx_frame` (~L502).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxComplete {
    pub hdr: CommonHdr,
    pub status: u16,
    pub flow_ring_id: u16,
    /// Combined status bits (low byte) and RSSI (high byte). Per
    /// `msgbuf.c::msgbuf_rx_complete.rx_status_0`.
    pub rx_status_0: u16,
    /// Additional rx-status bits (flags, sequence number fragment).
    pub rx_status_1: u16,
    /// Byte offset from the start of the DMA buffer to the first byte
    /// of the 802.11 frame payload. Mirrors `data_offset` in the
    /// `brcmf_rx_frame` strip path.
    pub data_offset: u8,
    /// Length in bytes of the 802.11 frame (payload only; excludes the
    /// DMA-buffer header bytes before `data_offset`).
    pub data_len: u16,
}

impl RxComplete {
    pub fn encode(self, out: &mut [u8]) -> Option<()> {
        if out.len() < RX_COMPLETE_SIZE {
            return None;
        }
        let mut hdr = self.hdr;
        hdr.msgtype = MsgType::RxCmplt as u8;
        hdr.encode(out)?;
        out[8..10].copy_from_slice(&self.status.to_le_bytes());
        out[10..12].copy_from_slice(&self.flow_ring_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.rx_status_0.to_le_bytes());
        out[14..16].copy_from_slice(&self.rx_status_1.to_le_bytes());
        out[16] = self.data_offset;
        out[17..19].copy_from_slice(&self.data_len.to_le_bytes());
        out[19..RX_COMPLETE_SIZE].fill(0);
        Some(())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RX_COMPLETE_SIZE {
            return None;
        }
        let hdr = CommonHdr::decode(&bytes[0..8])?;
        let status = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
        let flow_ring_id = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
        let rx_status_0 = u16::from_le_bytes(bytes[12..14].try_into().ok()?);
        let rx_status_1 = u16::from_le_bytes(bytes[14..16].try_into().ok()?);
        let data_offset = bytes[16];
        let data_len = u16::from_le_bytes(bytes[17..19].try_into().ok()?);
        Some(Self {
            hdr,
            status,
            flow_ring_id,
            rx_status_0,
            rx_status_1,
            data_offset,
            data_len,
        })
    }
}

// ── Chanspec encoding (cfg80211 / IOVAR `chanspec`) ──────────────────
//
// The brcmfmac firmware accepts a 16-bit `chanspec` word to describe
// a channel. The encoding is defined in Linux's
// `include/brcmu_wifi.h` (~L50..L164) and exercised by
// `cfg80211.c::brcmf_cfg80211_set_channel` via the `chanspec` IOVAR
// (~L2392..L2450, v6.6).
//
// Wire layout (16-bit LE):
//
//   bits 11-0  : channel number (1–14 for 2 GHz, 36–165 for 5 GHz)
//   bits 12    : CTL_SB_NONE (= 0 for 20 MHz)
//   bits 14-11 : bandwidth: 0x8 → BW_20
//   bits 15-12 : band:      0x1 → 5 GHz, 0x2 → 2 GHz
//
// Concretely:
//   `ch20mhz_chspec(channel)` (brcmu_wifi.h ~L158):
//       channel | WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE | band
//
// WL_CHANSPEC_BW_20   = 0x0800
// WL_CHANSPEC_CTL_SB_NONE = 0x0000 (no sub-band bits set for 20 MHz)
// WL_CHANSPEC_BAND_5G = 0x1000
// WL_CHANSPEC_BAND_2G = 0x2000

/// 20 MHz bandwidth selector (bits 11-10 = `0b10`).
/// `WL_CHANSPEC_BW_20`. Linux `include/brcmu_wifi.h:54`.
pub const WL_CHANSPEC_BW_20: u16 = 0x0800;
/// 5 GHz band selector (bits 15-12 = `0b0001`).
/// `WL_CHANSPEC_BAND_5G`. Linux `include/brcmu_wifi.h:60`.
pub const WL_CHANSPEC_BAND_5G: u16 = 0x1000;
/// 2.4 GHz band selector (bits 15-12 = `0b0010`).
/// `WL_CHANSPEC_BAND_2G`. Linux `include/brcmu_wifi.h:61`.
pub const WL_CHANSPEC_BAND_2G: u16 = 0x2000;
/// Maximum 2 GHz channel number. Channels 1-14 are 2 GHz.
/// `CH_MAX_2G_CHANNEL`. Linux `include/brcmu_wifi.h:43`.
pub const CH_MAX_2G_CHANNEL: u8 = 14;

/// Encode a 20 MHz chanspec for the given channel number.
///
/// Mirrors `ch20mhz_chspec()` from `include/brcmu_wifi.h` (~L158):
///
/// ```c
/// u16 rc = channel <= CH_MAX_2G_CHANNEL ?
///     WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G;
/// return (u16)(channel | WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE | rc);
/// ```
///
/// `WL_CHANSPEC_CTL_SB_NONE` = 0 (no control-subband bits), so it
/// does not appear in the expression.
pub const fn chanspec_20mhz(channel: u8) -> u16 {
    let band = if channel <= CH_MAX_2G_CHANNEL {
        WL_CHANSPEC_BAND_2G
    } else {
        WL_CHANSPEC_BAND_5G
    };
    (channel as u16) | WL_CHANSPEC_BW_20 | band
}

/// Return the channel number from an encoded chanspec.
/// `CHSPEC_CHANNEL(chspec)`. Linux `brcmu_wifi.h:99`.
pub const fn chanspec_channel(chspec: u16) -> u8 {
    // Channel number lives in the low 8 bits of the chanspec
    // (the CHAN_MASK per Linux is 0xFF).
    (chspec & 0x00FF) as u8
}

/// Return true if the chanspec is a 5 GHz channel.
/// Mirrors `CHSPEC_IS5G(chspec)`. Linux `brcmu_wifi.h:116`.
pub const fn chanspec_is5g(chspec: u16) -> bool {
    (chspec & 0xF000) == WL_CHANSPEC_BAND_5G
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
