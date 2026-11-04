//! Intel ixgbe — 82599 / X540 / X550 10 GbE controller driver.
//!
//! Spec: `drivers/net/specification/ixgbe.md`. Clean-room: register
//! layout sourced from the public Intel 82599 / X540 / X550
//! datasheets. No GPL Linux source consulted.

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer, TrySendError};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

use crate::ixgbe::queues::RegBank;

pub mod dcb;
pub mod eee;
pub mod ethtool;
pub mod fdir;
pub mod pm;
pub mod queues;
pub mod regs;
pub mod rss;
mod tests;
pub mod vlan;
pub mod vmdq;
pub mod wol;

// ── PCI device IDs ─────────────────────────────────────────────────

/// Intel.
pub const IXGBE_VENDOR: u16 = 0x8086;

/// 82599EB (SFI/SFP+).
pub const IXGBE_DEV_82599EB: u16 = 0x10FB;
/// X540-AT2.
pub const IXGBE_DEV_X540: u16 = 0x1528;
/// X550 (10G base-T copper).
pub const IXGBE_DEV_X550: u16 = 0x1563;
/// X550EM_x (10G SFP+).
pub const IXGBE_DEV_X550EM_X: u16 = 0x15AB;

const ALL_DEV_IDS: &[u16] = &[
    IXGBE_DEV_82599EB,
    IXGBE_DEV_X540,
    IXGBE_DEV_X550,
    IXGBE_DEV_X550EM_X,
];

// ── Register offsets (BAR0) ────────────────────────────────────────
// 82599 §8.2.

pub(crate) const REG_CTRL: u64 = 0x00000;
pub(crate) const REG_STATUS: u64 = 0x00008;
pub(crate) const REG_CTRL_EXT: u64 = 0x00018;
pub(crate) const REG_EERD: u64 = 0x10010;

pub(crate) const REG_EICR: u64 = 0x00800;
pub(crate) const REG_EIMS: u64 = 0x00880;
pub(crate) const REG_EIMC: u64 = 0x00888;
pub(crate) const REG_GPIE: u64 = 0x00898;
pub(crate) const REG_EIAM: u64 = 0x00890;

// Extended interrupt-mask/auto-mask registers for vectors 32..63
// (datasheet §8.2; cross-checked against Linux ixgbe_type.h @
// cbbddb6: IXGBE_EIMS_EX / IXGBE_EIAM_EX).
pub(crate) const REG_EIMS_EX0: u64 = 0x00AA0;
pub(crate) const REG_EIMS_EX1: u64 = 0x00AA4;
pub(crate) const REG_EIAM_EX0: u64 = 0x00AD0;

// EIMS OTHER-cause bit (Linux IXGBE_EIMS_OTHER = IXGBE_EICR_OTHER).
pub(crate) const EIMS_OTHER_CAUSE: u32 = 1 << 31;

pub(crate) const REG_FCTRL: u64 = 0x05080;
pub(crate) const REG_RAL0: u64 = 0x0A200; // 82599 receive-address regs §8.2.3.7.9
pub(crate) const REG_RAH0: u64 = 0x0A204;
pub(crate) const REG_RXCTRL: u64 = 0x03000;
pub(crate) const REG_LINKS: u64 = 0x04200;

// All queue registers come from queues::rx_queue_regs/tx_queue_regs
// (datasheet §8.2, stride 0x40 per queue); the tx/rx paths index
// them per queue, so no queue-0 tail-pointer constants remain.

// CTRL bits (§8.2.3.1.1).
pub(crate) const CTRL_RST_MASK: u32 = (1 << 26) | (1 << 3); // RST | LRST

// CTRL_EXT bits.
pub(crate) const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
pub(crate) const CTRL_EXT_NS_DIS: u32 = 1 << 16;

// FCTRL bits.
pub(crate) const FCTRL_BAM: u32 = 1 << 10;
pub(crate) const FCTRL_UPE: u32 = 1 << 9;
pub(crate) const FCTRL_MPE: u32 = 1 << 8;

// RXCTRL bits.
pub(crate) const RXCTRL_RXEN: u32 = 1 << 0;

// LINKS bits.
pub(crate) const LINKS_UP: u32 = 1 << 30;

// RAH bits — Address-Valid; programmed when we plumb the MAC into RAH/RAL.
#[allow(dead_code)]
pub(crate) const RAH_AV: u32 = 1 << 31;

// EERD bits (§10.2.4.2).
pub(crate) const EERD_START: u32 = 1 << 0;
pub(crate) const EERD_DONE: u32 = 1 << 1;
pub(crate) const EERD_ADDR_SHIFT: u32 = 2;

// RXDCTL / TXDCTL.
pub(crate) const RXDCTL_ENABLE: u32 = 1 << 25;
pub(crate) const TXDCTL_ENABLE: u32 = 1 << 25;

// SRRCTL — bsize selector (1 KiB units), legacy descriptor type.
pub(crate) const SRRCTL_BSIZE_2K: u32 = 2; // bits[4:0]
pub(crate) const SRRCTL_DESCTYPE_LEGACY: u32 = 0 << 25;

// Advanced TX descriptor cmd_type_len bits (§7.2.3.2.4).
pub(crate) const ADVTXD_DTYP_DATA: u32 = 0x3 << 20;
pub(crate) const ADVTXD_DCMD_DEXT: u32 = 1 << 29;
pub(crate) const ADVTXD_DCMD_RS: u32 = 1 << 27;
pub(crate) const ADVTXD_DCMD_IFCS: u32 = 1 << 25;
pub(crate) const ADVTXD_DCMD_EOP: u32 = 1 << 24;
pub(crate) const ADVTXD_STAT_DD: u32 = 1 << 0;

// TX context / TSO descriptor bits.
// Source: Linux ixgbe_type.h §7.2.3.2.2 / ixgbe_main.c.
pub const ADVTXD_DTYP_CTXT: u32 = 0x2 << 20;
pub const ADVTXD_DCMD_TSE: u32 = 1 << 31;
/// VLAN Packet Enable: when set on a data descriptor, hardware
/// inserts the 802.1Q tag from the preceding context descriptor's
/// VLAN field (datasheet §7.2.3.2.4: VLE is DCMD bit 6, i.e. word
/// bit 30; Linux ixgbe_type.h: IXGBE_ADVTXD_DCMD_VLE 0x40000000).
pub const ADVTXD_DCMD_VLE: u32 = 1 << 30;
/// VLAN tag shift in the context descriptor's vlan_macip_lens word
/// (Linux ixgbe_type.h: IXGBE_ADVTXD_VLAN_SHIFT 16).
pub const ADVTXD_VLAN_SHIFT: u32 = 16;

/// Non-TSO frame cap (existing behavior: MTU-sized frames only;
/// jumbo is a separate issue).
pub const TX_LEN_MAX: usize = 1518;
/// TSO frame cap for `tx()`: the per-slot copy buffer is 4096
/// bytes (see bring_up), so a copied TSO superframe cannot run
/// longer. Advertised as `max_tso_bytes` (see probe).
pub const TX_TSO_MAX_TX: usize = 4096;
/// TSO frame cap for `tx_frame()`: zero-copy, so the bound is the
/// per-descriptor data length (Linux ixgbe.h:
/// IXGBE_MAX_DATA_PER_TXD = 1 << 14). Larger TSO needs
/// multi-descriptor scatter, which this driver does not do yet.
pub const TX_TSO_MAX_TX_FRAME: usize = 16384;
pub const ADVTXD_POPTS_IXSM: u32 = 0x0100;
pub const ADVTXD_POPTS_TXSM: u32 = 0x0200;
pub(crate) const ADVTXD_PAYLEN_SHIFT: u32 = 14;
pub const ADVTXD_TUCMD_IPV4: u32 = 0x400;
pub const ADVTXD_TUCMD_L4T_TCP: u32 = 0x800;
#[allow(dead_code)]
pub(crate) const ADVTXD_TUCMD_L4T_UDP: u32 = 0x000;
pub(crate) const ADVTXD_L4LEN_SHIFT: u32 = 8;
pub const ADVTXD_MSS_SHIFT: u32 = 16;
pub(crate) const ADVTXD_MACLEN_SHIFT: u32 = 9;

/// RX checksum verification result decoded from a legacy ixgbe RxDesc.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not compute a checksum for this frame.
    None,
    /// Hardware computed and verified the checksum — no errors.
    Ok,
    /// Hardware detected a checksum error.
    Fail,
}

/// Advanced TX context descriptor — precedes the data descriptor for
/// TSO and carries MSS / L4-len / TUCMD fields. Per ixgbe §7.2.3.2.2.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxCtxtDesc {
    pub vlan_macip_lens: u32,
    pub seqnum_seed: u32,
    pub type_tucmd_mlhl: u32,
    pub mss_l4len_idx: u32,
}

// Legacy RX descriptor status bits.
pub(crate) const RXD_STAT_DD: u8 = 1 << 0;
#[allow(dead_code)]
pub(crate) const RXD_STAT_EOP: u8 = 1 << 1;

// Ring lengths come from `QueueConfig::ring_len` (32 for the
// single-queue config, matching the old Stage-3/4 constants).
// RX_BUF_LEN is a buffer size, not a ring length, and stays fixed.
pub(crate) const RX_BUF_LEN: usize = 2048;

// ── Descriptor types ───────────────────────────────────────────────

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxDesc {
    pub addr: u64,
    pub cmd_type_len: u32,
    pub olinfo: u32,
}
const _: () = assert!(core::mem::size_of::<AdvTxDesc>() == 16);

impl AdvTxDesc {
    /// Pack the cmd_type_len field for a single-buffer EOP send with
    /// RS reporting and FCS insertion. `len` must fit in 16 bits
    /// (datasheet §7.2.3.2.4: DTALEN is 16 bits).
    pub fn ctrl_word(len: u16) -> u32 {
        (len as u32)
            | ADVTXD_DTYP_DATA
            | ADVTXD_DCMD_DEXT
            | ADVTXD_DCMD_RS
            | ADVTXD_DCMD_IFCS
            | ADVTXD_DCMD_EOP
    }
}

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub csum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}
const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

// ── Descriptor offload helpers ───────────────────────────────────────

impl AdvTxDesc {
    /// Build a TX descriptor with IP + TCP/UDP checksum offload.
    /// POPTS bits are set in `olinfo`; PAYLEN is also loaded there.
    pub fn with_csum(addr: u64, len: u16) -> Self {
        AdvTxDesc {
            addr,
            cmd_type_len: Self::ctrl_word(len),
            olinfo: ((len as u32) << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM,
        }
    }

    /// Build a TX data descriptor for TSO. The DCMD_TSE bit is added to
    /// `cmd_type_len`; the context descriptor carries the MSS and L4len.
    /// `len` is the full superframe length (DTALEN); `paylen` is the
    /// TCP payload length (datasheet §7.2.3.2.4: in TSO, PAYLEN is
    /// the payload size, not the frame size — the headers are
    /// accounted by MACLEN/IPLEN/L4LEN in the context descriptor).
    pub fn with_tso(addr: u64, len: u16, paylen: u32) -> Self {
        AdvTxDesc {
            addr,
            cmd_type_len: Self::ctrl_word(len) | ADVTXD_DCMD_TSE,
            olinfo: (paylen << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM,
        }
    }
}

impl AdvTxCtxtDesc {
    /// Build a TSO context descriptor for an IPv4/TCP frame.
    /// `mac_len` = Ethernet header length (usually 14).
    /// `ip_len`  = IP header length in bytes (usually 20).
    /// `l4_len`  = TCP header length in bytes (usually 20).
    /// `mss`     = maximum segment size in bytes.
    /// `vlan_tag` = 802.1Q tag to insert when the data descriptor
    /// carries VLE, else `None` (tag rides in vlan_macip_lens bits
    /// 31:16 per Linux ixgbe's ctxtdesc construction).
    pub fn new_tso_v4(
        mac_len: u8,
        ip_len: u8,
        l4_len: u8,
        mss: u16,
        vlan_tag: Option<u16>,
    ) -> Self {
        let mut vlan_macip_lens = (ip_len as u32) | ((mac_len as u32) << ADVTXD_MACLEN_SHIFT);
        if let Some(tag) = vlan_tag {
            vlan_macip_lens |= (tag as u32) << ADVTXD_VLAN_SHIFT;
        }
        let type_tucmd_mlhl =
            ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT | ADVTXD_TUCMD_IPV4 | ADVTXD_TUCMD_L4T_TCP;
        let mss_l4len_idx =
            ((l4_len as u32) << ADVTXD_L4LEN_SHIFT) | ((mss as u32) << ADVTXD_MSS_SHIFT);
        AdvTxCtxtDesc {
            vlan_macip_lens,
            seqnum_seed: 0,
            type_tucmd_mlhl,
            mss_l4len_idx,
        }
    }

    /// Build a VLAN-insertion-only context descriptor (no
    /// segmentation, no checksum context): the tag rides in
    /// vlan_macip_lens bits 31:16, MACLEN is the driver-supplied
    /// Ethernet header (14 — the inserted tag is hardware-added,
    /// so it is NOT counted in MACLEN per datasheet §7.2.3.2.2's
    /// table: no SNAP + hardware VLAN gives MACLEN 14), and IPLEN
    /// is 0 (nothing in this context consumes header positions).
    /// The data descriptor must carry VLE for the tag to be used.
    pub fn new_vlan(vlan_tag: u16) -> Self {
        AdvTxCtxtDesc {
            vlan_macip_lens: ((vlan_tag as u32) << ADVTXD_VLAN_SHIFT)
                | ((14u32) << ADVTXD_MACLEN_SHIFT),
            seqnum_seed: 0,
            type_tucmd_mlhl: ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT,
            mss_l4len_idx: 0,
        }
    }
}

/// Parsed header lengths for a TSO frame (IPv4/TCP only).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct TsoHeaders {
    pub mac_len: u8,
    pub ip_len: u8,
    pub l4_len: u8,
}

/// Parse the Ethernet/IPv4/TCP header lengths of a TSO frame.
/// Returns the lengths the context descriptor needs
/// (MACLEN/IPLEN/L4LEN). Rejects anything that is not an
/// IPv4/TCP frame with sane header lengths — TSO for other
/// protocols, and TSO on an already-tagged frame, are follow-ups,
/// and sending a mis-parsed frame would segment garbage on
/// silicon. The caller supplies an untagged frame: with VLE
/// insertion the tag is hardware-added, so MACLEN stays 14.
/// `head` is the frame's leading bytes (at least the headers;
/// headers span at most 14 + 60 + 60 = 134 bytes) and `total_len`
/// is the full frame length, used for the truncation checks.
pub(crate) fn parse_tso_headers(head: &[u8], total_len: usize) -> Result<TsoHeaders, IxgbeError> {
    // Ethernet header (14) + min IPv4 (20) + min TCP (20).
    if total_len < 54 {
        return Err(IxgbeError::Other("tso frame too short"));
    }
    if head[12] == 0x81 && head[13] == 0x00 {
        return Err(IxgbeError::Other(
            "tso on VLAN-tagged frame: strip the tag or request vlan_tag insertion",
        ));
    }
    if head[12] != 0x08 || head[13] != 0x00 {
        return Err(IxgbeError::Other("tso requires IPv4"));
    }
    let ip = &head[14..];
    let ihl = (ip[0] & 0x0F) as usize;
    if ihl < 5 {
        return Err(IxgbeError::Other("tso bad IPv4 IHL"));
    }
    let ip_len = ihl * 4;
    if ip[9] != 6 {
        return Err(IxgbeError::Other("tso requires TCP"));
    }
    if total_len < 14 + ip_len + 20 {
        return Err(IxgbeError::Other("tso frame truncated"));
    }
    let tcp = &head[14 + ip_len..];
    let doff = (tcp[12] >> 4) as usize;
    if doff < 5 {
        return Err(IxgbeError::Other("tso bad TCP data offset"));
    }
    let l4_len = doff * 4;
    if total_len < 14 + ip_len + l4_len {
        return Err(IxgbeError::Other("tso frame truncated"));
    }
    Ok(TsoHeaders {
        mac_len: 14,
        ip_len: ip_len as u8,
        l4_len: l4_len as u8,
    })
}

/// Plan the descriptor pair for one transmit: optional context
/// descriptor (TSO and/or VLAN insertion) + data descriptor.
/// Callers enforce their own length bound first (`tx`: copy-buffer
/// bound, `tx_frame`: per-descriptor bound); `frame_len` fits u16
/// by construction of those bounds. `head` is the frame's leading
/// bytes (see `parse_tso_headers`); `tx()` passes the whole frame,
/// `tx_frame()` a stack copy of the header region.
///
/// VLAN + checksum offload without TSO is rejected: the csum path
/// programs no context descriptor, so a VLAN context with IPLEN 0
/// would misplace the hardware checksum computation (datasheet
/// Table 7.35: XSUM consumes MACLEN/IPLEN). VLAN + TSO is fine —
/// TSO parsing fills the context. The csum path gaining header
/// parsing is a follow-up (spec §13j).
fn tx_plan(
    phys: u64,
    frame_len: usize,
    head: &[u8],
    meta: &TxMeta,
) -> Result<(Option<AdvTxCtxtDesc>, AdvTxDesc), IxgbeError> {
    let tso = match meta.tso_mss {
        Some(0) => return Err(IxgbeError::Other("tso mss is zero")),
        Some(mss) => Some((mss, parse_tso_headers(head, frame_len)?)),
        None => None,
    };
    if meta.vlan_tag.is_some() && meta.csum_l4.is_some() && meta.tso_mss.is_none() {
        return Err(IxgbeError::Other(
            "vlan insertion with checksum offload requires TSO",
        ));
    }
    let ctxt = match (tso, meta.vlan_tag) {
        (Some((mss, h)), tag) => Some(AdvTxCtxtDesc::new_tso_v4(
            h.mac_len, h.ip_len, h.l4_len, mss, tag,
        )),
        (None, Some(tag)) => Some(AdvTxCtxtDesc::new_vlan(tag)),
        (None, None) => None,
    };
    let len = frame_len as u16;
    let mut desc = if let Some((_, h)) = tso {
        // PAYLEN is the TCP payload, not the frame (datasheet
        // §7.2.3.2.4: in TSO, PAYLEN defines the payload size).
        let hdr = h.mac_len as usize + h.ip_len as usize + h.l4_len as usize;
        AdvTxDesc::with_tso(phys, len, (frame_len - hdr) as u32)
    } else if meta.csum_l4.is_some() {
        AdvTxDesc::with_csum(phys, len)
    } else {
        AdvTxDesc {
            addr: phys,
            cmd_type_len: AdvTxDesc::ctrl_word(len),
            // PAYLEN field at bits [31:14] of olinfo (§7.2.3.2.4);
            // single-send PAYLEN is the full frame size.
            olinfo: (frame_len as u32) << 14,
        }
    };
    if meta.vlan_tag.is_some() {
        desc.cmd_type_len |= ADVTXD_DCMD_VLE;
    }
    Ok((ctxt, desc))
}

impl RxDesc {
    /// Decode the RX checksum result from the legacy ixgbe RxDesc.
    /// The `csum` field is non-zero when hardware computed a checksum;
    /// `errors` being 0 means the check passed.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn csum_result(&self) -> RxCsumResult {
        if self.csum == 0 {
            RxCsumResult::None
        } else if self.errors == 0 {
            RxCsumResult::Ok
        } else {
            RxCsumResult::Fail
        }
    }
}

// ── EEPROM decode helper (Stage 2) ─────────────────────────────────

/// Decode the EEPROM "data" word out of an EERD register value.
/// The 82599 datasheet (§10.2.4.2.1) places the read-result in
/// bits [31:16].
pub fn eeprom_decode(eerd: u32) -> u16 {
    (eerd >> 16) as u16
}

/// Pack a 16-bit EEPROM address into a START-bit-set EERD write.
pub fn eerd_start(addr: u16) -> u32 {
    ((addr as u32) << EERD_ADDR_SHIFT) | EERD_START
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IxgbeError {
    BarMapFailed,
    NoMemory,
    UnsupportedDevice,
    /// CTRL.RST never cleared.
    ResetTimeout,
    /// EERD.DONE never set.
    EepromTimeout,
    /// Caller passed a frame larger than 1518 bytes.
    FrameTooLong,
    /// TX descriptor never completed.
    TxTimeout,
    /// MSI-X capability not present / could not be enabled.
    MsixUnavailable,
    /// Catch-all.
    Other(&'static str),
}

// ── Driver state ───────────────────────────────────────────────────

/// One TX queue's DMA ring state. Index = queue number.
pub(crate) struct TxQueueState {
    pub(crate) tx_ring: DmaBuffer,
    /// Persistent per-slot TX frame buffers (audit #4 — pre-fix
    /// `tx()` did `alloc_coherent(4096)` per frame and dropped it
    /// on return). Indexed by descriptor slot.
    pub(crate) tx_pool: Vec<DmaBuffer>,
    pub(crate) tx_tail: IrqSafeSpinLock<u32>,
}

impl core::fmt::Debug for TxQueueState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxQueueState")
            .field("tx_pool_len", &self.tx_pool.len())
            .finish_non_exhaustive()
    }
}

/// One RX queue's DMA ring state. Index = queue number.
pub(crate) struct RxQueueState {
    pub(crate) rx_ring: DmaBuffer,
    /// The DMA buffer currently armed in each RX descriptor slot. Zero-copy RX
    /// (`rx_recv_frame`) hands a filled buffer to the stack as a `Frame` and
    /// swaps a fresh buffer into its slot, so the set rotates rather than
    /// staying fixed — hence the lock (the RX pump mutates it).
    pub(crate) rx_slots: IrqSafeSpinLock<Vec<DmaBuffer>>,
    pub(crate) rx_head: IrqSafeSpinLock<u32>,
}

impl core::fmt::Debug for RxQueueState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxQueueState")
            .field("rx_slots_len", &self.rx_slots.lock().len())
            .finish_non_exhaustive()
    }
}

pub struct Ixgbe {
    pub(crate) mmio: MmioRegion,
    /// Per-queue TX ring state, indexed by queue number; length
    /// `queue_config.num_tx`. `tx_queues[0]` is the queue-0 state
    /// the pre-multi-queue driver held as flat fields.
    pub(crate) tx_queues: Vec<TxQueueState>,
    /// Per-queue RX ring state, indexed by queue number; length
    /// `queue_config.num_rx`.
    pub(crate) rx_queues: Vec<RxQueueState>,
    /// Stack-facing RX mirror producer, shared by all RX pumps.
    /// `Producer` is single-owner + `!Sync`, so multi-queue fan-in
    /// goes through this lock; `try_send` is non-blocking, so a
    /// full/closed ring drops the mirror copy, never the stack's
    /// packet — the same semantics as the single-pump path.
    pub(crate) rx_mirror: IrqSafeSpinLock<Producer<Frame, RX_RING_N>>,
    /// MAC read from the EEPROM at bring-up.
    pub mac: [u8; 6],
    /// True after the MAC was successfully programmed into RAH/RAL
    /// and LINKS reports up. Locked: resume() refreshes it via &self.
    pub link_up: IrqSafeSpinLock<bool>,
    /// Recorded device id (drives `name()`).
    pub did: u16,
    /// Live queue configuration: the counts `tx_queues` /
    /// `rx_queues` were built for, and the ring length their rings
    /// use. `bring_up` builds 1/1; `bring_up_with_config` builds
    /// any validated config (up to 64/64).
    pub queue_config: queues::QueueConfig,
    /// Programmed RSS state, if `configure_rss` ran.
    pub rss_cfg: IrqSafeSpinLock<Option<rss::IxgbeRss>>,
    /// Programmed DCB state, if `configure_dcb` ran.
    pub dcb_cfg: IrqSafeSpinLock<Option<dcb::DcbConfig>>,
    /// Programmed VLAN filter, if `configure_vlan` ran.
    pub vlan_filter: IrqSafeSpinLock<Option<vlan::VlanFilter>>,
    /// Programmed Flow Director config, if `configure_fdir` ran.
    pub fdir_cfg: IrqSafeSpinLock<Option<fdir::FdirConfig>>,
    /// Programmed VMDq config, if `configure_vmdq` ran.
    pub vmdq_cfg: IrqSafeSpinLock<Option<vmdq::VmdqConfig>>,
    /// Armed WoL config, if `configure_wol` ran and was not disarmed.
    pub wol_armed: IrqSafeSpinLock<Option<wol::WolConfig>>,
    /// Programmed EEE state, if `configure_eee` ran. Always `None`
    /// on in-tree device ids: Linux marks none of them
    /// EEE-capable, so `configure_eee` returns
    /// `UnsupportedDevice` before storing anything (see
    /// `eee.rs`).
    pub eee_state: IrqSafeSpinLock<Option<eee::EeeState>>,
    /// Board WoL capability record for X540-and-newer parts
    /// (Linux EEPROM-cap rule, see wol.rs `WolBoardCap`).
    /// Default opts nothing in; the board/platform layer sets it
    /// via `set_wol_board_cap`.
    pub wol_board_cap: IrqSafeSpinLock<wol::WolBoardCap>,
    /// True while the datapath is quiesced (suspend/detach): tx/rx
    /// paths refuse work instead of feeding a stopped device.
    pub quiesced: IrqSafeSpinLock<bool>,
    /// Stage 5: MSI-X table once enabled.
    pub(crate) msix: Option<MsixTable>,
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl core::fmt::Debug for Ixgbe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ixgbe")
            .field("mac", &self.mac)
            .field("link_up", &*self.link_up.lock())
            .field("did", &format_args!("0x{:04X}", self.did))
            .field("num_tx_queues", &self.queue_config.num_tx)
            .field("num_rx_queues", &self.queue_config.num_rx)
            .finish_non_exhaustive()
    }
}

/// Program one TX queue's descriptor ring (base, length, head/tail,
/// queue-enable) on any [`RegBank`]. Shared by bring-up (via
/// [`queues::MmioBank`]) and the fake-bank fixtures, so the
/// register conversation the fixtures pin is the one the hardware
/// sees. Panics for an out-of-range queue; callers pass validated
/// queue counts, so this is unreachable in bring-up.
fn program_tx_queue(bank: &mut impl RegBank, q: usize, phys: u64, ring_len: usize) {
    let txq = queues::tx_queue_regs(q).expect("validated queue count is in range");
    bank.write32(txq.tdbal, phys as u32);
    bank.write32(txq.tdbah, (phys >> 32) as u32);
    bank.write32(txq.tdlen, (ring_len * 16) as u32);
    bank.write32(txq.tdh, 0);
    bank.write32(txq.tdt, 0);
    bank.set_bits(txq.txdctl, TXDCTL_ENABLE);
}

/// Program one RX queue's descriptor ring (base, length, head/tail,
/// SRRCTL 2K legacy buffers, queue-enable) on any [`RegBank`].
/// Same sharing note as [`program_tx_queue`].
fn program_rx_queue(bank: &mut impl RegBank, q: usize, phys: u64, ring_len: usize) {
    let rxq = queues::rx_queue_regs(q).expect("validated queue count is in range");
    bank.write32(rxq.rdbal, phys as u32);
    bank.write32(rxq.rdbah, (phys >> 32) as u32);
    bank.write32(rxq.rdlen, (ring_len * 16) as u32);
    bank.write32(rxq.rdh, 0);
    bank.write32(rxq.rdt, ring_len.saturating_sub(1) as u32);
    bank.write32(rxq.srrctl, SRRCTL_BSIZE_2K | SRRCTL_DESCTYPE_LEGACY);
    bank.set_bits(rxq.rxdctl, RXDCTL_ENABLE);
}

/// Route every configured queue to its own MSI-X vector (vector =
/// queue index; RX and TX of one queue share it) plus the OTHER
/// cause to vector 0. Shared by `enable_msix_queue_vectors` (via
/// [`queues::MmioBank`]) and the fake-bank routing-table fixtures.
/// Callers pass a validated `QueueConfig` (see
/// `QueueConfig::validate`); counts above 64 would truncate the
/// vector cast. Asymmetric configs route only the directions that
/// exist: a queue with no TX ring leaves its TX IVAR field
/// unprogrammed, and vice versa.
fn route_all_queue_vectors(bank: &mut impl RegBank, config: &queues::QueueConfig) {
    let n = config.num_tx.max(config.num_rx);
    for q in 0..n {
        if q < config.num_tx && q < config.num_rx {
            queues::route_queue_vector(bank, q, q as u8);
        } else if q < config.num_tx {
            queues::route_queue_vector_dir(bank, q, q as u8, true);
        } else {
            queues::route_queue_vector_dir(bank, q, q as u8, false);
        }
    }
    queues::route_misc_vector(bank, 0);
}

/// MSI-X vector for queue `q` under `config` (vector = queue
/// index), or `None` when neither direction of `q` is configured.
/// Counts are validated to 1..=64, so a `Some` vector is always
/// 0..=63. The single source for `queue_affinity`'s `irq` field.
pub(crate) fn queue_vector_for(config: &queues::QueueConfig, q: usize) -> Option<u8> {
    if q < config.num_tx.max(config.num_rx) {
        Some(q as u8)
    } else {
        None
    }
}

impl Ixgbe {
    /// Bring the controller up with the single-queue config: PCI
    /// MMIO map, master reset, MAC read, queue-0 TX/RX rings
    /// programmed, link enabled. MSI-X gets wired up by
    /// `enable_msix_vector()` once the bus side has been validated.
    /// See [`Self::bring_up_with_config`] for multi-queue bring-up.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Arc<Self>, IxgbeError> {
        // SAFETY: same caller-authority as `bring_up_with_config`.
        unsafe { Self::bring_up_with_config(device, cap, queues::QueueConfig::single()) }
    }

    /// Bring the controller up with `queue_config`: same steps as
    /// [`Self::bring_up`], but TX/RX DMA rings are allocated and
    /// programmed for every configured queue (not just queue 0)
    /// and a per-queue pump set is spawned. An invalid config
    /// (zero queues, >64 queues, bad ring length) is rejected
    /// before any register is touched. MSI-X routing for the
    /// queues is still a separate step
    /// (`enable_msix_queue_vectors`), mirroring the single-vector
    /// path's split between bring-up and `enable_msix_vector`.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively for the duration of
    /// init.
    pub unsafe fn bring_up_with_config(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
        queue_config: queues::QueueConfig,
    ) -> Result<Arc<Self>, IxgbeError> {
        // SAFETY: caller-authority over the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IxgbeError::BarMapFailed)?;
        queue_config
            .validate()
            .map_err(|_| IxgbeError::Other("invalid queue config"))?;

        // 1. Mask all extended interrupts (§4.6.3.2 — driver should
        //    own EIMC before firmware moves on).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_EIMC, 0xFFFF_FFFF);
            // Read EICR to clear any latched causes.
            let _ = mmio.read32(REG_EICR);
        }

        // 2. Master reset — CTRL.LRST | CTRL.RST.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, CTRL_RST_MASK);
        }
        // responsive_spin_until ticks sleep_pumps so cursor / serial
        // / audio drain stay alive on a slow reset. ixgbe datasheet
        // §4.6.3.1: CTRL.RST self-clears within 1 ms typical; 100 ms
        // is the wedge threshold.
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST_MASK == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(IxgbeError::ResetTimeout);
        }
        // Datasheet §4.6.3.2 — wait ~10 ms for FW handshake.
        // TSC-based busy_wait gives real wall-clock time vs the
        // 200_000 spin_loop estimate that varied with CPU clock.
        let tsc_hz = narf_time::calibrate_clocks();
        if tsc_hz > 0 {
            narf_time::busy_wait_cycles((tsc_hz / 1000) * 10);
        } else {
            for _ in 0..1_000_000 {
                core::hint::spin_loop();
            }
        }

        // 3. Re-mask after reset.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_EIMC, 0xFFFF_FFFF);
            let _ = mmio.read32(REG_EICR);
        }

        // 4. Read MAC. Try EEPROM words 0..2 first (§10.2.4.2);
        //    fall back to RAL/RAH if firmware already loaded the
        //    Receive Address.
        let mac = read_mac(&mmio).unwrap_or_else(|_| read_mac_from_rar(&mmio));

        // 5. Tell firmware the OS driver has loaded.
        // SAFETY: same.
        unsafe {
            let cur = mmio.read32(REG_CTRL_EXT);
            mmio.write32(REG_CTRL_EXT, cur | CTRL_EXT_DRV_LOAD | CTRL_EXT_NS_DIS);
        }

        // 6. TX rings + persistent per-slot frame buffers (audit
        //    #4), one per TX queue. Queue 0's sequence is the
        //    pre-multi-queue one verbatim (same registers, same
        //    values, via `tx_queue_regs(0)`); queues 1.. repeat it
        //    at their own 0x40-strided blocks.
        let ring_len = queue_config.ring_len;
        let ring_bytes = ring_len * 16;
        let ring_alloc = ring_bytes.div_ceil(4096) * 4096;
        let mut tx_queues: Vec<TxQueueState> = Vec::with_capacity(queue_config.num_tx);
        for q in 0..queue_config.num_tx {
            let tx_ring =
                alloc_coherent(ring_alloc, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
            let tx_phys = tx_ring.dma_addr().raw();
            let mut tx_pool: Vec<DmaBuffer> = Vec::with_capacity(ring_len);
            for _ in 0..ring_len {
                tx_pool.push(
                    alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?,
                );
            }
            // SAFETY: identity-mapped DMA.
            unsafe {
                for i in 0..ring_bytes {
                    core::ptr::write_volatile(tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
                }
            }
            let txq = queues::tx_queue_regs(q).expect("validated queue count is in range");
            {
                let mut bank = queues::MmioBank::new(&mmio);
                program_tx_queue(&mut bank, q, tx_phys, ring_len);
            }
            // Poll for queue-enable to take effect (§7.2.3.4.1).
            // responsive_spin_until ticks sleep_pumps; failure is
            // non-fatal here (queue may come up later), matching prior
            // behaviour. 100 ms wall-clock budget.
            let _ = narf_scheduler::responsive_spin_until(
                // SAFETY: identity-mapped MMIO.
                || unsafe { mmio.read32(txq.txdctl) } & TXDCTL_ENABLE != 0,
                narf_time::Deadline::after_ms(100),
            );
            tx_queues.push(TxQueueState {
                tx_ring,
                tx_pool,
                tx_tail: IrqSafeSpinLock::new(0),
            });
        }

        // 7. RX rings + pools, one per RX queue (queue 0's sequence
        //    verbatim, as for TX).
        let mut rx_queues: Vec<RxQueueState> = Vec::with_capacity(queue_config.num_rx);
        for q in 0..queue_config.num_rx {
            let rx_ring =
                alloc_coherent(ring_alloc, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
            let rx_ring_phys = rx_ring.dma_addr().raw();
            let mut rx_pool = Vec::with_capacity(ring_len);
            for i in 0..ring_len {
                let buf =
                    alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
                let bp = buf.dma_addr().raw();
                let desc = RxDesc {
                    addr: bp,
                    length: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                };
                // SAFETY: identity-mapped DMA ring page.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                            .kernel_mut_ptr::<RxDesc>(),
                        desc,
                    );
                }
                rx_pool.push(buf);
            }
            {
                let mut bank = queues::MmioBank::new(&mmio);
                program_rx_queue(&mut bank, q, rx_ring_phys, ring_len);
            }
            rx_queues.push(RxQueueState {
                rx_ring,
                rx_slots: IrqSafeSpinLock::new(rx_pool),
                rx_head: IrqSafeSpinLock::new(0),
            });
        }
        // Promiscuous + broadcast accept; master RX enable (global,
        // once — not per queue).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_FCTRL, FCTRL_BAM | FCTRL_UPE | FCTRL_MPE);
            mmio.write32(REG_RXCTRL, RXCTRL_RXEN);
        }

        // 8. Read LINKS to seed link_up.
        // SAFETY: same.
        let links = unsafe { mmio.read32(REG_LINKS) };
        let link_up = links & LINKS_UP != 0;

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
        // Per-queue TX channels, only for multi-TX-queue configs:
        // the dispatcher round-robins stack frames across them and
        // each queue's TX pump drains its own. Single-TX-queue
        // setups keep the direct pump (see `spawn_pumps`), so no
        // per-queue channel exists there at all.
        let mut tx_prods: Vec<Producer<Frame, TX_RING_N>> = Vec::new();
        let mut tx_cons_q: Vec<Consumer<Frame, TX_RING_N>> = Vec::new();
        if queue_config.num_tx > 1 {
            for _ in 0..queue_config.num_tx {
                let (p, c) = channel::<Frame, TX_RING_N>();
                tx_prods.push(p);
                tx_cons_q.push(c);
            }
        }

        let ixgbe = Arc::new(Self {
            mmio,
            tx_queues,
            rx_queues,
            rx_mirror: IrqSafeSpinLock::new(rx_prod),
            mac,
            link_up: IrqSafeSpinLock::new(link_up),
            did: device.id.device,
            queue_config,
            rss_cfg: IrqSafeSpinLock::new(None),
            dcb_cfg: IrqSafeSpinLock::new(None),
            vlan_filter: IrqSafeSpinLock::new(None),
            fdir_cfg: IrqSafeSpinLock::new(None),
            vmdq_cfg: IrqSafeSpinLock::new(None),
            wol_armed: IrqSafeSpinLock::new(None),
            eee_state: IrqSafeSpinLock::new(None),
            wol_board_cap: IrqSafeSpinLock::new(wol::WolBoardCap::default()),
            quiesced: IrqSafeSpinLock::new(false),
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn the device's per-queue pump set — probe spawns none,
        // so the set fed here is the set whose halves occupy the
        // ring slots.
        spawn_pumps(ixgbe.clone(), tx_cons, tx_prods, tx_cons_q);

        Ok(ixgbe)
    }

    /// Read the EERD-decoded MAC bytes (Stage 2 surface).
    pub fn read_mac_eeprom(&self) -> Result<[u8; 6], IxgbeError> {
        read_mac(&self.mmio)
    }

    /// Transmit a single frame on queue 0, polling the descriptor's
    /// DD bit. Honors `TxMeta`: TSO (IPv4/TCP, up to `TX_TSO_MAX_TX` bytes
    /// — the per-slot copy-buffer size) and VLAN insertion (tag
    /// from the context descriptor + VLE on the data descriptor).
    /// Non-TSO frames keep the 1518 cap. See [`Self::tx_on_queue`].
    pub fn tx(&self, frame: &[u8], meta: &TxMeta) -> Result<(), IxgbeError> {
        self.tx_on_queue(0, frame, meta)
    }

    /// Transmit a single frame on TX queue `q`, polling the
    /// descriptor's DD bit. `q` must be a configured TX queue.
    pub fn tx_on_queue(&self, q: usize, frame: &[u8], meta: &TxMeta) -> Result<(), IxgbeError> {
        if *self.quiesced.lock() {
            return Err(IxgbeError::Other("device quiesced"));
        }
        let queue = self
            .tx_queues
            .get(q)
            .ok_or(IxgbeError::Other("bad TX queue"))?;
        if frame.is_empty() {
            return Err(IxgbeError::FrameTooLong);
        }
        // Bounds: non-TSO keeps the 1518 cap; TSO runs to the
        // per-slot copy-buffer size. Larger TSO needs scatter.
        let limit = if meta.tso_mss.is_some() {
            TX_TSO_MAX_TX
        } else {
            TX_LEN_MAX
        };
        if frame.len() > limit {
            return Err(IxgbeError::FrameTooLong);
        }
        let ring_len = self.queue_config.ring_len;
        // Persistent per-slot buffer (audit #4).
        let mut tail_g = queue.tx_tail.lock();
        let slot = (*tail_g) as usize % ring_len;
        let phys = queue.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above
        // (len <= 4096 = slot size for TSO, <= 1518 otherwise).
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(queue.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        // Pure descriptor planning (no I/O); safe under the tail lock.
        let (ctxt, desc) = tx_plan(phys, frame.len(), frame, meta)?;
        let ring_phys = queue.tx_ring.dma_addr().raw();
        // Context first (if any), then the data descriptor; the tail
        // advances past both. DD is polled on the data descriptor
        // only (context descriptors carry no DD write-back).
        let has_ctxt = ctxt.is_some();
        let data_slot = if has_ctxt {
            (slot + 1) % ring_len
        } else {
            slot
        };
        let data_addr = ring_phys + (data_slot * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            if let Some(ctxt) = ctxt {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ring_phys + (slot * 16) as u64)
                        .kernel_mut_ptr::<AdvTxCtxtDesc>(),
                    ctxt,
                );
            }
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(data_addr).kernel_mut_ptr::<AdvTxDesc>(),
                desc,
            );
        }
        let used = 1 + has_ctxt as u32;
        let next_tail = (*tail_g + used) % (ring_len as u32);
        compiler_fence(Ordering::SeqCst);
        let txq = queues::tx_queue_regs(q).expect("validated queue count is in range");
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(txq.tdt, next_tail);
        }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll DD: olinfo's low 4 bits of [3:0] (status) carry DD.
        // Advanced write-back lays status at olinfo[3:0]
        // (§7.2.3.2.4 write-back layout). 250 ms wall-clock budget
        // covers a worst-case Tx-side congestion stall.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(data_addr + 12).kernel_ptr::<u32>()) } & ADVTXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IxgbeError::TxTimeout);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Zero-copy transmit (P-F) on queue 0: post the TX descriptor
    /// pointing straight at the `Frame`'s own DMA buffer — no copy
    /// into a per-slot buffer, unlike [`Self::tx`]. The stack built
    /// the frame into that buffer, so DMA it in place. Honors the
    /// frame's `TxMeta` (TSO / checksum offload / VLAN
    /// insertion). TSO frames run to `TX_TSO_MAX_TX_FRAME` (the
    /// per-descriptor data length); non-TSO frames keep the 1518 cap.
    /// ixgbe TX is synchronous (polls DD), so the device is done the
    /// moment this returns and the caller may drop or recycle the
    /// buffer immediately. See [`Self::tx_frame_on_queue`].
    pub fn tx_frame(&self, frame: &Frame) -> Result<(), IxgbeError> {
        self.tx_frame_on_queue(0, frame)
    }

    /// Zero-copy transmit (P-F) on TX queue `q`. `q` must be a
    /// configured TX queue.
    pub fn tx_frame_on_queue(&self, q: usize, frame: &Frame) -> Result<(), IxgbeError> {
        if *self.quiesced.lock() {
            return Err(IxgbeError::Other("device quiesced"));
        }
        let queue = self
            .tx_queues
            .get(q)
            .ok_or(IxgbeError::Other("bad TX queue"))?;
        let len = frame.len() as usize;
        if len == 0 {
            return Err(IxgbeError::FrameTooLong);
        }
        let meta = frame.tx_meta();
        let limit = if meta.tso_mss.is_some() {
            TX_TSO_MAX_TX_FRAME
        } else {
            TX_LEN_MAX
        };
        if len > limit {
            return Err(IxgbeError::FrameTooLong);
        }
        let ring_len = self.queue_config.ring_len;
        let phys = frame.buf().dma_addr_at(frame.offset() as u64).raw();
        // Stack copy of the header region for TSO parsing: headers
        // span at most 14 + 60 + 60 = 134 bytes. The frame owns its
        // DMA buffer for this synchronous call, so volatile header
        // reads are safe.
        let mut head = [0u8; 134];
        let head_len = len.min(134);
        // SAFETY: identity-mapped DMA buffer owned by `frame`; reads
        // stay within [offset, offset + head_len).
        unsafe {
            let base = frame.buf().cpu_ptr_at::<u8>(frame.offset() as u64);
            for (i, slot) in head.iter_mut().enumerate().take(head_len) {
                *slot = core::ptr::read_volatile(base.add(i));
            }
        }
        let mut tail_g = queue.tx_tail.lock();
        let slot = (*tail_g) as usize % ring_len;
        let ring_phys = queue.tx_ring.dma_addr().raw();
        // Pure descriptor planning (no I/O); safe under the tail lock.
        let (ctxt, desc) = tx_plan(phys, len, &head[..head_len], &meta)?;
        // Context first (if any), then the data descriptor; the tail
        // advances past both. DD is polled on the data descriptor
        // only (context descriptors carry no DD write-back).
        let has_ctxt = ctxt.is_some();
        let data_slot = if has_ctxt {
            (slot + 1) % ring_len
        } else {
            slot
        };
        let data_addr = ring_phys + (data_slot * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            if let Some(ctxt) = ctxt {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ring_phys + (slot * 16) as u64)
                        .kernel_mut_ptr::<AdvTxCtxtDesc>(),
                    ctxt,
                );
            }
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(data_addr).kernel_mut_ptr::<AdvTxDesc>(),
                desc,
            );
        }
        let used = 1 + has_ctxt as u32;
        let next_tail = (*tail_g + used) % (ring_len as u32);
        compiler_fence(Ordering::SeqCst);
        let txq = queues::tx_queue_regs(q).expect("validated queue count is in range");
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(txq.tdt, next_tail);
        }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll DD; the device reads the frame's buffer directly in this window.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(data_addr + 12).kernel_ptr::<u32>()) } & ADVTXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IxgbeError::TxTimeout);
        }
        Ok(())
    }

    /// Drain one RX frame from queue 0 into `out`. Returns 0 if
    /// nothing pending. See [`Self::rx_recv_on_queue`].
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        self.rx_recv_on_queue(0, out)
    }

    /// Drain one RX frame from RX queue `q` into `out`. Returns 0
    /// if nothing pending, or if `q` is not a configured RX queue.
    pub fn rx_recv_on_queue(&self, q: usize, out: &mut [u8]) -> usize {
        if *self.quiesced.lock() {
            return 0;
        }
        let queue = match self.rx_queues.get(q) {
            Some(queue) => queue,
            None => return 0,
        };
        let ring_len = self.queue_config.ring_len;
        let mut head_g = queue.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = queue.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let desc = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<RxDesc>())
        };
        if desc.status & RXD_STAT_DD == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = desc.addr;
        for (i, b) in out[..len].iter_mut().enumerate() {
            // SAFETY: identity-mapped DMA buffer; `buf_phys` is the
            // descriptor-published frame address and `i < len <= RX_BUF_LEN`,
            // so the byte read stays within the device-owned buffer.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(buf_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        let new_desc = RxDesc {
            addr: buf_phys,
            length: 0,
            csum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                new_desc,
            );
        }
        compiler_fence(Ordering::SeqCst);
        let rxq = queues::rx_queue_regs(q).expect("validated queue count is in range");
        // SAFETY: MMIO.
        unsafe {
            self.mmio.write32(rxq.rdt, head as u32);
        }
        let new_head = ((head + 1) % ring_len) as u32;
        *head_g = new_head;
        let _ = RXD_STAT_EOP;
        len
    }

    /// Zero-copy receive (P-F) from queue 0: hand the descriptor's
    /// own DMA buffer to the stack as a `Frame` and swap a fresh
    /// buffer into its slot — no copy into a scratch buffer and then
    /// into a freshly-allocated frame, unlike the pump's old
    /// `rx_recv` + `Frame::new` + `copy_from_slice`. Returns `None`
    /// when no frame is pending, or when the refill allocation fails
    /// — in which case the received frame is left in its descriptor
    /// (head not advanced) to be retried, rather than dropped with
    /// no buffer to replace it. See
    /// [`Self::rx_recv_frame_on_queue`].
    pub fn rx_recv_frame(&self) -> Option<Frame> {
        self.rx_recv_frame_on_queue(0)
    }

    /// Zero-copy receive (P-F) from RX queue `q`. Returns `None`
    /// when no frame is pending, when the refill allocation fails,
    /// or when `q` is not a configured RX queue.
    pub fn rx_recv_frame_on_queue(&self, q: usize) -> Option<Frame> {
        if *self.quiesced.lock() {
            return None;
        }
        let queue = self.rx_queues.get(q)?;
        let ring_len = self.queue_config.ring_len;
        let mut head_g = queue.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = queue.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let desc = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<RxDesc>())
        };
        if desc.status & RXD_STAT_DD == 0 {
            return None;
        }
        let len = (desc.length as usize).min(RX_BUF_LEN);
        // Refill before handing the filled buffer up, so the device never sees
        // an empty slot. On allocation failure, bail without advancing — the
        // frame stays in the ring for the next poll.
        let replacement = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
        let repl_phys = replacement.dma_addr().raw();
        let filled = {
            let mut slots = queue.rx_slots.lock();
            core::mem::replace(&mut slots[head], replacement)
        };
        let new_desc = RxDesc {
            addr: repl_phys,
            length: 0,
            csum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                new_desc,
            );
        }
        compiler_fence(Ordering::SeqCst);
        let rxq = queues::rx_queue_regs(q).expect("validated queue count is in range");
        // SAFETY: MMIO.
        unsafe {
            self.mmio.write32(rxq.rdt, head as u32);
        }
        *head_g = ((head + 1) % ring_len) as u32;
        Some(Frame::new(filled, len as u32))
    }

    /// Whether queue 0 has a completed RX descriptor. See
    /// [`Self::rx_has_pending_on_queue`].
    pub fn rx_has_pending(&self) -> bool {
        self.rx_has_pending_on_queue(0)
    }

    /// Whether RX queue `q` has a completed RX descriptor;
    /// `false` when `q` is not a configured RX queue.
    pub fn rx_has_pending_on_queue(&self, q: usize) -> bool {
        if *self.quiesced.lock() {
            return false;
        }
        let queue = match self.rx_queues.get(q) {
            Some(queue) => queue,
            None => return false,
        };
        let head = (*queue.rx_head.lock()) as usize;
        let ring_phys = queue.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 12).kernel_ptr::<u8>())
        };
        status & RXD_STAT_DD != 0
    }

    /// Stage 5: enable MSI-X on this device. Allocates a single
    /// shared "misc" vector and routes RX queue 0 + TX queue 0 + the
    /// OTHER cause onto it via the IVAR registers. Corrected
    /// 2026-10-31 against datasheet §8.2.3.5.16/.17: IVAR[0] is at
    /// 0x00900 (not 0x01000, which is RDBAL[0]) and packs RX0/TX0 as
    /// `0x8080` (vector 0 + both valid bits); IVAR_MISC is at
    /// 0x00A00 with the OTHER cause at bits 14:8 + valid bit 15
    /// (`0x8000` for vector 0), not `0x80`.
    pub fn enable_msix_vector(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(), IxgbeError> {
        let table = enable_msix(cap, device).map_err(|_| IxgbeError::MsixUnavailable)?;
        // Take vector 0 for "misc" (link / RX0 / TX0 collapsed).
        let _ = table.size(); // probed for completeness
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            queues::route_queue_vector(&mut bank, 0, 0);
            queues::route_misc_vector(&mut bank, 0);
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            // GPIE: enable multiple-MSIX, auto-mask, no EIAME yet.
            // Offset corrected to 0x00898 (datasheet §8.2.3.5.18).
            self.mmio.write32(REG_GPIE, (1 << 4) | (1 << 5) | (1 << 6));
            // EIAM: auto-clear vector 0 on read of EICR.
            // Offset corrected to 0x00890 (datasheet §8.2).
            self.mmio.write32(REG_EIAM, 1);
            // Unmask vector 0.
            self.mmio.write32(REG_EIMS, 1);
        }
        self.msix = Some(table);
        Ok(())
    }

    /// Program DCB (MTQC mode + packet buffers + arbiters + PFC +
    /// TC statistics) from `cfg`. Call before bringing up traffic:
    /// the MTQC write reinterprets the queue layout (see
    /// `dcb::DcbConfig::apply`). Composition with RSS is
    /// unvalidated (see the `dcb` module header); callers must
    /// pick one mode. No DCB disable path exists — re-probe
    /// restores non-DCB mode.
    pub fn configure_dcb(&self, cfg: dcb::DcbConfig) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            cfg.apply(&mut bank, self.did).map_err(|e| match e {
                dcb::DcbError::Device => IxgbeError::UnsupportedDevice,
                _ => IxgbeError::Other("bad DCB config"),
            })?;
        }
        *self.dcb_cfg.lock() = Some(cfg);
        Ok(())
    }

    /// Enable MSI-X with one vector per queue: RX queue `q` and TX
    /// queue `q` share vector `q` (the Linux q_vector shape), and
    /// the OTHER cause shares vector 0 with queue 0. Queue causes
    /// are unmasked via EIMS_EX (Linux `ixgbe_irq_enable_queues`
    /// for 82599/X540/X550: low qmask word to EIMS_EX(0), high
    /// word to EIMS_EX(1)); the OTHER cause is unmasked via EIMS
    /// bit 31 (EIMS_OTHER). EIAM/EIAM_EX0 auto-mask the same
    /// vector sets. The datapath stays polled — no production path
    /// consumes these interrupts yet — so this is routing +
    /// unmasking, not ISR wire-up. Alternative to
    /// [`Self::enable_msix_vector`] (single shared misc vector);
    /// do not call both (each owns the full mask state).
    pub fn enable_msix_queue_vectors(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(), IxgbeError> {
        let table = enable_msix(cap, device).map_err(|_| IxgbeError::MsixUnavailable)?;
        let cfg = self.queue_config;
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            route_all_queue_vectors(&mut bank, &cfg);
        }
        let n = cfg.num_tx.max(cfg.num_rx);
        // Vector masks: low word covers vectors 0..31, high word
        // 32..63. `n` is 1..=64 (validated), so no shift below
        // reaches the word width.
        let low: u32 = if n >= 32 {
            0xFFFF_FFFF
        } else {
            (1u32 << n) - 1
        };
        let high: u32 = if n >= 64 {
            0xFFFF_FFFF
        } else if n > 32 {
            (1u32 << (n - 32)) - 1
        } else {
            0
        };
        // SAFETY: identity-mapped MMIO.
        unsafe {
            // GPIE: enable multiple-MSIX, auto-mask, no EIAME yet
            // (same bits as the single-vector path).
            self.mmio.write32(REG_GPIE, (1 << 4) | (1 << 5) | (1 << 6));
            // EIAM: auto-mask for the routed vectors.
            self.mmio.write32(REG_EIAM, low);
            if high != 0 {
                self.mmio.write32(REG_EIAM_EX0, high);
            }
            // Unmask the OTHER cause + the routed queue vectors.
            self.mmio.write32(REG_EIMS, EIMS_OTHER_CAUSE);
            if low != 0 {
                self.mmio.write32(REG_EIMS_EX0, low);
            }
            if high != 0 {
                self.mmio.write32(REG_EIMS_EX1, high);
            }
        }
        self.msix = Some(table);
        Ok(())
    }

    /// Program RSS for `queues` RX queues (1..=16, MRQE = 0001
    /// mode). Callers must have RX disabled while reprogramming
    /// filters; bring-up leaves RSS off until this runs.
    pub fn configure_rss(&self, queues: usize) -> Result<(), IxgbeError> {
        let cfg = rss::IxgbeRss::standard(queues)
            .map_err(|_| IxgbeError::Other("bad RSS queue count"))?;
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            cfg.apply(&mut bank);
        }
        *self.rss_cfg.lock() = Some(cfg);
        Ok(())
    }

    /// Program VLAN filtering (VFTA + VLNCTRL). Callers must have
    /// RX disabled while reprogramming filters.
    pub fn configure_vlan(&self, filter: vlan::VlanFilter) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            filter.apply(&mut bank);
        }
        *self.vlan_filter.lock() = Some(filter);
        Ok(())
    }

    /// Initialize Flow Director (signature or perfect mode).
    /// Opt-in like `configure_rss`: probe still brings up 1/1 and
    /// the datapath is untouched until filters are added. A missed
    /// INIT_DONE poll is not an error (Linux debugs only); the
    /// config is recorded regardless.
    pub fn configure_fdir(&self, cfg: fdir::FdirConfig) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            match cfg.mode {
                fdir::FdirMode::Signature => {
                    fdir::init_signature(&mut bank, cfg.pballoc);
                }
                fdir::FdirMode::Perfect => {
                    fdir::init_perfect(&mut bank, cfg.pballoc);
                }
            }
        }
        *self.fdir_cfg.lock() = Some(cfg);
        Ok(())
    }

    /// Program a perfect-filter input mask. The SCTP mask register
    /// is written only for X550-family parts (Linux gates it by MAC
    /// type); other parts program TCP/UDP only.
    pub fn configure_fdir_mask(&self, mask: &fdir::FdirMask) -> Result<(), IxgbeError> {
        let sctp = self.did == IXGBE_DEV_X550 || self.did == IXGBE_DEV_X550EM_X;
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::set_input_mask(&mut bank, mask, sctp)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Add a perfect-match filter (IPv4 only; see fdir.rs docs).
    pub fn fdir_add_perfect(
        &self,
        input: &fdir::FdirPerfectInput,
        soft_id: u16,
        queue: u8,
    ) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::add_perfect(&mut bank, input, soft_id, queue)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Erase a perfect-match filter (query first, remove if present).
    pub fn fdir_erase_perfect(&self, bkt_hash: u16, soft_id: u16) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::erase_perfect(&mut bank, bkt_hash, soft_id)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Add a signature filter — the ATR primitive (see fdir.rs docs).
    /// `input` is the flow/vm/VLAN word, `common` the compressed
    /// dword, `flow_type` carries the tunnel bit (0x10).
    pub fn fdir_add_signature(
        &self,
        input: u32,
        common: u32,
        flow_type: u8,
        queue: u8,
    ) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::add_signature(&mut bank, input, common, flow_type, queue)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Reinitialize the Flow Director tables. NOTE: programmed
    /// filters do not survive a reinit (no filter list is kept);
    /// callers must re-add afterwards.
    pub fn fdir_reinit(&self) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::reinit_tables(&mut bank).map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Read Flow Director statistics (registers read to clear).
    pub fn fdir_stats(&self) -> fdir::FdirStats {
        let mut bank = queues::MmioBank::new(&self.mmio);
        fdir::stats(&mut bank)
    }

    /// Record the board's WoL capability for X540-and-newer parts
    /// (see wol.rs `WolBoardCap`). Explicit opt-in only: the
    /// default record permits nothing, and setting a record arms
    /// nothing by itself — `configure_wol` / `suspend` still gate
    /// on it. The record is a board-layer statement (today from
    /// board configuration; later it can come from EEPROM word
    /// 0x2c via the EERD helper).
    pub fn set_wol_board_cap(&self, cap: wol::WolBoardCap) {
        *self.wol_board_cap.lock() = cap;
    }

    /// Enable SR-IOV / VMDq (VT mode, 64 pools x 2 queues). Opt-in
    /// and orthogonal to bring-up: the PF keeps pool 0 (queues 0/1)
    /// and VF `i` maps to pool `i+1`; the VF mailbox dispatcher in
    /// `vmdq` is fixture-proven but awaits an interrupt pump, and
    /// PCI SR-IOV config-space enablement is a separate follow-up.
    /// Callers must have RX/TX quiesced while reprogramming the
    /// queue layout.
    pub fn configure_vmdq(&self, cfg: vmdq::VmdqConfig) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            vmdq::enable_virtualization(&mut bank, &cfg)
                .map_err(|_| IxgbeError::Other("bad VMDq config"))?;
        }
        *self.vmdq_cfg.lock() = Some(cfg);
        Ok(())
    }

    /// Arm Wake-on-LAN. 82599EB by its datasheet rule; X540 and
    /// newer only when the board record permits (`wol_allowed`).
    /// Other parts, or X540+ without a permitting record, return
    /// `UnsupportedDevice` — X540+ is never armed blindly.
    pub fn configure_wol(&self, cfg: wol::WolConfig) -> Result<(), IxgbeError> {
        if !wol::wol_allowed(self.did, *self.wol_board_cap.lock()) {
            return Err(IxgbeError::UnsupportedDevice);
        }
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            cfg.arm(&mut bank);
        }
        *self.wol_armed.lock() = Some(cfg);
        Ok(())
    }

    /// Whether this device is EEE-capable, exactly Linux's
    /// `ixgbe_set_eee_capable` switch (see `eee.rs`). False for
    /// every in-tree device id.
    pub fn eee_capable(&self) -> bool {
        eee::eee_capable(self.did)
    }

    /// Set EEE enabled/disabled, mirroring Linux `ixgbe_set_eee`:
    /// enabled stores advertised = supported, disabled stores
    /// advertised = empty. Returns `UnsupportedDevice` on every
    /// in-tree device id (none is EEE-capable per Linux) — the
    /// stored state only exists for the capable parts
    /// (X550EM_A 1G_T, E610), whose FW-PHY/ACI transports are
    /// follow-ups. Unlike Linux, this does NOT reset the link:
    /// link re-application after a set is a follow-up (see
    /// `eee.rs` header).
    pub fn configure_eee(&self, enable: bool) -> Result<(), IxgbeError> {
        let (supported, advertised) = if eee::is_e610(self.did) {
            eee::e610_defaults(self.did == eee::DEV_E610_2_5G_T)
        } else if self.did == eee::DEV_X550EM_A_1G_T || self.did == eee::DEV_X550EM_A_1G_T_L {
            eee::x550em_a_defaults()
        } else {
            return Err(IxgbeError::UnsupportedDevice);
        };
        let mut state = eee::EeeState::new(supported, advertised);
        state.set_enabled(enable);
        *self.eee_state.lock() = Some(state);
        Ok(())
    }

    /// The ethtool-visible EEE snapshot, if `configure_eee` ran.
    /// `None` on in-tree device ids (never configured) and
    /// before any configuration.
    pub fn eee_status(&self) -> Option<eee::EeeStatus> {
        self.eee_state.lock().map(eee::EeeStatus::from)
    }

    /// Suspend: quiesce the datapath (mask interrupts, RXEN off,
    /// queue 0 disabled, wake status cleared) and arm WoL if
    /// given. The platform PM layer owns the PCI D-state step.
    pub fn suspend(&self, wol_cfg: Option<wol::WolConfig>) -> Result<(), IxgbeError> {
        if let Some(cfg) = wol_cfg {
            if !wol::wol_allowed(self.did, *self.wol_board_cap.lock()) {
                return Err(IxgbeError::UnsupportedDevice);
            }
            let mut bank = queues::MmioBank::new(&self.mmio);
            pm::suspend_plan(&mut bank, Some(cfg));
            *self.wol_armed.lock() = Some(cfg);
        } else {
            let mut bank = queues::MmioBank::new(&self.mmio);
            pm::suspend_plan(&mut bank, None);
        }
        *self.quiesced.lock() = true;
        Ok(())
    }

    /// Resume: REBUILD the DMA rings in place from the retained
    /// host buffers, then unquiesce and refresh link state (spec
    /// §13l decision — rebuild, not re-probe, following Linux's
    /// resume shape of reset → reconfigure → open, minus the reset:
    /// a reset would wipe RAR/RSS/VLAN/IVAR state this rebuild
    /// does not restore, while the rebuild overwrites exactly the
    /// datapath state it owns, so it is correct whether or not
    /// the suspend actually lost device state).
    ///
    /// Fail-closed: every validation runs before any register or
    /// ring memory is touched. On `Err` the device stays quiesced
    /// (pumps keep refusing work) and the caller may re-probe;
    /// a half-rebuilt datapath is never re-enabled.
    pub fn resume(&self) -> Result<(), IxgbeError> {
        let cfg = &self.queue_config;
        cfg.validate()
            .map_err(|_| IxgbeError::Other("invalid queue config"))?;
        // The rebuild programs cfg.ring_len descriptors per queue
        // into the rings bring-up allocated; a mismatch would
        // over- or under-fill ring memory, so refuse rather than
        // guess. Bring-up builds each queue's ring for exactly
        // cfg.ring_len descriptors, so the per-queue state itself
        // is the allocated length to check against — not the old
        // single-ring constants (TX_RING_LEN/RX_RING_LEN were 32)
        // and not TX_RING_N/RX_RING_N (1024: Frame channel
        // capacities, a different quantity entirely).
        if self.tx_queues.len() != cfg.num_tx || self.rx_queues.len() != cfg.num_rx {
            return Err(IxgbeError::Other("queue count != configured queue count"));
        }
        for q in self.tx_queues.iter() {
            if q.tx_pool.len() != cfg.ring_len {
                return Err(IxgbeError::Other("tx pool size != ring length"));
            }
        }
        // A slot-count mismatch means the ring and the slot table
        // disagree; refuse before touching anything rather than
        // arm a descriptor with no backing buffer.
        for q in self.rx_queues.iter() {
            if q.rx_slots.lock().len() != cfg.ring_len {
                return Err(IxgbeError::Other("rx slot count != ring length"));
            }
        }
        // 1. Zero each TX ring: stale descriptors must not reach
        // the device after re-enable.
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            for q in self.tx_queues.iter() {
                for i in 0..(cfg.ring_len * 16) {
                    core::ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
                }
            }
        }
        // 2. Re-arm every RX descriptor from the buffer its slot
        // currently owns (slots rotate as frames are handed up, so
        // the current contents — not the bring-up pool order — are
        // the truth), one queue at a time.
        for q in self.rx_queues.iter() {
            let rx_phys = q.rx_ring.dma_addr().raw();
            {
                let slots = q.rx_slots.lock();
                for (i, buf) in slots.iter().enumerate() {
                    let desc = RxDesc {
                        addr: buf.dma_addr().raw(),
                        length: 0,
                        csum: 0,
                        status: 0,
                        errors: 0,
                        special: 0,
                    };
                    // SAFETY: identity-mapped DMA ring page.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(rx_phys + (i * 16) as u64)
                                .kernel_mut_ptr::<RxDesc>(),
                            desc,
                        );
                    }
                }
            }
        }
        // Descriptor writes must be visible before the device
        // reads the rebuilt rings (same fence discipline as the
        // RX pump's re-arm path).
        compiler_fence(Ordering::SeqCst);
        // 3. Reprogram rings + enables, one entry per queue.
        // resume_rebuild_plan validates the base counts against
        // cfg.num_tx / cfg.num_rx itself, so a vector/cfg skew
        // fails here before any register is written.
        {
            let tx_bases: Vec<u64> = self
                .tx_queues
                .iter()
                .map(|q| q.tx_ring.dma_addr().raw())
                .collect();
            let rx_bases: Vec<u64> = self
                .rx_queues
                .iter()
                .map(|q| q.rx_ring.dma_addr().raw())
                .collect();
            let mut bank = queues::MmioBank::new(&self.mmio);
            pm::resume_rebuild_plan(&mut bank, cfg, &tx_bases, &rx_bases)
                .map_err(IxgbeError::Other)?;
        }
        // 4. Reset the pump cursors to the rebuilt state, then
        // unquiesce last, so no pump runs against a half-rebuilt
        // ring.
        for q in self.tx_queues.iter() {
            *q.tx_tail.lock() = 0;
        }
        for q in self.rx_queues.iter() {
            *q.rx_head.lock() = 0;
        }
        *self.quiesced.lock() = false;
        // SAFETY: identity-mapped MMIO.
        let links = unsafe { self.mmio.read32(REG_LINKS) };
        *self.link_up.lock() = links & LINKS_UP != 0;
        Ok(())
    }

    /// Prepare detach: suspend with no WoL + clear DRV_LOAD, and
    /// mark quiesced. The framework half (CONTROLLER slot, mirror
    /// note, iface unregister) is `detach_controller`.
    pub fn prepare_detach(&self) {
        let mut bank = queues::MmioBank::new(&self.mmio);
        pm::detach_plan(&mut bank);
        *self.quiesced.lock() = true;
    }

    /// Build the ethtool-visible snapshot: identity, queues,
    /// caps word, filter state, and the interval counters
    /// (GPRC/GPTC and QPRC/QPTC are read-clear — see
    /// ethtool.rs header; one call consumes every interval).
    pub fn ethtool_info(&self) -> ethtool::EthtoolInfo {
        let bank = queues::MmioBank::new(&self.mmio);
        ethtool::EthtoolInfo {
            driver: ethtool::ETHTOOL_DRIVER,
            version: ethtool::ETHTOOL_VERSION,
            mac: self.mac,
            mtu: 1500,
            link_up: *self.link_up.lock(),
            num_tx_queues: self.queue_config.num_tx as u16,
            num_rx_queues: self.queue_config.num_rx as u16,
            caps: <Self as crate::HwNic>::caps(self).0,
            rss_enabled: self.rss_cfg.lock().is_some(),
            vlan_filter_enabled: self.vlan_filter.lock().is_some(),
            wol_supported: wol::wol_allowed(self.did, *self.wol_board_cap.lock()),
            wol_armed: self.wol_armed.lock().is_some(),
            stats: ethtool::read_stats(&bank),
            queue_stats: ethtool::read_queue_stats(
                &bank,
                self.queue_config.num_rx,
                self.queue_config.num_tx,
            ),
        }
    }

    /// Disarm Wake-on-LAN.
    pub fn disarm_wol(&self) {
        let mut bank = queues::MmioBank::new(&self.mmio);
        wol::WolConfig::disarm(&mut bank);
        *self.wol_armed.lock() = None;
    }

    /// Read the latched wake status (WUS, RW1C — the read itself
    /// does not clear; use `configure_wol`/`disarm_wol` to clear).
    pub fn wol_status(&self) -> wol::WakeStatus {
        // SAFETY: identity-mapped MMIO.
        let raw = unsafe { self.mmio.read32(wol::REG_WUS) };
        wol::WakeStatus { raw }
    }

    /// Clear VLAN filtering (empty table, VFE off).
    pub fn clear_vlan(&self) {
        let mut bank = queues::MmioBank::new(&self.mmio);
        vlan::VlanFilter::clear(&mut bank);
        *self.vlan_filter.lock() = None;
    }

    /// Enable/disable VLAN tag stripping (RXDCTL.VME) on RX queue `q`.
    pub fn set_vlan_strip(&self, q: usize, enable: bool) -> Result<(), IxgbeError> {
        let regs = queues::rx_queue_regs(q).ok_or(IxgbeError::Other("bad RX queue"))?;
        let mut bank = queues::MmioBank::new(&self.mmio);
        if enable {
            bank.set_bits(regs.rxdctl, vlan::RXDCTL_VME);
        } else {
            bank.clear_bits(regs.rxdctl, vlan::RXDCTL_VME);
        }
        Ok(())
    }

    /// The stack-visible RSS config, if programmed.
    pub fn rss_config(&self) -> Option<narf_net::rss::RssConfig> {
        self.rss_cfg.lock().as_ref().map(|c| c.as_net_config())
    }

    pub fn read_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_STATUS) }
    }

    pub fn read_links(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_LINKS) }
    }
}

// ── HwNic impl (Stage 6) ───────────────────────────────────────────

impl narf_net::Interface for Ixgbe {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // per-chip name before probe gets that far.
        let n = ixgbe_ifname();
        if n.is_empty() {
            name_for(self.did)
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        *self.link_up.lock()
    }
    fn num_rx_queues(&self) -> u16 {
        self.queue_config.num_rx as u16
    }
    fn num_tx_queues(&self) -> u16 {
        self.queue_config.num_tx as u16
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        // Pumps are spawned unpinned, so every queue reports the
        // boot CPU; the `irq` field carries this lane's routing
        // (vector = queue index) for configured queues.
        narf_net::rss::QueueAffinity {
            core: 0,
            irq: queue_vector_for(&self.queue_config, q as usize),
        }
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        self.rss_config()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

impl crate::HwNic for Ixgbe {
    fn name(&self) -> &'static str {
        let n = ixgbe_ifname();
        if n.is_empty() {
            name_for(self.did)
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        *self.link_up.lock()
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIxgbe
    }
    fn caps(&self) -> crate::NicCaps {
        // TSO is a static send-path capability now (see tx());
        // VLAN_TAGGING here still means RX filtering configured —
        // TX insertion is advertised via OffloadCapabilities.
        let mut caps =
            crate::NicCaps::PROMISC | crate::NicCaps::MULTICAST_HASH | crate::NicCaps::TSO;
        if self.rss_cfg.lock().is_some() {
            caps = caps | crate::NicCaps::RSS;
        }
        if self.vlan_filter.lock().is_some() {
            caps = caps | crate::NicCaps::VLAN_TAGGING;
        }
        caps
    }
    fn num_rx_queues(&self) -> u16 {
        self.queue_config.num_rx as u16
    }
    fn num_tx_queues(&self) -> u16 {
        self.queue_config.num_tx as u16
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        narf_net::rss::QueueAffinity {
            core: 0,
            irq: queue_vector_for(&self.queue_config, q as usize),
        }
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        self.rss_config()
    }
    fn ring_capacity(&self) -> usize {
        self.queue_config.ring_len
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

// ── IxgbeNic: lightweight ZST for narf-net registry ───────────────
//
// The full `Ixgbe` struct owns MMIO + DMA rings and can't be cloned.
// `IxgbeNic` is a zero-sized sentinel that delegates to the module-level
// `CONTROLLER` static, following the same pattern as `Rtl8139Nic`.

#[derive(Debug)]
pub struct IxgbeNic;

impl narf_net::Interface for IxgbeNic {
    fn name(&self) -> &str {
        let n = ixgbe_ifname();
        if n.is_empty() {
            with_controller(|c| name_for(c.did)).unwrap_or("ixgbe")
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| *c.link_up.lock()).unwrap_or(false)
    }
    fn num_rx_queues(&self) -> u16 {
        with_controller(|c| c.queue_config.num_rx as u16).unwrap_or(1)
    }
    fn num_tx_queues(&self) -> u16 {
        with_controller(|c| c.queue_config.num_tx as u16).unwrap_or(1)
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        with_controller(|c| narf_net::rss::QueueAffinity {
            core: 0,
            irq: queue_vector_for(&c.queue_config, q as usize),
        })
        .unwrap_or_default()
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        with_controller(|c| c.rss_config()).flatten()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
                if r.is_some() {
                    // Ring consumer attached: enable the RX mirror
                    // (e1000's `rx_mirror_enabled` moment).
                    crate::publish::note_rx_mirror_attached(ixgbe_ifname());
                }
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

// ── EEPROM helpers ─────────────────────────────────────────────────

fn eeprom_read_word(mmio: &MmioRegion, addr: u16) -> Result<u16, IxgbeError> {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        mmio.write32(REG_EERD, eerd_start(addr));
    }
    // EEPROM read is short (microseconds typically) but the
    // helper still ticks sleep_pumps in case of a wedged chip
    // or hot-plug-during-init pathology. 50 ms wall-clock wedge
    // threshold.
    let mut last = 0u32;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            last = unsafe { mmio.read32(REG_EERD) };
            last & EERD_DONE != 0
        },
        narf_time::Deadline::after_ms(50),
    );
    if done {
        Ok(eeprom_decode(last))
    } else {
        Err(IxgbeError::EepromTimeout)
    }
}

fn read_mac(mmio: &MmioRegion) -> Result<[u8; 6], IxgbeError> {
    let w0 = eeprom_read_word(mmio, 0)?;
    let w1 = eeprom_read_word(mmio, 1)?;
    let w2 = eeprom_read_word(mmio, 2)?;
    Ok([
        (w0 & 0xFF) as u8,
        (w0 >> 8) as u8,
        (w1 & 0xFF) as u8,
        (w1 >> 8) as u8,
        (w2 & 0xFF) as u8,
        (w2 >> 8) as u8,
    ])
}

fn read_mac_from_rar(mmio: &MmioRegion) -> [u8; 6] {
    // SAFETY: identity-mapped MMIO.
    let ral = unsafe { mmio.read32(REG_RAL0) };
    // SAFETY: same.
    let rah = unsafe { mmio.read32(REG_RAH0) };
    [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ]
}

// ── PCI registration ───────────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Ixgbe>>> = IrqSafeSpinLock::new(None);

/// Detach the controller: quiesce + clear DRV_LOAD on the device,
/// drop the CONTROLLER slot, clear the RX mirror note, and
/// unregister the iface so its eth%d name can be reused. Pumps
/// hold Arc clones and cannot be cancelled; the quiesced flag
/// makes their tx/rx paths refuse work instead.
pub fn detach_controller() {
    if let Some(dev) = CONTROLLER.lock().take() {
        dev.prepare_detach();
    }
    let name = ixgbe_ifname();
    if !name.is_empty() {
        crate::publish::clear_rx_mirror_attached(name);
        let _ = narf_net::iface::unregister(name);
    }
}

/// The interface name `iface::register` gave this NIC (`eth%d`, Linux
/// `dev_alloc_name`). Set once at probe; the device lives as long as
/// the kernel, so the name is leaked into a `&'static str`.
static IXGBE_IFNAME: crate::publish::IfName = crate::publish::IfName::new();

/// This NIC's interface name; empty until it has registered.
pub fn ixgbe_ifname() -> &'static str {
    IXGBE_IFNAME.get()
}

/// SendFn registered with `narf_net::iface` at probe time. Routes the
/// kernel-side TCP stack's outbound frames through `Ixgbe::tx`. The
/// Arc is cloned out rather than holding the IRQ-masking CONTROLLER
/// lock across `tx` (same reasoning as e1000's send path).
fn ixgbe_send_frame(frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = CONTROLLER.lock().clone().ok_or(())?;
    ctrl.tx(frame, &meta).map_err(|_| ())
}

/// Decode a `LINKS` word into a publication sample. LINKS reports
/// carrier in-band; its speed encoding is not decoded anywhere in the
/// tree yet (PHY work, issue #790), so the sample is carrier-only
/// rather than a guessed rate.
fn ixgbe_link_sample(links: u32) -> crate::publish::LinkSample {
    crate::publish::LinkSample::carrier_only(links & LINKS_UP != 0)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: `bring_up` requires exclusive ownership of the device's
    // BAR0 for init; we hold the bus `Cap<BusDeviceCap, Write>` and the
    // `CONTROLLER` guard above guarantees no other probe is racing this
    // device, so BAR0 is owned exclusively here.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { Ixgbe::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper that generalises
    // the e1000/igb pattern. The frame-ring registration below stays.
    let name = crate::publish::publish_netdev(
        dev.mac,
        ixgbe_send_frame,
        ixgbe_link_sample(dev.read_links()),
    );

    // Ethtool surface (what ETHTOOL_GDRVINFO reports): driver,
    // version, bus address, and the offloads the send path
    // actually honors (TX checksum, TSO to the tx() copy-buffer
    // bound, VLAN insertion — see ethtool.rs).
    // Runs before IXGBE_IFNAME.set moves `name`.
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "ixgbe", Some("0.1.0"), bus_info);
    narf_net::iface::set_offloads(
        &name,
        narf_net::OffloadCapabilities {
            tx_checksum: true,
            max_tso_bytes: TX_TSO_MAX_TX as u32,
            vlan_insert: true,
            ..Default::default()
        },
    );
    IXGBE_IFNAME.set(name);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, IxgbeNic);
    }

    // No pump spawn here: `bring_up` spawned the device's per-queue
    // pump set, fed by the channel pairs whose halves occupy the
    // `rx_ipc_ring`/`tx_ipc_ring` slots (igc's discipline). A second
    // set spawned from probe would drain the same descriptor rings
    // while its mirror sink's consumer is overwritten away — silently
    // losing frames an attached ring consumer must see.

    Ok(())
}

fn spawn_pumps(
    device: Arc<Ixgbe>,
    stack_tx_cons: Consumer<Frame, TX_RING_N>,
    tx_prods: Vec<Producer<Frame, TX_RING_N>>,
    tx_cons: Vec<Consumer<Frame, TX_RING_N>>,
) {
    let cfg = device.queue_config;
    for q in 0..cfg.num_rx {
        let d = device.clone();
        // Only queue 0's pump observes the link — one publisher
        // for carrier transitions, as before.
        let observe_link = q == 0;
        narf_scheduler::spawn(async move {
            ixgbe_rx_pump(d, q, observe_link).await;
        });
    }
    if cfg.num_tx == 1 {
        // Single TX queue keeps the direct pump: the stack channel
        // feeds queue 0's pump with no dispatcher hop — the exact
        // 1/1 topology.
        let d = device.clone();
        narf_scheduler::spawn(async move {
            ixgbe_tx_pump(d, 0, stack_tx_cons).await;
        });
    } else {
        let mut prods = tx_prods;
        narf_scheduler::spawn(async move {
            ixgbe_tx_dispatch(stack_tx_cons, &mut prods).await;
        });
        for (q, c) in tx_cons.into_iter().enumerate() {
            let d = device.clone();
            narf_scheduler::spawn(async move {
                ixgbe_tx_pump(d, q, c).await;
            });
        }
    }
}

async fn ixgbe_rx_pump(device: Arc<Ixgbe>, q: usize, observe_link: bool) {
    // Zero-copy (P-F): take the device-filled DMA buffer straight out of the RX
    // descriptor as a Frame (refilling the slot), with no copy through a scratch
    // buffer + freshly-allocated frame.
    //
    // Carrier refresh (issue #791): the datapath is polled — MSI-X is
    // enabled in bring-up but no production path consumes link
    // interrupts — so queue 0's already-running pump is the family's
    // link observer. It re-reads LINKS each pass and republishes only
    // on a transition, so `iface` metadata tracks cable pull/replug
    // instead of staying a probe-time photograph. Seeded from the
    // probe-time sample so a steady link publishes nothing.
    let mut last_sample = ixgbe_link_sample(device.read_links());
    loop {
        if observe_link {
            let sample = ixgbe_link_sample(device.read_links());
            if sample != last_sample {
                last_sample = sample;
                crate::publish::publish_link(ixgbe_ifname(), sample);
            }
        }
        match device.rx_recv_frame_on_queue(q) {
            Some(mut frame) => {
                // RX fan-out (issue #784), e1000's `dispatch_rx_frame`
                // shape via the shared helper: an attached ring
                // consumer gets a pristine pre-dispatch copy; the
                // original goes to the kernel stack in place. The
                // mirror is non-blocking — a full/closed ring drops
                // its copy, never the stack's packet. All RX pumps
                // fan into the one mirror producer on the device.
                let name = ixgbe_ifname();
                crate::publish::dispatch_rx(
                    name,
                    &mut frame,
                    crate::publish::rx_mirror_attached(name),
                    |mirror| {
                        let _ = device.rx_mirror.lock().try_send(mirror);
                    },
                );
            }
            None => narf_scheduler::yield_now().await,
        }
    }
}

async fn ixgbe_tx_pump(device: Arc<Ixgbe>, q: usize, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    // Zero-copy (P-F): DMA each frame straight out of its own buffer and honor
    // the TxMeta the stack set, instead of copying the payload into a per-slot
    // buffer and forcing plain metadata.
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.tx_frame_on_queue(q, &frame);
    }
}

/// Round-robin TX dispatcher for multi-queue setups: moves frames
/// from the stack-facing channel to per-queue channels, one queue
/// per frame. No flow steering — queue choice is position, not
/// hash (RSS steering is `configure_rss`'s job and stays opt-in);
/// ordering across queues is NOT preserved, matching multi-queue
/// TX semantics. A full target queue is skipped for the next one;
/// all-full yields and retries rather than dropping.
async fn ixgbe_tx_dispatch(
    mut stack_cons: Consumer<Frame, TX_RING_N>,
    prods: &mut [Producer<Frame, TX_RING_N>],
) {
    let n = prods.len();
    if n == 0 {
        return;
    }
    let mut next = 0usize;
    while let Ok(mut frame) = stack_cons.recv().await {
        // Labeled break, not a `placed` flag: the flag's value correlates
        // with whether `frame` was moved, which the borrow checker cannot
        // track across the retry loop (E0382). The moved path exits the
        // loop outright, so every path that reaches the next retry still
        // owns `frame` (recovered from Full/Closed).
        'place: loop {
            for _ in 0..n {
                let q = next;
                next = (next + 1) % n;
                match prods[q].try_send(frame) {
                    Ok(()) => break 'place,
                    Err(TrySendError::Full(f)) | Err(TrySendError::Closed(f)) => {
                        frame = f;
                    }
                }
            }
            narf_scheduler::yield_now().await;
        }
    }
}

pub fn register_pci_driver() {
    for did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(*did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IXGBE_VENDOR,
                device: *did,
            },
            probe,
        });
    }
}

pub fn name_for(did: u16) -> &'static str {
    match did {
        IXGBE_DEV_82599EB => "ixgbe-82599eb",
        IXGBE_DEV_X540 => "ixgbe-x540",
        IXGBE_DEV_X550 => "ixgbe-x550",
        IXGBE_DEV_X550EM_X => "ixgbe-x550em",
        _ => "ixgbe",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Ixgbe) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

pub fn with_controller_mut<R>(f: impl FnOnce(&mut Ixgbe) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("Ixgbe static has multiple owners")))
}
