//! Intel ixgbe — 82599 / X540 / X550 10 GbE controller driver.
//!
//! Spec: `drivers/net/specification/ixgbe.md`. Clean-room: register
//! layout sourced from the public Intel 82599 / X540 / X550
//! datasheets. No GPL Linux source consulted.

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

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
use crate::ixgbe::rxdesc::{AdvRxDescRead, AdvRxDescWb, ADV_RXD_STAT_DD};

pub mod aci;
pub mod dcb;
pub mod eee;
pub mod ethtool;
pub mod fcoe;
pub mod fdir;
pub mod hic;
pub mod mtu;
pub mod pm;
pub mod queues;
pub mod regs;
pub mod rss;
pub mod rxdesc;
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

/// X550EM_A 1G_T — EEE-capable via the FW-PHY transport
/// (Linux `ixgbe_set_eee_capable`; DID from Linux
/// `ixgbe_type.h`). A different part from X550EM_X
/// (0x15AB): same vendor, different device id. Note
/// 0x15E4 under vendor 0x1022 is AMD's MP2 — the PCI
/// match is vendor+device, so there is no conflict.
pub const IXGBE_DEV_X550EM_A_1G_T: u16 = 0x15E4;
/// X550EM_A 1G_T_L — EEE-capable via FW-PHY (Linux).
pub const IXGBE_DEV_X550EM_A_1G_T_L: u16 = 0x15E5;
/// E610 backplane — EEE-capable via ACI (Linux).
pub const IXGBE_DEV_E610_BACKPLANE: u16 = 0x57AE;
/// E610 SFP — EEE-capable via ACI (Linux).
pub const IXGBE_DEV_E610_SFP: u16 = 0x57AF;
/// E610 10G_T — EEE-capable via ACI (Linux).
pub const IXGBE_DEV_E610_10G_T: u16 = 0x57B0;
/// E610 2.5G_T — EEE-capable via ACI (Linux).
pub const IXGBE_DEV_E610_2_5G_T: u16 = 0x57B1;

const ALL_DEV_IDS: &[u16] = &[
    IXGBE_DEV_82599EB,
    IXGBE_DEV_X540,
    IXGBE_DEV_X550,
    IXGBE_DEV_X550EM_X,
    IXGBE_DEV_X550EM_A_1G_T,
    IXGBE_DEV_X550EM_A_1G_T_L,
    IXGBE_DEV_E610_BACKPLANE,
    IXGBE_DEV_E610_SFP,
    IXGBE_DEV_E610_10G_T,
    IXGBE_DEV_E610_2_5G_T,
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
/// LINKS (82599 datasheet §8.2.3.22.20; the same offset Linux's
/// `IXGBE_LINKS` uses for 82599/X540/X550). Was 0x04200 — that is
/// PCS1GCFIG (§8.2.3.22.1), whose bit 30 is PCS_isolate, not
/// link-up, so every LINKS consumer (probe seed, resume refresh,
/// queue-0 pump observer) read a config bit that never moves with
/// the cable and carrier could never come up on silicon
/// (issue #791).
pub(crate) const REG_LINKS: u64 = 0x042A4;

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

// LINKS bits (82599 datasheet §8.2.3.22.20).
pub(crate) const LINKS_UP: u32 = 1 << 30;
/// LINK_SPEED field (bits 29:28): 00b Reserved, 01b 100 Mb/s,
/// 10b 1 GbE, 11b 10 GbE. The field is MAC link speed, not a PHY
/// rate — no PHY work (#790) is needed to report it.
pub(crate) const LINKS_SPEED_MASK: u32 = 0b11 << 28;
pub(crate) const LINKS_SPEED_100: u32 = 0b01 << 28;
pub(crate) const LINKS_SPEED_1000: u32 = 0b10 << 28;
pub(crate) const LINKS_SPEED_10000: u32 = 0b11 << 28;

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

// SRRCTL — bsize selector (1 KiB units), advanced descriptor type.
// DESCTYPE 001 (ADV_ONEBUF, Linux ixgbe_type.h:2462) selects advanced
// one-buffer descriptors; 000 (legacy) cannot report stripped VLAN
// tags (datasheet §7.1.6 requires DESCTYPE != 000 for advanced).
// `SRRCTL_BSIZE_2K` is used only by the x86_64-only test module
// (`ixgbe/tests.rs`, `#![cfg(target_arch = "x86_64")]`); production
// code programs SRRCTL via `mtu::srrctl_bsize(frame)` instead. Without
// this, aarch64 clippy reports the const as dead code (`-D warnings`).
#[allow(dead_code)]
pub(crate) const SRRCTL_BSIZE_2K: u32 = 2; // bits[4:0]
pub(crate) const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;

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

/// TX watchdog timeout (Linux `dev->watchdog_timeo` is 5 s by
/// default, and igc's supervisor uses the same 5 s): a TX
/// descriptor posted longer ago than this with DD still clear is
/// a wedged ring, not congestion.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;
/// Watchdog supervisor cadence, matching igc's 10 ms maintenance tick.
const TX_WATCHDOG_POLL_NS: u64 = 10_000_000;
/// TSO frame cap for `tx()`: the advertised bound (see probe's
/// `max_tso_bytes`). The per-slot copy buffer is 10240 bytes (see
/// bring_up), so the 4096 cap is conservative, not slot-bound;
/// raising it is a separate change from the MTU lane (issue #802).
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

// Ring lengths come from `QueueConfig::ring_len` (32 for the
// single-queue config, matching the old Stage-3/4 constants).
// RX_BUF_LEN is a buffer size, not a ring length: fixed at the
// family's max-frame size (issue #802), 10240 covers the 9732-byte
// max RX frame, so an MTU change never reallocates.
pub(crate) const RX_BUF_LEN: usize = mtu::RX_BUF_BYTES;

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

impl From<eee::EeeLiveError> for IxgbeError {
    fn from(e: eee::EeeLiveError) -> Self {
        match e {
            eee::EeeLiveError::NotCapable => IxgbeError::UnsupportedDevice,
            other => IxgbeError::Other(other.as_str()),
        }
    }
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
    /// Cycle counter at which each TX slot was posted (`0` = no
    /// descriptor outstanding), indexed by descriptor slot. The
    /// watchdog treats an aged entry as a wedged ring. Stamped by
    /// `tx_on_queue` / `tx_frame_on_queue` after the TDT doorbell,
    /// cleared when the slot's DD bit sets.
    pub(crate) tx_posted_at: IrqSafeSpinLock<Vec<u64>>,
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

/// True when any posted TX descriptor has waited longer than
/// `timeout` cycles with DD still clear — the ring is wedged (igc
/// `Queue::stalled` shape, per-slot so a later post cannot mask
/// an older stuck one). Factored pure so the fixture pins the
/// decision the watchdog uses.
fn tx_stalled(posted_at: &[u64], now: u64, timeout: u64) -> bool {
    posted_at
        .iter()
        .any(|&posted| posted != 0 && now.wrapping_sub(posted) > timeout)
}

/// Clear a slot's post time only if it still holds the stamp this
/// post recorded: a later post to the same slot (after wraparound)
/// must not have its stamp wiped by the earlier post's completion.
fn tx_note_completed(posted_at: &mut [u64], slot: usize, stamped: u64) {
    if posted_at[slot] == stamped {
        posted_at[slot] = 0;
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
    /// Programmed MTU (payload bytes), issue #802. Probe default
    /// 1500; changed only by [`Ixgbe::set_mtu`], which reprograms
    /// MAXFRS + per-queue SRRCTL before storing it.
    pub mtu: IrqSafeSpinLock<u32>,
    /// LAN id: the PCI function number (Linux
    /// `ixgbe_set_lan_id_multi_port_pcie` sets
    /// `bus->lan_id = bus->func` for these parts). The
    /// FW-PHY host-interface commands and the ACI
    /// commands carry it as the port number. Non-PCIe
    /// (MMIO) devices report 0.
    pub lan_id: u8,
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
    /// Programmed VMDq config, if `configure_vmdq` ran.
    pub vmdq_cfg: IrqSafeSpinLock<Option<vmdq::VmdqConfig>>,
    /// FCoE RX queues programmed by `configure_fcoe`, if it ran
    /// (empty = not configured). The queue list is the FCRETA
    /// round-robin set; DDP contexts themselves are consumer
    /// state (no FCoE consumer in-tree) and live in `fcoe`.
    pub fcoe_queues: IrqSafeSpinLock<Vec<u32>>,
    /// Persistent Flow Director state (init config, input masks,
    /// IP6AT address, recorded filters) for restore after reinit /
    /// reset / resume. Recorded by the `configure_fdir*` / add
    /// methods; replayed by `fdir_restore` and `fdir_reinit`.
    pub fdir_state: IrqSafeSpinLock<fdir::FdirState>,
    /// Armed WoL config, if `configure_wol` ran and was not disarmed.
    pub wol_armed: IrqSafeSpinLock<Option<wol::WolConfig>>,
    /// Programmed EEE state, if `configure_eee` ran. Always `None`
    /// on the non-capable in-tree device ids (82599EB, X540,
    /// X550, X550EM_X): Linux marks none of them
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
    tx_timeouts: AtomicU64,
    /// Controller resets performed by [`Ixgbe::recover`].
    tx_resets: AtomicU64,
    /// Set while [`Ixgbe::recover`] owns the reset sequence: TX
    /// posts fail fast instead of racing the ring reprogram (a post
    /// landing mid-reset could be zeroed with the stale ring or
    /// never rung).
    recovering: AtomicBool,
    /// TX ring epoch, advanced by [`Ixgbe::recover`] on every
    /// recovery. A `tx_on_queue` / `tx_frame_on_queue` whose DD
    /// poll straddles a reset sees DD set because the reset zeroed
    /// the ring and a later frame completed on the reused slot —
    /// not because its frame went out. The epoch distinguishes a
    /// real completion from a reset, so that caller reports
    /// `TxTimeout` instead of a success it did not earn.
    tx_epoch: AtomicU64,
    /// PCI address of the function this instance drives. Probe
    /// refuses a second bind of the same live address (issue #795):
    /// two `Ixgbe`s for one chip would drive one set of rings.
    pub addr: narf_bus::BusAddr,
    /// Interface name `publish_netdev_with_context` assigned this
    /// instance (`eth%d`). Per-instance (i40e/igc pattern): the old
    /// module-level `IXGBE_IFNAME` static could only name one NIC.
    ifname: crate::publish::IfName,
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
            .field("lan_id", &self.lan_id)
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
/// SRRCTL advanced one-buffer descriptors, queue-enable) on any [`RegBank`].
/// Same sharing note as [`program_tx_queue`].
/// Program one RX queue's ring registers + SRRCTL. `srrctl_bsize`
/// is the SRRCTL.BSIZEPKT value (1 KiB units) for the programmed
/// MTU — 2 at the 1500 default, 10 at 9710 (issue #802). The value
/// goes in unshifted (bits[6:0]); the full-word write matches the
/// pre-existing shape (bring-up and resume both write SRRCTL whole).
fn program_rx_queue(
    bank: &mut impl RegBank,
    q: usize,
    phys: u64,
    ring_len: usize,
    srrctl_bsize: u32,
) {
    let rxq = queues::rx_queue_regs(q).expect("validated queue count is in range");
    bank.write32(rxq.rdbal, phys as u32);
    bank.write32(rxq.rdbah, (phys >> 32) as u32);
    bank.write32(rxq.rdlen, (ring_len * 16) as u32);
    bank.write32(rxq.rdh, 0);
    bank.write32(rxq.rdt, ring_len.saturating_sub(1) as u32);
    bank.write32(rxq.srrctl, srrctl_bsize | SRRCTL_DESCTYPE_ADV_ONEBUF);
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
                    alloc_coherent(mtu::TX_BUF_BYTES, DomainId::DRIVER_0)
                        .map_err(|_| IxgbeError::NoMemory)?,
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
                tx_posted_at: IrqSafeSpinLock::new(alloc::vec![0u64; ring_len]),
            });
        }

        // 7. RX rings + pools, one per RX queue (queue 0's sequence
        //    verbatim, as for TX). The MTU program for the 1500
        //    default: SRRCTL 2 KiB per queue, MAXFRS 1518 (written
        //    after the FCTRL/RXCTRL enable below).
        let mtu_program = mtu::mtu_transition(mtu::STD_MTU).expect("1500 is in range");
        let mut rx_queues: Vec<RxQueueState> = Vec::with_capacity(queue_config.num_rx);
        for q in 0..queue_config.num_rx {
            let rx_ring =
                alloc_coherent(ring_alloc, DomainId::DRIVER_0).map_err(|_| IxgbeError::NoMemory)?;
            let rx_ring_phys = rx_ring.dma_addr().raw();
            let mut rx_pool = Vec::with_capacity(ring_len);
            for i in 0..ring_len {
                let buf = alloc_coherent(mtu::RX_BUF_BYTES, DomainId::DRIVER_0)
                    .map_err(|_| IxgbeError::NoMemory)?;
                let bp = buf.dma_addr().raw();
                let desc = AdvRxDescRead::new(bp);
                // SAFETY: identity-mapped DMA ring page.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                            .kernel_mut_ptr::<AdvRxDescRead>(),
                        desc,
                    );
                }
                rx_pool.push(buf);
            }
            {
                let mut bank = queues::MmioBank::new(&mmio);
                program_rx_queue(
                    &mut bank,
                    q,
                    rx_ring_phys,
                    ring_len,
                    mtu_program.srrctl_bsize,
                );
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
            // MAXFRS — the device's RX length limit (issue #802):
            // 1518 at the 1500 default, 9728 at 9710. The PF never
            // programmed it before (the reset default accepted
            // standard frames); programming it explicitly makes the
            // acceptance limit follow the MTU.
            mmio.write32(vmdq::REG_MAXFRS, mtu_program.maxfrs);
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

        let lan_id = match device.addr {
            narf_bus::BusAddr::Pcie(pci) => pci.function,
            narf_bus::BusAddr::Mmio(_) => 0,
        };

        let ixgbe = Arc::new(Self {
            mmio,
            tx_queues,
            rx_queues,
            rx_mirror: IrqSafeSpinLock::new(rx_prod),
            mac,
            link_up: IrqSafeSpinLock::new(link_up),
            did: device.id.device,
            mtu: IrqSafeSpinLock::new(mtu::STD_MTU),
            lan_id,
            queue_config,
            rss_cfg: IrqSafeSpinLock::new(None),
            dcb_cfg: IrqSafeSpinLock::new(None),
            vlan_filter: IrqSafeSpinLock::new(None),
            vmdq_cfg: IrqSafeSpinLock::new(None),
            fcoe_queues: IrqSafeSpinLock::new(Vec::new()),
            fdir_state: IrqSafeSpinLock::new(fdir::FdirState::default()),
            wol_armed: IrqSafeSpinLock::new(None),
            eee_state: IrqSafeSpinLock::new(None),
            wol_board_cap: IrqSafeSpinLock::new(wol::WolBoardCap::default()),
            quiesced: IrqSafeSpinLock::new(false),
            tx_timeouts: AtomicU64::new(0),
            tx_resets: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            tx_epoch: AtomicU64::new(0),
            addr: device.addr,
            ifname: crate::publish::IfName::new(),
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
    /// — the advertised bound) and VLAN insertion (tag
    /// from the context descriptor + VLE on the data descriptor).
    /// Non-TSO frames keep the programmed MTU's wire-size cap
    /// (issue #802). See [`Self::tx_on_queue`].
    pub fn tx(&self, frame: &[u8], meta: &TxMeta) -> Result<(), IxgbeError> {
        self.tx_on_queue(0, frame, meta)
    }

    /// Transmit a single frame on TX queue `q`, polling the
    /// descriptor's DD bit. `q` must be a configured TX queue.
    pub fn tx_on_queue(&self, q: usize, frame: &[u8], meta: &TxMeta) -> Result<(), IxgbeError> {
        if *self.quiesced.lock() {
            return Err(IxgbeError::Other("device quiesced"));
        }
        // Fail fast while recovery owns the reset sequence: a post
        // landing mid-reset could be zeroed with the stale ring.
        if self.recovering.load(Ordering::Acquire) {
            return Err(IxgbeError::Other("ixgbe TX recovery in progress"));
        }
        let queue = self
            .tx_queues
            .get(q)
            .ok_or(IxgbeError::Other("bad TX queue"))?;
        if frame.is_empty() {
            return Err(IxgbeError::FrameTooLong);
        }
        // Bounds: non-TSO keeps the programmed MTU's wire-size cap
        // (issue #802); TSO runs to the advertised bound. Larger
        // TSO needs scatter.
        let limit = if meta.tso_mss.is_some() {
            TX_TSO_MAX_TX
        } else {
            mtu::frame_size(*self.mtu.lock()) as usize
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
        // (len <= 4096 = advertised TSO bound for TSO, <= MTU frame
        // otherwise).
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

        // Post time for the watchdog (see `tx_stalled`): stamped
        // once the TDT doorbell has rung, on the data descriptor's
        // slot (a context descriptor, when present, occupies the
        // tail slot and carries no DD write-back).
        let stamped = narf_time::now_cycles();
        queue.tx_posted_at.lock()[data_slot] = stamped;
        // TX epoch at post time: if a watchdog recovery resets the
        // ring while this poll runs, a later frame's DD on the
        // reused slot can read set — the epoch check below keeps
        // that from reporting as a completion.
        let epoch = self.tx_epoch.load(Ordering::Acquire);

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
        // A reset during the poll zeroes the ring, so a later
        // frame's DD on the reused slot can read set even though
        // this frame never went out: the epoch distinguishes a real
        // completion from a reset.
        if epoch != self.tx_epoch.load(Ordering::Acquire) {
            return Err(IxgbeError::TxTimeout);
        }
        // DD set: the descriptor completed, so its post time is
        // void (conditional clear — a later post to this slot must
        // keep its own stamp).
        {
            let mut posted = queue.tx_posted_at.lock();
            tx_note_completed(&mut posted, data_slot, stamped);
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
        // Fail fast while recovery owns the reset sequence (see
        // `tx_on_queue`).
        if self.recovering.load(Ordering::Acquire) {
            return Err(IxgbeError::Other("ixgbe TX recovery in progress"));
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
            mtu::frame_size(*self.mtu.lock()) as usize
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

        // Post time for the watchdog (see `tx_on_queue`): stamped
        // once the TDT doorbell has rung, on the data descriptor's
        // slot.
        let stamped = narf_time::now_cycles();
        queue.tx_posted_at.lock()[data_slot] = stamped;
        // TX epoch at post time (see `tx_on_queue`): a reset during
        // the DD poll must not report as a completion.
        let epoch = self.tx_epoch.load(Ordering::Acquire);

        // Poll DD; the device reads the frame's buffer directly in this window.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(data_addr + 12).kernel_ptr::<u32>()) } & ADVTXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IxgbeError::TxTimeout);
        }
        // A reset during the poll zeroes the ring, so a later
        // frame's DD on the reused slot can read set even though
        // this frame never went out: the epoch distinguishes a real
        // completion from a reset.
        if epoch != self.tx_epoch.load(Ordering::Acquire) {
            return Err(IxgbeError::TxTimeout);
        }
        // DD set: the descriptor completed, so its post time is
        // void (conditional clear — a later post to this slot must
        // keep its own stamp).
        {
            let mut posted = queue.tx_posted_at.lock();
            tx_note_completed(&mut posted, data_slot, stamped);
        }
        Ok(())
    }

    /// Drain one RX frame from queue 0 into `out`. Returns 0 if
    /// nothing pending. Copy path: returns bytes only, so it cannot
    /// carry completion metadata — the pump's `rx_recv_frame` is
    /// the path that attaches `RxMeta`. Advanced write-back
    /// overwrites the buffer address, so the buffer comes from the
    /// driver's own slot pool (same lock order as `rx_recv_frame`:
    /// head, then slots). See [`Self::rx_recv_on_queue`].
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
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<AdvRxDescWb>(),
            )
        };
        if !desc.is_done() {
            return 0;
        }
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = queue.rx_slots.lock()[head].dma_addr().raw();
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
        let new_desc = AdvRxDescRead::new(buf_phys);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<AdvRxDescRead>(),
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
    /// no buffer to replace it. Completion metadata (checksum
    /// verdicts + stripped VLAN tag) is decoded from the advanced
    /// write-back descriptor and attached via `set_rx_meta` (§13k).
    /// See [`Self::rx_recv_frame_on_queue`].
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
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<AdvRxDescWb>(),
            )
        };
        if !desc.is_done() {
            return None;
        }
        let len = (desc.length as usize).min(RX_BUF_LEN);
        let meta = desc.rx_meta();
        // Refill before handing the filled buffer up, so the device never sees
        // an empty slot. On allocation failure, bail without advancing — the
        // frame stays in the ring for the next poll.
        let replacement = alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).ok()?;
        let repl_phys = replacement.dma_addr().raw();
        let filled = {
            let mut slots = queue.rx_slots.lock();
            core::mem::replace(&mut slots[head], replacement)
        };
        let new_desc = AdvRxDescRead::new(repl_phys);
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<AdvRxDescRead>(),
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
        let mut frame = Frame::new(filled, len as u32);
        frame.set_rx_meta(meta);
        Some(frame)
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
        // Advanced write-back: status_error u32 at descriptor offset 8
        // (the legacy layout had a status byte at offset 12).
        let status_error = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 8).kernel_ptr::<u32>())
        };
        status_error & ADV_RXD_STAT_DD != 0
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
    /// filters; bring-up leaves RSS off until this runs. Refuses
    /// under VT mode: RSS-only mode would rewrite the `MRQC`
    /// the VMDq composition owns — use `configure_vmdq_rss`
    /// once `configure_vmdq` has run.
    pub fn configure_rss(&self, queues: usize) -> Result<(), IxgbeError> {
        if self.vmdq_cfg.lock().is_some() {
            return Err(IxgbeError::Other(
                "RSS-only mode conflicts with VT mode; use configure_vmdq_rss",
            ));
        }
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
        self.fdir_state.lock().config = Some(cfg);
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
        self.fdir_state.lock().mask = Some(*mask);
        Ok(())
    }

    /// Program the IPv6 mask register (FDIRIP6M). `sipm` masks the
    /// source IPv6 address per byte, `dipm` the destination per byte
    /// (hash/signature only — never the perfect-match destination
    /// compare; see fdir.rs). The pair is recorded for restore.
    pub fn configure_fdir_ip6_mask(&self, sipm: u16, dipm: u16) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::set_ip6_mask(&mut bank, sipm, dipm);
        }
        self.fdir_state.lock().ip6_mask = Some((sipm, dipm));
        Ok(())
    }

    /// Program the destination-IPv6 match address (IP6AT) used by
    /// perfect-match IPv6 filters, and record it for restore.
    /// IP6AT is the WoL table (datasheet §8.2.3.24.6), shared with
    /// directed-IPv6 wake-up: programming it here also changes the
    /// WoL address — use one writer (`wol::program_ipv6`) for that
    /// reason. The address is meaningful only when FDIRM.DIPv6 is
    /// clear (`FdirMask::dst_ipv6_match`).
    pub fn configure_fdir_ipv6_dst(&self, addr: [u8; 16]) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            wol::program_ipv6(&mut bank, addr);
        }
        self.fdir_state.lock().ip6at = Some(addr);
        Ok(())
    }

    /// Add a perfect-match filter (IPv4 only; see fdir.rs docs).
    /// Recorded on success for restore after reinit / reset / resume.
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
        self.fdir_state
            .lock()
            .record_perfect(*input, soft_id, queue);
        Ok(())
    }

    /// Add an IPv6 perfect-match filter (see fdir.rs docs: source
    /// IPv6 gets a full per-filter match; the destination compares
    /// against the global IP6AT entry, gated by FDIRM.DIPv6 and
    /// FDIRCMD.IPv6DMatch). Recorded on success for restore.
    pub fn fdir_add_perfect_ipv6(
        &self,
        input: &fdir::FdirPerfectInput6,
        soft_id: u16,
        queue: u8,
    ) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::add_perfect_ipv6(&mut bank, input, soft_id, queue)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        self.fdir_state
            .lock()
            .record_perfect6(*input, soft_id, queue);
        Ok(())
    }

    /// Erase a perfect-match filter (query first, remove if present).
    /// Forgotten from the recorded state on success, so a later
    /// restore does not resurrect it.
    pub fn fdir_erase_perfect(&self, bkt_hash: u16, soft_id: u16) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::erase_perfect(&mut bank, bkt_hash, soft_id)
                .map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        self.fdir_state.lock().forget_perfect(bkt_hash, soft_id);
        Ok(())
    }

    /// Add a signature filter — the ATR primitive (see fdir.rs docs).
    /// `input` is the flow/vm/VLAN word, `common` the compressed
    /// dword, `flow_type` carries the tunnel bit (0x10).
    /// Recorded on success for restore after reinit / reset / resume.
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
        self.fdir_state
            .lock()
            .record_signature(input, common, flow_type, queue);
        Ok(())
    }

    /// Reinitialize the Flow Director tables and re-program the
    /// recorded filters (masks, IP6AT, filters — see fdir.rs
    /// `replay`). FDIRCTRL mode is preserved by the reinit itself,
    /// so no full init is needed.
    pub fn fdir_reinit(&self) -> Result<(), IxgbeError> {
        let sctp = self.did == IXGBE_DEV_X550 || self.did == IXGBE_DEV_X550EM_X;
        // Snapshot the state first: the replay polls MMIO and must
        // not run under the IrqSafeSpinLock.
        let state = self.fdir_state.lock().clone();
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::reinit_tables(&mut bank).map_err(|e| IxgbeError::Other(e.as_str()))?;
            fdir::replay(&mut bank, &state, sctp).map_err(|e| IxgbeError::Other(e.as_str()))?;
        }
        Ok(())
    }

    /// Rebuild the Flow Director tables from the recorded state
    /// (full init + masks + IP6AT + filters) — used after reset /
    /// resume, which clear the tables. No-op when nothing was ever
    /// configured. A restore failure returns `Err` (fail-closed:
    /// the device must not resume with a silently missing filter
    /// set).
    pub fn fdir_restore(&self) -> Result<(), IxgbeError> {
        let sctp = self.did == IXGBE_DEV_X550 || self.did == IXGBE_DEV_X550EM_X;
        // Snapshot the state first: the restore polls MMIO and must
        // not run under the IrqSafeSpinLock.
        let state = self.fdir_state.lock().clone();
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            fdir::restore(&mut bank, &state, sctp).map_err(|e| IxgbeError::Other(e.as_str()))?;
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
        // VT mode rewrote `MRQC` to VMDQEN: a previously recorded
        // RSS-only config no longer matches the hardware, so drop
        // the record (callers re-apply RSS via `configure_vmdq_rss`).
        *self.rss_cfg.lock() = None;
        Ok(())
    }

    /// Program RSS inside VT mode (MRQE 0xB + per-pool RETA).
    /// Call after `configure_vmdq`; `rss` must be a 2-queue
    /// config (`rss::IxgbeRss::standard(2)` — one RETA entry per
    /// queue inside each pool). Callers must have RX disabled
    /// while reprogramming filters. The composed config is
    /// recorded like RSS-only mode, so `caps()` gains `RSS` and
    /// `rss()` exposes the within-pool table.
    pub fn configure_vmdq_rss(&self, rss: rss::IxgbeRss) -> Result<(), IxgbeError> {
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            vmdq::enable_vmdq_rss(&mut bank, &rss)
                .map_err(|_| IxgbeError::Other("bad VMDq RSS config"))?;
        }
        *self.rss_cfg.lock() = Some(rss);
        Ok(())
    }

    /// Program FCoE (Ethertype filters for FCoE/FIP, FCRETA
    /// redirection over `queues`, FCRXCTRL CRC offload). Callers
    /// must have RX disabled while reprogramming filters.
    /// `sriov_pool` adds the ETQF pool bits when SR-IOV is in
    /// use (None = no pool bits). DDP contexts are a separate
    /// `fcoe` API for the future consumer; this only programs
    /// the enable sequence. Datasheet grounding for the FCoE
    /// block is an open follow-up (see `fcoe` header).
    pub fn configure_fcoe(&self, queues: &[u32], sriov_pool: Option<u8>) -> Result<(), IxgbeError> {
        let cfg = fcoe::FcoeConfig { queues, sriov_pool };
        cfg.validate()
            .map_err(|_| IxgbeError::Other("bad FCoE config"))?;
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            cfg.apply(&mut bank, fcoe::family_for(self.did));
        }
        *self.fcoe_queues.lock() = queues.to_vec();
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
    /// non-capable device id (82599EB, X540, X550, X550EM_X).
    /// On the capable parts the set goes live through the
    /// firmware: the FW-PHY setup-link activity (X550EM_A
    /// 1G_T/L) or set_phy_cfg + restart-AN (E610). The
    /// setup-link / restart-AN step IS the link
    /// re-application; Linux additionally resets the link,
    /// which this driver does not do. Transport failures
    /// surface as `Other` with the transport's message.
    pub fn configure_eee(&self, enable: bool) -> Result<(), IxgbeError> {
        if !eee::eee_capable(self.did) {
            return Err(IxgbeError::UnsupportedDevice);
        }
        let mut bank = queues::MmioBank::new(&self.mmio);
        let state = if eee::is_e610(self.did) {
            let mut caps = alloc::vec![0u8; aci::ACI_MAX_BUFFER_SIZE];
            eee::configure_e610(&mut bank, self.lan_id, self.did, enable, &mut caps)?
        } else {
            eee::configure_fw_phy(&mut bank, self.lan_id, enable)?
        };
        *self.eee_state.lock() = Some(state);
        Ok(())
    }

    /// The ethtool set-EEE entry point (Linux `ixgbe_set_eee` +
    /// `ixgbe_validate_keee`, issue #794): validate the request
    /// against the stored state — or the identification defaults
    /// ([`eee::default_state`]) when nothing was ever configured
    /// — then apply it live through [`Ixgbe::configure_eee`].
    /// Only the enabled flag may move: a request whose TX-LPI
    /// enable/timer or advertised set differs from stored fails
    /// with `Other` (Linux `-EINVAL`); a request that changes
    /// nothing succeeds without touching the firmware (Linux
    /// converts `-EALREADY` to success). Returns
    /// `UnsupportedDevice` on non-capable device ids.
    pub fn set_eee(&self, req: eee::EeeRequest) -> Result<(), IxgbeError> {
        if !eee::eee_capable(self.did) {
            return Err(IxgbeError::UnsupportedDevice);
        }
        let stored = match *self.eee_state.lock() {
            Some(state) => state,
            None => match eee::default_state(self.did) {
                Some(state) => state,
                None => return Err(IxgbeError::UnsupportedDevice),
            },
        };
        match eee::validate_request(true, &stored, &req) {
            Ok(()) => {}
            Err(eee::EeeError::AlreadyEnabled) => return Ok(()),
            Err(e) => return Err(IxgbeError::Other(e.as_str())),
        }
        self.configure_eee(req.enabled)
    }

    /// The ethtool-visible EEE snapshot, if `configure_eee` ran.
    /// `None` on non-capable device ids and before any
    /// configuration.
    pub fn eee_status(&self) -> Option<eee::EeeStatus> {
        self.eee_state.lock().map(eee::EeeStatus::from)
    }

    /// Query the live EEE status from the firmware and
    /// refresh the stored state (Linux `ixgbe_get_eee`):
    /// UD_2 link-partner modes on the FW-PHY path,
    /// get_link_info enabled/active bits + the entry
    /// delay on the ACI path. Works without a prior
    /// `configure_eee` (the state starts at the
    /// identification defaults). Returns
    /// `UnsupportedDevice` on non-capable device ids.
    pub fn eee_status_live(&self) -> Result<eee::EeeStatus, IxgbeError> {
        if !eee::eee_capable(self.did) {
            return Err(IxgbeError::UnsupportedDevice);
        }
        let mut bank = queues::MmioBank::new(&self.mmio);
        let stored = *self.eee_state.lock();
        let state = if eee::is_e610(self.did) {
            eee::status_e610(&mut bank, self.lan_id, self.did, stored)?
        } else {
            eee::status_fw_phy(&mut bank, self.lan_id, stored)?
        };
        *self.eee_state.lock() = Some(state);
        Ok(eee::EeeStatus::from(state))
    }

    /// Read the X550 MAC LPI status registers (EEE_STAT +
    /// TLPIC/RLPIC). Gated to the X550 DID: the block is
    /// defined for the X550 by its datasheet (rev. 2.7
    /// §5.3.6, Table 8-26) and the spec-update errata
    /// disables the feature, so the bits read 0 on X550
    /// silicon — this is the observation surface, not a
    /// control path. NOTE: reading TLPIC/RLPIC clears both
    /// counters. Returns `UnsupportedDevice` on every
    /// other device id.
    pub fn eee_lpi_status(&self) -> Result<eee::LpiStatus, IxgbeError> {
        if self.did != IXGBE_DEV_X550 {
            return Err(IxgbeError::UnsupportedDevice);
        }
        let bank = queues::MmioBank::new(&self.mmio);
        Ok(eee::lpi_status_read(&bank))
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
    /// the suspend actually lost device state). Step 3b rebuilds
    /// the Flow Director tables from the recorded state (suspend
    /// clears programmed filters).
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
                    let desc = AdvRxDescRead::new(buf.dma_addr().raw());
                    // SAFETY: identity-mapped DMA ring page.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(rx_phys + (i * 16) as u64)
                                .kernel_mut_ptr::<AdvRxDescRead>(),
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
            // Rebuild SRRCTL from the stored MTU (issue #802), then
            // restore MAXFRS — the rebuild plan does not own it.
            let program =
                mtu::mtu_transition(*self.mtu.lock()).expect("stored MTU is always in range");
            pm::resume_rebuild_plan(&mut bank, cfg, &tx_bases, &rx_bases, program.srrctl_bsize)
                .map_err(IxgbeError::Other)?;
            bank.write32(vmdq::REG_MAXFRS, program.maxfrs);
        }
        // 3b. Rebuild the Flow Director tables from the recorded
        // state (suspend / reset clears programmed filters). A
        // failure returns Err here — before step 4 — so the device
        // stays quiesced rather than resuming with a silently
        // missing filter set.
        self.fdir_restore()?;
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

    /// TX stall recoveries (Linux `tx_timeout_count`).
    pub fn tx_timeouts(&self) -> u64 {
        self.tx_timeouts.load(Ordering::Relaxed)
    }

    /// Controller resets performed by [`Ixgbe::recover`].
    pub fn tx_resets(&self) -> u64 {
        self.tx_resets.load(Ordering::Relaxed)
    }

    /// One watchdog pass (shared by the supervisor task and the
    /// fixture): if the link is up and a TX descriptor has waited
    /// past the timeout, count the timeout and recover. Returns
    /// true when recovery fired.
    fn check_tx_watchdog_at(&self, now: u64) -> bool {
        if *self.quiesced.lock() || self.recovering.load(Ordering::Acquire) {
            return false;
        }
        if self.read_links() & LINKS_UP == 0 {
            return false;
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let stalled = self
            .tx_queues
            .iter()
            .any(|q| tx_stalled(&q.tx_posted_at.lock(), now, timeout));
        if !stalled {
            return false;
        }
        self.tx_timeouts.fetch_add(1, Ordering::Relaxed);
        self.recover().is_ok()
    }

    /// TX-timeout recovery (Linux `ixgbe_tx_timeout` +
    /// `ixgbe_reset` shape): master-reset the MAC, reprogram the
    /// rings and filters from the bring-up values and the recorded
    /// feature state, and restart. The TX cursors are reset —
    /// descriptors posted before the reset will never complete —
    /// and the RX descriptors are re-primed from the pool. A reset
    /// that never self-clears reports `ResetTimeout` and leaves
    /// the device stopped; a concurrent recovery reports `Other`
    /// without touching the device; a quiesced device refuses
    /// outright. FCoE state is NOT replayed: `configure_fcoe`
    /// records only the queue list, not `sriov_pool`, so a
    /// faithful replay is impossible from recorded state
    /// (follow-up: record the full `FcoeConfig`). WoL is not
    /// re-armed either: it only matters across suspend, and
    /// `resume` does not re-arm it either.
    pub fn recover(&self) -> Result<(), IxgbeError> {
        if *self.quiesced.lock() {
            return Err(IxgbeError::Other("device quiesced"));
        }
        if self.recovering.swap(true, Ordering::AcqRel) {
            return Err(IxgbeError::Other("ixgbe TX recovery already in progress"));
        }
        // Advance the TX epoch before the reset: any `tx_on_queue`
        // / `tx_frame_on_queue` whose DD poll straddles the reset
        // sees DD set because the reset zeroed the ring and a later
        // frame completed on the reused slot — the epoch lets it
        // report `TxTimeout` instead of a success it did not earn.
        self.tx_epoch.fetch_add(1, Ordering::Release);
        let result = self.recover_inner();
        self.recovering.store(false, Ordering::Release);
        if result.is_ok() {
            self.tx_resets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn recover_inner(&self) -> Result<(), IxgbeError> {
        // Fail-closed preamble (same as `resume`): every
        // validation runs before any register or ring memory is
        // touched.
        let cfg = &self.queue_config;
        cfg.validate()
            .map_err(|_| IxgbeError::Other("invalid queue config"))?;
        if self.tx_queues.len() != cfg.num_tx || self.rx_queues.len() != cfg.num_rx {
            return Err(IxgbeError::Other("queue count != configured queue count"));
        }
        for q in self.tx_queues.iter() {
            if q.tx_pool.len() != cfg.ring_len {
                return Err(IxgbeError::Other("tx pool size != ring length"));
            }
        }
        for q in self.rx_queues.iter() {
            if q.rx_slots.lock().len() != cfg.ring_len {
                return Err(IxgbeError::Other("rx slot count != ring length"));
            }
        }
        // Snapshot the recorded feature state before touching the
        // device: the replays below reprogram it after the reset.
        let vmdq = *self.vmdq_cfg.lock();
        let rss = self.rss_cfg.lock().clone();
        let vlan = self.vlan_filter.lock().clone();
        let dcb = self.dcb_cfg.lock().clone();
        let eee_enabled = self.eee_state.lock().as_ref().map(|s| s.enabled());
        // 1. Mask interrupts, stop the receiver at the master
        // enable, and disable every TX/RX queue.
        {
            let mut bank = queues::MmioBank::new(&self.mmio);
            bank.write32(REG_EIMC, 0xFFFF_FFFF);
            let _ = bank.read32(REG_EICR);
            bank.clear_bits(REG_RXCTRL, RXCTRL_RXEN);
            for q in 0..cfg.num_tx {
                if let Some(tx) = queues::tx_queue_regs(q) {
                    bank.clear_bits(tx.txdctl, pm::XDCTL_ENABLE_PM);
                }
            }
            for q in 0..cfg.num_rx {
                if let Some(rx) = queues::rx_queue_regs(q) {
                    bank.clear_bits(rx.rxdctl, pm::XDCTL_ENABLE_PM);
                }
            }
        }
        // 2. Master reset — CTRL.LRST | CTRL.RST (bring-up step
        // 2). Datasheet §4.6.3.1: CTRL.RST self-clears within
        // 1 ms typical; 100 ms is the wedge threshold.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_CTRL, CTRL_RST_MASK);
        }
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(REG_CTRL) } & CTRL_RST_MASK == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(IxgbeError::ResetTimeout);
        }
        // Datasheet §4.6.3.2 — wait ~10 ms for FW handshake
        // (bring-up step 2 tail).
        let tsc_hz = narf_time::calibrate_clocks();
        if tsc_hz > 0 {
            narf_time::busy_wait_cycles((tsc_hz / 1000) * 10);
        } else {
            for _ in 0..1_000_000 {
                core::hint::spin_loop();
            }
        }
        // 3. Re-mask after reset, and tell firmware the OS driver
        // is still loaded (bring-up steps 3 + 5).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_EIMC, 0xFFFF_FFFF);
            let _ = self.mmio.read32(REG_EICR);
            let cur = self.mmio.read32(REG_CTRL_EXT);
            self.mmio
                .write32(REG_CTRL_EXT, cur | CTRL_EXT_DRV_LOAD | CTRL_EXT_NS_DIS);
        }
        // 4. Zero each TX ring: stale descriptors must not reach
        // the device after re-enable (resume step 1).
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            for q in self.tx_queues.iter() {
                for i in 0..(cfg.ring_len * 16) {
                    core::ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
                }
            }
        }
        // 5. Re-arm every RX descriptor from the buffer its slot
        // currently owns (resume step 2).
        for q in self.rx_queues.iter() {
            let rx_phys = q.rx_ring.dma_addr().raw();
            {
                let slots = q.rx_slots.lock();
                for (i, buf) in slots.iter().enumerate() {
                    let desc = AdvRxDescRead::new(buf.dma_addr().raw());
                    // SAFETY: identity-mapped DMA ring page.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(rx_phys + (i * 16) as u64)
                                .kernel_mut_ptr::<AdvRxDescRead>(),
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
        // 6. Reprogram the station address from the recorded MAC.
        // The reset may have cleared RAR0; the write is idempotent
        // either way (same encoding as `read_mac_from_rar` decodes,
        // plus the address-valid bit).
        let ral = (self.mac[0] as u32)
            | ((self.mac[1] as u32) << 8)
            | ((self.mac[2] as u32) << 16)
            | ((self.mac[3] as u32) << 24);
        let rah = (self.mac[4] as u32) | ((self.mac[5] as u32) << 8) | RAH_AV;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RAL0, ral);
            self.mmio.write32(REG_RAH0, rah);
        }
        // 7. Reprogram rings + enables, one entry per queue, and
        // restore the bring-up receive filter + master enable
        // (resume step 3).
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
            // Rebuild SRRCTL from the stored MTU (issue #802).
            let program =
                mtu::mtu_transition(*self.mtu.lock()).expect("stored MTU is always in range");
            pm::resume_rebuild_plan(&mut bank, cfg, &tx_bases, &rx_bases, program.srrctl_bsize)
                .map_err(IxgbeError::Other)?;
        }
        // 8. Replay the recorded filter/feature state the reset
        // wiped. Order mirrors the runtime composition: VMDq first
        // (it owns MTQC/MRQC — `enable_vmdq_rss` requires VT mode
        // already on), then RSS (VMDq-RSS when VT mode is on,
        // RSS-only otherwise), VLAN, DCB, FDIR, EEE. DCB/RSS
        // composition is unvalidated at runtime and stays so here.
        if let Some(cfg) = vmdq {
            let mut bank = queues::MmioBank::new(&self.mmio);
            vmdq::enable_virtualization(&mut bank, &cfg)
                .map_err(|_| IxgbeError::Other("bad VMDq config"))?;
        }
        if let Some(rss) = &rss {
            let mut bank = queues::MmioBank::new(&self.mmio);
            if vmdq.is_some() {
                vmdq::enable_vmdq_rss(&mut bank, rss)
                    .map_err(|_| IxgbeError::Other("bad VMDq RSS config"))?;
            } else {
                rss.apply(&mut bank);
            }
        }
        if let Some(filter) = &vlan {
            let mut bank = queues::MmioBank::new(&self.mmio);
            filter.apply(&mut bank);
        }
        if let Some(cfg) = &dcb {
            let mut bank = queues::MmioBank::new(&self.mmio);
            cfg.apply(&mut bank, self.did).map_err(|e| match e {
                dcb::DcbError::Device => IxgbeError::UnsupportedDevice,
                _ => IxgbeError::Other("bad DCB config"),
            })?;
        }
        self.fdir_restore()?;
        if let Some(enabled) = eee_enabled {
            self.configure_eee(enabled)?;
        }
        // 9. Re-arm the MSI-X routing + unmasking when a table is
        // enabled (`enable_msix_queue_vectors` shape). The
        // single-vector path armed only vector 0 via EIMS bit 0,
        // while this replays the per-queue arm (OTHER via EIMS bit
        // 31, queue vectors via EIMS_EX); the IVAR routing is
        // identical for a 1/1 config and the datapath stays polled
        // with no consumer, so the union unmasking is the safe
        // post-reset state — Linux likewise re-enables every queue
        // interrupt after a reset.
        if self.msix.is_some() {
            let cfg = self.queue_config;
            {
                let mut bank = queues::MmioBank::new(&self.mmio);
                route_all_queue_vectors(&mut bank, &cfg);
            }
            let n = cfg.num_tx.max(cfg.num_rx);
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
                self.mmio.write32(REG_GPIE, (1 << 4) | (1 << 5) | (1 << 6));
                self.mmio.write32(REG_EIAM, low);
                if high != 0 {
                    self.mmio.write32(REG_EIAM_EX0, high);
                }
                self.mmio.write32(REG_EIMS, EIMS_OTHER_CAUSE);
                if low != 0 {
                    self.mmio.write32(REG_EIMS_EX0, low);
                }
                if high != 0 {
                    self.mmio.write32(REG_EIMS_EX1, high);
                }
            }
        }
        // 10. Reset the pump cursors to the rebuilt state, clear
        // every post time, and refresh + republish link from live
        // LINKS (resume step 4, plus the publish).
        for q in self.tx_queues.iter() {
            *q.tx_tail.lock() = 0;
            q.tx_posted_at.lock().fill(0);
        }
        for q in self.rx_queues.iter() {
            *q.rx_head.lock() = 0;
        }
        // SAFETY: identity-mapped MMIO.
        let links = unsafe { self.mmio.read32(REG_LINKS) };
        *self.link_up.lock() = links & LINKS_UP != 0;
        crate::publish::publish_link(self.ifname(), ixgbe_link_sample(links));
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
            mtu: *self.mtu.lock(),
            link_up: *self.link_up.lock(),
            num_tx_queues: self.queue_config.num_tx as u16,
            num_rx_queues: self.queue_config.num_rx as u16,
            caps: <Self as crate::HwNic>::caps(self).0,
            rss_enabled: self.rss_cfg.lock().is_some(),
            vlan_filter_enabled: self.vlan_filter.lock().is_some(),
            wol_supported: wol::wol_allowed(self.did, *self.wol_board_cap.lock()),
            wol_armed: self.wol_armed.lock().is_some(),
            eee: self.eee_status(),
            stats: ethtool::read_stats(&bank),
            queue_stats: ethtool::read_queue_stats(
                &bank,
                self.queue_config.num_rx,
                self.queue_config.num_tx,
            ),
            tx_timeouts: self.tx_timeouts(),
            tx_resets: self.tx_resets(),
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

    /// Program a validated MTU (issue #802): MAXFRS (the
    /// device-wide RX length limit) first, then per-queue SRRCTL
    /// (same full-word write bring-up/resume use). No queue
    /// disable is needed: the pools are fixed at the max-frame
    /// size, so a descriptor fetched with the old BSIZEPKT can
    /// only under-fill its slot, never overrun it.
    fn program_mtu(&self, program: mtu::MtuProgram) {
        let mut bank = queues::MmioBank::new(&self.mmio);
        bank.write32(vmdq::REG_MAXFRS, program.maxfrs);
        for q in 0..self.queue_config.num_rx {
            let rxq = queues::rx_queue_regs(q).expect("validated queue count is in range");
            bank.write32(
                rxq.srrctl,
                program.srrctl_bsize | SRRCTL_DESCTYPE_ADV_ONEBUF,
            );
        }
    }

    /// Change the MTU (issue #802). Validates via the pure policy
    /// module first (EINVAL 22 outside 68..=9710), no-ops when the
    /// MTU is unchanged, otherwise programs the hardware and then
    /// stores the new MTU. The RX/TX pools are fixed at the
    /// max-frame size, so no reallocation is needed.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), i32> {
        let program = mtu::mtu_transition(mtu).map_err(|e| e.0)?;
        if program.mtu == *self.mtu.lock() {
            return Ok(());
        }
        self.program_mtu(program);
        *self.mtu.lock() = program.mtu;
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

impl narf_power::device_pm::DevicePmOps for Ixgbe {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        // System suspend with no WoL arming: the `suspend` plan
        // disarms the wake filters. Arming a configured WoL policy
        // on system suspend is a follow-up (e1000's gap-6 shape);
        // the runtime `suspend(Some(cfg))` path stays for callers
        // that already hold a `WolConfig`.
        self.suspend(None)
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.resume()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
}

// ── MTU control hook ────────────────────────────────────────────────

/// `DeviceControl` adapter for the stack's MTU switch (issue #802):
/// the hook only acts on MTU — MAC, promiscuous and multicast pass
/// through untouched. Installed by `probe` after `iface::register`.
#[derive(Debug)]
pub struct IxgbeMtuControl {
    controller: Arc<Ixgbe>,
}

impl narf_net::iface::DeviceControl for IxgbeMtuControl {
    fn configure(&self, config: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        self.controller.set_mtu(config.mtu)
    }
}

// ── HwNic impl (Stage 6) ───────────────────────────────────────────

impl narf_net::Interface for Ixgbe {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // per-chip name before probe gets that far.
        let n = self.ifname();
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
        *self.mtu.lock()
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
        let n = self.ifname();
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
        *self.mtu.lock()
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

// ── IxgbeNic: one probed port for the narf-net registry ────────────
//
// The full `Ixgbe` struct owns MMIO + DMA rings and can't be cloned,
// so the registry holds this thin adapter instead. It owns its
// `Arc<Ixgbe>` and delegates every method to the struct's own
// per-device `Interface` / `HwNic` impls — the rings are borrowed
// out of the controller, so each port's frame rings are its own
// (i40e's `I40eNicIface` pattern). The old zero-sized sentinel
// delegated to the module-level `CONTROLLER` static instead, which
// could only ever serve the first port (issue #795).

#[derive(Debug)]
pub struct IxgbeNic {
    /// This port's controller; the rings are borrowed out of it.
    nic: Arc<Ixgbe>,
}

impl narf_net::Interface for IxgbeNic {
    fn name(&self) -> &str {
        <Ixgbe as narf_net::Interface>::name(&self.nic)
    }
    fn mac(&self) -> [u8; 6] {
        <Ixgbe as narf_net::Interface>::mac(&self.nic)
    }
    fn mtu(&self) -> u32 {
        // Delegates to `<Ixgbe as Interface>::mtu`, which the #802
        // change makes read the programmed `mtu` lock — the branch's
        // old singleton `with_controller` lookup is gone on main
        // (#1633, indexed now) and this Nic already holds its own
        // `Arc<Ixgbe>`, so per-port MTU comes from `self.nic`.
        <Ixgbe as narf_net::Interface>::mtu(&self.nic)
    }
    fn link_up(&self) -> bool {
        <Ixgbe as narf_net::Interface>::link_up(&self.nic)
    }
    fn num_rx_queues(&self) -> u16 {
        <Ixgbe as narf_net::Interface>::num_rx_queues(&self.nic)
    }
    fn num_tx_queues(&self) -> u16 {
        <Ixgbe as narf_net::Interface>::num_tx_queues(&self.nic)
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        <Ixgbe as narf_net::Interface>::queue_affinity(&self.nic, q)
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        <Ixgbe as narf_net::Interface>::rss(&self.nic)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        // Ring consumer attached: enable the RX mirror (e1000's
        // `rx_mirror_enabled` moment), keyed by this port's own
        // published name. The struct impl returns the controller's
        // own slot directly, so no take-into-static happens here.
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        <Ixgbe as narf_net::Interface>::rx_ring(&self.nic)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Ixgbe as narf_net::Interface>::tx_ring(&self.nic)
    }
}

impl crate::HwNic for IxgbeNic {
    fn name(&self) -> &'static str {
        <Ixgbe as crate::HwNic>::name(&self.nic)
    }
    fn mac(&self) -> [u8; 6] {
        <Ixgbe as crate::HwNic>::mac(&self.nic)
    }
    fn mtu(&self) -> u32 {
        <Ixgbe as crate::HwNic>::mtu(&self.nic)
    }
    fn link_up(&self) -> bool {
        <Ixgbe as crate::HwNic>::link_up(&self.nic)
    }
    fn model(&self) -> crate::NicModel {
        <Ixgbe as crate::HwNic>::model(&self.nic)
    }
    fn caps(&self) -> crate::NicCaps {
        <Ixgbe as crate::HwNic>::caps(&self.nic)
    }
    fn num_rx_queues(&self) -> u16 {
        <Ixgbe as crate::HwNic>::num_rx_queues(&self.nic)
    }
    fn num_tx_queues(&self) -> u16 {
        <Ixgbe as crate::HwNic>::num_tx_queues(&self.nic)
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        <Ixgbe as crate::HwNic>::queue_affinity(&self.nic, q)
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        <Ixgbe as crate::HwNic>::rss(&self.nic)
    }
    fn ring_capacity(&self) -> usize {
        <Ixgbe as crate::HwNic>::ring_capacity(&self.nic)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
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

impl Ixgbe {
    /// This instance's published interface name (`eth%d`), or `""`
    /// before probe publishes it. Per-instance state (i40e/igc
    /// pattern); the pumps and the registry adapter read the name
    /// off the device they serve, never a module-level static.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }
}

// ── PCI registration ───────────────────────────────────────────────

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`ixgbe_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second 82599/X540 on the same machine probes, binds, and carries
/// traffic instead of being dropped by a singleton slot (issue
/// #795). The vec never shrinks: detaches quiesce the device in
/// place instead of removing its slot, so a live controller's
/// cookie stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<Ixgbe>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// The probed controller at `index`, if it is live (probed and not
/// quiesced by detach/suspend). The index is the cookie probe
/// assigned (see `CONTROLLERS`); it is stable because the vec never
/// shrinks.
fn live_controller(index: usize) -> Option<Arc<Ixgbe>> {
    CONTROLLERS
        .lock()
        .get(index)
        .filter(|c| !*c.quiesced.lock())
        .cloned()
}

/// Detach the controller at `index`: quiesce + clear DRV_LOAD on the
/// device, drop the RX mirror note, and unregister the iface so its
/// `eth%d` name can be reused. Idempotent: an out-of-range index or
/// an already-quiesced controller does nothing. Pumps hold `Arc`
/// clones and cannot be cancelled; the quiesced flag makes their
/// tx/rx paths refuse work instead. The `CONTROLLERS` slot is kept
/// so other controllers' cookies stay valid.
pub fn detach_controller(index: usize) {
    let Some(dev) = CONTROLLERS.lock().get(index).cloned() else {
        return;
    };
    if *dev.quiesced.lock() {
        return;
    }
    dev.prepare_detach();
    let name = dev.ifname();
    if !name.is_empty() {
        crate::publish::clear_rx_mirror_attached(name);
        let _ = narf_net::iface::unregister(name);
        narf_power::device_pm::unregister_device_pm(name);
    }
}

/// `SendCtxFn` registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through `Ixgbe::tx`;
/// the cookie is the controller's index in `CONTROLLERS`. The `Arc`
/// is cloned out rather than holding the IRQ-masking `CONTROLLERS`
/// lock across `tx` (same reasoning as e1000's send path).
fn ixgbe_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = live_controller(cookie as usize).ok_or(())?;
    ctrl.tx(frame, &meta).map_err(|_| ())
}

/// Decode a `LINKS` word into a publication sample (82599
/// datasheet §8.2.3.22.20: bit 30 Link Up, bits 29:28 LINK_SPEED
/// 01b = 100 Mb/s, 10b = 1 GbE, 11b = 10 GbE, 00b Reserved).
/// Speed is MAC link speed, so it needs no PHY decode (#790).
/// Duplex stays `None`: LINKS reports no duplex bit, and the
/// 82599's link modes (KX/KR/SFI/SGMII) carry no half-duplex
/// state to publish — the sample says what the register proves
/// and nothing more.
fn ixgbe_link_sample(links: u32) -> crate::publish::LinkSample {
    if links & LINKS_UP == 0 {
        return crate::publish::LinkSample::DOWN;
    }
    let speed_mbps = match links & LINKS_SPEED_MASK {
        LINKS_SPEED_100 => Some(100),
        LINKS_SPEED_1000 => Some(1000),
        LINKS_SPEED_10000 => Some(10000),
        // 00b Reserved: carrier is real, the rate is not proven.
        _ => None,
    };
    crate::publish::LinkSample {
        carrier: true,
        speed_mbps,
        duplex: None,
        media_available: None,
        phy_type: None,
        phy_type_name: None,
    }
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // A second probe of the SAME live function is a no-op success
    // (the old idempotent behaviour): the bus re-walks devices, and
    // rebuilding a second `Ixgbe` for the same silicon would let two
    // instances drive one chip's rings. A second FUNCTION binds as a
    // new instance instead of being dropped (issue #795). A quiesced
    // (detached) entry does not block a re-probe of its address, so
    // a hot re-bind after detach can reclaim the function.
    if CONTROLLERS
        .lock()
        .iter()
        .any(|c| c.addr == device.addr && !*c.quiesced.lock())
    {
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
    // same-address guard above guarantees no other probe is racing this
    // device, so BAR0 is owned exclusively here.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { Ixgbe::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper, keyed by the
    // `CONTROLLERS` index so each port's send path resolves to its
    // own NIC (i40e pattern). The frame-ring registration below stays.
    let name = crate::publish::publish_netdev_with_context(
        dev.mac,
        index as u64,
        ixgbe_send_frame,
        ixgbe_link_sample(dev.read_links()),
    );

    // Ethtool surface (what ETHTOOL_GDRVINFO reports): driver,
    // version, bus address, and the offloads the paths actually
    // honor (TX checksum + RX checksum reporting, TSO to the tx()
    // copy-buffer bound, VLAN insertion — see ethtool.rs).
    // Runs before `dev.ifname.set` moves `name`.
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "ixgbe", Some("0.1.0"), bus_info);
    narf_net::iface::set_device_control(
        &name,
        Arc::new(IxgbeMtuControl {
            controller: dev.clone(),
        }),
    );
    narf_net::iface::set_offloads(
        &name,
        narf_net::OffloadCapabilities {
            tx_checksum: true,
            rx_checksum: true,
            max_tso_bytes: TX_TSO_MAX_TX as u32,
            vlan_insert: true,
        },
    );
    dev.ifname.set(name);

    // Device-PM registration (#793): system suspend fans out
    // through `Ixgbe::suspend(None)` / `Ixgbe::resume` via the
    // `DevicePmOps` impl above. The registry is idempotent on the
    // interface name; detach withdraws the entry. The suspend/resume
    // register plans are fixture-pinned in `ixgbe::pm` (`tests.rs`).
    narf_power::device_pm::register_device_pm_ops(dev.ifname(), dev.clone());

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, IxgbeNic { nic: dev.clone() });
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
    let d = device;
    narf_scheduler::spawn(async move {
        ixgbe_watchdog_pump(d).await;
    });
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
                crate::publish::publish_link(device.ifname(), sample);
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
                let name = device.ifname();
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

/// TX-timeout supervisor (igc maintenance-task shape): every 10 ms
/// run one watchdog pass; a queue stalled 5 s with carrier up is
/// recovered and counted. The pass itself gates on detach/suspend
/// (quiesced) and on an in-flight recovery, so this loop is only a
/// timer.
async fn ixgbe_watchdog_pump(device: Arc<Ixgbe>) {
    let tick = narf_time::ns_to_cycles(TX_WATCHDOG_POLL_NS);
    loop {
        narf_time::sleep_cycles(tick).await;
        device.check_tx_watchdog_at(narf_time::now_cycles());
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
        IXGBE_DEV_X550EM_A_1G_T => "ixgbe-x550em-a-1g-t",
        IXGBE_DEV_X550EM_A_1G_T_L => "ixgbe-x550em-a-1g-t-l",
        IXGBE_DEV_E610_BACKPLANE => "ixgbe-e610-backplane",
        IXGBE_DEV_E610_SFP => "ixgbe-e610-sfp",
        IXGBE_DEV_E610_10G_T => "ixgbe-e610-10g-t",
        IXGBE_DEV_E610_2_5G_T => "ixgbe-e610-2-5g-t",
        _ => "ixgbe",
    }
}

/// Number of live probed controllers (issue #795).
pub fn instance_count() -> usize {
    CONTROLLERS
        .lock()
        .iter()
        .filter(|c| !*c.quiesced.lock())
        .count()
}

/// `true` once at least one controller has been probed and not
/// quiesced by detach/suspend.
pub fn is_probed() -> bool {
    instance_count() > 0
}

/// The live probed controller at `index`, if it exists (see
/// `live_controller`).
pub fn controller(index: usize) -> Option<Arc<Ixgbe>> {
    live_controller(index)
}

/// Test-side accessor: run `f` against the live probed controller
/// at `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&Ixgbe) -> R) -> Option<R> {
    live_controller(index).map(|a| f(&a))
}

/// Mutable accessor.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut Ixgbe) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .filter(|c| !*c.quiesced.lock())
        .map(|a| f(Arc::get_mut(a).expect("Ixgbe static has multiple owners")))
}
