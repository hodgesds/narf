//! ixgbe SR-IOV / VMDq — PF-side virtualization: VT mode, VMDq pool
//! registers, the VF mailbox, and the PF/VF message interface.
//!
//! Grounding (STRICT): every register address and bit in this module
//! comes from Linux ixgbe @ cbbddb6 (`drivers/net/ethernet/intel/
//! ixgbe/ixgbe_type.h`, `ixgbe_mbx.h`, `ixgbe_mbx.c`,
//! `ixgbe_sriov.c`, `ixgbe_main.c`). No 82599 datasheet copy was
//! available locally, so Linux is the authoritative source here,
//! cross-checked against the in-tree datasheet-grounded values where
//! they overlap (queue stride 0x40 and the IVAR layout in
//! [`super::queues`]). Where Linux's own code is commented out, this
//! module mirrors the ACTIVE behavior and says so:
//!
//! * VF MACVLAN add is commented out in `ixgbe_sriov.c`
//!   (`ixgbe_set_vf_macvlan`): `SET_MACVLAN` with index > 1 is a
//!   success no-op; index <= 1 deletes the VF's extra filters.
//! * The `clear_to_send` gate in `ixgbe_rcv_msg_from_vf` is commented
//!   out: messages dispatch without it. The flag is still tracked
//!   (set true by RESET) so a future pump can re-enable the gate.
//! * Linux never sets `VT_CTL.VT_ENABLE` in this tree (it only reads
//!   it in `ixgbe_common.c`): VT mode here is exactly what Linux
//!   programs — `MTQC` VT_ENA + `MRQC` VMDQEN + `VT_CTL` pool/REPLEN.
//!   If silicon ever shows VT inactive, the `VT_ENABLE` bit is the
//!   first thing to check.
//! * The 82599 jumbo-mix rule in `ixgbe_set_vf_lpe` is commented
//!   out: `SET_LPE` only validates the range and bumps `MAXFRS`.
//!
//! Pool model (NARF deviation, documented): Linux numbers VF pools
//! from 0 with the PF's queues after them (`ring_feature[RING_F_VMDQ]
//! .offset = num_vfs`). NARF keeps the PF on pool 0 (queues 0/1, the
//! 1/1 default bring-up, untouched) and maps VF `i` to pool `i+1`,
//! so at most 63 VFs. Pool numbers are invisible to VFs (`GET_QUEUES`
//! reports counts only), so this changes no VF-visible behavior.
//!
//! Primary-MAC slot (NARF simplification, documented): Linux scans
//! for a free RAR on every filter add. NARF pins VF `i`'s primary MAC
//! to RAR `i+1` (RAR 0 is the PF's). Same observable register state
//! for the primary MAC, no scan, and reprogramming a VF's MAC
//! overwrites its own slot instead of leaking the old filter.
//!
//! VFTA composition (documented): `set_pool_vlan` sets the VLAN's
//! VFTA bit (additive OR, mirroring Linux's `set_vfta_generic`),
//! but `clear_pool_vlan` does NOT clear VFTA bits — those belong to
//! the PF's filter state owned by [`super::vlan`], and clearing them
//! on a pool-VLAN remove could silently drop a PF VLAN. Stale VFTA
//! bits after a pool-VLAN remove are benign: the pool-level VLVF
//! still gates delivery.
//!
//! NOT in this module (sequenced follow-ups, not silently dropped):
//! the mailbox *interrupt* routing (the pump below is polled from
//! the driver's 10 ms watchdog tick — no ISR exists in this driver
//! yet, and the `EICR_MAILBOX` cause bit's numeric value was not
//! verifiable against Linux ixgbe @ cbbddb6 from the sources
//! available to this lane, so no cause bit is programmed; wiring
//! the misc-vector cause to the pump is the follow-up), PCI SR-IOV
//! config-space enablement (VF devices appearing on the bus is a
//! PCI-layer step, not device registers),
//! `SET_MULTICAST` / `GET_RETA` / `GET_RSS_KEY` / `UPDATE_XCAST_MODE`
//! / link-state / IPSEC / `FEATURES_NEGOTIATE` (all NACKed),
//! 32-VF mode (4 queues/pool — `MTQC_32VF` needs its `MRQC` 32-pool
//! no-RSS pairing grounded before it is programmed), spoof-check
//! enforcement (only the `VMECM` counting bit is set on RESET;
//! `PFVFSPOOF` anti-spoofing is not programmed), and DCB+VT
//! combinations.
//!
//! Register map (settled by #1397): this module programs `MRQC`
//! through the shared authority `regs::REG_MRQC` (canonical
//! 0x05818, the Linux/compat alias; the datasheet dual-maps it
//! to 0x0EC80, and `rss.rs` programs the same canonical address
//! through `regs.rs`). `configure_rss` and `configure_vmdq`
//! therefore write the SAME `MRQC` register. The RSS+VMDq
//! composition lives here too ([`enable_vmdq_rss`]): after VT
//! mode is on, it switches the MRQE value from `VMDQEN` (0x8,
//! "64 pools no RSS") to `VMDQRSS64EN` (0xB, Linux's SR-IOV
//! value) with the hash fields on, programs the shared RSS key
//! + the per-pool indirection table (the 82599's single RETA is
//!   common to all pools; each entry is the queue inside the pool
//!   — datasheet §4.6.10.1.1), and bounds the lookup per pool
//!   with `PSRTYPE` RQPL. The X550 per-pool registers
//!   (`PFVFMRQC` / `PFVFRETA` / `PFVFRSSRK`) do not exist on
//!   82599 and are never programmed.
//!
//! RAR 16 note: VF 15's primary slot (RAR 16, 0x0A200) coincides
//! with the driver's `REG_RAL0` fallback-read address. That path
//! only reads, and only at bring-up before VMDq is configured, so
//! there is no live interference.

use super::queues::RegBank;
use super::regs::{REG_RETA_BASE, REG_RSSRK_BASE};
use super::rss::{reta_words, rssrk_words, IxgbeRss, MRQC_HASH_FIELDS};
use super::vlan::REG_VFTA_BASE;

/// VMDq pools on the 82599 (VLVF entries, VMOLR entries).
pub const MAX_POOLS: usize = 64;
/// VFs: pool 0 is the PF's, so VF `i` owns pool `i+1`.
pub const MAX_VFS: usize = 63;
/// Queues per pool in 64-pool VT mode (2 TX + 2 RX).
pub const QUEUES_PER_POOL: usize = 2;
/// RAR entries on the 82599 (MPSAR covers all of them).
pub const RAR_ENTRIES: usize = 128;
/// Mailbox message buffer size, in 32-bit words.
pub const MBX_WORDS: usize = 16;
/// RESET reply length, in words (`IXGBE_VF_PERMADDR_MSG_LEN`).
pub const PERMADDR_MSG_LEN: usize = 4;

// ── VT-mode registers ─────────────────────────────────────────────

/// Multiple Transmit Queues Control.
pub const REG_MTQC: u64 = 0x08120;
/// `MTQC` VT enable bit.
pub const MTQC_VT_ENA: u32 = 0x2;
/// `MTQC` 64-VF layout: 2 TX queues per pool.
pub const MTQC_64VF: u32 = 0x4;
/// Receive Transmit Descriptor Control Status (arbiter control).
pub const REG_RTTDCS: u64 = 0x04900;
/// `RTTDCS` arbiter-disable bit (set while programming `MTQC`).
pub const RTTDCS_ARBDIS: u32 = 0x40;
/// Multiple Receive Queues Command — shared authority, see `regs.rs`.
/// Re-exported (not redefined) so the VMDq path and the RSS path
/// program the same canonical address (`regs::REG_MRQC`).
pub use super::regs::REG_MRQC;
/// `MRQC` receive-mode field (bits 3:0).
pub const MRQC_MRQE_MASK: u32 = 0xF;
/// `MRQC` VMDq2, 64 pools, no RSS.
pub const MRQC_VMDQEN: u32 = 0x8;
/// `MRQC` VMDq2, 64 pools, with RSS — re-exported from the shared
/// authority (`regs::MRQE_VMDQ_64_RSS`), never redefined here.
pub use super::regs::MRQE_VMDQ_64_RSS;
/// Virtualization Control (`PFVTCTL`).
pub const REG_VT_CTL: u64 = 0x051B0;
/// `VT_CTL` VT-enable bit: defined, but NOT set by Linux in this
/// path (see module docs). Kept so a silicon follow-up can set it.
pub const VT_CTL_VT_ENABLE: u32 = 0x1;
/// `VT_CTL` replication-enable bit (Linux sets it with the pool).
pub const VT_CTL_REPLEN: u32 = 0x4000_0000;
/// `VT_CTL` disable-default-pool bit (not set: pool 0 stays default).
pub const VT_CTL_DIS_DEFPL: u32 = 0x2000_0000;
/// `VT_CTL` default-pool field shift.
pub const VT_CTL_POOL_SHIFT: u32 = 7;
/// `VT_CTL` default-pool field mask (bits 13:7).
pub const VT_CTL_POOL_MASK: u32 = 0x3F << VT_CTL_POOL_SHIFT;
/// PF DMA Transmit General Switch Control (VEB switching).
pub const REG_PFDTXGSWC: u64 = 0x08220;
/// `PFDTXGSWC` local-L2 VT-switch enable (VEB mode).
pub const PFDTXGSWC_VT_LBEN: u32 = 0x1;

// ── Per-pool RSS (PSRTYPE) ────────────────────────────────────────

/// Packet Split Receive Type, pool `pool` (64 registers: pools
/// 0..15 at 0x05480, pools 16..63 at 0x0EA00 — Linux
/// `IXGBE_PSRTYPE`).
pub fn psrtype(pool: usize) -> u64 {
    if pool <= 15 {
        0x05480 + 4 * pool as u64
    } else {
        0x0EA00 + 4 * pool as u64
    }
}

/// `PSRTYPE` TCP-header split bit.
pub const PSRTYPE_TCPHDR: u32 = 0x10;
/// `PSRTYPE` UDP-header split bit.
pub const PSRTYPE_UDPHDR: u32 = 0x20;
/// `PSRTYPE` IPv4-header split bit.
pub const PSRTYPE_IPV4HDR: u32 = 0x100;
/// `PSRTYPE` IPv6-header split bit.
pub const PSRTYPE_IPV6HDR: u32 = 0x200;
/// `PSRTYPE` L2-header split bit.
pub const PSRTYPE_L2HDR: u32 = 0x1000;
/// `PSRTYPE` RSS-queues-per-pool field mask (bits 31:29).
pub const PSRTYPE_RQPL_MASK: u32 = 0x7;
/// `PSRTYPE` RSS-queues-per-pool field shift.
pub const PSRTYPE_RQPL_SHIFT: u32 = 29;

/// `PSRTYPE` word for `rss_queues_per_pool` RSS queues per pool
/// (Linux `ixgbe_setup_psrtype`: the header-split bits are always
/// set; RQPL is 0 for 1 queue, 1 for 2 queues, 2 for 4 queues).
pub fn psrtype_word(rss_queues_per_pool: usize) -> u32 {
    let w = PSRTYPE_TCPHDR | PSRTYPE_UDPHDR | PSRTYPE_IPV4HDR | PSRTYPE_L2HDR | PSRTYPE_IPV6HDR;
    let rqpl = if rss_queues_per_pool > 3 {
        2
    } else if rss_queues_per_pool > 1 {
        1
    } else {
        0
    };
    w | ((rqpl & PSRTYPE_RQPL_MASK) << PSRTYPE_RQPL_SHIFT)
}

// ── Pool registers ────────────────────────────────────────────────

/// MAC Pool Select Array, low word: pools 0..31 for RAR `rar`.
pub fn mpsar_lo(rar: usize) -> u64 {
    0x0A600 + 8 * rar as u64
}

/// MAC Pool Select Array, high word: pools 32..63 for RAR `rar`.
pub fn mpsar_hi(rar: usize) -> u64 {
    0x0A604 + 8 * rar as u64
}

/// VLAN Filter, entry `i` (64 entries).
pub fn vlvf(i: usize) -> u64 {
    0x0F100 + 4 * i as u64
}

/// VLAN Filter Bitmap, word `i` (128 words: 2 per VLVF entry).
pub fn vlvfb(i: usize) -> u64 {
    0x0F200 + 4 * i as u64
}

/// `VLVF` filter-valid bit.
pub const VLVF_VIEN: u32 = 0x8000_0000;
/// `VLVF` VLAN-ID field (bits 11:0).
pub const VLVF_VLANID_MASK: u32 = 0xFFF;
/// `VLVF` entry count.
pub const VLVF_ENTRIES: usize = 64;

/// VM Offload register for VF `vf` (64 entries).
pub fn vmolr(vf: usize) -> u64 {
    0x0F000 + 4 * vf as u64
}

/// `VMOLR` unicast-promiscuous bit.
pub const VMOLR_UPE: u32 = 0x0040_0000;
/// `VMOLR` VLAN-promiscuous bit.
pub const VMOLR_VPE: u32 = 0x0080_0000;
/// `VMOLR` accept-untagged-packets bit.
pub const VMOLR_AUPE: u32 = 0x0100_0000;
/// `VMOLR` accept-packets-in-MTA-table bit.
pub const VMOLR_ROMPE: u32 = 0x0200_0000;
/// `VMOLR` accept-packets-in-UC-table bit.
pub const VMOLR_ROPE: u32 = 0x0400_0000;
/// `VMOLR` accept-broadcast-packets bit.
pub const VMOLR_BAM: u32 = 0x0800_0000;
/// `VMOLR` multicast-promiscuous bit.
pub const VMOLR_MPE: u32 = 0x1000_0000;

/// VM VLAN Insert register for VF `vf` (64 entries).
pub fn vmvir(vf: usize) -> u64 {
    0x08000 + 4 * vf as u64
}

/// `VMVIR` always-use-default-VLAN bit.
pub const VMVIR_VLANA_DEFAULT: u32 = 0x4000_0000;
/// `VMVIR` never-insert-VLAN-tag bit.
pub const VMVIR_VLANA_NEVER: u32 = 0x8000_0000;
/// `VMVIR` QoS (VLAN priority) field shift (bits 15:13).
pub const VMVIR_QOS_SHIFT: u32 = 13;

/// VF Receive Enable, word `i` (2 words cover 64 VFs).
pub fn vfre(i: usize) -> u64 {
    0x051E0 + 4 * i as u64
}

/// VF Transmit Enable, word `i` (2 words cover 64 VFs).
pub fn vfte(i: usize) -> u64 {
    0x08110 + 4 * i as u64
}

/// Queue Drop Enable (single register, write-per-queue).
pub const REG_QDE: u64 = 0x2F04;
/// `QDE` drop-enable bit.
pub const QDE_ENABLE: u32 = 0x1;
/// `QDE` hide-VLAN bit (strip before the VF sees it).
pub const QDE_HIDE_VLAN: u32 = 0x2;
/// `QDE` queue-index field shift (bits 14:8).
pub const QDE_IDX_SHIFT: u32 = 8;
/// `QDE` write-request bit (the write takes effect per queue).
pub const QDE_WRITE: u32 = 0x1_0000;

/// VM Spoof-Count Enable, word `i` (2 words cover 64 VFs).
pub fn vmecm(i: usize) -> u64 {
    0x08790 + 4 * i as u64
}

/// Per-VF TX descriptor control, queue `p` (absolute queue index).
pub fn pvftxdctl(p: usize) -> u64 {
    0x06028 + 0x40 * p as u64
}

/// Per-VF TX descriptor write-back low, queue `p`.
pub fn pvftdwbal(p: usize) -> u64 {
    0x06038 + 0x40 * p as u64
}

/// Per-VF TX descriptor write-back high, queue `p`.
pub fn pvftdwbah(p: usize) -> u64 {
    0x0603C + 0x40 * p as u64
}

/// Receive Address Low for RAR `i` (0..15 at 0x05400, rest at 0x0A200).
pub fn ral(i: usize) -> u64 {
    if i <= 15 {
        0x05400 + 8 * i as u64
    } else {
        0x0A200 + 8 * i as u64
    }
}

/// Receive Address High for RAR `i` (RAL + 4).
pub fn rah(i: usize) -> u64 {
    ral(i) + 4
}

/// `RAH` address-valid bit.
pub const RAH_AV: u32 = 0x8000_0000;

/// VF Reset Event, covering VF `vf` (0x00600 for 0..31, 0x001C0 else).
pub fn vflre(vf: usize) -> u64 {
    if vf < 32 {
        0x00600
    } else {
        0x001C0
    }
}

/// VF Reset Event Clear, word for VF `vf` (write-1-to-clear).
pub fn vflrec(vf: usize) -> u64 {
    0x00700 + 4 * (vf / 32) as u64
}

/// Max Frame Size register (SET_LPE bumps it).
pub const REG_MAXFRS: u64 = 0x04268;
/// `MAXFRS` max-frame-size field mask (bits 31:16).
pub const MAXFRS_MFS_MASK: u32 = 0xFFFF_0000;
/// `MAXFRS` max-frame-size field shift.
pub const MAXFRS_MFS_SHIFT: u32 = 16;
/// Smallest frame `SET_LPE` accepts (`ETH_MIN_MTU`).
pub const MIN_FRAME: u32 = 68;
/// Largest frame `SET_LPE` accepts (`IXGBE_MAX_JUMBO_FRAME_SIZE`).
pub const MAX_JUMBO_FRAME: u32 = 9728;

// ── Mailbox registers ─────────────────────────────────────────────

/// PF mailbox control for VF `vf` (64 entries).
pub fn pfmailbox(vf: usize) -> u64 {
    0x04B00 + 4 * vf as u64
}

/// `PFMAILBOX` initiate-message-send-to-VF bit.
pub const PFMAILBOX_STS: u32 = 0x1;
/// `PFMAILBOX` acknowledge-message-from-VF bit.
pub const PFMAILBOX_ACK: u32 = 0x2;
/// `PFMAILBOX` VF-owns-the-buffer bit.
pub const PFMAILBOX_VFU: u32 = 0x4;
/// `PFMAILBOX` PF-owns-the-buffer bit.
pub const PFMAILBOX_PFU: u32 = 0x8;
/// `PFMAILBOX` reset-VFU bit (VF stuck recovery).
pub const PFMAILBOX_RVFU: u32 = 0x10;

/// PF mailbox message memory for VF `vf` (16 words per VF).
pub fn pfmbmem(vf: usize) -> u64 {
    0x13000 + 64 * vf as u64
}

/// Mailbox VF Interrupt Cause, word for VF `vf`.
pub fn mbvficr(vf: usize) -> u64 {
    0x00710 + 4 * (vf >> 4) as u64
}

/// `MBVFICR` VF-request bit base (shifted by `vf % 16`).
pub const MBVFICR_VFREQ_VF1: u32 = 0x1;
/// `MBVFICR` VF-ack bit base (shifted by `vf % 16`).
pub const MBVFICR_VFACK_VF1: u32 = 0x1_0000;

// ── Mailbox message types + reply marks ───────────────────────────

/// VF requests reset.
pub const VF_RESET: u32 = 0x01;
/// VF requests PF to set its MAC address.
pub const VF_SET_MAC_ADDR: u32 = 0x02;
/// VF requests PF to set a multicast address (NACKed: unimplemented).
pub const VF_SET_MULTICAST: u32 = 0x03;
/// VF requests PF to set a VLAN.
pub const VF_SET_VLAN: u32 = 0x04;
/// VF requests PF to set its max frame (LPE).
pub const VF_SET_LPE: u32 = 0x05;
/// VF requests PF for a unicast filter (add is a no-op, see docs).
pub const VF_SET_MACVLAN: u32 = 0x06;
/// Negotiate the PF/VF API version.
pub const VF_API_NEGOTIATE: u32 = 0x08;
/// Get the VF's queue configuration.
pub const VF_GET_QUEUES: u32 = 0x09;
/// VF requests RETA (NACKed: unimplemented).
pub const VF_GET_RETA: u32 = 0x0A;
/// VF requests the RSS key (NACKed: unimplemented).
pub const VF_GET_RSS_KEY: u32 = 0x0B;
/// VF requests a multicast-mode update (NACKed: unimplemented).
pub const VF_UPDATE_XCAST_MODE: u32 = 0x0C;
/// VF requests an IPsec SA add (NACKed: unimplemented).
pub const VF_IPSEC_ADD: u32 = 0x0D;
/// VF requests an IPsec SA delete (NACKed: unimplemented).
pub const VF_IPSEC_DEL: u32 = 0x0E;
/// VF requests its link state (NACKed: unimplemented).
pub const VF_GET_LINK_STATE: u32 = 0x10;
/// VF requests the PF link status (NACKed: unimplemented).
pub const VF_GET_PF_LINK_STATE: u32 = 0x11;
/// VF negotiates PF features (NACKed: unimplemented).
pub const VF_FEATURES_NEGOTIATE: u32 = 0x12;
/// Reply mark: message acknowledged.
pub const VT_MSGTYPE_ACK: u32 = 0x8000_0000;
/// Reply mark: message not acknowledged.
pub const VT_MSGTYPE_NACK: u32 = 0x4000_0000;
/// Reply mark: clear to send (Linux sets it on every non-RESET reply).
pub const VT_MSGTYPE_CTS: u32 = 0x2000_0000;
/// Message-info field shift (bits 23:16: add flag / filter index).
pub const VT_MSGINFO_SHIFT: u32 = 16;
/// Message-info field mask.
pub const VT_MSGINFO_MASK: u32 = 0xFF << VT_MSGINFO_SHIFT;

/// `GET_QUEUES` reply word: number of TX queues.
pub const VF_TX_QUEUES: usize = 1;
/// `GET_QUEUES` reply word: number of RX queues.
pub const VF_RX_QUEUES: usize = 2;
/// `GET_QUEUES` reply word: VLAN-transport indication.
pub const VF_TRANS_VLAN: usize = 3;
/// `GET_QUEUES` reply word: default queue offset.
pub const VF_DEF_QUEUE: usize = 4;

// ── API versions (`enum ixgbe_pfvf_api_rev` order, 0-based) ───────

/// API 1.0.
pub const API_10: u8 = 0;
/// API 2.0 (Solaris Phase 1 VF driver).
pub const API_20: u8 = 1;
/// API 1.1.
pub const API_11: u8 = 2;
/// API 1.2.
pub const API_12: u8 = 3;
/// API 1.3.
pub const API_13: u8 = 4;
/// API 1.4.
pub const API_14: u8 = 5;
/// API 1.5 (deliberately NOT accepted by `API_NEGOTIATE`, per Linux).
pub const API_15: u8 = 6;
/// API 1.6.
pub const API_16: u8 = 7;
/// API 1.7.
pub const API_17: u8 = 8;

/// API versions `API_NEGOTIATE` accepts (Linux: 10, 11–14, 16, 17).
pub fn api_negotiate_accepted(api: u32) -> bool {
    matches!(api, 0 | 2 | 3 | 4 | 5 | 7 | 8)
}

/// API versions `GET_QUEUES` accepts (Linux: 20, 11–14, 16, 17).
pub fn get_queues_accepted(api: u32) -> bool {
    matches!(api, 1 | 2 | 3 | 4 | 5 | 7 | 8)
}

// ── Pool / VF / queue mapping ─────────────────────────────────────

/// Pool for VF `vf` (pool 0 is the PF's), or `None` past 63 VFs.
pub fn pool_for_vf(vf: usize) -> Option<usize> {
    if vf < MAX_VFS {
        Some(vf + 1)
    } else {
        None
    }
}

/// The two queues (RX and TX share the numbering) of `pool`.
pub fn pool_queues(pool: usize) -> Option<(usize, usize)> {
    if pool < MAX_POOLS {
        Some((2 * pool, 2 * pool + 1))
    } else {
        None
    }
}

/// RAR slot for VF `vf`'s primary MAC (RAR 0 is the PF's).
pub fn primary_rar(vf: usize) -> usize {
    vf + 1
}

/// `QDE` word for `queue`: write-request + index + enable/hide bits.
pub fn qde_word(queue: usize, enable: bool, hide_vlan: bool) -> u32 {
    let mut w = QDE_WRITE | ((queue as u32) << QDE_IDX_SHIFT);
    if enable {
        w |= QDE_ENABLE;
    }
    if hide_vlan {
        w |= QDE_HIDE_VLAN;
    }
    w
}

/// `VT_CTL` word for `default_pool` with replication as given
/// (mirrors Linux: pool field + REPLEN; `VT_ENABLE` unset, see docs).
pub fn vt_ctl_word(default_pool: usize, replication: bool) -> u32 {
    let mut w = (default_pool as u32) << VT_CTL_POOL_SHIFT;
    if replication {
        w |= VT_CTL_REPLEN;
    }
    w
}

/// `MTQC` word for 64-pool VT mode.
pub fn mtqc_vt_word() -> u32 {
    MTQC_VT_ENA | MTQC_64VF
}

// ── Errors ────────────────────────────────────────────────────────

/// `vmdq` operation failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdqError {
    /// Pool index out of range (0..64).
    BadPool,
    /// VF index out of range (0..63).
    BadVf,
    /// RAR index out of range (0..128).
    BadRar,
    /// VLAN ID out of range (0..4095), or an admin-locked VLAN op.
    BadVlan,
    /// No free VLVF slot for a new VLAN.
    NoVlvfSlot,
    /// API version the PF does not accept.
    BadApi,
    /// Invalid VF MAC (zero, or multicast).
    BadMac,
    /// Max frame outside 68..=9728.
    BadFrame,
    /// Mailbox lock not obtained (PFU bit not set on read-back).
    MailboxBusy,
    /// VT mode not enabled (`MTQC` VT_ENA clear) — call
    /// `enable_virtualization` before composing RSS.
    VtNotEnabled,
    /// RSS config not built for exactly `QUEUES_PER_POOL` queues,
    /// or its table names a queue outside the pool.
    BadRssQueues,
}

// ── Configuration ─────────────────────────────────────────────────

/// VT-mode configuration for [`enable_virtualization`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmdqConfig {
    /// Default pool for unmatched frames (`VT_CTL` pool field).
    pub default_pool: usize,
    /// Set `VT_CTL.REPLEN` (replicate unknown-unicast to all pools).
    pub replication: bool,
}

impl VmdqConfig {
    /// The Linux shape: default pool 0, replication on.
    pub const fn standard() -> Self {
        Self {
            default_pool: 0,
            replication: true,
        }
    }

    /// A custom default pool / replication setting.
    pub fn new(default_pool: usize, replication: bool) -> Result<Self, VmdqError> {
        let cfg = Self {
            default_pool,
            replication,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate before any register is touched.
    pub fn validate(&self) -> Result<(), VmdqError> {
        if self.default_pool >= MAX_POOLS {
            return Err(VmdqError::BadPool);
        }
        Ok(())
    }
}

// ── VT-mode enable ────────────────────────────────────────────────

/// Enable VT mode: 64 pools x 2 queues, default pool + replication,
/// VEB switching. Validates before touching any register. The PF's
/// own rings stay where bring-up put them (pool 0, queues 0/1);
/// enabling VT does not move them — pool 0 is the PF's pool, and
/// VF `i` owns pool `i+1`.
pub fn enable_virtualization(bank: &mut impl RegBank, cfg: &VmdqConfig) -> Result<(), VmdqError> {
    cfg.validate()?;
    // 1. TX pool layout: disable the arbiter, program MTQC, re-enable
    // (ixgbe_setup_mtqc). The SECTXMINIFG step is DCB-only; skipped.
    let rttdcs = bank.read32(REG_RTTDCS);
    bank.write32(REG_RTTDCS, rttdcs | RTTDCS_ARBDIS);
    bank.write32(REG_MTQC, mtqc_vt_word());
    bank.write32(REG_RTTDCS, rttdcs & !RTTDCS_ARBDIS);
    // 2. RX mode: 64 pools, no RSS (MRQE field only). Value VMDQEN
    // (0x8), not Linux's SR-IOV value VMDQRSS64EN (0xB): Linux always
    // pairs RSS, NARF programs no RSS here — see module docs.
    let mrqc = bank.read32(REG_MRQC);
    bank.write32(REG_MRQC, (mrqc & !MRQC_MRQE_MASK) | MRQC_VMDQEN);
    // 3. Default pool + replication (ixgbe_main.c VT_CTL programming).
    let vt = (bank.read32(REG_VT_CTL) & !VT_CTL_POOL_MASK)
        | vt_ctl_word(cfg.default_pool, cfg.replication);
    bank.write32(REG_VT_CTL, vt);
    // 4. VEB switching: VF-to-VF traffic stays on the device
    // (ixgbe_enable_sriov writes the constant directly).
    bank.write32(REG_PFDTXGSWC, PFDTXGSWC_VT_LBEN);
    Ok(())
}

// ── VT-mode RSS composition ───────────────────────────────────────

/// Enable RSS inside VT mode (MRQE 0xB, 64 pools + RSS): program
/// the shared RSS key + the per-pool indirection table, bound the
/// table per pool, then switch `MRQC` from `VMDQEN` (0x8) to
/// `VMDQRSS64EN` (0xB) with the hash fields on. Call after
/// [`enable_virtualization`]; callers must have RX disabled while
/// reprogramming filters.
///
/// The 82599 has ONE redirection table for the whole device
/// (datasheet §4.6.10.1.1: "the redirection table is common to
/// all the pools and only indicates the queue inside the pool to
/// use once the pool is chosen"; Table 7.4 indexes a queue as
/// pool + RSS bit). `rss` must therefore be a
/// [`QUEUES_PER_POOL`]-queue config (`IxgbeRss::standard(2)`):
/// each RETA entry is the queue offset *within* the pool, and an
/// entry >= 2 would steer into the next pool's queues. The
/// per-pool `PSRTYPE` RQPL field (Linux `ixgbe_setup_psrtype`)
/// bounds the lookup to the pool's queue subset; the X550
/// per-pool registers (`PFVFMRQC` / `PFVFRETA` / `PFVFRSSRK`)
/// do not exist on 82599 and are not programmed.
///
/// Validates everything before touching any register: VT mode
/// must be enabled, the config must be 2-queue, and every table
/// entry must be in-pool. Write order mirrors Linux
/// `ixgbe_setup_mrqc` (key + RETA first, `MRQC` last).
pub fn enable_vmdq_rss(bank: &mut impl RegBank, rss: &IxgbeRss) -> Result<(), VmdqError> {
    if bank.read32(REG_MTQC) & MTQC_VT_ENA == 0 {
        return Err(VmdqError::VtNotEnabled);
    }
    if rss.queues != QUEUES_PER_POOL || rss.table.iter().any(|&e| e as usize >= QUEUES_PER_POOL) {
        return Err(VmdqError::BadRssQueues);
    }
    for (n, w) in rssrk_words(&rss.key).iter().enumerate() {
        bank.write32(REG_RSSRK_BASE + 4 * n as u64, *w);
    }
    for (n, w) in reta_words(&rss.table).iter().enumerate() {
        bank.write32(REG_RETA_BASE + 4 * n as u64, *w);
    }
    for pool in 0..MAX_POOLS {
        bank.write32(psrtype(pool), psrtype_word(QUEUES_PER_POOL));
    }
    let mrqc = bank.read32(REG_MRQC);
    bank.write32(
        REG_MRQC,
        (mrqc & !MRQC_MRQE_MASK) | MRQE_VMDQ_64_RSS | MRQC_HASH_FIELDS,
    );
    Ok(())
}

// ── RAR / MPSAR ───────────────────────────────────────────────────

/// Add `pool` to RAR `rar`'s pool bitmap (OR semantics, per
/// `ixgbe_set_vmdq_generic`).
pub fn assign_rar_pool(bank: &mut impl RegBank, rar: usize, pool: usize) -> Result<(), VmdqError> {
    if rar >= RAR_ENTRIES {
        return Err(VmdqError::BadRar);
    }
    if pool >= MAX_POOLS {
        return Err(VmdqError::BadPool);
    }
    if pool < 32 {
        let reg = mpsar_lo(rar);
        bank.write32(reg, bank.read32(reg) | (1u32 << pool));
    } else {
        let reg = mpsar_hi(rar);
        bank.write32(reg, bank.read32(reg) | (1u32 << (pool - 32)));
    }
    Ok(())
}

/// Remove `pool` from RAR `rar`'s pool bitmap.
pub fn clear_rar_pool(bank: &mut impl RegBank, rar: usize, pool: usize) -> Result<(), VmdqError> {
    if rar >= RAR_ENTRIES {
        return Err(VmdqError::BadRar);
    }
    if pool >= MAX_POOLS {
        return Err(VmdqError::BadPool);
    }
    if pool < 32 {
        let reg = mpsar_lo(rar);
        bank.write32(reg, bank.read32(reg) & !(1u32 << pool));
    } else {
        let reg = mpsar_hi(rar);
        bank.write32(reg, bank.read32(reg) & !(1u32 << (pool - 32)));
    }
    Ok(())
}

/// True when RAR `rar`'s bitmap contains `pool`.
pub fn rar_has_pool(bank: &impl RegBank, rar: usize, pool: usize) -> bool {
    if rar >= RAR_ENTRIES || pool >= MAX_POOLS {
        return false;
    }
    if pool < 32 {
        bank.read32(mpsar_lo(rar)) & (1u32 << pool) != 0
    } else {
        bank.read32(mpsar_hi(rar)) & (1u32 << (pool - 32)) != 0
    }
}

/// True when RAR `rar` is address-valid.
pub fn rar_enabled(bank: &impl RegBank, rar: usize) -> bool {
    if rar >= RAR_ENTRIES {
        return false;
    }
    bank.read32(rah(rar)) & RAH_AV != 0
}

/// Program RAR `rar` with `mac` for `pool`, address-valid iff
/// `enable`. Pool selection goes first, then RAL, then RAH — the
/// Linux `ixgbe_set_rar_generic` order (a RAR must never be valid
/// before its pool is selected).
pub fn program_rar(
    bank: &mut impl RegBank,
    rar: usize,
    mac: &[u8; 6],
    pool: usize,
    enable: bool,
) -> Result<(), VmdqError> {
    if rar >= RAR_ENTRIES {
        return Err(VmdqError::BadRar);
    }
    assign_rar_pool(bank, rar, pool)?;
    let lo = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    bank.write32(ral(rar), lo);
    let reg = rah(rar);
    let mut hi = bank.read32(reg) & !(0xFFFF | RAH_AV);
    hi |= mac[4] as u32 | ((mac[5] as u32) << 8);
    if enable {
        hi |= RAH_AV;
    }
    bank.write32(reg, hi);
    Ok(())
}

/// Clear RAR `rar`'s address-valid bit (MAC bytes preserved, per
/// `ixgbe_clear_rar_generic`).
pub fn clear_rar(bank: &mut impl RegBank, rar: usize) -> Result<(), VmdqError> {
    if rar >= RAR_ENTRIES {
        return Err(VmdqError::BadRar);
    }
    let reg = rah(rar);
    bank.write32(reg, bank.read32(reg) & !RAH_AV);
    Ok(())
}

/// Read RAR `rar` back: (MAC bytes, address-valid).
pub fn read_rar(bank: &impl RegBank, rar: usize) -> ([u8; 6], bool) {
    if rar >= RAR_ENTRIES {
        return ([0; 6], false);
    }
    let lo = bank.read32(ral(rar)).to_le_bytes();
    let hi = bank.read32(rah(rar));
    let mac = [
        lo[0],
        lo[1],
        lo[2],
        lo[3],
        (hi & 0xFF) as u8,
        ((hi >> 8) & 0xFF) as u8,
    ];
    (mac, hi & RAH_AV != 0)
}

// ── Pool VLANs (VLVF / VLVFB / VFTA) ───────────────────────────────

/// Find the VLVF slot for `vlan`: VLAN 0 always maps to slot 0;
/// otherwise an exact match, else the highest empty slot (Linux
/// `ixgbe_find_vlvf_slot` scans 63..1 and keeps the first empty it
/// sees). `None` when the table is full.
pub fn find_vlvf_slot(bank: &impl RegBank, vlan: u16) -> Option<usize> {
    if vlan == 0 {
        return Some(0);
    }
    let want = VLVF_VIEN | vlan as u32;
    let mut first_empty = None;
    for i in (1..VLVF_ENTRIES).rev() {
        let bits = bank.read32(vlvf(i));
        if bits == want {
            return Some(i);
        }
        if first_empty.is_none() && bits == 0 {
            first_empty = Some(i);
        }
    }
    first_empty
}

/// Find the slot that already holds `vlan` exactly, if any.
pub fn find_vlvf_exact(bank: &impl RegBank, vlan: u16) -> Option<usize> {
    let want = VLVF_VIEN | vlan as u32;
    if vlan == 0 {
        return if bank.read32(vlvf(0)) == want {
            Some(0)
        } else {
            None
        };
    }
    (1..VLVF_ENTRIES)
        .rev()
        .find(|&i| bank.read32(vlvf(i)) == want)
}

/// Add `pool` to `vlan`'s pool set: allocate a VLVF slot if needed,
/// set the pool's VLVFB bit, write the slot valid, and set the
/// VLAN's VFTA bit (additive OR; see module docs for the VFTA
/// composition rule).
pub fn set_pool_vlan(bank: &mut impl RegBank, vlan: u16, pool: usize) -> Result<(), VmdqError> {
    if vlan > 4095 {
        return Err(VmdqError::BadVlan);
    }
    if pool >= MAX_POOLS {
        return Err(VmdqError::BadPool);
    }
    let slot = find_vlvf_slot(bank, vlan).ok_or(VmdqError::NoVlvfSlot)?;
    let fb_reg = vlvfb(slot * 2 + pool / 32);
    bank.write32(fb_reg, bank.read32(fb_reg) | (1u32 << (pool % 32)));
    bank.write32(vlvf(slot), VLVF_VIEN | vlan as u32);
    let vfta_reg = REG_VFTA_BASE + 4 * (vlan as u64 / 32);
    bank.write32(vfta_reg, bank.read32(vfta_reg) | (1u32 << (vlan % 32)));
    Ok(())
}

/// Remove `pool` from `vlan`'s pool set. Errors when the VLAN has no
/// VLVF entry (mirrors Linux: clearing an absent VLAN fails). When
/// the slot's last pool leaves, the slot itself is disabled. VFTA
/// is deliberately untouched (see module docs).
pub fn clear_pool_vlan(bank: &mut impl RegBank, vlan: u16, pool: usize) -> Result<(), VmdqError> {
    if vlan > 4095 {
        return Err(VmdqError::BadVlan);
    }
    if pool >= MAX_POOLS {
        return Err(VmdqError::BadPool);
    }
    let slot = find_vlvf_exact(bank, vlan).ok_or(VmdqError::NoVlvfSlot)?;
    let fb_reg = vlvfb(slot * 2 + pool / 32);
    bank.write32(fb_reg, bank.read32(fb_reg) & !(1u32 << (pool % 32)));
    // Disable the slot only when both bitmap words are empty.
    if bank.read32(vlvfb(slot * 2)) == 0 && bank.read32(vlvfb(slot * 2 + 1)) == 0 {
        bank.write32(vlvf(slot), 0);
    }
    Ok(())
}

/// Remove `pool` from every VLAN it belongs to (RESET path). Slots
/// that end up empty are disabled. Never errors: entries without
/// the pool's bit are skipped.
pub fn clear_all_pool_vlans(bank: &mut impl RegBank, pool: usize) {
    if pool >= MAX_POOLS {
        return;
    }
    for slot in 0..VLVF_ENTRIES {
        if bank.read32(vlvf(slot)) & VLVF_VIEN == 0 {
            continue;
        }
        let fb_reg = vlvfb(slot * 2 + pool / 32);
        let bits = bank.read32(fb_reg) & !(1u32 << (pool % 32));
        bank.write32(fb_reg, bits);
        if bank.read32(vlvfb(slot * 2)) == 0 && bank.read32(vlvfb(slot * 2 + 1)) == 0 {
            bank.write32(vlvf(slot), 0);
        }
    }
}

// ── Per-VF pool state (VMOLR / VMVIR / VFRE / VFTE / QDE / VMECM) ──

/// Program VF `vf`'s offload register: broadcast always accepted,
/// untagged accepted iff `aupe` (mirror `ixgbe_set_vmolr`).
pub fn set_vmolr(bank: &mut impl RegBank, vf: usize, aupe: bool) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let reg = vmolr(vf);
    let mut w = bank.read32(reg) | VMOLR_BAM;
    if aupe {
        w |= VMOLR_AUPE;
    } else {
        w &= !VMOLR_AUPE;
    }
    bank.write32(reg, w);
    Ok(())
}

/// Program VF `vf`'s VLAN-insert register: tag `vid` with `qos`,
/// always using the default VLAN (mirror `ixgbe_set_vmvir`).
pub fn set_vmvir(bank: &mut impl RegBank, vf: usize, vid: u16, qos: u16) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let w = (vid as u32) | ((qos as u32) << VMVIR_QOS_SHIFT) | VMVIR_VLANA_DEFAULT;
    bank.write32(vmvir(vf), w);
    Ok(())
}

/// Clear VF `vf`'s VLAN-insert register (mirror `ixgbe_clear_vmvir`).
pub fn clear_vmvir(bank: &mut impl RegBank, vf: usize) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    bank.write32(vmvir(vf), 0);
    Ok(())
}

/// Enable or disable VF `vf`'s receive + transmit (VFRE/VFTE bits,
/// mirror `ixgbe_set_vf_rx_tx` without the commented-out jumbo rule).
pub fn set_vf_rx_tx(bank: &mut impl RegBank, vf: usize, enable: bool) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let (reg_i, bit) = (vf / 32, 1u32 << (vf % 32));
    let rx_reg = vfre(reg_i);
    let tx_reg = vfte(reg_i);
    if enable {
        bank.write32(rx_reg, bank.read32(rx_reg) | bit);
        bank.write32(tx_reg, bank.read32(tx_reg) | bit);
    } else {
        bank.write32(rx_reg, bank.read32(rx_reg) & !bit);
        bank.write32(tx_reg, bank.read32(tx_reg) & !bit);
    }
    Ok(())
}

/// Program drop-enable for every queue of `pool` (QDE writes are
/// per-queue through the single QDE register).
pub fn set_pool_queue_drop(
    bank: &mut impl RegBank,
    pool: usize,
    enable: bool,
    hide_vlan: bool,
) -> Result<(), VmdqError> {
    let (q0, q1) = pool_queues(pool).ok_or(VmdqError::BadPool)?;
    bank.write32(REG_QDE, qde_word(q0, enable, hide_vlan));
    bank.write32(REG_QDE, qde_word(q1, enable, hide_vlan));
    Ok(())
}

/// Enable or disable spoofed-packet counting for VF `vf` (VMECM bit).
pub fn set_spoof_count(bank: &mut impl RegBank, vf: usize, enable: bool) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let reg = vmecm(vf / 32);
    let bit = 1u32 << (vf % 32);
    if enable {
        bank.write32(reg, bank.read32(reg) | bit);
    } else {
        bank.write32(reg, bank.read32(reg) & !bit);
    }
    Ok(())
}

/// Zero the TX descriptor write-back addresses of `pool`'s queues
/// (FLR does not clear them — mirror `ixgbe_vf_reset_msg`).
pub fn reset_vf_tx_addrs(bank: &mut impl RegBank, pool: usize) -> Result<(), VmdqError> {
    let (q0, q1) = pool_queues(pool).ok_or(VmdqError::BadPool)?;
    bank.write32(pvftdwbal(q0), 0);
    bank.write32(pvftdwbah(q0), 0);
    bank.write32(pvftdwbal(q1), 0);
    bank.write32(pvftdwbah(q1), 0);
    Ok(())
}

/// True when the hardware raised a reset event for VF `vf` (VFLRE).
pub fn vf_reset_pending(bank: &impl RegBank, vf: usize) -> bool {
    if vf >= MAX_VFS {
        return false;
    }
    bank.read32(vflre(vf)) & (1u32 << (vf % 32)) != 0
}

/// Acknowledge (write-1-to-clear) VF `vf`'s reset event.
pub fn clear_vf_reset_event(bank: &mut impl RegBank, vf: usize) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    bank.write32(vflrec(vf), 1u32 << (vf % 32));
    Ok(())
}

// ── Mailbox transport (PF side) ───────────────────────────────────

/// Take ownership of VF `vf`'s mailbox buffer: write PFU, read back,
/// require PFU set (mirror `ixgbe_obtain_mbx_lock_pf`).
pub fn mailbox_lock(bank: &mut impl RegBank, vf: usize) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let reg = pfmailbox(vf);
    bank.write32(reg, PFMAILBOX_PFU);
    if bank.read32(reg) & PFMAILBOX_PFU != 0 {
        Ok(())
    } else {
        Err(VmdqError::MailboxBusy)
    }
}

/// Write `msg` into VF `vf`'s mailbox and ring the VF (STS bit).
/// At most the 16-word buffer is written; longer messages are
/// truncated to it. Callers pass 4 (RESET reply) or 16 words.
pub fn mailbox_write(bank: &mut impl RegBank, vf: usize, msg: &[u32]) -> Result<(), VmdqError> {
    mailbox_lock(bank, vf)?;
    let base = pfmbmem(vf);
    for (i, w) in msg.iter().take(MBX_WORDS).enumerate() {
        bank.write32(base + 4 * i as u64, *w);
    }
    bank.write32(pfmailbox(vf), PFMAILBOX_STS);
    Ok(())
}

/// Read `out.len()` words (capped at the 16-word buffer) from VF
/// `vf`'s mailbox and acknowledge (ACK bit).
pub fn mailbox_read(bank: &mut impl RegBank, vf: usize, out: &mut [u32]) -> Result<(), VmdqError> {
    mailbox_lock(bank, vf)?;
    let base = pfmbmem(vf);
    for (i, slot) in out.iter_mut().take(MBX_WORDS).enumerate() {
        *slot = bank.read32(base + 4 * i as u64);
    }
    bank.write32(pfmailbox(vf), PFMAILBOX_ACK);
    Ok(())
}

/// Zero VF `vf`'s mailbox memory without taking the lock (mirror
/// `ixgbe_vf_clear_mbx`, used on the RESET path).
pub fn mailbox_clear(bank: &mut impl RegBank, vf: usize) -> Result<(), VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let base = pfmbmem(vf);
    for i in 0..MBX_WORDS {
        bank.write32(base + 4 * i as u64, 0);
    }
    Ok(())
}

/// True when VF `vf` has set its mailbox-request bit (MBVFICR).
pub fn mailbox_has_msg(bank: &impl RegBank, vf: usize) -> bool {
    if vf >= MAX_VFS {
        return false;
    }
    bank.read32(mbvficr(vf)) & (MBVFICR_VFREQ_VF1 << (vf % 16)) != 0
}

/// True when VF `vf` has set its mailbox-ack bit (MBVFICR).
pub fn mailbox_has_ack(bank: &impl RegBank, vf: usize) -> bool {
    if vf >= MAX_VFS {
        return false;
    }
    bank.read32(mbvficr(vf)) & (MBVFICR_VFACK_VF1 << (vf % 16)) != 0
}

// ── VF state ──────────────────────────────────────────────────────

/// Per-VF PF-side state for the mailbox dispatcher. Mirrors the
/// fields of Linux's `vf_data_storage` that this dispatcher uses;
/// `pf_vlan`/`pf_qos` administration (ndo_set_vf_vlan) is not wired
/// yet, so `pf_vlan` is set only by RESET's add-back of a stored
/// value — today always 0 unless a future admin path sets it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfState {
    /// VF's primary MAC, once set (by RESET's add-back or SET_MAC).
    pub mac: [u8; 6],
    /// True once `mac` holds a real address.
    pub mac_set: bool,
    /// True when the PF administrator pinned the MAC (SET_MAC from
    /// an untrusted VF with a different MAC is then refused).
    pub pf_set_mac: bool,
    /// Trusted VF (may override an admin-pinned MAC).
    pub trusted: bool,
    /// Negotiated API version (`API_*`, default 1.0).
    pub api: u8,
    /// PF-assigned VLAN (0 = none): drives VMOLR AUPE, QDE
    /// HIDE_VLAN, VMVIR, and the SET_VLAN admin lock.
    pub pf_vlan: u16,
    /// Link enabled (Linux defaults every VF to enabled).
    pub link_enable: bool,
    /// Set true by RESET; the dispatch gate that would read it is
    /// commented out in Linux (see module docs).
    pub clear_to_send: bool,
}

impl VfState {
    /// Fresh VF state: no MAC, API 1.0, link enabled.
    pub const fn new() -> Self {
        Self {
            mac: [0; 6],
            mac_set: false,
            pf_set_mac: false,
            trusted: false,
            api: API_10,
            pf_vlan: 0,
            link_enable: true,
            clear_to_send: false,
        }
    }
}

// NOTE: manual `Default`, not derived: the derive would set
// `link_enable` false, but Linux enables every VF's link on
// SR-IOV setup, so the default here is true.
impl Default for VfState {
    fn default() -> Self {
        Self::new()
    }
}

/// All VF states, indexed by VF number.
pub struct VfTable {
    /// One entry per VF (0..63).
    pub vfs: [VfState; MAX_VFS],
}

impl VfTable {
    /// Fresh table: every VF in its default state.
    pub const fn new() -> Self {
        Self {
            vfs: [VfState::new(); MAX_VFS],
        }
    }
}

// NOTE: no `#[derive(Default)]` — on the pinned toolchain, arrays
// implement `Default` only up to 32 elements, and this table holds
// 63. Do not re-add the derive (see the `[u32; 128]` precedent).
impl Default for VfTable {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VfTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VfTable")
            .field("vfs_len", &self.vfs.len())
            .finish_non_exhaustive()
    }
}

// ── PF/VF message dispatcher ──────────────────────────────────────

/// Outcome of [`dispatch_vf_message`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Message already carried ACK/NACK: ignored, nothing written.
    Ignored,
    /// A reply was written to the VF's mailbox.
    Replied,
}

/// True for a valid unicast Ethernet address (non-zero, not
/// multicast — Linux `is_valid_ether_addr`).
pub fn is_valid_ether_addr(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && mac[0] & 1 == 0
}

/// Split a mailbox message's MAC bytes (words 1–2, little-endian).
fn msg_mac(msg: &[u32; MBX_WORDS]) -> [u8; 6] {
    let lo = msg[1].to_le_bytes();
    let hi = msg[2].to_le_bytes();
    [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]]
}

/// Pack a MAC into mailbox words 1–2 (little-endian).
fn pack_mac(mac: &[u8; 6]) -> (u32, u32) {
    let lo = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let hi = mac[4] as u32 | ((mac[5] as u32) << 8);
    (lo, hi)
}

/// Dispatch one already-read VF message (16 words), mirroring
/// `ixgbe_rcv_msg_from_vf`: already-ACK/NACK messages are ignored;
/// RESET takes its own 4-word reply path; every other type gets the
/// full 16-word buffer back with ACK/NACK + CTS. `vf` must be
/// < 63; anything else is `BadVf` before any bank access.
pub fn dispatch_vf_message(
    bank: &mut impl RegBank,
    table: &mut VfTable,
    vf: usize,
    msg: &[u32; MBX_WORDS],
) -> Result<DispatchOutcome, VmdqError> {
    if vf >= MAX_VFS {
        return Err(VmdqError::BadVf);
    }
    let pool = pool_for_vf(vf).ok_or(VmdqError::BadVf)?;
    let word0 = msg[0];
    // Already processed: do nothing (Linux early-returns here).
    if word0 & (VT_MSGTYPE_ACK | VT_MSGTYPE_NACK) != 0 {
        return Ok(DispatchOutcome::Ignored);
    }
    if word0 == VF_RESET {
        let st = &mut table.vfs[vf];
        match reset_vf(bank, st, vf, pool) {
            Ok(()) => return Ok(DispatchOutcome::Replied),
            Err(e) => {
                // A failed reset must still answer, or the VF hangs
                // on a half-programmed state; retries are idempotent.
                let nack = [VF_RESET | VT_MSGTYPE_NACK, 0, 0, 0];
                mailbox_write(bank, vf, &nack)?;
                return Err(e);
            }
        }
    }
    let mut reply = *msg;
    let st = &mut table.vfs[vf];
    let result = match word0 & 0xFFFF {
        VF_SET_MAC_ADDR => set_vf_mac_msg(bank, st, vf, pool, msg),
        VF_SET_VLAN => set_vf_vlan_msg(bank, st, pool, msg),
        VF_SET_LPE => set_vf_lpe_msg(bank, msg),
        VF_SET_MACVLAN => set_vf_macvlan_msg(bank, st, vf, pool, msg),
        VF_API_NEGOTIATE => negotiate_api_msg(st, msg),
        VF_GET_QUEUES => get_vf_queues_msg(st, &mut reply),
        _ => Err(VmdqError::BadApi),
    };
    reply[0] = word0
        | if result.is_ok() {
            VT_MSGTYPE_ACK
        } else {
            VT_MSGTYPE_NACK
        }
        | VT_MSGTYPE_CTS;
    mailbox_write(bank, vf, &reply)?;
    Ok(DispatchOutcome::Replied)
}

/// RESET path (mirror `ixgbe_vf_reset_msg`): clear the VF's VLANs,
/// add back its PF VLAN (or VLAN 0), reset offloads to defaults,
/// clear the mailbox, restore the primary MAC, enable QDE + RX/TX,
/// enable spoof counting, clear TX write-back addresses, reset the
/// API to 1.0, and reply with 4 words: RESET | ACK/NACK, the MAC
/// (only when the PF pinned one), and the multicast-type word (0,
/// Linux's zero-init default).
fn reset_vf(
    bank: &mut impl RegBank,
    st: &mut VfState,
    vf: usize,
    pool: usize,
) -> Result<(), VmdqError> {
    clear_all_pool_vlans(bank, pool);
    set_pool_vlan(bank, st.pf_vlan, pool)?;
    set_vmolr(bank, vf, st.pf_vlan == 0)?;
    // NARF has no pf_qos / traffic classes: a PF VLAN means tag it,
    // no PF VLAN means clear the insert register (Linux: clear when
    // !pf_vlan && !pf_qos && !tcs, else set).
    if st.pf_vlan == 0 {
        clear_vmvir(bank, vf)?;
    } else {
        set_vmvir(bank, vf, st.pf_vlan, 0)?;
    }
    mailbox_clear(bank, vf)?;
    if st.mac_set {
        program_rar(bank, primary_rar(vf), &st.mac, pool, true)?;
    }
    set_pool_queue_drop(bank, pool, true, st.pf_vlan != 0)?;
    set_vf_rx_tx(bank, vf, st.link_enable)?;
    set_spoof_count(bank, vf, true)?;
    reset_vf_tx_addrs(bank, pool)?;
    st.api = API_10;
    st.clear_to_send = true;
    let mut reply = [0u32; PERMADDR_MSG_LEN];
    if st.mac_set && st.pf_set_mac {
        let (lo, hi) = pack_mac(&st.mac);
        reply[0] = VF_RESET | VT_MSGTYPE_ACK;
        reply[1] = lo;
        reply[2] = hi;
    } else {
        reply[0] = VF_RESET | VT_MSGTYPE_NACK;
    }
    reply[3] = 0;
    mailbox_write(bank, vf, &reply)?;
    Ok(())
}

/// `SET_MAC_ADDR`: validate, honor the admin pin, program the
/// primary-MAC RAR slot (mirror `ixgbe_set_vf_mac_addr`).
fn set_vf_mac_msg(
    bank: &mut impl RegBank,
    st: &mut VfState,
    vf: usize,
    pool: usize,
    msg: &[u32; MBX_WORDS],
) -> Result<(), VmdqError> {
    let mac = msg_mac(msg);
    if !is_valid_ether_addr(&mac) {
        return Err(VmdqError::BadMac);
    }
    if st.pf_set_mac && !st.trusted && st.mac_set && st.mac != mac {
        return Err(VmdqError::BadMac);
    }
    program_rar(bank, primary_rar(vf), &mac, pool, true)?;
    st.mac = mac;
    st.mac_set = true;
    Ok(())
}

/// `SET_VLAN`: add flag from the msginfo field, VID from word 1
/// (mirror `ixgbe_set_vf_vlan_msg`). A PF-assigned VLAN locks the
/// VF out; removing VLAN 0 is a no-op (Linux special case).
fn set_vf_vlan_msg(
    bank: &mut impl RegBank,
    st: &VfState,
    pool: usize,
    msg: &[u32; MBX_WORDS],
) -> Result<(), VmdqError> {
    let add = (msg[0] & VT_MSGINFO_MASK) >> VT_MSGINFO_SHIFT != 0;
    let vid = (msg[1] & VLVF_VLANID_MASK) as u16;
    if st.pf_vlan != 0 {
        return Err(VmdqError::BadVlan);
    }
    if vid == 0 && !add {
        return Ok(());
    }
    if add {
        set_pool_vlan(bank, vid, pool)
    } else {
        clear_pool_vlan(bank, vid, pool)
    }
}

/// `SET_LPE`: validate the range, bump `MAXFRS` if the VF asks for
/// more (mirror `ixgbe_set_vf_lpe`'s active tail).
fn set_vf_lpe_msg(bank: &mut impl RegBank, msg: &[u32; MBX_WORDS]) -> Result<(), VmdqError> {
    let max_frame = msg[1];
    if !(MIN_FRAME..=MAX_JUMBO_FRAME).contains(&max_frame) {
        return Err(VmdqError::BadFrame);
    }
    let cur = bank.read32(REG_MAXFRS);
    let cur_mfs = (cur & MAXFRS_MFS_MASK) >> MAXFRS_MFS_SHIFT;
    if cur_mfs < max_frame {
        bank.write32(REG_MAXFRS, max_frame << MAXFRS_MFS_SHIFT);
    }
    Ok(())
}

/// `SET_MACVLAN` (mirror `ixgbe_set_vf_macvlan_msg`'s ACTIVE code):
/// an admin-pinned MAC refuses index > 0 for untrusted VFs; index
/// <= 1 deletes this VF's extra filters (RAR scan, primary slot
/// preserved); index > 1 is a success no-op because Linux's add
/// path is commented out (see module docs).
fn set_vf_macvlan_msg(
    bank: &mut impl RegBank,
    st: &VfState,
    vf: usize,
    pool: usize,
    msg: &[u32; MBX_WORDS],
) -> Result<(), VmdqError> {
    let index = ((msg[0] & VT_MSGINFO_MASK) >> VT_MSGINFO_SHIFT) as usize;
    if st.pf_set_mac && !st.trusted && index > 0 {
        return Err(VmdqError::BadMac);
    }
    if index <= 1 {
        let primary = primary_rar(vf);
        for rar in 1..RAR_ENTRIES {
            if rar == primary || !rar_enabled(bank, rar) || !rar_has_pool(bank, rar, pool) {
                continue;
            }
            clear_rar(bank, rar)?;
            clear_rar_pool(bank, rar, pool)?;
        }
    }
    Ok(())
}

/// `API_NEGOTIATE`: record the version iff Linux accepts it.
fn negotiate_api_msg(st: &mut VfState, msg: &[u32; MBX_WORDS]) -> Result<(), VmdqError> {
    let api = msg[1];
    if !api_negotiate_accepted(api) {
        return Err(VmdqError::BadApi);
    }
    st.api = api as u8;
    Ok(())
}

/// `GET_QUEUES`: fill the reply's queue words (mirror
/// `ixgbe_get_vf_queues` with no traffic classes and no PF QoS:
/// transport-VLAN is 1 iff the VF has a PF VLAN).
fn get_vf_queues_msg(st: &VfState, reply: &mut [u32; MBX_WORDS]) -> Result<(), VmdqError> {
    if !get_queues_accepted(st.api as u32) {
        return Err(VmdqError::BadApi);
    }
    reply[VF_TX_QUEUES] = QUEUES_PER_POOL as u32;
    reply[VF_RX_QUEUES] = QUEUES_PER_POOL as u32;
    reply[VF_TRANS_VLAN] = if st.pf_vlan != 0 { 1 } else { 0 };
    reply[VF_DEF_QUEUE] = 0;
    Ok(())
}

// ── Mailbox interrupt pump ────────────────────────────────────────

/// Outcome of one [`mailbox_pump_step`]: which VFs had a message
/// dispatched, an ack consumed, or a reset event processed. Bit
/// `vf` set = VF `vf` took that path (63 VFs need a `u64` mask;
/// the igb pump's `u8` mask only covers its 8 VFs).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MailboxPumpOutcome {
    /// VFs whose pending message was read and dispatched (reply
    /// written, or ignored as already-ACK/NACK).
    pub msgs: u64,
    /// VFs whose VFACK bit was consumed (never dispatched: the PF
    /// sends no PF-initiated messages, so there is nothing for a
    /// VF ack to match).
    pub acks: u64,
    /// VFs whose VFLRE reset event was cleared.
    pub resets: u64,
}

impl MailboxPumpOutcome {
    /// No VF took any path.
    pub const fn is_empty(&self) -> bool {
        self.msgs == 0 && self.acks == 0 && self.resets == 0
    }
}

/// Run one mailbox-pump pass (Linux `ixgbe_msg_task`, as reached
/// from the misc vector's `EICR_MAILBOX` cause): consume MBVFICR /
/// VFLRE, dispatch each pending VF message through
/// [`dispatch_vf_message`], and write the reply back.
///
/// Per VF, in Linux's order: reset event, message, ack.
/// * Reset: `VFLRE` is cleared via `VFLREC` (Linux
///   `ixgbe_check_for_rst_pf`) and counted. It mutates no VF
///   state: the VF's RESET *message* owns the state reset (the
///   dispatcher RESET path), and an FLR always precedes one.
/// * Message: the request bit is cleared write-1-to-clear (Linux
///   `ixgbe_check_for_bit_pf` writes the mask back to the same
///   `MBVFICR` word), the message is read with [`mailbox_read`],
///   and [`dispatch_vf_message`] writes the reply. A message the
///   mailbox lock refuses is dropped with its bit already
///   cleared, exactly Linux's check-then-read order; a message
///   already carrying ACK/NACK still counts as dispatched
///   (`Ignored` — the pending request was consumed, nothing
///   further is owed).
/// * Ack: the ack bit is cleared write-1-to-clear (Linux
///   `ixgbe_check_for_ack_pf`) and counted, never dispatched.
///
/// Polled, not interrupt-driven: this driver has no ISR yet (the
/// datapath is polled), so the driver's 10 ms watchdog tick calls
/// this. The interrupt routing — `EICR_MAILBOX` on the misc
/// vector — is a follow-up: the cause's name and delivery path
/// (`ixgbe_msix_lsc` → `ixgbe_msg_task`) are verified against
/// Linux, but its numeric bit was not verifiable against Linux
/// ixgbe @ cbbddb6 from the sources available, so no cause bit
/// is programmed here. `num_vfs` bounds the scan (clamped to
/// [`MAX_VFS`]); VFs past it are never touched.
pub fn mailbox_pump_step(
    bank: &mut impl RegBank,
    table: &mut VfTable,
    num_vfs: usize,
) -> MailboxPumpOutcome {
    let mut outcome = MailboxPumpOutcome::default();
    let num_vfs = num_vfs.min(MAX_VFS);
    if num_vfs == 0 {
        return outcome;
    }
    // One MBVFICR word covers 16 VFs; snapshot each word once,
    // then work the VFs in ascending order.
    let groups = num_vfs.div_ceil(16);
    for group in 0..groups {
        let word = bank.read32(mbvficr(group * 16));
        for i in 0..16 {
            let vf = group * 16 + i;
            if vf >= num_vfs {
                break;
            }
            if vf_reset_pending(bank, vf) {
                if clear_vf_reset_event(bank, vf).is_ok() {
                    outcome.resets |= 1u64 << vf;
                }
            }
            let req_bit = MBVFICR_VFREQ_VF1 << i;
            if word & req_bit != 0 {
                bank.write32(mbvficr(vf), req_bit);
                let mut msg = [0u32; MBX_WORDS];
                if mailbox_read(bank, vf, &mut msg).is_ok()
                    && dispatch_vf_message(bank, table, vf, &msg).is_ok()
                {
                    outcome.msgs |= 1u64 << vf;
                }
            }
            let ack_bit = MBVFICR_VFACK_VF1 << i;
            if word & ack_bit != 0 {
                bank.write32(mbvficr(vf), ack_bit);
                outcome.acks |= 1u64 << vf;
            }
        }
    }
    outcome
}
