//! ixgbe advanced RX descriptors (one-buffer mode) + completion decode.
//!
//! Grounding: Linux `union ixgbe_adv_rx_desc` (`ixgbe_type.h:2903`),
//! status bits (`ixgbe_type.h:2380-2400`), error bits
//! (`ixgbe_type.h:2408-2426`), SRRCTL descriptor types
//! (`ixgbe_type.h:2461-2462`), `ixgbe_rx_checksum`
//! (`ixgbe_main.c:1676`) and the VLAN-accel path
//! (`ixgbe_main.c:1905-1909`), all @ `cbbddb6`; Intel 82599
//! Datasheet rev. 2.0 §7.1.6 (read format Table 7.15, write-back
//! format Table 7.16, status Tables 7.17/7.18). The datasheet and
//! Linux agree on the write-back byte layout: RSS/packet-type
//! dwords at bytes 0..8, status+error at bytes 8..12, packet
//! length at bytes 12..14, VLAN tag at bytes 14..16.
//!
//! The ring slot holds 16 bytes. Software arms it with the read
//! view (`AdvRxDescRead`: packet buffer address + header buffer
//! address, the latter zero in one-buffer mode — header split is
//! not used). Hardware overwrites the same 16 bytes with the
//! write-back view (`AdvRxDescWb`) on completion. The two views
//! are separate structs, not a union: the driver writes one view
//! and reads the other, never both at once.
//!
//! Checksum decode is conservative, following Linux's bit tests:
//! `csum_l3` requires the IPCS status bit AND the absence of the
//! IPE error bit; `csum_l4` requires the L4CS status bit AND the
//! absence of the TCPE error bit. A missing claim is fail-closed
//! (the stack verifies in software); a false claim would accept a
//! corrupt frame, so no claim is made on partial evidence.
//!
//! Deliberate non-goals, each a documented remainder:
//! - The 82599 UDP-zero-checksum errata carve-out (Linux ignores a
//!   TCPE error on UDP frames with a zero checksum) is NOT
//!   implemented: it needs packet-type decode from the lo dword
//!   plus ring state. Such frames report `csum_l4 = false` here,
//!   which is fail-closed, not wrong.
//! - RSS hash / flow-director ID (lo/hi dwords) are NOT surfaced:
//!   `RxMeta::rx_hash` stays 0 for ixgbe until the RSS row wires
//!   it (the RSS block itself is a separate stream item).
//! - RSC coalescing counts (RSCCNT) are NOT surfaced: `gro_segs`
//!   stays 0; the driver never enables RSC.

use core::sync::atomic::{compiler_fence, Ordering};

/// Advanced RX descriptor status bits (write-back `status_error`,
/// low 20 bits). Linux `ixgbe_type.h:2380-2400`.
pub const ADV_RXD_STAT_DD: u32 = 0x01;
/// End of packet.
pub const ADV_RXD_STAT_EOP: u32 = 0x02;
/// Flow-director filter match.
#[allow(dead_code)]
pub const ADV_RXD_STAT_FLM: u32 = 0x04;
/// VLAN packet: the `vlan` field carries a stripped tag.
pub const ADV_RXD_STAT_VP: u32 = 0x08;
/// UDP checksum calculated.
#[allow(dead_code)]
pub const ADV_RXD_STAT_UDPCS: u32 = 0x10;
/// L4 (TCP/UDP) checksum calculated.
pub const ADV_RXD_STAT_L4CS: u32 = 0x20;
/// IP header checksum calculated.
pub const ADV_RXD_STAT_IPCS: u32 = 0x40;
/// Passed in-exact filter.
#[allow(dead_code)]
pub const ADV_RXD_STAT_PIF: u32 = 0x80;

/// Advanced RX descriptor error bits (write-back `status_error`,
/// high 12 bits, mask `0xfff00000`). Linux `ixgbe_type.h:2408-2426`.
/// TCP/UDP checksum error.
pub const ADV_RXD_ERR_TCPE: u32 = 0x40000000;
/// IP header checksum error.
pub const ADV_RXD_ERR_IPE: u32 = 0x80000000;

/// Advanced RX descriptor, read (arming) view: packet buffer
/// address + header buffer address. Datasheet §7.1.6.1, Table 7.15.
/// `hdr_addr` is zero in one-buffer mode (no header split).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvRxDescRead {
    pub pkt_addr: u64,
    pub hdr_addr: u64,
}
const _: () = assert!(core::mem::size_of::<AdvRxDescRead>() == 16);
const _: () = assert!(core::mem::align_of::<AdvRxDescRead>() == 16);

impl AdvRxDescRead {
    /// Arm a slot with a packet buffer in one-buffer mode.
    pub const fn new(pkt_addr: u64) -> Self {
        Self {
            pkt_addr,
            hdr_addr: 0,
        }
    }
}

/// Advanced RX descriptor, write-back (completion) view.
/// Datasheet §7.1.6.2, Table 7.16; Linux `wb` member.
/// `lo`/`hi` are the RSS/packet-type dwords (bytes 0..8);
/// `status_error` (bytes 8..12) packs status (low 20 bits) and
/// error (high 12 bits); `length` (bytes 12..14) is the packet
/// length; `vlan` (bytes 14..16) is the stripped VLAN tag
/// (valid only when the VP status bit is set).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvRxDescWb {
    pub lo: u32,
    pub hi: u32,
    pub status_error: u32,
    pub length: u16,
    pub vlan: u16,
}
const _: () = assert!(core::mem::size_of::<AdvRxDescWb>() == 16);
const _: () = assert!(core::mem::align_of::<AdvRxDescWb>() == 16);

impl AdvRxDescWb {
    /// Sample an RX ring slot hardware may be completing right now.
    /// `word(i)` reads little-endian qword `i` of the 16-byte slot.
    ///
    /// Hardware writes the descriptor back while the host polls it, so a
    /// sample must never pair a fresh DD with fields of the slot's
    /// previous contents. Qword 1 carries status/error (with DD), the
    /// packet length and the VLAN tag: it is taken first and as ONE
    /// load, so a set DD always comes with the length written with it.
    /// Qword 0 (RSS / packet-type dwords) is loaded only after DD was
    /// seen. `None` means "not completed": nothing else of the slot was
    /// read. Linux `ixgbe_clean_rx_irq` does the same: it tests
    /// `wb.upper.length`, then `dma_rmb()`, then reads the rest.
    ///
    /// A whole-struct `read_volatile` gives no such order: the compiler
    /// lowers it to separate field loads in an order of its choosing,
    /// and loading `length` before `status_error` shows the armed
    /// slot's zero length under a DD posted between the two loads.
    #[inline]
    pub fn sample(mut word: impl FnMut(usize) -> u64) -> Option<Self> {
        let upper = word(1);
        if upper as u32 & ADV_RXD_STAT_DD == 0 {
            return None;
        }
        // Pair hardware's DD write with the loads that follow it.
        compiler_fence(Ordering::SeqCst);
        let lower = word(0);
        Some(Self {
            lo: lower as u32,
            hi: (lower >> 32) as u32,
            status_error: upper as u32,
            length: (upper >> 32) as u16,
            vlan: (upper >> 48) as u16,
        })
    }

    /// Descriptor Done: hardware has completed this descriptor.
    pub const fn is_done(&self) -> bool {
        self.status_error & ADV_RXD_STAT_DD != 0
    }

    /// End of packet: this descriptor holds the frame's tail.
    /// (The driver uses single-descriptor frames only, so every
    /// completed descriptor it consumes is also an EOP one; the
    /// bit is exposed for the fixture, not branched on.)
    pub const fn is_eop(&self) -> bool {
        self.status_error & ADV_RXD_STAT_EOP != 0
    }

    /// Stripped 802.1Q tag (TCI: PCP + CFI + VID) as reported by
    /// hardware, or `None` when the VP bit is clear. Mirrors
    /// Linux's `ixgbe_test_staterr(VP)` + `wb.upper.vlan` path:
    /// the tag is meaningful only with VP set, even if the
    /// `vlan` field holds a stale value.
    pub const fn vlan_tag(&self) -> Option<u16> {
        if self.status_error & ADV_RXD_STAT_VP != 0 {
            Some(self.vlan)
        } else {
            None
        }
    }

    /// Decode completion metadata for the frame ring. Follows
    /// Linux's `ixgbe_rx_checksum` bit tests, conservatively:
    /// each checksum claim needs its status bit AND the absence
    /// of its error bit. IPv6 never sets `csum_l3` — IPv6 has no
    /// header checksum, so hardware never sets IPCS for it.
    pub fn rx_meta(&self) -> narf_net::RxMeta {
        narf_net::RxMeta {
            csum_l3: self.status_error & ADV_RXD_STAT_IPCS != 0
                && self.status_error & ADV_RXD_ERR_IPE == 0,
            csum_l4: self.status_error & ADV_RXD_STAT_L4CS != 0
                && self.status_error & ADV_RXD_ERR_TCPE == 0,
            vlan_tag: self.vlan_tag(),
            ..Default::default()
        }
    }
}
