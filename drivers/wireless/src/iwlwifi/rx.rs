//! iwlwifi receive path — Stage 3.
//!
//! Implements the RX descriptor ring (RXB), IRQ-driven drain, and
//! `iwl_rx_packet` header decode + dispatch.
//!
//! ## Architecture
//!
//! The device writes filled descriptors into the RX ring. On each
//! `FH_RX` interrupt:
//!
//!   1. Read `CSR_FH_INT_STATUS` to confirm `FH_RX` set.
//!   2. Read the RX write-back pointer (RXQ_RB_STTS) which the
//!      device updates after DMAing the packet.
//!   3. Drain from `read_ptr` to `write_ptr`, calling the handler
//!      for each received `iwl_rx_packet`.
//!   4. Advance `read_ptr` to `write_ptr`, replenish free slots,
//!      and write `CSR_FH_RSCSR_CHNL0_RXBD_STTS_WPTR_REG`.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/pcie/rx.c` —
//!   `iwl_pcie_rx_handle`, `iwl_pcie_rx_alloc_page`,
//!   `iwl_pcie_rx_replenish`.
//! - `drivers/net/wireless/intel/iwlwifi/iwl-trans.h` —
//!   `iwl_rx_packet` layout.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/internal.h` —
//!   `iwl_rxq`, `iwl_rx_mem_buffer`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
// ── RX ring constants ───────────────────────────────────────────────

/// Default RX ring depth. Must be a power of 2. Linux uses 512 for
/// gen2, 256 for gen3; we use 256 uniformly (simpler).
pub const RX_RING_SIZE: usize = 256;
/// Mask for fast modular arithmetic on ring indices.
pub const RX_RING_MASK: usize = RX_RING_SIZE - 1;
/// Maximum receive buffer size. Linux uses 4096 (one page) as the
/// standard RXB size; 4096 fits an MPDU with all 802.11 headers.
pub const RXB_SIZE: usize = 4096;
/// Number of RX queues. Modern AX2xx hardware supports up to 512
/// queues; we initialise exactly one (queue 0) in this stage.
pub const N_RX_QUEUES: usize = 1;

// ── CSR offsets needed by the RX path ──────────────────────────────
// (sourced from pcie/rx.c and iwl-csr.h)

/// `FH_RSCSR_CHNL0_STTS_WPTR_REG` — device writes the current RXQ
/// write-back pointer here after DMAing a packet.
pub const CSR_FH_RSCSR_CHNL0_STTS_WPTR_REG: u32 = 0x940;
/// Host write-pointer for the RX free-buffer list.
pub const CSR_FH_RSCSR_CHNL0_WPTR: u32 = 0x980;
/// RX queue base address (host phys, 4 KB aligned).
pub const CSR_FH_MEM_RSCSR_CHNL0_RBDCB_BASE_REG: u32 = 0x950;

// ── iwl_rx_packet header ────────────────────────────────────────────

/// Constant for sequence field "no sequence".
pub const IWL_RX_SEQ_NONE: u16 = 0xFFFF;

/// Decoded rx_packet header. Mirrors the `iwl_rx_packet` struct from
/// `iwl-trans.h`. The device prepends this 8-byte header to every
/// received buffer.
#[derive(Copy, Clone, Debug)]
pub struct RxPacketHeader {
    /// Total length of the `len_n_flags` field including the header
    /// itself. Use `payload_len()` to get the data after the header.
    pub len_n_flags: u32,
    /// Response type identifier (command ID that triggered this
    /// notification).
    pub cmd: u8,
    /// Group ID (notification group / command group).
    pub group_id: u8,
    /// Sequence number from the originating host command. The value
    /// `IWL_RX_SEQ_NONE` means the packet is an unsolicited
    /// notification.
    pub sequence: u16,
}

impl RxPacketHeader {
    /// Packet data length in bytes, excluding the 8-byte header.
    pub fn payload_len(self) -> usize {
        let total = (self.len_n_flags & 0x0000_3FFF) as usize;
        total.saturating_sub(8)
    }

    /// True iff this is an unsolicited notification (not a command
    /// response).
    pub fn is_notification(self) -> bool {
        self.sequence == IWL_RX_SEQ_NONE
    }
}

/// Parse an `iwl_rx_packet` header from a raw byte slice. Returns
/// `None` if the slice is shorter than 8 bytes (the header size).
///
/// Layout (little-endian):
/// ```text
/// offset 0: u32 len_n_flags
/// offset 4: u8  cmd
/// offset 5: u8  group_id
/// offset 6: u16 sequence
/// ```
pub fn parse_rx_header(bytes: &[u8]) -> Option<RxPacketHeader> {
    if bytes.len() < 8 {
        return None;
    }
    let len_n_flags = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let cmd = bytes[4];
    let group_id = bytes[5];
    let sequence = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    Some(RxPacketHeader { len_n_flags, cmd, group_id, sequence })
}

// ── Well-known notification command IDs ────────────────────────────

/// `ALIVE` notification: `cmd=0x01, group=0x00`. Firmware sends
/// this after completing its startup sequence.
pub const NOTIF_ALIVE: u8 = 0x01;
pub const NOTIF_ALIVE_GROUP: u8 = 0x00;

/// `SCAN_COMPLETE_UMAC`: `cmd=0x07, group=0x0C`. MVM sends this
/// after a UMAC scan job finishes.
pub const NOTIF_SCAN_COMPLETE_UMAC: u8 = 0x07;
pub const NOTIF_SCAN_COMPLETE_GROUP: u8 = 0x0C;

/// `MAC_CONTEXT_CHANGED`: cmd=0x28, group=0x01. Sent when the
/// firmware changes the MAC/BSSID context.
pub const NOTIF_MAC_CONTEXT_CHANGED: u8 = 0x28;
pub const NOTIF_MAC_CONTEXT_GROUP: u8 = 0x01;

/// `RX_MPDU_NOTIF`: cmd=0x11, group=0x05. Carries a received
/// 802.11 frame (MPDU) upward to the host.
pub const NOTIF_RX_MPDU: u8 = 0x11;
pub const NOTIF_RX_MPDU_GROUP: u8 = 0x05;

// ── RX descriptor ──────────────────────────────────────────────────

/// One entry in the host RX free-buffer list. Holds the host phys
/// of a 4 KB page the device can DMA a received packet into.
#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDescriptor {
    /// Host physical address of the receive buffer page (4 KB
    /// aligned, lower 12 bits unused / zero).
    pub host_phys: u64,
}

// ── RX queue ───────────────────────────────────────────────────────

/// Soft state for one receive queue.  Mirrors `iwl_rxq` in
/// `pcie/internal.h` (at the level of fields we actually use).
///
/// The free-buffer list (one `RxDescriptor` per slot) lives in
/// DMA-coherent host RAM; the caller is responsible for allocating
/// that region and filling `descriptors_phys`.
#[derive(Debug)]
pub struct RxQueue {
    /// Host-side virtual address of the descriptor ring.
    pub descriptors: *mut RxDescriptor,
    /// Host physical address of `descriptors[0]`. Written to
    /// `CSR_FH_MEM_RSCSR_CHNL0_RBDCB_BASE_REG` during init.
    pub descriptors_phys: u64,
    /// Index of the next slot to give back to the device. Advanced
    /// by the drain loop; written to `CSR_FH_RSCSR_CHNL0_WPTR`.
    pub read_ptr: usize,
    /// The last write-pointer the device reported. Read from
    /// `CSR_FH_RSCSR_CHNL0_STTS_WPTR_REG` at IRQ time.
    pub write_ptr: usize,
}

unsafe impl Send for RxQueue {}
unsafe impl Sync for RxQueue {}

impl RxQueue {
    /// Create a new RX queue with `RX_RING_SIZE` empty descriptors.
    pub fn new(descriptors: *mut RxDescriptor, descriptors_phys: u64) -> Self {
        Self {
            descriptors,
            descriptors_phys,
            read_ptr: 0,
            write_ptr: 0,
        }
    }

    /// True iff `read_ptr != write_ptr` — i.e. there are packets
    /// the host hasn't processed yet.
    pub fn has_packets(&self) -> bool {
        self.read_ptr != self.write_ptr
    }

    /// Advance `read_ptr` by one and return the previous slot index.
    pub fn consume_one(&mut self) -> usize {
        let slot = self.read_ptr;
        self.read_ptr = (self.read_ptr + 1) & RX_RING_MASK;
        slot
    }
}

// ── Rx packet classifier ────────────────────────────────────────────

/// Classification of a decoded packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxKind {
    /// ALIVE notification from firmware startup.
    Alive,
    /// Scan-complete notification.
    ScanComplete,
    /// Received 802.11 MPDU.
    RxMpdu,
    /// MAC context change notification.
    MacContextChanged,
    /// Unknown / unhandled notification.
    Unknown { cmd: u8, group_id: u8 },
}

/// Classify an `RxPacketHeader` into an `RxKind`.
pub fn classify_rx(hdr: &RxPacketHeader) -> RxKind {
    match (hdr.cmd, hdr.group_id) {
        (NOTIF_ALIVE, NOTIF_ALIVE_GROUP) => RxKind::Alive,
        (NOTIF_SCAN_COMPLETE_UMAC, NOTIF_SCAN_COMPLETE_GROUP) => RxKind::ScanComplete,
        (NOTIF_RX_MPDU, NOTIF_RX_MPDU_GROUP) => RxKind::RxMpdu,
        (NOTIF_MAC_CONTEXT_CHANGED, NOTIF_MAC_CONTEXT_GROUP) => RxKind::MacContextChanged,
        _ => RxKind::Unknown { cmd: hdr.cmd, group_id: hdr.group_id },
    }
}

// ── IRQ drain scaffold ──────────────────────────────────────────────

/// Callback invoked for each received packet during drain.
/// The `payload` slice points into the RXB's data (after the
/// 8-byte header).
pub trait RxHandler {
    fn handle(&mut self, kind: RxKind, hdr: RxPacketHeader, payload: &[u8]);
}

/// Read the device write-back pointer from MMIO and drain new
/// entries from `rxq`.  For each entry, parse the `iwl_rx_packet`
/// header from the RXB contents (provided via `rxb_data`), classify
/// the kind, and call `handler.handle`.
///
/// `rxb_data(slot)` returns a byte slice for slot `slot`'s receive
/// buffer.  The caller owns the buffer allocation; this function
/// only reads.
///
/// `mmio_wptr` is the value the driver read from
/// `CSR_FH_RSCSR_CHNL0_STTS_WPTR_REG` immediately before calling
/// this function (passed in rather than read here so the function is
/// testable without live MMIO).
pub fn drain_rx_queue<'a, H, F>(
    rxq: &mut RxQueue,
    mmio_wptr: usize,
    mut rxb_data: F,
    handler: &mut H,
)
where
    H: RxHandler,
    F: FnMut(usize) -> &'a [u8],
{
    rxq.write_ptr = mmio_wptr & RX_RING_MASK;

    while rxq.has_packets() {
        let slot = rxq.consume_one();
        let data = rxb_data(slot);
        if let Some(hdr) = parse_rx_header(data) {
            let payload_len = hdr.payload_len();
            let payload_end = 8usize.saturating_add(payload_len).min(data.len());
            let payload = if data.len() >= 8 { &data[8..payload_end] } else { &[] };
            let kind = classify_rx(&hdr);
            handler.handle(kind, hdr, payload);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke: RX descriptor ring round-trip ───────────────────────

    /// Create a ring, fill a packet, drain it, confirm the handler
    /// fires once with the right kind.
    fn smoke_iwlwifi_rx_descriptor_ring_round_trip() -> TestResult {
        // Packet bytes: ALIVE notification header (8 bytes) + 4-byte
        // status payload.
        static RXB: &[u8] = &[
            // len_n_flags: total=12 (0x0C), no flags
            0x0C, 0x00, 0x00, 0x00,
            // cmd=ALIVE(0x01), group=0x00, seq=0xFFFF (notification)
            0x01, 0x00, 0xFF, 0xFF,
            // payload: ALIVE status = 0xCAFE (little-endian)
            0xFE, 0xCA, 0x00, 0x00,
        ];

        let mut rxq = RxQueue::new(core::ptr::null_mut(), 0);
        // Pretend slot 0's buffer is filled (wptr advances to 1).
        let mmio_wptr = 1;

        struct Capture {
            kind: Option<RxKind>,
            payload_len: usize,
        }
        impl RxHandler for Capture {
            fn handle(&mut self, kind: RxKind, _hdr: RxPacketHeader, payload: &[u8]) {
                self.kind = Some(kind);
                self.payload_len = payload.len();
            }
        }

        let mut cap = Capture { kind: None, payload_len: 0 };
        drain_rx_queue(
            &mut rxq,
            mmio_wptr,
            |_slot| RXB,
            &mut cap,
        );

        match cap.kind {
            Some(RxKind::Alive) => {}
            _ => return TestResult::Fail("expected RxKind::Alive"),
        }
        if cap.payload_len != 4 {
            return TestResult::Fail("payload_len wrong");
        }
        if rxq.read_ptr != 1 {
            return TestResult::Fail("read_ptr not advanced");
        }
        TestResult::Pass
    }

    // ── Smoke: parse_rx_header rejects short buffer ────────────────

    fn smoke_iwlwifi_rx_parse_header_rejects_short() -> TestResult {
        let short = [0u8; 7];
        if parse_rx_header(&short).is_some() {
            return TestResult::Fail("expected None for 7-byte buffer");
        }
        if parse_rx_header(&[]).is_some() {
            return TestResult::Fail("expected None for empty buffer");
        }
        TestResult::Pass
    }

    // ── Smoke: classify_rx dispatches known types ──────────────────

    fn smoke_iwlwifi_rx_classify_known_notifications() -> TestResult {
        let alive_hdr = RxPacketHeader {
            len_n_flags: 8,
            cmd: NOTIF_ALIVE,
            group_id: NOTIF_ALIVE_GROUP,
            sequence: IWL_RX_SEQ_NONE,
        };
        if classify_rx(&alive_hdr) != RxKind::Alive {
            return TestResult::Fail("ALIVE misclassified");
        }

        let scan_hdr = RxPacketHeader {
            len_n_flags: 8,
            cmd: NOTIF_SCAN_COMPLETE_UMAC,
            group_id: NOTIF_SCAN_COMPLETE_GROUP,
            sequence: IWL_RX_SEQ_NONE,
        };
        if classify_rx(&scan_hdr) != RxKind::ScanComplete {
            return TestResult::Fail("SCAN_COMPLETE misclassified");
        }

        let mpdu_hdr = RxPacketHeader {
            len_n_flags: 8,
            cmd: NOTIF_RX_MPDU,
            group_id: NOTIF_RX_MPDU_GROUP,
            sequence: IWL_RX_SEQ_NONE,
        };
        if classify_rx(&mpdu_hdr) != RxKind::RxMpdu {
            return TestResult::Fail("RX_MPDU misclassified");
        }

        // Unknown pair → Unknown variant.
        let unk = RxPacketHeader {
            len_n_flags: 8,
            cmd: 0xFE,
            group_id: 0xFF,
            sequence: 0x0042,
        };
        match classify_rx(&unk) {
            RxKind::Unknown { cmd: 0xFE, group_id: 0xFF } => {}
            _ => return TestResult::Fail("unknown pair not Unknown"),
        }

        TestResult::Pass
    }

    // ── Smoke: ALIVE notification decode ──────────────────────────

    /// Decode an ALIVE payload and confirm the status field reads
    /// 0xCAFE. Mirrors the production path in the probe handler.
    fn smoke_iwlwifi_rx_alive_notification_decode() -> TestResult {
        // Full ALIVE RXB: 8-byte header + 4-byte status.
        static RXB: &[u8] = &[
            0x0C, 0x00, 0x00, 0x00, // len_n_flags = 12
            0x01, 0x00, 0xFF, 0xFF, // ALIVE, group=0, seq=NONE
            0xFE, 0xCA, 0x00, 0x00, // status = 0xCAFE
        ];
        let hdr = parse_rx_header(RXB).expect("header parse");
        let kind = classify_rx(&hdr);
        if kind != RxKind::Alive {
            return TestResult::Fail("not classified as Alive");
        }
        // Decode payload: bytes[8..12] = little-endian status.
        let payload = &RXB[8..12];
        let status = u32::from_le_bytes(payload.try_into().unwrap());
        if status != super::super::regs::IWL_ALIVE_STATUS_OK {
            return TestResult::Fail("ALIVE status not 0xCAFE");
        }
        TestResult::Pass
    }

    // ── Smoke: drain does nothing when ring is empty ───────────────

    fn smoke_iwlwifi_rx_drain_noop_when_empty() -> TestResult {
        let mut rxq = RxQueue::new(core::ptr::null_mut(), 0);
        let mut called = 0u32;

        struct Counter<'a>(&'a mut u32);
        impl RxHandler for Counter<'_> {
            fn handle(&mut self, _: RxKind, _: RxPacketHeader, _: &[u8]) {
                *self.0 += 1;
            }
        }

        static DUMMY: &[u8] = &[];
        drain_rx_queue(&mut rxq, 0, |_| DUMMY, &mut Counter(&mut called));

        if called != 0 {
            return TestResult::Fail("handler called on empty ring");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_iwlwifi_rx_descriptor_ring_round_trip
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_iwlwifi_rx_parse_header_rejects_short
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_iwlwifi_rx_classify_known_notifications
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_iwlwifi_rx_alive_notification_decode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_iwlwifi_rx_drain_noop_when_empty
    );
}
