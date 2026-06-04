//! iwlwifi transmit path — Stage 3.
//!
//! Implements the TX scheduler ring (`iwl_txq`), the `iwl_tx_cmd`
//! builder, 802.11 MAC header prefixing, and the doorbell write that
//! signals the device scheduler.
//!
//! ## Architecture
//!
//! For AX2xx/BE2xx MVM firmware:
//!
//!   1. Host selects a TX queue (by AC / TID mapping or management
//!      queue).
//!   2. Host builds an `iwl_tx_cmd` at the head of the TFD (Transfer
//!      Frame Descriptor).
//!   3. Host chains the 802.11 MAC header + MSDU payload as scatter-
//!      gather entries in the TFD.
//!   4. Host writes the updated write-pointer to the SCD (scheduler
//!      doorbell) register at `SCD_QUEUE_WRPTR(queue)`.
//!   5. Firmware consumes the TFD, DMA-reads the payload, applies
//!      crypto / A-MPDU aggregation, and transmits on the RF.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/mvm/tx.c` —
//!   `iwl_mvm_tx_skb`, `iwl_mvm_set_tx_cmd`.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/tx.c` —
//!   `iwl_pcie_txq_alloc`, `iwl_pcie_txq_build_tfd`.
//! - `drivers/net/wireless/intel/iwlwifi/fw/api/tx.h` —
//!   `iwl_tx_cmd` layout, TX flags.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/tx-gen2.c` —
//!   gen2 doorbell write.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── TX ring constants ───────────────────────────────────────────────

/// Number of TX queues (MVM default: 31 data + 1 management = 32).
/// In this stage we expose management queue 0 only.
pub const N_TX_QUEUES: usize = 32;
/// TX ring depth (power of 2). Linux defaults to 256.
pub const TX_RING_SIZE: usize = 256;
/// Ring index mask.
pub const TX_RING_MASK: usize = TX_RING_SIZE - 1;

// ── Scheduler doorbell register ─────────────────────────────────────

/// Base of the SCD (scheduler) PRPH range.
/// `SCD_QUEUE_WRPTR(q) = SCD_BASE + q * 4`. Driver writes the
/// TX queue's new write-pointer here to kick the device scheduler.
///
/// Source: `pcie/gen1_2/tx-gen2.c::iwl_pcie_gen2_update_byte_tbl`.
pub const SCD_BASE: u32 = 0xA02C_00;
/// Per-queue write-pointer register: `SCD_BASE + queue_id * 4`.
#[inline]
pub const fn scd_queue_wrptr(queue_id: u32) -> u32 {
    SCD_BASE + queue_id * 4
}

// ── iwl_tx_cmd ─────────────────────────────────────────────────────

/// TX flags matching `iwl_tx_flags` in `fw/api/tx.h`. Only the
/// subset used during initial bring-up (management frames without
/// aggregation or encryption).
pub mod tx_flags {
    /// No ACK requested (used for broadcast/multicast management).
    pub const TX_CMD_FLG_NO_ACK: u32 = 1 << 12;
    /// Frame goes into AMPDU traffic (data only; never set for
    /// management).
    pub const TX_CMD_FLG_AMPDU: u32 = 1 << 10;
    /// Transmit at the station's default management rate (MCS0 /
    /// OFDM-6Mbps).
    pub const TX_CMD_FLG_MCS: u32 = 1 << 0;
    /// SEQ_CTL set by host (management frames only).
    pub const TX_CMD_FLG_SEQ_CTL: u32 = 1 << 3;
    /// Frame requires 802.11e QoS (add QoS control field).
    pub const TX_CMD_FLG_QOS: u32 = 1 << 8;
}

/// `sec_ctl` field values (from `TX_CMD_SEC_*` in `fw/api/tx.h`).
///
/// Written into `IwlTxCmd::sec_ctl` to enable hardware CCMP/TKIP
/// encryption on outgoing data frames after the PTK is installed.
pub mod sec_ctl {
    /// No encryption.
    pub const NO_ENC: u8 = 0x00;
    /// WEP encryption (legacy only).
    pub const WEP: u8 = 0x01;
    /// CCMP-128 (WPA2) hardware encryption. Set after PTK install.
    pub const CCM: u8 = 0x02;
    /// TKIP encryption (WPA1 legacy).
    pub const TKIP: u8 = 0x03;
    /// GCMP encryption (WPA3).
    pub const GCMP: u8 = 0x05;
    /// Use the key from the firmware key table (non-WEP keys).
    /// Must be OR'd with the algorithm byte.
    pub const KEY_FROM_TABLE: u8 = 0x10;
}

/// `iwl_tx_cmd` — the per-TFD header the MVM firmware expects.
/// Layout sourced from `fw/api/tx.h`. We expose the fields used
/// by management-frame TX; data-frame extras (aggregation start,
/// key material) are zeroed.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct IwlTxCmd {
    /// Total frame byte length excluding FCS. Includes 802.11 MAC
    /// header + any QoS / HT-Control fields + MSDU body.
    pub len: u16,
    /// Caller copy of `len`; firmware double-checks.
    pub offload_assist: u16,
    /// TX flags (`tx_flags::*` constants OR'd together).
    pub tx_flags: u32,
    /// Rate/modulation code for the initial transmission attempt.
    /// For management frames: 0x4001 (OFDM-6 Mbps, 20 MHz).
    pub rate_n_flags: u32,
    /// Station ID (index into firmware's station table). 0 for AP
    /// station after successful association; `BROADCAST_STATION_ID`
    /// (usually 0xFF) for pre-association management.
    pub sta_id: u8,
    /// Security key flags (0 = no encryption).
    pub sec_ctl: u8,
    /// Initial power-control index.
    pub initial_rate_index: u8,
    /// Reserved.
    pub reserved: u8,
    /// Association ID (set in data path; 0 for management TX).
    pub aid: u16,
    /// Padding to keep the struct at a multiple of 4 bytes.
    pub _pad: u16,
}

impl IwlTxCmd {
    /// Build a bare management-frame TX command. Rate = OFDM-6Mbps,
    /// SEQ_CTL managed by host, no encryption.
    pub fn for_management(frame_len: u16, sta_id: u8) -> Self {
        Self {
            len: frame_len,
            offload_assist: 0,
            tx_flags: tx_flags::TX_CMD_FLG_SEQ_CTL,
            rate_n_flags: 0x4001, // OFDM-6 Mbps, 20 MHz, no HT/VHT
            sta_id,
            sec_ctl: 0,
            initial_rate_index: 0,
            reserved: 0,
            aid: 0,
            _pad: 0,
        }
    }

    /// Build a data-frame TX command with CCMP-128 encryption enabled.
    ///
    /// Sets `sec_ctl = CCM | KEY_FROM_TABLE` so the firmware CCMP
    /// engine picks the key from the slot installed via `ADD_STA_KEY`.
    ///
    /// Reference: `mvm/tx.c::iwl_mvm_set_tx_cmd` (sec_ctl path) +
    /// `fw/api/tx.h` TX_CMD_SEC_CCM / TX_CMD_SEC_KEY_FROM_TABLE.
    pub fn for_data_ccmp(frame_len: u16, sta_id: u8) -> Self {
        Self {
            len: frame_len,
            offload_assist: 0,
            tx_flags: tx_flags::TX_CMD_FLG_QOS,
            rate_n_flags: 0x4001,
            sta_id,
            sec_ctl: sec_ctl::CCM | sec_ctl::KEY_FROM_TABLE,
            initial_rate_index: 0,
            reserved: 0,
            aid: 0,
            _pad: 0,
        }
    }
}

/// `iwl_cmd_header` — header for firmware commands (H2C).
/// Layout sourced from `fw/api/commands.h`.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct IwlCmdHeader {
    pub cmd: u8,
    pub group_id: u8,
    pub sequence: u16,
}

// ── 802.11 MAC header builder ───────────────────────────────────────

/// 802.11 frame control field constants.
pub mod fc {
    /// Protocol version bits 0-1: always 0.
    pub const VERS_MASK: u16 = 0x0003;
    /// Frame type bits 2-3.
    pub const TYPE_MASK: u16 = 0x000C;
    /// Frame subtype bits 4-7.
    pub const SUBTYPE_MASK: u16 = 0x00F0;
    /// To-DS bit (set when frame goes from STA to AP).
    pub const TO_DS: u16 = 1 << 8;
    /// Protected (encrypted) bit.
    pub const PROTECTED: u16 = 1 << 14;
    /// Retry bit.
    pub const RETRY: u16 = 1 << 11;

    // Frame types (bits 3:2).
    pub const TYPE_MGMT: u16 = 0x00;
    pub const TYPE_CTRL: u16 = 0x04;
    pub const TYPE_DATA: u16 = 0x08;

    // Management frame subtypes (bits 7:4) — OR with TYPE_MGMT.
    pub const SUBTYPE_PROBE_REQ: u16 = 0x40;
    pub const SUBTYPE_AUTH: u16 = 0xB0;
    pub const SUBTYPE_ASSOC_REQ: u16 = 0x00;  // subtype 0 = assoc req
    pub const SUBTYPE_DEAUTH: u16 = 0xC0;
    pub const SUBTYPE_DISASSOC: u16 = 0xA0;

    // Data subtypes.
    pub const SUBTYPE_DATA_QOS: u16 = 0x88; // QoS data
}

/// Minimal 802.11 management frame MAC header (24 bytes).
/// Does not include optional HT-Control, Addr4, or QoS fields.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MacHeader {
    /// Frame Control + Duration/ID (4 bytes).
    pub frame_control: u16,
    pub duration: u16,
    /// Destination address (DA).
    pub addr1: [u8; 6],
    /// Source address (SA).
    pub addr2: [u8; 6],
    /// BSSID.
    pub addr3: [u8; 6],
    /// Sequence control (fragment + sequence number).
    pub seq_ctrl: u16,
}

impl MacHeader {
    /// Build a management frame header. `fc_subtype` is one of the
    /// `fc::SUBTYPE_*` constants. `seq_num` is the 12-bit sequence
    /// number (bits 15:4 of seq_ctrl; fragment always 0).
    pub fn management(
        fc_subtype: u16,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        seq_num: u16,
    ) -> Self {
        let frame_control = fc::TYPE_MGMT | fc_subtype;
        Self {
            frame_control,
            duration: 0,
            addr1,
            addr2,
            addr3,
            seq_ctrl: (seq_num & 0x0FFF) << 4,
        }
    }

    /// Serialize the 24-byte header into a byte array.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..2].copy_from_slice(&self.frame_control.to_le_bytes());
        out[2..4].copy_from_slice(&self.duration.to_le_bytes());
        out[4..10].copy_from_slice(&self.addr1);
        out[10..16].copy_from_slice(&self.addr2);
        out[16..22].copy_from_slice(&self.addr3);
        out[22..24].copy_from_slice(&self.seq_ctrl.to_le_bytes());
        out
    }
}

// ── TFD (transfer frame descriptor) ────────────────────────────────

/// Maximum scatter-gather entries per TFD. Linux supports up to 20
/// (`IWL_NUM_OF_TBS`); we cap at 8 in this stage (sufficient for
/// management frames that fit in 1-2 segments).
pub const MAX_TFD_SEGS: usize = 8;

/// One scatter-gather segment in a TFD. Each segment describes a
/// contiguous chunk of host physical memory the DMA engine reads.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TbSeg {
    /// Host physical address of the segment.
    pub host_phys: u64,
    /// Length of the segment in bytes.
    pub len: u16,
    /// Reserved / flags. Always zero for data segments.
    pub _res: u16,
}

/// Transfer frame descriptor. The `tx_cmd` occupies the first 20
/// bytes (placed as a virtual seg); the actual TFD holds pointers to
/// DMA-coherent copies.
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug)]
pub struct Tfd {
    /// Number of valid `segs` entries.
    pub n_segs: u8,
    pub _pad: [u8; 3],
    /// Actual scatter-gather segments.
    pub segs: [TbSeg; MAX_TFD_SEGS],
}

impl Default for Tfd {
    fn default() -> Self {
        Self {
            n_segs: 0,
            _pad: [0; 3],
            segs: [TbSeg::default(); MAX_TFD_SEGS],
        }
    }
}

impl Tfd {
    /// Append one scatter-gather segment. Returns `false` if the TFD
    /// is already full (`n_segs == MAX_TFD_SEGS`).
    pub fn push_seg(&mut self, phys: u64, len: u16) -> bool {
        let n = self.n_segs as usize;
        if n >= MAX_TFD_SEGS {
            return false;
        }
        self.segs[n] = TbSeg { host_phys: phys, len, _res: 0 };
        self.n_segs += 1;
        true
    }
}

// ── TX queue ───────────────────────────────────────────────────────

/// Soft state for one TX queue.
#[derive(Debug)]
pub struct TxQueue {
    pub queue_id: u8,
    /// Ring write-pointer. Wraps at `TX_RING_MASK`.
    pub write_ptr: usize,
    /// Ring read-pointer (last index the device acknowledged).
    pub read_ptr: usize,
    /// Virtual address of the TFD ring in host RAM.
    pub tfds: *mut Tfd,
}

unsafe impl Send for TxQueue {}
unsafe impl Sync for TxQueue {}

impl TxQueue {
    pub fn new(queue_id: u8, tfds: *mut Tfd) -> Self {
        Self { queue_id, write_ptr: 0, read_ptr: 0, tfds }
    }

    /// Enqueue a pre-built `Tfd` and advance the write-pointer.
    /// Returns the slot index where the TFD was placed.
    pub fn enqueue(&mut self, tfd: Tfd) -> usize {
        let slot = self.write_ptr;
        unsafe {
            *self.tfds.add(slot) = tfd;
        }
        self.write_ptr = (self.write_ptr + 1) & TX_RING_MASK;
        slot
    }

    /// Number of used slots (write_ptr - read_ptr, wrapping).
    pub fn used_slots(&self) -> usize {
        (self.write_ptr.wrapping_sub(self.read_ptr)) & TX_RING_MASK
    }
}

// ── Doorbell write ──────────────────────────────────────────────────

use super::transport::IwlMmio;
use super::transport::{prph_write};

/// Write the updated TX queue write-pointer to the SCD doorbell via
/// the PRPH indirect-access registers. This is the "kick" that wakes
/// the firmware scheduler.
///
/// `mmio` — BAR0 MMIO surface.
/// `queue_id` — which queue to update.
/// `write_ptr` — the new write-pointer value (wraps at TX ring size).
pub fn tx_doorbell<M: IwlMmio>(mmio: &mut M, queue_id: u32, write_ptr: usize) {
    prph_write(mmio, scd_queue_wrptr(queue_id), write_ptr as u32);
}

// ── Frame builder ───────────────────────────────────────────────────

/// Complete TX packet: `iwl_tx_cmd` + 802.11 MAC header bytes.
/// Suitable for serialisation into a DMA-coherent buffer.
pub struct TxPacket {
    pub cmd: IwlTxCmd,
    pub mac_hdr: [u8; 24],
    pub mac_hdr_len: usize,
    pub payload: Vec<u8>,
}

impl TxPacket {
    /// Build a management frame packet for immediate transmission
    /// (no MSDU body; management frames carry their body inline
    /// after the MAC header, passed via `body`).
    pub fn management(
        fc_subtype: u16,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        seq_num: u16,
        sta_id: u8,
        body: &[u8],
    ) -> Self {
        let mac_hdr_raw = MacHeader::management(fc_subtype, addr1, addr2, addr3, seq_num);
        let mac_hdr_bytes = mac_hdr_raw.to_bytes();
        let frame_len = (24 + body.len()) as u16;
        let cmd = IwlTxCmd::for_management(frame_len, sta_id);
        let mut payload = Vec::with_capacity(body.len());
        payload.extend_from_slice(body);
        Self {
            cmd,
            mac_hdr: mac_hdr_bytes,
            mac_hdr_len: 24,
            payload,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use super::super::regs;

    // ── Mock MMIO ──────────────────────────────────────────────────

    struct MockMmio {
        writes: alloc::vec::Vec<(u32, u32)>,
    }
    impl MockMmio {
        fn new() -> Self {
            Self { writes: alloc::vec::Vec::new() }
        }
        fn last_write(&self, off: u32) -> Option<u32> {
            self.writes.iter().rev().find(|(o, _)| *o == off).map(|(_, v)| *v)
        }
    }
    impl IwlMmio for MockMmio {
        fn read(&mut self, _off: u32) -> u32 { 0 }
        fn write(&mut self, off: u32, value: u32) {
            self.writes.push((off, value));
        }
    }

    // ── Smoke: TX cmd builder ──────────────────────────────────────

    /// Build a management-frame TX command and verify key fields.
    fn smoke_iwlwifi_tx_cmd_builder() -> TestResult {
        let cmd = IwlTxCmd::for_management(256, 0);
        if cmd.len != 256 {
            return TestResult::Fail("len wrong");
        }
        if cmd.tx_flags & tx_flags::TX_CMD_FLG_SEQ_CTL == 0 {
            return TestResult::Fail("SEQ_CTL not set");
        }
        if cmd.tx_flags & tx_flags::TX_CMD_FLG_AMPDU != 0 {
            return TestResult::Fail("AMPDU should not be set for management");
        }
        if cmd.sta_id != 0 {
            return TestResult::Fail("sta_id wrong");
        }
        // Rate = OFDM-6Mbps sentinel.
        if cmd.rate_n_flags != 0x4001 {
            return TestResult::Fail("rate_n_flags wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: TX doorbell write ───────────────────────────────────

    /// Confirm that `tx_doorbell` writes the correct PRPH address.
    fn smoke_iwlwifi_tx_doorbell_write() -> TestResult {
        let mut mmio = MockMmio::new();
        // Queue 3, write-pointer = 42.
        tx_doorbell(&mut mmio, 3, 42);
        // HBUS_TARG_PRPH_WADDR must carry `scd_queue_wrptr(3)`.
        let expected_addr = scd_queue_wrptr(3);
        if mmio.last_write(regs::HBUS_TARG_PRPH_WADDR) != Some(expected_addr) {
            return TestResult::Fail("PRPH WADDR wrong");
        }
        // HBUS_TARG_PRPH_WDAT must carry the write-pointer value.
        if mmio.last_write(regs::HBUS_TARG_PRPH_WDAT) != Some(42) {
            return TestResult::Fail("PRPH WDAT wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: TFD push and overflow guard ────────────────────────

    fn smoke_iwlwifi_tfd_push_and_overflow_guard() -> TestResult {
        let mut tfd = Tfd::default();
        for i in 0..MAX_TFD_SEGS {
            if !tfd.push_seg(0x1000 * i as u64, 64) {
                return TestResult::Fail("push_seg failed before full");
            }
        }
        // One more should return false.
        if tfd.push_seg(0xDEAD_0000, 32) {
            return TestResult::Fail("push_seg should fail when full");
        }
        if tfd.n_segs as usize != MAX_TFD_SEGS {
            return TestResult::Fail("n_segs wrong after fill");
        }
        TestResult::Pass
    }

    // ── Smoke: TxQueue enqueue advances write_ptr ──────────────────

    fn smoke_iwlwifi_tx_queue_enqueue_advances_wptr() -> TestResult {
        let mut ring: alloc::vec::Vec<Tfd> =
            (0..TX_RING_SIZE).map(|_| Tfd::default()).collect();
        let mut q = TxQueue::new(0, ring.as_mut_ptr());
        let tfd = Tfd::default();
        let slot = q.enqueue(tfd);
        if slot != 0 {
            return TestResult::Fail("first enqueue should land in slot 0");
        }
        if q.write_ptr != 1 {
            return TestResult::Fail("write_ptr should be 1 after one enqueue");
        }
        if q.used_slots() != 1 {
            return TestResult::Fail("used_slots should be 1");
        }
        TestResult::Pass
    }

    // ── Smoke: management frame MAC header build ───────────────────

    fn smoke_iwlwifi_mac_header_management_build() -> TestResult {
        let addr1 = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // broadcast
        let addr2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // STA
        let addr3 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // BSSID
        let hdr = MacHeader::management(fc::SUBTYPE_PROBE_REQ, addr1, addr2, addr3, 7);
        let bytes = hdr.to_bytes();

        // frame_control = TYPE_MGMT | SUBTYPE_PROBE_REQ = 0x0040.
        let fc_val = u16::from_le_bytes([bytes[0], bytes[1]]);
        if fc_val != (fc::TYPE_MGMT | fc::SUBTYPE_PROBE_REQ) {
            return TestResult::Fail("frame_control wrong");
        }
        // addr1 at bytes[4..10].
        if bytes[4..10] != addr1 {
            return TestResult::Fail("addr1 wrong");
        }
        // seq_ctrl: seq_num=7 → bits[15:4]=7 → seq_ctrl = 7<<4 = 0x70.
        let sc = u16::from_le_bytes([bytes[22], bytes[23]]);
        if sc != 7 << 4 {
            return TestResult::Fail("seq_ctrl wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: data-frame TX command with CCMP crypto flags ───────

    fn smoke_iwlwifi_tx_cmd_ccmp_sec_ctl() -> TestResult {
        let cmd = IwlTxCmd::for_data_ccmp(1500, 0);
        // sec_ctl must have CCM algorithm + KEY_FROM_TABLE.
        let expected = sec_ctl::CCM | sec_ctl::KEY_FROM_TABLE;
        if cmd.sec_ctl != expected {
            return TestResult::Fail("sec_ctl wrong for CCMP data frame");
        }
        // QoS flag must be set (data frame).
        if cmd.tx_flags & tx_flags::TX_CMD_FLG_QOS == 0 {
            return TestResult::Fail("QoS flag not set for data frame");
        }
        // SEQ_CTL must NOT be set for data frames.
        if cmd.tx_flags & tx_flags::TX_CMD_FLG_SEQ_CTL != 0 {
            return TestResult::Fail("SEQ_CTL should not be set for data frame");
        }
        if cmd.len != 1500 {
            return TestResult::Fail("len wrong for CCMP data frame");
        }
        TestResult::Pass
    }

    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_tx_cmd_builder);
    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_tx_doorbell_write);
    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_tfd_push_and_overflow_guard);
    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_tx_queue_enqueue_advances_wptr);
    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_mac_header_management_build);
    kernel_test_in!("drivers/wireless/iwlwifi/tx", smoke_iwlwifi_tx_cmd_ccmp_sec_ctl);
}
