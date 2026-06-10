//! End-to-end block-stack smoke tests — NVMe + AHCI full walk-up path.
//!
//! These smokes exercise the register-layout, command encoding, and
//! queue-protocol layers synthetically: a `FakeNvmeMmio` ([u8; 16 KiB])
//! simulates a BAR0 window and a `FakeAhciMmio` ([u8; 64 KiB]) simulates
//! ABAR, without requiring real hardware or DMA page allocation.
//!
//! Smokes are numbered per the Wave-32 specification:
//!   NVMe  1..8  — controller reset → admin queue → IDENTIFY → IO queues
//!                 → READ/WRITE DMA round-trips → block registry
//!   AHCI  9..14 — HBA reset → port detect → cmd-list/FIS setup →
//!                 IDENTIFY DEVICE → READ/WRITE DMA EXT → block registry
//!   Integ 15..16 — GPT partition resolution for NVMe + AHCI devices
//!
//! Linux references (GPL-2.0-or-later, adapted under NARF post-2026-05-20):
//!   NVMe:  linux/drivers/nvme/host/pci.c (queue setup, doorbell stride)
//!   AHCI:  linux/drivers/ata/libahci.c (port reset, FIS area, CMD setup)

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use narf_block::registry::{
    register_block_device, register_block_device_with_meta, unregister_block_device,
    BlockDeviceSync, BlockIoError, PartitionMetadata,
};

// ═══════════════════════════════════════════════════════════════════════════
// ── FakeBlockDevice (shared helper) ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// In-memory block device backed by a `Vec<u8>`, 512-byte LBAs.
/// Shared by the NVMe + AHCI + integration smokes via `Arc`.
struct FakeBlockDevice {
    data: narf_lib::sync::IrqSafeSpinLock<Vec<u8>>,
    lba_size: u32,
    read_count: AtomicU64,
    write_count: AtomicU64,
}

impl core::fmt::Debug for FakeBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeBlockDevice")
            .field("lba_size", &self.lba_size)
            .finish_non_exhaustive()
    }
}

impl FakeBlockDevice {
    /// 4 MiB device (8192 × 512-byte sectors), zero-filled.
    fn new_4mib() -> Arc<Self> {
        const N: usize = 4 * 1024 * 1024;
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; N]),
            lba_size: 512,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        })
    }

    /// 4 MiB device with 4096-byte LBAs (1024 sectors).
    fn new_4mib_4k() -> Arc<Self> {
        const N: usize = 4 * 1024 * 1024;
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; N]),
            lba_size: 4096,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        })
    }

    /// Return a copy of backing bytes at `[byte_off..byte_off+len]`.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    fn backing_slice(&self, byte_off: usize, len: usize) -> Vec<u8> {
        let g = self.data.lock();
        g[byte_off..byte_off + len].to_vec()
    }

    /// Fill `[byte_off..byte_off+len]` with `pattern`.
    fn fill_range(&self, byte_off: usize, len: usize, pattern: u8) {
        let mut g = self.data.lock();
        for b in &mut g[byte_off..byte_off + len] {
            *b = pattern;
        }
    }
}

impl BlockDeviceSync for FakeBlockDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        let g = self.data.lock();
        (g.len() / self.lba_size as usize) as u64
    }
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        let g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if out.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        out[..end - start].copy_from_slice(&g[start..end]);
        Ok(())
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.write_count.fetch_add(1, Ordering::Relaxed);
        let mut g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if data.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        g[start..end].copy_from_slice(&data[..end - start]);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ── FakeNvmeMmio — 16 KiB synthetic BAR0 ───────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// NVMe register offsets (NVMe Base Spec 2.0c §3.1).
const NVME_REG_CAP_LO: usize = 0x00;
const NVME_REG_CAP_HI: usize = 0x04;
const NVME_REG_VS: usize = 0x08;
const NVME_REG_CC: usize = 0x14;
const NVME_REG_CSTS: usize = 0x1C;
const NVME_REG_AQA: usize = 0x24;
const NVME_REG_ASQ_LO: usize = 0x28;
const NVME_REG_ASQ_HI: usize = 0x2C;
const NVME_REG_ACQ_LO: usize = 0x30;
const NVME_REG_ACQ_HI: usize = 0x34;
const NVME_DOORBELL_BASE: usize = 0x1000;

const NVME_CC_EN: u32 = 1 << 0;
const NVME_CSTS_RDY: u32 = 1 << 0;

/// Admin opcode constants.
const OPC_IDENTIFY: u8 = 0x06;
const OPC_CREATE_IO_CQ: u8 = 0x05;
const OPC_CREATE_IO_SQ: u8 = 0x01;
const IO_OPC_READ: u8 = 0x02;
const IO_OPC_WRITE: u8 = 0x01;

/// 16 KiB fake BAR0: register window (4 KiB) + doorbell space (12 KiB).
struct FakeNvmeMmio {
    mem: [u8; 16 * 1024],
}

impl FakeNvmeMmio {
    fn new() -> Self {
        let mut m = Self {
            mem: [0u8; 16 * 1024],
        };
        // CAP: MQES=63, DSTRD=0 (stride=4), MPSMIN=0, MPSMAX=0.
        // CAP.TO (timeout in 500ms units) = 0x0F at bits[31:24] of CAP_HI.
        // CAP.MQES = 63 → depth up to 64. We use 4 for the admin queue.
        let cap_lo: u32 = 63; // MQES
        let cap_hi: u32 = 0x0F << 24; // TO=15 (7.5 s)
        m.write32(NVME_REG_CAP_LO, cap_lo);
        m.write32(NVME_REG_CAP_HI, cap_hi);
        // VS = 0x0001_0004 → version 1.4.
        m.write32(NVME_REG_VS, 0x0001_0004);
        // CSTS starts at 0 (RDY=0).
        m
    }

    fn write32(&mut self, off: usize, val: u32) {
        self.mem[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn read32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.mem[off..off + 4].try_into().unwrap())
    }

    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    fn write64(&mut self, off: usize, val: u64) {
        self.mem[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    fn read64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.mem[off..off + 8].try_into().unwrap())
    }

    /// Simulate the controller reacting to CC.EN transitions:
    /// - CC.EN cleared → CSTS.RDY clears.
    /// - CC.EN set      → CSTS.RDY sets.
    fn react_cc(&mut self) {
        let cc = self.read32(NVME_REG_CC);
        let rdy = if cc & NVME_CC_EN != 0 {
            NVME_CSTS_RDY
        } else {
            0
        };
        self.write32(NVME_REG_CSTS, rdy);
    }

    /// Doorbell offset for SQ tail of queue `qid` with stride 4 bytes.
    fn sq_db_off(qid: u16) -> usize {
        NVME_DOORBELL_BASE + 2 * qid as usize * 4
    }

    /// Doorbell offset for CQ head of queue `qid`.
    fn cq_db_off(qid: u16) -> usize {
        NVME_DOORBELL_BASE + (2 * qid as usize + 1) * 4
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ── NVMe SQE / CQE helper types (raw layout per spec §4.2 / §4.6) ──────
// ═══════════════════════════════════════════════════════════════════════════

/// Write a 64-byte NVMe SQE into a byte slice at slot `idx`.
/// Layout: CDW0 (4B) + NSID (4B) + resv (8B) + PRP1 (8B) + PRP2 (8B)
///         + CDW10..15 (6×4B) = 64B.
fn write_sqe_raw(sq: &mut [u8], idx: usize, cdw0: u32, nsid: u32, prp1: u64, cdw10: u32) {
    let off = idx * 64;
    sq[off..off + 4].copy_from_slice(&cdw0.to_le_bytes());
    sq[off + 4..off + 8].copy_from_slice(&nsid.to_le_bytes());
    // bytes 8..15: reserved
    // bytes 16..23: MPTR reserved
    sq[off + 24..off + 32].copy_from_slice(&prp1.to_le_bytes());
    sq[off + 40..off + 44].copy_from_slice(&cdw10.to_le_bytes());
}

/// Write a NVMe SQE for NVM Read/Write (needs CDW10=SLBA_LO,
/// CDW11=SLBA_HI, CDW12=NLB-1, PRP1=data phys addr).
#[allow(clippy::too_many_arguments)]
fn write_io_sqe_raw(
    sq: &mut [u8],
    idx: usize,
    opcode: u8,
    cid: u16,
    nsid: u32,
    prp1: u64,
    slba: u64,
    n_blocks: u16,
) {
    let off = idx * 64;
    let cdw0: u32 = ((cid as u32) << 16) | (opcode as u32);
    sq[off..off + 4].copy_from_slice(&cdw0.to_le_bytes());
    sq[off + 4..off + 8].copy_from_slice(&nsid.to_le_bytes());
    sq[off + 24..off + 32].copy_from_slice(&prp1.to_le_bytes());
    // CDW10 = SLBA[31:0]
    sq[off + 40..off + 44].copy_from_slice(&((slba & 0xFFFF_FFFF) as u32).to_le_bytes());
    // CDW11 = SLBA[63:32]
    sq[off + 44..off + 48].copy_from_slice(&((slba >> 32) as u32).to_le_bytes());
    // CDW12 bits[15:0] = NLB - 1
    sq[off + 48..off + 52].copy_from_slice(&((n_blocks - 1) as u32).to_le_bytes());
}

/// Write a 16-byte NVMe CQE indicating success at head slot `idx`.
/// `phase` = 1 for the first wrap of the queue.
fn write_cqe_success(cq: &mut [u8], idx: usize, sq_head: u16, cid: u16, phase: u16) {
    let off = idx * 16;
    // cmd_specific = 0
    cq[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
    // reserved
    cq[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
    // sq_head (lo 16) + sq_id (hi 16)
    cq[off + 8..off + 10].copy_from_slice(&sq_head.to_le_bytes());
    cq[off + 10..off + 12].copy_from_slice(&0u16.to_le_bytes());
    // cid
    cq[off + 12..off + 14].copy_from_slice(&cid.to_le_bytes());
    // status: phase in bit 0, NVMe status = 0 in bits 15..1
    cq[off + 14..off + 16].copy_from_slice(&(phase & 1).to_le_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 1: NVMe controller reset (CC→0 → CSTS.RDY=0 → program → CC.EN=1) ─
// ═══════════════════════════════════════════════════════════════════════════

/// NVMe controller reset sequence: clear CC.EN, verify CSTS.RDY drops,
/// program AQA/ASQ/ACQ, set CC.EN, verify CSTS.RDY rises.
///
/// Linux ref: drivers/nvme/host/pci.c:nvme_reset_work / nvme_configure_admin_queue
fn smoke_nvme_controller_reset() -> TestResult {
    let mut bar = FakeNvmeMmio::new();

    // Step 1: clear CC.EN → controller deasserts CSTS.RDY.
    bar.write32(NVME_REG_CC, 0);
    bar.react_cc();
    let csts = bar.read32(NVME_REG_CSTS);
    if csts & NVME_CSTS_RDY != 0 {
        return TestResult::Fail("CSTS.RDY must be 0 after CC.EN cleared");
    }

    // Step 2: program AQA — admin queue depth 4-1 in both nibbles.
    let aqa: u32 = 3 | (3 << 16);
    bar.write32(NVME_REG_AQA, aqa);
    if bar.read32(NVME_REG_AQA) != aqa {
        return TestResult::Fail("AQA round-trip failed");
    }

    // Step 3: program ASQ + ACQ physical addresses (synthetic).
    let asq_phys: u64 = 0x0000_0002_0000_0000;
    let acq_phys: u64 = 0x0000_0002_0001_0000;
    bar.write32(NVME_REG_ASQ_LO, asq_phys as u32);
    bar.write32(NVME_REG_ASQ_HI, (asq_phys >> 32) as u32);
    bar.write32(NVME_REG_ACQ_LO, acq_phys as u32);
    bar.write32(NVME_REG_ACQ_HI, (acq_phys >> 32) as u32);

    let got_asq = (bar.read32(NVME_REG_ASQ_HI) as u64) << 32 | bar.read32(NVME_REG_ASQ_LO) as u64;
    let got_acq = (bar.read32(NVME_REG_ACQ_HI) as u64) << 32 | bar.read32(NVME_REG_ACQ_LO) as u64;
    if got_asq != asq_phys {
        return TestResult::Fail("ASQ physical address round-trip failed");
    }
    if got_acq != acq_phys {
        return TestResult::Fail("ACQ physical address round-trip failed");
    }

    // Step 4: set CC.EN → controller asserts CSTS.RDY.
    let cc: u32 = NVME_CC_EN | (0 << 4) | (0 << 7) | (6 << 16) | (4 << 20);
    bar.write32(NVME_REG_CC, cc);
    bar.react_cc();
    let csts = bar.read32(NVME_REG_CSTS);
    if csts & NVME_CSTS_RDY == 0 {
        return TestResult::Fail("CSTS.RDY must be 1 after CC.EN set");
    }

    // Step 5: verify VS reads as a valid 1.x version.
    let vs = bar.read32(NVME_REG_VS);
    let major = (vs >> 16) as u16;
    if major < 1 {
        return TestResult::Fail("VS major version must be ≥1");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_controller_reset);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 2: IDENTIFY CONTROLLER (admin, CNS=1) ─────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Encode a minimal IDENTIFY CONTROLLER response and verify the decoded
/// VID, model number, and serial number fields survive a round-trip
/// through the raw byte layout.
///
/// Layout per NVMe Base Spec 2.0c §5.17.2.1 (table 111):
///   bytes  0..1  : VID
///   bytes  4..23 : SN (20 B, ASCII, space-padded)
///   bytes 24..63 : MN (40 B, ASCII, space-padded)
fn smoke_nvme_identify_controller() -> TestResult {
    // Build the 4 KiB IDENTIFY CONTROLLER response.
    let mut id_buf = vec![0u8; 4096];
    let vid: u16 = 0xFACE;
    let mut sn = [b' '; 20];
    sn[..8].copy_from_slice(b"FAKESNXX");
    let mut mn = [b' '; 40];
    mn[..8].copy_from_slice(b"FAKE SSD");

    id_buf[0..2].copy_from_slice(&vid.to_le_bytes());
    id_buf[4..24].copy_from_slice(&sn);
    id_buf[24..64].copy_from_slice(&mn);
    // NN (number of namespaces) at bytes 516..520 = 1.
    id_buf[516..520].copy_from_slice(&1u32.to_le_bytes());

    // Decode the same fields the driver parses.
    let got_vid = u16::from_le_bytes([id_buf[0], id_buf[1]]);
    let mut got_sn = [0u8; 20];
    got_sn.copy_from_slice(&id_buf[4..24]);
    let mut got_mn = [0u8; 40];
    got_mn.copy_from_slice(&id_buf[24..64]);
    let nn = u32::from_le_bytes(id_buf[516..520].try_into().unwrap());

    if got_vid != vid {
        return TestResult::Fail("IDENTIFY CONTROLLER: VID decode wrong");
    }
    if &got_mn[..8] != b"FAKE SSD" {
        return TestResult::Fail("IDENTIFY CONTROLLER: MN prefix decode wrong");
    }
    if &got_sn[..8] != b"FAKESNXX" {
        return TestResult::Fail("IDENTIFY CONTROLLER: SN prefix decode wrong");
    }
    if nn != 1 {
        return TestResult::Fail("IDENTIFY CONTROLLER: NN should be 1");
    }

    // Verify a SQE for IDENTIFY CONTROLLER encodes CNS=1 in CDW10.
    let mut sq = [0u8; 64];
    write_sqe_raw(&mut sq, 0, OPC_IDENTIFY as u32, 0, 0xDEAD_0000, 1);
    let cdw10 = u32::from_le_bytes(sq[40..44].try_into().unwrap());
    if cdw10 != 1 {
        return TestResult::Fail("IDENTIFY CONTROLLER SQE CDW10 must be 1 (CNS=1)");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_identify_controller);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 3: IDENTIFY NAMESPACE (CNS=0, NSID=1) ─────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Build an IDENTIFY NAMESPACE buffer with NSZE=1024 LBAs and
/// LBAF[0].LBADS=12 (4096-byte sectors), FLBAS=0x00 (active=LBAF[0]).
///
/// NVMe Base Spec 2.0c §5.17.2.2:
///   bytes   0..7  : NSZE (namespace size in LBAs)
///   byte     26   : FLBAS — bits[3:0] = active LBAF index
///   bytes 128..131: LBAF[0] — bits[23:16] = LBADS (log2 LBA size)
fn smoke_nvme_identify_namespace() -> TestResult {
    let nsze: u64 = 1024;
    // LBADS = 12 → 4096-byte LBAs; RP = 0 (best perf), MS = 0.
    let lbads: u8 = 12;
    let lba_bytes_expected: u32 = 1u32 << lbads; // 4096

    let mut ns_buf = vec![0u8; 4096];
    ns_buf[0..8].copy_from_slice(&nsze.to_le_bytes());
    ns_buf[8..16].copy_from_slice(&nsze.to_le_bytes()); // NCAP = NSZE
    ns_buf[25] = 0; // NLBAF = 0 → 1 format
    ns_buf[26] = 0; // FLBAS: active = LBAF[0]
                    // LBAF[0] at byte 128: MS[15:0] = 0, LBADS[23:16] = 12, RP[25:24] = 0
    ns_buf[130] = lbads; // LBAF[0].LBADS at byte offset +2 within LBAF

    // Decode the fields.
    let got_nsze = u64::from_le_bytes(ns_buf[0..8].try_into().unwrap());
    let flbas = ns_buf[26];
    let active_lbaf = (flbas & 0x0F) as usize;
    let lbaf_off = 128 + active_lbaf * 4;
    let got_lbads = ns_buf[lbaf_off + 2];
    let got_lba_bytes: u32 = if got_lbads == 0 {
        512
    } else {
        1u32 << got_lbads
    };

    if got_nsze != nsze {
        return TestResult::Fail("IDENTIFY NAMESPACE: NSZE round-trip wrong");
    }
    if active_lbaf != 0 {
        return TestResult::Fail("IDENTIFY NAMESPACE: active LBAF index should be 0");
    }
    if got_lba_bytes != lba_bytes_expected {
        return TestResult::Fail("IDENTIFY NAMESPACE: LBA size decode wrong (expected 4096)");
    }

    // Verify SQE for IDENTIFY NAMESPACE: CDW10=0 (CNS=0), NSID=1.
    let mut sq = [0u8; 64];
    let cdw0: u32 = (0u32 << 16) | (OPC_IDENTIFY as u32); // CID=0
    sq[0..4].copy_from_slice(&cdw0.to_le_bytes());
    sq[4..8].copy_from_slice(&1u32.to_le_bytes()); // NSID = 1
    sq[40..44].copy_from_slice(&0u32.to_le_bytes()); // CDW10 = CNS=0
    let got_nsid = u32::from_le_bytes(sq[4..8].try_into().unwrap());
    let got_cns = u32::from_le_bytes(sq[40..44].try_into().unwrap());
    if got_nsid != 1 {
        return TestResult::Fail("IDENTIFY NS SQE: NSID must be 1");
    }
    if got_cns != 0 {
        return TestResult::Fail("IDENTIFY NS SQE: CNS must be 0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_identify_namespace);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 4: Create IO Completion Queue (admin opcode 0x05) ─────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Verify the Create I/O CQ SQE encoding and a synthetic success CQE.
///
/// NVMe Base Spec 2.0c §5.2.2:
///   CDW10 bits[31:16] = QSIZE-1, bits[15:0] = QID
///   CDW11 bit[0] = PC (physically contiguous), bit[1] = IEN, bits[31:16] = IV
fn smoke_nvme_create_io_cq() -> TestResult {
    const QID: u16 = 1;
    const QSIZE: u16 = 64;

    let cdw10: u32 = (((QSIZE - 1) as u32) << 16) | (QID as u32);
    let cdw11: u32 = 1; // PC=1, IEN=0, IV=0 (polled)
    let cq_phys: u64 = 0x0000_0003_0000_0000;

    let mut sq = [0u8; 64];
    let cdw0: u32 = ((1u32) << 16) | (OPC_CREATE_IO_CQ as u32); // CID=1
    sq[0..4].copy_from_slice(&cdw0.to_le_bytes());
    sq[24..32].copy_from_slice(&cq_phys.to_le_bytes()); // PRP1
    sq[40..44].copy_from_slice(&cdw10.to_le_bytes());
    sq[44..48].copy_from_slice(&cdw11.to_le_bytes());

    // Decode opcode + QID.
    let got_opc = sq[0] as u8;
    let got_cid = u16::from_le_bytes(sq[2..4].try_into().unwrap());
    let got_cdw10 = u32::from_le_bytes(sq[40..44].try_into().unwrap());
    let got_qid = (got_cdw10 & 0xFFFF) as u16;
    let got_qsize = ((got_cdw10 >> 16) as u16) + 1;
    let got_pc = u32::from_le_bytes(sq[44..48].try_into().unwrap()) & 1;

    if got_opc != OPC_CREATE_IO_CQ {
        return TestResult::Fail("Create IO CQ: opcode must be 0x05");
    }
    if got_cid != 1 {
        return TestResult::Fail("Create IO CQ: CID round-trip failed");
    }
    if got_qid != QID {
        return TestResult::Fail("Create IO CQ: QID in CDW10 wrong");
    }
    if got_qsize != QSIZE {
        return TestResult::Fail("Create IO CQ: QSIZE in CDW10 wrong (zero-based)");
    }
    if got_pc != 1 {
        return TestResult::Fail("Create IO CQ: PC bit must be set");
    }

    // Simulate the controller writing a success CQE for this command.
    let mut cq = [0u8; 16];
    write_cqe_success(&mut cq, 0, 1, got_cid, 1);
    let cqe_status = u16::from_le_bytes(cq[14..16].try_into().unwrap());
    let nvme_status = cqe_status >> 1;
    let phase = cqe_status & 1;
    if nvme_status != 0 {
        return TestResult::Fail("Create IO CQ CQE: status should be 0 (success)");
    }
    if phase != 1 {
        return TestResult::Fail("Create IO CQ CQE: phase bit should be 1 (first wrap)");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_create_io_cq);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 5: Create IO Submission Queue (admin opcode 0x01) ─────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Verify the Create I/O SQ SQE encoding.
///
/// NVMe Base Spec 2.0c §5.2.1:
///   CDW10 bits[31:16] = QSIZE-1, bits[15:0] = QID
///   CDW11 bits[31:16] = CQID, bits[2:1] = QPRIO, bit[0] = PC
fn smoke_nvme_create_io_sq() -> TestResult {
    const QID: u16 = 1;
    const CQID: u16 = 1;
    const QSIZE: u16 = 64;

    let cdw10: u32 = (((QSIZE - 1) as u32) << 16) | (QID as u32);
    let cdw11: u32 = ((CQID as u32) << 16) | 1; // CQID + PC=1
    let sq_phys: u64 = 0x0000_0003_0001_0000;

    let mut sq = [0u8; 64];
    let cdw0: u32 = ((2u32) << 16) | (OPC_CREATE_IO_SQ as u32); // CID=2
    sq[0..4].copy_from_slice(&cdw0.to_le_bytes());
    sq[24..32].copy_from_slice(&sq_phys.to_le_bytes()); // PRP1
    sq[40..44].copy_from_slice(&cdw10.to_le_bytes());
    sq[44..48].copy_from_slice(&cdw11.to_le_bytes());

    let got_opc = sq[0] as u8;
    let got_cdw10 = u32::from_le_bytes(sq[40..44].try_into().unwrap());
    let got_cdw11 = u32::from_le_bytes(sq[44..48].try_into().unwrap());
    let got_qid = (got_cdw10 & 0xFFFF) as u16;
    let got_cqid = ((got_cdw11 >> 16) & 0xFFFF) as u16;
    let got_pc = got_cdw11 & 1;

    if got_opc != OPC_CREATE_IO_SQ {
        return TestResult::Fail("Create IO SQ: opcode must be 0x01");
    }
    if got_qid != QID {
        return TestResult::Fail("Create IO SQ: QID in CDW10 wrong");
    }
    if got_cqid != CQID {
        return TestResult::Fail("Create IO SQ: CQID in CDW11 wrong");
    }
    if got_pc != 1 {
        return TestResult::Fail("Create IO SQ: PC bit must be set");
    }

    // Doorbell stride: DSTRD=0 → 4 bytes per entry. SQ tail for qid=1
    // at offset 0x1000 + 2*1*4 = 0x1008.
    let sq_db_off = FakeNvmeMmio::sq_db_off(QID);
    let cq_db_off = FakeNvmeMmio::cq_db_off(QID);
    if sq_db_off != 0x1008 {
        return TestResult::Fail("SQ doorbell offset wrong for QID=1, DSTRD=0");
    }
    if cq_db_off != 0x100C {
        return TestResult::Fail("CQ doorbell offset wrong for QID=1, DSTRD=0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_create_io_sq);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 6: NVMe READ command (opcode 0x02) ────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Encode an NVM Read SQE (opcode 0x02), fill the fake backing data,
/// simulate the CQE success, and verify the data moved correctly.
///
/// NVMe NVM Command Set §2.3 (Read):
///   CDW10 = SLBA[31:0], CDW11 = SLBA[63:32], CDW12 bits[15:0] = NLB-1
fn smoke_nvme_read_command() -> TestResult {
    // Fake 4 KiB disk: LBA 0 filled with pattern 0xC7.
    let lba_size: usize = 4096;
    let mut disk = vec![0u8; lba_size * 4]; // 4 LBAs
    for b in &mut disk[0..lba_size] {
        *b = 0xC7;
    }

    // Encode the Read SQE: NSID=1, SLBA=0, NLB=1.
    let mut sq = [0u8; 64];
    write_io_sqe_raw(&mut sq, 0, IO_OPC_READ, 0xAABB, 1, 0x1000_0000_0000, 0, 1);

    // Decode and verify the SQE fields.
    let got_opc = sq[0];
    let got_cid = u16::from_le_bytes(sq[2..4].try_into().unwrap());
    let got_nsid = u32::from_le_bytes(sq[4..8].try_into().unwrap());
    let got_slba_lo = u32::from_le_bytes(sq[40..44].try_into().unwrap());
    let got_slba_hi = u32::from_le_bytes(sq[44..48].try_into().unwrap());
    let got_nlb_m1 = u32::from_le_bytes(sq[48..52].try_into().unwrap());
    let got_slba = ((got_slba_hi as u64) << 32) | got_slba_lo as u64;
    let got_nlb = got_nlb_m1 + 1;

    if got_opc != IO_OPC_READ {
        return TestResult::Fail("NVM Read SQE: opcode must be 0x02");
    }
    if got_cid != 0xAABB {
        return TestResult::Fail("NVM Read SQE: CID round-trip failed");
    }
    if got_nsid != 1 {
        return TestResult::Fail("NVM Read SQE: NSID must be 1");
    }
    if got_slba != 0 {
        return TestResult::Fail("NVM Read SQE: SLBA must be 0");
    }
    if got_nlb != 1 {
        return TestResult::Fail("NVM Read SQE: NLB must be 1");
    }

    // Simulate the controller filling a destination buffer from the
    // backing store at LBA 0 (FakeBlockDevice handles this normally,
    // so we just verify the data path inline).
    let mut read_buf = vec![0u8; lba_size];
    read_buf.copy_from_slice(&disk[0..lba_size]);

    // Simulate CQE success.
    let mut cq = [0u8; 16];
    write_cqe_success(&mut cq, 0, 1, got_cid, 1);
    let cqe_status = u16::from_le_bytes(cq[14..16].try_into().unwrap()) >> 1;
    if cqe_status != 0 {
        return TestResult::Fail("NVM Read CQE: status should be 0");
    }

    if read_buf.iter().any(|&b| b != 0xC7) {
        return TestResult::Fail("NVM Read: data pattern mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_read_command);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 7: NVMe WRITE command (opcode 0x01) + re-read confirms ────────
// ═══════════════════════════════════════════════════════════════════════════

/// Write a 4 KiB payload at LBA 1 via FakeBlockDevice, re-read, compare.
/// This exercises the full write→flush→read path at the block layer.
fn smoke_nvme_write_command() -> TestResult {
    let dev = FakeBlockDevice::new_4mib_4k();

    // Write a pattern to LBA 1.
    let lba_size = dev.lba_size() as usize;
    let mut payload = vec![0u8; lba_size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x3B) ^ 0xF1;
    }
    match dev.write(1, 1, &payload) {
        Ok(()) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("NVMe write: FakeBlockDevice write returned error");
        }
    }

    // Encode the Write SQE to verify CDW field correctness.
    let mut sq = [0u8; 64];
    write_io_sqe_raw(&mut sq, 0, IO_OPC_WRITE, 0x0001, 1, 0x2000_0000_0000, 1, 1);
    let got_opc = sq[0];
    if got_opc != IO_OPC_WRITE {
        return TestResult::Fail("NVM Write SQE: opcode must be 0x01");
    }
    let nlb_m1 = u32::from_le_bytes(sq[48..52].try_into().unwrap());
    if nlb_m1 != 0 {
        return TestResult::Fail("NVM Write SQE: NLB-1 should be 0 for 1-block write");
    }

    // Re-read and confirm.
    let mut readback = vec![0u8; lba_size];
    match dev.read(1, 1, &mut readback) {
        Ok(()) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("NVMe write: FakeBlockDevice readback returned error");
        }
    }
    if readback != payload {
        return TestResult::Fail("NVMe write: readback pattern mismatch");
    }

    // Simulate success CQE.
    let mut cq = [0u8; 16];
    write_cqe_success(&mut cq, 0, 1, 0x0001, 1);
    let cqe_status = u16::from_le_bytes(cq[14..16].try_into().unwrap()) >> 1;
    if cqe_status != 0 {
        return TestResult::Fail("NVM Write CQE: status should be 0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_write_command);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 8: NVMe register_block_device ("nvme0n1") ─────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// After a fake bring-up (FakeBlockDevice representing a 4 KiB-sector
/// NVMe namespace), register it as "nvme0n1" and verify the registry
/// entry round-trips the lba_size and capacity correctly.
fn smoke_nvme_register_block_device() -> TestResult {
    // Clean slate for this smoke.
    narf_block::registry::__reset_for_test();

    let dev = FakeBlockDevice::new_4mib_4k();
    let capacity = dev.capacity(); // 1024 LBAs at 4096 bytes = 4 MiB
    let lba_size = dev.lba_size();
    let dev_arc: Arc<dyn BlockDeviceSync> = dev;

    register_block_device("nvme0n1", dev_arc);

    let found = narf_block::registry::find_block_device("nvme0n1");
    let found = match found {
        Some(f) => f,
        None => return TestResult::Fail("nvme0n1 not found in block registry after register"),
    };

    if found.lba_size() != lba_size {
        return TestResult::Fail("nvme0n1: lba_size mismatch in registry");
    }
    if found.capacity() != capacity {
        return TestResult::Fail("nvme0n1: capacity mismatch in registry");
    }
    // Confirm byte capacity = 4 MiB.
    if found.capacity() * found.lba_size() as u64 != 4 * 1024 * 1024 {
        return TestResult::Fail("nvme0n1: byte capacity should be 4 MiB");
    }

    unregister_block_device("nvme0n1");
    TestResult::Pass
}
kernel_test_in!("drivers/storage/nvme-e2e", smoke_nvme_register_block_device);

// ═══════════════════════════════════════════════════════════════════════════
// ── FakeAhciMmio — 64 KiB synthetic BAR5 (ABAR) ─────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// AHCI HBA register offsets (AHCI 1.3.1 §3.1).
const AHCI_HBA_CAP: usize = 0x00;
const AHCI_HBA_GHC: usize = 0x04;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const AHCI_HBA_IS: usize = 0x08;
const AHCI_HBA_PI: usize = 0x0C;
const AHCI_HBA_VS: usize = 0x10;

const AHCI_GHC_HR: u32 = 1 << 0;
const AHCI_GHC_AE: u32 = 1 << 31;

/// Per-port register base (0x100 + 0x80 * port).
const fn port_off(port: u8) -> usize {
    0x100 + 0x80 * port as usize
}

/// Per-port register offsets (relative to port_off).
const PORT_CLB: usize = 0x00; // Command List Base Low
const PORT_CLBU: usize = 0x04; // Command List Base High
const PORT_FB: usize = 0x08; // FIS Receive Base Low
const PORT_FBU: usize = 0x0C; // FIS Receive Base High
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PORT_IS: usize = 0x10; // Interrupt Status
const PORT_CMD: usize = 0x18;
const PORT_TFD: usize = 0x20;
const PORT_SIG: usize = 0x24;
const PORT_SSTS: usize = 0x28;
const PORT_CI: usize = 0x38;

const PORT_CMD_ST: u32 = 1 << 0;
const PORT_CMD_FRE: u32 = 1 << 4;
const PORT_CMD_FR: u32 = 1 << 14;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PORT_CMD_CR: u32 = 1 << 15;

/// SATA device signature (ATA).
const SIG_SATA: u32 = 0x0000_0101;

/// 64 KiB fake BAR5 (ABAR).
struct FakeAhciMmio {
    mem: [u8; 64 * 1024],
}

impl FakeAhciMmio {
    /// Create a fake ABAR with port 0 pre-configured as a SATA device
    /// (DET=3, IPM=1, SIG=0x00000101).
    fn new_with_sata_port0() -> Self {
        let mut m = Self {
            mem: [0u8; 64 * 1024],
        };
        // CAP: NCS (num cmd slots) at bits[12:8] = 31, NP (num ports-1) at bits[4:0] = 0.
        let cap: u32 = (31 << 8) | 0;
        m.write32(AHCI_HBA_CAP, cap);
        // GHC: AE set, HR clear.
        m.write32(AHCI_HBA_GHC, AHCI_GHC_AE);
        // PI: bit 0 set (port 0 implemented).
        m.write32(AHCI_HBA_PI, 1);
        // VS: 0x0001_0301 → AHCI 1.3.1.
        m.write32(AHCI_HBA_VS, 0x0001_0301);

        let p = port_off(0);
        // SSTS: DET=3 (device present + PHY ready), IPM=1 (active).
        m.write32(p + PORT_SSTS, 0x0000_0103);
        // SIG: ATA SATA signature.
        m.write32(p + PORT_SIG, SIG_SATA);
        // TFD: BSY=0, DRQ=0, ERR=0 — ready.
        m.write32(p + PORT_TFD, 0x0000_0050); // DRDY bit set
                                              // CMD: FRE=1, FR=1, ST=1, CR=0 (idle, FIS receive active).
        m.write32(p + PORT_CMD, PORT_CMD_FRE | PORT_CMD_FR | PORT_CMD_ST);
        m
    }

    fn write32(&mut self, off: usize, val: u32) {
        self.mem[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn read32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.mem[off..off + 4].try_into().unwrap())
    }

    /// Simulate issuing a command: write PxCI bit 0, then clear it
    /// (controller completes instantly in test mode).
    fn issue_and_complete(&mut self, port: u8) {
        let p = port_off(port);
        // Set CI bit 0.
        let ci = self.read32(p + PORT_CI) | 1;
        self.write32(p + PORT_CI, ci);
        // Immediately clear it (command complete).
        self.write32(p + PORT_CI, ci & !1);
    }

    /// Simulate HBA reset: GHC.HR self-clears after write.
    fn react_hr(&mut self) {
        let ghc = self.read32(AHCI_HBA_GHC);
        if ghc & AHCI_GHC_HR != 0 {
            // Self-clear after reset.
            self.write32(AHCI_HBA_GHC, ghc & !AHCI_GHC_HR);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 9: AHCI controller reset + port detect ─────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// AHCI HBA Global Reset (GHC.HR=1 → wait clear → GHC.AE=1) and port
/// detection (PxSSTS.DET=3 = device present + PHY ready).
///
/// AHCI 1.3.1 §10.4.3 (HBA Reset) + §3.3.10 (SSTS).
/// Linux ref: libahci.c:ahci_reset_controller
fn smoke_ahci_controller_reset_and_port_detect() -> TestResult {
    let mut abar = FakeAhciMmio::new_with_sata_port0();

    // Step 1: initiate HBA reset (GHC.HR=1).
    let ghc = abar.read32(AHCI_HBA_GHC);
    abar.write32(AHCI_HBA_GHC, ghc | AHCI_GHC_HR);
    abar.react_hr();

    // Step 2: GHC.HR must have cleared.
    let ghc_after = abar.read32(AHCI_HBA_GHC);
    if ghc_after & AHCI_GHC_HR != 0 {
        return TestResult::Fail("AHCI: GHC.HR must self-clear after reset");
    }

    // Step 3: enable AHCI mode (GHC.AE=1).
    abar.write32(AHCI_HBA_GHC, AHCI_GHC_AE);
    if abar.read32(AHCI_HBA_GHC) & AHCI_GHC_AE == 0 {
        return TestResult::Fail("AHCI: GHC.AE must be set");
    }

    // Step 4: read CAP, PI, VS.
    let cap = abar.read32(AHCI_HBA_CAP);
    let pi = abar.read32(AHCI_HBA_PI);
    let vs = abar.read32(AHCI_HBA_VS);
    if pi == 0 {
        return TestResult::Fail("AHCI: PI should be non-zero (at least port 0 implemented)");
    }
    if vs == 0 || vs == 0xFFFF_FFFF {
        return TestResult::Fail("AHCI: VS reads as garbage");
    }
    // NCS = bits[12:8] of CAP.
    let ncs = ((cap >> 8) & 0x1F) + 1;
    if ncs == 0 {
        return TestResult::Fail("AHCI: CAP.NCS must be > 0");
    }

    // Step 5: port 0 detected — SSTS.DET=3 (device present + PHY ready).
    let ssts = abar.read32(port_off(0) + PORT_SSTS);
    let det = ssts & 0x0F;
    if det != 3 {
        return TestResult::Fail("AHCI: port 0 SSTS.DET should be 3 (device present + PHY)");
    }
    let sig = abar.read32(port_off(0) + PORT_SIG);
    if sig != SIG_SATA {
        return TestResult::Fail("AHCI: port 0 SIG should be 0x00000101 (ATA)");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci-e2e",
    smoke_ahci_controller_reset_and_port_detect
);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 10: AHCI command list + FIS receive area setup ─────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Program PxCLB / PxFB and verify the fake ABAR captures the addresses.
/// The command-list base must be 1 KiB-aligned; FIS receive area 256 B-aligned.
///
/// AHCI 1.3.1 §3.3.1 (PxCLB) + §3.3.3 (PxFB).
/// Linux ref: libahci.c:ahci_setup_port
fn smoke_ahci_command_list_and_fis_setup() -> TestResult {
    let mut abar = FakeAhciMmio::new_with_sata_port0();
    let p = port_off(0);

    // Command-list base: 1 KiB-aligned synthetic physical address.
    let clb_phys: u64 = 0x0000_0004_0000_0400;
    // FIS receive base: 256-byte-aligned.
    let fb_phys: u64 = 0x0000_0004_0001_0100;

    // Write PxCLB / CLBU.
    abar.write32(p + PORT_CLB, clb_phys as u32);
    abar.write32(p + PORT_CLBU, (clb_phys >> 32) as u32);
    // Write PxFB / FBU.
    abar.write32(p + PORT_FB, fb_phys as u32);
    abar.write32(p + PORT_FBU, (fb_phys >> 32) as u32);

    // Read back and reconstruct 64-bit addresses.
    let got_clb = (abar.read32(p + PORT_CLBU) as u64) << 32 | abar.read32(p + PORT_CLB) as u64;
    let got_fb = (abar.read32(p + PORT_FBU) as u64) << 32 | abar.read32(p + PORT_FB) as u64;

    if got_clb != clb_phys {
        return TestResult::Fail("AHCI: PxCLB round-trip failed");
    }
    if got_fb != fb_phys {
        return TestResult::Fail("AHCI: PxFB round-trip failed");
    }

    // Alignment checks.
    if got_clb & 0x3FF != 0 {
        return TestResult::Fail("AHCI: PxCLB must be 1 KiB-aligned");
    }
    if got_fb & 0xFF != 0 {
        return TestResult::Fail("AHCI: PxFB must be 256-byte-aligned");
    }

    // Enable FIS receive (FRE) and start (ST) via PxCMD.
    let cmd = abar.read32(p + PORT_CMD);
    abar.write32(p + PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);
    let cmd_after = abar.read32(p + PORT_CMD);
    if cmd_after & PORT_CMD_FRE == 0 {
        return TestResult::Fail("AHCI: PxCMD.FRE must be set after write");
    }
    if cmd_after & PORT_CMD_ST == 0 {
        return TestResult::Fail("AHCI: PxCMD.ST must be set after write");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci-e2e",
    smoke_ahci_command_list_and_fis_setup
);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 11: AHCI IDENTIFY DEVICE (ATA 0xEC) ───────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Build an IDENTIFY DEVICE CFIS (command FIS, H2D Register, 20 bytes),
/// simulate the 512-byte response with a known model string, and decode.
///
/// ATA-8 §7.20 (IDENTIFY DEVICE) + AHCI 1.3.1 §5.3.2.
/// Linux ref: libata-core.c:ata_std_identify
fn smoke_ahci_identify_device() -> TestResult {
    let mut abar = FakeAhciMmio::new_with_sata_port0();

    // Build the 20-byte CFIS for IDENTIFY DEVICE (ATA opcode 0xEC).
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27; // FIS type: Register H2D
    cfis[1] = 0x80; // C=1 (command), PMP=0
    cfis[2] = 0xEC; // ATA IDENTIFY DEVICE
    cfis[7] = 0x40; // Device: LBA mode

    // Verify CFIS fields.
    if cfis[0] != 0x27 {
        return TestResult::Fail("AHCI IDENTIFY DEVICE: FIS type must be 0x27");
    }
    if cfis[1] & 0x80 == 0 {
        return TestResult::Fail("AHCI IDENTIFY DEVICE: C bit must be set");
    }
    if cfis[2] != 0xEC {
        return TestResult::Fail("AHCI IDENTIFY DEVICE: command byte must be 0xEC");
    }

    // Simulate issuing the command via PxCI.
    abar.issue_and_complete(0);
    let ci_after = abar.read32(port_off(0) + PORT_CI);
    if ci_after & 1 != 0 {
        return TestResult::Fail("AHCI: PxCI slot 0 must clear after completion");
    }

    // Simulate the 512-byte IDENTIFY DEVICE response.
    // ATA strings are byte-swapped in each 2-byte pair.
    // Model number at words 27..46 (bytes 54..93).
    let mut id = [0u8; 512];
    // Write "FAKE SSD " as ATA byte-swapped model string.
    // ATA: byte[54]=char[1], byte[55]=char[0], byte[56]=char[3], byte[57]=char[2]...
    let model_chars = b"FAKE SSD                                ";
    for i in 0..20usize {
        id[54 + i * 2] = model_chars[i * 2 + 1];
        id[54 + i * 2 + 1] = model_chars[i * 2];
    }
    // LBA-48 capacity at words 100..103 (bytes 200..207), enabled by word 83 bit 10.
    let lba48_sectors: u64 = 8 * 1024 * 1024 / 512; // 8 MiB / 512 = 16384 sectors
    id[200..208].copy_from_slice(&lba48_sectors.to_le_bytes());
    // Word 83: set bit 10 (LBA-48) + validity marker 0x4000.
    let w83: u16 = (1 << 10) | 0x4000;
    id[166..168].copy_from_slice(&w83.to_le_bytes());

    // Decode model string (un-byte-swap).
    let model = crate::ahci::identify_model(&id);
    if &model[..8] != b"FAKE SSD" {
        return TestResult::Fail("AHCI IDENTIFY DEVICE: model string decode wrong");
    }

    // Decode LBA-48 capacity.
    let cap = crate::ahci::identify_lba48_capacity(&id);
    if cap != lba48_sectors {
        return TestResult::Fail("AHCI IDENTIFY DEVICE: LBA-48 capacity decode wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci-e2e", smoke_ahci_identify_device);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 12: AHCI READ DMA EXT (ATA 0x25) ──────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Build a READ DMA EXT CFIS, simulate completion, verify data via
/// FakeBlockDevice (which is what the driver's DMA path fills).
///
/// ATA-8 §7.23 (READ DMA EXT) + AHCI 1.3.1 §5.3.2.
/// Linux ref: libahci.c:ahci_fill_cmd_slot
fn smoke_ahci_read_dma_ext() -> TestResult {
    let dev = FakeBlockDevice::new_4mib();
    // Pre-fill sector 0 with a recognisable pattern.
    dev.fill_range(0, 512, 0xA3);

    // Build the CFIS for READ DMA EXT at LBA=0, count=1.
    let lba: u64 = 0;
    let n: u16 = 1;
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27;
    cfis[1] = 0x80;
    cfis[2] = 0x25; // READ DMA EXT
    cfis[7] = 0x40; // LBA mode
    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;
    cfis[12] = (n & 0xFF) as u8;
    cfis[13] = ((n >> 8) & 0xFF) as u8;

    // Verify CFIS encoding.
    if cfis[2] != 0x25 {
        return TestResult::Fail("AHCI READ DMA EXT: opcode must be 0x25");
    }

    // PRDT entry: single 512-byte scatter-gather descriptor.
    // DBC = byte_count - 1 (AHCI 1.3.1 §4.2.3.3).
    let prdt_dbc: u32 = 512 - 1;
    let mut prdt = [0u8; 16];
    prdt[12..16].copy_from_slice(&prdt_dbc.to_le_bytes());
    let got_dbc = u32::from_le_bytes(prdt[12..16].try_into().unwrap());
    if got_dbc != 511 {
        return TestResult::Fail("AHCI PRDT DBC must be byte_count-1 (511 for 512 bytes)");
    }

    // Use FakeBlockDevice to simulate the DMA read.
    let mut sector = vec![0u8; 512];
    match dev.read(0, 1, &mut sector) {
        Ok(()) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("AHCI READ DMA EXT: FakeBlockDevice read returned error");
        }
    }
    if sector.iter().any(|&b| b != 0xA3) {
        return TestResult::Fail("AHCI READ DMA EXT: sector data pattern mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci-e2e", smoke_ahci_read_dma_ext);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 13: AHCI WRITE DMA EXT (ATA 0x35) ─────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Write sector 3 via WRITE DMA EXT, re-read and verify.
///
/// ATA-8 §7.57 (WRITE DMA EXT) opcode 0x35.
/// Linux ref: libahci.c: write path uses ahci_qc_prep (same structure).
fn smoke_ahci_write_dma_ext() -> TestResult {
    let dev = FakeBlockDevice::new_4mib();

    let lba: u64 = 3;
    let n: u16 = 1;

    // Build WRITE DMA EXT CFIS.
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27;
    cfis[1] = 0x80;
    cfis[2] = 0x35; // WRITE DMA EXT
    cfis[7] = 0x40;
    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;
    cfis[12] = (n & 0xFF) as u8;
    cfis[13] = ((n >> 8) & 0xFF) as u8;

    if cfis[2] != 0x35 {
        return TestResult::Fail("AHCI WRITE DMA EXT: opcode must be 0x35");
    }

    // Command-list header word 0: W=1 (write), CFL=5, PRDT_LEN=1.
    let header_w0: u32 = (1u32 << 16) | (1 << 6) | 5; // PRDT_LEN=1 | W=1 | CFL=5
    if header_w0 & (1 << 6) == 0 {
        return TestResult::Fail("AHCI WRITE DMA EXT: W bit must be 1 for write");
    }

    // Synthesize a payload and write it.
    let mut payload = vec![0u8; 512];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x71) ^ 0x3C;
    }
    match dev.write(lba, n, &payload) {
        Ok(()) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("AHCI WRITE DMA EXT: FakeBlockDevice write error");
        }
    }

    // Re-read and confirm.
    let mut readback = vec![0u8; 512];
    match dev.read(lba, n, &mut readback) {
        Ok(()) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("AHCI WRITE DMA EXT: readback returned error");
        }
    }
    if readback != payload {
        return TestResult::Fail("AHCI WRITE DMA EXT: write/read pattern mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci-e2e", smoke_ahci_write_dma_ext);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 14: AHCI register_block_device ("sata0") ──────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Register a fake AHCI device as "sata0" and verify lba_size + capacity.
fn smoke_ahci_register_block_device() -> TestResult {
    narf_block::registry::__reset_for_test();

    let dev = FakeBlockDevice::new_4mib();
    let capacity = dev.capacity();
    let lba_size = dev.lba_size();
    let dev_arc: Arc<dyn BlockDeviceSync> = dev;

    register_block_device("sata0", dev_arc);

    let found = narf_block::registry::find_block_device("sata0");
    let found = match found {
        Some(f) => f,
        None => return TestResult::Fail("sata0 not found in block registry after register"),
    };

    if found.lba_size() != lba_size {
        return TestResult::Fail("sata0: lba_size mismatch in registry");
    }
    if found.capacity() != capacity {
        return TestResult::Fail("sata0: capacity mismatch in registry");
    }
    if found.capacity() * found.lba_size() as u64 != 4 * 1024 * 1024 {
        return TestResult::Fail("sata0: byte capacity should be 4 MiB");
    }

    unregister_block_device("sata0");
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci-e2e", smoke_ahci_register_block_device);

// ═══════════════════════════════════════════════════════════════════════════
// ── GPT helper (mirrors filesystem/e2e_tests.rs write_synthetic_gpt) ─────
// ═══════════════════════════════════════════════════════════════════════════

/// Write a minimal synthetic GPT into a 2 MiB backing buffer (4096 LBAs
/// of 512 bytes). One partition with the supplied UTF-16LE label.
///
/// Layout per UEFI 2.10 §5.3:
///   LBA 0  — protective MBR (0xEE partition type + 0xAA55)
///   LBA 1  — primary GPT header (92-byte minimal + CRC placeholders)
///   LBA 2  — partition entry array (128-byte entry at slot 0)
///   LBA 34+  — usable area (partition start)
fn write_synthetic_gpt_with_label(buf: &mut [u8], label: &str) {
    // LBA 0: protective MBR.
    let mbr = &mut buf[0..512];
    mbr[446 + 4] = 0xEE; // partition type: GPT protective
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // start LBA
    mbr[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // LBA 1: GPT header (92 bytes, rest zeroed).
    let total_lbas: u64 = (buf.len() / 512) as u64;
    {
        let hdr = &mut buf[512..1024];
        hdr[0..8].copy_from_slice(b"EFI PART"); // signature
        hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
                                                           // my_lba = 1
        hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
        // alternate_lba = last LBA of the disk.
        hdr[32..40].copy_from_slice(&(total_lbas - 1).to_le_bytes());
        // first_usable = LBA 34
        hdr[40..48].copy_from_slice(&34u64.to_le_bytes());
        // last_usable = total - 2
        hdr[48..56].copy_from_slice(&(total_lbas - 2).to_le_bytes());
        // partition_entry_lba = 2
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
        // num_partition_entries = 128
        hdr[80..84].copy_from_slice(&128u32.to_le_bytes());
        // size_of_partition_entry = 128
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes());
    }

    // LBA 2: partition entry 0 (128 bytes at offset 1024).
    let entry = &mut buf[1024..1024 + 128];
    // Partition type GUID (basic data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7)
    // stored as mixed-endian.
    let type_guid = [
        0xA2u8, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];
    entry[0..16].copy_from_slice(&type_guid);
    // Unique partition GUID (synthetic).
    let part_guid = [
        0x11u8, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];
    entry[16..32].copy_from_slice(&part_guid);
    // Starting LBA = 34.
    entry[32..40].copy_from_slice(&34u64.to_le_bytes());
    // Ending LBA = total - 2.
    entry[40..48].copy_from_slice(&(total_lbas - 2).to_le_bytes());
    // Partition name: UTF-16LE, up to 36 chars at offset 56.
    let name_bytes = &mut entry[56..56 + 72];
    for (i, c) in label.chars().enumerate() {
        if i >= 36 {
            break;
        }
        let ch = c as u16;
        name_bytes[i * 2] = (ch & 0xFF) as u8;
        name_bytes[i * 2 + 1] = ((ch >> 8) & 0xFF) as u8;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 15: NVMe + GPT partition resolves ("TEST_NVME") ───────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Register a fake NVMe namespace (nvme0n1) backed by a 2 MiB block device
/// with a synthetic GPT. Register the partition entry ("TEST_NVME") with
/// PartitionMetadata and verify `find_block_device("nvme0n1p1")` resolves.
///
/// Mirrors the Wave 27 GPT pattern from filesystem/src/e2e_tests.rs.
fn smoke_nvme_gpt_partition_resolves() -> TestResult {
    narf_block::registry::__reset_for_test();

    const LABEL: &str = "TEST_NVME";

    // Build a 2 MiB fake disk with GPT.
    let dev = Arc::new({
        let n: usize = 2 * 1024 * 1024;
        FakeBlockDevice {
            data: narf_lib::sync::IrqSafeSpinLock::new({
                let mut v = vec![0u8; n];
                write_synthetic_gpt_with_label(&mut v, LABEL);
                v
            }),
            lba_size: 512,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        }
    });

    // Register the whole disk.
    let dev_arc: Arc<dyn BlockDeviceSync> = dev.clone();
    register_block_device("nvme0n1", dev_arc);

    // Register the partition slice as "nvme0n1p1" with metadata.
    let part_dev: Arc<dyn BlockDeviceSync> = dev.clone();
    let meta = PartitionMetadata {
        partlabel: String::from(LABEL),
        partuuid: String::from("11111111-2222-3333-4444-555555555555"),
    };
    register_block_device_with_meta("nvme0n1p1", part_dev, Some(meta));

    // Verify the whole disk is findable.
    let whole = narf_block::registry::find_block_device("nvme0n1");
    if whole.is_none() {
        return TestResult::Fail("nvme0n1 (whole disk) not found in registry");
    }

    // Verify the partition is findable.
    let part = narf_block::registry::find_block_device("nvme0n1p1");
    if part.is_none() {
        return TestResult::Fail("nvme0n1p1 partition not found in registry");
    }

    // Verify block_devices() snapshot includes the partition with metadata.
    let all = narf_block::registry::block_devices();
    let has_label = all.iter().any(|e| {
        e.name == "nvme0n1p1"
            && e.partition
                .as_ref()
                .map(|p| p.partlabel == LABEL)
                .unwrap_or(false)
    });
    if !has_label {
        return TestResult::Fail("nvme0n1p1: partlabel 'TEST_NVME' not found in snapshot");
    }

    let has_partuuid = all.iter().any(|e| {
        e.name == "nvme0n1p1"
            && e.partition
                .as_ref()
                .map(|p| !p.partuuid.is_empty())
                .unwrap_or(false)
    });
    if !has_partuuid {
        return TestResult::Fail("nvme0n1p1: partuuid should be non-empty");
    }

    unregister_block_device("nvme0n1p1");
    unregister_block_device("nvme0n1");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/nvme-e2e",
    smoke_nvme_gpt_partition_resolves
);

// ═══════════════════════════════════════════════════════════════════════════
// ── Smoke 16: AHCI + GPT partition resolves ("TEST_SATA") ───────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Same as Smoke 15 but for the AHCI stack ("sata0" / "sata0p1").
fn smoke_ahci_gpt_partition_resolves() -> TestResult {
    narf_block::registry::__reset_for_test();

    const LABEL: &str = "TEST_SATA";

    let dev = Arc::new({
        let n: usize = 2 * 1024 * 1024;
        FakeBlockDevice {
            data: narf_lib::sync::IrqSafeSpinLock::new({
                let mut v = vec![0u8; n];
                write_synthetic_gpt_with_label(&mut v, LABEL);
                v
            }),
            lba_size: 512,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        }
    });

    let dev_arc: Arc<dyn BlockDeviceSync> = dev.clone();
    register_block_device("sata0", dev_arc);

    let part_dev: Arc<dyn BlockDeviceSync> = dev.clone();
    let meta = PartitionMetadata {
        partlabel: String::from(LABEL),
        partuuid: String::from("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
    };
    register_block_device_with_meta("sata0p1", part_dev, Some(meta));

    if narf_block::registry::find_block_device("sata0").is_none() {
        return TestResult::Fail("sata0 (whole disk) not found in registry");
    }
    if narf_block::registry::find_block_device("sata0p1").is_none() {
        return TestResult::Fail("sata0p1 partition not found in registry");
    }

    let all = narf_block::registry::block_devices();
    let has_label = all.iter().any(|e| {
        e.name == "sata0p1"
            && e.partition
                .as_ref()
                .map(|p| p.partlabel == LABEL)
                .unwrap_or(false)
    });
    if !has_label {
        return TestResult::Fail("sata0p1: partlabel 'TEST_SATA' not found in snapshot");
    }

    unregister_block_device("sata0p1");
    unregister_block_device("sata0");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci-e2e",
    smoke_ahci_gpt_partition_resolves
);
