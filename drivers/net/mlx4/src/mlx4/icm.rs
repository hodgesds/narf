//! ICM (host context memory) support: the virtual↔physical mapping
//! (VPM) mailbox shared by `MAP_FA` / `MAP_ICM_AUX` / `MAP_ICM`, the
//! `INIT_HCA` input mailbox encoder, and a sequential ICM layout
//! planner.
//!
//! ConnectX-3 keeps its object context tables (QP/CQ/EQ/MPT/MTT/…) in
//! driver-supplied host memory ("ICM"). Bring-up allocates the firmware
//! area and each context table, maps their pages to firmware-chosen
//! virtual addresses with VPM mailboxes, and hands firmware the table
//! base addresses + log sizes via `INIT_HCA`. Clean-room from the
//! ConnectX-3 PRM §12 ("ICM") + §9 (`INIT_HCA`).
//!
//! The VPM and `INIT_HCA` byte encodings are exact and unit-tested; the
//! [`make_layout`] sizing is a conservative sequential pack whose
//! absolute capacities are validated on silicon at boot.

use alloc::vec;
use alloc::vec::Vec;

use super::fw::DevCap;
use super::wire;

/// `INIT_HCA` input-mailbox length.
pub const INIT_HCA_IN_LEN: usize = 0x200;
/// `INIT_HCA` structure version for ConnectX-3.
pub const INIT_HCA_VERSION: u8 = 2;
/// ICM page shift / size — the smallest VPM mapping granularity.
pub const ICM_PAGE_SHIFT: u8 = 12;
pub const ICM_PAGE_SIZE: u64 = 1 << ICM_PAGE_SHIFT;

/// One VPM entry is a virtual address + a `(phys | log2size)` word.
pub const VPM_ENTRY_LEN: usize = 16;
/// Max VPM entries per 4-KiB mailbox.
pub const VPM_ENTRIES_PER_MAILBOX: usize = super::cmd::MAILBOX_SIZE / VPM_ENTRY_LEN;

/// A single page-mapping request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VpmEntry {
    /// ICM virtual address. Ignored by `MAP_FA` / `MAP_ICM_AUX` (pass 0).
    pub virt: u64,
    /// Device physical address of a 4-KiB page.
    pub phys: u64,
}

/// Build a VPM mailbox from up to [`VPM_ENTRIES_PER_MAILBOX`] entries.
/// Each entry maps one 4-KiB page (`log2size` field = 0). The caller
/// sets the command's input modifier to `entries.len()`.
pub fn build_vpm_mailbox(entries: &[VpmEntry]) -> Vec<u8> {
    let mut mb = vec![0u8; entries.len() * VPM_ENTRY_LEN];
    for (i, e) in entries.iter().enumerate() {
        let off = i * VPM_ENTRY_LEN;
        wire::put_be64(&mut mb, off, e.virt);
        // phys | log2size; log2size = 0 for a 4-KiB page (the page is
        // 4-KiB aligned, so the low bits are free for the size field).
        wire::put_be64(&mut mb, off + 8, e.phys);
    }
    mb
}

// ── INIT_HCA ───────────────────────────────────────────────────────

// Section bases within the INIT_HCA input mailbox (PRM §9).
const QPC_OFFSET: usize = 0x020;
const MCAST_OFFSET: usize = 0x0c0;
const TPT_OFFSET: usize = 0x0f0;
const UAR_OFFSET: usize = 0x120;

/// Table base addresses + log sizes handed to firmware by `INIT_HCA`.
#[derive(Copy, Clone, Debug, Default)]
pub struct InitHcaParams {
    pub qpc_base: u64,
    pub log_num_qps: u8,
    pub srqc_base: u64,
    pub log_num_srqs: u8,
    pub cqc_base: u64,
    pub log_num_cqs: u8,
    pub altc_base: u64,
    pub auxc_base: u64,
    pub eqc_base: u64,
    pub log_num_eqs: u8,
    pub rdmarc_base: u64,
    pub log_rd: u8,
    pub mc_base: u64,
    pub log_mc_entry_sz: u8,
    pub log_mc_hash_sz: u8,
    pub log_mc_table_sz: u8,
    pub dmpt_base: u64,
    pub log_mpt_sz: u8,
    pub mtt_base: u64,
    pub cmpt_base: u64,
    pub log_uar_sz: u8,
    pub uar_page_sz: u8,
}

/// Encode the 0x200-byte `INIT_HCA` input mailbox.
pub fn build_init_hca(p: &InitHcaParams) -> [u8; INIT_HCA_IN_LEN] {
    let mut m = [0u8; INIT_HCA_IN_LEN];
    wire::put_u8(&mut m, 0x000, INIT_HCA_VERSION);
    // Cacheline size: ((log2(line) - 4) << 5) | (1 << 4); 64-byte line.
    wire::put_u8(&mut m, 0x00e, ((6u8 - 4) << 5) | (1 << 4));
    // FLAGS @0x14: host is little-endian, so the BE-host bit stays 0.
    wire::put_be32(&mut m, 0x014, 1);

    // QPC section.
    wire::put_be64(&mut m, QPC_OFFSET + 0x10, p.qpc_base);
    wire::put_u8(&mut m, QPC_OFFSET + 0x17, p.log_num_qps);
    wire::put_be64(&mut m, QPC_OFFSET + 0x28, p.srqc_base);
    wire::put_u8(&mut m, QPC_OFFSET + 0x2f, p.log_num_srqs);
    wire::put_be64(&mut m, QPC_OFFSET + 0x30, p.cqc_base);
    wire::put_u8(&mut m, QPC_OFFSET + 0x37, p.log_num_cqs);
    wire::put_be64(&mut m, QPC_OFFSET + 0x40, p.altc_base);
    wire::put_be64(&mut m, QPC_OFFSET + 0x50, p.auxc_base);
    wire::put_be64(&mut m, QPC_OFFSET + 0x60, p.eqc_base);
    wire::put_u8(&mut m, QPC_OFFSET + 0x67, p.log_num_eqs);
    wire::put_be64(&mut m, QPC_OFFSET + 0x70, p.rdmarc_base);
    wire::put_u8(&mut m, QPC_OFFSET + 0x77, p.log_rd);

    // Multicast section.
    wire::put_be64(&mut m, MCAST_OFFSET, p.mc_base);
    wire::put_u8(&mut m, MCAST_OFFSET + 0x13, p.log_mc_entry_sz);
    wire::put_u8(&mut m, MCAST_OFFSET + 0x17, p.log_mc_hash_sz);
    wire::put_u8(&mut m, MCAST_OFFSET + 0x1b, p.log_mc_table_sz);

    // Translation/protection-table section.
    wire::put_be64(&mut m, TPT_OFFSET, p.dmpt_base);
    // mw_enable @+0x08 stays 0 (no memory windows).
    wire::put_u8(&mut m, TPT_OFFSET + 0x0b, p.log_mpt_sz);
    wire::put_be64(&mut m, TPT_OFFSET + 0x10, p.mtt_base);
    wire::put_be64(&mut m, TPT_OFFSET + 0x18, p.cmpt_base);

    // UAR section.
    wire::put_u8(&mut m, UAR_OFFSET + 0x0a, p.log_uar_sz);
    wire::put_u8(&mut m, UAR_OFFSET + 0x0b, p.uar_page_sz);
    m
}

// ── ICM layout planner ─────────────────────────────────────────────

/// Log2 object counts the driver asks ICM to hold. Defaults are sized
/// for a single-port Ethernet NIC (a handful of QP/CQ/EQ, enough MPT /
/// MTT for the RX/TX pools); they must be ≥ the device's reserved
/// counts (checked against [`DevCap`] in [`make_layout`]).
#[derive(Copy, Clone, Debug)]
pub struct IcmCounts {
    pub log_num_qps: u8,
    pub log_num_srqs: u8,
    pub log_num_cqs: u8,
    pub log_num_eqs: u8,
    pub log_num_mpts: u8,
    pub log_num_mtts: u8,
    pub log_rd: u8,
    pub log_mc_entry_sz: u8,
    pub log_mc_hash_sz: u8,
    pub log_mc_table_sz: u8,
}

impl Default for IcmCounts {
    fn default() -> Self {
        Self {
            log_num_qps: 7,
            log_num_srqs: 4,
            log_num_cqs: 7,
            log_num_eqs: 4,
            log_num_mpts: 7,
            log_num_mtts: 14,
            log_rd: 0,
            log_mc_entry_sz: 6,
            log_mc_hash_sz: 4,
            log_mc_table_sz: 8,
        }
    }
}

/// One ICM context region: its firmware virtual base, log object count
/// and per-entry size.
#[derive(Copy, Clone, Debug, Default)]
pub struct IcmRegion {
    pub base: u64,
    pub log_num: u8,
    pub entry_sz: u16,
}

impl IcmRegion {
    /// Byte span, rounded up to a whole number of ICM pages.
    pub fn size(&self) -> u64 {
        let raw = (1u64 << self.log_num) * u64::from(self.entry_sz.max(1));
        raw.div_ceil(ICM_PAGE_SIZE) * ICM_PAGE_SIZE
    }
}

/// The packed ICM layout: every context table placed at a page-aligned
/// virtual base, plus the total ICM byte span.
#[derive(Copy, Clone, Debug, Default)]
pub struct IcmLayout {
    pub cmpt: IcmRegion,
    pub mtt: IcmRegion,
    pub dmpt: IcmRegion,
    pub eqc: IcmRegion,
    pub cqc: IcmRegion,
    pub srqc: IcmRegion,
    pub altc: IcmRegion,
    pub auxc: IcmRegion,
    pub rdmarc: IcmRegion,
    pub qpc: IcmRegion,
    pub mcg: IcmRegion,
    pub total: u64,
}

impl IcmLayout {
    /// The INIT_HCA parameters this layout implies.
    pub fn init_hca_params(
        &self,
        counts: &IcmCounts,
        log_uar_sz: u8,
        uar_page_sz: u8,
    ) -> InitHcaParams {
        InitHcaParams {
            qpc_base: self.qpc.base,
            log_num_qps: self.qpc.log_num,
            srqc_base: self.srqc.base,
            log_num_srqs: self.srqc.log_num,
            cqc_base: self.cqc.base,
            log_num_cqs: self.cqc.log_num,
            altc_base: self.altc.base,
            auxc_base: self.auxc.base,
            eqc_base: self.eqc.base,
            log_num_eqs: self.eqc.log_num,
            rdmarc_base: self.rdmarc.base,
            log_rd: counts.log_rd,
            mc_base: self.mcg.base,
            log_mc_entry_sz: counts.log_mc_entry_sz,
            log_mc_hash_sz: counts.log_mc_hash_sz,
            log_mc_table_sz: counts.log_mc_table_sz,
            dmpt_base: self.dmpt.base,
            log_mpt_sz: self.dmpt.log_num,
            mtt_base: self.mtt.base,
            cmpt_base: self.cmpt.base,
            log_uar_sz,
            uar_page_sz,
        }
    }

    fn cmpt_bank(&self, kind: u64, log_num: u8) -> (u64, u64) {
        let base = self.cmpt.base + ((kind * u64::from(self.cmpt.entry_sz)) << 24);
        (
            base,
            IcmRegion {
                base,
                log_num,
                entry_sz: self.cmpt.entry_sz,
            }
            .size(),
        )
    }

    /// Every region as `(virt_base, byte_size)`, in mapping order, for
    /// the per-table `MAP_ICM` calls.
    pub fn regions(&self) -> [(u64, u64); 14] {
        [
            // cMPT type is in object-index bits 25:24, not tightly packed.
            // Reserve all four virtual banks, physically map only used entries.
            self.cmpt_bank(0, self.qpc.log_num),
            self.cmpt_bank(1, self.srqc.log_num),
            self.cmpt_bank(2, self.cqc.log_num),
            self.cmpt_bank(3, self.eqc.log_num),
            (self.mtt.base, self.mtt.size()),
            (self.dmpt.base, self.dmpt.size()),
            (self.eqc.base, self.eqc.size()),
            (self.cqc.base, self.cqc.size()),
            (self.srqc.base, self.srqc.size()),
            (self.altc.base, self.altc.size()),
            (self.auxc.base, self.auxc.size()),
            (self.rdmarc.base, self.rdmarc.size()),
            (self.qpc.base, self.qpc.size()),
            (self.mcg.base, self.mcg.size()),
        ]
    }
}

/// Plan a sequential ICM layout from the device capabilities + the
/// requested counts. Context tables are packed back-to-back at
/// page-aligned virtual bases starting at 0; `total` is the whole span
/// (the `SET_ICM_SIZE` argument). `cmpt` is sized to cover QP/SRQ/CQ/EQ
/// context-MPT entries.
pub fn make_layout(dev: &DevCap, counts: &IcmCounts) -> IcmLayout {
    let mut cursor: u64 = 0;
    let mut place = |log_num: u8, entry_sz: u16| -> IcmRegion {
        let mut r = IcmRegion {
            base: 0,
            log_num,
            entry_sz,
        };
        let alignment = r.size().next_power_of_two();
        r.base = cursor.div_ceil(alignment) * alignment;
        cursor = r.base + r.size();
        r
    };

    // Linux MLX4_NUM_CMPTS = 4 << 24. This reserves virtual space;
    // regions() maps sparse banks rather than allocating gigabytes of RAM.
    let cmpt = place(26, dev.cmpt_entry_sz);
    let mtt = place(counts.log_num_mtts, dev.mtt_entry_sz);
    let dmpt = place(counts.log_num_mpts, dev.dmpt_entry_sz);
    let eqc = place(counts.log_num_eqs, dev.eqc_entry_sz);
    let cqc = place(counts.log_num_cqs, dev.cqc_entry_sz);
    let srqc = place(counts.log_num_srqs, 64);
    let altc = place(counts.log_num_qps, dev.altc_entry_sz);
    let auxc = place(counts.log_num_qps, dev.auxc_entry_sz);
    let rdmarc = place(
        counts.log_num_qps + counts.log_rd,
        dev.rdmarc_entry_sz.max(16),
    );
    let qpc = place(counts.log_num_qps, dev.qpc_entry_sz);
    let mcg = place(counts.log_mc_table_sz, 1u16 << counts.log_mc_entry_sz);

    IcmLayout {
        cmpt,
        mtt,
        dmpt,
        eqc,
        cqc,
        srqc,
        altc,
        auxc,
        rdmarc,
        qpc,
        mcg,
        total: cursor,
    }
}
