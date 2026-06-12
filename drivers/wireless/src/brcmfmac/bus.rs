//! `brcmfmac` PCIe bus bring-up — firmware download + ring init + MSI-X.
//!
//! This file orchestrates the Stage-7..Stage-9 pieces (`ringbuf`,
//! `firmware`, `shared`, `connect`) into the full PCIe-attached chip
//! bring-up sequence Linux runs in
//! `brcmf_pcie_setup` → `brcmf_pcie_download_fw_nvram` →
//! `brcmf_pcie_init_share_ram_info` → `brcmf_pcie_init_ringbuffers`.
//!
//! ## Sequence
//!
//! 1. **BAR0 + BAR2 map** — already done by `pcie.rs::bring_up` (BAR0
//!    register window) + a follow-up BAR2 (TCM) map landed here.
//! 2. **Halt ARM** — `brcmf_pcie_enter_download_state` clears the
//!    ARM cm3 reset bit so the host can scribble RAM.
//! 3. **FW blob → ci->rambase** — straight `memcpy_toio` of the
//!    image; for raw blobs (PCIe path) this is the entire file.
//! 4. **NVRAM (if any) → rambase + ramsize - nvram_len** —
//!    appended to the end of RAM.
//! 5. **Optional random seed** — for fwseed-enabled chips, prepend a
//!    256-byte seed before the NVRAM.
//! 6. **Release ARM** — `brcmf_pcie_exit_download_state` writes the
//!    reset-int vector + lets the cm3 run.
//! 7. **Wait for shared-RAM addr** — poll the last 4 bytes of RAM
//!    until non-zero; that's the TCM address of the SharedInfo block.
//! 8. **Parse SharedInfo** — version + flags + ringinfo pointer.
//! 9. **Parse RingInfo + RingMem table** — allocate per-ring DMA
//!    buffers + register them with the firmware.
//! 10. **Allocate scratch / ringupd buffers** — DMA-coherent host RAM.
//! 11. **Allocate MSI-X vector** — route DB0/DB1 to a host IRQ vector.
//! 12. **Drive HOSTRDY doorbell** — write to H2D_MAILBOX_1 (or DB0)
//!     to tell the firmware the host is ready for IOCTL traffic.
//!
//! At step 12 the chip transitions to `BRCMFMAC_PCIE_STATE_UP` and
//! the connect orchestrator from [`super::connect`] can drive a
//! SET_SSID without further setup.
//!
//! ## References
//!
//! - Linux `brcmfmac/pcie.c`:
//!     - `brcmf_pcie_setup`              (~L2150..L2220)
//!     - `brcmf_pcie_download_fw_nvram`  (~L1689..L1780)
//!     - `brcmf_pcie_init_share_ram_info` (~L1617..L1670)
//!     - `brcmf_pcie_init_ringbuffers`   (~L1218..L1360)
//!     - `brcmf_pcie_alloc_dma_and_ring` (~L1158..L1196)
//!     - `brcmf_pcie_request_irq`        (~L948..L998)

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::firmware::{embedded_ramsize, parse_nvram};
use super::msgbuf::{
    ring_layout, D2H_MSGRING_CONTROL_COMPLETE, D2H_MSGRING_RX_COMPLETE, D2H_MSGRING_TX_COMPLETE,
    H2D_MSGRING_CONTROL_SUBMIT, H2D_MSGRING_RXPOST_SUBMIT, NROF_COMMON_MSGRINGS,
};
use super::ringbuf::RingBuf;
use super::shared::{RingInfo, SharedInfo, RING_MEM_SZ};

// ── Boot-time errors ───────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// BAR2 (TCM window) couldn't be mapped or has zero length.
    Bar2MapFailed,
    /// Embedded RAM-size hint disagrees with the host's stored value.
    RamSizeMismatch,
    /// Firmware didn't post a SharedInfo address within the timeout.
    FwStartTimeout,
    /// SharedInfo decode failed (bad version / short read).
    SharedInfoBadVersion,
    /// RingInfo block at the shared-info address didn't parse.
    RingInfoParseFailed,
    /// max_flowrings > 512 — invalid firmware advertisement.
    TooManyFlowrings,
    /// DMA-coherent allocation for a ring buffer failed.
    DmaAllocFailed,
    /// MSI-X vector allocation failed.
    MsiXAllocFailed,
}

// ── Per-ring DMA descriptor (planning view) ────────────────────────
//
// The bring-up planner builds one of these per common ring before
// touching the allocator. The actual `RingBuf` is constructed once the
// DMA-coherent backing store is in hand.

/// Planned shape of a per-ring DMA allocation. Used by the bring-up
/// orchestrator to size the buffer pool before issuing allocator
/// calls.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PlannedRing {
    pub id: u8,
    pub depth: u16,
    pub item_len: u16,
    /// Number of bytes the DMA-coherent slot array needs.
    pub buf_size: u32,
    /// True if the host produces (H2D), false if the host consumes (D2H).
    pub is_h2d: bool,
}

impl PlannedRing {
    pub const fn from_layout(id: u8, depth: u16, item_len: u16, is_h2d: bool) -> Self {
        Self {
            id,
            depth,
            item_len,
            buf_size: (depth as u32) * (item_len as u32),
            is_h2d,
        }
    }
}

/// Build the 5-entry plan for the common rings, picking the
/// appropriate item sizes for `pre_v7` firmware.
pub fn plan_common_rings(pre_v7: bool) -> [PlannedRing; NROF_COMMON_MSGRINGS] {
    let ids = [
        H2D_MSGRING_CONTROL_SUBMIT,
        H2D_MSGRING_RXPOST_SUBMIT,
        D2H_MSGRING_CONTROL_COMPLETE,
        D2H_MSGRING_TX_COMPLETE,
        D2H_MSGRING_RX_COMPLETE,
    ];
    let mut plan = [PlannedRing::from_layout(0, 0, 0, false); NROF_COMMON_MSGRINGS];
    let mut i = 0;
    while i < NROF_COMMON_MSGRINGS {
        let layout = match ring_layout(ids[i], pre_v7) {
            Some(l) => l,
            None => unreachable!(),
        };
        plan[i] = PlannedRing::from_layout(layout.id, layout.depth, layout.item_len, layout.is_h2d);
        i += 1;
    }
    plan
}

// ── DMA address plan for the per-ring index slots ──────────────────
//
// When the firmware advertises DMA-indices (`SHARED_FLAG_DMA_INDEX`),
// the host allocates one contiguous buffer that holds:
//
//   [h2d_w_idx ... × max_submission]
//   [h2d_r_idx ... × max_submission]
//   [d2h_w_idx ... × max_completion]
//   [d2h_r_idx ... × max_completion]
//
// `idx_size` is either 2 or 4 bytes depending on
// `SHARED_FLAG_DMA_2B_IDX`. The total size is
// `(max_submission + max_completion) * idx_size * 2`.

/// Compute the contiguous DMA-indices buffer size for the given
/// firmware ring-counts + idx width.
pub fn idx_buffer_size(max_submission: u16, max_completion: u16, idx_size: u8) -> u32 {
    ((max_submission as u32) + (max_completion as u32)) * (idx_size as u32) * 2
}

/// Compute the per-ring W-index TCM offset table when the firmware
/// uses DMA-indices. Returns a vec of (W_idx_addr, R_idx_addr) pairs in
/// ring-id order: 2 H2D rings followed by 3 D2H rings (= 5 entries).
///
/// `base` is the host-phys address of the contiguous idx buffer.
/// `max_submission` is the firmware-advertised count of H2D rings.
/// `max_completion` is the firmware-advertised count of D2H rings.
pub fn idx_addr_table(
    base: u64,
    max_submission: u16,
    max_completion: u16,
    idx_size: u8,
) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(NROF_COMMON_MSGRINGS);
    let stride = idx_size as u64;
    let h2d_w_base = base;
    let h2d_r_base = h2d_w_base + (max_submission as u64) * stride;
    let d2h_w_base = h2d_r_base + (max_submission as u64) * stride;
    let d2h_r_base = d2h_w_base + (max_completion as u64) * stride;
    // H2D rings: 2 entries.
    for i in 0..2u64 {
        out.push((h2d_w_base + i * stride, h2d_r_base + i * stride));
    }
    // D2H rings: 3 entries.
    for i in 0..3u64 {
        out.push((d2h_w_base + i * stride, d2h_r_base + i * stride));
    }
    out
}

// ── BAR2 (TCM) window helper ──────────────────────────────────────

/// Wrapper that owns the BAR2 (TCM / dongle RAM) mapping. The full
/// `BrcmfmacDevice` aggregates one of these alongside the BAR0
/// register-window in `pcie.rs`.
#[derive(Debug)]
pub struct TcmWindow {
    pub host_base: *mut u8,
    pub size: u64,
}

// SAFETY: `host_base` is a kernel-owned MMIO mapping of BAR2 (TCM),
// valid for the lifetime of the device; the raw pointer is not tied
// to any thread-local state, so moving the window across threads is
// sound.
unsafe impl Send for TcmWindow {}
// SAFETY: TCM accesses go through `read_volatile`/`write_volatile`
// against the device's own RAM window; concurrent access is the
// caller's responsibility (guarded by the device lock), and the
// pointer itself is immutable after mapping, so `&TcmWindow` is safe
// to share between threads.
unsafe impl Sync for TcmWindow {}

impl TcmWindow {
    /// Sample of the last 4 bytes of TCM — used to poll for the
    /// firmware-side SharedInfo address handshake after boot.
    /// Returns 0 if the device is still booting (firmware hasn't
    /// posted yet) or the host base is null (test build).
    pub fn read_shared_addr_tail(&self, ram_size: u32) -> u32 {
        if self.host_base.is_null() || ram_size < 4 {
            return 0;
        }
        // SAFETY: TCM is mapped, caller asserts `ram_size` fits inside
        // the BAR2 window.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let p = self.host_base.add(ram_size as usize - 4) as *const u32;
            core::ptr::read_volatile(p)
        }
    }
}

// ── Stage-summary helper ──────────────────────────────────────────

/// Snapshot of the bring-up state after each phase. The orchestrator
/// fills these in incrementally; the smoke tests assert on the
/// individual fields. Helps keep the state machine debuggable when
/// the live silicon doesn't behave.
#[derive(Debug, Default)]
pub struct BringUpState {
    pub bar0_mapped: bool,
    pub bar2_mapped: bool,
    pub fw_downloaded: bool,
    pub nvram_uploaded: bool,
    pub arm_running: bool,
    pub shared_info: Option<SharedInfo>,
    pub ring_info: Option<RingInfo>,
    pub common_rings: Vec<RingBuf>,
    pub msix_vector: Option<u32>,
    pub host_ready_signalled: bool,
}

/// Plan + verify the bring-up using only the inputs available before
/// any DMA allocator is called. Useful for pre-flight checks on
/// firmware blobs / NVRAM files / shared-info advertisements.
pub fn preflight(
    fw_blob: &[u8],
    nvram_text: &[u8],
    shared_bytes: &[u8],
    ring_info_bytes: &[u8],
) -> Result<(SharedInfo, RingInfo, [PlannedRing; NROF_COMMON_MSGRINGS]), BringUpError> {
    // FW blob can carry an embedded RAM-size override.
    let _ = embedded_ramsize(fw_blob);

    let _nvram = parse_nvram(nvram_text);
    let shared = SharedInfo::parse(shared_bytes).ok_or(BringUpError::SharedInfoBadVersion)?;
    let ring_info = RingInfo::parse(ring_info_bytes).ok_or(BringUpError::RingInfoParseFailed)?;
    if ring_info.max_flowrings > 512 {
        return Err(BringUpError::TooManyFlowrings);
    }
    let plan = plan_common_rings(shared.pre_v7());
    Ok((shared, ring_info, plan))
}

// ── Per-ring memory map (one entry into the RingMem table) ────────
//
// Each common ring's per-ring 16-byte entry in the RingMem table
// carries the max_item / len_items / base_addr fields. The driver
// builds the entries before writing them to TCM.

/// Build one 16-byte ring-mem entry for write to TCM.
///
/// Reference: Linux pcie.c `BRCMF_RING_MEM_*_OFFSET` (~L244..L247) +
/// `brcmf_pcie_init_ringbuffers` (~L1316) which advances
/// `ring_mem_ptr += BRCMF_RING_MEM_SZ` for each common ring.
pub fn encode_ring_mem_entry(max_item: u16, len_items: u16, base_addr: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    // bytes 0..4 are reserved / zero (Linux fields not exposed here).
    out[4..6].copy_from_slice(&max_item.to_le_bytes());
    out[6..8].copy_from_slice(&len_items.to_le_bytes());
    out[8..16].copy_from_slice(&base_addr.to_le_bytes());
    out
}

/// Decode the 16-byte ring-mem entry the host previously wrote.
/// Useful for the boot-smoke verify pass that confirms the firmware
/// hasn't clobbered the table.
pub fn decode_ring_mem_entry(bytes: &[u8]) -> Option<(u16, u16, u64)> {
    use core::convert::TryInto;
    if bytes.len() < RING_MEM_SZ as usize {
        return None;
    }
    let max_item = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let len_items = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let base_addr = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    Some((max_item, len_items, base_addr))
}
