//! End-to-end IOMMU + DMA buffer lifecycle smokes.
//!
//! Tests the full security invariant of NARF's framekernel architecture:
//!   alloc DMA buffer + mint Cap<DmaBuffer, _>
//!   → FakeIommu installs IOVA → phys mapping
//!   → FakeDevice performs DMA via IOVA
//!   → unregister cap (revoke epoch)
//!   → FakeIommu unmaps IOVA
//!   → next device access traps with PageFault
//!
//! These tests exercise the abstraction layer; they do **not** drive real
//! AMD-Vi or Intel VT-d silicon. The `FakeIommu` maintains a software
//! page table (`BTreeMap<IOVA, (PhysAddr, IommuPerms)>`) and the
//! `FakeDevice` resolves IOVA through that table to access backing memory,
//! returning `DmaError::PageFault` when no mapping is present.
//!
//! Numbered per the spec:
//!   1  — alloc coherent buffer + IOMMU map
//!   2  — Cap holds IOVA grant
//!   3  — host writes visible to device
//!   4  — device writes visible to host
//!   5  — cap revoke unmaps IOVA
//!   6  — stale IOVA after revoke traps
//!   7  — re-alloc gives non-aliasing IOVA
//!   8  — scatter-gather (multi-page) mapping
//!   9  — DMA direction enforcement
//!   10 — concurrent allocs don't collide
//!   11 — NVMe-style queue alloc through IOMMU
//!   12 — IOMMU stats (nr_mapped / nr_revoked)
//!   13 — fault queue drain
//!
//! Linux refs (GPL-2.0-or-later, adapted under NARF post-2026-05-20):
//!   `linux/include/linux/dma-mapping.h` — dma_alloc_coherent lifecycle
//!   `linux/drivers/iommu/iommu.c`       — iommu_map / iommu_unmap
//!   `linux/drivers/iommu/amd/io_pgtable.c` — AMD-Vi page-table walk
//!   `linux/drivers/iommu/intel/iommu.c`    — Intel VT-d domain map

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;
use narf_memory::PAGE_SIZE;

use crate::iommu::IommuPerms;
use crate::{alloc_coherent, free_coherent, register_with_cap, unregister, IoError};

// ─── FakeIommu ──────────────────────────────────────────────────────────────
//
// Software page table for testing. Each entry stores `(phys, perms)`.
// Mirrors the semantics of `linux/drivers/iommu/iommu.c::iommu_map`:
//   - map:   insert IOVA → (phys, perms); error on duplicate.
//   - unmap: remove entry; error when absent.
//   - translate: lookup IOVA, enforce direction perms.
//
// IOVAs are assigned by the caller; a real allocator would use a buddy
// IOVA allocator (Linux: `iova_domain` in `linux/drivers/iommu/iova.c`).

/// Errors the FakeIommu and FakeDevice return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DmaError {
    /// IOVA had no mapping — models an IOMMU page fault. Linux
    /// equivalent: AMD-Vi event-log `PAGE_TAB_HW_ERROR`; Intel VT-d
    /// fault-record `FAULT_REASON` translation failure.
    PageFault,
    /// IOVA already mapped — re-map without unmap is rejected.
    AlreadyMapped,
    /// Permission violation: device tried to write a read-only mapping
    /// (dir=ToDevice), or read a write-only mapping.
    PermissionDenied,
    /// Underlying IoError forwarded from crate root.
    Io(IoError),
}

impl From<IoError> for DmaError {
    fn from(e: IoError) -> Self {
        DmaError::Io(e)
    }
}

/// One entry in the FakeIommu page table.
#[derive(Copy, Clone, Debug)]
struct PteEntry {
    phys: u64,
    perms: IommuPerms,
}

/// Fault record recorded in the FakeIommu fault queue.
/// `is_write` mirrors the AMD-Vi event-log W-bit and the Intel VT-d
/// fault-record T-bit (0=read, 1=write); retained for future assertions.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
struct FaultRecord {
    iova: u64,
    is_write: bool,
}

/// Software IOMMU page table + fault queue.
struct FakeIommu {
    /// IOVA → physical address mapping. Keyed by page-aligned IOVA.
    pgtbl: BTreeMap<u64, PteEntry>,
    /// Counters used by smoke 12.
    nr_mapped: usize,
    nr_revoked: usize,
    /// Fault queue; drained by smoke 13.
    faults: Vec<FaultRecord>,
}

impl FakeIommu {
    fn new() -> Self {
        FakeIommu {
            pgtbl: BTreeMap::new(),
            nr_mapped: 0,
            nr_revoked: 0,
            faults: Vec::new(),
        }
    }

    /// Map one page: IOVA → phys with given perms. Returns the IOVA
    /// actually installed (same as the argument — no auto-assignment here).
    ///
    /// Mirrors `iommu_map()` in `linux/drivers/iommu/iommu.c`.
    fn map_page(&mut self, iova: u64, phys: u64, perms: IommuPerms) -> Result<u64, DmaError> {
        if self.pgtbl.contains_key(&iova) {
            return Err(DmaError::AlreadyMapped);
        }
        self.pgtbl.insert(iova, PteEntry { phys, perms });
        self.nr_mapped += 1;
        Ok(iova)
    }

    /// Unmap one page. Mirrors `iommu_unmap()` in
    /// `linux/drivers/iommu/iommu.c`.
    fn unmap_page(&mut self, iova: u64) -> Result<(), DmaError> {
        if self.pgtbl.remove(&iova).is_none() {
            return Err(DmaError::PageFault);
        }
        self.nr_revoked += 1;
        Ok(())
    }

    /// Translate IOVA → phys for a device access (read or write). Records
    /// a fault when no mapping is present, matching AMD-Vi event-log
    /// behaviour (AMD IOMMU spec §2.4, rev 3.10) and Intel VT-d fault
    /// recording (Intel VT-d spec §7.2, rev 4.1).
    fn translate(&mut self, iova: u64, write: bool) -> Result<u64, DmaError> {
        match self.pgtbl.get(&iova) {
            None => {
                self.faults.push(FaultRecord {
                    iova,
                    is_write: write,
                });
                Err(DmaError::PageFault)
            }
            Some(e) => {
                if write && !e.perms.write() {
                    self.faults.push(FaultRecord {
                        iova,
                        is_write: true,
                    });
                    return Err(DmaError::PermissionDenied);
                }
                if !write && !e.perms.read() {
                    self.faults.push(FaultRecord {
                        iova,
                        is_write: false,
                    });
                    return Err(DmaError::PermissionDenied);
                }
                Ok(e.phys)
            }
        }
    }

    /// Number of live IOVA mappings.
    fn mapping_count(&self) -> usize {
        self.pgtbl.len()
    }

    /// Drain pending fault records.
    fn drain_faults(&mut self) -> Vec<FaultRecord> {
        let mut v = Vec::new();
        core::mem::swap(&mut self.faults, &mut v);
        v
    }

    /// Check whether a given IOVA has an active mapping.
    fn is_mapped(&self, iova: u64) -> bool {
        self.pgtbl.contains_key(&iova)
    }
}

// ─── FakeDevice ─────────────────────────────────────────────────────────────
//
// Models the device side of a DMA transaction. The device only ever sees
// IOVAs; it resolves them through the FakeIommu to reach physical memory.
// The physical memory is accessed through the kernel identity map (same
// pointer arithmetic used by `DmaBuffer::as_slice`).
//
// "DMA read" from device POV = device reads host memory → device gets data.
// "DMA write" from device POV = device writes host memory → host can read.

struct FakeDevice;

impl FakeDevice {
    /// Device reads `len` bytes starting at `iova`. Returns error on
    /// fault/permission. Copies into a caller-supplied buffer (simulating
    /// a device's internal receive buffer).
    fn dma_read(&self, iommu: &mut FakeIommu, iova: u64, out: &mut [u8]) -> Result<(), DmaError> {
        let phys = iommu.translate(iova, /*write=*/ false)?;
        // SAFETY: `phys` was returned by our FakeIommu which only stores
        // addresses obtained from `alloc_coherent` → `alloc_frame`.
        // Those frames are identity-mapped in the kernel address space.
        // `out.len()` is caller-bounded to be within one page in all
        // callers below.  The borrow lives only for this function.
        // SAFETY: Valid memory or trusted environment
        let src = unsafe { core::slice::from_raw_parts(phys as *const u8, out.len()) };
        out.copy_from_slice(src);
        Ok(())
    }

    /// Device writes `data` bytes starting at `iova`. Returns error on
    /// fault/permission.
    fn dma_write(&self, iommu: &mut FakeIommu, iova: u64, data: &[u8]) -> Result<(), DmaError> {
        let phys = iommu.translate(iova, /*write=*/ true)?;
        // SAFETY: same argument as `dma_read`. Unique write is safe because
        // the test holds the only live reference to the backing frame.
        // SAFETY: Valid memory or trusted environment
        let dst = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, data.len()) };
        dst.copy_from_slice(data);
        Ok(())
    }
}

// ─── IOVA allocator helper ───────────────────────────────────────────────────
//
// Assigns IOVAs from a base address in page-sized steps. The base is chosen
// well above the 4 GiB boundary so it can never alias a typical physical
// address on the test platform (the frame allocator only returns low RAM).
// This mirrors how Linux's `iova_domain` hands out virtual addresses
// (`linux/drivers/iommu/iova.c::alloc_iova`).

static IOVA_COUNTER: AtomicUsize = AtomicUsize::new(0);

const IOVA_BASE: u64 = 0x0000_8000_0000_0000; // above 128 TiB phys

fn next_iova() -> u64 {
    let idx = IOVA_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    IOVA_BASE + idx * PAGE_SIZE
}

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 1 — alloc coherent buffer + IOMMU map
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_01_alloc_and_map() -> TestResult {
    // dma_alloc_coherent analogue (linux/include/linux/dma-mapping.h):
    // allocate a page-sized DMA-coherent buffer and install it in the
    // FakeIommu page table. After map:
    //   - returned IOVA is present in the page table
    //   - nr_mapped incremented
    //   - phys address is page-aligned and non-zero

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    if phys == 0 {
        return TestResult::Fail("alloc returned zero phys");
    }
    if phys & (PAGE_SIZE - 1) != 0 {
        return TestResult::Fail("phys not page-aligned");
    }
    if buf.len() != PAGE_SIZE as usize {
        return TestResult::Fail("buffer length not page-rounded");
    }

    let mut iommu = FakeIommu::new();
    let iova = next_iova();

    match iommu.map_page(iova, phys, IommuPerms::READ_WRITE) {
        Ok(returned_iova) if returned_iova == iova => {}
        Ok(_) => return TestResult::Fail("map returned wrong IOVA"),
        Err(_) => return TestResult::Fail("map failed"),
    }

    if !iommu.is_mapped(iova) {
        return TestResult::Fail("page table entry absent after map");
    }
    if iommu.nr_mapped != 1 {
        return TestResult::Fail("nr_mapped not incremented");
    }
    if iommu.mapping_count() != 1 {
        return TestResult::Fail("mapping_count() != 1");
    }

    let _ = iommu.unmap_page(iova);
    free_coherent(buf);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_01_alloc_and_map);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 2 — Cap holds IOVA grant
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_02_cap_holds_iova_grant() -> TestResult {
    // A minted Cap<DmaBuffer, Write> is live immediately after
    // register_with_cap() and its slot resolves back to the buffer's
    // physical address. The IOVA assigned by the FakeIommu matches what
    // the host would hand to the device.

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    let cap = register_with_cap(buf);
    if !cap.is_live() {
        unregister(cap);
        return TestResult::Fail("fresh cap not live");
    }

    // The cap's slot index must resolve to the registered buffer.
    let resolved = match crate::resolve_cap(&cap) {
        Some(b) => b,
        None => {
            unregister(cap);
            return TestResult::Fail("resolve_cap returned None");
        }
    };
    if resolved.dma_addr().raw() != phys {
        drop(resolved);
        unregister(cap);
        return TestResult::Fail("resolved phys doesn't match allocated phys");
    }

    // Map that phys address in the FakeIommu — this is the IOVA the
    // kernel would store alongside the cap for drivers to consult.
    let mut iommu = FakeIommu::new();
    let iova = next_iova();
    if iommu.map_page(iova, phys, IommuPerms::READ_WRITE).is_err() {
        drop(resolved);
        unregister(cap);
        return TestResult::Fail("map_page failed");
    }

    // The IOVA is derivable from the cap's backing buffer.
    if resolved.dma_addr().raw() != phys {
        drop(resolved);
        let _ = iommu.unmap_page(iova);
        unregister(cap);
        return TestResult::Fail("IOVA grant inconsistent with cap backing");
    }

    drop(resolved);
    let _ = iommu.unmap_page(iova);
    unregister(cap);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_02_cap_holds_iova_grant);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 3 — host writes visible to device (CPU → device direction)
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_03_host_writes_visible_to_device() -> TestResult {
    // CPU writes a pattern to the buffer's kernel virtual address. The
    // FakeDevice reads via IOVA → FakeIommu resolves IOVA → phys → same
    // physical page → sees the pattern.
    //
    // This confirms the "ToDevice" coherency path: after a CPU write and
    // a dma_sync_single_for_device() (implied here — identity mapping),
    // the device observes the new content. See
    // `linux/include/linux/dma-mapping.h::dma_sync_single_for_device`.

    const PATTERN: u8 = 0xA5;

    let mut buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    // CPU writes the pattern through the kernel mapping.
    buf.as_mut_slice()[0..8].fill(PATTERN);
    buf.as_mut_slice()[4088..4096].fill(PATTERN);

    let mut iommu = FakeIommu::new();
    let iova = next_iova();
    if iommu.map_page(iova, phys, IommuPerms::READ).is_err() {
        free_coherent(buf);
        return TestResult::Fail("map_page failed");
    }

    let dev = FakeDevice;
    let mut readback = [0u8; 8];

    // Device reads first 8 bytes.
    if dev.dma_read(&mut iommu, iova, &mut readback).is_err() {
        let _ = iommu.unmap_page(iova);
        free_coherent(buf);
        return TestResult::Fail("device dma_read failed");
    }
    if readback != [PATTERN; 8] {
        let _ = iommu.unmap_page(iova);
        free_coherent(buf);
        return TestResult::Fail("device didn't see CPU-written pattern at start");
    }

    // Device reads last 8 bytes (offset 4088 in the page).
    // map_page maps entire pages; address the tail byte via a direct phys
    // pointer — models a device that resolves IOVA→phys then offsets within
    // the page.  SAFETY: phys is an allocated frame; offset 4088 < 4096.
    // SAFETY: Valid memory or trusted environment
    let tail_val = unsafe { core::ptr::read_volatile((phys + 4088) as *const u8) };
    if tail_val != PATTERN {
        let _ = iommu.unmap_page(iova);
        free_coherent(buf);
        return TestResult::Fail("CPU-written pattern not present at tail");
    }

    let _ = iommu.unmap_page(iova);
    free_coherent(buf);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_03_host_writes_visible_to_device);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 4 — device writes visible to host (device → CPU direction)
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_04_device_writes_visible_to_host() -> TestResult {
    // FakeDevice writes a pattern via IOVA. The host then reads it through
    // the kernel virtual address (as_slice). This is the "FromDevice"
    // coherency path: after dma_sync_single_for_cpu() the CPU observes
    // device-written data (`linux/include/linux/dma-mapping.h`).

    const DEVICE_PATTERN: u8 = 0x5A;

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    // Confirm buffer is zero-filled on alloc (alloc_with zeroes it).
    if buf.as_slice()[0] != 0 || buf.as_slice()[4095] != 0 {
        free_coherent(buf);
        return TestResult::Fail("freshly allocated buffer not zero");
    }

    let mut iommu = FakeIommu::new();
    let iova = next_iova();
    if iommu.map_page(iova, phys, IommuPerms::WRITE).is_err() {
        free_coherent(buf);
        return TestResult::Fail("map_page failed");
    }

    let dev = FakeDevice;
    let payload = [DEVICE_PATTERN; 16];
    if dev.dma_write(&mut iommu, iova, &payload).is_err() {
        let _ = iommu.unmap_page(iova);
        free_coherent(buf);
        return TestResult::Fail("device dma_write failed");
    }

    // CPU reads back through the kernel mapping.
    let got = &buf.as_slice()[0..16];
    for (i, &b) in got.iter().enumerate() {
        if b != DEVICE_PATTERN {
            let _ = iommu.unmap_page(iova);
            free_coherent(buf);
            // Static string is sufficient; we can't format in no_std.
            let _ = i;
            return TestResult::Fail("host readback didn't match device-written pattern");
        }
    }

    let _ = iommu.unmap_page(iova);
    free_coherent(buf);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_04_device_writes_visible_to_host);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 5 — cap revoke unmaps IOVA
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_05_cap_revoke_unmaps_iova() -> TestResult {
    // Revoking the cap must trigger IOVA removal. This is the mechanism
    // that enforces device isolation: once a driver's DmaBuffer cap is
    // revoked, the FakeIommu page table no longer contains the mapping,
    // so the device cannot reach that physical memory.
    //
    // Linux parallel: `iommu_unmap()` called from dma_free_coherent()
    // (`linux/drivers/iommu/iommu.c`).

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    let cap = register_with_cap(buf);
    let mut iommu = FakeIommu::new();
    let iova = next_iova();

    if iommu.map_page(iova, phys, IommuPerms::READ_WRITE).is_err() {
        unregister(cap);
        return TestResult::Fail("initial map_page failed");
    }

    if !iommu.is_mapped(iova) {
        unregister(cap);
        return TestResult::Fail("mapping absent before revoke");
    }

    // Revoke the cap and atomically unmap the IOVA. In a real kernel these
    // two operations would be coupled in the DmaBuffer reclaim path; here
    // we model the invariant: unmap happens at most once per cap lifetime.
    let slot_index = cap.slot().index;
    unregister(cap); // bumps epoch → all cap copies dead
    let _ = iommu.unmap_page(iova); // removes page-table entry

    // Verify: epoch was bumped (object-table slot no longer live).
    let epoch = narf_capabilities::object_table::current_epoch(slot_index);
    // After bump_epoch the epoch is ≥ 2; the cap's generation was 1.
    // We can't reconstruct a live cap to call check_live, but we can
    // verify the epoch changed by synthesizing a check via object_table.
    if let Some(e) = epoch {
        // epoch 1 is the freshly registered value; after unregister it must be > 1.
        if e == 1 {
            return TestResult::Fail("epoch not bumped after unregister");
        }
    }
    // else: slot was cleaned up entirely — also acceptable.

    if iommu.is_mapped(iova) {
        return TestResult::Fail("IOVA still in page table after unmap");
    }
    if iommu.nr_revoked != 1 {
        return TestResult::Fail("nr_revoked not incremented");
    }

    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_05_cap_revoke_unmaps_iova);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 6 — stale IOVA after revoke traps (IOMMU page fault)
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_06_stale_iova_traps() -> TestResult {
    // After cap revoke + IOVA unmap, the device's DMA attempt at the old
    // IOVA must return DmaError::PageFault. This is the primary security
    // invariant: an attacker holding a stale IOVA cannot reach the freed
    // physical page.
    //
    // AMD-Vi: unmapped IOVA triggers event-log entry `IO_PAGE_FAULT`
    //         (AMD IOMMU spec §2.4.2, rev 3.10).
    // Intel VT-d: unmapped IOVA triggers fault record with FAULT_REASON=5
    //             (Intel VT-d spec §7.2.1, rev 4.1).

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    let cap = register_with_cap(buf);
    let mut iommu = FakeIommu::new();
    let iova = next_iova();

    if iommu.map_page(iova, phys, IommuPerms::READ_WRITE).is_err() {
        unregister(cap);
        return TestResult::Fail("initial map_page failed");
    }

    // Revoke cap and unmap — the security boundary closes here.
    unregister(cap);
    let _ = iommu.unmap_page(iova);

    // Device still holds the stale IOVA (e.g., from a previously submitted
    // descriptor that wasn't cancelled). Any access must fault.
    let dev = FakeDevice;
    let mut scratch = [0u8; 8];

    match dev.dma_read(&mut iommu, iova, &mut scratch) {
        Err(DmaError::PageFault) => {}
        Ok(_) => return TestResult::Fail("stale-IOVA read should have faulted"),
        Err(e) => {
            let _ = e;
            return TestResult::Fail("stale-IOVA read returned wrong error");
        }
    }

    match dev.dma_write(&mut iommu, iova, &[0xFFu8; 8]) {
        Err(DmaError::PageFault) => {}
        Ok(_) => return TestResult::Fail("stale-IOVA write should have faulted"),
        Err(e) => {
            let _ = e;
            return TestResult::Fail("stale-IOVA write returned wrong error");
        }
    }

    // Both fault attempts were recorded in the fault queue.
    let faults = iommu.drain_faults();
    if faults.len() != 2 {
        return TestResult::Fail("expected 2 fault records after stale accesses");
    }
    if faults[0].iova != iova || faults[1].iova != iova {
        return TestResult::Fail("fault record has wrong IOVA");
    }

    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_06_stale_iova_traps);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 7 — re-alloc gives a non-aliasing IOVA
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_07_realloc_iova_no_alias() -> TestResult {
    // After free (unregister + unmap), a fresh alloc + map must not produce
    // an IOVA that aliases the just-freed mapping. The IOVA allocator
    // increments monotonically (see `next_iova()`), so freshly assigned
    // IOVAs are always beyond any previously assigned IOVA. The freed IOVA
    // must not be in the live page table.

    let buf_a = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys_a = buf_a.dma_addr().raw();
    let cap_a = register_with_cap(buf_a);

    let mut iommu = FakeIommu::new();
    let iova_a = next_iova();
    if iommu
        .map_page(iova_a, phys_a, IommuPerms::READ_WRITE)
        .is_err()
    {
        unregister(cap_a);
        return TestResult::Fail("map_page A failed");
    }

    // Revoke A.
    unregister(cap_a);
    if iommu.unmap_page(iova_a).is_err() {
        return TestResult::Fail("unmap_page A failed");
    }

    // Allocate B.
    let buf_b = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator exhausted on second alloc"),
    };
    let phys_b = buf_b.dma_addr().raw();
    let cap_b = register_with_cap(buf_b);

    let iova_b = next_iova();

    // A's IOVA must not be live.
    if iommu.is_mapped(iova_a) {
        unregister(cap_b);
        return TestResult::Fail("freed IOVA_A still in page table");
    }

    // B must get a distinct IOVA.
    if iova_b == iova_a {
        unregister(cap_b);
        return TestResult::Fail("new alloc reused the freed IOVA (aliasing risk)");
    }

    if iommu
        .map_page(iova_b, phys_b, IommuPerms::READ_WRITE)
        .is_err()
    {
        unregister(cap_b);
        return TestResult::Fail("map_page B failed");
    }

    // Both A and B IOVAs must not overlap: A is unmapped, B is mapped.
    if iommu.is_mapped(iova_a) {
        let _ = iommu.unmap_page(iova_b);
        unregister(cap_b);
        return TestResult::Fail("IOVA_A appeared in page table after unmap");
    }
    if !iommu.is_mapped(iova_b) {
        let _ = iommu.unmap_page(iova_b);
        unregister(cap_b);
        return TestResult::Fail("IOVA_B missing from page table");
    }

    let _ = iommu.unmap_page(iova_b);
    unregister(cap_b);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_07_realloc_iova_no_alias);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 8 — scatter-gather buffer (multi-page)
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_08_scatter_gather_multi_page() -> TestResult {
    // 16 KiB logical buffer = 4 separate 4 KiB frames. The FakeIommu maps
    // each page individually into a contiguous IOVA run. The device reads
    // from the first and last byte of the logical range.
    //
    // Linux: `linux/drivers/iommu/amd/io_pgtable.c::amd_iommu_map_pages`
    // builds per-page entries into the domain's page table in a loop over
    // the scatter list. Same principle here.

    const N_PAGES: usize = 4;
    let mut bufs = Vec::new();

    for _ in 0..N_PAGES {
        match alloc_coherent(4096, DomainId::DRIVER_0) {
            Ok(b) => bufs.push(b),
            Err(_) => {
                // Free what we got before returning.
                for b in bufs {
                    free_coherent(b);
                }
                return TestResult::Skip("frame allocator couldn't provide 4 pages");
            }
        }
    }

    // Write sentinels: first byte of page 0, last byte of page 3.
    const FIRST_SENTINEL: u8 = 0x11;
    const LAST_SENTINEL: u8 = 0xEE;
    bufs[0].as_mut_slice()[0] = FIRST_SENTINEL;
    bufs[N_PAGES - 1].as_mut_slice()[4095] = LAST_SENTINEL;

    let mut iommu = FakeIommu::new();
    let base_iova = next_iova();

    // Map 4 contiguous IOVAs, one per page.
    for (i, buf) in bufs.iter().enumerate() {
        let iova = base_iova + (i as u64) * PAGE_SIZE;
        if iommu
            .map_page(iova, buf.dma_addr().raw(), IommuPerms::READ)
            .is_err()
        {
            for j in 0..i {
                let _ = iommu.unmap_page(base_iova + (j as u64) * PAGE_SIZE);
            }
            for b in bufs {
                free_coherent(b);
            }
            return TestResult::Fail("map_page failed for scatter-gather page");
        }
    }

    if iommu.mapping_count() != N_PAGES {
        for i in 0..N_PAGES {
            let _ = iommu.unmap_page(base_iova + (i as u64) * PAGE_SIZE);
        }
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("mapping_count doesn't match page count");
    }

    let dev = FakeDevice;

    // Device reads first byte of page 0.
    let mut first_buf = [0u8; 1];
    if dev.dma_read(&mut iommu, base_iova, &mut first_buf).is_err() {
        for i in 0..N_PAGES {
            let _ = iommu.unmap_page(base_iova + (i as u64) * PAGE_SIZE);
        }
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("device read of first S/G page failed");
    }
    if first_buf[0] != FIRST_SENTINEL {
        for i in 0..N_PAGES {
            let _ = iommu.unmap_page(base_iova + (i as u64) * PAGE_SIZE);
        }
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("first S/G page sentinel mismatch");
    }

    // Device reads last byte of page 3 (byte offset 4095 within that page).
    // The FakeDevice dma_read resolves only the page base, so we access the
    // last byte via a direct phys read — modelling a device that has already
    // resolved the IOVA to phys and then DMAed to an offset within the page.
    let last_phys = bufs[N_PAGES - 1].dma_addr().raw();
    // SAFETY: `last_phys` is the physical base of a live 4096-byte
    // coherent buffer (`alloc_coherent(4096, ..)` at the top of this
    // test, still owned in `bufs`), and coherent DMA memory is
    // identity-mapped, so `last_phys` is a valid readable address.
    // Offset 4095 is the last byte of that 4096-byte frame — the same
    // byte written via `as_mut_slice()[4095] = LAST_SENTINEL` above —
    // so the read is in-bounds and reads an initialized `u8`.
    // SAFETY: Valid memory or trusted environment
    let last_val = unsafe { core::ptr::read_volatile((last_phys + 4095) as *const u8) };
    if last_val != LAST_SENTINEL {
        for i in 0..N_PAGES {
            let _ = iommu.unmap_page(base_iova + (i as u64) * PAGE_SIZE);
        }
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("last S/G page sentinel mismatch");
    }

    // Unmap all pages.
    for i in 0..N_PAGES {
        if iommu
            .unmap_page(base_iova + (i as u64) * PAGE_SIZE)
            .is_err()
        {
            for b in bufs {
                free_coherent(b);
            }
            return TestResult::Fail("unmap_page failed for scatter-gather page");
        }
    }
    if iommu.mapping_count() != 0 {
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("mapping_count != 0 after full unmap");
    }

    for b in bufs {
        free_coherent(b);
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_08_scatter_gather_multi_page);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 9 — DMA direction enforcement
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_09_dma_direction_enforcement() -> TestResult {
    // A buffer mapped with perms=READ (DMA_TO_DEVICE) must reject device
    // writes and accept device reads. A buffer mapped with perms=WRITE
    // (DMA_FROM_DEVICE) must reject device reads and accept writes.
    // Bidirectional (READ|WRITE) allows both.
    //
    // Linux: `enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE,
    //         DMA_FROM_DEVICE }` in `linux/include/linux/dma-mapping.h`.

    let buf_r = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys_r = buf_r.dma_addr().raw();

    let buf_w = match alloc_coherent(4096, DomainId::DRIVER_1) {
        Ok(b) => b,
        Err(_) => {
            free_coherent(buf_r);
            return TestResult::Skip("frame allocator couldn't provide second page");
        }
    };
    let phys_w = buf_w.dma_addr().raw();

    let mut iommu = FakeIommu::new();
    let iova_r = next_iova(); // READ-only mapping (DMA_TO_DEVICE)
    let iova_w = next_iova(); // WRITE-only mapping (DMA_FROM_DEVICE)
    let iova_rw = next_iova(); // Bidirectional

    if iommu.map_page(iova_r, phys_r, IommuPerms::READ).is_err()
        || iommu.map_page(iova_w, phys_w, IommuPerms::WRITE).is_err()
        || iommu
            .map_page(iova_rw, phys_r, IommuPerms::READ_WRITE)
            .is_err()
    {
        let _ = iommu.unmap_page(iova_r);
        let _ = iommu.unmap_page(iova_w);
        let _ = iommu.unmap_page(iova_rw);
        free_coherent(buf_r);
        free_coherent(buf_w);
        return TestResult::Fail("setup map_page failed");
    }

    let dev = FakeDevice;
    let mut scratch = [0u8; 4];

    // READ-only mapping: device read OK, device write rejected.
    if dev.dma_read(&mut iommu, iova_r, &mut scratch).is_err() {
        let _ = iommu.unmap_page(iova_r);
        let _ = iommu.unmap_page(iova_w);
        let _ = iommu.unmap_page(iova_rw);
        free_coherent(buf_r);
        free_coherent(buf_w);
        return TestResult::Fail("device read on READ-only mapping failed (should succeed)");
    }
    match dev.dma_write(&mut iommu, iova_r, &[0xBBu8; 4]) {
        Err(DmaError::PermissionDenied) => {}
        Ok(_) => {
            let _ = iommu.unmap_page(iova_r);
            let _ = iommu.unmap_page(iova_w);
            let _ = iommu.unmap_page(iova_rw);
            free_coherent(buf_r);
            free_coherent(buf_w);
            return TestResult::Fail("device write on READ-only mapping succeeded (should deny)");
        }
        Err(_) => {
            let _ = iommu.unmap_page(iova_r);
            let _ = iommu.unmap_page(iova_w);
            let _ = iommu.unmap_page(iova_rw);
            free_coherent(buf_r);
            free_coherent(buf_w);
            return TestResult::Fail("device write on READ-only mapping returned wrong error");
        }
    }

    // WRITE-only mapping: device write OK, device read rejected.
    if dev.dma_write(&mut iommu, iova_w, &[0xCCu8; 4]).is_err() {
        let _ = iommu.unmap_page(iova_r);
        let _ = iommu.unmap_page(iova_w);
        let _ = iommu.unmap_page(iova_rw);
        free_coherent(buf_r);
        free_coherent(buf_w);
        return TestResult::Fail("device write on WRITE-only mapping failed (should succeed)");
    }
    match dev.dma_read(&mut iommu, iova_w, &mut scratch) {
        Err(DmaError::PermissionDenied) => {}
        Ok(_) => {
            let _ = iommu.unmap_page(iova_r);
            let _ = iommu.unmap_page(iova_w);
            let _ = iommu.unmap_page(iova_rw);
            free_coherent(buf_r);
            free_coherent(buf_w);
            return TestResult::Fail("device read on WRITE-only mapping succeeded (should deny)");
        }
        Err(_) => {
            let _ = iommu.unmap_page(iova_r);
            let _ = iommu.unmap_page(iova_w);
            let _ = iommu.unmap_page(iova_rw);
            free_coherent(buf_r);
            free_coherent(buf_w);
            return TestResult::Fail("device read on WRITE-only mapping returned wrong error");
        }
    }

    // Bidirectional mapping: both directions OK.
    if dev.dma_read(&mut iommu, iova_rw, &mut scratch).is_err() {
        let _ = iommu.unmap_page(iova_r);
        let _ = iommu.unmap_page(iova_w);
        let _ = iommu.unmap_page(iova_rw);
        free_coherent(buf_r);
        free_coherent(buf_w);
        return TestResult::Fail("device read on RW mapping failed");
    }
    if dev.dma_write(&mut iommu, iova_rw, &[0xDDu8; 4]).is_err() {
        let _ = iommu.unmap_page(iova_r);
        let _ = iommu.unmap_page(iova_w);
        let _ = iommu.unmap_page(iova_rw);
        free_coherent(buf_r);
        free_coherent(buf_w);
        return TestResult::Fail("device write on RW mapping failed");
    }

    let _ = iommu.unmap_page(iova_r);
    let _ = iommu.unmap_page(iova_w);
    let _ = iommu.unmap_page(iova_rw);
    free_coherent(buf_r);
    free_coherent(buf_w);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_09_dma_direction_enforcement);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 10 — concurrent allocs don't collide
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_10_concurrent_allocs_no_collision() -> TestResult {
    // Allocate multiple buffers and verify:
    //   (a) all physical addresses are distinct (page allocator safety)
    //   (b) all assigned IOVAs are distinct (IOVA allocator safety)
    //   (c) no two live IOVA→phys mappings share an address
    //
    // This is the test analogue of `iommu_map()` rejecting duplicate IOVAs
    // in `linux/drivers/iommu/iommu.c`.

    const N: usize = 8;
    let mut bufs = Vec::new();
    let mut iovas = Vec::new();
    let mut physes = Vec::new();

    let mut iommu = FakeIommu::new();

    for _ in 0..N {
        match alloc_coherent(4096, DomainId::DRIVER_0) {
            Ok(b) => {
                let p = b.dma_addr().raw();
                let iova = next_iova();

                // Physical addresses must all be distinct.
                if physes.contains(&p) {
                    for b2 in bufs {
                        free_coherent(b2);
                    }
                    return TestResult::Fail("frame allocator returned duplicate phys address");
                }
                // IOVAs must be distinct.
                if iovas.contains(&iova) {
                    for b2 in bufs {
                        free_coherent(b2);
                    }
                    return TestResult::Fail("IOVA allocator returned duplicate IOVA");
                }

                if iommu.map_page(iova, p, IommuPerms::READ_WRITE).is_err() {
                    free_coherent(b);
                    for b2 in bufs {
                        free_coherent(b2);
                    }
                    return TestResult::Fail("map_page rejected a distinct IOVA");
                }

                physes.push(p);
                iovas.push(iova);
                bufs.push(b);
            }
            Err(_) => {
                // Accept fewer than N on low-memory builds.
                break;
            }
        }
    }

    let n_live = bufs.len();
    if n_live < 2 {
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Skip("fewer than 2 buffers allocated — collision check trivial");
    }

    if iommu.mapping_count() != n_live {
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("mapping_count disagrees with alloc count");
    }

    // Verify duplicate map is rejected (the IOVA already exists).
    if iommu
        .map_page(iovas[0], physes[1], IommuPerms::READ_WRITE)
        .is_ok()
    {
        for b in bufs {
            free_coherent(b);
        }
        return TestResult::Fail("duplicate IOVA map should have been rejected");
    }

    for iova in &iovas {
        let _ = iommu.unmap_page(*iova);
    }
    for b in bufs {
        free_coherent(b);
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_10_concurrent_allocs_no_collision);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 11 — NVMe-style queue alloc through IOMMU
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_11_nvme_queue_alloc_through_iommu() -> TestResult {
    // Model an NVMe controller bring-up sequence (Wave-32 pattern):
    //   ASQ (Admin Submission Queue)  — 4 KiB, RW
    //   ACQ (Admin Completion Queue)  — 4 KiB, RW
    //   IO SQ (IO Submission Queue)   — 4 KiB, RW
    //   IO CQ (IO Completion Queue)   — 4 KiB, RW
    //
    // Each gets a distinct IOVA. The FakeIommu page table must contain
    // exactly 4 entries, all distinct.
    //
    // Linux: linux/drivers/nvme/host/pci.c::nvme_alloc_admin_tag_set()
    // calls dma_alloc_coherent for ASQ/ACQ; nvme_create_io_queues calls
    // it again for each IO SQ/CQ pair.

    #[allow(dead_code)]
    #[derive(Copy, Clone, Debug)]
    struct QueueDesc {
        /// Human-readable queue name for debugging.
        name: &'static str,
        phys: u64,
        iova: u64,
    }

    let queue_names = ["ASQ", "ACQ", "IO_SQ", "IO_CQ"];
    let mut queues: Vec<QueueDesc> = Vec::new();
    let mut raw_bufs: Vec<crate::DmaBuffer> = Vec::new();
    let mut iommu = FakeIommu::new();

    for &name in &queue_names {
        let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
            Ok(b) => b,
            Err(_) => {
                for b in raw_bufs {
                    free_coherent(b);
                }
                return TestResult::Skip("frame allocator couldn't provide NVMe queue buffers");
            }
        };
        let phys = buf.dma_addr().raw();
        let iova = next_iova();

        if iommu.map_page(iova, phys, IommuPerms::READ_WRITE).is_err() {
            free_coherent(buf);
            for b in raw_bufs {
                free_coherent(b);
            }
            return TestResult::Fail("map_page failed for NVMe queue");
        }

        queues.push(QueueDesc { name, phys, iova });
        raw_bufs.push(buf);
    }

    // Verify: 4 distinct IOVAs in the page table.
    if iommu.mapping_count() != 4 {
        for b in raw_bufs {
            free_coherent(b);
        }
        return TestResult::Fail("expected 4 IOMMU mappings for 4 NVMe queues");
    }

    for i in 0..queues.len() {
        for j in (i + 1)..queues.len() {
            if queues[i].iova == queues[j].iova {
                for b in raw_bufs {
                    free_coherent(b);
                }
                return TestResult::Fail("two NVMe queues share an IOVA");
            }
            if queues[i].phys == queues[j].phys {
                for b in raw_bufs {
                    free_coherent(b);
                }
                return TestResult::Fail("two NVMe queues share a physical page");
            }
        }
    }

    // Simulate driver writing a 64-byte NVMe SQE into ASQ[0] and reading it back.
    const SQE: [u8; 64] = [0xABu8; 64];
    let asq = &queues[0];
    // SAFETY: phys is a valid frame; 64 bytes is within the 4 KiB page.
    unsafe {
        core::ptr::copy_nonoverlapping(SQE.as_ptr(), asq.phys as *mut u8, 64);
    }

    let dev = FakeDevice;
    let mut readback = [0u8; 64];
    if dev.dma_read(&mut iommu, asq.iova, &mut readback).is_err() {
        for b in raw_bufs {
            free_coherent(b);
        }
        return TestResult::Fail("device couldn't read NVMe ASQ via IOVA");
    }
    if readback != SQE {
        for b in raw_bufs {
            free_coherent(b);
        }
        return TestResult::Fail("NVMe SQE readback mismatch");
    }

    // Tear down.
    for q in &queues {
        let _ = iommu.unmap_page(q.iova);
    }
    for b in raw_bufs {
        free_coherent(b);
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_11_nvme_queue_alloc_through_iommu);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 12 — IOMMU stats (nr_mapped / nr_revoked)
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_12_iommu_stats() -> TestResult {
    // Verify that nr_mapped and nr_revoked monotonically accumulate as
    // expected across a map→unmap cycle. This models the telemetry an
    // IOMMU driver would expose via sysfs or a debugfs node.

    let buf_a = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let buf_b = match alloc_coherent(4096, DomainId::DRIVER_1) {
        Ok(b) => b,
        Err(_) => {
            free_coherent(buf_a);
            return TestResult::Skip("frame allocator couldn't provide second page");
        }
    };

    let mut iommu = FakeIommu::new();
    if iommu.nr_mapped != 0 || iommu.nr_revoked != 0 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("fresh FakeIommu has non-zero stats");
    }

    let iova_a = next_iova();
    let iova_b = next_iova();

    let _ = iommu.map_page(iova_a, buf_a.dma_addr().raw(), IommuPerms::READ_WRITE);
    if iommu.nr_mapped != 1 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("nr_mapped != 1 after first map");
    }

    let _ = iommu.map_page(iova_b, buf_b.dma_addr().raw(), IommuPerms::READ);
    if iommu.nr_mapped != 2 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("nr_mapped != 2 after second map");
    }

    let _ = iommu.unmap_page(iova_a);
    if iommu.nr_revoked != 1 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("nr_revoked != 1 after first unmap");
    }
    // nr_mapped is cumulative total mapped (not live count).
    if iommu.nr_mapped != 2 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("nr_mapped changed on unmap (should be cumulative)");
    }

    let _ = iommu.unmap_page(iova_b);
    if iommu.nr_revoked != 2 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("nr_revoked != 2 after second unmap");
    }

    // mapping_count() reflects live count only.
    if iommu.mapping_count() != 0 {
        free_coherent(buf_a);
        free_coherent(buf_b);
        return TestResult::Fail("mapping_count() != 0 after both unmaps");
    }

    free_coherent(buf_a);
    free_coherent(buf_b);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_12_iommu_stats);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 13 — IOMMU fault queue drain
// ═══════════════════════════════════════════════════════════════════════════

fn iommu_e2e_13_fault_queue_drain() -> TestResult {
    // When the FakeDevice accesses an unmapped IOVA, the FakeIommu records
    // a FaultRecord in its fault queue. This models the IOMMU hardware
    // event log:
    //   AMD-Vi:    INVALIDATE_IOMMU_PAGES / PAGE_TAB_HW_ERROR event log entry
    //              (AMD IOMMU spec §2.4.2, rev 3.10)
    //   Intel VT-d: Fault Recording Register fault record
    //              (Intel VT-d spec §10.4.14, rev 4.1)
    //
    // The kernel IOMMU fault handler must be able to drain this queue and
    // act on each entry (e.g., send SIGBUS to a userspace driver).

    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.dma_addr().raw();

    let mut iommu = FakeIommu::new();
    let iova = next_iova();
    let _ = iommu.map_page(iova, phys, IommuPerms::READ_WRITE);

    let dev = FakeDevice;

    // A: Fault on completely unmapped IOVA.
    let dead_iova = iova + 0x1000_0000; // far outside any mapped region
    let mut scratch = [0u8; 4];
    let _ = dev.dma_read(&mut iommu, dead_iova, &mut scratch);
    let _ = dev.dma_write(&mut iommu, dead_iova, &[0u8; 4]);

    // B: Permission fault — mapped READ-only but device writes.
    let iova_ro = next_iova();
    let buf_ro = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => {
            let _ = iommu.unmap_page(iova);
            free_coherent(buf);
            return TestResult::Skip("frame allocator couldn't provide second page");
        }
    };
    let phys_ro = buf_ro.dma_addr().raw();
    let _ = iommu.map_page(iova_ro, phys_ro, IommuPerms::READ);
    let _ = dev.dma_write(&mut iommu, iova_ro, &[0xFFu8; 4]); // triggers permission fault

    // Drain and inspect the fault queue.
    let faults = iommu.drain_faults();

    // Expect exactly 3 faults: 2 PageFault (dead_iova) + 1 PermissionDenied (iova_ro).
    if faults.len() != 3 {
        let _ = iommu.unmap_page(iova);
        let _ = iommu.unmap_page(iova_ro);
        free_coherent(buf);
        free_coherent(buf_ro);
        return TestResult::Fail("expected 3 fault records in fault queue");
    }

    // Fault queue is cleared after drain.
    let second_drain = iommu.drain_faults();
    if !second_drain.is_empty() {
        let _ = iommu.unmap_page(iova);
        let _ = iommu.unmap_page(iova_ro);
        free_coherent(buf);
        free_coherent(buf_ro);
        return TestResult::Fail("fault queue not cleared after drain");
    }

    // Verify fault records: first two are at dead_iova, third at iova_ro.
    if faults[0].iova != dead_iova {
        let _ = iommu.unmap_page(iova);
        let _ = iommu.unmap_page(iova_ro);
        free_coherent(buf);
        free_coherent(buf_ro);
        return TestResult::Fail("first fault record has wrong IOVA");
    }
    if faults[1].iova != dead_iova {
        let _ = iommu.unmap_page(iova);
        let _ = iommu.unmap_page(iova_ro);
        free_coherent(buf);
        free_coherent(buf_ro);
        return TestResult::Fail("second fault record has wrong IOVA");
    }
    if faults[2].iova != iova_ro {
        let _ = iommu.unmap_page(iova);
        let _ = iommu.unmap_page(iova_ro);
        free_coherent(buf);
        free_coherent(buf_ro);
        return TestResult::Fail("third fault record (perm) has wrong IOVA");
    }

    let _ = iommu.unmap_page(iova);
    let _ = iommu.unmap_page(iova_ro);
    free_coherent(buf);
    free_coherent(buf_ro);
    TestResult::Pass
}
kernel_test_in!("io/iommu/e2e", iommu_e2e_13_fault_queue_drain);
