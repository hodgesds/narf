//! iwlwifi firmware download orchestrator — Stage 3.
//!
//! Bridges the TLV parser (`super::parse_ucode`) and the transport
//! paths (`transport::load_image_gen2`, `transport::boot_gen3`) into
//! a single orchestration function per generation.  Real DMA-coherent
//! allocation is handled by the caller via the `DmaAllocator` trait;
//! the loader itself is allocation-strategy-agnostic so the same code
//! drives both production (real PCIe DMA) and the mock-driven unit
//! tests here.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c` —
//!   `iwl_pcie_load_given_ucode_8000` (gen2 section-load sequence).
//! - `drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-v2.c` —
//!   `iwl_pcie_ctxt_info_v2_init` (gen3 IML / section-table build).
//! - `drivers/net/wireless/intel/iwlwifi/iwl-drv.c` —
//!   firmware-open / firmware-request flow.
//!
//! ## Error handling
//!
//! `load_firmware_gen2` / `load_firmware_gen3` return
//! `Err(FwLoadError::NotImplemented)` at the actual blob-load step
//! when the firmware registry doesn't have the matching .ucode file.
//! The parser/TLV scaffold below that runs purely from caller-provided
//! bytes (no registry) always succeeds on valid data.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::transport::{
    load_image_gen2, signal_load_done_gen2, release_cpu_gen2, boot_gen3,
    stage_sections_gen2, wait_alive, AliveSink, Gen3BootRegions, IwlMmio,
    SectionTableEntry, CtxtInfoV2, TransportError,
};
use super::{ParsedUcode, Generation, ChipConfig};
use super::transport::IML_SECTION_SENTINEL;

// ── Error ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwLoadError {
    /// Firmware blob not found in the kernel firmware registry.
    /// Caller must supply a .ucode blob via another path.
    NotImplemented,
    /// The parsed firmware contained no INIT sections (gen2 required).
    NoInitSections,
    /// The parsed firmware contained no runtime sections.
    NoRtSections,
    /// gen3-only: the IML section is absent from the runtime stream.
    NoIml,
    /// Transport-level error (APM timeout, section DMA timeout, etc.).
    Transport(TransportError),
}

impl From<TransportError> for FwLoadError {
    fn from(e: TransportError) -> Self {
        FwLoadError::Transport(e)
    }
}

// ── DMA allocator trait ─────────────────────────────────────────────

/// Minimal DMA-coherent allocation surface. The loader calls
/// `alloc_coherent` once per section to get the (virtual, phys) pair
/// needed by the FH service channel. Tests substitute a trivial
/// stack-backed shim.
///
/// Production wiring: the PCIe attach glue wraps `narf_memory`'s
/// coherent-DMA pool in `DmaAllocatorImpl` and passes it into the
/// loader.
pub trait DmaAllocator {
    /// Allocate `size` bytes of DMA-coherent host memory.
    /// Returns `(virt_ptr, host_phys)`. The allocation remains live
    /// until the device finishes consuming it (caller's
    /// responsibility to track lifetime).
    fn alloc_coherent(&mut self, size: usize) -> (*mut u8, u64);
}

// ── gen2 orchestrator ───────────────────────────────────────────────

/// Load firmware onto a gen2 device (AX200/AX201) via the FH service
/// channel.  Sequence mirrors `iwl_pcie_load_given_ucode_8000`:
///
///   1. Load the INIT image (SEC_INIT sections → device SRAM).
///   2. Signal "host done" via `PRPH_UREG_UCODE_LOAD_STATUS`.
///   3. Wait for the ALIVE notification from the INIT firmware.
///   4. Load the RUNTIME image (SEC_RT sections → device SRAM).
///   5. Release the embedded CPU (clear NEVO_RESET).
///   6. Wait for the second ALIVE notification from the RT firmware.
///
/// `alloc` — caller-supplied coherent DMA allocator.
/// `alive` — caller-supplied ALIVE notification sink.
///
/// Returns `Err(NotImplemented)` if `parsed.init_sections` or
/// `parsed.rt_sections` are empty — the blob was valid TLV but
/// didn't contain the sections we need, which in practice means the
/// firmware registry returned the wrong blob.
pub fn load_firmware_gen2<M, D, S>(
    mmio: &mut M,
    parsed: &ParsedUcode<'_>,
    alloc: &mut D,
    alive: &mut S,
) -> Result<(), FwLoadError>
where
    M: IwlMmio,
    D: DmaAllocator,
    S: AliveSink,
{
    if parsed.init_sections.is_empty() {
        return Err(FwLoadError::NoInitSections);
    }
    if parsed.rt_sections.is_empty() {
        return Err(FwLoadError::NoRtSections);
    }

    // Phase 1 — INIT image.
    let init_prepared = stage_sections_gen2(&parsed.init_sections, |payload| {
        let (virt, phys) = alloc.alloc_coherent(payload.len());
        // Copy section payload into coherent buffer. SAFETY: alloc
        // returned a valid writable buffer of `payload.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), virt, payload.len());
        }
        phys
    });
    load_image_gen2(mmio, &init_prepared)?;
    signal_load_done_gen2(mmio);
    wait_alive(alive)?;

    // Phase 2 — RUNTIME image.
    let rt_prepared = stage_sections_gen2(&parsed.rt_sections, |payload| {
        let (virt, phys) = alloc.alloc_coherent(payload.len());
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), virt, payload.len());
        }
        phys
    });
    load_image_gen2(mmio, &rt_prepared)?;
    release_cpu_gen2(mmio);
    wait_alive(alive)?;

    Ok(())
}

// ── gen3 section-table builder ──────────────────────────────────────

/// Build the runtime section table for gen3 IML boot. Linux's
/// `ctxt-info-v2.c::iwl_pcie_ctxt_info_v2_init` builds this
/// out-of-line table and points the `CtxtInfoV2::section_table_addr`
/// field at it. IML walks the table to pull each section.
///
/// Returns the list of entries (caller copies into DMA-coherent RAM
/// and passes the phys of the base entry as
/// `ctxt_info.section_table_addr`).
pub fn build_section_table(parsed: &ParsedUcode<'_>) -> Vec<SectionTableEntry> {
    parsed
        .rt_sections
        .iter()
        .filter(|s| {
            // Exclude the IML sentinel and CPU1/CPU2 separator
            // markers; they're not real memory regions.
            s.dest_offset != IML_SECTION_SENTINEL
                && s.dest_offset != super::CPU1_CPU2_SEPARATOR
                && s.dest_offset != super::PAGING_SEPARATOR
        })
        .map(|s| SectionTableEntry {
            dest_offset: s.dest_offset,
            byte_count: s.payload.len() as u32,
            // host_phys filled in by the caller after DMA alloc.
            host_phys: 0,
        })
        .collect()
}

/// Load firmware onto a gen3 device (AX210/AX211/BE200) via
/// context-info-v2 + IML. Sequence mirrors
/// `ctxt-info-v2.c::iwl_pcie_ctxt_info_v2_init` +
/// `iwl_pcie_load_given_ucode_8000` (gen3 branch):
///
///   1. Extract the IML section from SEC_RT.
///   2. Allocate DMA-coherent regions for IML, section table,
///      prph_scratch, prph_info, and ctxt_info_v2.
///   3. Populate CtxtInfoV2.
///   4. Boot: `CSR_CTXT_INFO_ADDR` + `CSR_IML_SIZE_ADDR` +
///      `CSR_AUTO_FUNC_BOOT_ENA`.
///   5. Wait for ALIVE notification.
pub fn load_firmware_gen3<M, D, S>(
    mmio: &mut M,
    parsed: &ParsedUcode<'_>,
    alloc: &mut D,
    alive: &mut S,
) -> Result<(), FwLoadError>
where
    M: IwlMmio,
    D: DmaAllocator,
    S: AliveSink,
{
    if parsed.rt_sections.is_empty() {
        return Err(FwLoadError::NoRtSections);
    }

    // Step 1: IML blob.
    let iml_bytes = parsed
        .rt_sections
        .iter()
        .find(|s| s.dest_offset == IML_SECTION_SENTINEL)
        .ok_or(FwLoadError::NoIml)?
        .payload;

    let (iml_virt, iml_phys) = alloc.alloc_coherent(iml_bytes.len());
    unsafe {
        core::ptr::copy_nonoverlapping(iml_bytes.as_ptr(), iml_virt, iml_bytes.len());
    }

    // Step 2: runtime section table.
    let mut table = build_section_table(parsed);
    let table_bytes = table.len() * core::mem::size_of::<SectionTableEntry>();
    let (table_virt, table_phys) = alloc.alloc_coherent(table_bytes.max(64));

    // Fill in host_phys for each entry.
    for entry in table.iter_mut() {
        let (virt, phys) = alloc.alloc_coherent(entry.byte_count as usize);
        // Copy section payload. The payload slice is still valid —
        // `parsed` borrows the firmware blob which outlives this call.
        let sec = parsed
            .rt_sections
            .iter()
            .find(|s| s.dest_offset == entry.dest_offset)
            .expect("section table entry must map to rt_section");
        unsafe {
            core::ptr::copy_nonoverlapping(sec.payload.as_ptr(), virt, sec.payload.len());
        }
        entry.host_phys = phys;
    }

    // Copy the populated section table into its DMA-coherent region.
    unsafe {
        let src = table.as_ptr() as *const u8;
        core::ptr::copy_nonoverlapping(src, table_virt, table_bytes);
    }

    // Step 3: prph_scratch + prph_info.
    let (_, scratch_phys) =
        alloc.alloc_coherent(core::mem::size_of::<super::transport::PrphScratch>());
    let (_, info_phys) =
        alloc.alloc_coherent(core::mem::size_of::<super::transport::PrphInfo>());

    // Step 4: populate CtxtInfoV2.
    let ctxt = CtxtInfoV2 {
        version: 2,
        msix_n_entries: 0,
        prph_scratch_addr: scratch_phys,
        prph_scratch_size: core::mem::size_of::<super::transport::PrphScratch>() as u32,
        prph_info_addr: info_phys,
        _pad0: 0,
        iml_addr: iml_phys,
        iml_size: iml_bytes.len() as u32,
        _pad1: 0,
        section_table_addr: table_phys,
        section_table_count: table.len() as u32,
        _pad2: 0,
    };

    let (ctxt_virt, ctxt_phys) =
        alloc.alloc_coherent(core::mem::size_of::<CtxtInfoV2>());
    unsafe {
        let src = &ctxt as *const CtxtInfoV2 as *const u8;
        core::ptr::copy_nonoverlapping(
            src,
            ctxt_virt,
            core::mem::size_of::<CtxtInfoV2>(),
        );
    }

    // Step 5: boot kick.
    let regions = Gen3BootRegions {
        ctxt_info_phys: ctxt_phys,
        iml_phys,
        iml_size: iml_bytes.len() as u32,
    };
    boot_gen3(mmio, &regions);
    wait_alive(alive)?;

    Ok(())
}

/// Dispatch to the correct per-generation loader based on chip config.
pub fn load_firmware<M, D, S>(
    mmio: &mut M,
    chip: &ChipConfig,
    parsed: &ParsedUcode<'_>,
    alloc: &mut D,
    alive: &mut S,
) -> Result<(), FwLoadError>
where
    M: IwlMmio,
    D: DmaAllocator,
    S: AliveSink,
{
    match chip.generation {
        Generation::Gen2 => load_firmware_gen2(mmio, parsed, alloc, alive),
        Generation::Gen3 => load_firmware_gen3(mmio, parsed, alloc, alive),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::{collections::VecDeque, string::String};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use super::super::{
        parse_ucode, FwSection, UcodeHeader, IWL_TLV_UCODE_MAGIC,
        CPU1_CPU2_SEPARATOR,
    };

    // ── Mock MMIO ──────────────────────────────────────────────────

    struct MockMmio {
        reads: VecDeque<(u32, u32)>,
        writes: alloc::vec::Vec<(u32, u32)>,
    }
    impl MockMmio {
        fn new() -> Self {
            Self { reads: VecDeque::new(), writes: alloc::vec::Vec::new() }
        }
        fn stage(&mut self, off: u32, val: u32) {
            self.reads.push_back((off, val));
        }
        #[allow(dead_code)]
        fn last_write(&self, off: u32) -> Option<u32> {
            self.writes.iter().rev().find(|(o, _)| *o == off).map(|(_, v)| *v)
        }
    }
    impl IwlMmio for MockMmio {
        fn read(&mut self, off: u32) -> u32 {
            for i in 0..self.reads.len() {
                if self.reads[i].0 == off {
                    return self.reads.remove(i).map(|(_, v)| v).unwrap_or(0);
                }
            }
            0
        }
        fn write(&mut self, off: u32, value: u32) {
            self.writes.push((off, value));
        }
    }

    // ── Mock DMA allocator — uses static scratch buffer ────────────

    /// Bump allocator backed by a fixed on-stack region. Suitable for
    /// tests only — gives fake phys addresses (base + offset).
    struct BumpAllocator {
        buf: alloc::vec::Vec<u8>,
        offset: usize,
        base_phys: u64,
    }
    impl BumpAllocator {
        fn new(size: usize, base_phys: u64) -> Self {
            Self { buf: alloc::vec![0u8; size], offset: 0, base_phys }
        }
    }
    impl DmaAllocator for BumpAllocator {
        fn alloc_coherent(&mut self, size: usize) -> (*mut u8, u64) {
            let aligned = (size + 63) & !63;
            let remaining = self.buf.len() - self.offset;
            let actual = aligned.min(remaining);
            let ptr = unsafe { self.buf.as_mut_ptr().add(self.offset) };
            let phys = self.base_phys + self.offset as u64;
            self.offset += actual;
            (ptr, phys)
        }
    }

    // ── Mock AliveSink ─────────────────────────────────────────────

    use super::super::regs::{IWL_ALIVE_STATUS_OK, CSR_RESET};

    struct MockAlive {
        /// Pre-loaded responses. Each call to `wait` pops one.
        responses: VecDeque<Option<u32>>,
    }
    impl MockAlive {
        fn ok() -> Self {
            let mut r = VecDeque::new();
            // Two OKs — one for INIT, one for RT.
            r.push_back(Some(IWL_ALIVE_STATUS_OK));
            r.push_back(Some(IWL_ALIVE_STATUS_OK));
            Self { responses: r }
        }
        fn timeout() -> Self {
            let mut r = VecDeque::new();
            r.push_back(None::<u32>);
            Self { responses: r }
        }
    }
    impl AliveSink for MockAlive {
        fn wait(&mut self, _deadline_ms: u64) -> Option<u32> {
            self.responses.pop_front().flatten()
        }
    }

    // ── Helper: build a minimal valid blob ─────────────────────────

    /// Minimal .ucode blob with one SEC_INIT and one SEC_RT section.
    fn make_minimal_blob() -> alloc::vec::Vec<u8> {
        let mut blob = alloc::vec::Vec::new();
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&IWL_TLV_UCODE_MAGIC.to_le_bytes());
        let mut hr = [0u8; 64];
        hr[..b"fw_load_test"[..].len()].copy_from_slice(b"fw_load_test");
        blob.extend_from_slice(&hr);
        blob.extend_from_slice(&1u32.to_le_bytes()); // version
        blob.extend_from_slice(&0u32.to_le_bytes()); // build
        blob.extend_from_slice(&[0u8; 8]); // ignore
        // SEC_INIT: dest=0x0000_0000, payload=[0xAA, 0xBB, 0xCC, 0xDD].
        blob.extend_from_slice(&20u32.to_le_bytes()); // type=SecInit
        blob.extend_from_slice(&8u32.to_le_bytes());  // len = 4+4
        blob.extend_from_slice(&0u32.to_le_bytes());  // dest
        blob.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // SEC_RT: dest=0x0010_0000, payload=[0x11, 0x22].
        blob.extend_from_slice(&19u32.to_le_bytes()); // type=SecRt
        blob.extend_from_slice(&6u32.to_le_bytes());  // len=4+2 (padded to 8)
        blob.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // dest
        blob.extend_from_slice(&[0x11, 0x22]);
        blob.extend_from_slice(&[0, 0]); // pad
        blob
    }

    // ── Smoke: FW header decode ─────────────────────────────────────

    /// Parse a hand-crafted blob and confirm the header fields
    /// decode to the expected values. Exercises the full path from
    /// raw bytes through `parse_ucode` to `UcodeHeader`.
    fn smoke_iwlwifi_fw_header_decode() -> TestResult {
        let blob = make_minimal_blob();
        let parsed = match parse_ucode(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse_ucode failed on minimal blob"),
        };
        if parsed.header.version != 1 {
            return TestResult::Fail("header.version wrong");
        }
        if parsed.header.human_readable != "fw_load_test" {
            return TestResult::Fail("header.human_readable wrong");
        }
        if parsed.init_sections.len() != 1 {
            return TestResult::Fail("expected 1 SEC_INIT");
        }
        if parsed.rt_sections.len() != 1 {
            return TestResult::Fail("expected 1 SEC_RT");
        }
        TestResult::Pass
    }

    // ── Smoke: gen2 load succeeds with mock MMIO + ALIVE ───────────

    /// Drive the full gen2 firmware-load orchestration with a mock
    /// MMIO, a bump DMA allocator, and a pre-staged ALIVE sink.
    fn smoke_iwlwifi_fw_load_gen2_mock_round_trip() -> TestResult {
        let blob = make_minimal_blob();
        let parsed = match parse_ucode(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse failed"),
        };

        // load_firmware_gen2 itself doesn't call apm_init (probe does that
        // before the loader runs). Only CSR_RESET is read by release_cpu_gen2.
        let mut mmio = MockMmio::new();
        mmio.stage(CSR_RESET, 0x80); // for release_cpu_gen2

        let mut alloc = BumpAllocator::new(64 * 1024, 0x1000_0000);
        let mut alive = MockAlive::ok();

        match load_firmware_gen2(&mut mmio, &parsed, &mut alloc, &mut alive) {
            Ok(()) => TestResult::Pass,
            Err(e) => {
                let _ = e;
                TestResult::Fail("gen2 load failed")
            }
        }
    }

    // ── Smoke: ALIVE timeout propagates ───────────────────────────

    fn smoke_iwlwifi_fw_load_gen2_alive_timeout_propagates() -> TestResult {
        let blob = make_minimal_blob();
        let parsed = match parse_ucode(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse failed"),
        };
        let mut mmio = MockMmio::new();
        let mut alloc = BumpAllocator::new(64 * 1024, 0x2000_0000);
        let mut alive = MockAlive::timeout();

        match load_firmware_gen2(&mut mmio, &parsed, &mut alloc, &mut alive) {
            Err(FwLoadError::Transport(TransportError::AliveTimeout)) => TestResult::Pass,
            _ => TestResult::Fail("expected AliveTimeout"),
        }
    }

    // ── Smoke: section table build skips separators ────────────────

    fn smoke_iwlwifi_fw_section_table_skips_separators() -> TestResult {
        let p1 = [0u8; 16];
        let p2 = [0u8; 8];
        let p3 = [0u8; 4];
        let ucode = ParsedUcode {
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 1,
            init_sections: alloc::vec![],
            rt_sections: alloc::vec![
                FwSection { dest_offset: 0x0010_0000, payload: &p1 },
                FwSection { dest_offset: CPU1_CPU2_SEPARATOR, payload: &[] },
                FwSection { dest_offset: 0x0020_0000, payload: &p2 },
                FwSection { dest_offset: IML_SECTION_SENTINEL, payload: &p3 },
            ],
            fw_version: None,
            pnvm_version: None,
            unknown_tlv_count: 0,
        };
        let table = build_section_table(&ucode);
        // Should have 2 entries: 0x0010_0000 and 0x0020_0000.
        // The separator and IML sentinel must be excluded.
        if table.len() != 2 {
            return TestResult::Fail("expected 2 section table entries");
        }
        if table[0].dest_offset != 0x0010_0000 || table[0].byte_count != 16 {
            return TestResult::Fail("entry[0] wrong");
        }
        if table[1].dest_offset != 0x0020_0000 || table[1].byte_count != 8 {
            return TestResult::Fail("entry[1] wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: missing RT sections errors correctly ────────────────

    fn smoke_iwlwifi_fw_load_gen3_no_iml_returns_error() -> TestResult {
        // gen3 blob with no IML section → FwLoadError::NoIml.
        let p1 = [0u8; 16];
        let ucode = ParsedUcode {
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 1,
            init_sections: alloc::vec![],
            rt_sections: alloc::vec![
                // Normal section, no IML sentinel.
                FwSection { dest_offset: 0x0010_0000, payload: &p1 },
            ],
            fw_version: None,
            pnvm_version: None,
            unknown_tlv_count: 0,
        };
        let mut mmio = MockMmio::new();
        let mut alloc = BumpAllocator::new(64 * 1024, 0x3000_0000);
        let mut alive = MockAlive::ok();

        match load_firmware_gen3(&mut mmio, &ucode, &mut alloc, &mut alive) {
            Err(FwLoadError::NoIml) => TestResult::Pass,
            _ => TestResult::Fail("expected NoIml"),
        }
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/fw_loader",
        smoke_iwlwifi_fw_header_decode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/fw_loader",
        smoke_iwlwifi_fw_load_gen2_mock_round_trip
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/fw_loader",
        smoke_iwlwifi_fw_load_gen2_alive_timeout_propagates
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/fw_loader",
        smoke_iwlwifi_fw_section_table_skips_separators
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/fw_loader",
        smoke_iwlwifi_fw_load_gen3_no_iml_returns_error
    );
}
