//! Gen9 DMC firmware loading on the display-init path.
//!
//! The parse/load/verify machinery lives in [`crate::intel_gpu_dmc`]
//! (Stage 5, #1014); this module is the probe-time wiring that
//! `intel_dmc_init` is in Linux: pick the platform blob, fetch it
//! from the firmware registry, parse it, stream it into the DMC
//! (`intel_dmc_load_program`), verify the load
//! (`assert_dmc_loaded`), and register the resident bytes with
//! [`crate::intel_gpu_pm`] so suspend/resume reloads them
//! (`intel_dmc_resume`'s reload; the core's `restore_dmc`).
//!
//! Pinned source: Linux `drivers/gpu/drm/i915/display/intel_dmc.c`
//! (`dmc_firmware_default`, `dmc_load_work_fn`,
//! `intel_dmc_load_program`) and `intel_dmc_regs.h` — the on-disk
//! reference at `~/workspace/scratch/linux-i915-ref`.
//!
//! Failure is fatal *for the modeset*, not for the probe — the
//! Lane 0 recorded default (spec §12.4, Q5), mirroring Gen12:
//! the display modeset refuses (`ModesetError::DmcUnavailable`)
//! when no DMC program loaded, because DC6 entry and the
//! DMC-driven power sequencing the modeset relies on are
//! unavailable without it. The probe itself continues so GT /
//! execlists still bind (a missing blob must not take the whole
//! GPU down); only the display modeset refuses. `load_for_display`
//! logs the outcome, records a successful load in the installed
//! flag the modeset gate reads, and returns the result; the probe
//! caller drops the result and continues.
//!
//! Firmware names (Linux `MODULE_FIRMWARE` strings, selected by
//! the `DISPLAY_VER == 9` arms of `dmc_firmware_default`):
//!
//! | Platform | Blob |
//! | --- | --- |
//! | Skylake | `i915/skl_dmc_ver1_27.bin` |
//! | Kaby Lake, Comet Lake | `i915/kbl_dmc_ver1_04.bin` |
//!
//! There is no fallback: `dmc_fallback_path` returns a path for
//! Alder Lake-P only, so an absent SKL/KBL blob is `NotFound`,
//! never a cue to try another name. Both shipped blobs are v1
//! packages (every entry is the main DMC); the parser refuses v3
//! program headers on display 9, as Linux's
//! `dmc_mmio_addr_sanity_check` does, and applies none of the
//! TGL/ADL-S event fixups (`fixup_dmc_evt` rewrites the HRR
//! handler on TGL/ADL-S only). Both blobs share the 0x3000
//! per-program payload ceiling (`BXT_DMC_MAX_FW_SIZE`).
//!
//! Blobs are never vendored into git (repo rule: firmware is
//! imported at build time via `cargo xtask import-firmware` /
//! `--initramfs-firmware` and lives in the registry). This module
//! only names the registry key.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dmc::{
    load_program, verify_loaded, DmcError, DmcId, DmcVerifyError, KBL_DMC_FIRMWARE,
    SKL_DMC_FIRMWARE,
};
use crate::intel_gpu_gt::Gen9Platform;
use crate::intel_gpu_pm::{register_dmc_firmware, PmError};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_capabilities::{Cap, Read};

/// Whether the probe-time Gen9 DMC load completed. Set by
/// [`load_for_display`] on success; the modeset gate
/// (`modeset_display_family`'s Gen9 arm) refuses the display
/// modeset while this is clear. Probe-only state: a failed
/// load never sets it, and nothing clears it once set.
static GEN9_DMC_LOADED: AtomicBool = AtomicBool::new(false);

/// Record a completed Gen9 DMC load (probe-time; also the
/// seam the modeset tests drive the gate through).
pub fn install_gen9_dmc_loaded() {
    GEN9_DMC_LOADED.store(true, Ordering::SeqCst);
}

/// Whether the probe-time Gen9 DMC load completed — the
/// modeset gate's input.
pub fn gen9_dmc_loaded() -> bool {
    GEN9_DMC_LOADED.load(Ordering::SeqCst)
}

/// Test-only reset for the installed flag. The flag is
/// probe-global, so fixtures that share it set it up front
/// instead of depending on run order.
#[cfg(feature = "kernel-test")]
pub(crate) fn set_gen9_dmc_loaded_for_test(loaded: bool) {
    GEN9_DMC_LOADED.store(loaded, Ordering::SeqCst);
}

/// The registry name for a Gen9 family: Linux selects
/// `SKL_DMC_PATH` for Skylake and `KBL_DMC_PATH` for Kaby
/// Lake / Coffee Lake / Whiskey Lake / Comet Lake
/// (`dmc_firmware_default`'s display-9 arms).
pub fn dmc_firmware_name(family: Gen9Platform) -> &'static str {
    match family {
        Gen9Platform::Skylake => SKL_DMC_FIRMWARE,
        Gen9Platform::KabyLake | Gen9Platform::CometLake => KBL_DMC_FIRMWARE,
        // `dmc_firmware_default`'s Gen9-LP arms. No Gen9-LP display path
        // loads it today (the DPIO PHY display is not programmed).
        Gen9Platform::Broxton => crate::intel_gpu_dmc::BXT_DMC_FIRMWARE,
        Gen9Platform::GeminiLake => crate::intel_gpu_dmc::GLK_DMC_FIRMWARE,
    }
}

/// Why the probe-time DMC load did not complete. Every variant
/// is fatal for the display modeset (the Q5 default: DMC is
/// REQUIRED, mirroring Gen12) but non-fatal for the probe —
/// GT / execlists still bind, and the display modeset refuses
/// with `ModesetError::DmcUnavailable` until a load completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9DmcLoadError {
    /// No blob under the SKL/KBL name for this family.
    NotFound,
    /// The registry refused the open for a reason other than
    /// absence (e.g. a bad signature).
    Registry(narf_firmware::FirmwareError),
    /// The registry cap was revoked mid-load.
    Revoked,
    /// The blob failed the container validation in
    /// [`crate::intel_gpu_dmc`]; no register was written.
    Parse(DmcError),
    /// The container carries no main program — Linux's
    /// "DMC firmware main program not found"; nothing was
    /// loaded, because there is nothing to hand the DC
    /// states to.
    NoMainProgram,
    /// The post-load readback disagreed with what the load
    /// wrote (program RAM start dword or an MMIO entry).
    Verify(DmcVerifyError),
    /// The resident copy could not be registered with the
    /// PM core for the resume reload.
    Register(PmError),
    /// The firmware copy could not be allocated.
    Allocation,
}

/// A loaded Gen9 DMC: the blob that resolved, its CSS version
/// (major in the high half, minor in the low half — the
/// `v%u.%u` Linux logs), and the program bitmask the PM core
/// registered for the resume reload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gen9DmcLoaded {
    pub name: &'static str,
    pub version: u32,
    pub programs: u8,
}

impl Gen9DmcLoaded {
    /// Firmware major version (`DMC_VERSION_MAJOR`).
    pub fn version_major(self) -> u32 {
        self.version >> 16
    }

    /// Firmware minor version (`DMC_VERSION_MINOR`).
    pub fn version_minor(self) -> u32 {
        self.version & 0xffff
    }
}

fn log_load_outcome(outcome: &Result<Gen9DmcLoaded, Gen9DmcLoadError>, family: Gen9Platform) {
    use core::fmt::Write as _;
    match outcome {
        Ok(loaded) => {
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu: Finished loading DMC firmware {} (v{}.{})",
                loaded.name,
                loaded.version_major(),
                loaded.version_minor()
            );
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu: Failed to load DMC firmware for {family:?} ({error:?}). Display modeset refused until DMC loads."
            );
        }
    }
}

/// Parse, load and verify a blob's bytes against `mmio` —
/// `parse_dmc_fw` + `intel_dmc_load_program` + the
/// `assert_dmc_loaded` readback. Returns the CSS version and
/// the program bitmask. No registry, no PM-core registration:
/// the seam the fixture tests drive.
#[cfg(any(test, feature = "kernel-test"))]
pub fn load_from_bytes<M: MmioWindow + ?Sized>(
    mmio: &M,
    bytes: &[u8],
) -> Result<(u32, u8), Gen9DmcLoadError> {
    load_from_bytes_max(mmio, bytes, crate::intel_gpu_dmc::SKL_DMC_MAX_FW_SIZE)
}

/// [`load_from_bytes`] under the platform's payload ceiling (Gemini Lake's
/// is larger).
pub fn load_from_bytes_max<M: MmioWindow + ?Sized>(
    mmio: &M,
    bytes: &[u8],
    max: usize,
) -> Result<(u32, u8), Gen9DmcLoadError> {
    let fw = crate::intel_gpu_dmc::parse_dmc_firmware_gen9_max(bytes, b'*', b'*', max).map_err(
        |error| match error {
            // `parse_for` reports a main-less container as
            // `NoMainProgram`; surface it as the load error of the
            // same name instead of burying it under `Parse` —
            // otherwise the `has_main()` gate below is unreachable
            // (a successful parse always carries a main program)
            // and callers cannot tell "no main program" from a
            // malformed container. All other parse refusals stay
            // `Parse`.
            DmcError::NoMainProgram => Gen9DmcLoadError::NoMainProgram,
            error => Gen9DmcLoadError::Parse(error),
        },
    )?;
    if !fw.has_main() {
        return Err(Gen9DmcLoadError::NoMainProgram);
    }
    load_program(mmio, &fw);
    verify_loaded(mmio, &fw).map_err(Gen9DmcLoadError::Verify)?;
    let mut programs = 0u8;
    for (i, id) in DmcId::ALL.iter().enumerate() {
        if fw.program(*id).is_some() {
            programs |= 1 << i;
        }
    }
    Ok((fw.version, programs))
}

/// Load the Gen9 DMC firmware for `family` on the display-init
/// path (`intel_dmc_init` + `dmc_load_work_fn`): fetch the blob
/// from the registry, parse, load, verify, then keep a resident
/// copy for the resume reload (`intel_dmc_resume` keeps the
/// parsed firmware in memory; here the PM core owns the copy
/// via `register_dmc_firmware`).
///
/// A successful load records the installed flag, which the
/// display modeset gate reads. A failed load leaves the flag
/// clear — the probe continues (GT / execlists still bind)
/// but the display modeset refuses — and is logged here, so
/// the probe caller drops the result and continues.
pub fn load_for_display<M: MmioWindow + ?Sized>(
    mmio: &M,
    family: Gen9Platform,
    authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
) -> Result<Gen9DmcLoaded, Gen9DmcLoadError> {
    let outcome = load_for_display_inner(mmio, family, authority);
    log_load_outcome(&outcome, family);
    if outcome.is_ok() {
        install_gen9_dmc_loaded();
    }
    outcome
}

fn load_for_display_inner<M: MmioWindow + ?Sized>(
    mmio: &M,
    family: Gen9Platform,
    authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
) -> Result<Gen9DmcLoaded, Gen9DmcLoadError> {
    let name = dmc_firmware_name(family);
    let blob = narf_firmware::open(name, authority).map_err(|error| match error {
        narf_firmware::FirmwareError::NotFound => Gen9DmcLoadError::NotFound,
        narf_firmware::FirmwareError::AuthorityRevoked => Gen9DmcLoadError::Revoked,
        error => Gen9DmcLoadError::Registry(error),
    })?;
    let view = narf_firmware::view_of(&blob).map_err(|error| match error {
        narf_firmware::FirmwareError::AuthorityRevoked => Gen9DmcLoadError::Revoked,
        error => Gen9DmcLoadError::Registry(error),
    })?;
    let max = if family == Gen9Platform::GeminiLake {
        crate::intel_gpu_dmc::GLK_DMC_MAX_FW_SIZE
    } else {
        crate::intel_gpu_dmc::SKL_DMC_MAX_FW_SIZE
    };
    let (version, programs) = load_from_bytes_max(mmio, view.bytes, max)?;
    // The PM core reloads from the registered bytes at resume,
    // so the copy must outlive this call — the same shape as
    // i915 keeping the firmware in memory after init. Leaked
    // once per boot, at most `SKL_DMC_MAX_FW_SIZE` bytes.
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(view.bytes.len())
        .map_err(|_| Gen9DmcLoadError::Allocation)?;
    owned.extend_from_slice(view.bytes);
    let resident: &'static [u8] = alloc::boxed::Box::leak(owned.into_boxed_slice());
    let registered = register_dmc_firmware(resident).map_err(Gen9DmcLoadError::Register)?;
    debug_assert_eq!(registered, programs);
    Ok(Gen9DmcLoaded {
        name,
        version,
        programs,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::intel_gpu_dmc::{
        CSS_HEADER_BYTES, CSS_HEADER_VER, CSS_MODULE_TYPE_DMC, CSS_VERSION_OFFSET, DC_STATE_DEBUG,
        DC_STATE_DEBUG_MASK_CORES, DC_STATE_DEBUG_MASK_MEMORY_UP, DMC_HEADER_V1_BYTES,
        DMC_HEADER_V3_BYTES, DMC_SIGNATURE, EVT_CTL_DISABLED, EVT_HANDLER_COUNT_GEN12,
        FW_INFO_BYTES, PACKAGE_HEADER_BYTES, PACKAGE_V1_MAX_ENTRIES, PACKAGE_V2_MAX_ENTRIES,
    };
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Write-through register file: reads return the last
    /// value written, so `verify_loaded` can read back what
    /// the load wrote, while `writes` keeps the full CSR
    /// sequence for assertions.
    struct RegFile {
        writes: RefCell<Vec<(u64, u32)>>,
        regs: RefCell<Vec<(u64, u32)>>,
    }

    impl RegFile {
        fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                regs: RefCell::new(Vec::new()),
            }
        }

        fn written(&self, off: u64) -> Option<u32> {
            self.writes
                .borrow()
                .iter()
                .rev()
                .find(|(o, _)| *o == off)
                .map(|(_, v)| *v)
        }
    }

    impl MmioWindow for RegFile {
        fn read32(&self, off: u64) -> u32 {
            self.regs
                .borrow()
                .iter()
                .rev()
                .find(|(o, _)| *o == off)
                .map_or(0, |(_, v)| *v)
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            let mut regs = self.regs.borrow_mut();
            match regs.iter_mut().find(|(o, _)| *o == off) {
                Some(slot) => slot.1 = val,
                None => regs.push((off, val)),
            }
        }
    }

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A minimal SKL DMC container: CSS header (v1.27), package
    /// v1 (every entry is the main DMC), one main program (v1
    /// header, wildcard stepping) with a 4-dword payload and a
    /// 3-entry MMIO table. The table carries a VBLANK_A
    /// EVT_CTL/HTP pair first: on Gen12 that pair would be
    /// rewritten to VBLANK_DELAYED_A by the TGL fixup and then
    /// disabled at load; on Gen9 both must pass through
    /// verbatim.
    fn fixture_dmc_blob() -> Vec<u8> {
        let package_size = PACKAGE_HEADER_BYTES + PACKAGE_V1_MAX_ENTRIES * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0001_001B);
        let pkg = CSS_HEADER_BYTES;
        blob[pkg] = (package_size / 4) as u8;
        blob[pkg + 1] = 1;
        put32(&mut blob, pkg + 12, 1);
        let e = pkg + PACKAGE_HEADER_BYTES;
        blob[e + 2] = b'*';
        blob[e + 3] = b'*';
        put32(&mut blob, e + 4, 0);
        let payload = [0xDAC0_0001u32, 0xDAC0_0002, 0xDAC0_0003, 0xDAC0_0004];
        let prog_off = blob.len();
        blob.resize(prog_off + DMC_HEADER_V1_BYTES + payload.len() * 4, 0);
        put32(&mut blob, prog_off, DMC_SIGNATURE);
        // The v1 quirk: header_len is in *bytes*.
        blob[prog_off + 4] = DMC_HEADER_V1_BYTES as u8;
        blob[prog_off + 5] = 1;
        put32(&mut blob, prog_off + 8, 0x12);
        put32(&mut blob, prog_off + 12, payload.len() as u32);
        put32(&mut blob, prog_off + 16, 0x0001_001B);
        put32(&mut blob, prog_off + 20, 3);
        // Main EVT_CTL handler 0 (0x8F034) with the VBLANK_A
        // event (0x32 in bits 15:8), then its HTP (0x8F004).
        put32(&mut blob, prog_off + 24, 0x8F034);
        put32(&mut blob, prog_off + 28, 0x8F004);
        put32(&mut blob, prog_off + 32, 0x8F074); // DMC_SSP_BASE
        put32(&mut blob, prog_off + 56, 0x0003_3200);
        put32(&mut blob, prog_off + 60, 0x0000_0000);
        put32(&mut blob, prog_off + 64, 0x0000_2FC0);
        for (j, v) in payload.iter().enumerate() {
            put32(&mut blob, prog_off + DMC_HEADER_V1_BYTES + 4 * j, *v);
        }
        blob
    }

    /// The same container shape with a v3 program header
    /// (package v2, one main entry): Linux refuses a v3 header
    /// on display 9 outright.
    fn fixture_v3_blob() -> Vec<u8> {
        let package_size = PACKAGE_HEADER_BYTES + PACKAGE_V2_MAX_ENTRIES * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0001_001B);
        let pkg = CSS_HEADER_BYTES;
        blob[pkg] = (package_size / 4) as u8;
        blob[pkg + 1] = 2;
        put32(&mut blob, pkg + 12, 1);
        let e = pkg + PACKAGE_HEADER_BYTES;
        blob[e + 1] = 0; // DmcId::Main
        blob[e + 2] = b'*';
        blob[e + 3] = b'*';
        put32(&mut blob, e + 4, 0);
        let payload = [0xDAC0_0001u32, 0xDAC0_0002, 0xDAC0_0003, 0xDAC0_0004];
        let prog_off = blob.len();
        blob.resize(prog_off + DMC_HEADER_V3_BYTES + payload.len() * 4, 0);
        put32(&mut blob, prog_off, DMC_SIGNATURE);
        blob[prog_off + 4] = (DMC_HEADER_V3_BYTES / 4) as u8;
        blob[prog_off + 5] = 3;
        put32(&mut blob, prog_off + 8, 0x12);
        put32(&mut blob, prog_off + 12, payload.len() as u32);
        put32(&mut blob, prog_off + 16, 0x0001_001B);
        put32(&mut blob, prog_off + 20, 0x80000);
        put32(&mut blob, prog_off + 92, 1);
        put32(&mut blob, prog_off + 96, 0x8F074); // DMC_SSP_BASE
        put32(&mut blob, prog_off + 176, 0x0000_2FC0);
        for (j, v) in payload.iter().enumerate() {
            put32(&mut blob, prog_off + DMC_HEADER_V3_BYTES + 4 * j, *v);
        }
        blob
    }

    /// A container that parses but carries no main program: a
    /// package-v2 pipe-A program (v1 header, so it parses on
    /// Gen9) and no main entry.
    fn fixture_no_main_blob() -> Vec<u8> {
        let package_size = PACKAGE_HEADER_BYTES + PACKAGE_V2_MAX_ENTRIES * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0001_001B);
        let pkg = CSS_HEADER_BYTES;
        blob[pkg] = (package_size / 4) as u8;
        blob[pkg + 1] = 2;
        put32(&mut blob, pkg + 12, 1);
        let e = pkg + PACKAGE_HEADER_BYTES;
        blob[e + 1] = 1; // DmcId::PipeA
        blob[e + 2] = b'*';
        blob[e + 3] = b'*';
        put32(&mut blob, e + 4, 0);
        let payload = [0xDAC0_0001u32, 0xDAC0_0002, 0xDAC0_0003, 0xDAC0_0004];
        let prog_off = blob.len();
        blob.resize(prog_off + DMC_HEADER_V1_BYTES + payload.len() * 4, 0);
        put32(&mut blob, prog_off, DMC_SIGNATURE);
        blob[prog_off + 4] = DMC_HEADER_V1_BYTES as u8;
        blob[prog_off + 5] = 1;
        put32(&mut blob, prog_off + 8, 0x12);
        put32(&mut blob, prog_off + 12, payload.len() as u32);
        put32(&mut blob, prog_off + 16, 0x0001_001B);
        put32(&mut blob, prog_off + 20, 1);
        put32(&mut blob, prog_off + 24, 0x8F074);
        put32(&mut blob, prog_off + 56, 0x0000_2FC0);
        for (j, v) in payload.iter().enumerate() {
            put32(&mut blob, prog_off + DMC_HEADER_V1_BYTES + 4 * j, *v);
        }
        blob
    }

    fn smoke_gen9_dmc_firmware_name() -> TestResult {
        use Gen9Platform::*;
        if dmc_firmware_name(Skylake) != SKL_DMC_FIRMWARE
            || dmc_firmware_name(KabyLake) != KBL_DMC_FIRMWARE
            || dmc_firmware_name(CometLake) != KBL_DMC_FIRMWARE
        {
            return TestResult::Fail("Gen9 platform must map to its SKL/KBL blob");
        }
        if SKL_DMC_FIRMWARE != "i915/skl_dmc_ver1_27.bin"
            || KBL_DMC_FIRMWARE != "i915/kbl_dmc_ver1_04.bin"
        {
            return TestResult::Fail("Gen9 DMC firmware names diverge from intel_dmc.c");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_firmware_name
    );

    fn smoke_gen9_dmc_load_from_bytes() -> TestResult {
        let io = RegFile::new();
        let blob = fixture_dmc_blob();
        let (version, programs) = match load_from_bytes(&io, &blob) {
            Ok(result) => result,
            Err(_) => {
                return TestResult::Fail("fixture SKL DMC blob refused at load");
            }
        };
        if version != 0x0001_001B || programs != 1 {
            return TestResult::Fail("loaded DMC version/program mask wrong");
        }
        // Payload dword stream to program RAM at 0x80000.
        for (i, expected) in [0xDAC0_0001u32, 0xDAC0_0002, 0xDAC0_0003, 0xDAC0_0004]
            .iter()
            .enumerate()
        {
            if io.written(0x80000 + 4 * i as u64) != Some(*expected) {
                return TestResult::Fail("DMC payload dword missing from program RAM");
            }
        }
        // The VBLANK_A EVT_CTL/HTP pair passes through verbatim:
        // no TGL fixup rewrites the event to VBLANK_DELAYED_A,
        // and no TGL/ADL-S load-time disable clears it. (The
        // handler sweep wrote EVT_CTL_DISABLED first; the MMIO
        // table write that follows is the last word.)
        if io.written(0x8F034) != Some(0x0003_3200) || io.written(0x8F004) != Some(0) {
            return TestResult::Fail("Gen9 must not apply the TGL event fixups");
        }
        // MMIO table entry, verbatim (DMC_SSP_BASE is not an
        // event-handler address, so no disable transform).
        if io.written(0x8F074) != Some(0x0000_2FC0) {
            return TestResult::Fail("DMC MMIO table entry missing");
        }
        // Every main-DMC event handler is swept disabled first,
        // EVT_CTL = TYPE EDGE_0_1 | EVENT FALSE, HTP zeroed.
        // Handler 0's CTL is then overwritten by the MMIO table
        // (the verbatim VBLANK_A write), so for it the sweep is
        // checked in order, not as the last word; its HTP is
        // zeroed by both the sweep and the table.
        let writes = io.writes.borrow();
        for h in 0..EVT_HANDLER_COUNT_GEN12 {
            let ctl = 0x8F000 + 0x034 + 4 * h as u64;
            let htp = 0x8F000 + 0x004 + 4 * h as u64;
            if h == 0 {
                let Some(disabled_at) = writes
                    .iter()
                    .position(|(o, v)| *o == ctl && *v == EVT_CTL_DISABLED)
                else {
                    return TestResult::Fail("main DMC event handler 0 not swept disabled");
                };
                let Some(table_at) = writes
                    .iter()
                    .position(|(o, v)| *o == ctl && *v == 0x0003_3200)
                else {
                    return TestResult::Fail("main DMC event handler 0 table write missing");
                };
                if disabled_at >= table_at {
                    return TestResult::Fail("handler sweep must precede the MMIO table write");
                }
                if writes.iter().filter(|(o, v)| *o == htp && *v == 0).count() != 2 {
                    return TestResult::Fail("handler 0 HTP must be zeroed twice (sweep, table)");
                }
                continue;
            }
            if io.written(ctl) != Some(EVT_CTL_DISABLED) || io.written(htp) != Some(0) {
                return TestResult::Fail("main DMC event handler not swept disabled");
            }
        }
        // DC_STATE_DEBUG mask (CORES | MEMORY_UP) is set, and
        // the posting read ran — the load's final writes.
        let debug = io.written(DC_STATE_DEBUG);
        if debug.is_none()
            || debug.unwrap() & (DC_STATE_DEBUG_MASK_CORES | DC_STATE_DEBUG_MASK_MEMORY_UP)
                != (DC_STATE_DEBUG_MASK_CORES | DC_STATE_DEBUG_MASK_MEMORY_UP)
        {
            return TestResult::Fail("DC_STATE_DEBUG mask not set by the DMC load");
        }
        // The payload went out before the MMIO table, which went
        // out before the debug mask: the `dmc_load_program`
        // order.
        let payload_at = writes
            .iter()
            .position(|(o, _)| *o == 0x80000)
            .unwrap_or(usize::MAX);
        let mmio_at = writes
            .iter()
            .position(|(o, _)| *o == 0x8F074)
            .unwrap_or(usize::MAX);
        let debug_at = writes
            .iter()
            .position(|(o, _)| *o == DC_STATE_DEBUG)
            .unwrap_or(usize::MAX);
        if !(payload_at < mmio_at && mmio_at < debug_at) {
            return TestResult::Fail("DMC load order is not payload, MMIO table, debug mask");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_load_from_bytes
    );

    fn smoke_gen9_dmc_corrupt_blob_writes_nothing() -> TestResult {
        let io = RegFile::new();
        let mut blob = fixture_dmc_blob();
        // Corrupt the CSS module type: the parser must refuse
        // before any register write.
        put32(&mut blob, 0, 0x08);
        if !matches!(
            load_from_bytes(&io, &blob),
            Err(Gen9DmcLoadError::Parse(DmcError::BadCssModuleType(0x08)))
        ) {
            return TestResult::Fail("corrupt CSS module type not refused as Parse");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("refused DMC blob wrote registers");
        }
        // A truncated blob is refused the same way, with no
        // writes either.
        let io = RegFile::new();
        if !matches!(
            load_from_bytes(&io, &blob[..64]),
            Err(Gen9DmcLoadError::Parse(_))
        ) {
            return TestResult::Fail("truncated DMC blob not refused as Parse");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("truncated DMC blob wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_corrupt_blob_writes_nothing
    );

    fn smoke_gen9_dmc_v3_header_refused() -> TestResult {
        let io = RegFile::new();
        let blob = fixture_v3_blob();
        if load_from_bytes(&io, &blob)
            != Err(Gen9DmcLoadError::Parse(
                DmcError::HeaderVersionUnsupported { header_ver: 3 },
            ))
        {
            return TestResult::Fail("v3 program header must be refused on display 9");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("refused v3 DMC blob wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_v3_header_refused
    );

    fn smoke_gen9_dmc_no_main_program() -> TestResult {
        let io = RegFile::new();
        // A container that parses but carries no main program
        // (its only entry is a pipe program): Linux reports
        // "DMC firmware main program not found" and loads
        // nothing.
        let blob = fixture_no_main_blob();
        if load_from_bytes(&io, &blob) != Err(Gen9DmcLoadError::NoMainProgram) {
            return TestResult::Fail("main-less DMC container not refused");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("main-less DMC container wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_no_main_program
    );

    fn smoke_gen9_dmc_over_ceiling_refused() -> TestResult {
        let io = RegFile::new();
        let mut blob = fixture_dmc_blob();
        // Claim a 0xC01-dword (12292-byte) payload: past the
        // 0x3000 Gen9 ceiling, so the parser must refuse with
        // PayloadTooLarge before any register write. (The
        // ceiling check precedes the truncation check, so the
        // short blob is enough.)
        let prog_off =
            CSS_HEADER_BYTES + PACKAGE_HEADER_BYTES + PACKAGE_V1_MAX_ENTRIES * FW_INFO_BYTES;
        put32(&mut blob, prog_off + 12, 0xC01);
        if !matches!(
            load_from_bytes(&io, &blob),
            Err(Gen9DmcLoadError::Parse(DmcError::PayloadTooLarge(12292)))
        ) {
            return TestResult::Fail("over-0x3000 DMC payload must be refused as PayloadTooLarge");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("over-ceiling DMC blob wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_over_ceiling_refused
    );

    fn smoke_gen9_dmc_installed_flag() -> TestResult {
        set_gen9_dmc_loaded_for_test(false);
        if gen9_dmc_loaded() {
            return TestResult::Fail("installed flag must start clear in the test");
        }
        install_gen9_dmc_loaded();
        if !gen9_dmc_loaded() {
            return TestResult::Fail("install must set the installed flag");
        }
        set_gen9_dmc_loaded_for_test(false);
        if gen9_dmc_loaded() {
            return TestResult::Fail("test-only setter must clear the installed flag");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dmc",
        smoke_gen9_dmc_installed_flag
    );
}
