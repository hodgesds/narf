//! Gen12 DMC firmware loading on the display-init path.
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
//! (`dmc_firmware_default`, `dmc_fallback_path`,
//! `dmc_load_work_fn`, `intel_dmc_load_program`) and
//! `intel_dmc_regs.h` — the on-disk reference at
//! `~/workspace/scratch/linux-i915-ref`.
//!
//! Failure is non-fatal by design, exactly as in Linux: a missing
//! or malformed blob only disables runtime power management — the
//! display still modesets. `load_for_display` logs the outcome and
//! returns it; the probe caller drops the result and continues.
//!
//! Firmware names (Linux `MODULE_FIRMWARE` strings):
//!
//! | Platform | Blob |
//! | --- | --- |
//! | Tiger Lake | `i915/tgl_dmc_ver2_12.bin` |
//! | Rocket Lake | `i915/rkl_dmc_ver2_03.bin` |
//! | Alder Lake-S | `i915/adls_dmc_ver2_01.bin` |
//! | Alder Lake-P (incl. Alder Lake-N, its subplatform) | `i915/adlp_dmc.bin`, fallback `i915/adlp_dmc_ver2_16.bin` |
//!
//! The fallback is Alder Lake-P only (`dmc_fallback_path` returns
//! a path for `alderlake_p` and `NULL` otherwise) and is tried
//! only when the primary name is absent (`-ENOENT`), never when
//! the registry refuses the open for another reason.
//!
//! Out of scope here:
//!
//! - DG1 (`i915/dg1_dmc_ver2_02.bin` in Linux): no Gen12 modeset
//!   path admits DG1 (`gen12_family_for_chip` never returns it),
//!   so there is no display-init site to load it from yet.
//! - Display 14 (Meteor Lake / Arrow Lake): its DMC lives in
//!   [`crate::intel_gpu_dc_states`], a separate programme.
//! - Retry after a later hot-install: Linux's load work fires
//!   once at init; a blob installed after probe is not picked
//!   up until the next probe. Same here.
//! - DC-state entry (DC5/DC6): the loaded program only *enables*
//!   the handoff; entering a DC state is the runtime-PM lane's
//!   job (`set_dc_target` in [`crate::intel_gpu_dmc`]).
//!
//! Blobs are never vendored into git (repo rule: firmware is
//! imported at build time via `cargo xtask import-firmware` /
//! `--initramfs-firmware` and lives in the registry). This module
//! only names the registry keys.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dmc::{
    load_program, parse_dmc_firmware, verify_loaded, DmcError, DmcId, DmcVerifyError,
    DMC_MAX_FW_SIZE_GEN12,
};
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_pm::{register_dmc_firmware, PmError};
use alloc::vec::Vec;
use narf_capabilities::{Cap, Read};

/// Tiger Lake DMC blob (`TGL_DMC_PATH`, `DMC_LEGACY_PATH(tgl, 2, 12)`).
pub const TGL_DMC_FIRMWARE: &str = "i915/tgl_dmc_ver2_12.bin";
/// Rocket Lake DMC blob (`RKL_DMC_PATH`, `DMC_LEGACY_PATH(rkl, 2, 03)`).
pub const RKL_DMC_FIRMWARE: &str = "i915/rkl_dmc_ver2_03.bin";
/// Alder Lake-S DMC blob (`ADLS_DMC_PATH`, `DMC_LEGACY_PATH(adls, 2, 01)`).
pub const ADLS_DMC_FIRMWARE: &str = "i915/adls_dmc_ver2_01.bin";
/// Alder Lake-P DMC blob (`ADLP_DMC_PATH`, `DMC_PATH(adlp)`).
pub const ADLP_DMC_FIRMWARE: &str = "i915/adlp_dmc.bin";
/// Alder Lake-P fallback blob (`ADLP_DMC_FALLBACK_PATH`,
/// `DMC_LEGACY_PATH(adlp, 2, 16)`).
pub const ADLP_DMC_FALLBACK_FIRMWARE: &str = "i915/adlp_dmc_ver2_16.bin";

/// The registry names for a Gen12 family: the primary blob, plus
/// the fallback Linux tries when the primary is absent (Alder
/// Lake-P only). `None` when the family has no DMC firmware on
/// the Gen12 modeset path — today only DG1, which no modeset
/// admits.
pub fn dmc_firmware_names(family: Gen12Platform) -> Option<(&'static str, Option<&'static str>)> {
    match family {
        Gen12Platform::TigerLake => Some((TGL_DMC_FIRMWARE, None)),
        Gen12Platform::RocketLake => Some((RKL_DMC_FIRMWARE, None)),
        Gen12Platform::AlderLakeS => Some((ADLS_DMC_FIRMWARE, None)),
        // Alder Lake-N is a subplatform of alderlake_p
        // (`intel_display_device.c`: `SUBPLATFORM(alderlake_p,
        // alderlake_n)`), so it takes the ADL-P blob + fallback.
        Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => {
            Some((ADLP_DMC_FIRMWARE, Some(ADLP_DMC_FALLBACK_FIRMWARE)))
        }
        Gen12Platform::Dg1 => None,
    }
}

/// Why the probe-time DMC load did not complete. Every variant
/// is non-fatal: the display modesets without DMC, with runtime
/// power management disabled — Linux's
/// `dmc_load_work_fn` failure path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmcLoadError {
    /// The family has no DMC blob on the Gen12 modeset path.
    Unsupported,
    /// No blob under any candidate name for this family.
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

/// A loaded Gen12 DMC: the blob that resolved, its CSS version
/// (major in the high half, minor in the low half — the
/// `v%u.%u` Linux logs), and the program bitmask the PM core
/// registered for the resume reload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmcLoaded {
    pub name: &'static str,
    pub version: u32,
    pub programs: u8,
}

impl DmcLoaded {
    /// Firmware major version (`DMC_VERSION_MAJOR`).
    pub fn version_major(self) -> u32 {
        self.version >> 16
    }

    /// Firmware minor version (`DMC_VERSION_MINOR`).
    pub fn version_minor(self) -> u32 {
        self.version & 0xffff
    }
}

fn log_load_outcome(outcome: &Result<DmcLoaded, DmcLoadError>, family: Gen12Platform) {
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
                "intel-gpu: Failed to load DMC firmware for {family:?} ({error:?}). Disabling runtime power management."
            );
        }
    }
}

/// Fetch the blob for `names`, trying the fallback when — and
/// only when — the primary name is absent, mirroring
/// `dmc_load_work_fn`. The `open` closure is the seam the
/// tests drive without a registry; production passes
/// `|name| narf_firmware::open(name, authority)`.
fn open_firmware_blob<T>(
    names: (&'static str, Option<&'static str>),
    mut open: impl FnMut(&'static str) -> Result<T, narf_firmware::FirmwareError>,
) -> Result<(T, &'static str), DmcLoadError> {
    let (primary, fallback) = names;
    match open(primary) {
        Ok(blob) => Ok((blob, primary)),
        Err(narf_firmware::FirmwareError::NotFound) => match fallback {
            Some(fallback) => match open(fallback) {
                Ok(blob) => Ok((blob, fallback)),
                Err(narf_firmware::FirmwareError::NotFound) => Err(DmcLoadError::NotFound),
                Err(narf_firmware::FirmwareError::AuthorityRevoked) => Err(DmcLoadError::Revoked),
                Err(error) => Err(DmcLoadError::Registry(error)),
            },
            None => Err(DmcLoadError::NotFound),
        },
        Err(narf_firmware::FirmwareError::AuthorityRevoked) => Err(DmcLoadError::Revoked),
        Err(error) => Err(DmcLoadError::Registry(error)),
    }
}

/// Parse, load and verify a blob's bytes against `mmio` —
/// `parse_dmc_fw` + `intel_dmc_load_program` + the
/// `assert_dmc_loaded` readback. Returns the CSS version and
/// the program bitmask. No registry, no PM-core registration:
/// the seam the fixture tests drive.
pub fn load_from_bytes<M: MmioWindow + ?Sized>(
    mmio: &M,
    bytes: &[u8],
) -> Result<(u32, u8), DmcLoadError> {
    let fw = parse_dmc_firmware(bytes, b'*', b'*', DMC_MAX_FW_SIZE_GEN12)
        .map_err(DmcLoadError::Parse)?;
    if !fw.has_main() {
        return Err(DmcLoadError::NoMainProgram);
    }
    load_program(mmio, &fw);
    verify_loaded(mmio, &fw).map_err(DmcLoadError::Verify)?;
    let mut programs = 0u8;
    for (i, id) in DmcId::ALL.iter().enumerate() {
        if fw.program(*id).is_some() {
            programs |= 1 << i;
        }
    }
    Ok((fw.version, programs))
}

/// Load the Gen12 DMC firmware for `family` on the display-init
/// path (`intel_dmc_init` + `dmc_load_work_fn`): fetch the blob
/// from the registry, parse, load, verify, then keep a resident
/// copy for the resume reload (`intel_dmc_resume` keeps the
/// parsed firmware in memory; here the PM core owns the copy
/// via `register_dmc_firmware`).
///
/// Non-fatal by design: every `Err` leaves the display usable
/// without DMC (no DC states) and is logged here, so the probe
/// caller drops the result and continues to modeset.
pub fn load_for_display<M: MmioWindow + ?Sized>(
    mmio: &M,
    family: Gen12Platform,
    authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
) -> Result<DmcLoaded, DmcLoadError> {
    let outcome = load_for_display_inner(mmio, family, authority);
    log_load_outcome(&outcome, family);
    outcome
}

fn load_for_display_inner<M: MmioWindow + ?Sized>(
    mmio: &M,
    family: Gen12Platform,
    authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
) -> Result<DmcLoaded, DmcLoadError> {
    let names = dmc_firmware_names(family).ok_or(DmcLoadError::Unsupported)?;
    let (blob, name) = open_firmware_blob(names, |name| narf_firmware::open(name, authority))?;
    let view = narf_firmware::view_of(&blob).map_err(|error| match error {
        narf_firmware::FirmwareError::AuthorityRevoked => DmcLoadError::Revoked,
        error => DmcLoadError::Registry(error),
    })?;
    let (version, programs) = load_from_bytes(mmio, view.bytes)?;
    // The PM core reloads from the registered bytes at resume,
    // so the copy must outlive this call — the same shape as
    // i915 keeping the firmware in memory after init. Leaked
    // once per boot, at most `DMC_MAX_FW_SIZE_GEN12` bytes.
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(view.bytes.len())
        .map_err(|_| DmcLoadError::Allocation)?;
    owned.extend_from_slice(view.bytes);
    let resident: &'static [u8] = alloc::boxed::Box::leak(owned.into_boxed_slice());
    let registered = register_dmc_firmware(resident).map_err(DmcLoadError::Register)?;
    debug_assert_eq!(registered, programs);
    Ok(DmcLoaded {
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
        DC_STATE_DEBUG_MASK_CORES, DC_STATE_DEBUG_MASK_MEMORY_UP, DMC_HEADER_V3_BYTES,
        DMC_SIGNATURE, EVT_CTL_DISABLED, EVT_HANDLER_COUNT_GEN12, FW_INFO_BYTES,
        PACKAGE_HEADER_BYTES, PACKAGE_V2_MAX_ENTRIES,
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

    /// A minimal DMC container: CSS header (v2.12), package v2,
    /// one Main program (v3 header, wildcard stepping) with a
    /// 4-dword payload and a one-entry MMIO table — the same
    /// layout as the PM core's `fixture_dmc_blob`.
    fn fixture_dmc_blob() -> Vec<u8> {
        fixture_dmc_blob_with_main(true)
    }

    fn fixture_dmc_blob_with_main(with_main: bool) -> Vec<u8> {
        let package_size = PACKAGE_HEADER_BYTES + PACKAGE_V2_MAX_ENTRIES * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0002_000C);
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
        put32(&mut blob, prog_off + 16, 0x0002_000C);
        put32(&mut blob, prog_off + 20, 0x80000);
        put32(&mut blob, prog_off + 92, if with_main { 1 } else { 0 });
        put32(&mut blob, prog_off + 96, 0x8F074); // DMC_SSP_BASE
        put32(&mut blob, prog_off + 176, 0x0000_2FC0);
        for (j, v) in payload.iter().enumerate() {
            put32(&mut blob, prog_off + DMC_HEADER_V3_BYTES + 4 * j, *v);
        }
        if !with_main {
            // Point the entry at a pipe slot with no program
            // instead: the container parses, but carries no
            // main program.
            blob[e + 1] = 1; // DmcId::PipeA
        }
        blob
    }

    fn smoke_gen12_dmc_firmware_names() -> TestResult {
        use Gen12Platform::*;
        if dmc_firmware_names(TigerLake) != Some((TGL_DMC_FIRMWARE, None))
            || dmc_firmware_names(RocketLake) != Some((RKL_DMC_FIRMWARE, None))
            || dmc_firmware_names(AlderLakeS) != Some((ADLS_DMC_FIRMWARE, None))
            || dmc_firmware_names(AlderLakeP)
                != Some((ADLP_DMC_FIRMWARE, Some(ADLP_DMC_FALLBACK_FIRMWARE)))
            || dmc_firmware_names(AlderLakeN)
                != Some((ADLP_DMC_FIRMWARE, Some(ADLP_DMC_FALLBACK_FIRMWARE)))
        {
            return TestResult::Fail("Gen12 DMC firmware name mapping wrong");
        }
        // DG1 has a Linux blob but no Gen12 modeset path admits
        // it, so the loader must not claim one.
        if dmc_firmware_names(Dg1).is_some() {
            return TestResult::Fail("DG1 must not map to a modeset-path DMC blob");
        }
        if TGL_DMC_FIRMWARE != "i915/tgl_dmc_ver2_12.bin"
            || RKL_DMC_FIRMWARE != "i915/rkl_dmc_ver2_03.bin"
            || ADLS_DMC_FIRMWARE != "i915/adls_dmc_ver2_01.bin"
            || ADLP_DMC_FIRMWARE != "i915/adlp_dmc.bin"
            || ADLP_DMC_FALLBACK_FIRMWARE != "i915/adlp_dmc_ver2_16.bin"
        {
            return TestResult::Fail("DMC firmware names diverge from intel_dmc.c");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_dmc",
        smoke_gen12_dmc_firmware_names
    );

    fn smoke_gen12_dmc_fallback_selection() -> TestResult {
        use narf_firmware::FirmwareError;
        let names = (ADLP_DMC_FIRMWARE, Some(ADLP_DMC_FALLBACK_FIRMWARE));
        // Primary present: the fallback is never tried.
        let mut calls: Vec<&str> = Vec::new();
        let found = open_firmware_blob(names, |name| {
            calls.push(name);
            Ok(1u8)
        });
        if !matches!(found, Ok((1, ADLP_DMC_FIRMWARE))) || calls != [ADLP_DMC_FIRMWARE] {
            return TestResult::Fail("primary blob must win without a fallback attempt");
        }
        // Primary absent: the fallback resolves.
        let mut calls: Vec<&str> = Vec::new();
        let found = open_firmware_blob(names, |name| {
            calls.push(name);
            if name == ADLP_DMC_FIRMWARE {
                Err(FirmwareError::NotFound)
            } else {
                Ok(2u8)
            }
        });
        if !matches!(found, Ok((2, ADLP_DMC_FALLBACK_FIRMWARE)))
            || calls != [ADLP_DMC_FIRMWARE, ADLP_DMC_FALLBACK_FIRMWARE]
        {
            return TestResult::Fail("absent primary must fall back to adlp_dmc_ver2_16.bin");
        }
        // Both absent: NotFound, after trying both names.
        let mut calls: Vec<&str> = Vec::new();
        let found = open_firmware_blob(names, |name| {
            calls.push(name);
            Err::<u8, _>(FirmwareError::NotFound)
        });
        if found != Err(DmcLoadError::NotFound)
            || calls != [ADLP_DMC_FIRMWARE, ADLP_DMC_FALLBACK_FIRMWARE]
        {
            return TestResult::Fail("absent primary + fallback must report NotFound");
        }
        // A non-absence refusal must NOT trigger the fallback:
        // a signature failure on the primary is the primary's
        // verdict, not a cue to load a different blob.
        let mut calls: Vec<&str> = Vec::new();
        let found = open_firmware_blob(names, |name| {
            calls.push(name);
            Err::<u8, _>(FirmwareError::SignatureInvalid)
        });
        if found != Err(DmcLoadError::Registry(FirmwareError::SignatureInvalid))
            || calls != [ADLP_DMC_FIRMWARE]
        {
            return TestResult::Fail("signature failure must not fall back");
        }
        // No fallback: a single absent-name attempt.
        let mut calls: Vec<&str> = Vec::new();
        let found = open_firmware_blob((TGL_DMC_FIRMWARE, None), |name| {
            calls.push(name);
            Err::<u8, _>(FirmwareError::NotFound)
        });
        if found != Err(DmcLoadError::NotFound) || calls != [TGL_DMC_FIRMWARE] {
            return TestResult::Fail("TGL must try exactly one name");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_dmc",
        smoke_gen12_dmc_fallback_selection
    );

    fn smoke_gen12_dmc_load_from_bytes() -> TestResult {
        let io = RegFile::new();
        let blob = fixture_dmc_blob();
        let (version, programs) = match load_from_bytes(&io, &blob) {
            Ok(result) => result,
            Err(_) => {
                return TestResult::Fail("fixture DMC blob refused at load");
            }
        };
        if version != 0x0002_000C || programs != 1 {
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
        // MMIO table entry, verbatim (DMC_SSP_BASE is not an
        // event-handler address, so no disable transform).
        if io.written(0x8F074) != Some(0x0000_2FC0) {
            return TestResult::Fail("DMC MMIO table entry missing");
        }
        // Every main-DMC event handler is swept disabled first,
        // EVT_CTL = TYPE EDGE_0_1 | EVENT FALSE, HTP zeroed.
        for h in 0..EVT_HANDLER_COUNT_GEN12 {
            let ctl = 0x8F000 + 0x034 + 4 * h as u64;
            let htp = 0x8F000 + 0x004 + 4 * h as u64;
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
        let writes = io.writes.borrow();
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
        "drivers/gpu/intel_gpu_gen12_dmc",
        smoke_gen12_dmc_load_from_bytes
    );

    fn smoke_gen12_dmc_corrupt_blob_writes_nothing() -> TestResult {
        let io = RegFile::new();
        let mut blob = fixture_dmc_blob();
        // Corrupt the CSS module type: the parser must refuse
        // before any register write.
        put32(&mut blob, 0, 0x08);
        if !matches!(
            load_from_bytes(&io, &blob),
            Err(DmcLoadError::Parse(DmcError::BadCssModuleType(0x08)))
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
            Err(DmcLoadError::Parse(_))
        ) {
            return TestResult::Fail("truncated DMC blob not refused as Parse");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("truncated DMC blob wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_dmc",
        smoke_gen12_dmc_corrupt_blob_writes_nothing
    );

    fn smoke_gen12_dmc_no_main_program() -> TestResult {
        let io = RegFile::new();
        // A container that parses but carries no main program
        // (its only entry is a pipe program): Linux reports
        // "DMC firmware main program not found" and loads
        // nothing.
        let blob = fixture_dmc_blob_with_main(false);
        if load_from_bytes(&io, &blob) != Err(DmcLoadError::NoMainProgram) {
            return TestResult::Fail("main-less DMC container not refused");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("main-less DMC container wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_dmc",
        smoke_gen12_dmc_no_main_program
    );
}
