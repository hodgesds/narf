//! GSP firmware acquisition + `nvfw` container parse (Turing+).
//!
//! ## Scope — lane GSP-1 (acquire + parse)
//!
//! On Turing and later the host driver no longer talks to most of
//! the GPU directly; it boots the **GSP** (GPU System Processor) by
//! staging NVIDIA-signed firmware and then speaks RPCs to it (see
//! [`crate::gsp`] for the RPC/ring layer). The very first step of
//! that flow — *locating and validating the firmware blobs* — is
//! what this module does. It does **not** stage anything into the
//! live Falcon yet (that needs real silicon; QEMU exposes no NVIDIA
//! GPU) and it does not construct the RM image's VRAM page tables.
//! Those are later lanes.
//!
//! The blobs come from the redistributable `linux-firmware` tree
//! under `nvidia/<chip>/gsp/`. NARF's [`narf_firmware`] registry
//! serves them by canonical name, cap-gated and signature-verified,
//! exactly as the AMD PSP path does (`drivers/gpu/src/amdgpu*`).
//!
//! ## Timing
//!
//! Firmware is only present in the registry after the `Stage::Late`
//! initramfs / rootfs scan, whereas the PCI probe runs at
//! `Stage::Subsys`. So acquisition is driven by a dedicated
//! `Stage::Late` pass ([`register_gsp_firmware_pass`]) registered
//! *after* the firmware scans, not inline in probe. The result per
//! card is stashed for later lanes and diagnostics via
//! [`last_report`].
//!
//! ## References
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/r535.c`**
//!   — `r535_gsp_load` requests `booter_load`, `booter_unload`,
//!   `bootloader`, and `gsp` under `nvidia/<chip>/gsp/<stem>-<ver>.bin`.
//! - **`include/nvfw/fw.h`** — `struct nvfw_bin_hdr`: the outer
//!   container wrapping every NVIDIA firmware binary.
//! - **`include/nvfw/hs.h`** — `struct nvfw_hs_header_v2` /
//!   `nvfw_hs_load_header_v2`: the "heavy-secure" (HS) layout the
//!   booter Falcons use, carrying the code/data split and the
//!   production signature.
//!
//! NARF licence: GPL-2.0-or-later. Nouveau citations are first-class
//! references.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareRegistry;

use crate::chip::{ChipFamily, ChipInfo};

/// GSP-RM firmware release this lane targets. The firmware filename
/// embeds the release, and the host-visible RPC layout is coupled to
/// it; `535.113.01` is Nouveau's canonical first GSP-RM set
/// (`nvkm/subdev/gsp/r535.c`). A later lane may select among several
/// installed releases.
pub const GSP_FW_VERSION: &str = "535.113.01";

/// One firmware blob the GSP boot flow needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GspBlobKind {
    /// HS Falcon ucode that sets up WPR2 and runs FWSEC-FRTS.
    BooterLoad,
    /// HS Falcon ucode that tears WPR2 back down on unload.
    BooterUnload,
    /// GSP-RM RISC-V bootloader image.
    Bootloader,
    /// The GSP-RM firmware image proper (large; VRAM-resident).
    GspRm,
    /// Ampere+ VRAM scrubber HS ucode run before WPR setup.
    Scrubber,
}

impl GspBlobKind {
    /// Filename stem under `nvidia/<chip>/gsp/`.
    pub const fn stem(self) -> &'static str {
        match self {
            GspBlobKind::BooterLoad => "booter_load",
            GspBlobKind::BooterUnload => "booter_unload",
            GspBlobKind::Bootloader => "bootloader",
            GspBlobKind::GspRm => "gsp",
            GspBlobKind::Scrubber => "scrubber",
        }
    }

    /// True when this blob is an HS (heavy-secure) Falcon container
    /// that GSP-1 parses with [`parse_booter`]. The RM image and the
    /// RISC-V bootloader use different layouts handled in later lanes.
    pub const fn is_hs_container(self) -> bool {
        matches!(
            self,
            GspBlobKind::BooterLoad | GspBlobKind::BooterUnload | GspBlobKind::Scrubber
        )
    }
}

/// The blobs each GSP family needs, in acquisition order. Turing
/// boots with the booter pair + bootloader + RM image; Ampere/Ada
/// additionally run a VRAM scrubber HS ucode before WPR setup
/// (`nvkm/subdev/gsp/ga102.c`).
pub const fn required_blobs(family: ChipFamily) -> &'static [GspBlobKind] {
    const TURING: &[GspBlobKind] = &[
        GspBlobKind::BooterLoad,
        GspBlobKind::BooterUnload,
        GspBlobKind::Bootloader,
        GspBlobKind::GspRm,
    ];
    const AMPERE_PLUS: &[GspBlobKind] = &[
        GspBlobKind::Scrubber,
        GspBlobKind::BooterLoad,
        GspBlobKind::BooterUnload,
        GspBlobKind::Bootloader,
        GspBlobKind::GspRm,
    ];
    match family {
        ChipFamily::Turing => TURING,
        ChipFamily::Ampere | ChipFamily::Ada => AMPERE_PLUS,
        _ => &[],
    }
}

/// Map a chip's ASIC tag to its `linux-firmware` directory. The tags
/// already match upstream for discrete parts; the mobile `ad106m`
/// variant shares the `ad106` firmware directory. Returns `None` for
/// a non-GSP ASIC.
pub fn fw_dir(asic: &str) -> Option<&'static str> {
    Some(match asic {
        // Turing.
        "tu102" => "tu102",
        "tu104" => "tu104",
        "tu106" => "tu106",
        "tu116" => "tu116",
        "tu117" => "tu117",
        // Ampere.
        "ga102" => "ga102",
        "ga104" => "ga104",
        "ga106" => "ga106",
        // Ada (mobile ad106m shares the ad106 blobs).
        "ad102" => "ad102",
        "ad103" => "ad103",
        "ad104" => "ad104",
        "ad106" | "ad106m" => "ad106",
        "ad107" => "ad107",
        _ => return None,
    })
}

/// Build the canonical registry name for a GSP blob:
/// `nvidia/<dir>/gsp/<stem>-<version>.bin`.
pub fn blob_name(dir: &str, kind: GspBlobKind, version: &str) -> String {
    let mut s = String::new();
    s.push_str("nvidia/");
    s.push_str(dir);
    s.push_str("/gsp/");
    s.push_str(kind.stem());
    s.push('-');
    s.push_str(version);
    s.push_str(".bin");
    s
}

// ── nvfw container parse ─────────────────────────────────────────

/// Error decoding an `nvfw` container.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvfwError {
    /// Buffer too small to hold the fixed `nvfw_bin_hdr`.
    TooSmall,
    /// A declared offset/size pair fell outside the blob. Carries a
    /// static tag naming which field so a maintainer can tell which
    /// structure was malformed.
    OutOfBounds(&'static str),
}

/// Outer container header. Wraps every NVIDIA firmware binary; the
/// `header_offset` points at the HS header and `data_offset` /
/// `data_size` bound the ucode image. Cite `include/nvfw/fw.h`
/// `struct nvfw_bin_hdr` (6 × u32, little-endian).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NvfwBinHdr {
    pub bin_magic: u32,
    pub bin_ver: u32,
    pub bin_size: u32,
    pub header_offset: u32,
    pub data_offset: u32,
    pub data_size: u32,
}

impl NvfwBinHdr {
    pub const SIZE: usize = 24;

    fn parse(buf: &[u8]) -> Result<Self, NvfwError> {
        if buf.len() < Self::SIZE {
            return Err(NvfwError::TooSmall);
        }
        Ok(Self {
            bin_magic: rd32(buf, 0),
            bin_ver: rd32(buf, 4),
            bin_size: rd32(buf, 8),
            header_offset: rd32(buf, 12),
            data_offset: rd32(buf, 16),
            data_size: rd32(buf, 20),
        })
    }
}

/// HS (heavy-secure) header v2. Carries the production signature and
/// points at the load header. Cite `include/nvfw/hs.h`
/// `struct nvfw_hs_header_v2` — the leading fields this lane reads
/// (`sig_prod_offset`, `sig_prod_size`, `header_offset`,
/// `header_size`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NvfwHsHeaderV2 {
    pub sig_prod_offset: u32,
    pub sig_prod_size: u32,
    pub patch_loc: u32,
    pub patch_sig: u32,
    pub meta_data_offset: u32,
    pub meta_data_size: u32,
    pub num_sig: u32,
    pub header_offset: u32,
    pub header_size: u32,
}

impl NvfwHsHeaderV2 {
    pub const SIZE: usize = 36;

    fn parse_at(buf: &[u8], at: u32) -> Result<Self, NvfwError> {
        let s = slice_at(buf, at, Self::SIZE, "hs_header_v2")?;
        Ok(Self {
            sig_prod_offset: rd32(s, 0),
            sig_prod_size: rd32(s, 4),
            patch_loc: rd32(s, 8),
            patch_sig: rd32(s, 12),
            meta_data_offset: rd32(s, 16),
            meta_data_size: rd32(s, 20),
            num_sig: rd32(s, 24),
            header_offset: rd32(s, 28),
            header_size: rd32(s, 32),
        })
    }
}

/// HS load header v2. Splits the image into OS code / OS data and is
/// followed by `num_apps` per-app descriptors. Cite `include/nvfw/hs.h`
/// `struct nvfw_hs_load_header_v2` — the fixed leading fields plus the
/// `app[]` tail (each app = `{offset, size, data_offset, data_size}`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NvfwHsLoadHeaderV2 {
    pub os_code_offset: u32,
    pub os_code_size: u32,
    pub os_data_offset: u32,
    pub os_data_size: u32,
    pub num_apps: u32,
}

impl NvfwHsLoadHeaderV2 {
    /// Size of the fixed leading fields (the `app[]` tail follows).
    pub const SIZE: usize = 20;
    /// Size of one `app[]` descriptor (offset, size, data_offset, data_size).
    pub const APP_SIZE: usize = 16;

    fn parse_at(buf: &[u8], at: u32) -> Result<Self, NvfwError> {
        let s = slice_at(buf, at, Self::SIZE, "hs_load_header_v2")?;
        Ok(Self {
            os_code_offset: rd32(s, 0),
            os_code_size: rd32(s, 4),
            os_data_offset: rd32(s, 8),
            os_data_size: rd32(s, 12),
            num_apps: rd32(s, 16),
        })
    }

    /// Read `app[idx]`'s `(offset, size)`. The app array begins right
    /// after the fixed fields at `load_at + SIZE`.
    fn app_at(buf: &[u8], load_at: u32, idx: u32) -> Result<(u32, u32), NvfwError> {
        let off = (load_at as u64)
            .checked_add(Self::SIZE as u64)
            .and_then(|b| b.checked_add((idx as u64) * (Self::APP_SIZE as u64)))
            .ok_or(NvfwError::OutOfBounds("hs_load_header_v2.app"))?;
        if off > u32::MAX as u64 {
            return Err(NvfwError::OutOfBounds("hs_load_header_v2.app"));
        }
        let s = slice_at(buf, off as u32, Self::APP_SIZE, "hs_load_header_v2.app")?;
        Ok((rd32(s, 0), rd32(s, 4)))
    }
}

/// Fully validated view of a booter (HS) firmware container: the
/// signed ucode image and its code/data split, all bounds-checked
/// against the blob. This is what a later lane stages into the GSP
/// Falcon's IMEM/DMEM via [`crate::falcon`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BooterImage {
    pub bin_magic: u32,
    pub bin_ver: u32,
    /// Ucode image within the blob (`bin_hdr.data_offset/size`).
    pub image_offset: u32,
    pub image_size: u32,
    /// Production signature within the blob.
    pub sig_offset: u32,
    pub sig_size: u32,
    /// OS (non-secure) code segment, relative to `image_offset`.
    pub code_offset: u32,
    pub code_size: u32,
    /// OS data segment, relative to `image_offset`.
    pub data_offset: u32,
    pub data_size: u32,
    /// Secure (HS) code segment = `app[0]` `(offset, size)`, relative
    /// to `image_offset`. On Turing the booter stages this as a
    /// SECURE-marked IMEM section after the non-secure `code` section;
    /// `(0, 0)` when the container declares no apps. Cite
    /// `nvkm/subdev/gsp/tu102.c::tu102_gsp_booter_ctor` (`imem_base =
    /// lhdr->app[0].offset`).
    pub sec_offset: u32,
    pub sec_size: u32,
}

/// Parse and validate a booter (HS) container. Every declared
/// offset/size is checked to lie within `buf`; the code/data
/// segments are checked to lie within the ucode image. Mirrors the
/// walk in `nvkm/falcon/fw.c::nvkm_falcon_fw_oneinit` /
/// `nvfw_hs_header_v2`.
pub fn parse_booter(buf: &[u8]) -> Result<BooterImage, NvfwError> {
    let bin = NvfwBinHdr::parse(buf)?;
    // The ucode image must lie within the blob.
    end_within(buf.len(), bin.data_offset, bin.data_size, "bin.data")?;
    // The HS header is at bin.header_offset.
    let hs = NvfwHsHeaderV2::parse_at(buf, bin.header_offset)?;
    end_within(buf.len(), hs.sig_prod_offset, hs.sig_prod_size, "hs.sig")?;
    // The load header is at hs.header_offset.
    let load = NvfwHsLoadHeaderV2::parse_at(buf, hs.header_offset)?;
    // Code/data segments are relative to the image and must fit it.
    end_within(
        bin.data_size as usize,
        load.os_code_offset,
        load.os_code_size,
        "load.code",
    )?;
    end_within(
        bin.data_size as usize,
        load.os_data_offset,
        load.os_data_size,
        "load.data",
    )?;
    // Secure HS section = app[0], when the container declares one.
    // The booter always does; a zero-app HS blob leaves it (0, 0).
    let (sec_offset, sec_size) = if load.num_apps >= 1 {
        let (off, size) = NvfwHsLoadHeaderV2::app_at(buf, hs.header_offset, 0)?;
        end_within(bin.data_size as usize, off, size, "load.app0")?;
        (off, size)
    } else {
        (0, 0)
    };
    Ok(BooterImage {
        bin_magic: bin.bin_magic,
        bin_ver: bin.bin_ver,
        image_offset: bin.data_offset,
        image_size: bin.data_size,
        sig_offset: hs.sig_prod_offset,
        sig_size: hs.sig_prod_size,
        code_offset: load.os_code_offset,
        code_size: load.os_code_size,
        data_offset: load.os_data_offset,
        data_size: load.os_data_size,
        sec_offset,
        sec_size,
    })
}

// ── acquisition ──────────────────────────────────────────────────

/// Outcome of trying to pull one blob from the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobResult {
    /// Found and (for HS containers) parsed. `booter` is `Some` only
    /// for [`GspBlobKind::is_hs_container`] blobs.
    Loaded {
        size: usize,
        booter: Option<BooterImage>,
    },
    /// The HS container was found but failed to parse.
    ParseError(NvfwError),
    /// Not present in the registry (not installed, or wrong version).
    Missing,
}

/// One blob's acquisition record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobOutcome {
    pub kind: GspBlobKind,
    pub name: String,
    pub result: BlobResult,
}

/// Per-card GSP firmware acquisition report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GspFirmware {
    pub asic: &'static str,
    pub family: ChipFamily,
    pub blobs: Vec<BlobOutcome>,
}

impl GspFirmware {
    /// True when every required blob was found (and every HS
    /// container parsed) — i.e. the card is ready for a staging lane.
    pub fn is_complete(&self) -> bool {
        !self.blobs.is_empty()
            && self
                .blobs
                .iter()
                .all(|b| matches!(b.result, BlobResult::Loaded { .. }))
    }

    /// Count of blobs still missing from the registry.
    pub fn missing_count(&self) -> usize {
        self.blobs
            .iter()
            .filter(|b| matches!(b.result, BlobResult::Missing))
            .count()
    }
}

/// Why acquisition could not even be attempted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcquireError {
    /// The chip family has no GSP (pre-Turing), or its ASIC tag has
    /// no firmware directory.
    NotGspFamily,
}

/// Attempt to acquire every required GSP blob for `chip` from the
/// firmware registry, parsing each HS container. Never stages
/// anything; purely a read + validate pass. The returned report
/// records per-blob presence so a caller can decide whether the card
/// can proceed to a staging lane.
pub fn acquire(
    chip: ChipInfo,
    fw: &Cap<FirmwareRegistry, Read>,
) -> Result<GspFirmware, AcquireError> {
    if !chip.family.has_gsp() {
        return Err(AcquireError::NotGspFamily);
    }
    let dir = fw_dir(chip.asic).ok_or(AcquireError::NotGspFamily)?;
    let mut blobs = Vec::new();
    for &kind in required_blobs(chip.family) {
        let name = blob_name(dir, kind, GSP_FW_VERSION);
        let result = acquire_one(&name, kind, fw);
        blobs.push(BlobOutcome { kind, name, result });
    }
    Ok(GspFirmware {
        asic: chip.asic,
        family: chip.family,
        blobs,
    })
}

fn acquire_one(name: &str, kind: GspBlobKind, fw: &Cap<FirmwareRegistry, Read>) -> BlobResult {
    let cap = match narf_firmware::open(name, fw) {
        Ok(cap) => cap,
        // Absent / wrong version / revoked all collapse to "not
        // available for staging"; the report tracks it as Missing.
        Err(_) => return BlobResult::Missing,
    };
    let view = match narf_firmware::view_of(&cap) {
        Ok(v) => v,
        Err(_) => return BlobResult::Missing,
    };
    if kind.is_hs_container() {
        match parse_booter(view.bytes) {
            Ok(booter) => BlobResult::Loaded {
                size: view.bytes.len(),
                booter: Some(booter),
            },
            Err(e) => BlobResult::ParseError(e),
        }
    } else {
        BlobResult::Loaded {
            size: view.bytes.len(),
            booter: None,
        }
    }
}

// ── runtime pass + report registry ───────────────────────────────

use narf_driver_runtime::Lock as IrqSafeSpinLock;

static REPORTS: IrqSafeSpinLock<Vec<(u32, GspFirmware)>> = IrqSafeSpinLock::new(Vec::new());

fn record_report(card_index: u32, report: GspFirmware) {
    let mut list = REPORTS.lock();
    if let Some(slot) = list.iter_mut().find(|(i, _)| *i == card_index) {
        slot.1 = report;
    } else {
        list.push((card_index, report));
    }
}

/// The most recent GSP firmware report for a card, if a pass has run
/// for it. Used by later lanes and diagnostics.
pub fn last_report(card_index: u32) -> Option<GspFirmware> {
    REPORTS
        .lock()
        .iter()
        .find(|(i, _)| *i == card_index)
        .map(|(_, r)| r.clone())
}

/// Run one acquisition pass over every bound GSP-capable card.
/// Returns the number of cards for which a report was recorded.
///
/// Best-effort: if the firmware registry is not yet populated, or no
/// firmware read authority can be derived, the pass records nothing
/// and returns 0 — it never blocks or panics.
pub fn run_acquire_pass() -> usize {
    if !narf_firmware::is_populated() {
        return 0;
    }
    let Some(auth) = narf_firmware::trusted_loader_authority() else {
        return 0;
    };
    let fw: Cap<FirmwareRegistry, Read> = match auth.derive() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let mut count = 0;
    for idx in crate::pci::card_indices() {
        let Some((chip, is_gsp)) =
            crate::pci::with_card(idx, |d| (d.chip, d.chip.family.has_gsp()))
        else {
            continue;
        };
        if !is_gsp {
            continue;
        }
        if let Ok(report) = acquire(chip, &fw) {
            record_report(idx, report);
            count += 1;
        }
    }
    count
}

/// Register the `Stage::Late` GSP firmware acquisition pass. Must be
/// registered *after* the firmware initramfs/rootfs scans so the
/// registry is populated when it runs (registration order is
/// execution order within a stage). Called from `bare_main` right
/// after `narf_firmware::register_rootfs_scan_initcall()`.
pub fn register_gsp_firmware_pass() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "nvidia-gsp-firmware", || {
        let _ = run_acquire_pass();
        InitResult::Ok
    });
}

/// Test helper — wipe the report registry for hermetic per-test state.
#[doc(hidden)]
pub fn __reset_for_test() {
    REPORTS.lock().clear();
}

// ── little-endian helpers ────────────────────────────────────────

/// Read a little-endian u32 at `off`. Caller guarantees
/// `off + 4 <= buf.len()` (all call sites bounds-check first).
fn rd32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Borrow a `len`-byte sub-slice at `at`, or `OutOfBounds(tag)`.
fn slice_at<'a>(
    buf: &'a [u8],
    at: u32,
    len: usize,
    tag: &'static str,
) -> Result<&'a [u8], NvfwError> {
    let start = at as usize;
    let end = start.checked_add(len).ok_or(NvfwError::OutOfBounds(tag))?;
    buf.get(start..end).ok_or(NvfwError::OutOfBounds(tag))
}

/// Check that `[off, off+size)` lies within `len`.
fn end_within(len: usize, off: u32, size: u32, tag: &'static str) -> Result<(), NvfwError> {
    let end = (off as usize)
        .checked_add(size as usize)
        .ok_or(NvfwError::OutOfBounds(tag))?;
    if end > len {
        return Err(NvfwError::OutOfBounds(tag));
    }
    Ok(())
}
