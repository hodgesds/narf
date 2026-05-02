//! narf-firmware — kernel firmware blob registry.
//!
//! Spec: `firmware/specification/spec.md` (Stage-6 v0.1).
//!
//! Drivers fetch their device firmware via a cap-gated `open()` call:
//!
//! ```ignore
//! use narf_firmware::{open, FirmwareError};
//! let cap   = open("qcom/qcnfa765/amss.bin", &fw_authority)?;
//! let view  = cap.view()?;
//! // SAFETY: BAR0 mapped, exclusive owner; phys is DMA-coherent.
//! unsafe { self.bhi_load(view.phys, view.bytes.len() as u32)?; }
//! ```
//!
//! ## Sources
//!
//! Three population paths, walked in priority order at lookup time:
//! in-tree fallback (lowest, registered at `register_initcalls`),
//! initramfs unpack (mid, written into the registry by the boot
//! path at `Stage::Late`), and hot-install (highest, via
//! `install()` cap-gated on `Cap<FirmwareRegistry, Write>`).
//!
//! ## Stage-6 cut
//!
//! Step 1 of the migration plan in the spec §11. Lands the crate
//! skeleton + cap types + an in-tree fallback path. Signature
//! verification calls into `narf-crypto`'s Ed25519 surface but the
//! trusted-firmware-signers list is empty until production
//! infrastructure ships keys; under the `firmware-allow-unsigned`
//! feature the registry accepts blobs whose trailer is a single
//! all-zero "unsigned" sentinel, which lets developer builds
//! exercise the path end-to-end.
//!
//! initramfs + hot-install are still follow-ups. Calling
//! `install()` works (the storage layer is ready) but the kernel's
//! initramfs-unpack code doesn't yet route firmware blobs into it.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

mod registry;
mod signature;

mod tests;

pub use signature::{BLOB_TRAILER_MAGIC, BlobTrailer};

/// Cap-type marker for a loaded firmware blob.
///
/// `Cap<FirmwareBlob, Read>` lets the holder borrow the blob's
/// bytes through `view()`. Revoking the cap (or dropping the last
/// outstanding cap pointing at a blob) returns the blob's
/// DMA-coherent backing pages after an RCU grace period.
#[derive(Debug)]
pub struct FirmwareBlob;
impl CapType for FirmwareBlob { const KIND: CapKind = CapKind::Firmware; }

/// Cap-type marker for the registry authority.
///
/// `Cap<FirmwareRegistry, Read>` lets the holder call `open()` to
/// fetch a blob; `Cap<FirmwareRegistry, Write>` additionally lets
/// the holder call `install()` to add or replace blobs at runtime.
/// Both are bootstrapped once at boot — typically by the firmware-
/// load daemon (Write) and the trusted-driver loader (Read).
#[derive(Debug)]
pub struct FirmwareRegistry;
impl CapType for FirmwareRegistry { const KIND: CapKind = CapKind::FirmwareRegistry; }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    /// No blob registered under this canonical name.
    NotFound,
    /// Blob was found but its signature didn't verify.
    SignatureInvalid,
    /// Blob trailer didn't decode (magic / format).
    BadFormat,
    /// Allocation failed minting the cap or staging the bytes.
    OutOfMemory,
    /// The registry authority cap has been revoked.
    AuthorityRevoked,
    /// Build profile rejects unsigned blobs.
    UnsignedRejected,
}

/// Read-only view of a loaded blob. Returned by `Cap::view()`.
///
/// `bytes` lives in DMA-coherent memory; `phys` is the address the
/// device-side loader uses (BHI on Qualcomm, ACP RI_LOAD on AMD,
/// iwlwifi UCODE_* phases on Intel, …). The slice is valid until
/// the cap is dropped.
#[derive(Copy, Clone, Debug)]
pub struct BlobView<'a> {
    /// Canonical name, e.g. "qcom/qcnfa765/amss.bin".
    pub name:    &'static str,
    /// Vendor-supplied version string parsed from the blob trailer.
    /// `None` when the trailer carried no version metadata.
    pub version: Option<&'a str>,
    /// SHA-256 of the blob's raw firmware bytes (everything before
    /// the signature trailer). Recorded in the bound-driver
    /// inventory so kernel snapshots correlate driver behaviour
    /// with firmware version.
    pub sha256:  [u8; 32],
    /// Signer fingerprint (Ed25519 public-key hash). `None` when
    /// the blob was unsigned and the build accepts unsigned blobs.
    pub signer:  Option<[u8; 32]>,
    /// The bytes themselves. Identity-mapped DMA-coherent memory
    /// on kernel-resident builds; on a future userspace-driver
    /// build this is the user-AS view of the same shared frame.
    pub bytes:   &'a [u8],
    /// Phys address corresponding to `bytes`. Same on kernel
    /// builds; IOMMU-translated on userspace builds.
    pub phys:    u64,
}

/// One blob's identity for `snapshot()`. Used by observability +
/// the bound-driver inventory.
#[derive(Clone, Debug)]
pub struct BlobIdentity {
    pub name:    &'static str,
    pub size:    usize,
    pub sha256:  [u8; 32],
    pub signer:  Option<[u8; 32]>,
    pub source:  BlobSource,
    pub version: Option<String>,
}

/// Where a blob came from — set when the blob is registered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlobSource {
    /// `register_initcalls` time; an `include_bytes!` blob.
    InTree,
    /// `Stage::Late` initramfs unpack.
    Initramfs,
    /// Post-boot via `install()`.
    HotInstall,
}

// ── Public API ─────────────────────────────────────────────────────

/// Look up a firmware blob by canonical name. Returns a fresh
/// `Cap<FirmwareBlob, Read>` on success.
///
/// Resolution walks the registry in priority order: hot-installed
/// entries override initramfs entries which override in-tree
/// fallbacks. `source_for(name)` reports which source served a
/// given name.
pub fn open(
    name: &str,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<Cap<FirmwareBlob, Read>, FirmwareError> {
    if auth.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    registry::open_blob(name)
}

/// Install (or replace) a blob. Cap-gated against
/// `Cap<FirmwareRegistry, Write>`. Validates the signature trailer
/// before accepting.
///
/// `name` is the canonical lookup key — `bytes` carries the raw
/// firmware payload followed by the signature trailer described in
/// the spec §6.
///
/// On success the new blob lives at priority `BlobSource::HotInstall`;
/// existing caps pointing at the prior entry of this name continue
/// to see the old bytes (RCU grace) until they're dropped.
pub fn install(
    name:  &'static str,
    bytes: &[u8],
    auth:  &Cap<FirmwareRegistry, Write>,
) -> Result<(), FirmwareError> {
    if auth.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    registry::install_blob(name, bytes, BlobSource::HotInstall)
}

/// Snapshot of every loaded blob's identity. Used by the
/// observability layer to roll firmware versions into the kernel's
/// system-state report.
pub fn snapshot() -> Vec<BlobIdentity> {
    registry::snapshot_all()
}

/// Where a given blob currently resolves from. `None` when the
/// name isn't registered.
pub fn source_for(name: &str) -> Option<BlobSource> {
    registry::source_for(name)
}

/// `true` if the registry has at least one blob loaded. Used by
/// the test harness + the bound-driver inventory.
pub fn is_populated() -> bool {
    registry::has_any()
}

/// Bootstrap the registry-authority caps. Returns `(write, read)`.
/// Called once at boot by the trusted bootstrap path. `Read` is
/// derived from `Write` via the standard cap-rights lattice.
pub fn bootstrap_authority()
    -> (Cap<FirmwareRegistry, Write>, Cap<FirmwareRegistry, Read>)
{
    let write: Cap<FirmwareRegistry, Write> = Cap::bootstrap();
    let read = write.derive().expect("Read derivation from Write");
    (write, read)
}

/// In-tree blob registration. Drivers can register a blob shipped
/// via `include_bytes!` from their `register_initcalls` step. The
/// blob's bytes are copied into a DMA-coherent page at
/// registration time; the source slice may live in `.rodata`.
///
/// Bypasses the cap gate (in-tree blobs are kernel-trusted by
/// definition) but still runs signature verification.
pub fn register_in_tree(
    name:  &'static str,
    bytes: &[u8],
) -> Result<(), FirmwareError> {
    registry::install_blob(name, bytes, BlobSource::InTree)
}

// ── Cap::view() — accessor ────────────────────────────────────────

/// Per-cap sequence number used to bind a `BlobView` lifetime to
/// the cap's revocation state without leaking the slot index. The
/// cap stores this in its handle; the registry keeps a parallel
/// table.
static SEQ_NEXT: AtomicUsize = AtomicUsize::new(1);

#[doc(hidden)]
pub fn __seq_next() -> usize {
    SEQ_NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Borrow a blob's view through a previously-issued cap. The view
/// is valid until the cap is dropped or revoked.
pub fn view_of<'a>(
    cap: &'a Cap<FirmwareBlob, Read>,
) -> Result<BlobView<'a>, FirmwareError> {
    if cap.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    registry::view_for(cap)
}

// Re-exports of internal types used by the `Cap::view()` helper +
// the bus-side bound-driver inventory.
pub use registry::Entry as RegistryEntry;
