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
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;

pub mod registry;
mod signature;

mod tests;

pub use signature::{
    register_trusted_signer, trusted_signer_count, BlobTrailer, BLOB_TRAILER_MAGIC,
};

/// Cap-type marker for a loaded firmware blob.
///
/// `Cap<FirmwareBlob, Read>` lets the holder borrow the blob's
/// bytes through `view()`. Revoking the cap (or dropping the last
/// outstanding cap pointing at a blob) returns the blob's
/// DMA-coherent backing pages after an RCU grace period.
#[derive(Debug)]
pub struct FirmwareBlob;
impl CapType for FirmwareBlob {
    const KIND: CapKind = CapKind::Firmware;
}

/// Cap-type marker for the registry authority.
///
/// `Cap<FirmwareRegistry, Read>` lets the holder call `open()` to
/// fetch a blob; `Cap<FirmwareRegistry, Write>` additionally lets
/// the holder call `install()` to add or replace blobs at runtime.
/// Both are bootstrapped once at boot — typically by the firmware-
/// load daemon (Write) and the trusted-driver loader (Read).
#[derive(Debug)]
pub struct FirmwareRegistry;
impl CapType for FirmwareRegistry {
    const KIND: CapKind = CapKind::FirmwareRegistry;
}

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
    pub name: &'static str,
    /// Vendor-supplied version string parsed from the blob trailer.
    /// `None` when the trailer carried no version metadata.
    pub version: Option<&'a str>,
    /// SHA-256 of the blob's raw firmware bytes (everything before
    /// the signature trailer). Recorded in the bound-driver
    /// inventory so kernel snapshots correlate driver behaviour
    /// with firmware version.
    pub sha256: [u8; 32],
    /// Signer fingerprint (Ed25519 public-key hash). `None` when
    /// the blob was unsigned and the build accepts unsigned blobs.
    pub signer: Option<[u8; 32]>,
    /// The bytes themselves. Identity-mapped DMA-coherent memory
    /// on kernel-resident builds; on a future userspace-driver
    /// build this is the user-AS view of the same shared frame.
    pub bytes: &'a [u8],
    /// Phys address corresponding to `bytes`. Same on kernel
    /// builds; IOMMU-translated on userspace builds.
    pub phys: u64,
}

/// One blob's identity for `snapshot()`. Used by observability +
/// the bound-driver inventory.
#[derive(Clone, Debug)]
pub struct BlobIdentity {
    pub name: &'static str,
    pub size: usize,
    pub sha256: [u8; 32],
    pub signer: Option<[u8; 32]>,
    pub source: BlobSource,
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
    name: &'static str,
    bytes: &[u8],
    auth: &Cap<FirmwareRegistry, Write>,
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
pub fn bootstrap_authority() -> (Cap<FirmwareRegistry, Write>, Cap<FirmwareRegistry, Read>) {
    let write: Cap<FirmwareRegistry, Write> = Cap::bootstrap();
    let read = write.derive().expect("Read derivation from Write");
    (write, read)
}

/// Trusted-loader authority — a process-global Write cap minted
/// once at boot and stored here for the kernel-side syscall
/// trampoline (`sys_install`). Userspace callers reach the
/// authority through the syscall's privilege check rather than
/// holding the cap directly.
///
/// In-kernel callers should NOT touch this static; they bootstrap
/// their own cap pair via `bootstrap_authority()` and revoke at
/// will. The static is for the syscall layer only.
static TRUSTED_LOADER: IrqSafeSpinLock<Option<Cap<FirmwareRegistry, Write>>> =
    IrqSafeSpinLock::new(None);

/// Install (idempotently) the trusted-loader authority used by the
/// `sys_firmware_install` syscall. The first caller wins;
/// subsequent calls are no-ops. Called once from the kernel boot
/// path.
pub fn install_trusted_loader_authority(cap: Cap<FirmwareRegistry, Write>) {
    let mut g = TRUSTED_LOADER.lock();
    if g.is_none() {
        *g = Some(cap);
    }
}

/// Borrow the trusted-loader authority. `None` until
/// `install_trusted_loader_authority` runs at boot.
pub fn trusted_loader_authority() -> Option<Cap<FirmwareRegistry, Write>> {
    TRUSTED_LOADER.lock().as_ref().cloned()
}

// ── Per-task firmware-loader cap table ─────────────────────────────
//
// Replaces the earlier `TRUSTED_LOADERS: Vec<u64>` pid allowlist
// with a real cap table: each privileged task holds its own
// `Cap<FirmwareRegistry, Write>`, kept here so the syscall trap
// handler can pull the calling task's cap and feed it into
// `sys_install`. Revoking the cap (or removing the entry) revokes
// the task's authority instantly.
//
// Backwards-compatible accessors `add_trusted_firmware_loader_task`
// and `is_trusted_firmware_loader_task` mint / probe entries here
// without exposing the cap directly — those are kept for the boot
// path's bootstrap shape (it grants task 0 by pid alone) and for
// the existing pid-allowlist smoke. The cap-aware API
// (`grant_firmware_authority` / `firmware_authority_of`) replaces
// them as call sites move over to cap-typed grants.

static LOADER_AUTHORITIES: IrqSafeSpinLock<alloc::vec::Vec<(u64, Cap<FirmwareRegistry, Write>)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Grant `task_id` a fresh `Cap<FirmwareRegistry, Write>` minted
/// from the trusted-loader authority. The trap handler for
/// `sys_firmware_install` uses this cap to gate the call.
///
/// Returns the granted cap so the granting code can also hand it
/// to userspace if the cap-mint syscall plumbing is wired (today
/// kernel-side only; the cap stays in the kernel's per-task table
/// and the trap handler reaches for it via `firmware_authority_of`).
///
/// Idempotent on `task_id` — re-granting replaces the prior cap
/// (the prior cap is implicitly revoked by being dropped from the
/// table).
pub fn grant_firmware_authority(task_id: u64) -> Cap<FirmwareRegistry, Write> {
    let cap: Cap<FirmwareRegistry, Write> = Cap::bootstrap();
    let mut g = LOADER_AUTHORITIES.lock();
    if let Some(pos) = g.iter().position(|(t, _)| *t == task_id) {
        g[pos] = (task_id, cap.clone());
    } else {
        g.push((task_id, cap.clone()));
    }
    cap
}

/// Borrow `task_id`'s firmware-registry authority cap. `None` if
/// the task hasn't been granted one (or its grant was revoked).
pub fn firmware_authority_of(task_id: u64) -> Option<Cap<FirmwareRegistry, Write>> {
    LOADER_AUTHORITIES
        .lock()
        .iter()
        .find(|(t, _)| *t == task_id)
        .map(|(_, c)| c.clone())
}

/// Revoke `task_id`'s firmware-registry authority. The cap is
/// dropped from the per-task table; subsequent
/// `firmware_authority_of(task_id)` calls return `None` so the
/// trap handler rejects the next syscall from that task.
/// Returns `true` if an entry was actually removed.
pub fn revoke_firmware_authority(task_id: u64) -> bool {
    let mut g = LOADER_AUTHORITIES.lock();
    let n = g.len();
    g.retain(|(t, _)| *t != task_id);
    g.len() != n
}

/// Backwards-compatible: mint an authority cap for `task_id`
/// without exposing it to the caller. Equivalent to
/// `grant_firmware_authority(task_id)` followed by dropping the
/// returned cap (the table keeps a clone). Kept so existing call
/// sites that just want pid-level grants stay terse.
pub fn add_trusted_firmware_loader_task(task_id: u64) {
    let _ = grant_firmware_authority(task_id);
}

/// `true` if `task_id` holds a live firmware-loader authority.
pub fn is_trusted_firmware_loader_task(task_id: u64) -> bool {
    LOADER_AUTHORITIES
        .lock()
        .iter()
        .any(|(t, c)| *t == task_id && c.check_live().is_ok())
}

#[doc(hidden)]
pub fn __reset_trusted_loader_tasks() {
    LOADER_AUTHORITIES.lock().clear();
}

/// In-tree blob registration. Drivers can register a blob shipped
/// via `include_bytes!` from their `register_initcalls` step. The
/// blob's bytes are copied into a DMA-coherent page at
/// registration time; the source slice may live in `.rodata`.
///
/// Bypasses the cap gate (in-tree blobs are kernel-trusted by
/// definition) but still runs signature verification.
pub fn register_in_tree(name: &'static str, bytes: &[u8]) -> Result<(), FirmwareError> {
    registry::install_blob(name, bytes, BlobSource::InTree)
}

/// Convenience: register multiple in-tree blobs in one shot. Used
/// from `register_initcalls`-like driver bootstraps that ship a
/// small bundle of `(name, &[u8])` pairs.
///
/// Bytes whose trailer is malformed or whose signature is rejected
/// surface a panic; in-tree blobs are kernel build-time inputs and
/// failure here means the kernel image is wrong, not a runtime
/// fault.
pub fn register_in_tree_bundle(blobs: &[(&'static str, &'static [u8])]) {
    for (name, bytes) in blobs {
        match register_in_tree(name, bytes) {
            Ok(()) => {}
            Err(e) => panic!(
                "narf-firmware: in-tree blob {:?} rejected by registry: {:?}",
                name, e
            ),
        }
    }
}

/// Stage::Subsys + Stage::Late initcalls for this crate.
///
/// `Stage::Subsys` slot reserved for build profiles that ship
/// kernel-baked vendor firmware images via `register_in_tree_bundle`.
///
/// `Stage::Late` slot scans whatever initramfs the boot path
/// staged via `install_initramfs(&'static Initramfs)` and
/// populates the registry's `Initramfs` priority tier. When no
/// initramfs is staged the slot returns `NotPresent` so the init
/// harness records the absence without flagging it as failure.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "firmware-init", || InitResult::Ok);
    narf_init::register(Stage::Late, "firmware-scan-initramfs", || {
        // The staged initramfs lives in `narf-initramfs` (spec §6
        // step-2 consolidation). When the boot path stages one,
        // we pick up `firmware/*` entries; otherwise no-op.
        let fs = match narf_initramfs::staged() {
            Some(f) => f,
            None => return InitResult::NotPresent,
        };
        let auth = match trusted_loader_authority() {
            Some(a) => a,
            None => return InitResult::Error("no trusted-loader authority"),
        };
        match scan_initramfs(fs, &auth) {
            Ok(_) => InitResult::Ok,
            Err(_) => InitResult::Error("scan_initramfs failed"),
        }
    });
}

/// Stage an initramfs for the Stage::Late firmware scanner.
///
/// Deprecated: thin shim around `narf_initramfs::install`. New
/// callers should reach `narf-initramfs` directly so the eventual
/// removal of this re-export (spec §6 step-3) is invisible.
#[deprecated(note = "use narf_initramfs::install instead")]
pub fn install_initramfs(fs: &'static narf_filesystem::Initramfs) {
    narf_initramfs::install(fs);
}

/// `true` once a kernel-supplied initramfs has been staged.
///
/// Deprecated: thin shim around `narf_initramfs::is_staged`.
#[deprecated(note = "use narf_initramfs::is_staged instead")]
pub fn initramfs_staged() -> bool {
    narf_initramfs::is_staged()
}

#[doc(hidden)]
pub fn __reset_staged_initramfs() {
    narf_initramfs::__reset_staged();
}

/// Walk every `firmware/*` entry in an initramfs and register it
/// with the registry under `BlobSource::Initramfs`. Per spec §5,
/// this is the mid-priority population path — it overrides
/// in-tree fallbacks but is overridden by `HotInstall`.
///
/// Naming: each archive entry whose path starts with `"firmware/"`
/// is registered under the suffix as its canonical name. So
/// `firmware/qcom/qcnfa765/amss.bin` lands in the registry under
/// `"qcom/qcnfa765/amss.bin"`.
///
/// Returns the number of entries successfully registered. Any
/// entry whose trailer is malformed or whose signature is rejected
/// surfaces a warning (best-effort; one bad blob doesn't poison
/// the rest) and decrements the count.
pub fn scan_initramfs(
    fs: &narf_filesystem::Initramfs,
    auth: &Cap<FirmwareRegistry, Write>,
) -> Result<usize, FirmwareError> {
    if auth.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    let mut n_ok = 0usize;
    for (name, bytes) in fs.iter_files() {
        // Only entries under `firmware/`.
        let suffix = match name.strip_prefix("firmware/") {
            Some(s) => s,
            None => continue,
        };
        // Empty suffix or a directory-marker — skip.
        if suffix.is_empty() {
            continue;
        }
        match registry::install_blob(suffix, bytes, BlobSource::Initramfs) {
            Ok(()) => n_ok += 1,
            Err(_) => {
                // Best-effort: skip bad blobs without aborting the
                // rest of the walk. A future iteration may surface
                // these via the observability layer.
            }
        }
    }
    Ok(n_ok)
}

/// Cap-gated entry point for the userspace `sys_firmware_install`
/// syscall. Wraps `install()` with the byte-pointer translation
/// the syscall layer needs.
///
/// # Safety
/// `bytes_ptr` must point at exactly `bytes_len` valid bytes
/// readable by the kernel. The caller (the syscall trap handler)
/// is responsible for validating the user-mode pointer + length
/// against the calling task's address space.
pub unsafe fn sys_install(
    name: &'static str,
    bytes_ptr: *const u8,
    bytes_len: usize,
    auth: &Cap<FirmwareRegistry, Write>,
) -> Result<(), FirmwareError> {
    if auth.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    // SAFETY: forwarded from caller — pointer + length validated
    // against the user task's AS by the syscall handler.
    let bytes = unsafe { core::slice::from_raw_parts(bytes_ptr, bytes_len) };
    registry::install_blob(name, bytes, BlobSource::HotInstall)
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
pub fn view_of<'a>(cap: &'a Cap<FirmwareBlob, Read>) -> Result<BlobView<'a>, FirmwareError> {
    if cap.check_live().is_err() {
        return Err(FirmwareError::AuthorityRevoked);
    }
    registry::view_for(cap)
}

// Re-exports of internal types used by the `Cap::view()` helper +
// the bus-side bound-driver inventory.
pub use registry::Entry as RegistryEntry;
