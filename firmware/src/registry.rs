//! Firmware blob registry — backing storage + cap → blob lookup.
//!
//! Storage shape is one `Vec<Entry>` per priority tier:
//!
//! | Tier         | Priority | Source                           |
//! |--------------|----------|----------------------------------|
//! | `InTree`     | lowest   | `register_in_tree` at boot       |
//! | `Initramfs`  | mid-low  | `firmware-scan-initramfs` initcall |
//! | `Rootfs`     | mid-high | `firmware-scan-rootfs` initcall  |
//! | `HotInstall` | highest  | `sys_firmware_install` at runtime|
//!
//! Lookup walks high → low so a later-registered rootfs entry
//! shadows an initramfs entry of the same name — matching the
//! Linux convention where /lib/firmware/ takes precedence over
//! the initramfs copy.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, Read};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::signature;
use crate::{BlobIdentity, BlobSource, BlobView, FirmwareBlob, FirmwareError};

/// Small images retain their direct-DMA view. Large images, or images whose
/// contiguous allocation fails, use page-backed virtual memory like Linux's
/// firmware loader (`fs/kernel_read_file.c`); transport DMA is separate.
#[derive(Debug)]
enum Backing {
    Coherent(DmaBuffer),
    Paged { ptr: NonNull<u8>, len: usize },
}

// SAFETY: allocation is uniquely owned until installation finishes copying
// the payload. Published backings are immutable, shared through Arc, and freed
// only when the last registry entry/cap binding drops its reference.
unsafe impl Send for Backing {}
// SAFETY: shared access exposes only immutable bytes from the owned backing.
unsafe impl Sync for Backing {}

impl Backing {
    fn new(len: usize) -> Result<Self, FirmwareError> {
        if let Ok(buffer) = alloc_coherent(len, DomainId::DRIVER_0) {
            return Ok(Self::Coherent(buffer));
        }
        let ptr = narf_memory::vmalloc::valloc(len).ok_or(FirmwareError::OutOfMemory)?;
        Ok(Self::Paged { ptr, len })
    }

    fn ptr(&self) -> *mut u8 {
        match self {
            Self::Coherent(buffer) => buffer.cpu_mut_ptr::<u8>(),
            Self::Paged { ptr, .. } => ptr.as_ptr(),
        }
    }

    fn phys(&self) -> Option<u64> {
        match self {
            Self::Coherent(buffer) => Some(buffer.phys_addr().raw()),
            Self::Paged { .. } => None,
        }
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        if let Self::Paged { ptr, len } = self {
            // SAFETY: exactly the allocation returned by valloc in new;
            // Arc ownership keeps it live until the final borrower retires.
            unsafe { narf_memory::vmalloc::vfree(*ptr, *len) };
        }
    }
}

/// One registered blob.
///
/// Public so the bus / driver inventory layers can match cap
/// holders to entries — but the field set is opaque to consumers.
#[derive(Debug)]
pub struct Entry {
    /// Canonical name; used as the lookup key.
    pub name: &'static str,
    /// BLAKE3 of the payload; historical field name retained for compatibility.
    pub sha256: [u8; 32],
    /// Ed25519 signer fingerprint; `None` on unsigned blobs.
    pub signer: Option<[u8; 32]>,
    /// Vendor-supplied version string, if present.
    pub version: Option<String>,
    /// Source priority tier this entry was registered under.
    pub source: BlobSource,
    /// Per-entry sequence number; caps issued against this entry
    /// stash this so a `view()` call can find the entry without
    /// the registry holding a strong slot index.
    pub seq: usize,
    /// Owned coherent or page-backed storage for the payload bytes.
    backing: Arc<Backing>,
    /// Length of the payload (the backing is page-rounded).
    payload_len: usize,
}

/// One slot in the issued-cap → entry routing table. Keeps a
/// strong reference to the entry's backing so a `view()` call can
/// produce a slice even mid-revocation race.
#[derive(Clone, Debug)]
struct CapBinding {
    cap_index: u32,
    name: &'static str,
    sha256: [u8; 32],
    signer: Option<[u8; 32]>,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    version: Option<String>,
    backing: Arc<Backing>,
    payload_len: usize,
}

static IN_TREE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static INITRAMFS: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
/// Root-partition firmware scan tier. Populated by `firmware-scan-rootfs`
/// after `root-mount-auto`; shadows Initramfs entries of the same name.
static ROOTFS: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static HOT_INSTALL: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

// A rejected explicit wireless policy must not look absent to the Linux
// world-domain fallback. Only a later verified signed installation clears
// this latch; admitting an unsigned development blob cannot clear it.
const REGULATORY_POLICY: &str = "wireless-regulatory.bin";
static REGULATORY_POLICY_REJECTED: AtomicBool = AtomicBool::new(false);

pub(super) fn note_rejection(name: &str) {
    if name == REGULATORY_POLICY {
        REGULATORY_POLICY_REJECTED.store(true, Ordering::Release);
    }
}

/// Cap-binding routing table. Indexed by cap sequence number;
/// kept in priority order matching the source tiers above. A
/// `Cap<FirmwareBlob, Read>::view()` looks up its sequence here
/// to find the still-valid backing.
static BINDINGS: IrqSafeSpinLock<Vec<CapBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Look up an entry by canonical name across all priority tiers,
/// high → low. Returns the entry's binding parameters.
fn lookup(name: &str) -> Option<CapBinding> {
    for tier in [&HOT_INSTALL, &ROOTFS, &INITRAMFS, &IN_TREE] {
        let g = tier.lock();
        if let Some(e) = g.iter().find(|e| e.name == name) {
            return Some(CapBinding {
                cap_index: 0,
                name: e.name,
                sha256: e.sha256,
                signer: e.signer,
                version: e.version.clone(),
                backing: e.backing.clone(),
                payload_len: e.payload_len,
            });
        }
    }
    None
}

/// Mint a fresh `Cap<FirmwareBlob, Read>` for the named blob. The
/// caller has already validated the registry-authority cap.
pub(crate) fn open_blob(name: &str) -> Result<Cap<FirmwareBlob, Read>, FirmwareError> {
    let binding = lookup(name);
    if name == REGULATORY_POLICY && REGULATORY_POLICY_REJECTED.load(Ordering::Acquire) {
        return Err(FirmwareError::SignatureInvalid);
    }
    let mut binding = binding.ok_or(FirmwareError::NotFound)?;
    // The cap minted via `Cap::bootstrap()` and routed through the
    // standard cap object table; the registry-side binding stays
    // alive in the BINDINGS vec until the cap is revoked.
    let cap: Cap<FirmwareBlob, Read> = Cap::bootstrap();
    binding.cap_index = cap.slot().index;
    let mut g = BINDINGS.lock();
    g.retain(|b| b.cap_index != binding.cap_index);
    g.push(binding);
    Ok(cap)
}

/// Translate a cap into a borrow of its current binding. Returns
/// `NotFound` if the binding has been revoked since the cap was
/// issued.
pub(crate) fn view_for<'a>(
    cap: &'a Cap<FirmwareBlob, Read>,
) -> Result<BlobView<'a>, FirmwareError> {
    if cap.check_live().is_err() {
        return Err(FirmwareError::NotFound);
    }
    let cap_index = cap.slot().index;
    let g = BINDINGS.lock();
    let b = g
        .iter()
        .find(|binding| binding.cap_index == cap_index)
        .ok_or(FirmwareError::NotFound)?
        .clone();
    let phys = b.backing.phys();
    let bytes_ptr = b.backing.ptr().cast_const();
    // SAFETY: the owned backing is mapped in the shared kernel address space;
    // the `payload_len` was set when the entry was installed and
    // is bounded by the backing buffer's length.
    // SAFETY: Valid memory or trusted environment
    let bytes = unsafe { core::slice::from_raw_parts(bytes_ptr, b.payload_len) };
    // Leak the version string so the lifetime fits the cap's. The
    // string lives in the registry until revocation, so the leak
    // is bounded; on revocation the BINDINGS entry is dropped.
    // For the step-1 cut we sidestep the lifetime by emitting
    // `None`; richer surfacing lands once cap → binding routing
    // gets first-class support.
    Ok(BlobView {
        name: b.name,
        version: None,
        sha256: b.sha256,
        signer: b.signer,
        bytes,
        phys,
    })
}

/// Install a blob into the priority tier matching `source`. Run
/// signature verification, allocate backing storage, copy the
/// payload in, register the entry.
pub(crate) fn install_blob(
    name: impl Into<Cow<'static, str>>,
    bytes: &[u8],
    source: BlobSource,
) -> Result<(), FirmwareError> {
    let name = name.into();
    // 1. Decode + verify the trailer.
    let validated = signature::decode(bytes).and_then(|trailer| {
        signature::verify(&trailer)?;
        Ok(trailer)
    });
    let trailer = match validated {
        Ok(trailer) => trailer,
        Err(error) => {
            note_rejection(&name);
            return Err(error);
        }
    };

    // 2. Prefer the existing coherent backing; fall back to individual pages
    //    mapped contiguously in kernel VA, without a high-order requirement.
    let payload_len = trailer.payload.len();
    let backing = Backing::new(payload_len)?;

    // 3. Copy payload in.
    let dst = backing.ptr();
    // SAFETY: the pointer covers this exclusively owned allocation.
    // Every payload byte is initialized before the backing is published.
    // A physical address is not a CPU pointer after user page-table swaps.
    unsafe {
        core::ptr::copy_nonoverlapping(trailer.payload.as_ptr(), dst, payload_len);
    }

    // 4. Build the entry.
    let signer = if trailer.is_unsigned() {
        None
    } else {
        Some(trailer.signer)
    };
    // Only successfully staged rootfs entries need a permanent canonical name.
    let name: &'static str = match name {
        Cow::Borrowed(name) => name,
        Cow::Owned(name) => alloc::boxed::Box::leak(name.into_boxed_str()),
    };
    let entry = Entry {
        name,
        sha256: signature::sha256(trailer.payload),
        signer,
        version: trailer.version.clone(),
        source,
        seq: crate::__seq_next(),
        backing: alloc::sync::Arc::new(backing),
        payload_len,
    };

    // 5. Push into the right tier. Replace any prior entry with
    //    the same name in this tier (re-installs are idempotent).
    let tier = match source {
        BlobSource::InTree => &IN_TREE,
        BlobSource::Initramfs => &INITRAMFS,
        BlobSource::Rootfs => &ROOTFS,
        BlobSource::HotInstall => &HOT_INSTALL,
    };
    let mut g = tier.lock();
    g.retain(|e| e.name != name);
    g.push(entry);
    if name == REGULATORY_POLICY && signer.is_some() {
        REGULATORY_POLICY_REJECTED.store(false, Ordering::Release);
    }
    Ok(())
}

pub(crate) fn snapshot_all() -> Vec<BlobIdentity> {
    let mut out = Vec::new();
    for (tier, src) in [
        (&IN_TREE, BlobSource::InTree),
        (&INITRAMFS, BlobSource::Initramfs),
        (&ROOTFS, BlobSource::Rootfs),
        (&HOT_INSTALL, BlobSource::HotInstall),
    ] {
        let g = tier.lock();
        for e in g.iter() {
            out.push(BlobIdentity {
                name: e.name,
                size: e.payload_len,
                sha256: e.sha256,
                signer: e.signer,
                source: src,
                version: e.version.clone(),
            });
        }
    }
    out
}

pub(crate) fn source_for(name: &str) -> Option<BlobSource> {
    for (tier, src) in [
        (&HOT_INSTALL, BlobSource::HotInstall),
        (&ROOTFS, BlobSource::Rootfs),
        (&INITRAMFS, BlobSource::Initramfs),
        (&IN_TREE, BlobSource::InTree),
    ] {
        let g = tier.lock();
        if g.iter().any(|e| e.name == name) {
            return Some(src);
        }
    }
    None
}

pub(crate) fn has_any() -> bool {
    !IN_TREE.lock().is_empty()
        || !INITRAMFS.lock().is_empty()
        || !ROOTFS.lock().is_empty()
        || !HOT_INSTALL.lock().is_empty()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    IN_TREE.lock().clear();
    INITRAMFS.lock().clear();
    ROOTFS.lock().clear();
    HOT_INSTALL.lock().clear();
    BINDINGS.lock().clear();
    REGULATORY_POLICY_REJECTED.store(false, Ordering::Release);
}
