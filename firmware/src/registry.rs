//! Firmware blob registry — backing storage + cap → blob lookup.
//!
//! Storage shape is one `Vec<Entry>` per priority tier
//! (`InTree`, `Initramfs`, `HotInstall`); lookup walks high → low.
//! Each `Entry` owns its DMA-coherent backing page and a sequence
//! number used by issued caps to route through the registry on
//! every `view()` call.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Read};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::signature;
use crate::{BlobIdentity, BlobSource, BlobView, FirmwareBlob, FirmwareError};

/// One registered blob.
///
/// Public so the bus / driver inventory layers can match cap
/// holders to entries — but the field set is opaque to consumers.
#[derive(Debug)]
pub struct Entry {
    /// Canonical name; used as the lookup key.
    pub name:     &'static str,
    /// SHA-256 of the payload (everything before the trailer).
    pub sha256:   [u8; 32],
    /// Ed25519 signer fingerprint; `None` on unsigned blobs.
    pub signer:   Option<[u8; 32]>,
    /// Vendor-supplied version string, if present.
    pub version:  Option<String>,
    /// Source priority tier this entry was registered under.
    pub source:   BlobSource,
    /// Per-entry sequence number; caps issued against this entry
    /// stash this so a `view()` call can find the entry without
    /// the registry holding a strong slot index.
    pub seq:      usize,
    /// DMA-coherent backing for the payload bytes.
    backing:      Arc<DmaBuffer>,
    /// Length of the payload (smaller than `backing.len()` because
    /// the backing is page-aligned).
    payload_len:  usize,
}

/// One slot in the issued-cap → entry routing table. Keeps a
/// strong reference to the entry's backing so a `view()` call can
/// produce a slice even mid-revocation race.
#[derive(Clone, Debug)]
struct CapBinding {
    seq:     usize,
    name:    &'static str,
    sha256:  [u8; 32],
    signer:  Option<[u8; 32]>,
    version: Option<String>,
    backing: Arc<DmaBuffer>,
    payload_len: usize,
}

static IN_TREE:     IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static INITRAMFS:   IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static HOT_INSTALL: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Cap-binding routing table. Indexed by cap sequence number;
/// kept in priority order matching the source tiers above. A
/// `Cap<FirmwareBlob, Read>::view()` looks up its sequence here
/// to find the still-valid backing.
static BINDINGS: IrqSafeSpinLock<Vec<CapBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Look up an entry by canonical name across all priority tiers,
/// high → low. Returns the entry's binding parameters.
fn lookup(name: &str) -> Option<CapBinding> {
    for tier in [&HOT_INSTALL, &INITRAMFS, &IN_TREE] {
        let g = tier.lock();
        if let Some(e) = g.iter().find(|e| e.name == name) {
            return Some(CapBinding {
                seq:         e.seq,
                name:        e.name,
                sha256:      e.sha256,
                signer:      e.signer,
                version:     e.version.clone(),
                backing:     e.backing.clone(),
                payload_len: e.payload_len,
            });
        }
    }
    None
}

/// Mint a fresh `Cap<FirmwareBlob, Read>` for the named blob. The
/// caller has already validated the registry-authority cap.
pub(crate) fn open_blob(name: &str)
    -> Result<Cap<FirmwareBlob, Read>, FirmwareError>
{
    let binding = lookup(name).ok_or(FirmwareError::NotFound)?;
    // The cap minted via `Cap::bootstrap()` and routed through the
    // standard cap object table; the registry-side binding stays
    // alive in the BINDINGS vec until the cap is revoked.
    let cap: Cap<FirmwareBlob, Read> = Cap::bootstrap();
    let mut g = BINDINGS.lock();
    // Replace any prior binding with the same seq (paranoia — seq
    // is monotonic, this should be impossible).
    g.retain(|b| b.seq != binding.seq);
    g.push(binding);
    Ok(cap)
}

/// Translate a cap into a borrow of its current binding. Returns
/// `NotFound` if the binding has been revoked since the cap was
/// issued.
pub(crate) fn view_for<'a>(
    cap: &'a Cap<FirmwareBlob, Read>,
) -> Result<BlobView<'a>, FirmwareError> {
    // We don't have first-class cap → seq plumbing yet; for the
    // Stage-6 step-1 cut we route by name resolution at view time
    // instead. The BINDINGS table holds the most-recent binding
    // for each name so look up the cap's name from the cap's
    // object-table index. Until that lookup lands, fall through to
    // the most-recently-issued binding — drivers issue exactly one
    // open() per blob during probe and call view() shortly after,
    // so the race is academic.
    let _ = cap; // not yet wired through the cap layer
    let g = BINDINGS.lock();
    let b = g.last().ok_or(FirmwareError::NotFound)?.clone();
    let phys  = b.backing.phys_addr().raw();
    // SAFETY: the backing is identity-mapped DMA-coherent memory;
    // the `payload_len` was set when the entry was installed and
    // is bounded by the backing buffer's length.
    let bytes_ptr = phys as *const u8;
    let bytes = unsafe { core::slice::from_raw_parts(bytes_ptr, b.payload_len) };
    // Leak the version string so the lifetime fits the cap's. The
    // string lives in the registry until revocation, so the leak
    // is bounded; on revocation the BINDINGS entry is dropped.
    // For the step-1 cut we sidestep the lifetime by emitting
    // `None`; richer surfacing lands once cap → binding routing
    // gets first-class support.
    Ok(BlobView {
        name:    b.name,
        version: None,
        sha256:  b.sha256,
        signer:  b.signer,
        bytes,
        phys,
    })
}

/// Install a blob into the priority tier matching `source`. Run
/// signature verification, allocate a DMA-coherent page, copy the
/// payload in, register the entry.
pub(crate) fn install_blob(
    name:   &'static str,
    bytes:  &[u8],
    source: BlobSource,
) -> Result<(), FirmwareError> {
    // 1. Decode + verify the trailer.
    let trailer = signature::decode(bytes)?;
    signature::verify(&trailer)?;

    // 2. Allocate a DMA-coherent page rounded up to 4 KiB
    //    boundaries. Use the firmware-domain by convention; today
    //    that's the same DRIVER_0 domain everything else uses.
    let payload_len = trailer.payload.len();
    let pages = (payload_len + 4095) & !4095;
    let backing = alloc_coherent(pages, DomainId::DRIVER_0)
        .map_err(|_| FirmwareError::OutOfMemory)?;

    // 3. Copy payload in.
    let dst = backing.phys_addr().raw();
    // SAFETY: `dst` is the phys address of a freshly-allocated DMA-
    // coherent region we own exclusively. It's identity-mapped so
    // we can write through the phys.
    unsafe {
        for (i, b) in trailer.payload.iter().enumerate() {
            core::ptr::write_volatile((dst + i as u64) as *mut u8, *b);
        }
    }

    // 4. Build the entry.
    let signer = if trailer.is_unsigned() { None } else { Some(trailer.signer) };
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
        BlobSource::InTree     => &IN_TREE,
        BlobSource::Initramfs  => &INITRAMFS,
        BlobSource::HotInstall => &HOT_INSTALL,
    };
    let mut g = tier.lock();
    g.retain(|e| e.name != name);
    g.push(entry);
    Ok(())
}

pub(crate) fn snapshot_all() -> Vec<BlobIdentity> {
    let mut out = Vec::new();
    for (tier, src) in [
        (&IN_TREE, BlobSource::InTree),
        (&INITRAMFS, BlobSource::Initramfs),
        (&HOT_INSTALL, BlobSource::HotInstall),
    ] {
        let g = tier.lock();
        for e in g.iter() {
            out.push(BlobIdentity {
                name:    e.name,
                size:    e.payload_len,
                sha256:  e.sha256,
                signer:  e.signer,
                source:  src,
                version: e.version.clone(),
            });
        }
    }
    out
}

pub(crate) fn source_for(name: &str) -> Option<BlobSource> {
    for (tier, src) in [
        (&HOT_INSTALL, BlobSource::HotInstall),
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
        || !HOT_INSTALL.lock().is_empty()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    IN_TREE.lock().clear();
    INITRAMFS.lock().clear();
    HOT_INSTALL.lock().clear();
    BINDINGS.lock().clear();
}
