//! Cross-device Intel PRIME: the dma-buf ops of an exported Intel GEM object
//! (attach, pin, map) and the foreign import that consumes them.
//!
//! MIT Linux v7.4-rc4 `drivers/gpu/drm/xe/xe_dma_buf.c`:
//!
//! - `xe_dma_buf_attach`: an importer that asks for peer-to-peer keeps it
//!   only when `pci_p2pdma_distance(exporter, importer) >= 0`
//!   ([`narf_io::p2pdma`]); without it the object must be able to migrate
//!   to system memory (`xe_bo_can_migrate(bo, XE_PL_TT)`), else -EOPNOTSUPP.
//! - `xe_dma_buf_pin`: VRAM stays only while every attachment is
//!   peer-to-peer; otherwise the object migrates to system memory first. A
//!   pinned VRAM object refuses a system pin (-EINVAL)
//!   ([`GemObject::pin_external`]).
//! - `xe_dma_buf_map`: system pages (`drm_prime_pages_to_sg` +
//!   `dma_map_sgtable`), or for a peer-to-peer VRAM object the LMEM BAR bus
//!   addresses in segments of at most 2 GiB (`xe_ttm_vram_mgr_alloc_sgt` +
//!   `dma_map_resource`), refused (-EOPNOTSUPP) unless the object is wholly
//!   CPU-visible.
//! - `xe_gem_prime_import`: the exporter's own device gets the same object
//!   back (`drm_devfs_bridge::intel_prime_import`); another device creates
//!   a system-placed sg object over a dynamic attachment
//!   (`xe_dma_buf_create_obj`, `GemState::import_attachment`) sharing the
//!   exporter's reservation, mapped at first VM bind ([`ensure_mapped`]).
//!
//! NARF importers are static: they have no `invalidate_mappings`
//! (`xe_dma_buf_move_notify`), so mapping pins the export for the
//! attachment's life (`dma-buf.c::dma_buf_pin_on_map`) and the exporter
//! cannot evict or migrate it underneath the importer. A pinned VRAM export
//! therefore also refuses system suspend (Linux evicts and restores pinned
//! external objects in place). The exporter's runtime-PM reference
//! (`xe_pm_runtime_get` in attach) is taken at the first pin, since NARF's
//! runtime resume is asynchronous; it holds the BAR decoding while a peer
//! may DMA into it.
//!
//! Peer-to-peer into another function's BAR is unvalidated on hardware:
//! the live importer asks for it only with `narf.intel.prime_p2p=1`, and
//! otherwise takes the migration path.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::FsError;
use narf_io::p2pdma::{P2pMapType, P2pTopology};
use narf_io::sg::Segment;
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

use crate::intel_gpu_gem::{GemObject, GemState};
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_user::UserBackend;

const PAGE: u64 = 4096;
/// `xe_ttm_vram_mgr_alloc_sgt`: "Limit maximum size to 2GiB due to SG table
/// limitations."
const SZ_2G: u64 = 1 << 31;
/// `drm_prime_pages_to_sg` with no device limit: `UINT_MAX` rounded down to
/// a page.
const MAX_SYSTEM_SEGMENT: u64 = u32::MAX as u64 & !(PAGE - 1);

/// Boot option admitting peer-to-peer for live cross-device imports.
pub(crate) const P2P_OPTION: &str = "narf.intel.prime_p2p";

/// The exporting device: what migration and the runtime-PM reference use.
pub(crate) struct Exporter {
    pub(crate) platform: GtPlatform,
    pub(crate) backend: Arc<dyn UserBackend>,
}

impl core::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Exporter")
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

/// Where a mapped attachment's addresses point.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SgPlacement {
    /// Exporter system pages, as the importer's DMA sees them.
    System,
    /// The exporter's LMEM BAR, reached over `P2pMapType`.
    PeerVram(P2pMapType),
}

/// A mapped attachment (Linux `struct sg_table` from `map_dma_buf`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SgTable {
    pub(crate) placement: SgPlacement,
    pub(crate) segments: Vec<Segment>,
}

impl SgTable {
    /// The importer's per-page DMA addresses.
    pub(crate) fn pages(&self) -> Vec<u64> {
        self.segments
            .iter()
            .flat_map(|segment| {
                (0..u64::from(segment.len) / PAGE).map(move |page| segment.dma + page * PAGE)
            })
            .collect()
    }
    pub(crate) fn len(&self) -> u64 {
        self.segments.iter().map(|s| u64::from(s.len)).sum()
    }
}

/// One importer of an Intel export (Linux `struct dma_buf_attachment`).
pub(crate) struct Attachment {
    object: Arc<GemObject>,
    exporter: Exporter,
    /// `attach->peer2peer` after `xe_dma_buf_attach`.
    peer2peer: Option<P2pMapType>,
    /// Serializes this attachment's pin and map.
    serial: Mutex<()>,
    pinned: AtomicBool,
    wakeref: IrqSafeSpinLock<Option<Box<dyn core::any::Any + Send>>>,
    sg: IrqSafeSpinLock<Option<Arc<SgTable>>>,
}

impl core::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attachment")
            .field("exporter", &self.exporter)
            .field("peer2peer", &self.peer2peer)
            .field("pinned", &self.pinned.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// `dma_buf_dynamic_attach` + `xe_dma_buf_attach` for `object`, exported by
/// `exporter` whose PCI function is `provider`, to an importer whose PCI
/// function is `client` (`None`: not a PCI device). `allow_peer2peer` is
/// the importer's `dma_buf_attach_ops.allow_peer2peer`.
pub(crate) fn attach<T: P2pTopology>(
    object: Arc<GemObject>,
    exporter: Exporter,
    topology: &T,
    provider: Option<T::Node>,
    client: Option<T::Node>,
    allow_peer2peer: bool,
) -> Result<Attachment, FsError> {
    // xe_gem_prime_export: a VM-private object is never exported, and an
    // import or USERPTR is not an Intel dma-buf here.
    if object.vm_owner().is_some()
        || object.is_userptr()
        || object.private_staging()
        || object.is_imported()
    {
        return Err(FsError::InvalidData);
    }
    let peer2peer = match (allow_peer2peer, provider, client) {
        (true, Some(provider), Some(client)) => {
            match narf_io::p2pdma::map_type_and_distance(topology, provider, client) {
                (P2pMapType::NotSupported, _) => None,
                (map, _) => Some(map),
            }
        }
        _ => None,
    };
    if peer2peer.is_none() && !object.can_migrate_to_system() {
        return Err(FsError::Unsupported);
    }
    object.prime_attach(peer2peer.is_some());
    Ok(Attachment {
        object,
        exporter,
        peer2peer,
        serial: Mutex::new(()),
        pinned: AtomicBool::new(false),
        wakeref: IrqSafeSpinLock::new(None),
        sg: IrqSafeSpinLock::new(None),
    })
}

impl Attachment {
    pub(crate) fn object(&self) -> &Arc<GemObject> {
        &self.object
    }
    /// `attach->peer2peer`, with the path the oracle chose.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn peer2peer(&self) -> Option<P2pMapType> {
        self.peer2peer
    }
    pub(crate) fn pinned(&self) -> bool {
        self.pinned.load(Ordering::Acquire)
    }

    /// `xe_dma_buf_pin` for this attachment. NARF importers are static, so
    /// the only caller is [`Self::map`] (`dma_buf_pin_on_map`); the pin lasts
    /// until the attachment drops (`dma_buf_detach` unpins).
    async fn pin_locked(&self) -> Result<(), FsError> {
        if self.wakeref.lock().is_none() {
            let wakeref = self.exporter.backend.cpu_vram_wakeref().await?;
            let previous = self.wakeref.lock().replace(wakeref);
            drop(previous);
        }
        let epoch = self
            .exporter
            .backend
            .status()
            .filter(|s| s.platform == self.exporter.platform && s.epoch != 0)
            .map(|s| s.epoch);
        self.object
            .pin_external(self.exporter.backend.as_ref(), epoch)
            .await?;
        self.pinned.store(true, Ordering::Release);
        Ok(())
    }

    /// `dma_buf_map_attachment` -> `xe_dma_buf_map`, pinning first
    /// (`dma_buf_pin_on_map`). One mapping per attachment; later calls
    /// return it.
    pub(crate) async fn map(&self) -> Result<Arc<SgTable>, FsError> {
        let _serial = self.serial.lock().await;
        if let Some(sg) = self.sg.lock().clone() {
            return Ok(sg);
        }
        if self.peer2peer.is_none() && !self.object.can_migrate_to_system() {
            return Err(FsError::Unsupported);
        }
        let newly_pinned = !self.pinned();
        if newly_pinned {
            self.pin_locked().await?;
        }
        match self.build_sg() {
            Ok(sg) => {
                let sg = Arc::new(sg);
                *self.sg.lock() = Some(sg.clone());
                Ok(sg)
            }
            Err(error) => {
                // dma_buf_map_attachment unpins a pin-on-map that failed.
                if newly_pinned && self.pinned.swap(false, Ordering::AcqRel) {
                    self.object.unpin_external();
                }
                Err(error)
            }
        }
    }

    /// The `switch (bo->ttm.resource->mem_type)` of `xe_dma_buf_map` on the
    /// pinned placement.
    fn build_sg(&self) -> Result<SgTable, FsError> {
        if self.object.is_vram() {
            // Fail closed where Linux would hand a non-P2P importer a VRAM
            // table: a non-P2P pin either migrated the object or refused.
            let map = self.peer2peer.ok_or(FsError::InvalidData)?;
            let base = self.object.lmem_bar_address().ok_or(FsError::Unsupported)?;
            let mut segments = Vec::new();
            let mut offset = 0;
            while offset < self.object.size() {
                let len = (self.object.size() - offset).min(SZ_2G);
                // dma_map_resource; dma_mapping_error is -ENOMEM.
                let dma =
                    narf_io::iommu::map_phys(base + offset).map_err(|_| FsError::OutOfMemory)?;
                segments.push(Segment {
                    dma,
                    len: len as u32,
                });
                offset += len;
            }
            return Ok(SgTable {
                placement: SgPlacement::PeerVram(map),
                segments,
            });
        }
        // drm_prime_pages_to_sg merges physically contiguous pages;
        // dma_map_sgtable failure is -EBUSY (`error_free`).
        let mut segments: Vec<Segment> = Vec::new();
        for page in self.object.pages() {
            let dma = narf_io::iommu::map_phys(page).map_err(|_| FsError::Busy)?;
            match segments.last_mut() {
                Some(last)
                    if last.dma + u64::from(last.len) == dma
                        && u64::from(last.len) + PAGE <= MAX_SYSTEM_SEGMENT =>
                {
                    last.len += PAGE as u32;
                }
                _ => segments.push(Segment {
                    dma,
                    len: PAGE as u32,
                }),
            }
        }
        if segments.iter().map(|s| u64::from(s.len)).sum::<u64>() != self.object.size() {
            return Err(FsError::InvalidData);
        }
        Ok(SgTable {
            placement: SgPlacement::System,
            segments,
        })
    }
}

impl Drop for Attachment {
    /// `dma_buf_detach`: unmap (identity here), unpin a pin-on-map, then
    /// `xe_dma_buf_detach`'s runtime-PM put.
    fn drop(&mut self) {
        if self.pinned.swap(false, Ordering::AcqRel) {
            self.object.unpin_external();
        }
        self.object.prime_detach(self.peer2peer.is_some());
        let wakeref = self.wakeref.lock().take();
        drop(wakeref);
    }
}

/// A foreign dma-buf held by an importing open: the exporter's card (for a
/// re-export, which names the original buffer) and the attachment.
#[derive(Debug)]
pub(crate) struct Import {
    card: u32,
    attachment: Attachment,
}

impl Import {
    pub(crate) fn new(card: u32, attachment: Attachment) -> Self {
        Self { card, attachment }
    }
    pub(crate) fn card(&self) -> u32 {
        self.card
    }
    pub(crate) fn exporter_object(&self) -> &Arc<GemObject> {
        self.attachment.object()
    }
    pub(crate) fn attachment(&self) -> &Attachment {
        &self.attachment
    }
}

/// Map an imported object's attachment before its first GPU use (Linux
/// `xe_bo_validate` -> `xe_bo_move` -> `dma_buf_map_attachment` of the sg
/// BO), installing its pages once. Not an import: nothing to do.
pub(crate) async fn ensure_mapped(object: &Arc<GemObject>) -> Result<(), FsError> {
    let Some(import) = object.import() else {
        return Ok(());
    };
    if object.import_mapped() {
        return Ok(());
    }
    let sg = import.attachment().map().await?;
    if sg.len() != object.size() {
        return Err(FsError::InvalidData);
    }
    object.install_import_pages(sg.pages())
}

/// The live PCI function of an Intel DRM card.
fn pci_function(card: u32) -> Option<narf_bus::BusDevice> {
    crate::intel_gpu_gt_runtime::pci_function(card)
}

/// `xe_gem_prime_import` of another Intel card's dma-buf: `object` was
/// exported by `exporter_card`, the importing open belongs to
/// `importer_card`. The importer must be a native Xe card; the exporter
/// must have a GT owner to migrate and keep the BAR awake. A reimport of
/// the same buffer returns the open's existing handle. Peer-to-peer is
/// requested only with `narf.intel.prime_p2p=1`.
pub(crate) fn import_foreign(
    importer_card: u32,
    gem: &GemState,
    exporter_card: u32,
    object: &Arc<GemObject>,
) -> Result<u32, FsError> {
    let importer =
        crate::intel_gpu_render::DeviceInfo::for_card(importer_card).ok_or(FsError::InvalidData)?;
    if !importer
        .backend
        .as_ref()
        .is_some_and(|backend| backend.native_xe())
    {
        return Err(FsError::InvalidData);
    }
    if let Some(handle) = gem.imported_handle(object) {
        return Ok(handle);
    }
    let exporter =
        crate::intel_gpu_render::DeviceInfo::for_card(exporter_card).ok_or(FsError::InvalidData)?;
    let backend = exporter.backend.clone().ok_or(FsError::InvalidData)?;
    let allow_peer2peer = crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), P2P_OPTION);
    let attachment = attach(
        object.clone(),
        Exporter {
            platform: exporter.platform,
            backend,
        },
        &narf_bus::p2pdma::LiveTopology,
        pci_function(exporter_card),
        pci_function(importer_card),
        allow_peer2peer,
    )?;
    gem.import_attachment(Import::new(exporter_card, attachment))
}

/// A modelled PCIe fabric for native fixtures (no live registry): the
/// exporter and a peer below two downstream ports of one switch (Linux
/// `calc_map_type_and_dist` distance 4 over bus addresses), and a distant
/// function below a second root port of a host bridge off the p2pdma
/// whitelist, on a CPU that is not AMD Zen (no peer path).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod fixture {
    use narf_io::p2pdma::{HostBridgeDev, P2pTopology};

    /// Root port 0 -> switch upstream port 1 -> downstream ports 2 and 3;
    /// root port 6 -> 7.
    const PARENT: [Option<u8>; 8] = [
        None,
        Some(0),
        Some(1),
        Some(1),
        Some(2),
        Some(3),
        None,
        Some(6),
    ];
    pub(crate) const EXPORTER: u8 = 4;
    pub(crate) const PEER: u8 = 5;
    pub(crate) const DISTANT: u8 = 7;

    #[derive(Debug)]
    pub(crate) struct Fabric;

    impl P2pTopology for Fabric {
        type Node = u8;
        fn same(&self, a: u8, b: u8) -> bool {
            a == b
        }
        fn upstream_bridge(&self, node: u8) -> Option<u8> {
            PARENT.get(usize::from(node)).copied().flatten()
        }
        fn acs_redirect(&self, _node: u8) -> bool {
            false
        }
        fn host_bridge(&self, _node: u8) -> u64 {
            0
        }
        /// An Intel client host bridge outside `pci_p2pdma_whitelist`.
        fn host_bridge_dev(&self, _node: u8) -> Option<HostBridgeDev> {
            Some(HostBridgeDev {
                vendor: 0x8086,
                device: 0x4660,
            })
        }
        fn cpu_supports_p2pdma(&self) -> bool {
            false
        }
    }
}
