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
//! Live importers are dynamic (`dma_buf_dynamic_attach` with
//! `xe_dma_buf_attach_ops`): mapping does not pin, so the exporter may evict
//! or migrate the object. Each move first calls
//! `DmaBufObject::invalidate_mappings` (`xe_bo_move_notify` ->
//! `dma_buf_invalidate_mappings`), and the importer's
//! `invalidate_mappings` (`xe_dma_buf_move_notify`) makes its mapping and
//! installed pages stale ([`MoveNotify`]). The importer's VM bindings keep
//! their records; the next VM_BIND or exec maps the attachment again and
//! rebuilds its page tables from the new pages (`xe_bo_trigger_rebind`,
//! `xe_bo_move_dmabuf`). A static attachment ([`attach`]; Linux
//! `dma_buf_attach`) still pins on map for its whole life
//! (`dma_buf_pin_on_map`). The exporter's runtime-PM reference
//! (`xe_pm_runtime_get` in attach) is taken at the first map or pin, since
//! NARF's runtime resume is asynchronous; it holds the BAR decoding while a
//! peer may DMA into it.
//!
//! Peer-to-peer into another function's BAR is unvalidated on hardware:
//! the live importer asks for it only with `narf.intel.prime_p2p=1`, and
//! otherwise takes the migration path.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_filesystem::dma_buf::DmaBufAttachOps;
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
    /// The attachment's move count this table was built at.
    pub(crate) generation: u64,
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

/// The importer side of an attachment: its move count and cached table.
/// A dynamic attachment registers it with the exporter's dma-buf as its
/// `dma_buf_attach_ops` (`xe_dma_buf_attach_ops`); a static one never moves.
#[derive(Debug)]
pub(crate) struct MoveNotify {
    /// Bumped by every move notification. A table or installed page list
    /// built at an older count is stale.
    moves: AtomicU64,
    /// The cached table (`ttm_bo->sg`).
    sg: IrqSafeSpinLock<Option<Arc<SgTable>>>,
}

impl MoveNotify {
    fn new() -> Self {
        Self {
            moves: AtomicU64::new(0),
            sg: IrqSafeSpinLock::new(None),
        }
    }
}

impl DmaBufAttachOps for MoveNotify {
    /// `xe_dma_buf_move_notify` -> `xe_bo_evict` of the import: the sg BO
    /// moves to SYSTEM, `xe_bo_trigger_rebind` invalidates its VMAs, and
    /// `xe_bo_move_dmabuf` unmaps the stale table at the next map. NARF's VM
    /// bindings build page tables from the import's pages at every exec, so
    /// the bumped count is the invalidation: the stale pages read as none
    /// until the next VM_BIND or exec maps the attachment again.
    fn invalidate_mappings(&self) {
        self.moves.fetch_add(1, Ordering::AcqRel);
        let stale = self.sg.lock().take();
        drop(stale);
    }
}

/// One importer of an Intel export (Linux `struct dma_buf_attachment`).
pub(crate) struct Attachment {
    object: Arc<GemObject>,
    exporter: Exporter,
    /// `attach->peer2peer` after `xe_dma_buf_attach`.
    peer2peer: Option<P2pMapType>,
    /// `dma_buf_attachment_is_dynamic`: registered with the exporter's
    /// dma-buf, mapped without a pin.
    dynamic: bool,
    /// Serializes this attachment's pin and map.
    serial: Mutex<()>,
    pinned: AtomicBool,
    wakeref: IrqSafeSpinLock<Option<Box<dyn core::any::Any + Send>>>,
    mapping: Arc<MoveNotify>,
}

impl core::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attachment")
            .field("exporter", &self.exporter)
            .field("peer2peer", &self.peer2peer)
            .field("dynamic", &self.dynamic)
            .field("pinned", &self.pinned.load(Ordering::Relaxed))
            .field("moves", &self.mapping.moves.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// `dma_buf_attach` + `xe_dma_buf_attach` for `object`, exported by
/// `exporter` whose PCI function is `provider`, to an importer whose PCI
/// function is `client` (`None`: not a PCI device). `allow_peer2peer` is
/// the importer's `dma_buf_attach_ops.allow_peer2peer`. The attachment is
/// static: its first map pins the export until it drops. Live Intel
/// importers are dynamic ([`attach_dynamic`]); fixtures model a static
/// (non-Intel) importer with this.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn attach<T: P2pTopology>(
    object: Arc<GemObject>,
    exporter: Exporter,
    topology: &T,
    provider: Option<T::Node>,
    client: Option<T::Node>,
    allow_peer2peer: bool,
) -> Result<Attachment, FsError> {
    attach_with(
        object,
        exporter,
        topology,
        provider,
        client,
        allow_peer2peer,
        false,
    )
}

/// [`attach`] as `dma_buf_dynamic_attach` with `xe_dma_buf_attach_ops`: the
/// attachment maps without a pin and follows the exporter's moves through
/// [`MoveNotify`], registered once the exporter's `attach` admitted it.
pub(crate) fn attach_dynamic<T: P2pTopology>(
    object: Arc<GemObject>,
    exporter: Exporter,
    topology: &T,
    provider: Option<T::Node>,
    client: Option<T::Node>,
    allow_peer2peer: bool,
) -> Result<Attachment, FsError> {
    attach_with(
        object,
        exporter,
        topology,
        provider,
        client,
        allow_peer2peer,
        true,
    )
}

fn attach_with<T: P2pTopology>(
    object: Arc<GemObject>,
    exporter: Exporter,
    topology: &T,
    provider: Option<T::Node>,
    client: Option<T::Node>,
    allow_peer2peer: bool,
    dynamic: bool,
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
    let mapping = Arc::new(MoveNotify::new());
    if dynamic {
        let weak: Weak<MoveNotify> = Arc::downgrade(&mapping);
        object.dma_buf.attach_dynamic(weak);
    }
    Ok(Attachment {
        object,
        exporter,
        peer2peer,
        dynamic,
        serial: Mutex::new(()),
        pinned: AtomicBool::new(false),
        wakeref: IrqSafeSpinLock::new(None),
        mapping,
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
    /// `dma_buf_attachment_is_dynamic`.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn is_dynamic(&self) -> bool {
        self.dynamic
    }
    /// The move count now: a table or page list built at an older count is
    /// stale.
    pub(crate) fn moves(&self) -> u64 {
        self.mapping.moves.load(Ordering::Acquire)
    }
    /// No move was notified since `generation`.
    pub(crate) fn current(&self, generation: u64) -> bool {
        self.moves() == generation
    }

    /// The exporter's runtime-PM reference, held from the first map or pin
    /// until the attachment drops (`xe_dma_buf_attach`/`detach`).
    async fn wake(&self) -> Result<(), FsError> {
        if self.wakeref.lock().is_none() {
            let wakeref = self.exporter.backend.cpu_vram_wakeref().await?;
            let previous = self.wakeref.lock().replace(wakeref);
            drop(previous);
        }
        Ok(())
    }

    /// The exporter's current user epoch, which a migration copy runs in.
    fn exporter_epoch(&self) -> Option<u64> {
        self.exporter
            .backend
            .status()
            .filter(|s| s.platform == self.exporter.platform && s.epoch != 0)
            .map(|s| s.epoch)
    }

    /// `xe_dma_buf_pin` for this attachment: [`Self::map`] of a static
    /// attachment (`dma_buf_pin_on_map`). The pin lasts until the attachment
    /// drops (`dma_buf_detach` unpins).
    async fn pin_locked(&self) -> Result<(), FsError> {
        self.wake().await?;
        let epoch = self.exporter_epoch();
        self.object
            .pin_external(self.exporter.backend.as_ref(), epoch)
            .await?;
        self.pinned.store(true, Ordering::Release);
        Ok(())
    }

    /// `xe_bo_restore_late` for this attachment's export when a system resume
    /// has not restored it yet: an importer must not reach VRAM S3 cleared.
    /// The copy runs in the exporter's epoch; without a running exporter GT
    /// the use waits (`WouldBlock`).
    pub(crate) async fn restore_export(&self) -> Result<(), FsError> {
        if !self.object.restore_pending() {
            return Ok(());
        }
        let epoch = self.exporter_epoch().ok_or(FsError::WouldBlock)?;
        self.object
            .restore_pinned(self.exporter.backend.as_ref(), epoch)
            .await
            .map(drop)
    }

    /// `dma_buf_map_attachment` -> `xe_dma_buf_map`. A static attachment
    /// pins first (`dma_buf_pin_on_map`) and keeps one table for its life. A
    /// dynamic one validates the placement without a pin and caches its
    /// table until the next move notification; a later call after a move
    /// maps the new placement.
    pub(crate) async fn map(&self) -> Result<Arc<SgTable>, FsError> {
        let _serial = self.serial.lock().await;
        let cached = self.mapping.sg.lock().clone();
        if let Some(sg) = cached.filter(|sg| self.current(sg.generation)) {
            return Ok(sg);
        }
        if self.peer2peer.is_none() && !self.object.can_migrate_to_system() {
            return Err(FsError::Unsupported);
        }
        if self.dynamic && !self.pinned() {
            self.wake().await?;
            let epoch = self.exporter_epoch();
            // Every move takes this placement lock and notifies under it, so
            // the count read here stays current while the table is built.
            let _placement = self
                .object
                .validate_for_dma_buf(
                    self.exporter.backend.as_ref(),
                    epoch,
                    self.peer2peer.is_some(),
                )
                .await?;
            let sg = Arc::new(self.build_sg(self.moves())?);
            *self.mapping.sg.lock() = Some(sg.clone());
            return Ok(sg);
        }
        let newly_pinned = !self.pinned();
        if newly_pinned {
            self.pin_locked().await?;
        }
        match self.build_sg(self.moves()) {
            Ok(sg) => {
                let sg = Arc::new(sg);
                *self.mapping.sg.lock() = Some(sg.clone());
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
    /// pinned or validated placement, at move count `generation`.
    fn build_sg(&self, generation: u64) -> Result<SgTable, FsError> {
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
                generation,
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
            generation,
        })
    }
}

impl Drop for Attachment {
    /// `dma_buf_detach`: leave the dynamic attachment list, unmap (identity
    /// here), unpin a pin-on-map, then `xe_dma_buf_detach`'s runtime-PM put.
    fn drop(&mut self) {
        if self.dynamic {
            let weak: Weak<MoveNotify> = Arc::downgrade(&self.mapping);
            let ops: Weak<dyn DmaBufAttachOps> = weak;
            self.object.dma_buf.detach_dynamic(&ops);
        }
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

/// Moves that may overtake one [`ensure_mapped`] before it reports
/// `WouldBlock` (the exec ioctl's -EAGAIN) instead of mapping again.
const MAP_RETRIES: usize = 8;

/// Map an imported object's attachment before a GPU use (Linux
/// `xe_bo_validate` -> `xe_bo_move` -> `dma_buf_map_attachment` of the sg
/// BO), installing its pages. After a move notification the stale pages are
/// replaced by a fresh mapping: the rebind of `xe_bo_trigger_rebind`. Not an
/// import: nothing to do.
pub(crate) async fn ensure_mapped(object: &Arc<GemObject>) -> Result<(), FsError> {
    let Some(import) = object.import() else {
        return Ok(());
    };
    // A pinned export's tables stay valid across suspend; its contents come
    // back only with the restore.
    import.attachment().restore_export().await?;
    for _ in 0..MAP_RETRIES {
        if object.import_mapped() {
            return Ok(());
        }
        let sg = import.attachment().map().await?;
        if sg.len() != object.size() {
            return Err(FsError::InvalidData);
        }
        match object.install_import_pages(sg.pages(), sg.generation) {
            // Moved again since this table was built: map the new placement.
            Err(FsError::WouldBlock) => continue,
            result => return result,
        }
    }
    Err(FsError::WouldBlock)
}

/// Whether any import in `objects` was notified of a move since its pages
/// were installed: page tables built from them are stale
/// (`xe_exec_ioctl`'s retry after `xe_vm_validate_rebind`).
pub(crate) fn imports_stale<'a>(objects: impl IntoIterator<Item = &'a Arc<GemObject>>) -> bool {
    objects
        .into_iter()
        .any(|object| object.is_imported() && !object.import_mapped())
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
    // xe_dma_buf_attach_ops: an Intel importer follows the exporter's moves.
    let attachment = attach_dynamic(
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
