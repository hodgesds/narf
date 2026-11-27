// Cross-device Intel PRIME against Linux xe_dma_buf.c (v7.4-rc4), over the
// fake-LMEM BMG fixture of `vram_evict` and a modelled PCIe fabric:
// 1. A VRAM export attached peer-to-peer maps the LMEM BAR bus addresses
//    (xe_ttm_vram_mgr_alloc_sgt: DPA + io_start), pins VRAM against
//    eviction and suspend drain, and a foreign import binds them.
// 2. An importer without a P2P path makes xe_dma_buf_pin migrate the
//    VRAM|system BO to system memory; the import binds those pages, shares
//    the exporter's reservation and refuses CPU access.
// 3. Refusals: a VRAM-only placement without P2P (-EOPNOTSUPP), a system pin
//    of an object pinned in VRAM (-EINVAL), a VRAM scanout object.
// 4. Dynamic importers (xe_dma_buf_attach_ops): mapping does not pin, so the
//    exporter evicts and migrates the object; each move notifies the
//    importer first (xe_bo_move_notify -> dma_buf_invalidate_mappings ->
//    xe_dma_buf_move_notify), whose binding has no pages until its next exec
//    or VM_BIND maps the new placement (xe_bo_trigger_rebind).
// 5. System suspend with a pinned VRAM export (xe_bo_evict_all ->
//    xe_bo_evict_pinned, xe_bo_restore_late -> xe_bo_restore_pinned): the
//    drain evicts unpinned VRAM; a pinned export keeps its allocation, its
//    data saved to system memory, and the resume copies it back to the same
//    device address.
use super::vram_evict::{create_vram_bo, evict_fixture, EvictBackend};
use super::*;
use crate::intel_gpu_exec::vram_clear;
use crate::intel_gpu_gem::GemObject;
use crate::intel_gpu_prime::fixture::{Fabric, DISTANT, EXPORTER, PEER};
use crate::intel_gpu_prime::{attach, attach_dynamic, Exporter, Import, SgPlacement};
use narf_io::p2pdma::P2pMapType;
use narf_io::sg::Segment;
use narf_scheduler::block_on_spin;

const BO: u64 = 64 * 1024;
/// The exporting card an import records (its re-export names this card).
const EXPORTER_CARD: u32 = 7;
/// Two-way coherent Xe2 PAT index (xe2_pat_table[2]).
const PAT_2WAY: u16 = 2;

fn exporter(backend: &Arc<EvictBackend>) -> Exporter {
    Exporter {
        platform: GtPlatform::Battlemage,
        backend: backend.clone(),
        mapped_moves: false,
    }
}

fn pattern(seed: u64) -> Vec<u8> {
    (0..BO).map(|i| (i * 13 + seed) as u8).collect()
}

fn smoke_xe_prime_peer_vram_maps_lmem_bar_bus_addresses_and_pins() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    assert!(object.is_vram());
    object.write(0, &pattern(1)).unwrap();
    // xe_ttm_vram_mgr_alloc_sgt: cursor.start (the DPA) plus the region's
    // io_start (the fixture BAR, tile offset 0).
    let dpa = object.pages().next().unwrap();
    let bus = frame.start_address().raw() + dpa;
    let exported = file.gem.export_object(handle).unwrap();
    let peer = attach(
        exported,
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    // Two devices below one switch with no ACS redirect: PCI_P2PDMA_MAP_BUS_ADDR.
    assert_eq!(peer.peer2peer(), Some(P2pMapType::BusAddr));
    let sg = block_on_spin(peer.map()).unwrap();
    assert_eq!(sg.placement, SgPlacement::PeerVram(P2pMapType::BusAddr));
    assert_eq!(
        sg.segments,
        [Segment {
            dma: bus,
            len: BO as u32
        }]
    );
    // The bus address is the BAR frame a CPU mmap of the same BO uses.
    let view = object.backing(0, 4096).unwrap();
    assert_eq!(view.frames[0], bus);
    drop(view);
    // The pin keeps VRAM: no eviction, and the suspend drain frees nothing.
    assert!(object.is_vram() && object.externally_pinned() && peer.pinned());
    assert!(!object.is_evictable(true));
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, true)),
        Err(FsError::Busy)
    );
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::evict_vram_for(
            backend.as_ref(),
            &pool,
            false,
            0,
            epoch,
            true
        )),
        Ok(0)
    );
    assert_eq!(pool.used(), BO);

    // A foreign import binds the peer BAR pages as system PTEs.
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, peer))
        .unwrap();
    let imported = importer.gem.object(imported_handle).unwrap();
    assert!(!imported.is_vram() && !imported.import_mapped());
    let vm = create_vm(&importer, &info, &user);
    // xe_vm_bind_ioctl_validate_bo: an import needs 1-way or 2-way coherency.
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x5678_0000_0000, 0, BO, 0, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Err(FsError::InvalidData));
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x5678_0000_0000, 0, BO, PAT_2WAY, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Ok(0));
    let expected: Vec<u64> = (0..BO / 4096).map(|page| bus + page * 4096).collect();
    assert_eq!(imported.pages().collect::<Vec<_>>(), expected);
    assert!(object.is_vram());

    // Dropping the import (handle, VM and open) detaches and unpins.
    importer.gem.close(imported_handle).unwrap();
    drop(imported);
    drop(importer);
    assert!(!object.externally_pinned());
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, true)),
        Ok(BO)
    );
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(1));

    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_peer_vram_maps_lmem_bar_bus_addresses_and_pins
);

fn smoke_xe_prime_import_without_p2p_migrates_to_system_and_binds() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    assert!(object.is_vram() && object.can_migrate_to_system());
    object.write(0, &pattern(5)).unwrap();
    // Below another root port of a non-whitelisted host bridge, without an
    // AMD Zen CPU, calc_map_type_and_dist is NOT_SUPPORTED: xe_dma_buf_attach
    // clears peer2peer and the VRAM|system object may still migrate.
    let host = attach(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(DISTANT),
        true,
    )
    .unwrap();
    assert_eq!(host.peer2peer(), None);
    assert!(object.is_vram(), "attach alone never migrates");

    // xe_gem_prime_import on another device: a system-placed sg object over
    // the attachment, sharing the exporter's reservation.
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, host))
        .unwrap();
    let imported = importer.gem.object(imported_handle).unwrap();
    assert!(Arc::ptr_eq(&imported.dma_buf, &object.dma_buf));
    assert!(imported.is_imported() && !imported.is_vram());
    assert_eq!(imported.size(), BO);
    assert_eq!(imported.pages().next(), None);
    // Its MMAP_OFFSET maps the exporter's object (dma_buf_mmap), not its own
    // pages; the import has no kernel CPU access of its own.
    let offset = importer.gem.mmap_offset(imported_handle).unwrap();
    let (owner, within) = importer.gem.mapping_object(offset, 4096).unwrap();
    assert!(Arc::ptr_eq(&owner, &object) && within == 0);
    drop(owner);
    assert_eq!(imported.read(0, &mut [0]), Err(FsError::Unsupported));
    assert_eq!(imported.write(0, &[0]), Err(FsError::Unsupported));
    assert_eq!(imported.backing(0, 4096).err(), Some(FsError::Unsupported));
    assert!(!imported.can_migrate_to_system());
    // A reimport of the same buffer is the same handle; a re-export names the
    // original buffer and card.
    assert_eq!(importer.gem.imported_handle(&object), Some(imported_handle));
    assert!(imported
        .prime_origin()
        .is_some_and(|(card, origin)| card == EXPORTER_CARD && Arc::ptr_eq(&origin, &object)));

    // VM_BIND validates the import: pin-on-map migrates the exporter to
    // system memory through the eviction copy, then maps its pages.
    let vm = create_vm(&importer, &info, &user);
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x5678_0000_0000, 0, BO, PAT_2WAY, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Ok(0));
    assert!(!object.is_vram() && object.externally_pinned());
    assert_eq!(pool.used(), 0);
    let exporter_pages: Vec<u64> = object.pages().collect();
    assert_eq!(exporter_pages.len() as u64, BO / 4096);
    assert_eq!(imported.pages().collect::<Vec<_>>(), exporter_pages);
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(5));
    // The pin refuses exec's re-migration (xe_bo_migrate -EBUSY on a pinned BO).
    assert_eq!(
        block_on_spin(object.migrate_to_vram(backend.as_ref(), &pool, true, epoch)),
        Err(FsError::Busy)
    );

    importer.gem.close(imported_handle).unwrap();
    drop(imported);
    drop(importer);
    assert!(!object.externally_pinned());
    assert_eq!(
        block_on_spin(object.migrate_to_vram(backend.as_ref(), &pool, true, epoch)),
        Ok(())
    );
    assert!(object.is_vram());
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(5));

    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_import_without_p2p_migrates_to_system_and_binds
);

fn smoke_xe_prime_pinned_and_vram_only_refusals() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let host_attach = |object: &Arc<GemObject>| {
        attach(
            object.clone(),
            exporter(&backend),
            &Fabric,
            Some(EXPORTER),
            Some(DISTANT),
            true,
        )
    };
    let peer_attach = |object: &Arc<GemObject>| {
        attach(
            object.clone(),
            exporter(&backend),
            &Fabric,
            Some(EXPORTER),
            Some(PEER),
            true,
        )
    };

    // A VRAM-only placement: xe_bo_can_migrate(bo, XE_PL_TT) is false, so an
    // attachment without peer-to-peer is -EOPNOTSUPP, whether the path is
    // missing or the importer never asked for P2P.
    let only = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 2).unwrap())
        .unwrap();
    assert!(only.is_vram() && !only.can_migrate_to_system());
    assert_eq!(host_attach(&only).err(), Some(FsError::Unsupported));
    assert_eq!(
        attach(
            only.clone(),
            exporter(&backend),
            &Fabric,
            Some(EXPORTER),
            Some(PEER),
            false
        )
        .err(),
        Some(FsError::Unsupported)
    );
    // A peer reaches it in place.
    let peer = peer_attach(&only).unwrap();
    assert!(block_on_spin(peer.map()).is_ok_and(|sg| sg.placement != SgPlacement::System));
    drop(peer);
    // The placement list decides, not the current placement: evicted to
    // system memory, the VRAM-only object still refuses a host attachment.
    assert_eq!(
        block_on_spin(only.evict_to_system(backend.as_ref(), epoch, false)),
        Ok(BO)
    );
    assert_eq!(host_attach(&only).err(), Some(FsError::Unsupported));

    // Pinned in VRAM by a peer, a VRAM|system object refuses a host pin:
    // "Can't migrate pinned bo for dma-buf pin" (-EINVAL). The failed
    // pin-on-map leaves no pin behind.
    let shared = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 3).unwrap())
        .unwrap();
    let peer = peer_attach(&shared).unwrap();
    block_on_spin(peer.map()).unwrap();
    let host = host_attach(&shared).unwrap();
    assert_eq!(block_on_spin(host.map()).err(), Some(FsError::InvalidData));
    assert!(shared.is_vram() && !host.pinned());
    // allow_vram covers every attachment: with a host importer attached, a
    // second peer may not pin the VRAM object either.
    let second = peer_attach(&shared).unwrap();
    assert_eq!(block_on_spin(second.map()).err(), Some(FsError::InvalidData));
    drop(second);
    drop(peer);
    assert!(!shared.externally_pinned());
    // Unpinned, the host pin migrates and maps system pages; a later peer
    // gets those pages too (the object is in TT).
    let sg = block_on_spin(host.map()).unwrap();
    assert_eq!(sg.placement, SgPlacement::System);
    assert!(!shared.is_vram());
    let late = peer_attach(&shared).unwrap();
    let late_sg = block_on_spin(late.map()).unwrap();
    assert_eq!(late_sg.placement, SgPlacement::System);
    assert_eq!(late_sg.segments, sg.segments);
    drop(late);
    drop(host);
    assert!(!shared.externally_pinned());

    // NARF has no display pin count: a VRAM scanout object is pinned.
    let scanout = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 3).unwrap())
        .unwrap();
    scanout.mark_scanout();
    let host = host_attach(&scanout).unwrap();
    assert_eq!(block_on_spin(host.map()).err(), Some(FsError::InvalidData));
    assert!(scanout.is_vram());
    drop(host);

    drop(scanout);
    drop(shared);
    drop(only);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_pinned_and_vram_only_refusals
);

/// The importer's exec at the import's binding: `xe_exec_ioctl`, whose
/// `xe_vm_validate_rebind` maps a moved import again.
fn exec_import(importer: &RenderFile, info: &DeviceInfo, user: &Cpu, queue: u32) {
    exec_wire(user, queue, true, &[]);
    assert_eq!(
        block_on_spin(importer.dispatch_user(info, xe::EXEC, 64, user)).expect("native EXEC"),
        Ok(0)
    );
}

fn smoke_xe_prime_move_notify_invalidates_and_rebinds_dynamic_import() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(9)).unwrap();
    let bar = |object: &Arc<GemObject>| -> Vec<u64> {
        // xe_ttm_vram_mgr_alloc_sgt: the DPA plus the fixture BAR's io_start.
        let bus = frame.start_address().raw() + object.pages().next().unwrap();
        (0..BO / 4096).map(|page| bus + page * 4096).collect()
    };

    // A dynamic peer attachment joins the exporter's attachment list.
    let peer = attach_dynamic(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    assert!(peer.is_dynamic() && peer.moves() == 0);
    assert_eq!(object.dma_buf.dynamic_importers(), 1);
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, peer))
        .unwrap();
    let imported = importer.gem.object(imported_handle).unwrap();
    let vm = create_vm(&importer, &info, &user);
    let queue = create_queue(&importer, &info, &user, vm, 0);
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x1234_0000_0000, 0, BO, PAT_2WAY, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Ok(0));
    let in_vram = bar(&object);
    assert_eq!(imported.pages().collect::<Vec<_>>(), in_vram);
    // dma_buf_pin_on_map is false for a dynamic attachment: no pin, so the
    // object stays evictable.
    assert!(object.is_vram() && !object.externally_pinned());
    assert!(object.is_evictable(false));

    // VRAM pressure evicts the export. The importer is notified before the
    // move: its binding has no pages, not the freed VRAM.
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, false)),
        Ok(BO)
    );
    assert!(!object.is_vram());
    assert_eq!(pool.used(), 0);
    let moves = imported.import().unwrap().attachment().moves();
    assert_eq!(moves, 1);
    assert!(!imported.import_mapped());
    assert_eq!(imported.pages().next(), None);

    // The importer's next exec maps the attachment again: a peer takes the
    // object where it is (system memory now) and the exec's tables use it.
    exec_import(&importer, &info, &user, queue);
    assert!(imported.import_mapped());
    let in_system: Vec<u64> = object.pages().collect();
    assert_eq!(in_system.len() as u64, BO / 4096);
    assert_eq!(imported.pages().collect::<Vec<_>>(), in_system);
    assert!(!object.is_vram());

    // The exporter migrates it back (its exec's re-migration): notified
    // again, and a VM_BIND of the same range rebinds the new BAR pages.
    assert_eq!(
        block_on_spin(object.migrate_to_vram(backend.as_ref(), &pool, true, epoch)),
        Ok(())
    );
    assert!(object.is_vram() && !imported.import_mapped());
    assert_eq!(imported.import().unwrap().attachment().moves(), moves + 1);
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x1234_0000_0000, 0, BO, PAT_2WAY, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Ok(0));
    assert_eq!(imported.pages().collect::<Vec<_>>(), bar(&object));
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(9));

    // A move the importer has not mapped since makes exec map again first.
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, false)),
        Ok(BO)
    );
    exec_import(&importer, &info, &user, queue);
    assert_eq!(
        imported.pages().collect::<Vec<_>>(),
        object.pages().collect::<Vec<_>>()
    );

    // dma_buf_detach: the import's last owner leaves the attachment list.
    importer.gem.close(imported_handle).unwrap();
    drop(imported);
    drop(importer);
    assert_eq!(object.dma_buf.dynamic_importers(), 0);
    assert!(!object.externally_pinned());

    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_move_notify_invalidates_and_rebinds_dynamic_import
);

fn smoke_xe_prime_dynamic_host_import_follows_exporter_migration() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(11)).unwrap();
    // No P2P path: xe_dma_buf_map of an unpinned object migrates it to TT.
    let host = attach_dynamic(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(DISTANT),
        true,
    )
    .unwrap();
    assert_eq!(host.peer2peer(), None);
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, host))
        .unwrap();
    let imported = importer.gem.object(imported_handle).unwrap();
    let vm = create_vm(&importer, &info, &user);
    let queue = create_queue(&importer, &info, &user, vm, 0);
    bind_wire(
        &user,
        vm,
        &[mapping(imported_handle, 0x1234_0000_0000, 0, BO, PAT_2WAY, 0)],
        &[],
    );
    assert_eq!(bind_now(&importer, &info, &user), Ok(0));
    assert!(!object.is_vram() && !object.externally_pinned());
    assert_eq!(
        imported.pages().collect::<Vec<_>>(),
        object.pages().collect::<Vec<_>>()
    );
    // The migration on map notified this importer too, before the table it
    // installed was built.
    assert!(imported.import_mapped());

    // Unpinned, the export may go back to VRAM (a static attachment's pin
    // refuses this with -EBUSY); the importer is notified.
    assert_eq!(
        block_on_spin(object.migrate_to_vram(backend.as_ref(), &pool, true, epoch)),
        Ok(())
    );
    assert!(object.is_vram() && !imported.import_mapped());
    // Its next exec maps again, which migrates the export to system memory
    // once more (Linux's dynamic ping-pong between a VRAM-preferring
    // exporter and a host importer).
    exec_import(&importer, &info, &user, queue);
    assert!(!object.is_vram() && imported.import_mapped());
    assert_eq!(
        imported.pages().collect::<Vec<_>>(),
        object.pages().collect::<Vec<_>>()
    );
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(11));

    importer.gem.close(imported_handle).unwrap();
    drop(imported);
    drop(importer);
    assert_eq!(object.dma_buf.dynamic_importers(), 0);
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_dynamic_host_import_follows_exporter_migration
);

// CPU mmap of a VRAM export through a peer's import: the importer's offset
// maps the exporter's LMEM BAR frames write-combining (xe_gem_object_mmap
// of the exporter, reached by dma_buf_mmap), and the live alias keeps the
// export in place: an eviction would move pages a process maps.
fn smoke_xe_prime_foreign_import_mmap_maps_exporter_bar_and_holds_placement() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(13)).unwrap();
    let bus = frame.start_address().raw() + object.pages().next().unwrap();
    let peer = attach_dynamic(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, peer))
        .unwrap();
    let offset = importer.gem.mmap_offset(imported_handle).unwrap();
    assert_ne!(Ok(offset), file.gem.mmap_offset(handle));
    let view = importer.gem.mmap_backing(offset + 4096, 8192).unwrap();
    assert_eq!(view.frames, [bus + 4096, bus + 8192]);
    assert_eq!(view.memory_type, narf_memory::MemoryType::WriteCombining);
    // The alias is the exporter's: no eviction while it is mapped.
    assert!(!object.is_evictable(false));
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, false)),
        Err(FsError::Busy)
    );
    assert!(object.is_vram());
    drop(view);
    assert_eq!(
        block_on_spin(object.evict_to_system(backend.as_ref(), epoch, false)),
        Ok(BO)
    );
    // After the move the same offset maps the exporter's system pages.
    let view = importer.gem.mmap_backing(offset, 4096).unwrap();
    assert_eq!(view.frames[0], object.pages().next().unwrap());
    assert_eq!(view.memory_type, narf_memory::MemoryType::WriteBack);
    drop(view);
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(13));

    importer.gem.close(imported_handle).unwrap();
    drop(importer);
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_foreign_import_mmap_maps_exporter_bar_and_holds_placement
);

fn smoke_xe_prime_pinned_vram_export_survives_suspend_in_place() -> TestResult {
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let epoch = backend.status().unwrap().epoch;
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(17)).unwrap();
    let other = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 3).unwrap())
        .unwrap();
    other.write(0, &pattern(19)).unwrap();
    let dpa = object.pages().next().unwrap();
    // A peer's static attachment pins the export in VRAM.
    let peer = attach(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    let sg = block_on_spin(peer.map()).unwrap();
    assert!(object.externally_pinned() && object.is_vram());

    // xe_bo_evict_all_user: the drain moves only the unpinned object, and
    // the pinned one is all prepare_suspend's gate would lose.
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::evict_vram_for(
            backend.as_ref(),
            &pool,
            false,
            0,
            epoch,
            true
        )),
        Ok(BO)
    );
    assert!(!other.is_vram() && object.is_vram());
    assert_eq!(pool.unsaved_bytes(), BO);
    // xe_bo_evict_pinned: saved to system memory, the allocation kept.
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::backup_pinned_vram(
            backend.as_ref(),
            &pool,
            epoch
        )),
        Ok(BO)
    );
    assert!(object.restore_pending() && object.is_vram());
    assert_eq!(pool.used(), BO);
    assert_eq!(pool.unsaved_bytes(), 0);
    // A second pass keeps the backup that still holds the data.
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::backup_pinned_vram(
            backend.as_ref(),
            &pool,
            epoch
        )),
        Ok(BO)
    );
    // Until the restore nothing reaches the VRAM: no CPU copy or mapping,
    // no eviction.
    assert_eq!(object.read(0, &mut [0]), Err(FsError::WouldBlock));
    assert_eq!(object.write(0, &[0]), Err(FsError::WouldBlock));
    assert_eq!(object.backing(0, 4096).err(), Some(FsError::WouldBlock));
    assert!(!object.is_evictable(true));

    // S3 loses LMEM: poison the fixture aperture behind the object.
    // SAFETY: the fixture exclusively owns its fake LMEM frames; nothing
    // maps or accesses this object while its restore is pending.
    unsafe {
        core::ptr::write_bytes(
            frame.start_address().kernel_mut_ptr::<u8>().add(dpa as usize),
            0x5a,
            BO as usize,
        )
    };
    // xe_bo_restore_pinned: the same device address, the saved bytes.
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::restore_pinned_vram(
            backend.as_ref(),
            &pool,
            epoch
        )),
        Ok(1)
    );
    assert!(!object.restore_pending() && object.is_vram());
    assert_eq!(object.pages().next(), Some(dpa));
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(17));
    // The peer's table names the same BAR addresses as before the suspend.
    assert_eq!(block_on_spin(peer.map()).unwrap().segments, sg.segments);

    // Another suspend: the importer's first use after resume restores the
    // export before mapping it.
    assert_eq!(
        block_on_spin(crate::intel_gpu_xe::backup_pinned_vram(
            backend.as_ref(),
            &pool,
            epoch
        )),
        Ok(BO)
    );
    // SAFETY: as above.
    unsafe {
        core::ptr::write_bytes(
            frame.start_address().kernel_mut_ptr::<u8>().add(dpa as usize),
            0xa5,
            BO as usize,
        )
    };
    let importer = RenderFile::new();
    let imported_handle = importer
        .gem
        .import_attachment(Import::new(EXPORTER_CARD, peer))
        .unwrap();
    let imported = importer.gem.object(imported_handle).unwrap();
    assert_eq!(
        block_on_spin(crate::intel_gpu_prime::ensure_mapped(&imported)),
        Ok(())
    );
    assert!(!object.restore_pending());
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(17));
    let bus = frame.start_address().raw() + dpa;
    assert_eq!(imported.pages().next(), Some(bus));

    importer.gem.close(imported_handle).unwrap();
    drop(imported);
    drop(importer);
    assert!(!object.externally_pinned());
    // Unpinned, a later suspend drains it like any other object.
    other.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(19));
    drop(other);
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_pinned_vram_export_survives_suspend_in_place
);

/// `xe_dma_buf_begin_cpu_access` (DMA_BUF_IOCTL_SYNC START). The dma-buf
/// core's direction (`dma_buf_ioctl`: SYNC_READ is DMA_FROM_DEVICE,
/// SYNC_WRITE DMA_TO_DEVICE, SYNC_RW DMA_BIDIRECTIONAL, neither -EINVAL)
/// decides: only a read migrates a VRAM|system export to system memory
/// (`xe_bo_migrate(bo, XE_PL_TT)`) with its data, its dynamic importer
/// notified first and its mmap offset then mapping the system pages; a
/// second call finds it there. A live CPU mapping of the BAR, a pinned
/// export (-EBUSY) and a VRAM-only one (-EINVAL) stay in VRAM, and the
/// exporter hook still succeeds, as Linux's returns 0 ("cpu-access takes
/// place in current placement").
fn smoke_xe_prime_begin_cpu_access_migrates_vram_for_cpu_reads() -> TestResult {
    use crate::intel_gpu_prime::{migrate_for_cpu_read, CpuAccess};
    use narf_filesystem::dma_buf::{DmaBufCpuAccess, DmaDataDirection as D};
    assert_eq!(D::from_sync_flags(1), Some(D::FromDevice));
    assert_eq!(D::from_sync_flags(2), Some(D::ToDevice));
    assert_eq!(D::from_sync_flags(3), Some(D::Bidirectional));
    assert_eq!(D::from_sync_flags(3 | 4), Some(D::Bidirectional));
    assert_eq!(D::from_sync_flags(0), None);
    assert_eq!(D::from_sync_flags(4), None);
    assert!(D::FromDevice.cpu_reads() && !D::FromDevice.cpu_writes());
    assert!(!D::ToDevice.cpu_reads() && D::ToDevice.cpu_writes());
    assert!(D::Bidirectional.cpu_reads() && D::Bidirectional.cpu_writes());

    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(23)).unwrap();
    // A dynamic peer maps the export in place.
    let peer = attach_dynamic(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    let generation = block_on_spin(peer.map()).unwrap().generation;
    assert!(object.is_vram() && peer.current(generation));
    // A CPU write does not migrate.
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&object, backend.as_ref(), D::ToDevice, false)),
        Ok(false)
    );
    assert!(object.is_vram() && peer.current(generation));
    // A live CPU mapping of the BAR keeps the export where it is.
    let offset = file.gem.mmap_offset(handle).unwrap();
    let view = file.gem.mmap_backing(offset, 4096).unwrap();
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&object, backend.as_ref(), D::FromDevice, false)),
        Err(FsError::Busy)
    );
    assert!(object.is_vram() && peer.current(generation));
    drop(view);
    // A read migrates it: the data moves, the importer is notified first,
    // and the VRAM is free.
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&object, backend.as_ref(), D::FromDevice, false)),
        Ok(true)
    );
    assert!(!object.is_vram() && !peer.current(generation));
    assert_eq!(pool.used(), 0);
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(23));
    let view = file.gem.mmap_backing(offset, 4096).unwrap();
    assert_eq!(view.frames[0], object.pages().next().unwrap());
    assert_eq!(view.memory_type, narf_memory::MemoryType::WriteBack);
    drop(view);
    // Already in system memory: nothing to do.
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&object, backend.as_ref(), D::Bidirectional, false)),
        Ok(false)
    );

    // A static peer's map pins its export in VRAM: -EBUSY.
    let pinned = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 3).unwrap())
        .unwrap();
    let pin = attach(
        pinned.clone(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    assert!(block_on_spin(pin.map()).is_ok() && pinned.externally_pinned());
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&pinned, backend.as_ref(), D::FromDevice, false)),
        Err(FsError::Busy)
    );
    assert!(pinned.is_vram());
    // A VRAM-only placement has no system placement: -EINVAL.
    let only = file
        .gem
        .object(create_vram_bo(&file, &info, &user, BO, 2).unwrap())
        .unwrap();
    assert_eq!(
        block_on_spin(migrate_for_cpu_read(&only, backend.as_ref(), D::FromDevice, false)),
        Err(FsError::InvalidData)
    );
    assert!(only.is_vram());
    // The exporter hook succeeds whatever the migration did; on a card with
    // no device behind it nothing moves.
    assert_eq!(
        block_on_spin(CpuAccess::new(u32::MAX, &only).begin_cpu_access(D::FromDevice)),
        Ok(())
    );
    assert!(only.is_vram());

    drop(pin);
    drop(peer);
    drop(only);
    drop(pinned);
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_begin_cpu_access_migrates_vram_for_cpu_reads
);

// ── Migrating a VRAM export a process has mmapped ────────────────────

/// The address spaces the substitute VM owner freezes; the userspace one
/// (`mapped_file::relocate_device_frames`) takes every process root.
static MAPPED_SPACES: IrqSafeSpinLock<Vec<Arc<narf_memory::AddressSpace>>> =
    IrqSafeSpinLock::new(Vec::new());

/// `relocate_device_frames` over [`MAPPED_SPACES`].
fn relocate_named_spaces(
    old: &[u64],
    new: &[u64],
    aliases: fn(u64) -> usize,
    commit: &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<(), FsError> {
    use narf_memory::{AddressSpaceError, PhysAddr};
    let spaces = MAPPED_SPACES.lock().clone();
    let old: Vec<_> = old.iter().copied().map(PhysAddr::new).collect();
    let new: Vec<_> = new.iter().copied().map(PhysAddr::new).collect();
    let mut failure = None;
    // SAFETY: the driver retains both frame lists through this call; the
    // fixture retains every named root.
    let result = unsafe {
        narf_memory::address_space::with_revoked_shared_frames(&spaces, &old, &new, aliases, || {
            commit().map_err(|error| {
                failure = Some(error);
                AddressSpaceError::NotImplemented
            })
        })
    };
    match (failure, result) {
        (Some(error), _) => Err(error),
        (None, Ok(())) => Ok(()),
        (None, Err(_)) => Err(FsError::Busy),
    }
}

/// Install `frames` at `va` as the device mmap path does (a SHARED VMA
/// counted by the external alias registry) and fault them in.
fn map_frames(
    space: &narf_memory::AddressSpace,
    va: u64,
    frames: &[u64],
    memory_type: narf_memory::MemoryType,
) -> bool {
    use narf_memory::{PhysAddr, Region, RegionPerms, VirtAddr};
    let perms = (RegionPerms::READ
        | RegionPerms::WRITE
        | RegionPerms::SHARED
        | RegionPerms::EXTERNAL_REFS
        | RegionPerms::LOCK_EXEMPT)
        .with_memory_type(memory_type);
    let len = frames.len() as u64 * 4096;
    let phys: Vec<_> = frames.iter().copied().map(PhysAddr::new).collect();
    space
        .map_region(Region {
            base: VirtAddr::new(va),
            len,
            perms,
            phys: phys.into(),
        })
        .is_ok()
        // SAFETY: a fixture-owned root that is never activated.
        && unsafe { space.materialize_range(VirtAddr::new(va), len) }.is_ok()
}

/// The frame the leaf at `va` translates to.
fn leaf_frame(space: &narf_memory::AddressSpace, va: u64) -> Option<u64> {
    let va = narf_memory::VirtAddr::new(va);
    // SAFETY: a fixture-owned live root, mutated only by this fixture.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            narf_memory::x86_64::paging::translate(space.root, va).map(|p| p.raw())
        }
        #[cfg(target_arch = "aarch64")]
        {
            narf_memory::aarch64::paging::translate(space.root, va).map(|p| p.raw())
        }
    }
}

/// `xe_bo_migrate(bo, XE_PL_TT)` of a VRAM export a process has mmapped
/// (Linux 7.4-rc4 `ttm_bo_handle_move_mem`: `ttm_bo_unmap_virtual` before
/// the move, `xe_bo_cpu_fault` mapping the new placement after it), on the
/// BMG fixture with two processes mapping the whole export:
/// - without `narf.intel.prime_mmap_migrate=1` the live mapping keeps the
///   export in VRAM (`Busy`), its leaves unchanged;
/// - with it, a mapping handed out but not yet installed, or an alias
///   outside the VM snapshot, refuses the move with nothing changed;
/// - otherwise DMA_BUF_IOCTL_SYNC's read (`xe_dma_buf_begin_cpu_access`)
///   moves the bytes to system memory, notifies the dynamic peer, frees
///   the VRAM and leaves every process's leaves on the new system pages;
///   a later mmap of the offset maps them write-back;
/// - a host importer's map (`xe_dma_buf_map`'s migration) of a second
///   mapped export is `Busy` from an exporter without the option and moves
///   export and mapping from one with it.
fn smoke_xe_prime_mmapped_vram_export_migrates_with_its_mappings() -> TestResult {
    use crate::intel_gpu_prime::migrate_for_cpu_read;
    use narf_filesystem::dma_buf::DmaDataDirection as D;
    use narf_memory::{AddressSpace, MemoryType};
    // SAFETY: paging is live; the fixture exclusively owns never-activated roots.
    let spaces = match unsafe { (AddressSpace::new_for_user(), AddressSpace::new_for_user()) } {
        (Ok(a), Ok(b)) => [Arc::new(a), Arc::new(b)],
        _ => return TestResult::Skip("address-space allocation"),
    };
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Battlemage, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handle = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    object.write(0, &pattern(31)).unwrap();
    let offset = file.gem.mmap_offset(handle).unwrap();
    let view = file.gem.mmap_backing(offset, BO as usize).unwrap();
    assert_eq!(view.memory_type, MemoryType::WriteCombining);
    let bar = view.frames.clone();
    const VA: u64 = 0x4103_0000_0000;
    const VA2: u64 = 0x4104_0000_0000;
    for space in &spaces {
        assert!(map_frames(space, VA, &bar, view.memory_type));
    }
    crate::intel_gpu_gem::cpu_mapping::published(view.lifetime.as_ref());
    assert_eq!(leaf_frame(&spaces[1], VA + 4096), Some(bar[1]));
    let read = |object: &Arc<GemObject>, mapped_moves| {
        block_on_spin(migrate_for_cpu_read(
            object,
            backend.as_ref(),
            D::FromDevice,
            mapped_moves,
        ))
    };
    let in_place = |spaces: &[Arc<AddressSpace>]| {
        spaces.iter().all(|space| {
            bar.iter()
                .enumerate()
                .all(|(i, &phys)| leaf_frame(space, VA + i as u64 * 4096) == Some(phys))
        })
    };

    // The option off: the mapping holds the export in VRAM.
    assert_eq!(read(&object, false), Err(FsError::Busy));
    assert!(object.is_vram() && in_place(&spaces));

    let previous =
        narf_filesystem::mmap_relocation::replace(Some(relocate_named_spaces));
    *MAPPED_SPACES.lock() = spaces.to_vec();
    // A mapping handed out but not yet published would install the old
    // frames after the move.
    let unpublished = file.gem.mmap_backing(offset, 4096).unwrap();
    assert_eq!(read(&object, true), Err(FsError::Busy));
    assert!(object.is_vram() && in_place(&spaces));
    drop(unpublished);
    // An alias outside the snapshot: the census refuses the freeze.
    *MAPPED_SPACES.lock() = alloc::vec![spaces[0].clone()];
    assert_eq!(read(&object, true), Err(FsError::Busy));
    assert!(object.is_vram() && in_place(&spaces));
    let mut back = alloc::vec![0; BO as usize];
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(31));

    // Every alias in the snapshot: the read moves the export, its
    // dynamic peer notified, and both processes now map its system pages.
    let peer = attach_dynamic(
        file.gem.export_object(handle).unwrap(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(PEER),
        true,
    )
    .unwrap();
    let generation = block_on_spin(peer.map()).unwrap().generation;
    assert!(object.is_vram() && peer.current(generation));
    *MAPPED_SPACES.lock() = spaces.to_vec();
    assert_eq!(read(&object, true), Ok(true));
    assert!(!object.is_vram() && !peer.current(generation));
    assert_eq!(pool.used(), 0);
    let pages: Vec<u64> = object.pages().collect();
    assert_eq!(pages.len(), bar.len());
    assert!(pages.iter().all(|phys| !bar.contains(phys)));
    for space in &spaces {
        for (i, &phys) in pages.iter().enumerate() {
            assert_eq!(leaf_frame(space, VA + i as u64 * 4096), Some(phys));
        }
    }
    object.read(0, &mut back).unwrap();
    assert_eq!(back, pattern(31));
    // The bytes the processes see are the system pages'.
    let mut first = [0u8; 8];
    for (i, byte) in first.iter_mut().enumerate() {
        // SAFETY: the object's live system frame, read without a reference.
        *byte = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(pages[0]).kernel_ptr::<u8>().add(i))
        };
    }
    assert_eq!(first[..], pattern(31)[..8]);
    let again = file.gem.mmap_backing(offset, 4096).unwrap();
    assert_eq!(again.frames, [pages[0]]);
    assert_eq!(again.memory_type, MemoryType::WriteBack);
    drop(again);
    // Already in system memory: nothing to do.
    assert_eq!(read(&object, true), Ok(false));

    // A second mapped export and a host importer (no peer path): its map
    // must migrate the export (xe_dma_buf_map -> xe_bo_migrate).
    let handle2 = create_vram_bo(&file, &info, &user, BO, 3).unwrap();
    let second = file.gem.object(handle2).unwrap();
    second.write(0, &pattern(37)).unwrap();
    let view2 = file
        .gem
        .mmap_backing(file.gem.mmap_offset(handle2).unwrap(), BO as usize)
        .unwrap();
    assert!(map_frames(&spaces[0], VA2, &view2.frames, view2.memory_type));
    crate::intel_gpu_gem::cpu_mapping::published(view2.lifetime.as_ref());
    let host = attach_dynamic(
        second.clone(),
        exporter(&backend),
        &Fabric,
        Some(EXPORTER),
        Some(DISTANT),
        true,
    )
    .unwrap();
    assert_eq!(block_on_spin(host.map()).err(), Some(FsError::Busy));
    assert!(second.is_vram());
    assert_eq!(leaf_frame(&spaces[0], VA2), Some(view2.frames[0]));
    drop(host);
    let host = attach_dynamic(
        second.clone(),
        Exporter {
            mapped_moves: true,
            ..exporter(&backend)
        },
        &Fabric,
        Some(EXPORTER),
        Some(DISTANT),
        true,
    )
    .unwrap();
    let sg = block_on_spin(host.map()).unwrap();
    assert_eq!(sg.placement, SgPlacement::System);
    assert!(!second.is_vram());
    assert_eq!(pool.used(), 0);
    assert_eq!(leaf_frame(&spaces[0], VA2), second.pages().next());
    let mut back2 = alloc::vec![0; BO as usize];
    second.read(0, &mut back2).unwrap();
    assert_eq!(back2, pattern(37));

    narf_filesystem::mmap_relocation::replace(previous);
    MAPPED_SPACES.lock().clear();
    drop(sg);
    drop(host);
    drop(peer);
    drop(spaces);
    drop(view);
    drop(view2);
    drop(second);
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_mmapped_vram_export_migrates_with_its_mappings
);

/// DG2's Flat-CCS: Linux's GPU move copies the compression metadata with
/// the data (`xe_migrate_copy`); the CPU copy that moves a mapped export
/// cannot, so with the option a mapped Alchemist VRAM export still stays in
/// VRAM (`Busy`), its mapping untouched, while the same export unmapped
/// moves by the eviction copy.
fn smoke_xe_prime_mmapped_dg2_export_with_flat_ccs_stays_in_vram() -> TestResult {
    use crate::intel_gpu_prime::migrate_for_cpu_read;
    use narf_filesystem::dma_buf::DmaDataDirection as D;
    let (frame, pool, backend, info) = evict_fixture(GtPlatform::Alchemist, 0x130044);
    let file = RenderFile::new();
    let user = Cpu::new();
    let handle = create_vram_bo(&file, &info, &user, 65536, 3).unwrap();
    let object = file.gem.object(handle).unwrap();
    let offset = file.gem.mmap_offset(handle).unwrap();
    let view = file.gem.mmap_backing(offset, 4096).unwrap();
    crate::intel_gpu_gem::cpu_mapping::published(view.lifetime.as_ref());
    let read = |mapped_moves| {
        block_on_spin(migrate_for_cpu_read(
            &object,
            backend.as_ref(),
            D::FromDevice,
            mapped_moves,
        ))
    };
    assert_eq!(read(true), Err(FsError::Busy));
    assert!(object.is_vram());
    assert_eq!(file.gem.mmap_backing(offset, 4096).unwrap().frames, view.frames);
    drop(view);
    assert_eq!(read(true), Ok(true));
    assert!(!object.is_vram() && object.has_ccs_backup());
    drop(object);
    drop(file);
    drop(info);
    drop(backend);
    drop(pool);
    vram_clear::fixture_finish();
    narf_memory::frame::free_pages(frame, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_xe_prime_mmapped_dg2_export_with_flat_ccs_stays_in_vram
);
