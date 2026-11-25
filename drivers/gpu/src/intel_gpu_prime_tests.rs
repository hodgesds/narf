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
use super::vram_evict::{create_vram_bo, evict_fixture, EvictBackend};
use super::*;
use crate::intel_gpu_exec::vram_clear;
use crate::intel_gpu_gem::GemObject;
use crate::intel_gpu_prime::fixture::{Fabric, DISTANT, EXPORTER, PEER};
use crate::intel_gpu_prime::{attach, Exporter, Import, SgPlacement};
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
    assert_eq!(
        importer.gem.mmap_offset(imported_handle),
        Err(FsError::Unsupported)
    );
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
