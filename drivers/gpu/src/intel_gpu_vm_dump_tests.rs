// Literal wire/ownership tests over actual GEM, VM_BIND and private PPGTT.
use super::*;
use crate::{
    intel_gpu_exec::{ResidentBatch, VmMapping},
    intel_gpu_gem::GemState,
    intel_gpu_ppgtt::PtMemory,
    intel_gpu_xe_vm::{Bind, State, Vm},
};

fn qword(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn object(gem: &GemState, size: u64) -> (u32, Arc<crate::intel_gpu_gem::GemObject>) {
    let handle = gem.create(size, |_, _| Ok(())).unwrap();
    (handle, gem.object(handle).unwrap())
}
fn mapping(object: Option<Arc<crate::intel_gpu_gem::GemObject>>, va: u64) -> VmMapping {
    VmMapping {
        object,
        va,
        offset: 0,
        length: 4096,
        writable: true,
        pat: 2,
        dumpable: true,
    }
}
fn capture(batch: &ResidentBatch, access: impl FnMut() -> bool) -> Arc<Dump> {
    let index = free_slot();
    Armed::reserve(index).unwrap().capture_with_vm(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        |_, _| None,
        |output, access| {
            output.push(37, 0x534e4150, batch, access);
            Some(1)
        },
        access,
    );
    let dump = snapshot(index).unwrap();
    assert!(clear(index, dump.generation));
    dump
}

fn smoke_coredump_vm_dumpable_bind_split_replace_and_frozen_disclosure() -> TestResult {
    let gem = GemState::new();
    let (handle, object) = object(&gem, 16384);
    let vm = Vm::new(false).unwrap();
    let mut wire = [0; 80];
    wire[8..12].copy_from_slice(&handle.to_le_bytes());
    wire[12..14].copy_from_slice(&2u16.to_le_bytes());
    wire[24..32].copy_from_slice(&16384u64.to_le_bytes());
    wire[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
    wire[44..48].copy_from_slice(&8u32.to_le_bytes());
    let bind = Bind::read(&wire, &vm, &gem, GtPlatform::Battlemage).unwrap();
    assert!(bind.mapping.as_ref().unwrap().dumpable);
    let mut state = State {
        mappings: Vec::new(),
        active: Vec::new(),
    };
    state.publish(state.prepare(&[bind], false).unwrap());
    // The submitted graph is fixed before a subsequent disclosure change.
    let old = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &state.mappings,
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    wire[16..24].copy_from_slice(&4096u64.to_le_bytes());
    wire[24..32].copy_from_slice(&8192u64.to_le_bytes());
    wire[32..40].copy_from_slice(&0x11000u64.to_le_bytes());
    wire[44..48].copy_from_slice(&0u32.to_le_bytes());
    let replace = Bind::read(&wire, &vm, &gem, GtPlatform::Battlemage).unwrap();
    state.publish(state.prepare(&[replace], false).unwrap());
    assert_eq!(state.mappings.len(), 3);
    assert!(state.mappings[0].dumpable && state.mappings[2].dumpable);
    assert!(!state.mappings[1].dumpable);
    assert_eq!(state.mappings[2].offset, 12288);
    let new =
        ResidentBatch::from_vm(GtPlatform::Battlemage, &state.mappings, None, false, None).unwrap();
    assert_eq!(old.diagnostic_vm().mappings.len(), 1);
    assert_eq!(new.diagnostic_vm().mappings.len(), 2);
    assert_eq!(old.diagnostic_vm().mappings[0].length, 16384);
    let weak = Arc::downgrade(&object);
    gem.close(handle).unwrap();
    drop(object);
    drop(state);
    drop(vm);
    assert!(weak.upgrade().is_some());
    let dump = capture(&new, || true);
    let section = &dump.bytes[0x1b4540..];
    assert_eq!((word(section, 24), word(section, 28)), (1, 1));
    let record = &section[64..];
    assert_eq!((word(record, 40), word(record, 44)), (2, 2));
    // Fixed descriptors: replacement without DUMPABLE is never included.
    let ranges = &record[0x10180..];
    assert_eq!(qword(ranges, 0), 0x10000);
    assert_eq!(qword(ranges, 64), 0x13000);
    assert_eq!(qword(ranges, 64 + 16), 12288);
    drop(old);
    drop(new);
    assert!(
        weak.upgrade().is_none(),
        "snapshot retained live GEM instead of bytes"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_vm_dumpable_bind_split_replace_and_frozen_disclosure
);

fn smoke_coredump_vm_wire_owned_tables_corruption_and_immutable_reads() -> TestResult {
    let gem = GemState::new();
    let (handle, object) = object(&gem, 12288);
    object.write(4096, &[0x6d; 8192]).unwrap();
    let mut included = mapping(Some(object.clone()), 0x10000);
    included.offset = 4096;
    included.length = 8192;
    included.writable = false;
    let mut excluded = mapping(Some(object.clone()), 0x30000);
    excluded.dumpable = false;
    let null = mapping(None, 0x40000);
    let batch = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &[included, excluded, null],
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    // A corrupt hardware-visible link cannot redirect capture to foreign RAM.
    let view = batch.diagnostic_vm();
    let table_pages: Vec<_> = view.memory.diagnostic_tables().collect();
    assert_eq!(table_pages.len(), 4);
    let root = narf_memory::PhysAddr::new(view.root).kernel_mut_ptr::<u64>();
    // SAFETY: root is one of this batch's retained private table pages. Its
    // entries are restored before teardown, and no device owns this fixture.
    let original = unsafe { core::ptr::read_volatile(root) };
    // SAFETY: the same retained root page, before any GPU publication.
    unsafe { core::ptr::write_volatile(root, 0xdead_beef_f003) };
    let dump = capture(&batch, || true);
    // SAFETY: restore that owned entry before the walker tears it down.
    unsafe { core::ptr::write_volatile(root, original) };
    assert_eq!(&dump.bytes[..8], b"NARFCDMP");
    assert_eq!(word(&dump.bytes, 8), 4);
    assert_eq!(dump.bytes.len(), 0x27d3c0);
    assert_eq!(word(&dump.bytes, 72), 17);
    assert_eq!(word(&dump.bytes, 160), 0x1b4540);
    assert_eq!(word(&dump.bytes, 164), 0xc0e40);
    assert_eq!(word(&dump.bytes, 168), 0);
    let section = &dump.bytes[0x1b4540..];
    assert_eq!(&section[..8], b"NARFVMEM");
    assert_eq!(
        (word(section, 8), word(section, 12), word(section, 16)),
        (1, 64, 0x30380)
    );
    assert_eq!(
        (
            word(section, 20),
            word(section, 24),
            word(section, 28),
            word(section, 32)
        ),
        (4, 1, 1, 1)
    );
    let record = &section[64..];
    assert_eq!((word(record, 0), word(record, 4)), (37, 0x534e4150));
    assert_eq!((qword(record, 8), qword(record, 16)), (0x10000, 8192));
    assert_eq!(qword(record, 24), batch.space().root_phys());
    assert_eq!(
        (
            word(record, 32),
            word(record, 36),
            word(record, 40),
            word(record, 44)
        ),
        (4, 4, 2, 2)
    );
    for (index, phys) in table_pages.iter().enumerate() {
        let descriptor = &record[128 + index * 16..];
        assert_eq!(qword(descriptor, 0), *phys);
        assert_eq!(word(descriptor, 12), 4096);
        let absolute = word(descriptor, 8) as usize;
        assert_eq!(absolute, 0x1b4700 + index * 4096);
        if *phys == batch.space().root_phys() {
            assert_eq!(qword(&dump.bytes, absolute), 0xdead_beef_f003);
        } else {
            assert_eq!(
                qword(&dump.bytes, absolute),
                view.memory.read_entry(*phys, 0)
            );
        }
    }
    let ranges = &record[0x10180..];
    assert_eq!(
        (
            qword(ranges, 0),
            qword(ranges, 8),
            qword(ranges, 16),
            qword(ranges, 24)
        ),
        (0x10000, 8192, 4096, 12288)
    );
    assert_eq!(
        (
            word(ranges, 32),
            word(ranges, 36),
            word(ranges, 40),
            word(ranges, 44)
        ),
        (33, 2, 0x1c4900, 8192)
    );
    assert!(dump.bytes[0x1c4900..0x1c6900].iter().all(|b| *b == 0x6d));
    assert_eq!(qword(ranges, 64), 0x40000);
    assert_eq!(word(ranges, 64 + 32), 2);
    assert_eq!((word(ranges, 64 + 40), word(ranges, 64 + 44)), (0, 0));
    object.write(4096, &[0x22; 8192]).unwrap();
    let file = File {
        dump: dump.clone(),
        gate: OPEN,
        writable: false,
    };
    let mut bytes = [0; 17];
    assert_eq!(ready(file.read(0x1c48fe, &mut bytes)), Ok(17));
    assert_eq!(&bytes[2..], &[0x6d; 15]);
    gem.close(handle).unwrap();
    drop(object);
    drop(batch);
    assert_eq!(ready(file.read(0x27537e, &mut bytes)), Ok(2));
    assert_eq!(ready(file.read(0x275380, &mut bytes)), Ok(0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_vm_wire_owned_tables_corruption_and_immutable_reads
);

fn smoke_coredump_vm_limits_and_payload_prefix_are_explicit() -> TestResult {
    let gem = GemState::new();
    let (_, object) = object(&gem, 32768);
    object.write(0, &[0x47; 16384]).unwrap();
    let mappings: Vec<_> = (0..20)
        .map(|i| {
            let mut m = mapping(Some(object.clone()), 0x10000 + i * 0x200000);
            m.dumpable = i < 9;
            if i == 0 {
                m.length = 32768;
            }
            m
        })
        .collect();
    let batch = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &mappings,
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    let index = free_slot();
    let calls = Cell::new(0usize);
    Armed::reserve(index).unwrap().capture_with_vm(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        |_, _| None,
        |output, access| {
            for id in 0..4 {
                output.push(id, 1, &batch, access);
            }
            let before = calls.get();
            output.push(4, 1, &batch, access);
            assert_eq!(calls.get(), before, "omitted slot accessed sources");
            Some(5)
        },
        || {
            calls.set(calls.get() + 1);
            true
        },
    );
    let dump = snapshot(index).unwrap();
    assert!(clear(index, dump.generation));
    assert_eq!(word(&dump.bytes, 168), 29);
    let section = &dump.bytes[0x1b4540..];
    assert_eq!(
        (
            word(section, 24),
            word(section, 28),
            word(section, 32),
            word(section, 36)
        ),
        (5, 4, 0, 29)
    );
    for index in 0..4 {
        let record = &section[64 + index * 0x30380..];
        assert_eq!((word(record, 32), word(record, 36)), (23, 16));
        assert_eq!(
            (word(record, 40), word(record, 44), word(record, 52)),
            (9, 8, 28)
        );
        let ranges = &record[0x10180..];
        assert_eq!(qword(ranges, 8), 32768);
        assert_eq!((word(ranges, 32), word(ranges, 44)), (96, 16384));
        let offset = word(ranges, 40) as usize;
        assert!(dump.bytes[offset..offset + 16384]
            .iter()
            .all(|b| *b == 0x47));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_vm_limits_and_payload_prefix_are_explicit
);

fn smoke_coredump_vm_access_loss_zeros_current_payload_and_suppresses_later_jobs() -> TestResult {
    let gem = GemState::new();
    let (_, object) = object(&gem, 8192);
    object.write(0, &[0xa5; 8192]).unwrap();
    let mut m = mapping(Some(object), 0x10000);
    m.length = 8192;
    let batch =
        ResidentBatch::from_vm(GtPlatform::Battlemage, &[m], Some(0x10000), false, None).unwrap();
    let index = free_slot();
    let calls = Cell::new(0usize);
    Armed::reserve(index).unwrap().capture_with_vm(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        |_, _| None,
        |output, access| {
            for id in 0..2 {
                if !access() {
                    break;
                }
                output.push(id, 1, &batch, access);
            }
            Some(2)
        },
        || {
            let n = calls.get() + 1;
            calls.set(n);
            n < 12
        },
    );
    assert_eq!(calls.get(), 12);
    let dump = snapshot(index).unwrap();
    assert!(clear(index, dump.generation));
    assert_eq!(word(&dump.bytes, 168), 35);
    let section = &dump.bytes[0x1b4540..];
    assert_eq!(
        (word(section, 24), word(section, 28), word(section, 32)),
        (2, 1, 0)
    );
    let record = &section[64..];
    assert_eq!(
        (word(record, 36), word(record, 44), word(record, 52)),
        (4, 1, 34)
    );
    let range = &record[0x10180..];
    assert_eq!(
        (word(range, 32), word(range, 40), word(range, 44)),
        (128, 0, 0)
    );
    assert!(record[0x10380..0x10380 + 8192].iter().all(|b| *b == 0));
    assert!(section[64 + 0x30380..].iter().all(|b| *b == 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_vm_access_loss_zeros_current_payload_and_suppresses_later_jobs
);

fn smoke_coredump_vm_userptr_pins_and_vram_bar_refusal() -> TestResult {
    let frame = narf_memory::frame::alloc_frame().unwrap();
    // SAFETY: this fixture owns the RAM until the retain completes.
    unsafe { core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0x73, 4096) };
    // SAFETY: the allocation remains owned until after this retain completes.
    let pin = unsafe { narf_memory::address_space::UserPagePin::retain_ram(frame.start_address()) };
    let userptr = crate::intel_gpu_gem::GemObject::from_user_pins(alloc::vec![pin], 9).unwrap();
    narf_memory::frame::free_frame(frame);
    let weak = Arc::downgrade(&userptr);
    let batch = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &[mapping(Some(userptr.clone()), 0x10000)],
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    drop(userptr);
    let dump = capture(&batch, || true);
    let range = &dump.bytes[0x1c4700..];
    assert_eq!((word(range, 32), word(range, 44)), (36, 4096));
    let data = word(range, 40) as usize;
    assert!(dump.bytes[data..data + 4096].iter().all(|b| *b == 0x73));
    drop(batch);
    assert!(weak.upgrade().is_none());

    let gem = GemState::new();
    let (_, wb) = object(&gem, 4096);
    wb.write(0, &[0x29; 4096]).unwrap();
    let mut noncoherent = mapping(Some(wb), 0x10000);
    noncoherent.pat = 1; // Xe-LPG WT, not coherent with a WB CPU alias.
    let batch = ResidentBatch::from_vm(
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        &[noncoherent],
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    let mut report = report();
    report.capture.platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let index = free_slot();
    Armed::reserve(index).unwrap().capture_with_vm(
        report,
        None,
        None::<&Backing>,
        None::<&Backing>,
        |_, _| None,
        |output, access| {
            output.push(0, 1, &batch, access);
            Some(1)
        },
        || true,
    );
    let dump = snapshot(index).unwrap();
    assert!(clear(index, dump.generation));
    assert_eq!(word(&dump.bytes, 168), 32);
    let range = &dump.bytes[0x1c4700..];
    assert_eq!(
        (word(range, 32), word(range, 40), word(range, 44)),
        (128, 0, 0)
    );
    assert!(dump.bytes[0x1c4900..0x1c5900].iter().all(|b| *b == 0));
    drop(batch);

    // A real private VRAM reservation over owned fixture pages. Its raw BAR
    // bytes remain untouched: a lost GT cannot grant the live epoch proof.
    let aperture = narf_memory::frame::alloc_pages_on(0, 4).unwrap();
    // SAFETY: this fixture exclusively owns all sixteen aperture pages.
    unsafe { core::ptr::write_bytes(aperture.start_address().kernel_mut_ptr::<u8>(), 0x5c, 65536) };
    let region = narf_bus::MmioRegion {
        phys: aperture.start_address(),
        virt: aperture.start_address().kernel_ptr::<u8>() as u64,
        len: 65536,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = crate::intel_gpu_vram::VramLayout {
        tile_size: 65536,
        tile_offset: 0,
        usable: 65536,
    };
    // SAFETY: the fixture owns the full aperture through pool destruction.
    let pool = unsafe { crate::intel_gpu_vram::Vram::new(region, layout) }.unwrap();
    let gem = GemState::new();
    let pending = gem.prepare_vram(4096, None, &pool).unwrap();
    let object = pending.object();
    let mut output = [0xa5; 4096];
    assert!(!object.diagnostic_read(0, &mut output, &mut || panic!(
        "VRAM must refuse before BAR access"
    )));
    let batch = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &[mapping(Some(object), 0x10000)],
        Some(0x10000),
        false,
        None,
    )
    .unwrap();
    let dump = capture(&batch, || true);
    assert_eq!(word(&dump.bytes, 168), 128);
    let range = &dump.bytes[0x1c4700..];
    assert_eq!(
        (word(range, 32), word(range, 40), word(range, 44)),
        (136, 0, 0)
    );
    assert!(dump.bytes[0x1c4900..0x1c5900].iter().all(|b| *b == 0));
    drop(batch);
    drop(pending);
    assert_eq!(pool.used(), 0);
    drop(pool);
    narf_memory::frame::free_pages(aperture, 4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_vm_userptr_pins_and_vram_bar_refusal
);
