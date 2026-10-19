//! GART, user GPUVM and isolation models over the GMC register fake.
use super::tests::{bar, fixture_sized, fixture_with, run, Fake, VRAM};
use super::*;
use crate::amdgpu_uapi as uapi;
use crate::amdgpu_vm::{Geometry as Layout, Level};
use alloc::{sync::Arc, vec::Vec};
use core::{
    future::Future,
    ops::Range,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const GART_BYTES: u64 = (GART_SIZE / 4096) * 8 + 4096;
const ADDRESS: u64 = 0x0000_ffff_ffff_f000;
const RW: u32 = uapi::AMDGPU_VM_PAGE_READABLE | uapi::AMDGPU_VM_PAGE_WRITEABLE;
const GFX_BASE: u64 = 0x10000;
const MM_BASE: u64 = 0x20000;
/// GPU physical address of pool byte `mc` (fb 0x8_0000_0000, offset 4 GiB).
fn physical(mc: u64) -> u64 {
    mc - 0x8_0000_0000 + 0x1_0000_0000
}
fn reg(engine: &Engine<Fake>, base: u64, reg: u32) -> u32 {
    engine
        .io
        .registers
        .get(&(base + u64::from(reg) * 4))
        .copied()
        .unwrap_or(0)
}
fn reg64(engine: &Engine<Fake>, base: u64, r: u32) -> u64 {
    u64::from(reg(engine, base, r)) | u64::from(reg(engine, base, r + 1)) << 32
}
fn read64(engine: &Engine<Fake>, physical: u64) -> u64 {
    u64::from(engine.io.word(bar(physical))) | u64::from(engine.io.word(bar(physical) + 4)) << 32
}
/// Both hubs must agree on a context's table base.
fn table_base(engine: &Engine<Fake>, vmid: u32) -> Option<u64> {
    let gfx = reg64(engine, GFX_BASE, GFX.pt_base + 2 * vmid);
    (gfx == reg64(engine, MM_BASE, MM.pt_base + 2 * vmid)).then_some(gfx)
}
/// Hardware-style four-level walk of a user context; returns the leaf PTE.
fn translate(engine: &Engine<Fake>, vmid: u32, va: u64) -> Option<u64> {
    let mut entry = table_base(engine, vmid)?;
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0, Level::Ptb] {
        if entry & 1 == 0 {
            return None;
        }
        let index = Layout::GMC11.index_at(va, level);
        entry = read64(engine, (entry & ADDRESS) + index * 8);
    }
    (entry & 1 != 0).then_some(entry)
}
fn walk(engine: &Engine<Fake>, table: u64, depth: u32, out: &mut (Vec<u64>, Vec<u64>)) {
    out.1.push(table);
    for index in 0..512 {
        let entry = read64(engine, table + index * 8);
        if entry & 1 == 0 {
            continue;
        }
        if depth == 3 {
            out.0.push(entry);
        } else {
            walk(engine, entry & ADDRESS, depth + 1, out);
        }
    }
}
/// Every valid leaf reachable from a context, and every table page walked.
fn reachable(engine: &Engine<Fake>, vmid: u32) -> (Vec<u64>, Vec<u64>) {
    let mut out = (Vec::new(), Vec::new());
    if let Some(root) = table_base(engine, vmid).filter(|e| e & 1 != 0) {
        walk(engine, root & ADDRESS, 0, &mut out);
    }
    out
}
/// Last value software stored to the MMHUB engine-17 semaphore.
fn semaphore(engine: &Engine<Fake>) -> Option<u32> {
    let address = MM_BASE + u64::from(MM.inv_sem) * 4;
    engine
        .io
        .writes
        .iter()
        .rev()
        .find(|(a, _)| *a == address)
        .map(|(_, v)| *v)
}
fn inside(address: u64, ranges: &[Range<u64>]) -> bool {
    ranges.iter().any(|r| r.contains(&address))
}
fn ready(extra: u64) -> (Pool, Engine<Fake>) {
    ready_with(extra, &[])
}
fn ready_with(extra: u64, protected: &[Range<u64>]) -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture_with(BYTES + GART_BYTES + extra, protected);
    engine.prepare_gart().unwrap();
    run(engine.initialize()).unwrap();
    run(engine.enable_gart()).unwrap();
    (pool, engine)
}
fn dma(pages: usize) -> narf_io::DmaBuffer {
    narf_io::alloc_coherent(pages * 4096, narf_lib::id::DomainId::DRIVER_0).unwrap()
}
fn system(pages: usize) -> Arc<Buffer> {
    Arc::new(Buffer::system(dma(pages), false).unwrap())
}
fn pending<T>(future: impl Future<Output = T>) -> bool {
    let mut future = core::pin::pin!(future);
    future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
}
fn request(va: u64, offset: u64, size: u64, flags: u32) -> Mapping {
    Mapping {
        va,
        offset,
        size,
        flags,
    }
}

fn gart_navi22_replaces_vmid0_table_and_arms_user_contexts() -> TestResult {
    let (_pool, engine) = ready(0);
    let Some(info) = engine.gart.as_ref().and_then(gart::Gart::info) else {
        return TestResult::Fail("GART not enabled");
    };
    let aperture = engine.aperture.unwrap();
    let table = physical(info.table);
    let root = table + (GART_SIZE / 4096) * 8;
    if info.start != aperture.start
        || info.size != 512 << 20
        || info.table != VRAM + BYTES
        || read64(&engine, table) != physical(VRAM + 8192) | 0x61
        || read64(&engine, table + 8) != physical(VRAM + 12288) | 0x61
        || read64(&engine, table + 16) != 0
    {
        return TestResult::Fail("GART placement or retained boot pages");
    }
    for (base, r) in [(GFX_BASE, GFX), (MM_BASE, MM)] {
        if reg64(&engine, base, r.pt_base) != table | 1
            || reg64(&engine, base, r.pt_start) != info.start >> 12
            || reg64(&engine, base, r.pt_end) != (info.start + (512 << 20) - 1) >> 12
            || reg(&engine, base, r.inv_req) != 0xf8_0001
            || reg(&engine, base, r.ctx) != 0x55_5401
        {
            return TestResult::Fail("VMID0 GART aperture registers");
        }
        for vmid in 1..16 {
            // gfxhub_v2_1/mmhub_v2_0_setup_vmid_config golden values.
            if reg(&engine, base, r.ctx + vmid) != 0x55_5407
                || reg64(&engine, base, r.pt_base + 2 * vmid) != root | 1
                || reg64(&engine, base, r.pt_start + 2 * vmid) != 0
                || reg(&engine, base, r.pt_end + 2 * vmid) != 0xffff_ffff
                || reg(&engine, base, r.pt_end + 2 * vmid + 1) != 0xf
            {
                return TestResult::Fail("user context configuration");
            }
        }
    }
    if engine.runtime != Runtime::Idle || (1..16).any(|v| translate(&engine, v, 0x1000).is_some()) {
        return TestResult::Fail("unbound context translates");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gart_navi22_replaces_vmid0_table_and_arms_user_contexts
);

fn gart_navi22_binds_snooped_system_pages_and_unbinds_after_ack() -> TestResult {
    let (_pool, mut engine) = ready(0);
    let info = engine.gart.as_ref().and_then(gart::Gart::info).unwrap();
    let table = physical(info.table);
    let pages = dma(2);
    let address = pages.dma_addr().raw();
    let gtt = run(engine.bind_gtt(pages, true)).unwrap();
    // VALID|SYSTEM|SNOOPED|EXECUTABLE|READABLE|WRITEABLE, MTYPE_UC (50:48).
    let flags = 0x77 | 3 << 48;
    if gtt.address() != info.start + 512 * 4096
        || gtt.size() != 8192
        || read64(&engine, table + 512 * 8) != address | flags
        || read64(&engine, table + 513 * 8) != (address + 4096) | flags
    {
        return TestResult::Fail("GTT PTE encoding or placement");
    }
    let stores = engine.io.stores;
    let pages = run(engine.unbind_gtt(gtt)).unwrap();
    if pages.dma_addr().raw() != address
        || read64(&engine, table + 512 * 8) != 0
        || engine.io.stores != stores + 2
        || semaphore(&engine) != Some(0)
    {
        return TestResult::Fail("GTT unbind did not clear/invalidate");
    }
    let gtt = run(engine.bind_gtt(pages, false)).unwrap();
    if gtt.address() != info.start + 512 * 4096
        || read64(&engine, table + 512 * 8) != address | 0x37 | 3 << 48
    {
        return TestResult::Fail("read-only GTT or freed range reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gart_navi22_binds_snooped_system_pages_and_unbinds_after_ack
);

fn gart_navi22_timeout_cancel_and_order_fail_closed() -> TestResult {
    // GART before hubs, bind before GART, and foreign handles are refused.
    let (_pool, mut early) = fixture_sized(BYTES + GART_BYTES);
    early.prepare_gart().unwrap();
    if run(early.enable_gart()) != Err(Error::Busy) || early.prepare_gart() != Err(Error::Busy) {
        return TestResult::Fail("GART enabled before memory hubs");
    }
    run(early.initialize()).unwrap();
    if run(early.bind_gtt(dma(1), true)).err() != Some(Error::Invalid) {
        return TestResult::Fail("GTT bound without GART");
    }
    let (_pool, mut engine) = ready(0);
    engine.io.stall = Some(MM_BASE + u64::from(MM.inv_ack) * 4);
    let writes = engine.io.writes.len();
    let released = |engine: &Engine<Fake>| {
        let address = MM_BASE + u64::from(MM.inv_sem) * 4;
        engine.io.writes[writes..]
            .iter()
            .any(|(a, _)| *a == address)
    };
    if run(engine.bind_gtt(dma(1), true)).err() != Some(Error::Timeout)
        || engine.runtime != Runtime::Failed
        || released(&engine)
    {
        return TestResult::Fail("unbounded or replayable GTT invalidation");
    }
    engine.io.stall = None;
    if run(engine.bind_gtt(dma(1), true)).err() != Some(Error::Busy)
        || run(engine.create_vm()).err() != Some(Error::Busy)
    {
        return TestResult::Fail("failed GMC accepted new work");
    }
    let (_pool, mut engine) = ready(0);
    engine.io.stall = Some(GFX_BASE + u64::from(GFX.inv_ack) * 4);
    if !pending(engine.bind_gtt(dma(1), true)) || engine.runtime != Runtime::Busy {
        return TestResult::Fail("stalled bind completed");
    }
    engine.io.stall = None;
    if run(engine.create_vm()).err() != Some(Error::Busy) {
        return TestResult::Fail("cancelled bind released the latch");
    }
    let (_pool, mut other) = ready(0);
    let foreign = run(other.bind_gtt(dma(1), true)).unwrap();
    let (_pool, mut engine) = ready(0);
    let writes = engine.io.writes.len();
    if run(engine.unbind_gtt(foreign)).err() != Some(Error::Invalid)
        || engine.io.writes.len() != writes
    {
        return TestResult::Fail("foreign GTT handle accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gart_navi22_timeout_cancel_and_order_fail_closed
);

fn vm_navi22_encodes_linux_pde_pte_and_invalidates_vmid() -> TestResult {
    let (_pool, mut engine) = ready(1 << 20);
    let geometry = engine.geometry.unwrap();
    let vm = run(engine.create_vm()).unwrap();
    let info = engine.vm_info(&vm).unwrap();
    if vm.vmid() != 1
        || table_base(&engine, 1) != Some(info.page_table_base)
        || info.page_table_base & 0xfff != 1
        || reg(&engine, GFX_BASE, GFX.inv_req) != 0xf8_0002
        || reg(&engine, MM_BASE, MM.inv_req) != 0xf8_0002
    {
        return TestResult::Fail("VMID bind or per-VMID invalidation request");
    }
    let vram = Arc::new(engine.allocate_vram(8192, false).unwrap());
    let pa = vram.device_address(geometry);
    // Straddle a 1 GiB (PDB1 entry) boundary: two PDB0s and two PTBs.
    let va = 0x7f_3fff_f000;
    run(engine.map(&vm, request(va, 0, 8192, RW), vram.clone())).unwrap();
    let sys = system(1);
    let address = sys.system_pages().unwrap().dma_addr().raw();
    let exec = RW | uapi::AMDGPU_VM_PAGE_EXECUTABLE | uapi::AMDGPU_VM_MTYPE_UC;
    run(engine.map(&vm, request(0x10_0000, 0, 4096, exec), sys.clone())).unwrap();
    let readonly = Arc::new(engine.allocate_vram(4096, true).unwrap());
    let flags = RW | uapi::AMDGPU_VM_PAGE_NOALLOC | uapi::AMDGPU_VM_MTYPE_WC;
    run(engine.map(&vm, request(0x20_0000, 0, 4096, flags), readonly.clone())).unwrap();
    // gmc_v10_0_get_vm_pte: NC VRAM RW; UC snooped system RWX; read-only
    // BO keeps R only, WC, NOALLOC (bit 58).
    if translate(&engine, 1, va) != Some(pa | 0x61)
        || translate(&engine, 1, va + 4096) != Some((pa + 4096) | 0x61)
        || translate(&engine, 1, 0x10_0000) != Some(address | 0x77 | 3 << 48)
        || translate(&engine, 1, 0x20_0000).map(|e| e & !ADDRESS) != Some(0x21 | 1 << 48 | 1 << 58)
        || translate(&engine, 1, va + 8192).is_some()
    {
        return TestResult::Fail("GMC10 PTE encoding or four-level walk");
    }
    // Root, PDB1[0], 2 PDB0 + 2 PTB for the straddle, PDB0[0], 2 low PTBs.
    let tables = engine.vm_info(&vm).unwrap().tables;
    if tables != reachable(&engine, 1).1.len() || tables != 9 {
        return TestResult::Fail("page-table accounting");
    }
    let prt = uapi::AMDGPU_VM_PAGE_PRT;
    for (mapping, error) in [
        (request(va + 4096, 0, 4096, RW), Error::Invalid), // overlap
        (request(0x40_0000, 4096, 8192, RW), Error::Invalid), // past buffer
        (request(0x40_0800, 0, 4096, RW), Error::Invalid), // misaligned
        (request(1 << 48, 0, 4096, RW), Error::Invalid),   // beyond max_pfn
        (request(0x40_0000, 0, 4096, prt), Error::Invalid), // PRT unsupported
    ] {
        if run(engine.map(&vm, mapping, vram.clone())) != Err(error) {
            return TestResult::Fail("invalid map request accepted");
        }
    }
    let writes = engine.io.writes.len();
    run(engine.unmap(&vm, va)).unwrap();
    if translate(&engine, 1, va).is_some()
        || Arc::strong_count(&vram) != 1
        || engine.io.writes.len() <= writes
        || reg(&engine, MM_BASE, MM.inv_req) != 0xf8_0002
        || run(engine.unmap(&vm, va)) != Err(Error::Invalid)
    {
        return TestResult::Fail("unmap released before/without invalidation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_encodes_linux_pde_pte_and_invalidates_vmid
);

fn vm_navi22_clients_cannot_reach_each_other_or_firmware() -> TestResult {
    // A retained firmware/TMR hole inside the pool's aperture.
    let tmr = 0x20_0000..0x30_0000;
    let (_pool, mut engine) = ready_with(5 << 20, core::slice::from_ref(&tmr));
    let geometry = engine.geometry.unwrap();
    let protected = physical(VRAM + tmr.start)..physical(VRAM + tmr.end);
    let a = run(engine.create_vm()).unwrap();
    let b = run(engine.create_vm()).unwrap();
    let mut owned: [Vec<Range<u64>>; 2] = [Vec::new(), Vec::new()];
    let mut keep = Vec::new();
    for (index, vm) in [&a, &b].into_iter().enumerate() {
        for (va, pages) in [
            (0x10_0000, 64),
            (0x80_0000_0000 - 0x1000, 1),
            (0x1_0000_0000, 2),
        ] {
            let buffer = Arc::new(engine.allocate_vram(pages * 4096, false).unwrap());
            let start = buffer.device_address(geometry);
            owned[index].push(start..start + pages * 4096);
            run(engine.map(vm, request(va, 0, pages * 4096, RW), buffer.clone())).unwrap();
            keep.push(buffer);
        }
        let sys = system(1);
        let address = sys.system_pages().unwrap().dma_addr().raw();
        owned[index].push(address..address + 4096);
        let va = 0x4000_0000 + index as u64 * 0x20_0000;
        run(engine.map(vm, request(va, 0, 4096, RW), sys.clone())).unwrap();
        keep.push(sys);
    }
    let gart = engine.gart.as_ref().and_then(gart::Gart::info).unwrap();
    let kernel = [
        physical(VRAM)..physical(VRAM + BYTES),
        physical(gart.table)..physical(gart.table + GART_BYTES),
    ];
    let walks = [a.vmid(), b.vmid()].map(|v| reachable(&engine, u32::from(v)));
    for index in 0..2 {
        let (leaves, tables) = &walks[index];
        let (_, other_tables) = &walks[1 - index];
        if leaves.len() != 68 {
            return TestResult::Fail("unexpected leaf count");
        }
        for leaf in leaves {
            let address = leaf & ADDRESS;
            if !inside(address, &owned[index])
                || inside(address, &owned[1 - index])
                || protected.contains(&address)
                || inside(address, &kernel)
                || tables
                    .iter()
                    .chain(other_tables)
                    .any(|t| (*t..*t + 4096).contains(&address))
            {
                return TestResult::Fail("client PTE reaches memory it does not own");
            }
        }
        if tables
            .iter()
            .any(|t| protected.contains(t) || other_tables.contains(t) || inside(*t, &kernel))
        {
            return TestResult::Fail("page tables placed in shared/protected memory");
        }
    }
    // Only A maps this VA; B must fault to the default page instead.
    if translate(&engine, u32::from(b.vmid()), 0x4000_0000).is_some()
        || translate(&engine, u32::from(a.vmid()), 0x4000_0000).is_none()
    {
        return TestResult::Fail("VA leaked across VMIDs");
    }
    // Another GPU owner's VRAM cannot be mapped here.
    let (_other_pool, mut other) = ready(1 << 20);
    let foreign = Arc::new(other.allocate_vram(4096, false).unwrap());
    if run(engine.map(&a, request(0x9000_0000, 0, 4096, RW), foreign)) != Err(Error::Invalid) {
        return TestResult::Fail("foreign VRAM mapped");
    }
    // Destroying A moves its context to the empty root and releases only
    // A's buffers; B still translates everything it owns.
    let vmid = u32::from(a.vmid());
    run(engine.destroy_vm(a)).unwrap();
    if !reachable(&engine, vmid).0.is_empty()
        || table_base(&engine, vmid) != table_base(&engine, 15)
        || reachable(&engine, u32::from(b.vmid())).0.len() != 68
        || keep[..4].iter().any(|b| Arc::strong_count(b) != 1)
        || keep[4..].iter().any(|b| Arc::strong_count(b) != 2)
    {
        return TestResult::Fail("destroy left translations or retained buffers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_clients_cannot_reach_each_other_or_firmware
);

fn vm_navi22_failures_retain_buffers_and_tables() -> TestResult {
    let mapping = request(0x1000, 0, 4096, RW);
    let (_pool, mut engine) = ready(1 << 20);
    let vm = run(engine.create_vm()).unwrap();
    let buffer = Arc::new(engine.allocate_vram(4096, false).unwrap());
    engine.io.stall = Some(MM_BASE + u64::from(MM.inv_ack) * 4);
    if run(engine.map(&vm, mapping, buffer.clone())) != Err(Error::Timeout)
        || engine.runtime != Runtime::Failed
        || run(engine.unmap(&vm, 0x1000)) != Err(Error::Busy)
        || run(engine.destroy_vm(vm)) != Err(Error::Busy)
    {
        return TestResult::Fail("timed-out map replayed or released");
    }
    drop(engine);
    if Arc::strong_count(&buffer) != 2 {
        return TestResult::Fail("possibly mapped buffer freed");
    }
    // Revocation before the first table store: nothing written, retained.
    let (_pool, mut engine) = ready(1 << 20);
    let vm = run(engine.create_vm()).unwrap();
    let buffer = Arc::new(engine.allocate_vram(4096, false).unwrap());
    let stores = engine.io.stores;
    engine.authority.revoke();
    if run(engine.map(&vm, mapping, buffer.clone())) != Err(Error::Revoked)
        || engine.io.stores != stores
        || Arc::strong_count(&buffer) != 2
    {
        return TestResult::Fail("revoked map wrote tables or dropped buffer");
    }
    // A cancelled unmap keeps the buffer and the latch.
    let (_pool, mut engine) = ready(1 << 20);
    let vm = run(engine.create_vm()).unwrap();
    let buffer = Arc::new(engine.allocate_vram(4096, false).unwrap());
    run(engine.map(&vm, mapping, buffer.clone())).unwrap();
    engine.io.stall = Some(GFX_BASE + u64::from(GFX.inv_ack) * 4);
    if !pending(engine.unmap(&vm, 0x1000)) || Arc::strong_count(&buffer) != 2 {
        return TestResult::Fail("cancelled unmap released buffer");
    }
    engine.io.stall = None;
    if run(engine.unmap(&vm, 0x1000)) != Err(Error::Busy) {
        return TestResult::Fail("cancelled unmap replayed");
    }
    // Fifteen user contexts, then Exhausted; a destroyed VMID is reusable.
    let (_pool, mut engine) = ready(1 << 20);
    let mut vms = Vec::new();
    for _ in 1..16 {
        vms.push(run(engine.create_vm()).unwrap());
    }
    if run(engine.create_vm()).err() != Some(Error::Exhausted)
        || (1..16).any(|v| !vms.iter().any(|vm| vm.vmid() == v))
    {
        return TestResult::Fail("VMID allocation");
    }
    let last = vms.pop().unwrap();
    let (vmid, generation) = (last.vmid(), last.generation());
    run(engine.destroy_vm(last)).unwrap();
    let reused = run(engine.create_vm()).unwrap();
    if reused.vmid() != vmid || reused.generation() == generation {
        return TestResult::Fail("freed VMID not reusable with a new generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_failures_retain_buffers_and_tables
);

fn vm_navi22_faults_attribute_to_owning_vm() -> TestResult {
    let (_pool, mut engine) = ready(1 << 20);
    let vm = run(engine.create_vm()).unwrap();
    let status = 0x0010_0000 | 0x1b << 9 | 0x40000 | 0x100; // VMID1, CID, RW, MAPPING
    engine
        .io
        .registers
        .insert(GFX_BASE + u64::from(GFX.fault_status) * 4, status);
    let address = 0x7f_1234_5000u64;
    let iv = [(address >> 12) as u32, (address >> 44) as u32 | 0x20];
    let Some(fault) = Fault::decode(Fault::CLIENT_UTCL2, 0, 1, iv) else {
        return TestResult::Fail("UTCL2 IV rejected");
    };
    let word = u32::from(Fault::CLIENT_UTCL2) | 1 << 24;
    let iv = crate::amdgpu_ih_navi22::Iv::decode([word, 0, 0, 0, iv[0], iv[1], 0, 0]);
    if Fault::from_iv(&iv) != Some(fault) {
        return TestResult::Fail("IH IV adapter");
    }
    let iv = [iv.src_data[0], iv.src_data[1]];
    if fault.hub != Hub::Gfx || fault.address != address || !fault.write || fault.retry {
        return TestResult::Fail("IV decode differs from gmc_v10_0_process_interrupt");
    }
    let cntl = reg(&engine, GFX_BASE, GFX.fault_cntl);
    let owner = FaultOwner::Vm {
        vmid: 1,
        generation: vm.generation(),
    };
    if engine.handle_fault(fault) != Ok(owner) || reg(&engine, GFX_BASE, GFX.fault_cntl) != cntl | 1
    {
        return TestResult::Fail("fault not attributed or status not re-armed");
    }
    let _ = engine.handle_fault(fault);
    let info = engine.vm_fault(&vm).unwrap();
    if info.address != address || info.status != status || info.count != 2 || info.hub != Hub::Gfx {
        return TestResult::Fail("fault cache");
    }
    let mm = Fault::decode(Fault::CLIENT_VMC, 0, 0, [0, 0x80]).unwrap();
    let unbound = Fault::decode(Fault::CLIENT_VMC, 0, 9, [0, 0]).unwrap();
    if mm.hub != Hub::Mm
        || !mm.retry
        || engine.handle_fault(mm) != Ok(FaultOwner::Kernel)
        || engine.handle_fault(unbound) != Ok(FaultOwner::Unowned)
        || Fault::decode(0x0a, 0, 1, iv).is_some()
        || Fault::decode(Fault::CLIENT_UTCL2, 1, 1, iv).is_some()
        || Fault::decode(Fault::CLIENT_UTCL2, 0, 16, iv).is_some()
    {
        return TestResult::Fail("hub/owner attribution");
    }
    // Fault interrupts stay off until an IH owner enables them, then toggle
    // every context mask and the per-client L2 enables on both hubs.
    engine.set_fault_interrupts(true).unwrap();
    for (base, r) in [(GFX_BASE, GFX), (MM_BASE, MM)] {
        if (0..16).any(|c| reg(&engine, base, r.ctx + c) & 0x2a_aa00 != 0x2a_aa00)
            || reg(&engine, base, r.fault_cntl) & 0x3fff_e000 != 0x3fff_e000
        {
            return TestResult::Fail("fault interrupt enable");
        }
    }
    engine.set_fault_interrupts(false).unwrap();
    if (0..16).any(|c| reg(&engine, GFX_BASE, GFX.ctx + c) & 0x2a_aa00 != 0)
        || reg(&engine, MM_BASE, MM.ctx + 1) != 0x55_5407
    {
        return TestResult::Fail("fault interrupt disable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_faults_attribute_to_owning_vm
);

fn vm_navi22_pte_flags_match_linux_composition() -> TestResult {
    use crate::amdgpu_vm::{PTE_EXECUTABLE as X, PTE_READABLE as R, PTE_WRITEABLE as W};
    let nc = |f: u64| f & !(7 << 48);
    for (system, read_only, flags, want) in [
        (false, false, 0, 1), // no access bits requested
        (false, false, RW, 1 | R | W),
        (true, false, RW, 7 | R | W),
        (false, true, RW, 1 | R),
        (false, false, uapi::AMDGPU_VM_PAGE_EXECUTABLE, 1 | X),
    ] {
        let uncached = vm::pte_flags(system, read_only, true, flags);
        if vm::pte_flags(system, read_only, false, flags) != want
            || nc(uncached) != want
            || uncached >> 48 & 7 != 3
        {
            return TestResult::Fail("PTE flag composition");
        }
    }
    if vm::pte_flags(false, false, false, RW | uapi::AMDGPU_VM_MTYPE_CC) >> 48 != 2
        || vm::pte_flags(false, false, false, RW | uapi::AMDGPU_VM_MTYPE_RW) >> 48 != 0
        || gart::gtt_flags(true) != 0x77 | 3 << 48
    {
        return TestResult::Fail("MTYPE selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_pte_flags_match_linux_composition
);

fn vm_navi22_client_vmids_are_lent_and_faults_charge_the_pasid() -> TestResult {
    let (_pool, mut engine) = ready(1 << 20);
    // Lent: VMIDs 1..first_kfd_vmid, once; the owner's own VMs skip them.
    let lent = match engine.reserve_client_vmids() {
        Ok(lent) => lent,
        Err(_) => return TestResult::Fail("client VMIDs not lent"),
    };
    if lent.range() != (1, FIRST_KFD_VMID - 1)
        || lent.owner() != engine.token
        || engine.reserve_client_vmids().err() != Some(Error::Busy)
    {
        return TestResult::Fail("lent range or double lend");
    }
    let own = run(engine.create_vm()).unwrap();
    if own.vmid() < FIRST_KFD_VMID {
        return TestResult::Fail("owner VM took a lent client VMID");
    }
    // A UTCL2 fault on lent VMID 3 whose IV names an allocated PASID (the
    // job's LUT write) is cached for that PASID, as
    // amdgpu_vm_update_fault_cache, and reaches the space's GPUVM_FAULT.
    let space = crate::amdgpu_vm::VmState::with_geometry(crate::amdgpu_vm::Geometry::GMC11);
    let Some(pasid) = space.pasid() else {
        return TestResult::Fail("no PASID");
    };
    let status = 0x0010_0000 | 0x1b << 9 | 3 << 4 | 0x100; // CID, VMID3, MAPPING
    engine
        .io
        .registers
        .insert(GFX_BASE + u64::from(GFX.fault_status) * 4, status);
    let address = 0x7f_4321_0000u64;
    let data = [(address >> 12) as u32, (address >> 44) as u32];
    let word = u32::from(Fault::CLIENT_UTCL2) | 3 << 24;
    let iv =
        crate::amdgpu_ih_navi22::Iv::decode([word, 0, 0, u32::from(pasid), data[0], data[1], 0, 0]);
    let Some(fault) = Fault::from_iv(&iv) else {
        return TestResult::Fail("UTCL2 IV rejected");
    };
    let cntl = reg(&engine, GFX_BASE, GFX.fault_cntl);
    if fault.pasid != pasid
        || engine.handle_fault(fault) != Ok(FaultOwner::Client { vmid: 3, pasid })
        || reg(&engine, GFX_BASE, GFX.fault_cntl) != cntl | 1
    {
        return TestResult::Fail("lent-VMID fault not charged to the IV's PASID");
    }
    let info = space.fault();
    if info.addr != address || info.status != status || info.vmhub != 0 {
        return TestResult::Fail("GPUVM_FAULT cache");
    }
    // MMHUB faults are charged with vmhub MM0; a zero status (a follow-on
    // fault of the burst) does not replace a useful one.
    engine
        .io
        .registers
        .insert(MM_BASE + u64::from(MM.fault_status) * 4, 0x55);
    let mm = Fault {
        pasid,
        ..Fault::decode(Fault::CLIENT_VMC, 0, 5, [0x10, 0]).unwrap()
    };
    let _ = engine.handle_fault(mm);
    let after = space.fault();
    engine
        .io
        .registers
        .insert(MM_BASE + u64::from(MM.fault_status) * 4, 0);
    let _ = engine.handle_fault(mm);
    if after.vmhub != 1 || after.status != 0x55 || space.fault() != after {
        return TestResult::Fail("MMHUB attribution or zero-status replacement");
    }
    // No PASID mapped yet (the LUT still reads 0): nothing is charged.
    let unmapped = Fault { pasid: 0, ..mm };
    engine
        .io
        .registers
        .insert(MM_BASE + u64::from(MM.fault_status) * 4, 0x66);
    if engine.handle_fault(unmapped) != Ok(FaultOwner::Client { vmid: 5, pasid: 0 })
        || space.fault() != after
    {
        return TestResult::Fail("fault without a PASID charged");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    vm_navi22_client_vmids_are_lent_and_faults_charge_the_pasid
);

fn rdna2_gart_and_client_gpuvm_use_resolved_hubs_and_isolate_clients() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        for &mmhub in crate::amdgpu_rdna2::GMC_MMHUB_VERSIONS {
            let (_pool, mut engine) = fixture_sized(BYTES + GART_BYTES + (1 << 20));
            let gpu = super::tests::rdna2_gpu(profile, profile.pci_ids[0], mmhub);
            engine.layout = super::Layout::resolve_rdna2(&gpu).unwrap();
            engine.prepare_gart().unwrap();
            run(engine.initialize()).unwrap();
            let info = run(engine.enable_gart()).unwrap();
            if engine.state != State::Ready
                || engine.runtime != Runtime::Idle
                || info.size != GART_SIZE
                || semaphore(&engine) != Some(0)
            {
                return TestResult::Fail("RDNA2 GART setup or MMHUB invalidation failed");
            }
            let a = run(engine.create_vm()).unwrap();
            let b = run(engine.create_vm()).unwrap();
            let va = 0x7f_3fff_f000; // straddle a 1 GiB page-directory boundary
            let ba = Arc::new(engine.allocate_vram(8192, false).unwrap());
            let bb = Arc::new(engine.allocate_vram(8192, false).unwrap());
            let geometry = engine.geometry.unwrap();
            let pa = ba.device_address(geometry);
            let pb = bb.device_address(geometry);
            run(engine.map(&a, request(va, 0, 8192, RW), ba.clone())).unwrap();
            run(engine.map(&b, request(va, 0, 8192, RW), bb.clone())).unwrap();
            for offset in [0, 4096] {
                if pa == pb
                    || translate(&engine, u32::from(a.vmid()), va + offset)
                        != Some((pa + offset) | 0x61)
                    || translate(&engine, u32::from(b.vmid()), va + offset)
                        != Some((pb + offset) | 0x61)
                {
                    return TestResult::Fail(
                        "RDNA2 clients share translations or have invalid PTEs",
                    );
                }
            }
            if translate(&engine, u32::from(a.vmid()), va + 8192).is_some()
                || translate(&engine, u32::from(b.vmid()), va + 8192).is_some()
            {
                return TestResult::Fail("RDNA2 GPUVM exposed an unmapped page");
            }
            run(engine.unmap(&a, va)).unwrap();
            if translate(&engine, u32::from(a.vmid()), va).is_some()
                || translate(&engine, u32::from(b.vmid()), va) != Some(pb | 0x61)
                || reg(&engine, GFX_BASE, GFX.inv_req) != 0xf8_0000 | (1 << a.vmid())
                || reg(&engine, MM_BASE, MM.inv_req) != 0xf8_0000 | (1 << a.vmid())
            {
                return TestResult::Fail("RDNA2 unmap missed a hub or changed another client's VM");
            }
            run(engine.destroy_vm(a)).unwrap();
            run(engine.unmap(&b, va)).unwrap();
            run(engine.destroy_vm(b)).unwrap();
            if engine.runtime != Runtime::Idle {
                return TestResult::Fail("RDNA2 VM teardown left a pending operation");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_gart_and_client_gpuvm_use_resolved_hubs_and_isolate_clients
);
