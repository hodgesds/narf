//! 9p mmap fault regression (#903): a fault inside a 9p file's EOF
//! must succeed and serve the file's bytes.
//!
//! `NinepNode::stat()` hardcoded `size: 0`, and the generic fault
//! path's EOF check consults the *synchronous* stat
//! (`mapped_file::demand_frame_inner`: `offset >= ops.stat().size`
//! → Bus), so every generic-path fault on a 9p file was refused at
//! any offset. The node now caches the length from the lookup
//! `Rstat` and refreshes it in `stat_async`. This smoke is the
//! independent regression pin for that fix — PR #864's coherence
//! pins exercise the same path, but they were written against the
//! coherence contract, not this defect.
//!
//! The scenario is deliberately minimal: fault a page well inside
//! EOF and the final partial page, check the served bytes (and the
//! zero tail past EOF), check that a page wholly beyond EOF is
//! still refused, and check the synchronous stat reports the real
//! length. On the unfixed code the first fault is refused with Bus
//! — the failure this smoke exists to catch.

use alloc::sync::Arc;

use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;

static NINEP_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_9p_as() -> Option<Arc<AddressSpace>> {
    NINEP_AS.lock().clone()
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    ops: Arc<dyn FileOps>,
    fd: u64,
}

fn install_fd(ops: &Arc<dyn FileOps>) -> Result<u64, &'static str> {
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops: Arc::clone(ops),
            offset: 0,
            flags: 0,
            status_flags: O_RDWR,
        },
    )
    .map(u64::from)
    .ok_or("installing the fd failed")
}

fn open_narf(
    volume: &Arc<narf_drivers_fs_9p::volume::NinepVolume>,
) -> Result<Arc<dyn FileOps>, &'static str> {
    crate::handlers::poll_io_to_completion(volume.root().lookup_async("narf.txt"))
        .and_then(|r| r.ok())
        .ok_or("lookup of narf.txt failed")
}

/// Mount the loopback volume seeded with `seed`, prime the file's
/// qid version past 0 (a same-byte rewrite, as in the coherence
/// fixtures — a version-0 file stays out of the retained cache),
/// install one fd on a fresh open, and run `body`.
fn with_9p(seed: &[u8], body: impl FnOnce(&Fixture) -> Result<(), &'static str>) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *NINEP_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_9p_as);
        let result = (|| {
            let transport =
                narf_drivers_fs_9p::loopback::LoopbackTransport::new(&[("narf.txt", seed)]);
            let t: Arc<dyn narf_drivers_fs_9p::session::Transport> = transport.clone();
            let volume = crate::handlers::poll_io_to_completion(
                narf_drivers_fs_9p::volume::NinepVolume::mount(t, narf_lib::id::DomainId::DRIVER_0),
            )
            .and_then(|r| r.ok())
            .ok_or("mounting the loopback 9p volume failed")?;
            let primer = open_narf(&volume)?;
            let n = crate::handlers::poll_io_to_completion(primer.write(0, &seed[..1]))
                .and_then(|r| r.ok())
                .ok_or("priming write failed")?;
            if n != 1 {
                return Err("priming write was short");
            }
            let ops = open_narf(&volume)?;
            let fd = install_fd(&ops)?;
            body(&Fixture { aspace, ops, fd })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *NINEP_AS.lock() = None;
        result
    })
}

fn map_shared(fd: u64, len: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: 0,
        arg1: len,
        arg2: PROT_READ | PROT_WRITE,
        arg3: MAP_SHARED,
        arg4: fd,
        arg5: 0,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(addr) if addr > 0 => Ok(addr as u64),
        _ => Err("MAP_SHARED mmap failed"),
    }
}

fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the 9p file's EOF was refused (#903)")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

fn mapped_bytes(
    aspace: &AddressSpace,
    va: u64,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let phys = mapped_frame(aspace, va).ok_or("the page is not backed")?;
    let ptr = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
    // SAFETY: `ptr` is the direct-map alias of a frame the mapping holds.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len).to_vec() })
}

fn content(len: usize) -> alloc::vec::Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The #903 regression: faults inside EOF succeed and serve the
/// file's bytes; the page wholly beyond EOF is still refused; the
/// synchronous stat reports the length the lookup `Rstat` carried.
fn smoke_9p_fault_inside_eof_serves_bytes() -> TestResult {
    let seed = content(3 * PAGE as usize - 100);
    with_9p(&seed, |fx| {
        // Map one page past the file so the beyond-EOF page is
        // inside the mapping and its refusal is the fault path's
        // EOF check, not a missing region.
        let base = map_shared(fx.fd, 4 * PAGE)?;
        fault(&fx.aspace, base + PAGE)?;
        if mapped_bytes(&fx.aspace, base + PAGE, 64)? != seed[PAGE as usize..PAGE as usize + 64] {
            return Err("the faulted page does not show the seed bytes");
        }
        // The final partial page: real bytes up to EOF, zeros after.
        fault(&fx.aspace, base + 2 * PAGE)?;
        let last = mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)?;
        let in_file = PAGE as usize - 100;
        if last[..in_file] != seed[2 * PAGE as usize..] {
            return Err("the final page does not show the seed's tail bytes");
        }
        if last[in_file..].iter().any(|&b| b != 0) {
            return Err("the final page is not zero past EOF");
        }
        // A page wholly beyond EOF must still be refused: the fix
        // reports the true length, it does not open the gate.
        // SAFETY: `aspace` is a live user root and paging is enabled.
        if unsafe { fx.aspace.demand_alloc_page(VirtAddr::new(base + 3 * PAGE)) }.is_ok() {
            return Err("a fault wholly beyond EOF was not refused");
        }
        // The defect site itself: the synchronous stat must report
        // the length the lookup Rstat carried, and agree with the
        // live stat.
        if fx.ops.stat().size != seed.len() as u64 {
            return Err("the synchronous stat() does not report the file's length (#903)");
        }
        let live = crate::handlers::poll_io_to_completion(fx.ops.stat_async())
            .and_then(|r| r.ok())
            .ok_or("stat_async failed")?;
        if live.size != seed.len() as u64 {
            return Err("stat_async does not report the file's length");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/9p", smoke_9p_fault_inside_eof_serves_bytes);
