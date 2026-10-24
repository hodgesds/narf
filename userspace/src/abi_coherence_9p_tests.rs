//! 9p page-cache coherence matrix (#742): the scenarios that fit a
//! versioned, server-owned filesystem.
//!
//! 9p's generation contract is unlike the local filesystems': the
//! generation folds `qid.version`, so it is the *server's* mutations
//! — not just this client's — that must invalidate retained pages
//! (#720/#681). The centrepiece scenario therefore faults a page in,
//! changes the file behind the client's back (`replace_data` on the
//! loopback transport, the fixture's simulated external change),
//! and requires a fault through a fresh open to serve the new bytes
//! while the identity stays put.
//!
//! The truncate scenarios of the matrix are not applicable: the 9p
//! node implements no `truncate` (the `FileOps` default returns
//! `Unsupported` — there is no Twstat path in the client yet). The
//! second scenario pins that contract at the syscall surface so the
//! day a truncate lands, this test is the one that flips.

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

static COH9P_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_coh9p_as() -> Option<Arc<AddressSpace>> {
    COH9P_AS.lock().clone()
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    volume: Arc<narf_drivers_fs_9p::volume::NinepVolume>,
    transport: Arc<narf_drivers_fs_9p::loopback::LoopbackTransport>,
    fd1: u64,
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
/// qid version past 0 (a same-byte rewrite, as in
/// `abi_fault_write_tests`), install one fd, and run `body`.
fn with_9p(seed: &[u8], body: impl FnOnce(&Fixture) -> Result<(), &'static str>) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *COH9P_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_coh9p_as);
        let result = (|| {
            let transport =
                narf_drivers_fs_9p::loopback::LoopbackTransport::new(&[("narf.txt", seed)]);
            let t: Arc<dyn narf_drivers_fs_9p::session::Transport> = Arc::clone(&transport);
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
            let ops1 = open_narf(&volume)?;
            let fd1 = install_fd(&ops1)?;
            body(&Fixture {
                aspace,
                volume,
                transport,
                fd1,
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *COH9P_AS.lock() = None;
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
        .map_err(|_| "a fault inside the file's EOF was refused")?;
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

/// The 9p generation contract end-to-end: a page retained under
/// version N must not be served to a fault that arrives after the
/// server moved to version N+1 — the fold of (qid.path, qid.version)
/// is the only thing standing between the second fault and stale
/// bytes, since the backing identity deliberately does not change.
fn smoke_9p_external_change_invalidates_retained_pages() -> TestResult {
    let seed = content(3 * PAGE as usize - 100);
    with_9p(&seed, |fx| {
        let base = map_shared(fx.fd1, 3 * PAGE)?;
        fault(&fx.aspace, base + PAGE)?;
        if mapped_bytes(&fx.aspace, base + PAGE, 32)? != seed[PAGE as usize..PAGE as usize + 32] {
            return Err("the faulted page does not show the seed bytes");
        }
        // The server-side file changes behind the client's back;
        // `replace_data` bumps the qid version like a real server's
        // write from another client would.
        let replacement = alloc::vec![0xE7u8; seed.len()];
        if !fx.transport.replace_data("narf.txt", &replacement) {
            return Err("replace_data on the loopback transport failed");
        }
        // A fresh open's walk reports the new version; a fault
        // through it must fill from the server, not from the page
        // retained under the old generation.
        let ops2 = open_narf(&fx.volume)?;
        let fd2 = install_fd(&ops2)?;
        let base2 = map_shared(fd2, 3 * PAGE)?;
        fault(&fx.aspace, base2 + PAGE)?;
        let served = mapped_bytes(&fx.aspace, base2 + PAGE, PAGE as usize)?;
        if served.iter().any(|&b| b != 0xE7) {
            return Err("a fault after the external change served the retained stale page");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/9p",
    smoke_9p_external_change_invalidates_retained_pages
);

/// The truncate scenarios of the matrix do not apply to 9p today —
/// pin the surface contract instead: `ftruncate` on a 9p file fails
/// (the node has no truncate; the trait default is `Unsupported`)
/// and the file is untouched. When a Twstat-based truncate lands,
/// this smoke is the one to replace with the real scenarios.
fn smoke_9p_ftruncate_is_unsupported() -> TestResult {
    let seed = content(100);
    with_9p(&seed, |fx| {
        match call(Syscall::Ftruncate.raw(), a1(fx.fd1, PAGE)) {
            Some(0) => return Err("ftruncate on a 9p file unexpectedly succeeded"),
            Some(_) => {}
            None => return Err("ftruncate did not return"),
        }
        let mut buf = [0u8; 100];
        match call(
            Syscall::Pread64.raw(),
            a3(fx.fd1, buf.as_mut_ptr() as u64, 100, 0),
        ) {
            Some(100) => {}
            _ => return Err("pread after the failed ftruncate was short"),
        }
        if &buf[..] != seed.as_slice() {
            return Err("the failed ftruncate disturbed the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/9p",
    smoke_9p_ftruncate_is_unsupported
);
