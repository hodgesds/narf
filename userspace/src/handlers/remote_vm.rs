//! Access to another process's memory: the syscall-layer halves of Linux's
//! `ptrace_access_vm` (`kernel/ptrace.c`), `process_vm_readv`/`writev`
//! (`mm/process_vm_access.c`) and `/proc/<pid>/mem` (`fs/proc/base.c`).
//!
//! All three resolve the target's address space and hand the transfer to
//! [`narf_memory::AddressSpace::access_remote`], which works from the
//! target's region table — never from the CALLER's mapping of the target's
//! address, and never from the target's page-table leaves (see that
//! module's documentation for why a leaf walk returns the wrong bytes).

#[allow(unused_imports)]
use super::*;

use narf_filesystem::procfs::ProcMemAccess;
use narf_filesystem::FsError;
use narf_memory::{RemoteAccess, RemoteBuf};

/// Linux `get_task_mm(task)`: the address space `task` runs in, whether it is
/// queued, parked or being polled on some CPU right now. A `CLONE_THREAD`
/// sibling shares the group's mm, so any queued member answers for a member
/// that is momentarily invisible. `None` for a task without one (a kernel
/// task, or one whose mm is already torn down — Linux's `PF_EXITING`).
pub(crate) fn task_mm(task: u64) -> Option<Arc<AddressSpace>> {
    // CLONE_THREAD implies CLONE_VM: every thread of the caller's own
    // process runs in the caller's mm.
    if same_thread_group(task, current_task_id()) {
        return current_address_space();
    }
    if let Some(mm) = narf_scheduler::address_space_of_live(narf_scheduler::TaskId(task)) {
        return Some(mm);
    }
    let pid = task_to_pid_raw(task)?;
    crate::task::thread_group_tids(pid)
        .into_iter()
        .filter(|&member| member != task)
        .find_map(|member| narf_scheduler::address_space_of_live(narf_scheduler::TaskId(member)))
}

/// `kernel/ptrace.c::ptrace_access_vm(tsk, addr, buf, len, gup_flags)` for
/// the PEEK/POKE family, which always passes `FOLL_FORCE` (plus
/// `FOLL_WRITE` for POKE). Returns the bytes transferred; the caller turns a
/// short count into `-EIO`.
///
/// ```text
/// mm = get_task_mm(tsk);
/// if (!mm) return 0;
/// if (!tsk->ptrace || (current != tsk->parent) ||
///     ((get_dumpable(mm) != SUID_DUMP_USER) &&
///      !ptracer_capable(tsk, mm->user_ns))) { mmput(mm); return 0; }
/// ret = access_remote_vm(mm, addr, buf, len, gup_flags);
/// ```
///
/// The tracer relationship is `ptrace_check_attach`'s, which `sys_ptrace`
/// has already enforced for every PEEK/POKE request.
pub(crate) fn ptrace_access_vm(tracer: u64, tracee: u64, addr: u64, buf: RemoteBuf<'_>) -> usize {
    let write = matches!(buf, RemoteBuf::Write(_));
    let Some(mm) = task_mm(tracee) else {
        return 0;
    };
    // `ptracer_capable(tsk, mm->user_ns)` asks whether the tracer held
    // CAP_SYS_PTRACE when it attached (`tsk->ptracer_cred`); NARF keeps no
    // attach-time credential snapshot, so the tracer's current capability
    // stands in for it.
    if !read_prctl(tracee).dumpable && !task_capable(tracer, CAP_SYS_PTRACE) {
        return 0;
    }
    let access = RemoteAccess {
        write,
        force: true,
        // `__access_remote_vm` expands a stack VMA under `current`'s limits.
        expand_stack: Some(current_stack_growth_limits()),
    };
    // SAFETY: `mm` is a live user address space (the Arc retains it); the
    // remote helper faults pages in and breaks COW through the same paths
    // the owner's own faults take.
    unsafe { mm.access_remote(addr, buf, access) }
}

// ── process_vm_readv / process_vm_writev ─────────────────────────────

/// `lib/iov_iter.c::iovec_from_user` for the REMOTE vector of
/// `process_vm_rw`: no `access_ok` (the addresses belong to another mm) and
/// no MAX_RW_COUNT clamp — only the segment-count and sign checks.
///
/// ```text
/// if (nr_segs == 0) return iov;
/// if (nr_segs > UIO_MAXIOV) return ERR_PTR(-EINVAL);
/// ... copy_iovec_from_user: -EFAULT on a faulting array,
///     -EINVAL on an iov_len with the ssize_t sign bit set
/// ```
fn remote_iovecs_from_user(uvec: u64, nr_segs: u64) -> Result<alloc::vec::Vec<(u64, u64)>, i64> {
    if nr_segs == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if nr_segs > LINUX_IOV_MAX as u64 {
        return Err(EINVAL);
    }
    let nr_segs = nr_segs as usize;
    // SAFETY: at most 1024 native iovecs (16 KiB), range-validated inside.
    let raw = unsafe { copy_from_user_vec(uvec, nr_segs * 16) }.map_err(|e| e as i64)?;
    let mut out = alloc::vec::Vec::with_capacity(nr_segs);
    for slot in raw.chunks_exact(16) {
        let base = u64::from_ne_bytes(slot[..8].try_into().unwrap());
        let len = u64::from_ne_bytes(slot[8..].try_into().unwrap());
        if (len as i64) < 0 {
            return Err(EINVAL);
        }
        out.push((base, len));
    }
    Ok(out)
}

/// A cursor over the caller's (local) iovecs: Linux's `iov_iter`.
#[derive(Clone)]
struct LocalIter<'a> {
    iovs: &'a [ImportedRwIovec],
    seg: usize,
    off: usize,
    remaining: usize,
}

impl<'a> LocalIter<'a> {
    fn new(iovs: &'a [ImportedRwIovec]) -> Self {
        Self {
            iovs,
            seg: 0,
            off: 0,
            remaining: iovs.iter().map(|iov| iov.len).sum(),
        }
    }

    /// The next local span, bounded by `max` and by the end of the caller's
    /// page it starts in. A user copy faults at a page boundary, so moving
    /// one page-bounded span at a time reproduces exactly how far Linux's
    /// `copy_page_{to,from}_iter` gets before its short copy.
    fn next_span(&mut self, max: usize) -> Option<(u64, usize)> {
        while self.seg < self.iovs.len() && self.off == self.iovs[self.seg].len {
            self.seg += 1;
            self.off = 0;
        }
        let iov = self.iovs.get(self.seg)?;
        let base = iov.base.wrapping_add(self.off as u64);
        let to_page_end = 4096 - (base & 0xFFF) as usize;
        Some((base, (iov.len - self.off).min(max).min(to_page_end)))
    }

    fn advance(&mut self, n: usize) {
        self.off += n;
        self.remaining -= n;
    }

    /// `copy_page_to_iter`: store `data` at the cursor. Returns how many
    /// bytes landed before the first local fault.
    fn copy_out(&mut self, data: &[u8]) -> usize {
        let mut done = 0;
        while done < data.len() {
            let Some((base, n)) = self.next_span(data.len() - done) else {
                break;
            };
            // SAFETY: a page-bounded span of the caller's own buffer,
            // range-validated by import_iovec; the guarded copy turns a
            // fault into Err.
            if unsafe { copy_to_user(base, &data[done..done + n]) }.is_err() {
                break;
            }
            self.advance(n);
            done += n;
        }
        done
    }

    /// `copy_page_from_iter`: fill `out` from the cursor. Returns how many
    /// bytes were read before the first local fault.
    fn copy_in(&mut self, out: &mut [u8]) -> usize {
        let mut done = 0;
        while done < out.len() {
            let Some((base, n)) = self.next_span(out.len() - done) else {
                break;
            };
            // SAFETY: as in `copy_out`.
            if unsafe { copy_from_user(&mut out[done..done + n], base) }.is_err() {
                break;
            }
            self.advance(n);
            done += n;
        }
        done
    }
}

/// `process_vm_rw_single_vec` for one remote segment. `Err(())` is its
/// `-EFAULT`: a remote page that could not be pinned, or a short local copy
/// while the local iterator still had room.
fn process_vm_rw_single_vec(
    mm: &AddressSpace,
    addr: u64,
    len: u64,
    iter: &mut LocalIter<'_>,
    vm_write: bool,
) -> Result<(), ()> {
    let access = RemoteAccess {
        write: vm_write,
        // GUP proper: `pin_user_pages_remote(mm, pa, n, flags)` with
        // `flags = vm_write ? FOLL_WRITE : 0` — no FOLL_FORCE, and no stack
        // expansion.
        force: false,
        expand_stack: None,
    };
    let mut page_buf = [0u8; 4096];
    let mut addr = addr;
    let mut len = len;
    while len != 0 && iter.remaining != 0 {
        let in_page = (addr & 0xFFF) as usize;
        let chunk = ((4096 - in_page) as u64).min(len) as usize;
        let chunk = chunk.min(iter.remaining);
        if vm_write {
            // Linux pins the remote page, then `copy_page_from_iter` moves
            // the local bytes into it, advancing the iterator by what it
            // copied before a local fault. Gather on a copy of the cursor so
            // a page that cannot be written leaves the iterator untouched,
            // exactly like a failed pin.
            let mut gather = iter.clone();
            let got = gather.copy_in(&mut page_buf[..chunk]);
            if got == 0 {
                // Either the pin or a zero-byte local copy: -EFAULT.
                return Err(());
            }
            // SAFETY: `mm` is retained by the caller's Arc.
            let written =
                unsafe { mm.access_remote(addr, RemoteBuf::Write(&page_buf[..got]), access) };
            if written != got {
                return Err(());
            }
            *iter = gather;
            if got < chunk {
                return Err(());
            }
        } else {
            // SAFETY: `mm` is retained by the caller's Arc.
            let read =
                unsafe { mm.access_remote(addr, RemoteBuf::Read(&mut page_buf[..chunk]), access) };
            if read != chunk {
                return Err(());
            }
            let stored = iter.copy_out(&page_buf[..chunk]);
            if stored < chunk {
                return Err(());
            }
        }
        addr = addr.wrapping_add(chunk as u64);
        len -= chunk as u64;
    }
    Ok(())
}

/// `mm/process_vm_access.c::process_vm_rw` + `process_vm_rw_core`.
///
/// ```text
/// if (flags != 0) return -EINVAL;
/// rc = import_iovec(dir, lvec, liovcnt, UIO_FASTIOV, &iov_l, &iter);
/// if (rc < 0) return rc;
/// if (!iov_iter_count(&iter)) goto free_iov_l;            /* 0 */
/// iov_r = iovec_from_user(rvec, riovcnt, ...);           /* -EINVAL/-EFAULT */
/// -- process_vm_rw_core --
/// nr_pages = max pages spanned by any rvec[i] with iov_len > 0;
/// if (nr_pages == 0) return 0;
/// task = find_get_task_by_vpid(pid);                      /* -ESRCH */
/// mm = mm_access(task, PTRACE_MODE_ATTACH_REALCREDS);     /* -ESRCH, -EACCES→-EPERM */
/// for (i = 0; i < riovcnt && iov_iter_count(iter) && !rc; i++)
///         rc = process_vm_rw_single_vec(...);
/// total_len -= iov_iter_count(iter);
/// if (total_len) rc = total_len;
/// ```
pub(crate) fn process_vm_transfer(ctx: &mut dyn TrapContext, vm_write: bool) {
    let a = *ctx.args();
    // `pid_t pid`: the low 32 bits of the register, sign-extended.
    let pid = a.arg0 as i32;
    let lvec = a.arg1;
    // `import_iovec(..., unsigned nr_segs, ...)`: the `unsigned long liovcnt`
    // is narrowed to 32 bits on the way in.
    let liovcnt = a.arg2 as u32 as usize;
    let rvec = a.arg3;
    // `iovec_from_user(..., unsigned long nr_segs, ...)` keeps all 64 bits.
    let riovcnt = a.arg4;
    let flags = a.arg5;
    if flags != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let local = match import_rw_iovecs(lvec, liovcnt) {
        Ok(local) => local,
        Err(errno) => {
            ctx.set_return(errno_ret(errno as i64));
            return;
        }
    };
    let mut iter = LocalIter::new(&local);
    if iter.remaining == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let remote = match remote_iovecs_from_user(rvec, riovcnt) {
        Ok(remote) => remote,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if remote.iter().all(|&(_, len)| len == 0) {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let caller = current_task_id();
    let Some(target) = find_task_by_vpid(caller, pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    // `mm_access`: `get_task_mm` → -ESRCH for a task without one; then
    // `may_access_mm`: the caller's own mm needs no check, otherwise
    // `ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)` (-EACCES,
    // which process_vm_rw_core reports as -EPERM).
    let Some(mm) = task_mm(target) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let own_mm = current_address_space().is_some_and(|own| Arc::ptr_eq(&own, &mm));
    if !own_mm && !ptrace_may_access_mode(caller, target, PtraceCreds::Real) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let total_len = iter.remaining;
    let mut faulted = false;
    for &(base, len) in &remote {
        if iter.remaining == 0 {
            break;
        }
        if process_vm_rw_single_vec(&mm, base, len, &mut iter, vm_write).is_err() {
            faulted = true;
            break;
        }
    }
    let copied = total_len - iter.remaining;
    if copied != 0 {
        ctx.set_return(SyscallReturn::ok(copied as u64));
    } else if faulted {
        ctx.set_return(errno_ret(EFAULT));
    } else {
        ctx.set_return(SyscallReturn::ok(0));
    }
}

// ── /proc/<pid>/mem ──────────────────────────────────────────────────

/// The mm an open `/proc/<pid>/mem` is bound to. Linux holds it with
/// `mmgrab` (the struct survives) but not `mmget` (its memory does not):
/// once the process exits or execs, `mmget_not_zero` fails and every access
/// returns 0. A `Weak` is the same contract.
struct ProcMemMm {
    mm: alloc::sync::Weak<AddressSpace>,
}

impl ProcMemMm {
    /// `mem_rw`'s loop: `access_remote_vm(mm, addr, page, this_len,
    /// FOLL_FORCE | (write ? FOLL_WRITE : 0))` until it returns 0, with
    /// `-EIO` only when nothing at all was transferred. Linux's default
    /// `proc_mem_force_override` is `PROC_MEM_FORCE_ALWAYS`
    /// (`CONFIG_PROC_MEM_ALWAYS_FORCE`), so FOLL_FORCE is unconditional.
    fn rw(&self, addr: u64, buf: RemoteBuf<'_>) -> Result<usize, FsError> {
        let Some(mm) = self.mm.upgrade() else {
            return Ok(0);
        };
        let access = RemoteAccess {
            write: matches!(buf, RemoteBuf::Write(_)),
            force: true,
            expand_stack: Some(current_stack_growth_limits()),
        };
        // SAFETY: the upgraded Arc keeps the address space alive.
        match unsafe { mm.access_remote(addr, buf, access) } {
            0 => Err(FsError::Io(narf_block::BlockError::IOError)),
            n => Ok(n),
        }
    }
}

impl ProcMemAccess for ProcMemMm {
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.rw(addr, RemoteBuf::Read(buf))
    }
    fn write_at(&self, addr: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.rw(addr, RemoteBuf::Write(buf))
    }
}

/// `fs/proc/base.c::proc_mem_open(inode, PTRACE_MODE_ATTACH)` for the
/// process `pid` (outer pid space), installed as procfs's mem open hook.
///
/// ```text
/// task = get_proc_task(inode);           if (!task) return ERR_PTR(-ESRCH);
/// mm = mm_access(task, mode | PTRACE_MODE_FSCREDS);
/// if (IS_ERR(mm)) return mm == ERR_PTR(-ESRCH) ? NULL : mm;   → -ESRCH / -EACCES
/// ```
pub fn proc_mem_open(pid: u64) -> Result<Arc<dyn ProcMemAccess>, FsError> {
    let caller = current_task_id();
    let task = pid_to_task_raw(pid).ok_or(FsError::NoSuchProcess)?;
    let mm = task_mm(task).ok_or(FsError::NoSuchProcess)?;
    let own_mm = current_address_space().is_some_and(|own| Arc::ptr_eq(&own, &mm));
    if !own_mm && !ptrace_may_access_mode(caller, task, PtraceCreds::Fs) {
        return Err(FsError::PermissionDenied);
    }
    Ok(Arc::new(ProcMemMm {
        mm: Arc::downgrade(&mm),
    }))
}
