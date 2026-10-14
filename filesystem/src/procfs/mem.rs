//! `/proc/<pid>/mem` and `/proc/<pid>/task/<tid>/mem`.
//!
//! Linux ref: `fs/proc/base.c` — `proc_mem_open`, `mem_open`, `mem_rw`,
//! `mem_lseek`, `proc_mem_operations` (`FOP_UNSIGNED_OFFSET`), and the
//! `REG("mem", S_IRUSR|S_IWUSR, proc_mem_operations)` entries of
//! `tgid_base_stuff` / `tid_base_stuff`.
//!
//! The node found by path lookup carries no access by itself. `open(2)` —
//! after the DAC check against the node's 0600 mode and owner — calls the
//! open hook, which is Linux's `proc_mem_open(inode, PTRACE_MODE_ATTACH)`:
//! it resolves the task's mm, applies `mm_access` (`PTRACE_MODE_FSCREDS`)
//! and binds that mm to the open file for its lifetime. Reads and writes then
//! go through the bound mm (`access_remote_vm` with `FOLL_FORCE`), never the
//! task the path names now, so an open descriptor keeps addressing the image
//! it was opened on across an `exec` (where it reads 0, as Linux's dead mm
//! does).

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// The memory an open `/proc/<pid>/mem` addresses — Linux's
/// `file->private_data` mm, accessed with `access_remote_vm(..., FOLL_FORCE)`.
pub trait ProcMemAccess: Send + Sync {
    /// `mem_rw(..., write = 0)` for one call: fill `buf` from address
    /// `addr`. `Ok(0)` when the mm is gone (`mmget_not_zero` failed);
    /// `Err(FsError::Io)` (EIO) when not one byte at `addr` is accessible;
    /// otherwise the length of the accessible prefix.
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> Result<usize, FsError>;
    /// `mem_rw(..., write = 1)`, same conventions.
    fn write_at(&self, addr: u64, buf: &[u8]) -> Result<usize, FsError>;
}

/// `proc_mem_open` for the process `pid` (outer pid space): `Err(NoSuchProcess)`
/// for a task with no mm, `Err(PermissionDenied)` when `mm_access` refuses.
pub type ProcMemOpenFn = fn(u64) -> Result<Arc<dyn ProcMemAccess>, FsError>;

static PROC_MEM_OPEN_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the `/proc/<pid>/mem` open hook (userspace owns tasks and mms).
pub fn install_proc_mem_hook(open: ProcMemOpenFn) {
    PROC_MEM_OPEN_HOOK.store(open as usize, Ordering::Release);
}

fn hook_proc_mem_open(pid: u64) -> Result<Arc<dyn ProcMemAccess>, FsError> {
    let v = PROC_MEM_OPEN_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Err(FsError::Unsupported);
    }
    // SAFETY: stored by install_proc_mem_hook as exactly ProcMemOpenFn.
    let f: ProcMemOpenFn = unsafe { core::mem::transmute::<usize, ProcMemOpenFn>(v) };
    f(pid)
}

/// `S_IRUSR|S_IWUSR`.
const MEM_MODE: Mode = Mode {
    file_type: FileType::File,
    perms: 0o600,
};

fn mem_stat() -> Stat {
    Stat {
        size: 0,
        blocks: 0,
        mode: MEM_MODE,
        mtime_cycles: 0,
    }
}

/// The path-lookup node of a `mem` file. Every access goes through the
/// per-open instance minted by `open_instance_checked`.
#[derive(Debug)]
pub(crate) struct ProcMemNode {
    pub(crate) pid: u64,
    pub(crate) ino: u64,
}

impl FileOps for ProcMemNode {
    fn ino(&self) -> u64 {
        self.ino
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        super::proc_attrs()
    }
    fn open_instance_checked(&self, _write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        // `mem_open` → `__mem_open(inode, file, PTRACE_MODE_ATTACH)`:
        // `IS_ERR_OR_NULL(mm) ? (mm ? PTR_ERR(mm) : -ESRCH)`.
        let mm = hook_proc_mem_open(self.pid)?;
        Ok(Some(Arc::new(ProcMemFile {
            pid: self.pid,
            ino: self.ino,
            mm,
        })))
    }
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        mem_stat()
    }
    fn owners(&self) -> (u32, u32) {
        super::task_file_owners(self.pid)
    }
    fn unsigned_offsets(&self) -> bool {
        true
    }
}

/// An open `/proc/<pid>/mem`: the mm bound at open.
struct ProcMemFile {
    pid: u64,
    ino: u64,
    mm: Arc<dyn ProcMemAccess>,
}

impl FileOps for ProcMemFile {
    fn ino(&self) -> u64 {
        self.ino
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        super::proc_attrs()
    }
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // `while (count > 0)` never runs for a zero-length read.
            if buf.is_empty() {
                return Ok(0);
            }
            self.mm.read_at(offset, buf)
        })
    }
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.is_empty() {
                return Ok(0);
            }
            self.mm.write_at(offset, buf)
        })
    }
    fn stat(&self) -> Stat {
        mem_stat()
    }
    fn owners(&self) -> (u32, u32) {
        super::task_file_owners(self.pid)
    }
    /// `mem_lseek`:
    ///
    /// ```text
    /// switch (orig) {
    /// case 0: file->f_pos = offset; break;
    /// case 1: file->f_pos += offset; break;
    /// default: return -EINVAL;
    /// }
    /// force_successful_syscall_return();
    /// return file->f_pos;
    /// ```
    ///
    /// Any position is accepted — it is an address, including one in the
    /// kernel half — and the add wraps (the kernel builds with
    /// `-fno-strict-overflow`).
    fn llseek_pos(&self, offset: i64, whence: u32, pos: u64) -> Option<Result<u64, i64>> {
        const EINVAL: i64 = 22;
        Some(match whence {
            0 => Ok(offset as u64),
            1 => Ok(pos.wrapping_add(offset as u64)),
            _ => Err(EINVAL),
        })
    }
    fn unsigned_offsets(&self) -> bool {
        true
    }
}
