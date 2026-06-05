//! `<sys/mman.h>` + `<sys/utsname.h>` + `<sys/sysinfo.h>` +
//! `<sys/resource.h>` + `<dlfcn.h>` final-tier system surfaces.
//!
//! mmap / munmap delegate into the existing `narf_user_runtime`
//! anonymous-mapping path. mprotect / mlock / mlockall accept and
//! ignore (NARF doesn't expose page-protection or pin-in-RAM
//! controls to user mode). uname / sysinfo populate canonical
//! fields. getrusage zeroes the supplied struct. dlopen / dlsym /
//! dlclose surface "no dynamic loader" errors so a binary linking
//! against them succeeds even though no plugin can ever load.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int, c_void};

pub const ENOSYS: c_int = 38;

// ── <sys/mman.h> ────────────────────────────────────────────────────

pub const PROT_NONE: c_int = 0;
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const PROT_EXEC: c_int = 4;

pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

pub const MAP_SHARED: c_int = 0x01;
pub const MAP_PRIVATE: c_int = 0x02;
pub const MAP_ANONYMOUS: c_int = 0x20;
pub const MAP_FIXED: c_int = 0x10;

/// `mmap(addr, len, prot, flags, fd, offset)` — full POSIX shape.
/// We honour anonymous mappings via the existing user-runtime entry;
/// every other shape (file-backed, MAP_FIXED with a real address)
/// returns `MAP_FAILED` with `errno = ENOSYS`.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    _prot: c_int,
    flags: c_int,
    fd: c_int,
    _off: i64,
) -> *mut c_void {
    if (flags & MAP_ANONYMOUS) == 0 || fd != -1 {
        crate::errno::set_errno(ENOSYS);
        return MAP_FAILED;
    }
    // SAFETY: forwarded; user-runtime owns the mapping table.
    let p = unsafe { narf_user_runtime::mmap(addr as usize, len, flags as u32) };
    if p.is_null() {
        crate::errno::set_errno(ENOSYS);
        MAP_FAILED
    } else {
        p as *mut c_void
    }
}

/// `munmap(addr, len)` — POSIX shape. The kernel-side surface keys
/// on the start address only; `len` is recorded for ABI parity.
///
/// # Safety
/// `addr` must be a pointer previously returned from [`mmap`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut c_void, _len: usize) -> c_int {
    // SAFETY: caller-asserted prior mmap.
    match unsafe { narf_user_runtime::munmap(addr as *mut u8) } {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `mprotect(addr, len, prot)` — flip permissions on an existing
/// mapping. Returns 0 on success, -1 + errno=ENOMEM on failure
/// (no region intersects the range; AS lookup failed; bad bits in
/// `prot`). Backed by the kernel SYS_MPROTECT introduced this
/// session.
///
/// `prot` follows POSIX: PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4.
/// The kernel side ignores PROT_NONE (always installs READ at
/// minimum); call `munmap` if you actually want to drop the
/// mapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    // SAFETY: forwarded; user-runtime issues SYS_MPROTECT.
    match unsafe { narf_user_runtime::mprotect(addr as *mut u8, len, prot) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(12); // ENOMEM
            -1
        }
    }
}

/// `mlock(addr, len)` — force-back every demand-paged page in the
/// range and tell the kernel "don't reclaim me." Backed by the
/// kernel SYS_MLOCK introduced this session. Returns 0 on
/// success, -1 + errno=ENOMEM on failure (no region intersects /
/// OOM trying to back the lazy pages).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mlock(addr: *const c_void, len: usize) -> c_int {
    // SAFETY: forwarded; user-runtime issues SYS_MLOCK.
    match unsafe { narf_user_runtime::mlock(addr as *const u8, len) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(12); // ENOMEM
            -1
        }
    }
}

/// `munlock(addr, len)` — clear the LOCKED flag. Frames stay
/// backed (no swap exists yet to reclaim them); call `munmap`
/// to actually release storage. Returns 0 on success, -1 +
/// errno=EINVAL if no region intersects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn munlock(addr: *const c_void, len: usize) -> c_int {
    // SAFETY: forwarded; user-runtime issues SYS_MUNLOCK.
    match unsafe { narf_user_runtime::munlock(addr as *const u8, len) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

/// `mlockall(flags)` — accept and ignore.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mlockall(_flags: c_int) -> c_int {
    0
}

/// `munlockall()` — accept and ignore.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn munlockall() -> c_int {
    0
}

// ── <sys/mman.h> madvise constants ──────────────────────────────────
//
// Linux POSIX madvise advice values. NARF honours MADV_DONTNEED and
// MADV_FREE (both release the backing frames so the next access reads
// zero); every other advice value succeeds as a no-op.
pub const MADV_NORMAL: c_int = 0;
pub const MADV_RANDOM: c_int = 1;
pub const MADV_SEQUENTIAL: c_int = 2;
pub const MADV_WILLNEED: c_int = 3;
pub const MADV_DONTNEED: c_int = 4;
pub const MADV_FREE: c_int = 8;
pub const MADV_REMOVE: c_int = 9;
pub const MADV_DONTFORK: c_int = 10;
pub const MADV_DOFORK: c_int = 11;
pub const MADV_HUGEPAGE: c_int = 14;
pub const MADV_NOHUGEPAGE: c_int = 15;
pub const MADV_DONTDUMP: c_int = 16;
pub const MADV_DODUMP: c_int = 17;

/// `madvise(addr, len, advice)` — hint about how `[addr, addr+len)`
/// will be used. MADV_DONTNEED / MADV_FREE release the backing frames
/// so the next access reads zero; every other advice value is a
/// successful no-op. Backed by the kernel SYS_MADVISE.
///
/// Returns 0 on success, -1 + errno=ENOMEM on failure (no region
/// intersects, range misaligned, AS lookup failed). Matches Linux's
/// madvise(2) errno mapping: `EINVAL` would arguably fit misaligned
/// args better, but jemalloc/mimalloc consumers treat ENOMEM as
/// "back off and retry" which is the right behaviour for either case.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    // SAFETY: forwarded; user-runtime issues SYS_MADVISE.
    match unsafe { narf_user_runtime::madvise(addr as *mut u8, len, advice) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(12); // ENOMEM
            -1
        }
    }
}

/// `posix_madvise(addr, len, advice)` — POSIX alias of madvise with
/// the same advice values pinned (POSIX_MADV_* = MADV_*). Backed by
/// the same kernel surface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    // SAFETY: same as madvise.
    unsafe { madvise(addr, len, advice) }
}

/// `brk(end_data_segment)` — Linux brk(2). Sets the program-break
/// to the requested address (or queries it when `end == NULL`).
/// Returns 0 on success, -1 + errno=ENOMEM on failure. The current
/// break is also reflected back through [`sbrk`].
///
/// Reference: musl `src/internal/syscall.h::__syscall_brk`.
///
/// # Safety
/// Pure value op; the kernel owns brk-region accounting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn brk(end: *mut c_void) -> c_int {
    let r = narf_user_runtime::brk(end as usize);
    if r == 0 {
        crate::errno::set_errno(12); // ENOMEM
        -1
    } else {
        0
    }
}

/// `sbrk(increment)` — POSIX shape. Returns the previous program-
/// break address on success, `(void*) -1` on failure. `sbrk(0)`
/// queries the current break without moving it.
///
/// Reference: musl `src/legacy/sbrk.c`.
///
/// # Safety
/// Pure value op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut c_void {
    // Query first.
    let cur = narf_user_runtime::brk(0);
    if cur == 0 {
        crate::errno::set_errno(12);
        return !0usize as *mut c_void;
    }
    if increment == 0 {
        return cur as *mut c_void;
    }
    let new = (cur as isize).wrapping_add(increment) as usize;
    let r = narf_user_runtime::brk(new);
    if r == 0 || r < new {
        crate::errno::set_errno(12);
        return !0usize as *mut c_void;
    }
    cur as *mut c_void
}

/// `mremap(old_addr, old_len, new_len, flags, [new_addr])` —
/// Linux mremap(2). NARF doesn't support in-place mapping
/// resize today; surface ENOMEM so callers fall back to
/// alloc+copy+munmap.
///
/// Reference: musl `src/mman/mremap.c`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mremap(
    _old_addr: *mut c_void,
    _old_len: usize,
    _new_len: usize,
    _flags: c_int,
) -> *mut c_void {
    crate::errno::set_errno(12); // ENOMEM
    !0usize as *mut c_void
}

// ── <sys/utsname.h> ─────────────────────────────────────────────────

const UTS_FIELD: usize = 65;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct utsname {
    pub sysname: [c_char; UTS_FIELD],
    pub nodename: [c_char; UTS_FIELD],
    pub release: [c_char; UTS_FIELD],
    pub version: [c_char; UTS_FIELD],
    pub machine: [c_char; UTS_FIELD],
    pub domainname: [c_char; UTS_FIELD],
}

fn pack_field(field: &mut [c_char; UTS_FIELD], src: &[u8]) {
    let n = src.len().min(UTS_FIELD - 1);
    for i in 0..n {
        field[i] = src[i] as c_char;
    }
    field[n] = 0;
    for slot in field.iter_mut().take(UTS_FIELD).skip(n + 1) {
        *slot = 0;
    }
}

/// `uname(*buf)` — populate canonical fields. The release string
/// includes the NARF stage prefix so a consumer can match against
/// it.
///
/// # Safety
/// `buf` must be a writable `*mut utsname`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uname(buf: *mut utsname) -> c_int {
    if buf.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied writable struct.
    unsafe {
        let b = &mut *buf;
        pack_field(&mut b.sysname, b"NARF");
        pack_field(&mut b.nodename, b"narf-host");
        pack_field(&mut b.release, b"0.0.0-stage4");
        pack_field(&mut b.version, b"#1 NARF Stage 4");
        #[cfg(target_arch = "x86_64")]
        pack_field(&mut b.machine, b"x86_64");
        #[cfg(target_arch = "aarch64")]
        pack_field(&mut b.machine, b"aarch64");
        pack_field(&mut b.domainname, b"(none)");
    }
    0
}

// ── <sys/sysinfo.h> ─────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct sysinfo_t {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: [u8; 22],
}

/// `sysinfo(*info)` — populate the canonical "tiny system" snapshot.
/// We don't have a memory-pressure model at user-mode, so the values
/// are nominal: uptime from monotonic_ns / 1e9, totalram = 256 MiB,
/// procs = 1.
///
/// # Safety
/// `info` must be a writable `*mut sysinfo_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sysinfo(info: *mut sysinfo_t) -> c_int {
    if info.is_null() {
        return -1;
    }
    let (sec, _ns) = narf_user_runtime::clock_gettime(0);
    // SAFETY: caller-supplied writable struct.
    unsafe {
        *info = sysinfo_t {
            uptime: sec,
            loads: [0; 3],
            totalram: 256 * 1024 * 1024,
            freeram: 128 * 1024 * 1024,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 1,
            pad: [0; 22],
        };
    }
    0
}

// ── <sys/resource.h> ────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct rusage {
    pub ru_utime: crate::time::timeval,
    pub ru_stime: crate::time::timeval,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

pub const RUSAGE_SELF: c_int = 0;
pub const RUSAGE_CHILDREN: c_int = -1;

/// `getrusage(who, *usage)` — populate utime from the kernel's
/// monotonic clock; every other field is zero. NARF doesn't track
/// per-task user/system splits yet — the surface round-trips so
/// time(1)-shaped consumers see a usable wall measurement.
///
/// # Safety
/// `usage` must be a writable `*mut rusage`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut rusage) -> c_int {
    if usage.is_null() {
        return -1;
    }
    let mut tmp = [0i64; 18];
    let r = narf_user_runtime::getrusage(who, &mut tmp);
    if r != 0 {
        return -1;
    }
    // SAFETY: caller-supplied writable struct; we re-shape the 18
    // i64s into the C-shaped rusage.
    unsafe {
        *usage = rusage {
            ru_utime: crate::time::timeval {
                tv_sec: tmp[0],
                tv_usec: tmp[1],
            },
            ru_stime: crate::time::timeval {
                tv_sec: tmp[2],
                tv_usec: tmp[3],
            },
            ru_maxrss: tmp[4],
            ru_ixrss: tmp[5],
            ru_idrss: tmp[6],
            ru_isrss: tmp[7],
            ru_minflt: tmp[8],
            ru_majflt: tmp[9],
            ru_nswap: tmp[10],
            ru_inblock: tmp[11],
            ru_oublock: tmp[12],
            ru_msgsnd: tmp[13],
            ru_msgrcv: tmp[14],
            ru_nsignals: tmp[15],
            ru_nvcsw: tmp[16],
            ru_nivcsw: tmp[17],
        };
    }
    0
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

pub const RLIM_INFINITY: u64 = !0;

pub const RLIMIT_CPU: c_int = 0;
pub const RLIMIT_FSIZE: c_int = 1;
pub const RLIMIT_DATA: c_int = 2;
pub const RLIMIT_STACK: c_int = 3;
pub const RLIMIT_CORE: c_int = 4;
pub const RLIMIT_NOFILE: c_int = 7;
pub const RLIMIT_AS: c_int = 9;

/// `getrlimit(resource, *rlim)` — read the calling task's rlimit
/// for `resource`. NARF tracks rlimits as structural state only
/// (capabilities still gate every privileged operation), so the
/// values round-trip via setrlimit / getrlimit but don't enforce.
///
/// # Safety
/// `rlim` must be a writable `*mut rlimit`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut rlimit) -> c_int {
    if rlim.is_null() {
        return -1;
    }
    let mut out: [u64; 2] = [0; 2];
    let r = narf_user_runtime::getrlimit(resource as u32, &mut out);
    if r != 0 {
        return -1;
    }
    // SAFETY: caller-supplied writable struct.
    unsafe {
        *rlim = rlimit {
            rlim_cur: out[0],
            rlim_max: out[1],
        };
    }
    0
}

/// `setrlimit(resource, *rlim)` — record the new soft+hard limits.
///
/// # Safety
/// `rlim` must be a readable `*const rlimit`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const rlimit) -> c_int {
    if rlim.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied readable struct.
    let r = unsafe { *rlim };
    let pair: [u64; 2] = [r.rlim_cur, r.rlim_max];
    narf_user_runtime::setrlimit(resource as u32, &pair)
}

/// `prlimit64(pid, resource, new, old)` — Linux combined get-and-
/// set. `pid = 0` means "self". Either pointer may be NULL.
///
/// # Safety
/// `new` / `old`, when non-null, must point at a writable rlimit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prlimit(
    pid: i32,
    resource: c_int,
    new_lim: *const rlimit,
    old_lim: *mut rlimit,
) -> c_int {
    let new_pair = if new_lim.is_null() {
        None
    } else {
        // SAFETY: caller-asserted readable rlimit.
        let r = unsafe { *new_lim };
        Some([r.rlim_cur, r.rlim_max])
    };
    let mut old_pair: [u64; 2] = [0; 2];
    let r = narf_user_runtime::prlimit64(
        pid as u64,
        resource as u32,
        new_pair.as_ref(),
        if old_lim.is_null() {
            None
        } else {
            Some(&mut old_pair)
        },
    );
    if r != 0 {
        return -1;
    }
    if !old_lim.is_null() {
        // SAFETY: caller-asserted writable rlimit.
        unsafe {
            *old_lim = rlimit {
                rlim_cur: old_pair[0],
                rlim_max: old_pair[1],
            };
        }
    }
    0
}

// ── <sched.h> CPU affinity ─────────────────────────────────────────

/// `cpu_set_t` per `<sched.h>`. 1024 bits = 128 bytes = 16 u64 words.
/// Wire-compatible with the SUSv4 shape.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct cpu_set_t {
    pub bits: [u64; 16],
}

impl Default for cpu_set_t {
    fn default() -> Self {
        Self { bits: [0; 16] }
    }
}

/// `CPU_ZERO(set)` — clear every bit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CPU_ZERO(set: *mut cpu_set_t) {
    if set.is_null() {
        return;
    }
    // SAFETY: caller-supplied writable struct.
    unsafe {
        *set = cpu_set_t::default();
    }
}

/// `CPU_SET(cpu, set)` — set bit `cpu`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CPU_SET(cpu: c_int, set: *mut cpu_set_t) {
    if set.is_null() || cpu < 0 || cpu >= 1024 {
        return;
    }
    let i = (cpu / 64) as usize;
    let b = (cpu % 64) as u64;
    // SAFETY: caller-supplied; index in-range.
    unsafe {
        (*set).bits[i] |= 1u64 << b;
    }
}

/// `CPU_ISSET(cpu, set)` — non-zero iff bit `cpu` is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CPU_ISSET(cpu: c_int, set: *const cpu_set_t) -> c_int {
    if set.is_null() || cpu < 0 || cpu >= 1024 {
        return 0;
    }
    let i = (cpu / 64) as usize;
    let b = (cpu % 64) as u64;
    // SAFETY: caller-supplied readable struct.
    let bit = unsafe { ((*set).bits[i] >> b) & 1 };
    bit as c_int
}

/// `sched_getaffinity(pid, cpusetsize, mask)` per `<sched.h>`.
/// Returns 0 on success, -1 on bad pointer or oversized request.
///
/// # Safety
/// `mask` must be writable for `cpusetsize` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_getaffinity(
    pid: u32,
    cpusetsize: usize,
    mask: *mut cpu_set_t,
) -> c_int {
    if mask.is_null() || cpusetsize == 0 {
        return -1;
    }
    // SAFETY: caller-supplied writable region.
    let bytes = unsafe { core::slice::from_raw_parts_mut(mask as *mut u8, cpusetsize) };
    let n = narf_user_runtime::sched_getaffinity(pid, bytes);
    if n < 0 {
        -1
    } else {
        0
    }
}

/// `sched_setaffinity(pid, cpusetsize, mask)`.
///
/// # Safety
/// `mask` must be readable for `cpusetsize` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_setaffinity(
    pid: u32,
    cpusetsize: usize,
    mask: *const cpu_set_t,
) -> c_int {
    if mask.is_null() || cpusetsize == 0 {
        return -1;
    }
    // SAFETY: caller-supplied readable region.
    let bytes = unsafe { core::slice::from_raw_parts(mask as *const u8, cpusetsize) };
    narf_user_runtime::sched_setaffinity(pid, bytes)
}

// ── <sched.h> priority surface ─────────────────────────────────────

pub const SCHED_OTHER: c_int = 0;
pub const SCHED_FIFO: c_int = 1;
pub const SCHED_RR: c_int = 2;
pub const SCHED_BATCH: c_int = 3;
pub const SCHED_IDLE: c_int = 5;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct sched_param {
    pub sched_priority: c_int,
}

/// `sched_get_priority_max(policy)` — POSIX scheduler upper bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    if policy < 0 {
        return -1;
    }
    narf_user_runtime::sched_get_priority_max(policy as u32)
}

/// `sched_get_priority_min(policy)` — POSIX scheduler lower bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    if policy < 0 {
        return -1;
    }
    narf_user_runtime::sched_get_priority_min(policy as u32)
}

/// `sched_getparam(pid, *param)` — read the task's sched_priority.
///
/// # Safety
/// `param` must be a writable `*mut sched_param`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_getparam(pid: i32, param: *mut sched_param) -> c_int {
    if param.is_null() {
        return -1;
    }
    let prio = narf_user_runtime::sched_getparam(pid as u64);
    if prio == -1 {
        return -1;
    }
    // SAFETY: caller-supplied writable struct.
    unsafe {
        (*param).sched_priority = prio;
    }
    0
}

/// `sched_setparam(pid, *param)` — set sched_priority.
///
/// # Safety
/// `param` must be a readable `*const sched_param`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_setparam(pid: i32, param: *const sched_param) -> c_int {
    if param.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied readable struct.
    let prio = unsafe { (*param).sched_priority };
    narf_user_runtime::sched_setparam(pid as u64, prio)
}

// ── <sched.h> sched_getcpu ─────────────────────────────────────────

/// `sched_getcpu()` — return the CPU id the calling task is
/// currently running on. Used by consumer code to pin per-CPU
/// caches. NARF user mode is single-CPU; this always returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_getcpu() -> c_int {
    let (cpu, _node) = narf_user_runtime::getcpu();
    cpu as c_int
}

/// `getcpu(cpu, node)` per the SUSv4 extended sched API. Both
/// pointers may be null. Returns 0 on success.
///
/// # Safety
/// `cpu` and `node`, when non-null, must be writable `*mut u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getcpu(cpu: *mut u32, node: *mut u32) -> c_int {
    let (c, n) = narf_user_runtime::getcpu();
    // SAFETY: caller-supplied writable slots.
    unsafe {
        if !cpu.is_null() {
            *cpu = c;
        }
        if !node.is_null() {
            *node = n;
        }
    }
    0
}

// ── <dlfcn.h> ───────────────────────────────────────────────────────
//
// NARF has no dynamic loader at user mode (Stage-4 binaries are
// statically linked). dlopen / dlsym / dlclose surface "no support"
// per the Linux RTLD convention: NULL handle, NULL symbol, error
// string available via dlerror.

pub const RTLD_LAZY: c_int = 0x001;
pub const RTLD_NOW: c_int = 0x002;
pub const RTLD_GLOBAL: c_int = 0x100;
pub const RTLD_LOCAL: c_int = 0;

static DLERROR_MSG: &[u8] = b"narf-libc: no dynamic loader available\0";

/// `dlopen(file, flag)` — always returns NULL. dlerror will surface
/// a fixed message until cleared.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(_file: *const c_char, _flag: c_int) -> *mut c_void {
    core::ptr::null_mut()
}

/// `dlsym(handle, name)` — always returns NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(_handle: *mut c_void, _name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

/// `dlclose(handle)` — always succeeds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlclose(_handle: *mut c_void) -> c_int {
    0
}

/// `dlerror()` — pointer to a static error string, then NULL on the
/// next call (POSIX: subsequent calls clear the error).
static mut DLERROR_REPORTED: bool = false;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlerror() -> *mut c_char {
    // SAFETY: single-threaded user-mode invariant.
    unsafe {
        if DLERROR_REPORTED {
            DLERROR_REPORTED = false;
            return core::ptr::null_mut();
        }
        DLERROR_REPORTED = true;
        DLERROR_MSG.as_ptr() as *mut c_char
    }
}
