//! `/proc` synthetic filesystem — every read produces text on
//! demand from a closure. POSIX has no `/proc`; Linux's shape is
//! the de-facto standard and the one tooling expects (ps, top,
//! lsof, /proc/cpuinfo readers, build-system hardware probes).
//!
//! Stage-1 entries:
//!   /proc/cpuinfo     — one block per logical CPU (vendor/model/MHz)
//!   /proc/meminfo     — total/free RAM
//!   /proc/mounts      — current mount table
//!   /proc/uptime      — seconds since boot, idle seconds
//!   /proc/version     — kernel version string
//!   /proc/[pid]/{stat,status,cmdline,maps,comm}
//!     — per-task views; pid is the live scheduler TaskId
//!   /proc/self/...    — symlink-shape: each lookup resolves the
//!                       calling task fresh via the
//!                       `current-pid` hook
//!
//! The dir tree is read-only. Per-task data comes from the kernel
//! through fn-pointer hooks installed at boot
//! (`install_proc_hooks`); without the hooks installed, /proc/[pid]
//! lookups return NotFound and /proc/self resolves to pid 0.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat,
};

// ── Hook plumbing ───────────────────────────────────────────────

/// Per-task metadata snapshot returned by the kernel when /proc
/// asks for /proc/[pid]/* contents. Filled by `install_proc_hooks`
/// at boot — the filesystem crate doesn't depend on the scheduler
/// directly to keep the dep graph one-way.
#[derive(Clone, Debug, Default)]
pub struct ProcTaskInfo {
    pub pid: u64,
    pub comm: String,
    /// One-character POSIX state: R running, S sleeping, Z zombie.
    pub state: char,
    pub brk_top: u64,
    pub stack_top: u64,
    /// argv joined with NULs (Linux /proc/[pid]/cmdline shape).
    pub cmdline: Vec<u8>,
    /// VMA list — one entry per address-space region. Filled by
    /// the kernel hook from the AS's regions table; rendered into
    /// /proc/[pid]/maps text by `render_maps`.
    pub vmas: Vec<ProcVma>,
}

/// One virtual-memory area entry. Mirrors what `/proc/[pid]/maps`
/// reports per line: range, protection bits, and an optional name.
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcVma {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    /// Optional Linux-style label (`[heap]`, `[stack]`, `[vdso]`).
    /// Empty for anonymous mappings.
    pub label: &'static str,
}

type CurrentPidFn = fn() -> u64;
type ListPidsFn = fn() -> Vec<u64>;
type TaskInfoFn = fn(u64) -> Option<ProcTaskInfo>;

static CURRENT_PID_HOOK: AtomicUsize = AtomicUsize::new(0);
static LIST_PIDS_HOOK: AtomicUsize = AtomicUsize::new(0);
static TASK_INFO_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the kernel-side accessors. Called once from boot init.
pub fn install_proc_hooks(current: CurrentPidFn, list: ListPidsFn, info: TaskInfoFn) {
    CURRENT_PID_HOOK.store(current as usize, Ordering::Release);
    LIST_PIDS_HOOK.store(list as usize, Ordering::Release);
    TASK_INFO_HOOK.store(info as usize, Ordering::Release);
}

fn current_pid() -> u64 {
    let v = CURRENT_PID_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    let f: CurrentPidFn = unsafe { core::mem::transmute(v) };
    f()
}

fn list_pids() -> Vec<u64> {
    let v = LIST_PIDS_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    let f: ListPidsFn = unsafe { core::mem::transmute(v) };
    f()
}

fn task_info(pid: u64) -> Option<ProcTaskInfo> {
    let v = TASK_INFO_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    let f: TaskInfoFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

// ── Generic closure-backed read-only file ───────────────────────

/// Closure-backed virtual file. `gen` is called on every `read` —
/// we re-render rather than cache because the values (uptime,
/// /proc/self/stat) change between reads.
type GenStaticFn = fn() -> String;

struct ProcStaticFile {
    name: &'static str,
    gen: GenStaticFn,
}

impl core::fmt::Debug for ProcStaticFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcStaticFile").field("name", &self.name).finish()
    }
}

impl FileOps for ProcStaticFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let s = (self.gen)();
            slice_read(s.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // See note on ProcPidFile::stat for why we don't call the
        // generator here — same lock-reentrancy reason.
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

/// Per-pid file with bound `pid` so the generator knows whose
/// state to render.
struct ProcPidFile {
    pid: u64,
    field: PidField,
}

#[derive(Copy, Clone, Debug)]
enum PidField {
    Stat,
    Status,
    Cmdline,
    Maps,
    Comm,
}

impl core::fmt::Debug for ProcPidFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcPidFile")
            .field("pid", &self.pid)
            .field("field", &self.field)
            .finish()
    }
}

impl FileOps for ProcPidFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let field = self.field;
        Box::pin(async move {
            let info = match task_info(pid) {
                Some(i) => i,
                None => {
                    // Task gone (zombie reaped). Linux returns ESRCH;
                    // we surface as 0 bytes for read — same outcome
                    // for most consumers.
                    return Ok(0);
                }
            };
            let body = match field {
                PidField::Stat => render_stat(&info),
                PidField::Status => render_status(&info),
                PidField::Cmdline => return slice_read(&info.cmdline, offset, buf),
                PidField::Maps => render_maps(&info),
                PidField::Comm => format!("{}\n", info.comm),
            };
            slice_read(body.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

fn slice_read(bytes: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    let off = offset as usize;
    if off >= bytes.len() {
        return Ok(0);
    }
    let n = core::cmp::min(buf.len(), bytes.len() - off);
    buf[..n].copy_from_slice(&bytes[off..off + n]);
    Ok(n)
}

// ── Directory-marker file ───────────────────────────────────────
//
// resolve_async walks intermediate path components by calling
// lookup_async (returns a FileOps) + checking stat().mode.file_type
// == Dir, then calling lookup_dir_async to actually descend. For
// /proc/self/comm and /proc/[pid]/stat we need lookup("self") /
// lookup("<pid>") to return SOMETHING that stat()s as Dir even
// though those names refer to subdirs. ProcDirMarker is that
// stub — never read or written, exists only to pass the kind
// check in resolve_async.

#[derive(Debug)]
struct ProcDirMarker;

impl FileOps for ProcDirMarker {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::DIR_RO,
            mtime_cycles: 0,
        }
    }
}

// ── Per-pid directory ───────────────────────────────────────────

#[derive(Debug)]
struct ProcPidDir {
    pid: u64,
}

impl DirOps for ProcPidDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let field = match name {
            "stat" => PidField::Stat,
            "status" => PidField::Status,
            "cmdline" => PidField::Cmdline,
            "maps" => PidField::Maps,
            "comm" => PidField::Comm,
            _ => return None,
        };
        Some(Arc::new(ProcPidFile { pid: self.pid, field }))
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [
                DirEntry { name: "stat", file_type: FileType::File },
                DirEntry { name: "status", file_type: FileType::File },
                DirEntry { name: "cmdline", file_type: FileType::File },
                DirEntry { name: "maps", file_type: FileType::File },
                DirEntry { name: "comm", file_type: FileType::File },
            ]
            .into_iter(),
        )
    }
}

// ── /proc root ──────────────────────────────────────────────────

#[derive(Debug)]
struct ProcRoot;

impl DirOps for ProcRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "cpuinfo" => Some(Arc::new(ProcStaticFile { name: "cpuinfo", gen: gen_cpuinfo })),
            "meminfo" => Some(Arc::new(ProcStaticFile { name: "meminfo", gen: gen_meminfo })),
            "mounts" => Some(Arc::new(ProcStaticFile { name: "mounts", gen: gen_mounts })),
            "uptime" => Some(Arc::new(ProcStaticFile { name: "uptime", gen: gen_uptime })),
            "version" => Some(Arc::new(ProcStaticFile { name: "version", gen: gen_version })),
            "cmdline" => Some(Arc::new(ProcStaticFile { name: "cmdline", gen: gen_cmdline })),
            "loadavg" => Some(Arc::new(ProcStaticFile { name: "loadavg", gen: gen_loadavg })),
            "filesystems" => Some(Arc::new(ProcStaticFile { name: "filesystems", gen: gen_filesystems })),
            "partitions" => Some(Arc::new(ProcStaticFile { name: "partitions", gen: gen_partitions })),
            "self" => Some(Arc::new(ProcDirMarker)),
            _ => {
                // Numeric pid → directory marker (lookup-as-file).
                // resolve_async needs lookup_async to return a
                // FileOps that stat()s as Dir before it'll call
                // lookup_dir_async for the descent.
                if let Ok(pid) = name.parse::<u64>() {
                    if task_info(pid).is_some() {
                        return Some(Arc::new(ProcDirMarker));
                    }
                }
                None
            }
        }
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if name == "self" {
            // /proc/self resolves to the calling task's pid each
            // time; we materialise a fresh ProcPidDir bound to it.
            let pid = current_pid();
            return Some(Arc::new(ProcPidDir { pid }));
        }
        // Numeric name → per-pid dir. Validate the pid is live.
        if let Ok(pid) = name.parse::<u64>() {
            if task_info(pid).is_some() {
                return Some(Arc::new(ProcPidDir { pid }));
            }
        }
        None
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        // Static entries first, then "self", then every live pid
        // as its own decimal-named subdirectory. The decimal names
        // need owned Strings — but DirEntry holds &'static str, so
        // we leak the names (one allocation per pid per readdir).
        // Followups: switch DirEntry's name to String once a real
        // consumer needs the savings.
        let mut entries: Vec<DirEntry> = alloc::vec![
            DirEntry { name: "cpuinfo", file_type: FileType::File },
            DirEntry { name: "meminfo", file_type: FileType::File },
            DirEntry { name: "mounts", file_type: FileType::File },
            DirEntry { name: "uptime", file_type: FileType::File },
            DirEntry { name: "version", file_type: FileType::File },
            DirEntry { name: "cmdline", file_type: FileType::File },
            DirEntry { name: "loadavg", file_type: FileType::File },
            DirEntry { name: "filesystems", file_type: FileType::File },
            DirEntry { name: "partitions", file_type: FileType::File },
            DirEntry { name: "self", file_type: FileType::Dir },
        ];
        for pid in list_pids() {
            let s = pid.to_string();
            // Leak the String so its bytes outlive this iter call.
            // Acceptable cost: real consumers (ls, ps) read /proc
            // infrequently and we cap at the live-pid count.
            let leaked: &'static str = Box::leak(s.into_boxed_str());
            entries.push(DirEntry { name: leaked, file_type: FileType::Dir });
        }
        Box::new(entries.into_iter())
    }
}

#[derive(Debug)]
pub struct ProcFs;

impl FsInstance for ProcFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(ProcRoot)
    }
    fn name(&self) -> &str {
        "procfs"
    }
}

// ── Generators (system-wide) ────────────────────────────────────

fn gen_cpuinfo() -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    #[cfg(target_arch = "x86_64")]
    {
        use narf_arch::x86_64::ident;
        let id = ident::read();
        let vendor_str = match id.vendor {
            ident::Vendor::Intel => "GenuineIntel",
            ident::Vendor::Amd => "AuthenticAMD",
            ident::Vendor::Hygon => "HygonGenuine",
            ident::Vendor::Centaur => "CentaurHauls",
            ident::Vendor::Via => "VIA VIA VIA ",
            ident::Vendor::Zhaoxin => "  Shanghai  ",
            ident::Vendor::Other(_) => "Unknown",
        };
        let brand = ident::brand_str(&id);
        let model_name = if brand.is_empty() {
            "(unknown)"
        } else {
            brand
        };
        // One block per logical CPU. SMP enumeration lands when the
        // userspace AP-count surface is wired through; today we
        // report the BSP only — matches what /proc/cpuinfo on a
        // single-CPU Linux config would show, and the fields are
        // identical per-block on a homogeneous system anyway.
        let _ = writeln!(s, "processor\t: 0");
        let _ = writeln!(s, "vendor_id\t: {}", vendor_str);
        let _ = writeln!(s, "cpu family\t: {}", id.family);
        let _ = writeln!(s, "model\t\t: {}", id.model);
        let _ = writeln!(s, "model name\t: {}", model_name);
        let _ = writeln!(s, "stepping\t: {}", id.stepping);
        let _ = writeln!(s, "");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = writeln!(s, "processor\t: 0");
        let _ = writeln!(s, "vendor_id\t: NARF");
        let _ = writeln!(s, "model name\t: (arch ident not yet wired)");
        let _ = writeln!(s, "");
    }
    s
}

fn gen_meminfo() -> String {
    use core::fmt::Write as _;
    let stats = narf_memory::frame::stats();
    // Frames are 4 KiB on every arch we target.
    let total_kb = stats.total * 4;
    let free_kb = stats.free * 4;
    let reserved_kb = stats.reserved * 4;
    let mut s = String::new();
    let _ = writeln!(s, "MemTotal:     {:>10} kB", total_kb);
    let _ = writeln!(s, "MemFree:      {:>10} kB", free_kb);
    // Without page-cache + slab accounting separated out we can't
    // distinguish "available" from "free"; report the same value
    // so the standard `free` math (`available = MemAvailable`)
    // still produces a meaningful number.
    let _ = writeln!(s, "MemAvailable: {:>10} kB", free_kb);
    let _ = writeln!(s, "Buffers:      {:>10} kB", 0);
    let _ = writeln!(s, "Cached:       {:>10} kB", 0);
    let _ = writeln!(s, "Reserved:     {:>10} kB", reserved_kb);
    s
}

fn gen_mounts() -> String {
    let mut s = String::new();
    for (path, fs_name) in crate::registry().list_with_names() {
        let _ = core::fmt::Write::write_fmt(
            &mut s,
            format_args!("none {} {} rw 0 0\n", path, fs_name),
        );
    }
    s
}

fn gen_cmdline() -> String {
    let mut s = String::from(narf_boot::cmdline());
    s.push('\n');
    s
}

fn gen_loadavg() -> String {
    // Linux format: "0.00 0.00 0.00 1/1 1\n"
    //   1/5/15-min averages | runnable/total | last_pid
    // We don't track EWMA averages today; report the same
    // instantaneous total task count for all three slots so the
    // standard parsers (`uptime`, `top`, `glibc::getloadavg`)
    // produce a meaningful number rather than zeros. last_pid is
    // approximated by the number of live tasks.
    let n = narf_scheduler::all_task_ids().len();
    format!("{n}.00 {n}.00 {n}.00 {n}/{n} {n}\n")
}

fn gen_filesystems() -> String {
    use alloc::collections::BTreeSet;
    use core::fmt::Write as _;
    // Distinct fs.name() values from currently-mounted instances.
    // Linux's /proc/filesystems prefixes "nodev" for FS types that
    // can't back a block device; our mount surface doesn't track
    // that today, so omit the prefix — bare `mount` (no -t) only
    // checks for the FS-type token.
    let names: BTreeSet<String> = crate::registry()
        .list_with_names()
        .into_iter()
        .map(|(_p, n)| n)
        .collect();
    let mut s = String::new();
    for n in names {
        let _ = writeln!(s, "\t{}", n);
    }
    s
}

fn gen_partitions() -> String {
    use core::fmt::Write as _;
    // Linux format:
    //   major minor  #blocks  name
    // We don't have a major/minor allocator (no devnode space yet),
    // so report 0/N for major and the registry index for minor.
    // #blocks is capacity_kb, derived from capacity * lba_size.
    let mut s = String::from("major minor  #blocks  name\n");
    for (i, dev) in narf_block::block_devices().iter().enumerate() {
        let bytes = dev.dev.capacity().saturating_mul(dev.dev.lba_size() as u64);
        let kb = bytes / 1024;
        let _ = writeln!(s, "    0  {:>4}  {:>10}  {}", i, kb, dev.name);
    }
    s
}

fn gen_uptime() -> String {
    let now_ns = narf_time::monotonic_ns();
    let seconds = now_ns / 1_000_000_000;
    let frac_centi = (now_ns / 10_000_000) % 100;
    format!("{}.{:02} 0.00\n", seconds, frac_centi)
}

fn gen_version() -> String {
    String::from(concat!(
        "NARF kernel ",
        env!("CARGO_PKG_VERSION"),
        " (microkernel)\n",
    ))
}

// ── Per-pid renderers ───────────────────────────────────────────

fn render_stat(info: &ProcTaskInfo) -> String {
    // Linux /proc/[pid]/stat has 52 space-separated fields. We
    // populate the leading positions that real readers (ps, top,
    // glibc's getproctitle, /usr/bin/uptime) actually consume.
    // Fields:
    //   pid (comm) state ppid pgrp session tty_nr tpgid flags
    //   minflt cminflt majflt cmajflt utime stime cutime cstime
    //   priority nice num_threads itrealvalue starttime vsize rss
    //   ...  — we fill the first 23 with sensible values and pad.
    format!(
        "{} ({}) {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0\n",
        info.pid, info.comm, info.state,
    )
}

fn render_status(info: &ProcTaskInfo) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Name:\t{}\n", info.comm));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("State:\t{} ({})\n",
        info.state,
        match info.state {
            'R' => "running",
            'S' => "sleeping",
            'Z' => "zombie",
            _ => "unknown",
        },
    ));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Pid:\t{}\n", info.pid));
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmStk:\t{} kB\n", info.stack_top / 1024),
    );
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmData:\t{} kB\n", info.brk_top / 1024),
    );
    s
}

fn render_maps(info: &ProcTaskInfo) -> String {
    // Linux /proc/[pid]/maps shape:
    //   start-end perms offset dev:major:minor inode pathname
    // We omit dev:major:minor (NARF doesn't yet model per-VMA
    // backing files); pathname slot carries our label or empty.
    let mut s = String::new();
    for v in info.vmas.iter() {
        let r = if v.readable { 'r' } else { '-' };
        let w = if v.writable { 'w' } else { '-' };
        let x = if v.executable { 'x' } else { '-' };
        let p = if v.shared { 's' } else { 'p' };
        let _ = core::fmt::Write::write_fmt(
            &mut s,
            format_args!(
                "{:016x}-{:016x} {}{}{}{} 00000000 00:00 0",
                v.start, v.end, r, w, x, p,
            ),
        );
        if !v.label.is_empty() {
            let _ = core::fmt::Write::write_fmt(
                &mut s,
                format_args!("          {}", v.label),
            );
        }
        s.push('\n');
    }
    s
}
