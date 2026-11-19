//! `/proc/kallsyms` kernel tests: format, order, perf's reference symbols,
//! the address rule per `kptr_restrict`, and the open-time credential rule.
//!
//! Every case opens the file the way `sys_open` does — `/proc` root lookup,
//! then `open_instance_checked` — so the per-open path is what is tested,
//! not the registry adapter. The opener's privilege is driven through the
//! `caller_capable` hook, which is the question the open path asks; the
//! syscall-level twin with real credentials is
//! `userspace/src/abi_kallsyms_tests.rs`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_observability::kallsyms as ksyms;

use super::{kallsyms_show_value, CAP_SYSLOG};
use crate::procfs::sys_kernel::{KPTR_RESTRICT, KPTR_RESTRICT_DEFAULT};
use crate::{DirOps, FileOps};

/// Restores the three inputs of `kallsyms_show_value` on drop, so a failing
/// case cannot leave the kernel exposing (or hiding) addresses for the next.
struct Policy {
    hook: Option<fn(u32) -> bool>,
    paranoid: i32,
}

impl Drop for Policy {
    fn drop(&mut self) {
        crate::__test_swap_caller_capable_hook(self.hook);
        KPTR_RESTRICT.store(KPTR_RESTRICT_DEFAULT, Ordering::Release);
        set_paranoid(self.paranoid);
    }
}

fn set_paranoid(v: i32) {
    let f = super::super::lookup_registry(&["sys", "kernel", "perf_event_paranoid"]);
    if let Some(super::super::ProcNodeSnapshot::File(f)) = f {
        let _ = f.write(alloc::format!("{v}\n").as_bytes());
    }
}

fn privileged(cap: u32) -> bool {
    cap == CAP_SYSLOG
}
fn unprivileged(_cap: u32) -> bool {
    false
}

/// Set the policy; the returned guard puts the boot values back.
fn policy(kptr: u32, paranoid: i32, hook: fn(u32) -> bool) -> Policy {
    crate::procfs::sys_kernel::register_all();
    super::register_all();
    let guard = Policy {
        hook: crate::__test_swap_caller_capable_hook(Some(hook)),
        paranoid: crate::procfs::sys_kernel::perf_event_paranoid(),
    };
    KPTR_RESTRICT.store(kptr, Ordering::Release);
    set_paranoid(paranoid);
    guard
}

fn set_hook(hook: fn(u32) -> bool) {
    crate::__test_swap_caller_capable_hook(Some(hook));
}

/// `open("/proc/kallsyms", O_RDONLY)` as `sys_open` performs it.
fn open() -> Result<Arc<dyn FileOps>, &'static str> {
    let node = super::super::ProcRoot
        .lookup("kallsyms")
        .ok_or("/proc/kallsyms does not exist")?;
    match node.open_instance_checked(false) {
        Ok(Some(f)) => Ok(f),
        Ok(None) => Err("/proc/kallsyms open did not mint a per-open file"),
        Err(_) => Err("/proc/kallsyms open failed"),
    }
}

fn read_at(f: &dyn FileOps, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
    match super::super::poll_once(f.read(offset, buf)) {
        Some(Ok(n)) => Ok(n),
        Some(Err(_)) => Err("read failed"),
        None => Err("read did not complete"),
    }
}

/// Read `f` from 0 with `chunk`-sized reads, stopping after `limit` bytes.
/// A read cut short by the limit is trimmed to its last complete line.
fn read_upto(f: &dyn FileOps, chunk: usize, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; chunk];
    while out.len() < limit {
        let n = read_at(f, out.len() as u64, &mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
    let complete = out.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    out.truncate(complete);
    Ok(out)
}

/// One parsed line.
struct Line<'a> {
    addr: u64,
    kind: u8,
    name: &'a str,
}

/// Parse one `%px %c %s` line (without its newline) strictly.
fn parse_line(line: &[u8]) -> Result<Line<'_>, &'static str> {
    let line = core::str::from_utf8(line).map_err(|_| "/proc/kallsyms is not UTF-8")?;
    let b = line.as_bytes();
    if b.len() < 20 || b[16] != b' ' || b[18] != b' ' {
        return Err("line is not `%px %c %s`");
    }
    if !b[..16]
        .iter()
        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("address is not 16 lowercase hex digits");
    }
    if !b[17].is_ascii_alphabetic() {
        return Err("type is not an nm letter");
    }
    let name = &line[19..];
    if name.len() > ksyms::MAX_NAME || name.contains('\t') {
        return Err("name too long, or carries a module tab");
    }
    Ok(Line {
        addr: u64::from_str_radix(&line[..16], 16).map_err(|_| "bad hex")?,
        kind: b[17],
        name,
    })
}

/// Parse a buffer of complete lines.
fn parse(body: &[u8]) -> Result<Vec<Line<'_>>, &'static str> {
    if !body.is_empty() && body.last() != Some(&b'\n') {
        return Err("/proc/kallsyms does not end with a newline");
    }
    body.split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(parse_line)
        .collect()
}

/// Stream the WHOLE file through `visit`, one parsed line at a time, in
/// 64 KiB reads. A full image's file is ~40 MB — more than a test guest's
/// heap can hold at once — so nothing here keeps more than one read plus a
/// partial line. Returns the number of lines.
fn for_each_line(
    f: &dyn FileOps,
    mut visit: impl FnMut(&Line<'_>) -> Result<(), &'static str>,
) -> Result<usize, &'static str> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut carry: Vec<u8> = Vec::new();
    let mut offset = 0u64;
    let mut lines = 0;
    loop {
        let n = read_at(f, offset, &mut buf)?;
        if n == 0 {
            break;
        }
        offset += n as u64;
        let mut rest = &buf[..n];
        while let Some(i) = rest.iter().position(|&b| b == b'\n') {
            if carry.is_empty() {
                visit(&parse_line(&rest[..i])?)?;
            } else {
                // The line began in the previous read.
                carry.extend_from_slice(&rest[..i]);
                let line = core::mem::take(&mut carry);
                visit(&parse_line(&line)?)?;
            }
            lines += 1;
            rest = &rest[i + 1..];
        }
        carry.extend_from_slice(rest);
        if carry.len() > 16 + 3 + ksyms::MAX_NAME {
            return Err("a /proc/kallsyms line is longer than the format allows");
        }
    }
    if !carry.is_empty() {
        return Err("/proc/kallsyms does not end with a newline");
    }
    Ok(lines)
}

fn table() -> Result<ksyms::Table<'static>, &'static str> {
    ksyms::table().map_err(|_| {
        "the image carries no kernel symbol table — was it built without xtask's kallsyms patch?"
    })
}

fn outcome(r: Result<(), &'static str>) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

/// Format, completeness and order, privileged; plus perf's reference
/// relocation symbols and a known function's address — one streamed pass,
/// because a pass over a full image's file is the expensive part.
///
/// * every line is `%px %c %s`, one per table symbol, ascending, none below
///   `_text`, with text, data, rodata and bss letters all present;
/// * `_text` carries a function letter (`kallsyms__get_function_start`
///   ignores anything else) at the runtime `_text`, which is the lowest
///   address; `_stext`, `_etext` and `_edata` are present and ordered;
/// * the slide the table implies is the KASLR slide in force;
/// * `kallsyms_probe_target` is listed under its `nm -C` name at its
///   runtime address, and `lookup` maps an address inside it back to it.
fn smoke_proc_kallsyms_format_order_and_addresses() -> TestResult {
    let _p = policy(1, 2, privileged);
    outcome((|| {
        let t = table()?;
        let base = ksyms::text_base();
        const PROBE: &str = "narf_filesystem::procfs::kallsyms::tests::kallsyms_probe_target";
        let probe = kallsyms_probe_target as usize as u64;
        if kallsyms_probe_target() != 0x6b61_6c6c_7379_6d73 {
            return Err("probe target miscompiled");
        }

        let mut prev = 0u64;
        let mut first = None;
        let mut kinds = [false; 4]; // text, data, rodata, bss
        let (mut text, mut stext, mut etext, mut edata) = (None, None, None, None);
        let mut probe_line = None;
        let n = for_each_line(&*open()?, |l| {
            if l.addr < prev {
                return Err("/proc/kallsyms is not sorted by address");
            }
            prev = l.addr;
            if l.addr < base {
                return Err("a symbol lies below _text");
            }
            first.get_or_insert(l.addr);
            match l.kind {
                b'T' | b't' => kinds[0] = true,
                b'D' | b'd' => kinds[1] = true,
                b'R' | b'r' => kinds[2] = true,
                b'B' | b'b' => kinds[3] = true,
                _ => {}
            }
            match l.name {
                "_text" => text = Some((l.addr, l.kind)),
                "_stext" => stext = Some(l.addr),
                "_etext" => etext = Some(l.addr),
                "_edata" => edata = Some(l.addr),
                PROBE => probe_line = Some((l.addr, l.kind)),
                _ => {}
            }
            Ok(())
        })?;

        if n != t.len() || n == 0 {
            return Err("/proc/kallsyms line count differs from the table");
        }
        if kinds.iter().any(|seen| !seen) {
            return Err("missing text, data, rodata or bss symbols");
        }
        let (text, kind) = text.ok_or("no _text")?;
        if !matches!(kind, b'T' | b't') {
            return Err("_text is not a text symbol; perf skips it");
        }
        if text != base {
            return Err("_text does not print its runtime address");
        }
        if first != Some(text) {
            return Err("_text is not the lowest address");
        }
        let (stext, etext, edata) = (
            stext.ok_or("no _stext")?,
            etext.ok_or("no _etext")?,
            edata.ok_or("no _edata")?,
        );
        if stext != text || etext <= text || edata <= etext {
            return Err("_stext/_etext/_edata are not ordered around _text");
        }
        let slide = narf_memory::kaslr::KERNEL_SLIDE.load(Ordering::Relaxed);
        if base.wrapping_sub(t.text_link()) != slide {
            return Err("runtime _text minus the table's link-time _text is not the KASLR slide");
        }

        let (addr, kind) =
            probe_line.ok_or("the probe function is not listed under its demangled name")?;
        if addr != probe {
            return Err("the probe function's printed address is not its runtime address");
        }
        if !matches!(kind, b't' | b'T') {
            return Err("the probe function is not a text symbol");
        }
        let mut name = ksyms::NameBuf::new();
        let (_, off, _) = ksyms::lookup(probe + 1, &mut name).ok_or("lookup missed")?;
        if name.as_str() != Some(PROBE) || off != 1 {
            return Err("lookup did not resolve inside the probe function");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "filesystem/procfs/kallsyms",
    smoke_proc_kallsyms_format_order_and_addresses
);

/// A function the test can name and take the address of. Distinct body so
/// LLVM cannot merge it with another function.
#[inline(never)]
fn kallsyms_probe_target() -> u64 {
    core::hint::black_box(0x6b61_6c6c_7379_6d73)
}

/// `kallsyms_show_value`'s matrix, and the file honouring it: when values
/// are hidden EVERY address is zero, while names and types stay visible.
fn smoke_proc_kallsyms_zero_unless_allowed() -> TestResult {
    // (kptr_restrict, perf_event_paranoid, opener holds CAP_SYSLOG, shown)
    const CASES: &[(u32, i32, bool, bool)] = &[
        (0, -1, false, true), // kallsyms_for_perf
        (0, 1, false, true),
        (0, 2, false, false), // paranoid: falls through to CAP_SYSLOG
        (0, 2, true, true),
        (1, -1, false, false), // the perf allowance stops at 0
        (1, 2, true, true),
        (2, -1, true, false), // never
        (2, 2, true, false),
    ];
    outcome((|| {
        let reference: Vec<(u8, String)> = {
            let _p = policy(1, 2, privileged);
            let body = read_upto(&*open()?, 16 * 1024, 64 * 1024)?;
            parse(&body)?
                .iter()
                .map(|l| (l.kind, String::from(l.name)))
                .collect()
        };
        for &(kptr, paranoid, cap, shown) in CASES {
            let hook: fn(u32) -> bool = if cap { privileged } else { unprivileged };
            let _p = policy(kptr, paranoid, hook);
            if kallsyms_show_value(|| crate::caller_capable(CAP_SYSLOG)) != shown {
                return Err("kallsyms_show_value disagrees with Linux's matrix");
            }
            let body = read_upto(&*open()?, 16 * 1024, 64 * 1024)?;
            let lines = parse(&body)?;
            if lines.is_empty() || lines.len() != reference.len() {
                return Err("the privileged and unprivileged files differ in shape");
            }
            let nonzero = lines.iter().filter(|l| l.addr != 0).count();
            if shown && nonzero != lines.len() {
                return Err("a privileged reader saw a zero address");
            }
            if !shown && nonzero != 0 {
                return Err("an unprivileged reader saw a kernel address");
            }
            // Names and types are not secret, and must not change.
            for (l, (k, n)) in lines.iter().zip(&reference) {
                if l.kind != *k || l.name != n {
                    return Err("names or types changed with the reader's privilege");
                }
            }
        }
        // And the whole file, not a prefix, for a hidden case: not one
        // address anywhere.
        let _p = policy(2, 2, privileged);
        let n = for_each_line(&*open()?, |l| {
            if l.addr != 0 {
                Err("kptr_restrict=2 leaked an address somewhere in the file")
            } else {
                Ok(())
            }
        })?;
        if n != table()?.len() {
            return Err("the hidden file does not list every symbol");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "filesystem/procfs/kallsyms",
    smoke_proc_kallsyms_zero_unless_allowed
);

/// The decision belongs to the OPENER: a descriptor opened privileged keeps
/// showing addresses after the privilege goes; one opened unprivileged stays
/// zero after it arrives (`kallsyms_open` caches `file->f_cred`'s answer).
fn smoke_proc_kallsyms_opener_credentials_fixed_at_open() -> TestResult {
    let _p = policy(1, 2, privileged);
    outcome((|| {
        let opened_privileged = open()?;
        set_hook(unprivileged);
        let opened_unprivileged = open()?;
        // Read the privileged one now, unprivileged.
        let a = read_upto(&*opened_privileged, 4096, 16 * 1024)?;
        set_hook(privileged);
        // And the unprivileged one now, privileged.
        let b = read_upto(&*opened_unprivileged, 4096, 16 * 1024)?;
        let a = parse(&a)?;
        let b = parse(&b)?;
        if a.is_empty() || a.iter().any(|l| l.addr == 0) {
            return Err("dropping privilege after open hid addresses from a privileged fd");
        }
        if b.is_empty() || b.iter().any(|l| l.addr != 0) {
            return Err(
                "gaining privilege after open revealed addresses through an unprivileged fd",
            );
        }
        Ok(())
    })())
}
kernel_test_in!(
    "filesystem/procfs/kallsyms",
    smoke_proc_kallsyms_opener_credentials_fixed_at_open
);

/// Streaming: odd-sized sequential reads, a pread at an arbitrary offset, a
/// rewind and a read past the end all agree with one large read.
fn smoke_proc_kallsyms_reads_are_offset_exact() -> TestResult {
    let _p = policy(1, 2, privileged);
    outcome((|| {
        let f = open()?;
        let whole = read_upto(&*f, 64 * 1024, 256 * 1024)?;
        if whole.len() < 128 * 1024 {
            return Err("/proc/kallsyms is implausibly short");
        }
        let g = open()?;
        let small = read_upto(&*g, 7, 9000)?;
        if small.is_empty() || small[..] != whole[..small.len()] {
            return Err("7-byte reads disagree with one large read");
        }
        let mut buf = [0u8; 1000];
        let at = 123_457usize;
        let n = read_at(&*g, at as u64, &mut buf)?;
        if n != buf.len() || buf[..] != whole[at..at + n] {
            return Err("pread at an arbitrary offset disagrees");
        }
        // Rewind behind the cursor.
        let n = read_at(&*g, 10, &mut buf)?;
        if n == 0 || buf[..n] != whole[10..10 + n] {
            return Err("a read behind the cursor disagrees");
        }
        if read_at(&*g, u64::MAX / 2, &mut buf)? != 0 {
            return Err("a read past the end returned data");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "filesystem/procfs/kallsyms",
    smoke_proc_kallsyms_reads_are_offset_exact
);
