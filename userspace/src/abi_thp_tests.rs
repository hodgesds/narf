//! Linux syscall ABI conformance — the transparent-hugepage sysfs knobs.
//!
//! CachyOS ships `/usr/lib/tmpfiles.d/thp.conf`
//! (`w! /sys/kernel/mm/transparent_hugepage/defrag - - - - defer+madvise`)
//! and `thp-shrinker.conf`
//! (`w! /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none - - - - 409`).
//! Both files were read-only on NARF, so systemd-tmpfiles failed with
//! "Failed to write file ...: Read-only file system". On Linux they are
//! 0644 attributes whose store functions (`mm/huge_memory.c::defrag_store`,
//! `enabled_store`, `mm/khugepaged.c::max_ptes_none_store`, ...) accept a
//! fixed vocabulary and answer -EINVAL for anything else.

use crate::abi_test_support::*;

const THP: &str = "/sys/kernel/mm/transparent_hugepage/";

fn path_of(name: &str) -> alloc::vec::Vec<u8> {
    let mut p = alloc::vec::Vec::from(THP.as_bytes());
    p.extend_from_slice(name.as_bytes());
    p.push(0);
    p
}

/// Make sure `/sys/kernel/mm/transparent_hugepage` exists.
///
/// Boot populates it, but the filesystem sysfs smokes run earlier in the same
/// kernel image and call `sysfs::__reset_for_test()`, rebuilding only the
/// part of the tree each case needs; the last one leaves no `kernel/mm`, and
/// every open below would be ENOENT. `populate_kernel_dir` is idempotent
/// (`get_or_create_child`), so on an intact tree this changes nothing.
fn thp_fixture() {
    narf_filesystem::sysfs::populate_kernel_dir();
}

/// open(O_WRONLY) + write(value), as systemd's write_string_file does.
fn write_knob(name: &str, value: &[u8]) -> Option<i64> {
    let path = path_of(name);
    let fd = call_open(path.as_ptr() as u64, 0o1)?;
    if fd < 0 {
        return Some(fd);
    }
    let r = call(
        Syscall::Write.raw(),
        a2(fd as u64, value.as_ptr() as u64, value.len() as u64),
    );
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
    r
}

fn read_knob(name: &str) -> Option<alloc::string::String> {
    let path = path_of(name);
    let fd = call_open(path.as_ptr() as u64, 0)?;
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    let n = call(
        Syscall::Read.raw(),
        a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
    );
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
    let n = usize::try_from(n?).ok()?;
    core::str::from_utf8(&buf[..n])
        .ok()
        .map(alloc::string::String::from)
}

/// Every value tmpfiles and admins write is accepted, lands, and reads
/// back in Linux's bracketed / numeric form.
fn smoke_abi_thp_knobs_writable_pos() -> TestResult {
    with_setup(|| {
        thp_fixture();
        let restore = |r: Result<(), &'static str>| {
            let _ = write_knob("defrag", b"never\n");
            let _ = write_knob("enabled", b"never\n");
            let _ = write_knob("khugepaged/max_ptes_none", b"511\n");
            r
        };
        if write_knob("defrag", b"defer+madvise\n") != Some(14) {
            return restore(Err("writing defer+madvise to THP defrag must succeed"));
        }
        if read_knob("defrag").as_deref() != Some("always defer [defer+madvise] madvise never\n") {
            return restore(Err("defrag must read back [defer+madvise]"));
        }
        for (value, shown) in [
            (
                &b"always"[..],
                "[always] defer defer+madvise madvise never\n",
            ),
            (b"defer", "always [defer] defer+madvise madvise never\n"),
            (b"never\n", "always defer defer+madvise madvise [never]\n"),
            (b"madvise", "always defer defer+madvise [madvise] never\n"),
        ] {
            if write_knob("defrag", value) != Some(value.len() as i64)
                || read_knob("defrag").as_deref() != Some(shown)
            {
                return restore(Err("a Linux defrag policy did not round-trip"));
            }
        }
        if write_knob("enabled", b"madvise\n") != Some(8)
            || read_knob("enabled").as_deref() != Some("always [madvise] never\n")
        {
            return restore(Err("enabled=madvise did not round-trip"));
        }
        if write_knob("khugepaged/max_ptes_none", b"409\n") != Some(4)
            || read_knob("khugepaged/max_ptes_none").as_deref() != Some("409\n")
        {
            return restore(Err("khugepaged/max_ptes_none=409 did not round-trip"));
        }
        if write_knob("khugepaged/pages_to_scan", b"+4096\n") != Some(6)
            || write_knob("use_zero_page", b"1") != Some(1)
            || write_knob("shrink_underused", b"off\n") != Some(4)
            || read_knob("shrink_underused").as_deref() != Some("0\n")
            || write_knob("shrink_underused", b"Y") != Some(1)
        {
            return restore(Err("a numeric/bool THP knob refused a Linux-valid value"));
        }
        if read_knob("hpage_pmd_size").as_deref() != Some("2097152\n") {
            return restore(Err("hpage_pmd_size must be 2097152"));
        }
        restore(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_thp_knobs_writable_pos);

/// The store functions' -EINVAL cases, and a refused write changes
/// nothing.
fn smoke_abi_thp_knobs_reject_neg() -> TestResult {
    with_setup(|| {
        thp_fixture();
        let before = read_knob("defrag");
        for bad in [&b"bogus"[..], b"defer+madvise\n\n", b" never", b"Never"] {
            if write_knob("defrag", bad) != Some(EINVAL) {
                return Err("defrag must refuse a value outside its vocabulary with EINVAL");
            }
        }
        if read_knob("defrag") != before {
            return Err("a refused defrag write changed the policy");
        }
        if write_knob("enabled", b"sometimes") != Some(EINVAL) {
            return Err("enabled must refuse an unknown policy with EINVAL");
        }
        for bad in [&b"512"[..], b"-1", b"12abc", b"\n", b"0x10"] {
            if write_knob("khugepaged/max_ptes_none", bad) != Some(EINVAL) {
                return Err("max_ptes_none must refuse >511 / non-decimal with EINVAL");
            }
        }
        if write_knob("khugepaged/pages_to_scan", b"0") != Some(EINVAL) {
            return Err("pages_to_scan=0 must be EINVAL");
        }
        if write_knob("use_zero_page", b"2") != Some(EINVAL) {
            return Err("use_zero_page=2 must be EINVAL");
        }
        if write_knob("shrink_underused", b"maybe") != Some(EINVAL) {
            return Err("shrink_underused must refuse a non-boolean with EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_thp_knobs_reject_neg);
