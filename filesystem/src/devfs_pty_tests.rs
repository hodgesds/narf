//! Smoke tests for `/dev/ptmx`, `/dev/pts/<N>`, and `/dev/full`.
//!
//! These run under the NARF kernel-test harness via `kernel_test_in!`.
//! All tests are synchronous (poll-once) because the PTY ring ops are
//! non-blocking by design in v1.

extern crate alloc;

use alloc::sync::Arc;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::devfs_misc::DevFull;
use crate::devfs_pty::{open_ptmx, pts_lookup, DevPts, PtySlave, __reset_for_test};
use crate::{DirOps, FileOps, FsError};

// ── Helper ────────────────────────────────────────────────────────────────────

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    unsafe fn no_clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    unsafe fn no_op(_: *const ()) {}
    fn raw_waker() -> RawWaker {
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: the RawWaker's vtable (no_clone/no_op) never dereferences the
    // null data pointer and the clone fn returns an equivalently-valid waker,
    // so this RawWaker upholds the Waker contract.
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is owned by this function and never moved again after this
    // line (it is only polled through `pinned`), so pinning it in place is sound.
    // SAFETY: Valid memory or trusted environment
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Test 1: open /dev/ptmx returns a master ───────────────────────────────────

fn smoke_pty_ptmx_open_returns_master() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let stat = master.stat();
    // index is encoded in stat.size
    if stat.size > 1_000_000 {
        return TestResult::Fail("ptmx stat.size (index) unreasonably large");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_ptmx_open_returns_master);

// ── Test 2: master write → slave read (master_tx_to_slave) ───────────────────

fn smoke_pty_master_write_slave_read() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    // Put a complete line into master_tx_to_slave via master write.
    let msg = b"hello\n";
    let w = poll_once(master.write(0, msg));
    if !matches!(w, Some(Ok(6))) {
        return TestResult::Fail("master write didn't return 6");
    }

    // Slave read with ICANON on should return the whole line.
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None after ptmx open"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));
    let mut buf = [0u8; 16];
    let r = poll_once(slave.read(0, &mut buf));
    match r {
        Some(Ok(n)) if n == 6 => {
            if &buf[..n] != b"hello\n" {
                return TestResult::Fail("slave read returned wrong bytes");
            }
        }
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("slave read returned wrong count");
        }
        _ => return TestResult::Fail("slave read failed"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_master_write_slave_read);

// ── Test 3: slave write → master read (slave_tx_to_master) ───────────────────

fn smoke_pty_slave_write_master_read() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // Slave writes to slave_tx_to_master.
    let w = poll_once(slave.write(0, b"world"));
    if !matches!(w, Some(Ok(5))) {
        return TestResult::Fail("slave write didn't return 5");
    }

    // Master reads from slave_tx_to_master.
    let mut buf = [0u8; 16];
    let r = poll_once(master.read(0, &mut buf));
    match r {
        Some(Ok(n)) if n == 5 => {
            if &buf[..n] != b"world" {
                return TestResult::Fail("master read returned wrong bytes");
            }
        }
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("master read wrong count");
        }
        _ => return TestResult::Fail("master read failed"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_slave_write_master_read);

// ── Test 4: /dev/pts/<N> appears in DevPts after ptmx open ───────────────────

fn smoke_pty_pts_dir_lists_open_ptys() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    let dir = DevPts;
    let entries = dir.enumerate(0, 64);
    let found = entries
        .iter()
        .any(|(name, _)| name.parse::<u32>().ok() == Some(idx));
    if !found {
        return TestResult::Fail("/dev/pts did not list newly-opened PTY");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_pts_dir_lists_open_ptys);

// ── Test 5: /dev/pts/<N> disappears after master drop ────────────────────────

fn smoke_pty_pts_disappears_after_master_drop() -> TestResult {
    __reset_for_test();
    let idx = {
        let master = open_ptmx();
        master.index()
        // master dropped here → ptmx_close() removes from PTY_TABLE
    };

    let dir = DevPts;
    let entries = dir.enumerate(0, 64);
    let found = entries
        .iter()
        .any(|(name, _)| name.parse::<u32>().ok() == Some(idx));
    if found {
        return TestResult::Fail("/dev/pts still lists PTY after master drop");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_pts_disappears_after_master_drop);

// ── Test 6: slave read with ICANON blocks until newline ───────────────────────
//
// In NARF's non-blocking model "blocks" means returns 0 bytes when no
// complete line is available.  This test verifies that behaviour.

fn smoke_pty_slave_icanon_blocks_until_newline() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // Write bytes without a newline.
    poll_once(master.write(0, b"partial"));

    // Slave read with ICANON on should return 0 (no complete line yet).
    let mut buf = [0u8; 16];
    let r = poll_once(slave.read(0, &mut buf));
    if !matches!(r, Some(Ok(0))) {
        return TestResult::Fail("slave ICANON read returned bytes before newline");
    }

    // Now add a newline — slave read should return the full line.
    poll_once(master.write(0, b"\n"));
    let r2 = poll_once(slave.read(0, &mut buf));
    match r2 {
        Some(Ok(n)) if n == 8 => {
            if &buf[..n] != b"partial\n" {
                return TestResult::Fail("slave ICANON read returned wrong bytes");
            }
        }
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("slave ICANON read returned wrong count after newline");
        }
        _ => return TestResult::Fail("slave read failed after newline"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_slave_icanon_blocks_until_newline
);

// ── Test 7: ECHO — slave write sends copy to master ──────────────────────────

fn smoke_pty_slave_echo_to_master() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed"),
    };
    // Verify ECHO is on by default.
    {
        let t = slave_arc.termios.lock();
        if !t.echo() {
            return TestResult::Fail("ECHO not on by default");
        }
    }

    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // Slave writes — this should push to slave_tx_to_master.
    poll_once(slave.write(0, b"echo-test"));

    // Master reads what slave wrote.
    let mut buf = [0u8; 32];
    let r = poll_once(master.read(0, &mut buf));
    match r {
        Some(Ok(n)) if n == 9 => {
            if &buf[..n] != b"echo-test" {
                return TestResult::Fail("echo bytes mismatch");
            }
        }
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("echo read wrong count");
        }
        _ => return TestResult::Fail("echo master read failed"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_slave_echo_to_master);

// ── Test 8: /dev/full read returns zeros ─────────────────────────────────────

fn smoke_pty_full_read_returns_zeros() -> TestResult {
    let full = DevFull;
    let mut buf = [0xAAu8; 16];
    let r = poll_once(full.read(0, &mut buf));
    if !matches!(r, Some(Ok(16))) {
        return TestResult::Fail("/dev/full read didn't return 16");
    }
    if buf.iter().any(|&b| b != 0) {
        return TestResult::Fail("/dev/full read didn't zero-fill");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_full_read_returns_zeros);

// ── Test 9: /dev/full write returns NoSpace ───────────────────────────────────

fn smoke_pty_full_write_returns_nospace() -> TestResult {
    let full = DevFull;
    let r = poll_once(full.write(0, b"data"));
    if !matches!(r, Some(Err(FsError::NoSpace))) {
        return TestResult::Fail("/dev/full write didn't return NoSpace");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_full_write_returns_nospace);

// ── Test 10: two concurrent ptmx opens allocate different indices ─────────────

fn smoke_pty_two_opens_different_indices() -> TestResult {
    __reset_for_test();
    let m1 = open_ptmx();
    let m2 = open_ptmx();
    let i1 = m1.index();
    let i2 = m2.index();
    if i1 == i2 {
        return TestResult::Fail("two ptmx opens got the same index");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_two_opens_different_indices);

// ── Test 11: /dev/ptmx reachable via DevDir lookup ───────────────────────────

fn smoke_pty_ptmx_reachable_via_devdir() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs};
    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    let ptmx = registry()
        .resolve_absolute("/dev/ptmx", |fs, rel| crate::resolve(fs.root(), rel).ok())
        .flatten();
    if ptmx.is_none() {
        return TestResult::Fail("resolve /dev/ptmx returned None");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_ptmx_reachable_via_devdir);

// ── Test 12: /dev/full reachable via DevDir lookup ────────────────────────────

fn smoke_pty_full_reachable_via_devdir() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs};
    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    let full = registry()
        .resolve_absolute("/dev/full", |fs, rel| crate::resolve(fs.root(), rel).ok())
        .flatten();
    if full.is_none() {
        return TestResult::Fail("resolve /dev/full returned None");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_full_reachable_via_devdir);

// ── Test 13: ^D (EOF) on slave read ──────────────────────────────────────────

fn smoke_pty_slave_ctrl_d_eof() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed"),
    };
    let slave = PtySlave::new(slave_arc);

    // Write ^D to master_tx_to_slave.
    poll_once(master.write(0, &[0x04u8]));

    // Slave read should return 0 (EOF).
    let mut buf = [0u8; 8];
    let r = poll_once(slave.read(0, &mut buf));
    if !matches!(r, Some(Ok(0))) {
        return TestResult::Fail("^D should signal EOF (return 0) on slave read");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_slave_ctrl_d_eof);

// ── Wave-76: ioctls ───────────────────────────────────────────────────────────
//
// On the kernel-test path the "user pointer" is just a kernel-owned
// scratch slot; `copy_in`/`copy_out` reduce to plain ptr ops.

#[cfg(feature = "linux-compat")]
fn smoke_pty_master_tiocgptn_returns_index() -> TestResult {
    use crate::devfs_pty::TIOCGPTN;
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let mut scratch: u32 = 0xDEAD_BEEF;
    let arg = &mut scratch as *mut u32 as usize;
    if master.ioctl(TIOCGPTN, arg) != Ok(0) {
        return TestResult::Fail("TIOCGPTN did not return Ok(0)");
    }
    if scratch != idx {
        return TestResult::Fail("TIOCGPTN did not write the slave index");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_master_tiocgptn_returns_index);

#[cfg(feature = "linux-compat")]
fn smoke_pty_slave_locked_until_tiocsptlck_clear() -> TestResult {
    use crate::devfs_pty::TIOCSPTLCK;
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    // Locked-by-default: DevPts::lookup must NOT return the slave.
    let dir = DevPts;
    let mut tmp = [0u8; 10];
    let digits = {
        let mut n = idx;
        if n == 0 {
            tmp[9] = b'0';
            // SAFETY: tmp[9..] contains only ASCII digit bytes written above.
            unsafe { core::str::from_utf8_unchecked(&tmp[9..]) }
        } else {
            let mut pos = 10;
            while n > 0 {
                pos -= 1;
                tmp[pos] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            // SAFETY: tmp[pos..] contains only ASCII digit bytes written in the loop above.
            unsafe { core::str::from_utf8_unchecked(&tmp[pos..]) }
        }
    };
    if dir.lookup(digits).is_some() {
        return TestResult::Fail("locked slave appeared in DevPts::lookup");
    }

    // Clear lock.
    let mut zero: i32 = 0;
    let arg = &mut zero as *mut i32 as usize;
    if master.ioctl(TIOCSPTLCK, arg) != Ok(0) {
        return TestResult::Fail("TIOCSPTLCK(0) failed");
    }
    if dir.lookup(digits).is_none() {
        return TestResult::Fail("slave still hidden after TIOCSPTLCK(0)");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_slave_locked_until_tiocsptlck_clear
);

#[cfg(feature = "linux-compat")]
fn smoke_pty_per_tty_fg_pgrp_isolated() -> TestResult {
    use crate::devfs_pty::{TIOCGPGRP, TIOCSPGRP};
    __reset_for_test();
    let m1 = open_ptmx();
    let m2 = open_ptmx();

    let mut p1: i32 = 111;
    let mut p2: i32 = 222;
    if m1.ioctl(TIOCSPGRP, &mut p1 as *mut i32 as usize).is_err() {
        return TestResult::Fail("TIOCSPGRP on m1 failed");
    }
    if m2.ioctl(TIOCSPGRP, &mut p2 as *mut i32 as usize).is_err() {
        return TestResult::Fail("TIOCSPGRP on m2 failed");
    }
    let mut got1: i32 = 0;
    let mut got2: i32 = 0;
    let _ = m1.ioctl(TIOCGPGRP, &mut got1 as *mut i32 as usize);
    let _ = m2.ioctl(TIOCGPGRP, &mut got2 as *mut i32 as usize);
    if got1 != 111 || got2 != 222 {
        return TestResult::Fail("per-tty fg_pgrp slots leaked across PTYs");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_per_tty_fg_pgrp_isolated);

// Master fg_pgrp and slave fg_pgrp share the *same* `Pty.fg_pgrp` slot.
// Setting from the master must be visible from the slave (and vice versa).
#[cfg(feature = "linux-compat")]
fn smoke_pty_master_slave_share_fg_pgrp() -> TestResult {
    use crate::devfs_pty::{TIOCGPGRP, TIOCSPGRP};
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    // Clear the lock so DevPts::lookup hands out the slave.
    let mut zero: i32 = 0;
    let _ = master.ioctl(crate::devfs_pty::TIOCSPTLCK, &mut zero as *mut i32 as usize);

    let slave_arc = pts_lookup(idx).expect("slave");
    let slave = PtySlave::new(slave_arc);

    let mut p: i32 = 9000;
    if master
        .ioctl(TIOCSPGRP, &mut p as *mut i32 as usize)
        .is_err()
    {
        return TestResult::Fail("master TIOCSPGRP failed");
    }
    let mut got: i32 = 0;
    if slave
        .ioctl(TIOCGPGRP, &mut got as *mut i32 as usize)
        .is_err()
    {
        return TestResult::Fail("slave TIOCGPGRP failed");
    }
    if got != 9000 {
        return TestResult::Fail("slave did not see master's TIOCSPGRP");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_master_slave_share_fg_pgrp);

// TIOCGPTPEER routes via `pts_open_peer`. Lock must gate the peer open.
#[cfg(feature = "linux-compat")]
fn smoke_pty_gptpeer_respects_lock() -> TestResult {
    use crate::devfs_pty::{pts_open_peer, TIOCSPTLCK};
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    // Default-locked: pts_open_peer returns Some(Err(())).
    match pts_open_peer(idx) {
        Some(Err(())) => {}
        _ => return TestResult::Fail("locked PTY allowed pts_open_peer"),
    }
    // Unlock.
    let mut zero: i32 = 0;
    let _ = master.ioctl(TIOCSPTLCK, &mut zero as *mut i32 as usize);
    match pts_open_peer(idx) {
        Some(Ok(_)) => TestResult::Pass,
        _ => TestResult::Fail("unlocked PTY refused pts_open_peer"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_gptpeer_respects_lock);

// `DevPtmx` is the singleton FileOps that `DevDir::lookup("ptmx")`
// returns. `sys_open` checks `is_ptmx_clone()` and, when true,
// allocates a fresh `Pty` pair via `open_ptmx()` and installs the
// master in the caller's fd table instead. The singleton itself is
// never the fd's FileOps; this test pins the bit so a future refactor
// of `DevDir::lookup` doesn't silently break musl's `open("/dev/ptmx")`.
#[cfg(feature = "linux-compat")]
fn smoke_pty_devptmx_is_ptmx_clone() -> TestResult {
    use crate::devfs_pty::DevPtmx;
    let p = DevPtmx;
    if !p.is_ptmx_clone() {
        return TestResult::Fail("DevPtmx::is_ptmx_clone() returned false");
    }
    // Fresh open via the public helper. The two indices MUST differ
    // (clone-on-open semantics); same as `posix_openpt()` twice.
    __reset_for_test();
    let m1 = open_ptmx();
    let m2 = open_ptmx();
    if m1.index() == m2.index() {
        return TestResult::Fail("open_ptmx() handed out duplicate index");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_devptmx_is_ptmx_clone);

// TIOCGWINSZ / TIOCSWINSZ round-trip on a master fd. The window
// state is per-pair (master + slave share one `WinSize` slot), so
// a set via the master must be visible through the same master.
#[cfg(feature = "linux-compat")]
fn smoke_pty_winsize_round_trip() -> TestResult {
    use crate::devfs_pty::{TIOCGWINSZ, TIOCSWINSZ};
    __reset_for_test();
    let master = open_ptmx();
    // struct winsize { u16 row; u16 col; u16 xpix; u16 ypix; }
    let mut set_ws: [u16; 4] = [50, 132, 800, 600];
    let arg = set_ws.as_mut_ptr() as usize;
    if master.ioctl(TIOCSWINSZ, arg) != Ok(0) {
        return TestResult::Fail("TIOCSWINSZ failed");
    }
    let mut got_ws: [u16; 4] = [0; 4];
    let arg2 = got_ws.as_mut_ptr() as usize;
    if master.ioctl(TIOCGWINSZ, arg2) != Ok(0) {
        return TestResult::Fail("TIOCGWINSZ failed");
    }
    if got_ws[0] != 50 || got_ws[1] != 132 {
        return TestResult::Fail("winsize row/col did not round-trip");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_winsize_round_trip);

// Master and slave share one window-size slot. A TIOCSWINSZ on the
// master must be visible through TIOCGWINSZ on the slave (and vice
// versa) — `stty rows N cols M` typically writes via the master fd
// while the child reads via the slave.
#[cfg(feature = "linux-compat")]
fn smoke_pty_winsize_shared_master_slave() -> TestResult {
    use crate::devfs_pty::{TIOCGWINSZ, TIOCSWINSZ};
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    // Unlock so DevPts::lookup hands the slave out.
    let mut zero: i32 = 0;
    let _ = master.ioctl(crate::devfs_pty::TIOCSPTLCK, &mut zero as *mut i32 as usize);
    let slave_arc = pts_lookup(idx).expect("slave");
    let slave = PtySlave::new(slave_arc);

    let mut set_ws: [u16; 4] = [40, 100, 0, 0];
    let arg = set_ws.as_mut_ptr() as usize;
    if master.ioctl(TIOCSWINSZ, arg) != Ok(0) {
        return TestResult::Fail("master TIOCSWINSZ failed");
    }
    let mut got_ws: [u16; 4] = [0; 4];
    let arg2 = got_ws.as_mut_ptr() as usize;
    if slave.ioctl(TIOCGWINSZ, arg2) != Ok(0) {
        return TestResult::Fail("slave TIOCGWINSZ failed");
    }
    if got_ws[0] != 40 || got_ws[1] != 100 {
        return TestResult::Fail("slave did not see master's winsize");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_winsize_shared_master_slave);

// FIONREAD on a master fd reports the count of slave-written bytes
// available to read. On a slave fd, it reports master-written bytes.
#[cfg(feature = "linux-compat")]
fn smoke_pty_fionread_reports_ring_depth() -> TestResult {
    use crate::devfs_pty::FIONREAD;
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let mut zero: i32 = 0;
    let _ = master.ioctl(crate::devfs_pty::TIOCSPTLCK, &mut zero as *mut i32 as usize);
    let slave_arc = pts_lookup(idx).expect("slave");
    let slave = PtySlave::new(slave_arc);

    // Slave writes 5 bytes; master FIONREAD should see 5.
    poll_once(slave.write(0, b"hello"));
    let mut got: i32 = 0;
    let _ = master.ioctl(FIONREAD, &mut got as *mut i32 as usize);
    if got != 5 {
        return TestResult::Fail("master FIONREAD wrong count");
    }

    // Master writes 4 bytes; slave FIONREAD should see 4.
    poll_once(master.write(0, b"hiya"));
    let mut got2: i32 = 0;
    let _ = slave.ioctl(FIONREAD, &mut got2 as *mut i32 as usize);
    if got2 != 4 {
        return TestResult::Fail("slave FIONREAD wrong count");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_fionread_reports_ring_depth);

// TCGETS on master/slave must not error — musl's `isatty(3)` /
// `tcgetattr(3)` only check for success (not the actual termios
// fields), so returning `Ok(0)` with zeroed termios memory is
// enough for `pty_smoke` and `script(1)`-style programs to see
// the fd as a tty.
#[cfg(feature = "linux-compat")]
fn smoke_pty_tcgets_ok_on_both_ends() -> TestResult {
    use crate::devfs_pty::TCGETS;
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let mut zero: i32 = 0;
    let _ = master.ioctl(crate::devfs_pty::TIOCSPTLCK, &mut zero as *mut i32 as usize);
    let slave_arc = pts_lookup(idx).expect("slave");
    let slave = PtySlave::new(slave_arc);

    let mut termios = [0u8; 60];
    if master.ioctl(TCGETS, termios.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("master TCGETS failed");
    }
    if slave.ioctl(TCGETS, termios.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("slave TCGETS failed");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_tcgets_ok_on_both_ends);

// poll_readiness — master sees POLLIN only when the slave has
// written bytes; slave sees POLLIN only when the master has
// written bytes. POLLOUT is always set (the rings have a fixed
// 4 KiB capacity but never report blocking writes in v1).
#[cfg(feature = "linux-compat")]
fn smoke_pty_poll_readiness_tracks_ring_depth() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let mut zero: i32 = 0;
    let _ = master.ioctl(crate::devfs_pty::TIOCSPTLCK, &mut zero as *mut i32 as usize);
    let slave_arc = pts_lookup(idx).expect("slave");
    let slave = PtySlave::new(slave_arc);

    // Empty: only POLLOUT.
    let m_mask = master.poll_readiness();
    let s_mask = slave.poll_readiness();
    if (m_mask & crate::POLL_IN) != 0 {
        return TestResult::Fail("master POLLIN set on empty ring");
    }
    if (s_mask & crate::POLL_IN) != 0 {
        return TestResult::Fail("slave POLLIN set on empty ring");
    }
    if (m_mask & crate::POLL_OUT) == 0 || (s_mask & crate::POLL_OUT) == 0 {
        return TestResult::Fail("POLLOUT not set");
    }

    // Slave writes → master POLLIN set; slave POLLIN still clear.
    poll_once(slave.write(0, b"x"));
    if (master.poll_readiness() & crate::POLL_IN) == 0 {
        return TestResult::Fail("master POLLIN not set after slave write");
    }
    if (slave.poll_readiness() & crate::POLL_IN) != 0 {
        return TestResult::Fail("slave POLLIN set after slave write (own data)");
    }

    // Master drains; master POLLIN clears again.
    let mut buf = [0u8; 4];
    poll_once(master.read(0, &mut buf));
    if (master.poll_readiness() & crate::POLL_IN) != 0 {
        return TestResult::Fail("master POLLIN still set after drain");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem/pty", smoke_pty_poll_readiness_tracks_ring_depth);
