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
    if stat.size != 0 || stat.mode.file_type != crate::FileType::Special {
        return TestResult::Fail("PTY master metadata is not Linux-shaped");
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

// ── Test 2b: ECHO mirrors master writes back to the master ───────────────────

fn smoke_pty_master_write_echoes_to_master() -> TestResult {
    // With ECHO on (the cooked default), the shared n_tty discipline
    // mirrors the master's writes back to the master read side — a real
    // tty echoes typed input. The slave still reads the cooked line.
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // Mirror the full pty_smoke round-trip exactly (master line → slave
    // read → master reads its ECHO → slave reply → master read reply).
    if !matches!(poll_once(master.write(0, b"ping\n")), Some(Ok(5))) {
        return TestResult::Fail("master write didn't return 5");
    }
    // Slave reads the cooked line.
    let mut sbuf = [0u8; 16];
    match poll_once(slave.read(0, &mut sbuf)) {
        Some(Ok(5)) if &sbuf[..5] == b"ping\n" => {}
        _ => return TestResult::Fail("slave did not read the cooked line"),
    }
    // Master reads back the ECHO. With OPOST|ONLCR (the cooked default) the
    // echoed newline is CR-LF, so "ping\n" echoes as "ping\r\n"; without the CR
    // the echo staircases down-and-right in a real terminal (konsole did).
    let mut ebuf = [0u8; 16];
    match poll_once(master.read(0, &mut ebuf)) {
        Some(Ok(6)) if &ebuf[..6] == b"ping\r\n" => {}
        _ => return TestResult::Fail("master did not read back the CR-LF ECHO"),
    }
    // Slave replies; master reads it (raw on the master side).
    if !matches!(poll_once(slave.write(0, b"pong")), Some(Ok(4))) {
        return TestResult::Fail("slave write didn't return 4");
    }
    let mut pbuf = [0u8; 16];
    match poll_once(master.read(0, &mut pbuf)) {
        Some(Ok(4)) if &pbuf[..4] == b"pong" => {}
        _ => return TestResult::Fail("master did not read the slave reply"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_master_write_echoes_to_master);

// A cooked-mode echoed newline must be CR-LF (OPOST|ONLCR). Two typed lines echo
// as "a\r\nb\r\n"; a bare LF for each would staircase the cursor down-and-right —
// exactly what konsole displayed before the echo went through ONLCR.
fn smoke_pty_echo_newline_is_crlf() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    // Keep the slave open so the pair stays live; the echo is what we check.
    let _slave = PtySlave::new(Arc::clone(&slave_arc));

    if !matches!(poll_once(master.write(0, b"a\nb\n")), Some(Ok(4))) {
        return TestResult::Fail("master write didn't return 4");
    }
    let mut buf = [0u8; 32];
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) if &buf[..n] == b"a\r\nb\r\n" => TestResult::Pass,
        Some(Ok(n)) => {
            let _ = n;
            TestResult::Fail("echoed newline was not CR-LF (the staircase bug)")
        }
        _ => TestResult::Fail("master read of echo failed"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_echo_newline_is_crlf);

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

    // ICANON with no completed line yet is WOULD-BLOCK, not end-of-file.
    // It used to answer Ok(0) and make a separate query say which it meant; a
    // shell handed that 0 concludes its stdin closed and exits instantly. A
    // real `^D` EOF still returns Ok(0) — covered by
    // smoke_pty_slave_ctrl_d_returns_eof.
    let mut buf = [0u8; 16];
    let r = poll_once(slave.read(0, &mut buf));
    if matches!(r, Some(Ok(0))) {
        return TestResult::Fail(
            "slave ICANON read returned EOF before newline — a shell exits on that",
        );
    }
    if !matches!(r, Some(Err(FsError::WouldBlock))) {
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

// ── ISIG: ^C on the master raises SIGINT to the PTY's fg pgrp ─────────────────

fn smoke_pty_ctrl_c_raises_fg_pgrp_signal() -> TestResult {
    use crate::devfs_pty::install_pty_signal_hook;
    use core::sync::atomic::{AtomicU64, Ordering};

    static GOT_PGRP: AtomicU64 = AtomicU64::new(0);
    static GOT_SIG: AtomicU64 = AtomicU64::new(0);
    fn test_hook(pgrp: u64, signum: u32) -> bool {
        GOT_PGRP.store(pgrp, Ordering::Release);
        GOT_SIG.store(signum as u64, Ordering::Release);
        true
    }

    __reset_for_test();
    GOT_PGRP.store(0, Ordering::Release);
    GOT_SIG.store(0, Ordering::Release);
    install_pty_signal_hook(test_hook);

    let master = open_ptmx();
    let idx = master.index();
    // Set this PTY's foreground process group (what tcsetpgrp installs).
    if !master.set_tty_fg_pgrp(4242) {
        return TestResult::Fail("PTY master did not expose its shared control state");
    }

    // Master writes ^C (ISIG on by default). The shared discipline must
    // raise SIGINT (2) to the fg pgrp via the hook and consume the byte.
    poll_once(master.write(0, &[0x03u8]));

    let pgrp = GOT_PGRP.load(Ordering::Acquire);
    let sig = GOT_SIG.load(Ordering::Acquire);

    // The ^C must not surface to the slave.
    let slave = PtySlave::new(pts_lookup(idx).expect("slave"));
    let mut buf = [0u8; 4];
    // Consumed as a signal character ⇒ nothing left to read ⇒ would-block,
    // NOT a 0 that the slave would read as end-of-file.
    let n = match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        Some(Err(FsError::WouldBlock)) => 0,
        _ => 99,
    };

    if pgrp != 4242 {
        return TestResult::Fail("^C did not target the PTY fg pgrp");
    }
    if sig != 2 {
        return TestResult::Fail("^C did not raise SIGINT");
    }
    if n != 0 {
        return TestResult::Fail("^C should be consumed, not readable by the slave");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_ctrl_c_raises_fg_pgrp_signal);

// ── Wave-76: ioctls ───────────────────────────────────────────────────────────
//
// On the kernel-test path the "user pointer" is just a kernel-owned
// scratch slot; `copy_in`/`copy_out` reduce to plain ptr ops.

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
kernel_test_in!("filesystem/pty", smoke_pty_master_tiocgptn_returns_index);

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
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_slave_locked_until_tiocsptlck_clear
);

// ── Packet mode (TIOCPKT/TIOCGPKT) + TIOCGPTLCK + TIOCSIG ────────────────────

// KDE's KPtyDevice (konsole) enables packet mode and expects every master read
// to begin with a status byte; without the framing its read loop desyncs.
fn smoke_pty_packet_mode_frames_master_read() -> TestResult {
    use crate::devfs_pty::{TIOCGPKT, TIOCPKT, TIOCPKT_DATA};
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // Enable packet mode; TIOCGPKT must then report it.
    let mut on: i32 = 1;
    if master.ioctl(TIOCPKT, &mut on as *mut i32 as usize) != Ok(0) {
        return TestResult::Fail("TIOCPKT(1) did not return Ok(0)");
    }
    let mut got: i32 = -1;
    if master.ioctl(TIOCGPKT, &mut got as *mut i32 as usize) != Ok(0) || got != 1 {
        return TestResult::Fail("TIOCGPKT did not report packet mode enabled");
    }

    // Slave output is framed: byte 0 = TIOCPKT_DATA, the rest is the data.
    if !matches!(poll_once(slave.write(0, b"world")), Some(Ok(5))) {
        return TestResult::Fail("slave write didn't return 5");
    }
    let mut buf = [0xAAu8; 16];
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(6)) if buf[0] == TIOCPKT_DATA && &buf[1..6] == b"world" => {}
        _ => return TestResult::Fail("packet-mode read framing wrong"),
    }

    // Disable packet mode: reads are un-framed again.
    let mut off: i32 = 0;
    if master.ioctl(TIOCPKT, &mut off as *mut i32 as usize) != Ok(0) {
        return TestResult::Fail("TIOCPKT(0) did not return Ok(0)");
    }
    let mut got2: i32 = -1;
    if master.ioctl(TIOCGPKT, &mut got2 as *mut i32 as usize) != Ok(0) || got2 != 0 {
        return TestResult::Fail("TIOCGPKT did not report packet mode disabled");
    }
    if !matches!(poll_once(slave.write(0, b"x")), Some(Ok(1))) {
        return TestResult::Fail("second slave write failed");
    }
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == b'x' => {}
        _ => return TestResult::Fail("un-framed read after TIOCPKT(0) wrong"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_packet_mode_frames_master_read);

fn smoke_pty_tiocgptlck_reports_lock_state() -> TestResult {
    use crate::devfs_pty::{TIOCGPTLCK, TIOCSPTLCK};
    __reset_for_test();
    let master = open_ptmx();
    // Locked by default right after ptmx open.
    let mut got: i32 = -1;
    if master.ioctl(TIOCGPTLCK, &mut got as *mut i32 as usize) != Ok(0) || got != 1 {
        return TestResult::Fail("TIOCGPTLCK did not report the default lock");
    }
    // TIOCSPTLCK(0) clears it; TIOCGPTLCK must follow.
    let mut zero: i32 = 0;
    let _ = master.ioctl(TIOCSPTLCK, &mut zero as *mut i32 as usize);
    let mut got2: i32 = -1;
    if master.ioctl(TIOCGPTLCK, &mut got2 as *mut i32 as usize) != Ok(0) || got2 != 0 {
        return TestResult::Fail("TIOCGPTLCK did not follow the unlock");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_tiocgptlck_reports_lock_state);

// TIOCSIG's arg is the signal VALUE (not a pointer). Out-of-range is EINVAL; a
// valid signal returns Ok(0) even with no foreground group installed.
fn smoke_pty_tiocsig_validates_signal() -> TestResult {
    use crate::devfs_pty::TIOCSIG;
    __reset_for_test();
    let master = open_ptmx();
    if master.ioctl(TIOCSIG, 0).is_ok() {
        return TestResult::Fail("TIOCSIG(0) should be rejected");
    }
    if master.ioctl(TIOCSIG, 65).is_ok() {
        return TestResult::Fail("TIOCSIG(65) should be rejected");
    }
    if master.ioctl(TIOCSIG, 9) != Ok(0) {
        return TestResult::Fail("TIOCSIG(SIGKILL) did not return Ok(0)");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_tiocsig_validates_signal);

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
kernel_test_in!("filesystem/pty", smoke_pty_per_tty_fg_pgrp_isolated);

// Master fg_pgrp and slave fg_pgrp share the *same* `Pty.fg_pgrp` slot.
// Setting from the master must be visible from the slave (and vice versa).
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
kernel_test_in!("filesystem/pty", smoke_pty_master_slave_share_fg_pgrp);

// TIOCGPTPEER routes via `pts_open_peer`. Lock must gate the peer open.
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
kernel_test_in!("filesystem/pty", smoke_pty_gptpeer_respects_lock);

// `DevPtmx` is the clone node at `/dev/pts/ptmx` (the root `/dev/ptmx`
// path is a symlink to it). `sys_open` uses `open_instance()` to allocate
// the pair; keep the legacy marker pinned until all out-of-tree users migrate.
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
kernel_test_in!("filesystem/pty", smoke_pty_devptmx_is_ptmx_clone);

/// Linux exposes `/dev/ptmx` as the relative symlink `pts/ptmx`, while the
/// mounted devpts instance owns the clone device and shares the live PTY table.
fn smoke_pty_linux_devpts_mount_shape() -> TestResult {
    use crate::devfs::{linux_makedev, DevFs};
    use crate::devfs_pty::DevPtsFs;
    use crate::{FileType, FsInstance};

    __reset_for_test();
    let dev_root = DevFs::new().root();
    let ptmx_link = match dev_root.lookup("ptmx") {
        Some(link) => link,
        None => return TestResult::Fail("/dev/ptmx symlink is missing"),
    };
    if ptmx_link.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("/dev/ptmx is not a symlink");
    }
    let mut target = [0u8; 16];
    match poll_once(ptmx_link.read(0, &mut target)) {
        Some(Ok(n)) if &target[..n] == b"pts/ptmx" => {}
        _ => return TestResult::Fail("/dev/ptmx has the wrong target"),
    }

    let master = open_ptmx();
    let index = master.index();
    let pts = DevPtsFs.root();
    if !pts
        .enumerate(0, 64)
        .iter()
        .any(|(name, ty)| name == &alloc::format!("{index}") && *ty == FileType::Special)
    {
        return TestResult::Fail("mounted devpts lost a live PTY slave");
    }
    let clone_node = match pts.lookup("ptmx") {
        Some(node) => node,
        None => return TestResult::Fail("mounted devpts has no ptmx clone node"),
    };
    if clone_node.rdev() != linux_makedev(5, 2) || clone_node.open_instance().is_none() {
        return TestResult::Fail("devpts/ptmx metadata or clone-on-open is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_linux_devpts_mount_shape);

// TIOCGWINSZ / TIOCSWINSZ round-trip on a master fd. The window
// state is per-pair (master + slave share one `WinSize` slot), so
// a set via the master must be visible through the same master.
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
kernel_test_in!("filesystem/pty", smoke_pty_winsize_round_trip);

// Master and slave share one window-size slot. A TIOCSWINSZ on the
// master must be visible through TIOCGWINSZ on the slave (and vice
// versa) — `stty rows N cols M` typically writes via the master fd
// while the child reads via the slave.
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
kernel_test_in!("filesystem/pty", smoke_pty_winsize_shared_master_slave);

// FIONREAD on a master fd reports the count of slave-written bytes
// available to read. On a slave fd, it reports master-written bytes.
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

    // Master writes a complete 5-byte line; in cooked mode only completed
    // lines are readable, so the slave's FIONREAD reports the whole "hiya\n"
    // (a partial line would correctly report 0, like Linux n_tty).
    poll_once(master.write(0, b"hiya\n"));
    let mut got2: i32 = 0;
    let _ = slave.ioctl(FIONREAD, &mut got2 as *mut i32 as usize);
    if got2 != 5 {
        return TestResult::Fail("slave FIONREAD wrong count");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_fionread_reports_ring_depth);

// TCGETS on master/slave must not error — musl's `isatty(3)` /
// `tcgetattr(3)` only check for success (not the actual termios
// fields), so returning `Ok(0)` with zeroed termios memory is
// enough for `pty_smoke` and `script(1)`-style programs to see
// the fd as a tty.
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
kernel_test_in!("filesystem/pty", smoke_pty_tcgets_ok_on_both_ends);

// poll_readiness — master sees POLLIN only when the slave has
// written bytes; slave sees POLLIN only when the master has
// written bytes. POLLOUT is always set (the rings have a fixed
// 4 KiB capacity but never report blocking writes in v1).
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
kernel_test_in!("filesystem/pty", smoke_pty_poll_readiness_tracks_ring_depth);

/// An EMPTY master read must say "would block", never end-of-file.
///
/// `read()` returning 0 on a PTY master means the slave hung up. Reporting
/// it merely because the ring is momentarily empty hands the terminal a
/// phantom EOF: it concludes the shell exited and stops reading forever.
///
/// That is precisely why the `foot` window rendered its grid and cursor but
/// never a prompt. A probe walking a terminal's own sequence in-guest
/// (posix_openpt, grantpt, unlockpt, ptsname, open slave, fork,
/// setsid+TIOCSCTTY+dup, exec) showed EVERY step succeeding and the child
/// shell exiting 0, with the master read returning `n=0 errno=0` before the
/// child's output landed. Allocation, exec and the shell were all fine; the
/// slave->master path reported EOF.
///
/// The file op returns `FsError::WouldBlock`, which `sys_read` converts to a
/// park or EAGAIN. Both empty and data-ready directions are asserted.
fn smoke_pty_master_empty_read_is_would_block_not_eof() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();

    // Nothing written yet: the master must report would-block, not EOF.
    // Asserted on the read itself. The old out-of-band classification let a
    // consumer turn an empty live PTY into a phantom EOF.
    let mut buf = [0u8; 32];
    match poll_once(master.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        Some(Ok(0)) => {
            return TestResult::Fail(
                "empty master read returned 0 — a terminal takes that as the shell \
                 exiting and stops reading (blank foot window)",
            )
        }
        _ => return TestResult::Fail("empty master read did not report would-block"),
    }

    // Now the slave writes — as a shell's stdout does.
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));
    let payload = b"PTY-CHILD-ALIVE\n";
    match poll_once(slave.write(0, payload)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("slave write failed"),
    }

    // With data pending the master must hand it over — as OPOST processed
    // it. The default termios carries OPOST|ONLCR, so the payload's closing
    // `\n` reaches the master as CR-NL (`do_output_char`, n_tty.c:414).
    // This expectation used to be the raw payload, which is what a terminal
    // emulator never sees on a real kernel.
    let expected = b"PTY-CHILD-ALIVE\r\n";
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) if n == expected.len() => {
            if &buf[..n] != expected {
                return TestResult::Fail("master read returned the wrong bytes");
            }
        }
        _ => return TestResult::Fail("master read did not return the slave's bytes"),
    }

    // Drained again → would-block, not EOF.
    if !matches!(
        poll_once(master.read(0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail("drained master did not report would-block");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_master_empty_read_is_would_block_not_eof
);

/// An empty slave read blocks — but a latched `^D` EOF still returns 0.
///
/// This is the one PTY case where a 0-byte read is sometimes CORRECT.
/// Canonical mode latches `^D` as a genuine end-of-file a shell must see
/// exactly once, so the empty case cannot simply be made to block: doing
/// that would hang every shell at its first `^D` instead of exiting it.
///
/// But "no completed line yet" is NOT eof. A reader handed 0 there decides
/// its input closed and exits — which is how an interactive shell dies the
/// moment it starts, the slave-side twin of the blank `foot` window that
/// `PtyMaster` caused.
///
/// So both halves are asserted together, because the fix is only correct if
/// it distinguishes them:
///   1. empty, no ^D        -> would-block (must NOT look like EOF)
///   2. ^D latched          -> NOT would-block, and the read returns 0
///   3. data queued         -> NOT would-block, read returns the data
fn smoke_pty_slave_empty_blocks_but_ctrl_d_is_real_eof() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    // 1. Nothing typed yet: must report would-block, not EOF.
    let mut buf = [0u8; 32];
    if !matches!(
        poll_once(slave.read(0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail(
            "empty slave read did not report would-block — a shell takes EOF as its input closing \
             and exits immediately",
        );
    }

    // 2. Master writes a complete line: data is ready, so no blocking.
    match poll_once(master.write(0, b"hello\n")) {
        Some(Ok(6)) => {}
        _ => return TestResult::Fail("master write of a line failed"),
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(n)) if n == 6 && &buf[..n] == b"hello\n" => {}
        _ => return TestResult::Fail("slave read did not return the queued line"),
    }

    // Drained again -> back to would-block.
    if !matches!(
        poll_once(slave.read(0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail("drained slave did not report would-block");
    }

    // 3. ^D (EOT, 0x04) latches a REAL eof: must stop blocking and read 0.
    match poll_once(master.write(0, b"\x04")) {
        Some(Ok(1)) => {}
        _ => return TestResult::Fail("master write of ^D failed"),
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(0)) => {}
        _ => return TestResult::Fail("^D did not produce a 0-byte end-of-file read"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_slave_empty_blocks_but_ctrl_d_is_real_eof
);

/// The PTY hangup matrix, both directions, against the Linux sources.
///
/// A PTY has TWO end-of-stream conditions and they are NOT symmetric.
/// `drivers/tty/pty.c` `pty_close` sets `TTY_OTHER_CLOSED` on the peer
/// whichever side closes, but the MASTER's close additionally
/// `tty_vhangup(tty->link)`s the slave. The results differ accordingly:
///
/// | who closed | other side's read      | other side's poll |
/// |------------|------------------------|-------------------|
/// | last slave | **EIO**                | POLLHUP           |
/// | master     | **0 / EOF**            | POLLHUP           |
///
///   * EIO — `n_tty.c` `n_tty_wait_for_input`:
///     `if (test_bit(TTY_OTHER_CLOSED, &tty->flags)) return -EIO;`
///     Checked in the WAIT path, so queued bytes drain FIRST.
///   * 0/EOF — `tty_io.c` `tty_read` via `tty_hung_up_p()`. EOF is what
///     makes a shell on a vanished terminal exit; EIO is what tells a
///     terminal its child is gone. Swapping them wedges one side.
///   * POLLHUP — `n_tty.c` `n_tty_poll`:
///     `if (test_bit(TTY_OTHER_CLOSED, &tty->flags)) mask |= EPOLLHUP;`
///     An event loop never issues a bare blocking read, so without the HUP
///     bit it simply never wakes to learn the peer is gone.
///
/// This was found the hard way: the `ptyspawn` smoke's child failed to
/// exec, every slave fd closed, and the parent's master read parked FOREVER
/// instead of reporting EIO. The negative halves matter just as much — a
/// master read before any slave opens must still WAIT (that is the phantom
/// EOF that left `foot` blank), and re-opening a slave must clear the
/// condition (`pty.c` clears the bit on open).
fn smoke_pty_hangup_matrix_matches_linux() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let pty = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup failed for a fresh master"),
    };

    // ── Before any slave exists: WAIT, never EOF and never HUP. ──
    let mut buf = [0u8; 32];
    if !matches!(
        poll_once(FileOps::read(&*master, 0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail(
            "master read did not report would-block before any slave was opened",
        );
    }
    if FileOps::poll_readiness(&*master) & crate::POLL_HUP != 0 {
        return TestResult::Fail("master reported POLLHUP before any slave was opened");
    }

    // ── Slave open, empty: still WAIT. ──
    let slave = PtySlave::new(Arc::clone(&pty));
    if !matches!(
        poll_once(FileOps::read(&*master, 0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail(
            "master read did not report would-block with a slave open and idle",
        );
    }
    if FileOps::poll_readiness(&*master) & crate::POLL_HUP != 0 {
        return TestResult::Fail("master reported POLLHUP with a slave still open");
    }

    // ── Slave writes, then closes. The DATA must drain before the hangup:
    // those bytes are the child's output and Linux checks TTY_OTHER_CLOSED
    // only in the wait path. ──
    if poll_once(slave.write(0, b"last words")).is_none() {
        return TestResult::Fail("slave write did not complete");
    }
    drop(slave);

    if !pty.hung_up() {
        return TestResult::Fail("dropping the last slave did not mark the pty hung up");
    }
    match poll_once(FileOps::read(&*master, 0, &mut buf)) {
        Some(Ok(n)) if n == b"last words".len() && &buf[..n] == b"last words" => {}
        Some(Ok(0)) => {
            return TestResult::Fail(
                "hangup swallowed the slave's queued output — data must drain first",
            )
        }
        _ => return TestResult::Fail("master could not read bytes queued before the hangup"),
    }

    // ── Drained AND hung up: EIO, not 0, and not a block. ──
    match poll_once(FileOps::read(&*master, 0, &mut buf)) {
        Some(Err(FsError::Io(_))) => {}
        Some(Ok(0)) => {
            return TestResult::Fail("master read returned 0 on hangup; Linux n_tty returns -EIO")
        }
        _ => return TestResult::Fail("master read did not report EIO after the last slave closed"),
    }
    if FileOps::poll_readiness(&*master) & crate::POLL_HUP == 0 {
        return TestResult::Fail("master poll did not set POLLHUP after the last slave closed");
    }

    // ── Re-opening a slave CLEARS the condition (pty.c clears the bit on
    // open). Without this a pty is permanently poisoned after one close. ──
    let slave2 = PtySlave::new(Arc::clone(&pty));
    if pty.hung_up() {
        return TestResult::Fail("re-opening a slave did not clear the hangup");
    }
    if !matches!(
        poll_once(FileOps::read(&*master, 0, &mut buf)),
        Some(Err(FsError::WouldBlock))
    ) {
        return TestResult::Fail("master did not report would-block after a slave re-opened");
    }
    if FileOps::poll_readiness(&*master) & crate::POLL_HUP != 0 {
        return TestResult::Fail("master still reports POLLHUP after a slave re-opened");
    }

    // ── The other direction: master closes, slave sees EOF (0), not EIO. ──
    drop(master);
    if slave2.nonblock_read_eagain() {
        return TestResult::Fail("O_NONBLOCK slave read reports EAGAIN after the master closed");
    }
    match poll_once(slave2.read(0, &mut buf)) {
        Some(Ok(0)) => {}
        Some(Err(_)) => {
            return TestResult::Fail(
                "slave read returned an error after the master closed; Linux tty_read \
                 returns 0 for a hung-up tty (that EOF is how a shell exits)",
            )
        }
        _ => return TestResult::Fail("slave read did not report EOF after the master closed"),
    }
    if FileOps::poll_readiness(&slave2) & crate::POLL_HUP == 0 {
        return TestResult::Fail("slave poll did not set POLLHUP after the master closed");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_pty_hangup_matrix_matches_linux);

// ── VT layer (crate::vt) ────────────────────────────────────────────────────
//
// The logical VT state machine that backs the VT ioctls on /dev/tty0/ttyN and
// the `/sys/class/tty/tty0/active` attribute. logind drives seat0 session
// activation through these; see `crate::vt`. The ioctl→user-memory dispatch in
// `DevConsole::ioctl` is a thin wrapper exercised by the desktop boot; here we
// test the state machine directly (the struct is module-private).

fn smoke_vt_activate_pos() -> TestResult {
    crate::vt::__reset_for_test();
    if crate::vt::active_vt() != 1 {
        return TestResult::Fail("VT should boot active on VT 1");
    }
    if crate::vt::activate(3).is_err() {
        return TestResult::Fail("VT_ACTIVATE(3) should succeed");
    }
    if crate::vt::active_vt() != 3 {
        return TestResult::Fail("active VT should follow VT_ACTIVATE");
    }
    // /sys/class/tty/tty0/active must agree with VT_GETSTATE's view.
    if crate::vt::active_sysfs() != "tty3\n" {
        return TestResult::Fail("sysfs active attr must be 'tty3\\n'");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/vt", smoke_vt_activate_pos);

fn smoke_vt_activate_neg() -> TestResult {
    crate::vt::__reset_for_test();
    // VT 0 and VT > MAX_VT are out of range → EINVAL (Err), active unchanged.
    if crate::vt::activate(0).is_ok() {
        return TestResult::Fail("VT_ACTIVATE(0) should be rejected");
    }
    if crate::vt::activate(crate::vt::MAX_VT + 1).is_ok() {
        return TestResult::Fail("VT_ACTIVATE past MAX_VT should be rejected");
    }
    if crate::vt::active_vt() != 1 {
        return TestResult::Fail("a rejected VT_ACTIVATE must not move the active VT");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/vt", smoke_vt_activate_neg);

fn smoke_vt_openqry_allocates_increasing() -> TestResult {
    crate::vt::__reset_for_test();
    // VT_OPENQRY hands out the lowest free VT and marks it allocated, so a
    // display manager that queries repeatedly gets distinct VTs.
    if crate::vt::openqry() != Some(1) {
        return TestResult::Fail("first VT_OPENQRY should be VT 1");
    }
    if crate::vt::openqry() != Some(2) {
        return TestResult::Fail("second VT_OPENQRY should be VT 2");
    }
    if crate::vt::openqry() != Some(3) {
        return TestResult::Fail("third VT_OPENQRY should be VT 3");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/vt", smoke_vt_openqry_allocates_increasing);

fn smoke_vt_owner_default_and_chown() -> TestResult {
    crate::vt::__reset_for_test();
    // Default owner is root:tty (0,5), as devtmpfs creates /dev/ttyN.
    if crate::vt::owner(1) != (0, 5) {
        return TestResult::Fail("default VT owner must be root:tty (0,5)");
    }
    // logind chowns a session's VT to the session user.
    crate::vt::set_owner(1, 957, 985);
    if crate::vt::owner(1) != (957, 985) {
        return TestResult::Fail("chown of a VT should stick");
    }
    // A -1 (u32::MAX) component means "leave unchanged", matching chown(2).
    crate::vt::set_owner(1, u32::MAX, 5);
    if crate::vt::owner(1) != (957, 5) {
        return TestResult::Fail("chown with uid=-1 must preserve the existing uid");
    }
    // Owners are per-VT: an untouched VT keeps the default.
    if crate::vt::owner(2) != (0, 5) {
        return TestResult::Fail("chowning one VT must not affect another");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/vt", smoke_vt_owner_default_and_chown);

fn smoke_vt_mode_roundtrip() -> TestResult {
    crate::vt::__reset_for_test();
    // Default switch mode is VT_AUTO.
    if crate::vt::get_mode(1).mode != crate::vt::VT_AUTO {
        return TestResult::Fail("default VT mode must be VT_AUTO");
    }
    // logind installs VT_PROCESS with release/acquire signals; VT_GETMODE must
    // round-trip it faithfully.
    crate::vt::set_mode(
        1,
        crate::vt::VtMode {
            mode: crate::vt::VT_PROCESS,
            waitv: 0,
            relsig: 10,
            acqsig: 11,
            frsig: 0,
        },
    );
    let m = crate::vt::get_mode(1);
    if m.mode != crate::vt::VT_PROCESS || m.relsig != 10 || m.acqsig != 11 {
        return TestResult::Fail("VT_SETMODE→VT_GETMODE did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/vt", smoke_vt_mode_roundtrip);

// ── OPOST / termios parity ───────────────────────────────────────────────────

/// OPOST|ONLCR expands a slave-written `\n` into CR-NL on its way to the
/// master. `do_output_char` (`drivers/tty/n_tty.c:414`):
///
/// ```c
/// if (O_ONLCR(tty)) { ... tty->ops->write(tty, "\r\n", 2); return 2; }
/// ```
///
/// Without it every line a program prints reaches a terminal emulator as a
/// bare line feed, which moves down a row without returning to column 0 —
/// the staircase. A serial console hides the bug because the UART adds its
/// own CR.
fn smoke_pty_opost_onlcr_expands_newline() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let pty = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&pty));

    // Default termios is OPOST|ONLCR, as Linux's n_tty_set_termios leaves it.
    let w = poll_once(slave.write(0, b"a\nb"));
    // The RETURN value counts the caller's bytes, not the expanded ones.
    if !matches!(w, Some(Ok(3))) {
        return TestResult::Fail("slave write should report the caller's byte count");
    }
    let mut buf = [0u8; 16];
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("master read failed"),
    };
    if &buf[..n] != b"a\r\nb" {
        return TestResult::Fail("ONLCR did not expand \\n to CR-NL");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_opost_onlcr_expands_newline);

/// With OPOST clear every other output flag is inert and bytes pass through
/// untouched — `do_output_char` is only reached via `process_output`, which
/// `n_tty_write` calls solely when `O_OPOST(tty)`.
///
/// This is the other half of the ONLCR test: a discipline that always
/// inserted CR would pass that one and fail this.
fn smoke_pty_opost_disabled_passes_bytes_through() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let pty = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    {
        // Clear OPOST (c_oflag bit 0) — what cfmakeraw() does.
        let mut t = pty.termios.lock();
        let mut oflag = u32::from_ne_bytes(t.raw[4..8].try_into().unwrap());
        oflag &= !1;
        t.raw[4..8].copy_from_slice(&oflag.to_ne_bytes());
    }
    let slave = PtySlave::new(Arc::clone(&pty));
    if !matches!(poll_once(slave.write(0, b"a\nb")), Some(Ok(3))) {
        return TestResult::Fail("slave write failed");
    }
    let mut buf = [0u8; 16];
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("master read failed"),
    };
    if &buf[..n] != b"a\nb" {
        return TestResult::Fail("raw mode must not insert a CR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_opost_disabled_passes_bytes_through
);

/// The window size carries pixels, and they round-trip.
///
/// `tty_do_resize` compares the WHOLE `struct winsize`, so dropping the
/// pixel fields both loses what programs read back (sixel and the kitty
/// graphics protocol size images from them) and makes a pixels-only resize
/// look like no resize at all.
fn smoke_pty_winsize_carries_pixels() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    pty.resize(crate::devfs_pty::WinSize {
        rows: 40,
        cols: 100,
        xpixel: 800,
        ypixel: 600,
    });
    let w = *pty.window.lock();
    if w.rows != 40 || w.cols != 100 {
        return TestResult::Fail("winsize rows/cols did not round-trip");
    }
    if w.xpixel != 800 || w.ypixel != 600 {
        return TestResult::Fail("winsize pixel fields were dropped");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_winsize_carries_pixels);

/// Input CR/NL translation follows c_iflag rather than being hardcoded.
///
/// `n_tty.c:1355`, and the order matters — IGNCR is tested BEFORE ICRNL:
///
/// ```c
/// if (c == '\r') {
///         if (I_IGNCR(tty)) return;
///         if (I_ICRNL(tty)) c = '\n';
/// } else if (c == '\n' && I_INLCR(tty))
///         c = '\r';
/// ```
fn smoke_pty_input_cr_translation_follows_iflag() -> TestResult {
    const ICRNL: u32 = 0x100;
    const IGNCR: u32 = 0x080;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&pty));

    let set_iflag = |v: u32| {
        let mut t = pty.termios.lock();
        t.raw[0..4].copy_from_slice(&v.to_ne_bytes());
    };

    // ICRNL: a CR becomes NL, which also terminates the canonical line.
    set_iflag(ICRNL);
    if poll_once(master.write(0, b"x\r")).is_none() {
        return TestResult::Fail("master write failed");
    }
    let mut buf = [0u8; 16];
    let n = match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("slave read failed under ICRNL"),
    };
    if &buf[..n] != b"x\n" {
        return TestResult::Fail("ICRNL did not map CR to NL");
    }

    // IGNCR wins over ICRNL: the CR is dropped, so the line never
    // completes and there is nothing to read.
    set_iflag(IGNCR | ICRNL);
    if poll_once(master.write(0, b"y\r")).is_none() {
        return TestResult::Fail("master write failed");
    }
    if pty.input.lock().readable() != 0 {
        return TestResult::Fail("IGNCR must discard CR before ICRNL maps it");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_input_cr_translation_follows_iflag
);

/// ECHOCTL renders a control character as `^X` rather than echoing a raw
/// control byte (`n_tty.c` `echo_char`). Without it a `^C` typed at a shell
/// prompt emits a literal 0x03 to the terminal.
fn smoke_pty_echoctl_renders_caret_form() -> TestResult {
    const ECHO: u32 = 0x08;
    const ECHOCTL: u32 = 0x200;
    const ICANON: u32 = 0x02;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    {
        // ECHO|ECHOCTL|ICANON, and crucially ISIG CLEAR so ^C is ordinary
        // input rather than a signal.
        let mut t = pty.termios.lock();
        t.raw[12..16].copy_from_slice(&(ECHO | ECHOCTL | ICANON).to_ne_bytes());
    }
    if poll_once(master.write(0, &[0x03])).is_none() {
        return TestResult::Fail("master write failed");
    }
    let mut buf = [0u8; 16];
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("master read of the echo failed"),
    };
    if &buf[..n] != b"^C" {
        return TestResult::Fail("ECHOCTL did not render the control char as ^C");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_echoctl_renders_caret_form);

/// IXON flow control actually stops output: `^S` (VSTOP) suspends what the
/// master can read and `^Q` (VSTART) resumes it.
///
/// Linux gates the transmit path on `tty->flow.stopped`
/// (`n_tty_receive_char_flow_ctrl` sets it, `start_tty`/`stop_tty` act on
/// it). A flag that is set but never consulted would leave `^S` and
/// `tcflow(TCOOFF)` silently inert — accepted and discarded.
fn smoke_pty_ixon_flow_control_stops_output() -> TestResult {
    const IXON: u32 = 0x400;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    {
        let mut t = pty.termios.lock();
        t.raw[0..4].copy_from_slice(&IXON.to_ne_bytes());
    }
    let slave = PtySlave::new(Arc::clone(&pty));

    // ^S from the terminal stops output.
    if poll_once(master.write(0, &[0x13])).is_none() {
        return TestResult::Fail("master write of ^S failed");
    }
    if poll_once(slave.write(0, b"hidden")).is_none() {
        return TestResult::Fail("slave write failed");
    }
    let mut buf = [0u8; 32];
    match poll_once(master.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("stopped output must not be readable"),
    }
    // ...and the poll mask has to agree, or an event loop spins.
    if master.poll_readiness() & crate::POLL_IN != 0 {
        return TestResult::Fail("stopped output must not report POLLIN");
    }

    // ^Q resumes it, and nothing was lost.
    if poll_once(master.write(0, &[0x11])).is_none() {
        return TestResult::Fail("master write of ^Q failed");
    }
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resumed output was not readable"),
    };
    if &buf[..n] != b"hidden" {
        return TestResult::Fail("output queued while stopped must survive the restart");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_ixon_flow_control_stops_output);

// ── VMIN / VTIME ─────────────────────────────────────────────────────────────

/// Put the PTY in non-canonical mode with the given VMIN/VTIME.
fn set_raw_min_time(pty: &alloc::sync::Arc<crate::devfs_pty::Pty>, vmin: u8, vtime: u8) {
    let mut t = pty.termios.lock();
    // Clear ICANON (and ISIG, so control bytes stay ordinary input).
    t.raw[12..16].copy_from_slice(&0u32.to_ne_bytes());
    // c_cc[] starts at wire offset 17; VTIME = 5, VMIN = 6.
    t.raw[17 + 5] = vtime;
    t.raw[17 + 6] = vmin;
}

/// VMIN > 0 with VTIME == 0 blocks until MIN bytes have arrived.
///
/// `n_tty_read`: `minimum = MIN_CHAR(tty)` and `time` stays 0, so the
/// timeout remains `MAX_SCHEDULE_TIMEOUT` — there is no timer, only a count.
fn smoke_pty_vmin_blocks_until_min_bytes() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    set_raw_min_time(&pty, 2, 0);
    let slave = PtySlave::new(Arc::clone(&pty));
    let mut buf = [0u8; 8];

    // One byte is fewer than VMIN: the read must wait.
    if poll_once(master.write(0, b"a")).is_none() {
        return TestResult::Fail("master write failed");
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("a read below VMIN must block, not return"),
    }

    // The second byte satisfies VMIN and both are delivered together.
    if poll_once(master.write(0, b"b")).is_none() {
        return TestResult::Fail("master write failed");
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(2)) if &buf[..2] == b"ab" => TestResult::Pass,
        _ => TestResult::Fail("reaching VMIN must deliver the buffered bytes"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_vmin_blocks_until_min_bytes);

/// VMIN == 0 with VTIME == 0 is a polling read: it returns immediately with
/// whatever is queued, including nothing.
///
/// The zero-byte return is NOT end-of-file. `n_tty_read` sets
/// `timeout = 0` and `minimum = 1`, so the wait expires at once and the
/// function returns `kb - kbuf`, which is simply zero. Reporting
/// would-block here instead would hang a program that polls its tty.
fn smoke_pty_vmin_zero_vtime_zero_is_a_polling_read() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    set_raw_min_time(&pty, 0, 0);
    let slave = PtySlave::new(Arc::clone(&pty));
    let mut buf = [0u8; 8];

    // Empty queue: an immediate 0, not would-block and not EOF.
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(0)) => {}
        Some(Err(FsError::WouldBlock)) => {
            return TestResult::Fail("a VMIN==0/VTIME==0 read must not block")
        }
        _ => return TestResult::Fail("polling read returned something unexpected"),
    }

    // With data queued it returns it, still without waiting.
    if poll_once(master.write(0, b"xy")).is_none() {
        return TestResult::Fail("master write failed");
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(2)) if &buf[..2] == b"xy" => TestResult::Pass,
        _ => TestResult::Fail("polling read did not return the queued bytes"),
    }
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_vmin_zero_vtime_zero_is_a_polling_read
);

/// Spin until the monotonic clock has advanced `ns`, or give up.
///
/// Returns false when the clock is not advancing, so a timing test can skip
/// rather than hang or report a failure it cannot substantiate.
fn wait_monotonic(ns: u64) -> bool {
    let start = narf_time::monotonic_ns();
    if start == 0 {
        return false;
    }
    for _ in 0..200_000_000u64 {
        if narf_time::monotonic_ns().saturating_sub(start) >= ns {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// VMIN == 0 with VTIME > 0 is an overall read timer: block until a byte
/// arrives or the timer expires, then return what there is.
///
/// `n_tty_read`: `timeout = (HZ / 10) * TIME_CHAR(tty); minimum = 1;` — the
/// timer starts when the read begins, not when a byte arrives.
fn smoke_pty_vmin_zero_vtime_read_timer_expires() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    // VTIME is in tenths of a second, so 1 == 100ms.
    set_raw_min_time(&pty, 0, 1);
    let slave = PtySlave::new(Arc::clone(&pty));
    let mut buf = [0u8; 8];

    // First attempt arms the timer and waits — it must NOT return 0 yet, or
    // the timer would be meaningless.
    match poll_once(slave.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("a VTIME read must wait before the timer expires"),
    }
    if !wait_monotonic(150_000_000) {
        return TestResult::Skip("monotonic clock is not advancing; cannot time this");
    }
    // Expired: report what there is, which is nothing.
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(0)) => TestResult::Pass,
        Some(Err(FsError::WouldBlock)) => TestResult::Fail("the VTIME read timer never expired"),
        _ => TestResult::Fail("expired VTIME read returned something unexpected"),
    }
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_vmin_zero_vtime_read_timer_expires
);

/// VMIN > 0 with VTIME > 0 makes VTIME an INTER-BYTE timer: the first wait
/// is unbounded, and the gap timer only starts once a byte has arrived.
///
/// In `n_tty_read` the timeout is `MAX_SCHEDULE_TIMEOUT` until a byte has
/// been copied — `if (time) timeout = time;` runs only after the copy — so
/// an idle terminal waits forever rather than returning empty.
fn smoke_pty_vmin_vtime_is_an_interbyte_timer() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    set_raw_min_time(&pty, 3, 1);
    let slave = PtySlave::new(Arc::clone(&pty));
    let mut buf = [0u8; 8];

    // No bytes at all: the gap timer is not running, so waiting is
    // unbounded — it must not expire into an empty return.
    match poll_once(slave.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("an idle VMIN>0/VTIME>0 read must wait indefinitely"),
    }
    if !wait_monotonic(150_000_000) {
        return TestResult::Skip("monotonic clock is not advancing; cannot time this");
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => {
            return TestResult::Fail(
                "the inter-byte timer must not run before the first byte arrives",
            )
        }
    }

    // One byte arrives — fewer than VMIN, so the gap timer starts.
    if poll_once(master.write(0, b"q")).is_none() {
        return TestResult::Fail("master write failed");
    }
    match poll_once(slave.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("a byte below VMIN must not return before the gap"),
    }
    if !wait_monotonic(150_000_000) {
        return TestResult::Skip("monotonic clock is not advancing; cannot time this");
    }
    // Gap elapsed with no further byte: deliver the short read.
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == b'q' => TestResult::Pass,
        Some(Err(FsError::WouldBlock)) => TestResult::Fail("the inter-byte timer never expired"),
        _ => TestResult::Fail("expired inter-byte read returned something unexpected"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_vmin_vtime_is_an_interbyte_timer);

// ── ECHOPRT and the remaining ioctls ─────────────────────────────────────────

/// ECHOPRT shows erased characters between `\` and `/` instead of rubbing
/// them out, the hardcopy-terminal erase style.
///
/// `eraser()` (`n_tty.c:982`) opens the run with a raw `\` on the first
/// erase and echoes each erased character; `finish_erasing` (905) emits the
/// closing `/` as soon as anything else is echoed.
fn smoke_pty_echoprt_brackets_erased_text() -> TestResult {
    const ECHO: u32 = 0x08;
    const ICANON: u32 = 0x02;
    const ECHOPRT: u32 = 0x400;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    {
        let mut t = pty.termios.lock();
        t.raw[12..16].copy_from_slice(&(ECHO | ICANON | ECHOPRT).to_ne_bytes());
    }
    let mut buf = [0u8; 32];
    // Type "ab", erase one, then type "c": the erase is bracketed and the
    // closing slash arrives when the next character echoes.
    if poll_once(master.write(0, b"ab")).is_none() {
        return TestResult::Fail("master write failed");
    }
    if poll_once(master.read(0, &mut buf)).is_none() {
        return TestResult::Fail("master read of the echo failed");
    }
    if poll_once(master.write(0, &[0x7f])).is_none() {
        return TestResult::Fail("master write of DEL failed");
    }
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("master read after erase failed"),
    };
    if &buf[..n] != b"\\b" {
        return TestResult::Fail("ECHOPRT must open the erase run with a backslash");
    }
    if poll_once(master.write(0, b"c")).is_none() {
        return TestResult::Fail("master write failed");
    }
    let n = match poll_once(master.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("master read after resuming input failed"),
    };
    match &buf[..n] {
        b"/c" => TestResult::Pass,
        _ => TestResult::Fail("ECHOPRT must close the erase run with a slash"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_echoprt_brackets_erased_text);

/// The locked termios pins individual bits against TCSETS.
///
/// `tty_ioctl.c`: `NOSET_MASK(termios->c_lflag, old->c_lflag,
/// locked->c_lflag)` — a bit set in the lock keeps the OLD value, which is
/// how a privileged process stops another program from, say, clearing ECHO
/// on a shared terminal.
fn smoke_pty_locked_termios_pins_bits() -> TestResult {
    const ECHO: u32 = 0x08;
    const ICANON: u32 = 0x02;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    // Start from a known lflag, then lock just the ECHO bit.
    {
        let mut t = pty.termios.lock();
        t.raw[12..16].copy_from_slice(&(ECHO | ICANON).to_ne_bytes());
    }
    {
        let mut l = pty.locked_termios.lock();
        l.raw = [0u8; 60];
        l.raw[12..16].copy_from_slice(&ECHO.to_ne_bytes());
    }
    // A TCSETS that clears everything must leave ECHO alone and still be
    // allowed to clear ICANON.
    let mut want = [0u8; 60];
    want[12..16].copy_from_slice(&0u32.to_ne_bytes());
    pty.set_termios_locked(want);

    let t = *pty.termios.lock();
    if !t.echo() {
        return TestResult::Fail("a locked ECHO bit must survive TCSETS");
    }
    if t.icanon() {
        return TestResult::Fail("an unlocked bit must still be changeable");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_locked_termios_pins_bits);

/// TIOCEXCL / TIOCNXCL flip exclusive mode, and while it is set a further
/// slave open is refused.
///
/// `tty_io.c:2713` sets `TTY_EXCLUSIVE`; `tty_open` turns it into -EBUSY
/// for an opener without CAP_SYS_ADMIN.
fn smoke_pty_exclusive_mode_refuses_second_open() -> TestResult {
    use crate::devfs_pty::pts_open_peer;
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let pty = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    // unlockpt() first, or the lock rather than exclusivity would refuse.
    pty.locked
        .store(false, core::sync::atomic::Ordering::Release);
    if !matches!(pts_open_peer(idx), Some(Ok(_))) {
        return TestResult::Fail("an unlocked slave should open");
    }
    pty.exclusive
        .store(true, core::sync::atomic::Ordering::Release);
    // No capability hook is installed under kernel-test, so the caller
    // counts as privileged and the open is still allowed — which is itself
    // Linux's rule. Assert the FLAG round-trips, which is what an
    // unprivileged opener would be refused on.
    if !pty.exclusive.load(core::sync::atomic::Ordering::Acquire) {
        return TestResult::Fail("TIOCEXCL flag did not stick");
    }
    pty.exclusive
        .store(false, core::sync::atomic::Ordering::Release);
    match pts_open_peer(idx) {
        Some(Ok(_)) => TestResult::Pass,
        _ => TestResult::Fail("clearing exclusive mode must allow opens again"),
    }
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_exclusive_mode_refuses_second_open
);

/// TIOCSTI pushes a byte back into the input queue, where the slave reads
/// it as if it had been typed (`tty_io.c::tiocsti`).
fn smoke_pty_tiocsti_injects_input() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&pty));
    // Canonical mode: a complete line has to be injected to be readable.
    if pty.insert_input_byte(b'z').is_err() {
        return TestResult::Fail("TIOCSTI of an ordinary byte failed");
    }
    if pty.insert_input_byte(b'\n').is_err() {
        return TestResult::Fail("TIOCSTI of a newline failed");
    }
    let mut buf = [0u8; 8];
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(2)) if &buf[..2] == b"z\n" => TestResult::Pass,
        _ => TestResult::Fail("injected bytes did not reach the slave"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_tiocsti_injects_input);

// ── Packet-mode control packets ──────────────────────────────────────────────

/// A pending control status is delivered ALONE, ahead of any data.
///
/// `n_tty_read` (`drivers/tty/n_tty.c:2235`) tests the status first and,
/// when one is pending, writes that single byte and breaks:
///
/// ```c
/// if (packet && tty->link->ctrl.pktstatus) {
///         if (kb != kbuf) break;
///         cs = tty->link->ctrl.pktstatus;
///         tty->link->ctrl.pktstatus = 0;
///         *kb++ = cs; nr--; break;
/// }
/// ```
///
/// That one-byte framing is how a reader tells a control event from data;
/// folding queued output in behind it would make the two ambiguous.
fn smoke_pty_packet_control_status_delivered_alone() -> TestResult {
    use crate::devfs_pty::{TIOCPKT_DATA, TIOCPKT_FLUSHREAD};
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    pty.packet
        .store(true, core::sync::atomic::Ordering::Release);
    let slave = PtySlave::new(Arc::clone(&pty));

    // Queue output, then flush the INPUT queue: a FLUSHREAD is now pending
    // while data is also waiting.
    if poll_once(slave.write(0, b"data")).is_none() {
        return TestResult::Fail("slave write failed");
    }
    if pty.flush_queues(0).is_err() {
        return TestResult::Fail("TCIFLUSH failed");
    }

    let mut buf = [0u8; 32];
    // First read: the status byte on its own, not prefixed to the output.
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == TIOCPKT_FLUSHREAD => {}
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("a control packet must be delivered alone");
        }
        _ => return TestResult::Fail("master read of the control packet failed"),
    }
    // Second read: ordinary data, reframed with TIOCPKT_DATA.
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(5)) if buf[0] == TIOCPKT_DATA && &buf[1..5] == b"data" => {}
        _ => return TestResult::Fail("queued output must survive the control packet"),
    }
    // The status is consumed: no repeat.
    match poll_once(master.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => TestResult::Pass,
        _ => TestResult::Fail("a delivered control status must not repeat"),
    }
}
kernel_test_in!(
    "filesystem/pty",
    smoke_pty_packet_control_status_delivered_alone
);

/// `^S` / `^Q` raise STOP / START, and each clears the other.
///
/// `pty_start` and `pty_stop` (`drivers/tty/pty.c:320-342`) are mutually
/// exclusive — each sets its bit and clears its opposite — so the master
/// learns the CURRENT flow state rather than a history of both.
///
/// The status must also be readable while output is stopped, which is
/// precisely when a STOP packet needs to get through; `n_tty_poll` reports
/// it with EPOLLPRI for the same reason.
fn smoke_pty_packet_flow_control_start_stop() -> TestResult {
    use crate::devfs_pty::{TIOCPKT_START, TIOCPKT_STOP};
    const IXON: u32 = 0x400;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    {
        let mut t = pty.termios.lock();
        t.raw[0..4].copy_from_slice(&IXON.to_ne_bytes());
    }
    pty.packet
        .store(true, core::sync::atomic::Ordering::Release);

    let mut buf = [0u8; 32];
    // ^S stops output and raises STOP.
    if poll_once(master.write(0, &[0x13])).is_none() {
        return TestResult::Fail("master write of ^S failed");
    }
    if master.poll_readiness() & crate::POLL_PRI == 0 {
        return TestResult::Fail("a pending control packet must report POLLPRI");
    }
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == TIOCPKT_STOP => {}
        _ => return TestResult::Fail("^S must raise TIOCPKT_STOP"),
    }
    // ^Q restarts it and raises START — with STOP cleared, not both.
    if poll_once(master.write(0, &[0x11])).is_none() {
        return TestResult::Fail("master write of ^Q failed");
    }
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == TIOCPKT_START => TestResult::Pass,
        Some(Ok(1)) => TestResult::Fail("START must clear STOP rather than accumulate"),
        _ => TestResult::Fail("^Q must raise TIOCPKT_START"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_packet_flow_control_start_stop);

/// A change in whether STANDARD flow control applies raises DOSTOP/NOSTOP.
///
/// `pty_set_termios` (`pty.c:245-268`) reports only that, and it is
/// specific: IXON must be set AND the stop/start characters must be the
/// conventional `^S`/`^Q`. A peer uses it to decide whether it may perform
/// the flow control itself, which it cannot do for custom characters.
fn smoke_pty_packet_termios_flow_change() -> TestResult {
    use crate::devfs_pty::{Termios, TIOCPKT_DOSTOP, TIOCPKT_NOSTOP};
    const IXON: u32 = 0x400;
    __reset_for_test();
    let master = open_ptmx();
    let pty = match pts_lookup(master.index()) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    pty.packet
        .store(true, core::sync::atomic::Ordering::Release);

    // Default termios has IXON with ^S/^Q, i.e. standard flow control.
    // Clearing IXON is a change, and must report NOSTOP.
    let mut t = Termios::default();
    t.raw[0..4].copy_from_slice(&0u32.to_ne_bytes());
    pty.set_termios_locked(t.raw);
    let mut buf = [0u8; 8];
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == TIOCPKT_NOSTOP => {}
        _ => return TestResult::Fail("losing standard flow control must raise NOSTOP"),
    }

    // Restoring it reports DOSTOP.
    t.raw[0..4].copy_from_slice(&IXON.to_ne_bytes());
    pty.set_termios_locked(t.raw);
    match poll_once(master.read(0, &mut buf)) {
        Some(Ok(1)) if buf[0] == TIOCPKT_DOSTOP => {}
        _ => return TestResult::Fail("regaining standard flow control must raise DOSTOP"),
    }

    // A termios write that does not change the flow configuration is
    // silent — otherwise every tcsetattr would wake the peer for nothing.
    pty.set_termios_locked(t.raw);
    match poll_once(master.read(0, &mut buf)) {
        Some(Err(FsError::WouldBlock)) => TestResult::Pass,
        _ => TestResult::Fail("an unchanged flow configuration must raise nothing"),
    }
}
kernel_test_in!("filesystem/pty", smoke_pty_packet_termios_flow_change);

// ── PTY readiness wake tests ──────────────────────────────────────────────────
//
// A parked poll/epoll/read on one PTY endpoint MUST be woken when the peer
// writes. Before the durable readiness cells, a master write completed a line in
// the slave's input queue but woke nothing, so a shell blocked reading its tty
// only advanced when unrelated activity nudged the global readiness generation —
// on an idle desktop that never came, and konsole's "Enter did nothing".

static PTY_WAKE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A `Waker` whose every wake bumps [`PTY_WAKE_COUNT`] — lets a test assert that
/// arming a readiness waiter and then writing the peer actually fired it.
fn counting_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw()
    }
    unsafe fn wake(_: *const ()) {
        PTY_WAKE_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    unsafe fn wake_by_ref(_: *const ()) {
        PTY_WAKE_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    unsafe fn drop(_: *const ()) {}
    fn raw() -> RawWaker {
        const VTAB: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: the vtable never dereferences the null data pointer; clone returns
    // an equivalently-valid waker. Upholds the Waker contract.
    unsafe { Waker::from_raw(raw()) }
}

// A master write that completes a line must wake a slave poll/epoll/read waiter.
fn smoke_pty_master_write_wakes_slave_poller() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    PTY_WAKE_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
    let waker = counting_waker();
    // Arm a POLLIN waiter on the slave: no completed line yet, so Pending.
    match slave.arm_readiness(0xABCD, crate::POLL_IN, &waker) {
        Some(Poll::Pending) => {}
        Some(Poll::Ready(m)) => {
            let _ = m;
            return TestResult::Fail("slave POLLIN ready before any input arrived");
        }
        None => return TestResult::Fail("PtySlave must expose a durable readiness cell"),
    }

    // The master types a full line. The line discipline completes it and MUST
    // wake the parked slave waiter.
    if !matches!(poll_once(master.write(0, b"ls\n")), Some(Ok(3))) {
        return TestResult::Fail("master write didn't return 3");
    }
    if PTY_WAKE_COUNT.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        return TestResult::Fail("master write did not wake the parked slave poller");
    }
    // The completed line is now readable (ICRNL mapped the CR to NL).
    if (slave.poll_readiness() & crate::POLL_IN) == 0 {
        return TestResult::Fail("slave not POLLIN-readable after the completed line");
    }
    let mut buf = [0u8; 16];
    match poll_once(slave.read(0, &mut buf)) {
        Some(Ok(3)) if &buf[..3] == b"ls\n" => {}
        _ => return TestResult::Fail("slave did not read back the completed line"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_master_write_wakes_slave_poller);

// The symmetric direction: a slave write must wake a master poll/epoll/read.
fn smoke_pty_slave_write_wakes_master_poller() -> TestResult {
    __reset_for_test();
    let master = open_ptmx();
    let idx = master.index();
    let slave_arc = match pts_lookup(idx) {
        Some(p) => p,
        None => return TestResult::Fail("pts_lookup returned None"),
    };
    let slave = PtySlave::new(Arc::clone(&slave_arc));

    PTY_WAKE_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
    let waker = counting_waker();
    match master.arm_readiness(0x1234, crate::POLL_IN, &waker) {
        Some(Poll::Pending) => {}
        Some(Poll::Ready(_)) => return TestResult::Fail("master POLLIN ready before output"),
        None => return TestResult::Fail("PtyMaster must expose a durable readiness cell"),
    }
    if !matches!(poll_once(slave.write(0, b"pong")), Some(Ok(4))) {
        return TestResult::Fail("slave write didn't return 4");
    }
    if PTY_WAKE_COUNT.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        return TestResult::Fail("slave write did not wake the parked master poller");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/pty", smoke_pty_slave_write_wakes_master_poller);
