//! Linux syscall ABI conformance — kernel-AIO (libaio) group.
//!
//! Exercises the synchronous libaio backend (see [[narf-libaio-sync-backend]]):
//! io_setup mints a context, io_submit runs each iocb synchronously and
//! queues an io_event, io_getevents reaps them, io_cancel/io_destroy behave
//! per Linux. All user-pointer buffers here are kernel-owned arrays passed by
//! address — the handlers access them through copy_from_user / copy_to_user,
//! so the tests are deterministic and SMAP-agnostic in the test harness.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// ── iocb / io_event field layout (Linux <uapi/linux/aio_abi.h>) ─────
const IOCB_SIZE: usize = 64;
const IO_EVENT_SIZE: usize = 32;

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_NOOP: u16 = 6;

/// Build a 64-byte iocb with the fields we test set.
fn make_iocb(
    data: u64,
    opcode: u16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
) -> [u8; IOCB_SIZE] {
    let mut b = [0u8; IOCB_SIZE];
    b[0..8].copy_from_slice(&data.to_le_bytes()); // aio_data
    b[16..18].copy_from_slice(&opcode.to_le_bytes()); // aio_lio_opcode
    b[20..24].copy_from_slice(&fildes.to_le_bytes()); // aio_fildes
    b[24..32].copy_from_slice(&buf.to_le_bytes()); // aio_buf
    b[32..40].copy_from_slice(&nbytes.to_le_bytes()); // aio_nbytes
    b[40..48].copy_from_slice(&offset.to_le_bytes()); // aio_offset
    b
}

/// Decode an io_event from a 32-byte kernel buffer.
fn decode_event(b: &[u8]) -> (u64, u64, i64, i64) {
    let data = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let obj = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let res = i64::from_le_bytes(b[16..24].try_into().unwrap());
    let res2 = i64::from_le_bytes(b[24..32].try_into().unwrap());
    (data, obj, res, res2)
}

fn open_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
    }
}

/// io_setup(nr_events, &ctx_id) → 0 and a non-zero ctx id written out.
fn io_setup(nr_events: u32) -> Result<u64, &'static str> {
    let mut ctx_id: u64 = 0;
    let r = call(
        Syscall::IoSetup.raw(),
        a1(nr_events as u64, (&mut ctx_id as *mut u64) as u64),
    );
    match r {
        Some(0) if ctx_id != 0 => Ok(ctx_id),
        _ => Err("io_setup did not return 0 + non-zero ctx id"),
    }
}

// ── io_setup / io_destroy ───────────────────────────────────────────

fn smoke_abi_aio_setup_writes_ctx() -> TestResult {
    with_setup(|| {
        let _ctx = io_setup(32)?;
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_setup_writes_ctx);

fn smoke_abi_aio_destroy_unknown() -> TestResult {
    with_setup(|| {
        // io_destroy of a ctx that was never set up → -EINVAL.
        match call(Syscall::IoDestroy.raw(), a0(0xdead_beef)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("io_destroy of unknown ctx should be -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_destroy_unknown);

fn smoke_abi_aio_setup_destroy_roundtrip() -> TestResult {
    with_setup(|| {
        let ctx = io_setup(8)?;
        match call(Syscall::IoDestroy.raw(), a0(ctx)) {
            Some(0) => Ok(()),
            _ => Err("io_destroy of a live ctx should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_setup_destroy_roundtrip);

// ── io_submit PWRITE then PREAD round-trip ──────────────────────────

fn smoke_abi_aio_write_read_roundtrip() -> TestResult {
    with_memfs("/aio", "aio", &[("f", b"")], || {
        let fd = open_fd(b"/aio/f\0")?;
        let ctx = io_setup(8)?;

        // Submit a PWRITE of "abcd" at offset 0.
        let payload = *b"abcd";
        let wr_iocb = make_iocb(
            0x1111,
            IOCB_CMD_PWRITE,
            fd,
            payload.as_ptr() as u64,
            payload.len() as u64,
            0,
        );
        let wr_ptr_arr = [(&wr_iocb as *const u8) as u64];
        let submitted = call(
            Syscall::IoSubmit.raw(),
            a2(ctx, 1, wr_ptr_arr.as_ptr() as u64),
        );
        if submitted != Some(1) {
            return Err("io_submit(PWRITE) should return 1");
        }

        // Reap the write completion.
        let mut evbuf = [0u8; IO_EVENT_SIZE];
        let got = call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 1, 1, evbuf.as_mut_ptr() as u64),
        );
        if got != Some(1) {
            return Err("io_getevents after PWRITE should return 1");
        }
        let (data, obj, res, res2) = decode_event(&evbuf);
        if data != 0x1111 || res != 4 || res2 != 0 || obj != (&wr_iocb as *const u8) as u64 {
            return Err("PWRITE io_event fields wrong");
        }

        // Submit a PREAD of 4 bytes at offset 0 into a fresh buffer.
        let mut rbuf = [0u8; 4];
        let rd_iocb = make_iocb(
            0x2222,
            IOCB_CMD_PREAD,
            fd,
            rbuf.as_mut_ptr() as u64,
            rbuf.len() as u64,
            0,
        );
        let rd_ptr_arr = [(&rd_iocb as *const u8) as u64];
        let submitted = call(
            Syscall::IoSubmit.raw(),
            a2(ctx, 1, rd_ptr_arr.as_ptr() as u64),
        );
        if submitted != Some(1) {
            return Err("io_submit(PREAD) should return 1");
        }
        let mut evbuf2 = [0u8; IO_EVENT_SIZE];
        let got = call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 1, 1, evbuf2.as_mut_ptr() as u64),
        );
        if got != Some(1) {
            return Err("io_getevents after PREAD should return 1");
        }
        let (data, _obj, res, _res2) = decode_event(&evbuf2);
        if data != 0x2222 || res != 4 || &rbuf != b"abcd" {
            return Err("PREAD did not round-trip the bytes");
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_write_read_roundtrip);

// ── batch submit returns 2 events ───────────────────────────────────

fn smoke_abi_aio_batch_two_events() -> TestResult {
    with_memfs("/aio", "aio", &[("f", b"XYZW")], || {
        let fd = open_fd(b"/aio/f\0")?;
        let ctx = io_setup(8)?;

        let mut r1 = [0u8; 2];
        let mut r2 = [0u8; 2];
        let iocb1 = make_iocb(0xa1, IOCB_CMD_PREAD, fd, r1.as_mut_ptr() as u64, 2, 0);
        let iocb2 = make_iocb(0xa2, IOCB_CMD_PREAD, fd, r2.as_mut_ptr() as u64, 2, 2);
        let arr = [(&iocb1 as *const u8) as u64, (&iocb2 as *const u8) as u64];
        let submitted = call(Syscall::IoSubmit.raw(), a2(ctx, 2, arr.as_ptr() as u64));
        if submitted != Some(2) {
            return Err("io_submit of 2 iocbs should return 2");
        }
        // Reap both events at once.
        let mut evs = [0u8; IO_EVENT_SIZE * 2];
        let got = call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 2, 2, evs.as_mut_ptr() as u64),
        );
        if got != Some(2) {
            return Err("io_getevents should reap 2 events");
        }
        let (d0, _, res0, _) = decode_event(&evs[..IO_EVENT_SIZE]);
        let (d1, _, res1, _) = decode_event(&evs[IO_EVENT_SIZE..]);
        if d0 != 0xa1 || d1 != 0xa2 || res0 != 2 || res1 != 2 {
            return Err("batch events have wrong data/res");
        }
        if &r1 != b"XY" || &r2 != b"ZW" {
            return Err("batch reads returned wrong bytes");
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_batch_two_events);

// ── bad fd → event res == -EBADF (not a syscall error) ──────────────

fn smoke_abi_aio_badfd_event() -> TestResult {
    with_setup(|| {
        let ctx = io_setup(4)?;
        let mut buf = [0u8; 4];
        let iocb = make_iocb(0x77, IOCB_CMD_PREAD, 4242, buf.as_mut_ptr() as u64, 4, 0);
        let arr = [(&iocb as *const u8) as u64];
        // io_submit still succeeds (returns 1) — the failure is in the event.
        let submitted = call(Syscall::IoSubmit.raw(), a2(ctx, 1, arr.as_ptr() as u64));
        if submitted != Some(1) {
            return Err("io_submit with a bad fd should still submit (return 1)");
        }
        let mut ev = [0u8; IO_EVENT_SIZE];
        let got = call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 1, 1, ev.as_mut_ptr() as u64),
        );
        if got != Some(1) {
            return Err("io_getevents should return the bad-fd event");
        }
        let (data, _obj, res, _res2) = decode_event(&ev);
        if data != 0x77 || res != EBADF {
            return Err("bad-fd io_event.res should be -EBADF");
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_badfd_event);

// ── NOOP succeeds with res == 0 ─────────────────────────────────────

fn smoke_abi_aio_noop() -> TestResult {
    with_setup(|| {
        let ctx = io_setup(4)?;
        let iocb = make_iocb(0x5a, IOCB_CMD_NOOP, 0, 0, 0, 0);
        let arr = [(&iocb as *const u8) as u64];
        let submitted = call(Syscall::IoSubmit.raw(), a2(ctx, 1, arr.as_ptr() as u64));
        if submitted != Some(1) {
            return Err("io_submit(NOOP) should return 1");
        }
        let mut ev = [0u8; IO_EVENT_SIZE];
        let got = call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 1, 1, ev.as_mut_ptr() as u64),
        );
        let (data, _obj, res, _res2) = decode_event(&ev);
        if got != Some(1) || data != 0x5a || res != 0 {
            return Err("NOOP event should be res=0");
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_noop);

// ── io_getevents on an empty ctx → 0 ────────────────────────────────

fn smoke_abi_aio_getevents_empty() -> TestResult {
    with_setup(|| {
        let ctx = io_setup(4)?;
        let mut ev = [0u8; IO_EVENT_SIZE];
        match call(
            Syscall::IoGetevents.raw(),
            a3(ctx, 0, 1, ev.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("io_getevents on an empty ctx should return 0"),
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_getevents_empty);

// ── io_getevents on an unknown ctx → -EINVAL ────────────────────────

fn smoke_abi_aio_getevents_unknown() -> TestResult {
    with_setup(|| {
        let mut ev = [0u8; IO_EVENT_SIZE];
        match call(
            Syscall::IoGetevents.raw(),
            a3(0xbadc0de, 0, 1, ev.as_mut_ptr() as u64),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("io_getevents on unknown ctx should be -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_getevents_unknown);

// ── io_cancel → -EINVAL (synchronous completions can't be cancelled) ─

fn smoke_abi_aio_cancel_einval() -> TestResult {
    with_setup(|| {
        let ctx = io_setup(4)?;
        match call(Syscall::IoCancel.raw(), a2(ctx, 0, 0)) {
            Some(v) if v == EINVAL => {}
            _ => return Err("io_cancel should return -EINVAL"),
        }
        let _ = call(Syscall::IoDestroy.raw(), a0(ctx));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_cancel_einval);

// ── io_submit on an unknown ctx → -EINVAL ───────────────────────────

fn smoke_abi_aio_submit_unknown_ctx() -> TestResult {
    with_setup(|| {
        let iocb = make_iocb(1, IOCB_CMD_NOOP, 0, 0, 0, 0);
        let arr = [(&iocb as *const u8) as u64];
        match call(Syscall::IoSubmit.raw(), a2(0xfeed, 1, arr.as_ptr() as u64)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("io_submit on unknown ctx should be -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_aio_submit_unknown_ctx);
