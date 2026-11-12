//! Timeout → reset → replay smokes: `run_with_replay` and the last look at
//! the CQ, driven through the registry's block device against QEMU's NVMe
//! controller with the test-only fault hooks.
//!
//! Two faults are injected, both on the real submission paths:
//!  - a *lost* command ([`super::IO_LOSE_FOR_TEST`]): the SQE is written but
//!    the SQ doorbell is never rung, so the device never sees the command
//!    and no completion ever arrives. Whatever the request achieves, the
//!    replay achieved it.
//!  - a *late* completion ([`super::IO_LATE_FOR_TEST`]): the command runs
//!    normally but the wait ignores the CQ until the budget is spent, so
//!    only the last look can find the completion.
//!
//! The I/O budget is shortened for the duration ([`FAULT_TIMEOUT_MS`]); the
//! production budget is a constant the smokes only compare against.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use narf_block::{BlockDeviceSync, BlockIoError};
use narf_kernel_test::{kernel_test_in, TestResult};

use super::tests_multi::{pattern, reinstall, SCRATCH_BLOCKS, SCRATCH_LBA};
use super::{IO_LATE_FOR_TEST, IO_LOSE_FOR_TEST, IO_MAX_RETRIES, IO_TIMEOUT_MS_FOR_TEST};

/// I/O completion budget while a fault smoke runs. QEMU completes a 20 KiB
/// transfer in well under a millisecond, so this is generous for the late
/// completion to be sitting in the CQ at the last look, and short enough
/// that seven timeouts in a row stay near a second.
const FAULT_TIMEOUT_MS: u64 = 150;

/// The fault hooks, armed for one smoke and disarmed on every exit path.
#[derive(Debug)]
struct FaultHooks;

impl FaultHooks {
    fn arm() -> Self {
        IO_LOSE_FOR_TEST.store(0, Ordering::Release);
        IO_LATE_FOR_TEST.store(0, Ordering::Release);
        IO_TIMEOUT_MS_FOR_TEST.store(FAULT_TIMEOUT_MS, Ordering::Release);
        FaultHooks
    }
    /// Lose the next `n` I/O commands.
    fn lose(&self, n: u32) {
        IO_LOSE_FOR_TEST.store(n, Ordering::Release);
    }
    /// Make the next `n` I/O commands complete late.
    fn late(&self, n: u32) {
        IO_LATE_FOR_TEST.store(n, Ordering::Release);
    }
    fn pending_losses(&self) -> u32 {
        IO_LOSE_FOR_TEST.load(Ordering::Acquire)
    }
}

impl Drop for FaultHooks {
    fn drop(&mut self) {
        IO_LOSE_FOR_TEST.store(0, Ordering::Release);
        IO_LATE_FOR_TEST.store(0, Ordering::Release);
        IO_TIMEOUT_MS_FOR_TEST.store(0, Ordering::Release);
    }
}

fn nvme0_dead() -> Option<bool> {
    super::with_controller_at(0, |c| c.is_dead())
}

/// Bring nvme0 up fresh, save the scratch window, run `body` with the fault
/// hooks armed, then disarm and restore the window whatever `body` found.
fn with_fault_fixture(
    body: impl FnOnce(&dyn BlockDeviceSync, &FaultHooks) -> Result<(), &'static str>,
) -> TestResult {
    if super::controller_count() < 1 {
        return TestResult::Skip("needs an NVMe controller");
    }
    if super::IO_TIMEOUT_MS != 30_000 || IO_MAX_RETRIES != 5 {
        return TestResult::Fail("I/O budget / replay limit differ from Linux (30 s, 5)");
    }
    if let Err(e) = reinstall(0) {
        return TestResult::Fail(e);
    }
    let Some(d): Option<Arc<dyn BlockDeviceSync>> = narf_block::find_block_device("nvme0n1") else {
        return TestResult::Fail("nvme0n1 not registered");
    };
    let n = SCRATCH_BLOCKS;
    let mut saved = vec![0u8; n as usize * 512];
    if d.read(SCRATCH_LBA, n, &mut saved).is_err() {
        return TestResult::Fail("initial scratch read failed");
    }
    let hooks = FaultHooks::arm();
    let outcome = body(&*d, &hooks);
    drop(hooks);
    // The window is restored on a controller that must be answering again:
    // every body leaves it reset, never dead.
    let restored = d.write(SCRATCH_LBA, n, &saved).is_ok();
    match outcome {
        Err(e) => TestResult::Fail(e),
        Ok(()) if !restored => TestResult::Fail("restoring the scratch window failed"),
        Ok(()) => TestResult::Pass,
    }
}

/// Fill the controller's DMA scratch with something that is not the
/// pattern: a read of LBA 0.. goes through the same scratch a later read
/// of the window uses, so a "replay" that returned without transferring
/// would hand back these bytes, not the pattern.
fn scramble_scratch(d: &dyn BlockDeviceSync, p: &[u8]) -> Result<(), &'static str> {
    let mut other = vec![0u8; p.len()];
    d.read(0, SCRATCH_BLOCKS, &mut other)
        .map_err(|_| "scratch-scrambling read failed")?;
    if other == p {
        return Err("fixture: LBA 0.. already holds the test pattern");
    }
    Ok(())
}

/// A command whose first attempt times out is replayed after a controller
/// reset and succeeds with correct data — for a write (the pattern can only
/// be on the disk because the replay wrote it, from the caller's data), a
/// read (the pattern can only be in the caller's buffer because the replay
/// read it) and a Flush. One timeout, one reset, one replay each; the
/// caller sees no error.
fn smoke_nvme_lost_command_is_replayed_qemu() -> TestResult {
    with_fault_fixture(|d, hooks| {
        let n = SCRATCH_BLOCKS;
        let len = n as usize * 512;
        let replays0 = super::io_replays();
        let timeouts0 = super::command_timeouts();

        // Write.
        let p = pattern(0xA7);
        hooks.lose(1);
        if d.write(SCRATCH_LBA, n, &p).is_err() {
            return Err("a write whose first attempt timed out was not replayed to success");
        }
        if hooks.pending_losses() != 0 {
            return Err("the write never took the fault: nothing was tested");
        }
        if super::io_replays() != replays0 + 1 || super::command_timeouts() != timeouts0 + 1 {
            return Err("a lost write was not exactly one timeout and one replay");
        }
        if nvme0_dead() != Some(false) {
            return Err("controller left dead after a replayed write");
        }
        let mut back = vec![0u8; len];
        if d.read(SCRATCH_LBA, n, &mut back).is_err() {
            return Err("read-back after the replayed write failed");
        }
        if back != p {
            return Err("the replayed write did not put the caller's data on the disk");
        }

        // Read.
        scramble_scratch(d, &p)?;
        let mut back: Vec<u8> = vec![0u8; len];
        hooks.lose(1);
        if d.read(SCRATCH_LBA, n, &mut back).is_err() {
            return Err("a read whose first attempt timed out was not replayed to success");
        }
        if hooks.pending_losses() != 0 {
            return Err("the read never took the fault: nothing was tested");
        }
        if super::io_replays() != replays0 + 2 || super::command_timeouts() != timeouts0 + 2 {
            return Err("a lost read was not exactly one timeout and one replay");
        }
        if back != p {
            return Err("the replayed read returned wrong data");
        }

        // Flush: a command is only sent to a controller with a volatile
        // write cache.
        if super::with_controller_at(0, |c| c.has_volatile_write_cache()) == Some(true) {
            let flushes0 = super::with_controller_at(0, |c| c.flushes_completed()).unwrap_or(0);
            hooks.lose(1);
            if super::NvmeNamespaceBlock::new(0, 1).flush().is_err() {
                return Err("a Flush whose first attempt timed out was not replayed to success");
            }
            if hooks.pending_losses() != 0 || super::io_replays() != replays0 + 3 {
                return Err("a lost Flush was not exactly one replay");
            }
            // The counter survives the in-place reset; only the replayed
            // Flush completed.
            if super::with_controller_at(0, |c| c.flushes_completed()) != Some(flushes0 + 1) {
                return Err("the replayed Flush did not complete exactly once");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/nvme/retry",
    smoke_nvme_lost_command_is_replayed_qemu
);

/// Replays are bounded and the final error is returned: with every attempt
/// lost, a read is attempted `1 + IO_MAX_RETRIES` times and then fails; the
/// next request on the still-silent controller gets a single attempt and
/// no replay (the budget is consecutive timeouts on the controller); and
/// once the device answers again I/O works at once — the controller was
/// reset at the timeout, not left dead — and the replay budget is back.
fn smoke_nvme_replay_is_bounded_qemu() -> TestResult {
    with_fault_fixture(|d, hooks| {
        let n = SCRATCH_BLOCKS;
        let len = n as usize * 512;
        let p = pattern(0x3C);
        if d.write(SCRATCH_LBA, n, &p).is_err() {
            return Err("pattern write failed");
        }
        let replays0 = super::io_replays();
        let timeouts0 = super::command_timeouts();
        let mut back = vec![0u8; len];

        hooks.lose(u32::MAX);
        if d.read(SCRATCH_LBA, n, &mut back) != Err(BlockIoError::DriverError) {
            return Err("a request that keeps timing out did not return the I/O error");
        }
        if super::io_replays() != replays0 + IO_MAX_RETRIES as u64 {
            return Err("the request was not replayed exactly IO_MAX_RETRIES times");
        }
        if super::command_timeouts() != timeouts0 + IO_MAX_RETRIES as u64 + 1 {
            return Err("the request was not attempted exactly 1 + IO_MAX_RETRIES times");
        }

        // Still silent: one attempt, no replay, the error again.
        if d.read(SCRATCH_LBA, n, &mut back) != Err(BlockIoError::DriverError) {
            return Err("a request on a still-silent controller did not fail");
        }
        if super::io_replays() != replays0 + IO_MAX_RETRIES as u64
            || super::command_timeouts() != timeouts0 + IO_MAX_RETRIES as u64 + 2
        {
            return Err("a controller past its replay budget was replayed again");
        }

        // The device answers again.
        hooks.lose(0);
        if nvme0_dead() != Some(false) {
            return Err("the controller was left dead instead of reset at the timeout");
        }
        scramble_scratch(d, &p)?;
        if d.read(SCRATCH_LBA, n, &mut back).is_err() || back != p {
            return Err("I/O did not resume with intact data once the device answered");
        }
        // A completed command ends the streak: replays are available again.
        scramble_scratch(d, &p)?;
        let mut again = vec![0u8; len];
        hooks.lose(1);
        if d.read(SCRATCH_LBA, n, &mut again).is_err() || again != p {
            return Err("the replay budget did not come back after a completed command");
        }
        if super::io_replays() != replays0 + IO_MAX_RETRIES as u64 + 1 {
            return Err("the post-recovery lost read was not replayed exactly once");
        }
        Ok(())
    })
}
kernel_test_in!("drivers/nvme/retry", smoke_nvme_replay_is_bounded_qemu);

/// A completion the wait missed is found by the last look at the CQ when
/// the budget runs out (Linux "timeout, completion polled"): the command
/// succeeds with correct data, and nothing is declared lost — no timeout,
/// no reset, no replay.
fn smoke_nvme_late_completion_is_polled_qemu() -> TestResult {
    with_fault_fixture(|d, hooks| {
        let n = SCRATCH_BLOCKS;
        let p = pattern(0x5E);
        if d.write(SCRATCH_LBA, n, &p).is_err() {
            return Err("pattern write failed");
        }
        scramble_scratch(d, &p)?;
        let late0 = super::late_completions();
        let replays0 = super::io_replays();
        let timeouts0 = super::command_timeouts();
        let mut back = vec![0u8; n as usize * 512];
        hooks.late(1);
        if d.read(SCRATCH_LBA, n, &mut back).is_err() {
            return Err("a late completion failed the command instead of being polled");
        }
        if IO_LATE_FOR_TEST.load(Ordering::Acquire) != 0 {
            return Err("the read never took the fault: nothing was tested");
        }
        if back != p {
            return Err("the polled late completion returned wrong data");
        }
        if super::late_completions() != late0 + 1 {
            return Err("the late completion was not counted");
        }
        if super::command_timeouts() != timeouts0 || super::io_replays() != replays0 {
            return Err("a command that completed was declared lost");
        }
        if nvme0_dead() != Some(false) {
            return Err("a late completion marked the controller dead");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/nvme/retry",
    smoke_nvme_late_completion_is_polled_qemu
);

/// The queued block path (`NvmeBlockDevice::submit` → `req::NvmeRequest`)
/// hands the device the caller's own DMA buffer. When its request fails
/// with a timeout the controller has been reset at the timeout site —
/// confirmed disabled, so nothing can still write the buffer — and the
/// request's pin on the buffer is released with the reset: not retained,
/// its reference count unchanged.
fn smoke_nvme_timed_out_buffer_released_after_confirmed_reset_qemu() -> TestResult {
    use narf_block::{BlockDevice, BlockError, BlockOp, BlockRequest, QosHint};
    use narf_io::{alloc_coherent, register_with_cap, resolve_cap};
    use narf_lib::id::DomainId;
    with_fault_fixture(|_d, hooks| {
        let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "alloc_coherent failed")?;
        let write_cap = register_with_cap(buf);
        let request = || -> Result<BlockRequest, &'static str> {
            Ok(BlockRequest {
                op: BlockOp::Read,
                lba: SCRATCH_LBA,
                blocks: 1,
                buffer: write_cap
                    .derive::<narf_capabilities::Read>()
                    .map_err(|_| "derive Read from live write cap failed")?,
                qos: QosHint::Latency,
                user_tag: 0,
            })
        };
        let buffer = resolve_cap(&write_cap).ok_or("cap did not resolve to its buffer")?;
        let refs0 = Arc::strong_count(&buffer);
        let retained0 = super::retained_io_buffers();
        let replays0 = super::io_replays();
        let dev = super::NvmeBlockDevice;

        hooks.lose(u32::MAX);
        let r = narf_scheduler::block_on_spin(dev.submit(request()?)).result;
        hooks.lose(0);
        if r != Err(BlockError::IOError) {
            return Err("a submit that keeps timing out did not return the I/O error");
        }
        if super::io_replays() != replays0 + IO_MAX_RETRIES as u64 {
            return Err("the queued submit was not replayed IO_MAX_RETRIES times");
        }
        // Reset at the timeout site: alive again, hence confirmed stopped
        // in between.
        if super::with_controller_at(0, |c| c.is_dead() || c.may_still_dma()) != Some(false) {
            return Err("the controller was not reset before the request returned");
        }
        if super::retained_io_buffers() != retained0 || Arc::strong_count(&buffer) != refs0 {
            return Err("the buffer was retained although the controller was confirmed disabled");
        }
        // And the same request works once the device answers.
        if narf_scheduler::block_on_spin(dev.submit(request()?))
            .result
            .is_err()
        {
            return Err("the request did not succeed once the device answered");
        }
        narf_io::unregister(write_cap);
        Ok(())
    })
}
kernel_test_in!(
    "drivers/nvme/retry",
    smoke_nvme_timed_out_buffer_released_after_confirmed_reset_qemu
);

/// The other half: when the controller could NOT be shown disabled at the
/// teardown that follows a timeout, it may still write the command's
/// pages, so the queue leaks them — the payload pin and the PRP page — and
/// the memory can never be recycled under that write. A teardown after a
/// confirmed stop frees them. Device-less fake queue: only the decision
/// is under test.
fn smoke_nvme_timed_out_buffer_retained_while_device_live() -> TestResult {
    use super::mq::{Cmd, CmdResources};
    use super::tests_cid::fake_cid_controller_with;
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let Ok(buf) = alloc_coherent(4096, DomainId::DRIVER_0) else {
        return TestResult::Fail("alloc_coherent failed");
    };
    let buffer = Arc::new(buf);
    let retained0 = super::retained_io_buffers();
    let post = |fx: &super::tests_cid::FakeCidCtrl| -> Option<Cmd> {
        let q = fx.ctrl.io_queues()[0].clone();
        let tag = q.try_alloc_tag(None)?;
        let mut sqe = super::Sqe::zero();
        sqe.cdw0 = super::IoOpcode::Read as u32;
        sqe.nsid = 1;
        sqe.prp1 = buffer.dma_addr().raw();
        let res = CmdResources {
            prp_list: q.prp_page(),
            hold: Some(Arc::clone(&buffer)),
        };
        let id = q.post(tag, sqe, res).ok()?;
        Some(Cmd::new(q, id))
    };

    // Confirmed stopped: the pages come back.
    let Some(fx) = fake_cid_controller_with(None) else {
        return TestResult::Fail("fake controller setup failed");
    };
    let Some(cmd) = post(&fx) else {
        return TestResult::Fail("post failed");
    };
    drop(cmd);
    fx.ctrl.io_queues()[0].teardown(true);
    if Arc::strong_count(&buffer) != 1 || super::retained_io_buffers() != retained0 {
        return TestResult::Fail("a buffer was retained for a controller that cannot DMA");
    }

    // Never confirmed stopped: the device may still write them.
    let Some(fx) = fake_cid_controller_with(None) else {
        return TestResult::Fail("fake controller setup failed");
    };
    let Some(cmd) = post(&fx) else {
        return TestResult::Fail("post failed");
    };
    drop(cmd);
    fx.ctrl.io_queues()[0].teardown(false);
    if Arc::strong_count(&buffer) != 2 || super::retained_io_buffers() != retained0 + 2 {
        return TestResult::Fail("the pages of a possibly-live command were not retained");
    }
    // The leaked reference is the point of the test; the page stays
    // allocated for the rest of the boot.
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/retry",
    smoke_nvme_timed_out_buffer_retained_while_device_live
);
