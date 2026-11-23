//! Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
//! Comet Lake) SAGV control: the pcode 0x21 enable/disable
//! primitives from `display/skl_watermark.c`.
//!
//! ## Which command controls SAGV on display 9
//!
//! `GEN9_PCODE_SAGV_CONTROL` (0x21,
//! `include/drm/intel/intel_pcode_regs.h:84`) is the pre-ICL
//! mechanism: `skl_sagv_enable` / `skl_sagv_disable`
//! (`display/skl_watermark.c:175-219`) write
//! `GEN9_SAGV_ENABLE` (0x3) / request `GEN9_SAGV_DISABLE`
//! (0x0) and poll for `GEN9_SAGV_IS_DISABLED` (0x1). It is
//! the Skylake (display 9) path; `skl_sagv_pre/post_plane_update`
//! runs it only below display 11. On display 11 SAGV is
//! instead controlled by restricting QGV points
//! (`intel_gpu_gen11_sagv`, command 0xe) — the two mechanisms
//! must not be mixed.
//!
//! ## The transactions
//!
//! - Enable is a pcode *write* transaction
//!   (`intel_parent_pcode_write`, 1 ms timeout): mailbox
//!   command 0x21, DATA0-in `GEN9_SAGV_ENABLE` (0x3). Linux
//!   does not wait for SAGV when enabling ("We don't need to
//!   wait for SAGV when enabling"), so neither does this
//!   primitive — the write completing is the whole enable.
//!   (NARF's `pcode_write` carries a 2 ms budget rather than
//!   Linux's 1 ms; same protocol, same mailbox word.)
//! - Disable is a pcode *read* transaction
//!   (`skl_pcode_request`, `intel_pcode.c:163`): the request
//!   is re-sent until the reply dword satisfies
//!   `(reply & GEN9_SAGV_IS_DISABLED) == GEN9_SAGV_IS_DISABLED`
//!   — i.e. DATA0-in is `GEN9_SAGV_DISABLE` (0x0) and the
//!   reply mask/value are both `GEN9_SAGV_IS_DISABLED` (0x1).
//!   Linux retries for a 1 ms base window and then a further
//!   50 ms with preemption disabled ("bspec says to keep
//!   retrying for at least 1 ms"); this module retries inside
//!   one 51 ms cycle budget, which bounds a wedged punit
//!   without depending on another task — the same budget
//!   shape as the display-11 restrict primitive.
//!
//! ## What this module does not do
//!
//! It is the enable/disable primitive, not the bandwidth
//! manager. The presence + status model
//! (`I915_SAGV_ENABLED / DISABLED / NOT_CONTROLLED`,
//! `intel_has_sagv`) lives with the caller: Linux gates both
//! functions on `intel_has_sagv(display)` and on the current
//! status (already-enabled / already-disabled return early),
//! and maps a Skylake `-ENXIO` ("no SAGV found on system")
//! to `NOT_CONTROLLED`. This module performs the mailbox
//! transaction and reports its outcome; the caller owns
//! presence, status tracking, and the pre/post-plane-update
//! sequencing (`skl_sagv_pre/post_plane_update`, which run
//! disable/enable around a plane update only when the
//! bandwidth state admits it).

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pcode::{pcode_read, pcode_write, PcodeError};

/// `GEN9_PCODE_SAGV_CONTROL` (0x21): the display-9 SAGV
/// control mailbox command.
pub const PCODE_CMD_SAGV_CONTROL_GEN9: u32 = 0x21;
/// `GEN9_SAGV_ENABLE` (0x3): the DATA0-in value that enables
/// SAGV.
pub const GEN9_SAGV_ENABLE: u32 = 0x3;
/// `GEN9_SAGV_DISABLE` (0x0): the DATA0-in request value
/// that disables SAGV.
pub const GEN9_SAGV_DISABLE: u32 = 0x0;
/// `GEN9_SAGV_IS_DISABLED` (0x1): the reply mask *and* the
/// reply value a disable request waits for.
pub const GEN9_SAGV_IS_DISABLED: u32 = 0x1;

/// Failure modes of a Gen9 SAGV request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9SagvError {
    /// The mailbox transaction itself failed.
    Pcode(PcodeError),
    /// The disable reply never carried `GEN9_SAGV_IS_DISABLED`
    /// inside the retry budget.
    Timeout,
}

impl From<PcodeError> for Gen9SagvError {
    fn from(e: PcodeError) -> Self {
        Gen9SagvError::Pcode(e)
    }
}

/// `skl_sagv_enable` for display 9: send
/// `GEN9_SAGV_ENABLE` (0x3) to the punit via the 0x21
/// mailbox command and return once the write completes —
/// Linux does not wait for SAGV when enabling. A mailbox
/// error fails at once. Presence and status tracking belong
/// to the caller (see the module header).
pub fn skl_sagv_enable<M: MmioWindow + ?Sized>(mmio: &M) -> Result<(), Gen9SagvError> {
    pcode_write(mmio, PCODE_CMD_SAGV_CONTROL_GEN9, 0, 0, GEN9_SAGV_ENABLE, 0)?;
    Ok(())
}

/// Whether a disable reply dword acknowledges the request:
/// `(reply & GEN9_SAGV_IS_DISABLED) ==
/// GEN9_SAGV_IS_DISABLED`, the check `skl_pcode_request`
/// applies to the reply of a `GEN9_SAGV_DISABLE` request.
pub const fn disable_acknowledged(data0: u32) -> bool {
    data0 & GEN9_SAGV_IS_DISABLED == GEN9_SAGV_IS_DISABLED
}

/// `skl_sagv_disable` for display 9: re-send the
/// `GEN9_SAGV_DISABLE` (0x0) request on the 0x21 mailbox
/// command until the reply dword acknowledges it, inside a
/// 51 ms budget (Linux's 1 ms base window plus its 50 ms
/// fallback). A mailbox error fails at once. Presence and
/// status tracking belong to the caller (see the module
/// header).
pub fn skl_sagv_disable<M: MmioWindow + ?Sized>(mmio: &M) -> Result<(), Gen9SagvError> {
    let budget = narf_time::wall::ns_to_cycles(51_000_000);
    let start = narf_time::now_cycles();
    loop {
        let (data0, _) = pcode_read(
            mmio,
            PCODE_CMD_SAGV_CONTROL_GEN9,
            0,
            0,
            GEN9_SAGV_DISABLE,
            0,
        )?;
        if disable_acknowledged(data0) {
            return Ok(());
        }
        if narf_time::now_cycles().wrapping_sub(start) > budget {
            return Err(Gen9SagvError::Timeout);
        }
        core::hint::spin_loop();
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the Gen9 SAGV conversation. The fake is
    //! a scripted pcode endpoint: the MAILBOX write runs the
    //! command at once (READY clears immediately) and DATA0
    //! answers the next scripted reply dword. Expected
    //! values are hand-derived from `skl_watermark.c` /
    //! `intel_pcode.c` — never recorded from the
    //! implementation under test.

    use super::*;
    use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_DATA1, PCODE_MAILBOX, PCODE_READY};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted pcode endpoint: `replies` is consumed one
    /// entry per MAILBOX write; once exhausted the endpoint
    /// keeps answering the last entry (so a stuck-not-disabled
    /// endpoint is scripted with a single 0x0).
    #[derive(Debug)]
    pub struct Gen9SagvMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        replies: RefCell<Vec<u32>>,
        data0: RefCell<u32>,
    }

    impl Gen9SagvMmio {
        fn new(replies: Vec<u32>) -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                replies: RefCell::new(replies),
                data0: RefCell::new(0),
            }
        }
    }

    impl MmioWindow for Gen9SagvMmio {
        fn read32(&self, off: u64) -> u32 {
            if off == PCODE_MAILBOX {
                // READY clears immediately; status 0.
                return 0;
            }
            if off == PCODE_DATA0 {
                return *self.data0.borrow();
            }
            0
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            if off == PCODE_MAILBOX {
                // The mailbox word's command byte must be the
                // Gen9 SAGV control command; anything else is
                // a fixture bug, not hardware behaviour.
                debug_assert_eq!(val & 0xFF, PCODE_CMD_SAGV_CONTROL_GEN9);
                debug_assert_eq!(val & PCODE_READY, PCODE_READY);
                let mut replies = self.replies.borrow_mut();
                let reply = if replies.len() > 1 {
                    replies.remove(0)
                } else {
                    replies.first().copied().unwrap_or(0)
                };
                *self.data0.borrow_mut() = reply;
            } else if off == PCODE_DATA0 {
                *self.data0.borrow_mut() = val;
            }
        }
    }

    fn smoke_gen9_sagv_command_values() -> TestResult {
        // The display-9 control command is 0x21, not the
        // display-11 0x0E the QGV mechanism uses.
        if PCODE_CMD_SAGV_CONTROL_GEN9 != 0x21 {
            return TestResult::Fail("Gen9 SAGV control command must be 0x21");
        }
        if GEN9_SAGV_ENABLE != 0x3 || GEN9_SAGV_DISABLE != 0x0 || GEN9_SAGV_IS_DISABLED != 0x1 {
            return TestResult::Fail("Gen9 SAGV request/reply values wrong");
        }
        // The disable acknowledgement is the low bit set;
        // other bits in the reply dword do not matter.
        if !disable_acknowledged(0x1) || !disable_acknowledged(0xFFFFFFFD) {
            return TestResult::Fail("a reply with the IS_DISABLED bit must acknowledge");
        }
        if disable_acknowledged(0x0) || disable_acknowledged(0x2) {
            return TestResult::Fail("a reply without the IS_DISABLED bit must not acknowledge");
        }
        // The display-11 command is a different mechanism —
        // pin that the two do not collide.
        if PCODE_CMD_SAGV_CONTROL_GEN9
            == crate::intel_gpu_gen11_sagv::PCODE_CMD_SAGV_DE_MEM_SS_CONFIG
        {
            return TestResult::Fail("Gen9 and Gen11 SAGV commands must differ");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_sagv",
        smoke_gen9_sagv_command_values
    );

    fn smoke_skl_sagv_enable_conversation() -> TestResult {
        let mmio = Gen9SagvMmio::new(alloc::vec![0x0]);
        if skl_sagv_enable(&mmio).is_err() {
            return TestResult::Fail("skl_sagv_enable failed over the scripted endpoint");
        }
        // The conversation: DATA0-in carries GEN9_SAGV_ENABLE,
        // then the mailbox word READY | 0x21. No wait, no
        // reply read — enabling does not poll.
        let writes = mmio.writes.borrow();
        if !writes.contains(&(PCODE_DATA0, GEN9_SAGV_ENABLE))
            || !writes.contains(&(PCODE_MAILBOX, PCODE_READY | 0x21))
        {
            return TestResult::Fail("enable must send GEN9_SAGV_ENABLE via the 0x21 command");
        }
        // DATA1 is written (zero) as part of the transaction.
        if !writes.contains(&(PCODE_DATA1, 0)) {
            return TestResult::Fail("enable must write DATA1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_sagv",
        smoke_skl_sagv_enable_conversation
    );

    fn smoke_skl_sagv_disable_accepts_at_once() -> TestResult {
        let mmio = Gen9SagvMmio::new(alloc::vec![0x1]);
        if skl_sagv_disable(&mmio).is_err() {
            return TestResult::Fail("an acknowledged disable must succeed");
        }
        let writes = mmio.writes.borrow();
        if !writes.contains(&(PCODE_DATA0, GEN9_SAGV_DISABLE))
            || !writes.contains(&(PCODE_MAILBOX, PCODE_READY | 0x21))
        {
            return TestResult::Fail("disable must send GEN9_SAGV_DISABLE via the 0x21 command");
        }
        let mailbox_writes = writes.iter().filter(|(o, _)| *o == PCODE_MAILBOX).count();
        if mailbox_writes != 1 {
            return TestResult::Fail("an acknowledged disable must send exactly one request");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_sagv",
        smoke_skl_sagv_disable_accepts_at_once
    );

    fn smoke_skl_sagv_disable_retries_then_accepts() -> TestResult {
        // Not-disabled, not-disabled, disabled: the request is
        // re-sent until the punit acknowledges it.
        let mmio = Gen9SagvMmio::new(alloc::vec![0x0, 0x0, 0x1]);
        if skl_sagv_disable(&mmio).is_err() {
            return TestResult::Fail("retry-then-acknowledge must succeed");
        }
        let mailbox_writes = mmio
            .writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == PCODE_MAILBOX)
            .count();
        if mailbox_writes != 3 {
            return TestResult::Fail("each unacknowledged reply must re-send the request");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_sagv",
        smoke_skl_sagv_disable_retries_then_accepts
    );

    fn smoke_skl_sagv_disable_timeout() -> TestResult {
        // A punit that never reports disabled: the retry loop
        // is bounded by the 51 ms budget, not infinite.
        let mmio = Gen9SagvMmio::new(alloc::vec![0x0]);
        if skl_sagv_disable(&mmio) != Err(Gen9SagvError::Timeout) {
            return TestResult::Fail("an endlessly unacknowledged disable must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_sagv",
        smoke_skl_sagv_disable_timeout
    );
}
