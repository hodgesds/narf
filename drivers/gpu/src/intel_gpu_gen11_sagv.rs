//! Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) SAGV
//! control: the QGV-point restriction pcode request that
//! enables and disables SAGV on display 11, and the reply
//! decoding that decides whether the restriction took.
//!
//! ## Which command controls SAGV on display 11
//!
//! Two different mechanisms exist, and the Gen11 watermark
//! module's header named the wrong one for ICL (corrected
//! here — see the remainder note in `intel_gpu_gen11_wm`):
//!
//! - `GEN9_PCODE_SAGV_CONTROL` (0x21) is the pre-ICL
//!   mechanism: `skl_sagv_enable` / `skl_sagv_disable`
//!   (`display/skl_watermark.c`) write `GEN9_SAGV_ENABLE` /
//!   request `GEN9_SAGV_DISABLE` and poll for
//!   `GEN9_SAGV_IS_DISABLED`. It is the Skylake (display 9)
//!   path, implemented in `intel_gpu_gen9_sagv`;
//!   `skl_sagv_pre/post_plane_update` runs it only below
//!   display 11.
//! - On display 11 SAGV is controlled by restricting QGV
//!   points: `icl_pcode_restrict_qgv_points`
//!   (`display/intel_bw.c`) sends
//!   `ICL_PCODE_SAGV_DE_MEM_SS_CONFIG` (0xe,
//!   `include/drm/intel/intel_pcode_regs.h:59`) with the
//!   allowed-points mask as the request, and the punit
//!   answers SAFE / POLL / REJECTED in the reply dword's
//!   QGV field. `icl_force_disable_sagv` restricts to the
//!   maximum-bandwidth point mask at init (SAGV starts
//!   forced off); `icl_sagv_pre_plane_update` restricts
//!   before a plane update and `icl_sagv_post_plane_update`
//!   relaxes the mask after it — masking and unmasking
//!   never happen in one step, per the BSpec note there.
//!
//! ## The request (`intel_pcode.c::skl_pcode_request`)
//!
//! A request is a pcode *read* transaction
//! (`__snb_pcode_rw`, `is_read = true`) with the mailbox
//! command 0xe and DATA0-in carrying the request (the QGV
//! points mask, `ICL_PCODE_REQ_QGV_PT`, bits [7:0]; the PSF
//! field, bits [10:8], is an Alder Lake addition and zero
//! on Gen11). The transaction succeeds when the mailbox
//! status is 0 *and* the reply DATA0 satisfies
//! `(reply & reply_mask) == reply`, where the caller passes
//! `reply_mask = ICL_PCODE_REP_QGV_MASK |
//! ADLS_PCODE_REP_PSF_MASK` (0xF) and `reply =
//! ICL_PCODE_REP_QGV_SAFE | ADLS_PCODE_REP_PSF_SAFE` (0).
//! The QGV reply field itself decodes as SAFE = 0, POLL = 1
//! (retry), REJECTED = 2. Linux retries a POLL reply for a
//! 1 ms base window and then a further 50 ms with preemption
//! disabled; this module retries inside one 51 ms cycle
//! budget, which bounds a wedged punit without depending on
//! another task.
//!
//! ## What this module does not do
//!
//! It is the restriction primitive, not the bandwidth
//! manager. Computing the mask — the QGV point inventory
//! (`ICL_PCODE_MEM_SS_READ_QGV_POINT_INFO`), the data-rate
//! / bandwidth calculation, `intel_bw_calc` — and the
//! sequencing around plane updates (`icl_sagv_pre/post_plane_update`,
//! the force-disable at `intel_bw_init`) belong to a
//! bandwidth-state lane, which this module's
//! [`restrict_qgv_points`] serves. The SAGV status model
//! (`I915_SAGV_ENABLED / DISABLED / NOT_CONTROLLED`,
//! `intel_has_sagv`) lives there too: presence is a platform
//! property (BIOS SAGV + the pcode block time), not something
//! a mailbox write can report.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pcode::{pcode_read, PcodeError};

/// `ICL_PCODE_SAGV_DE_MEM_SS_CONFIG` (0xe): the display-11
/// SAGV control mailbox command.
pub const PCODE_CMD_SAGV_DE_MEM_SS_CONFIG: u32 = 0x0E;
/// `ICL_PCODE_REQ_QGV_PT_MASK`: the allowed-QGV-points
/// field of the request, bits [7:0].
pub const SAGV_REQ_QGV_PT_MASK: u32 = 0xFF;
/// `ICL_PCODE_REP_QGV_MASK`: the QGV reply field, bits [1:0].
pub const SAGV_REP_QGV_MASK: u32 = 0x3;
/// `ICL_PCODE_REP_QGV_SAFE`: the punit accepted the mask.
pub const SAGV_REP_QGV_SAFE: u32 = 0;
/// `ICL_PCODE_REP_QGV_POLL`: not applied yet — retry.
pub const SAGV_REP_QGV_POLL: u32 = 1;
/// `ICL_PCODE_REP_QGV_REJECTED`: the punit refused the mask.
pub const SAGV_REP_QGV_REJECTED: u32 = 2;
/// `ADLS_PCODE_REP_PSF_MASK`: the PSF reply field, bits
/// [3:2]. Alder Lake and later; zero on Gen11, and the
/// restrict call passes its SAFE value (0) either way.
pub const SAGV_REP_PSF_MASK: u32 = 0xC;
/// The combined reply mask the restrict call checks:
/// QGV | PSF.
pub const SAGV_REPLY_MASK: u32 = SAGV_REP_QGV_MASK | SAGV_REP_PSF_MASK;
/// The combined reply value for acceptance: SAFE in both fields.
pub const SAGV_REPLY_SAFE: u32 = 0;

/// The QGV reply field of a SAGV restrict response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SagvReply {
    /// The punit accepted the points mask.
    Safe,
    /// Not applied yet — the request must be retried.
    Poll,
    /// The punit refused the points mask.
    Rejected,
}

/// Decode the QGV reply field from a restrict response
/// dword (`ICL_PCODE_REP_QGV_MASK`).
pub const fn decode_reply(data0: u32) -> SagvReply {
    match data0 & SAGV_REP_QGV_MASK {
        SAGV_REP_QGV_SAFE => SagvReply::Safe,
        SAGV_REP_QGV_POLL => SagvReply::Poll,
        _ => SagvReply::Rejected,
    }
}

/// Whether the full restrict reply accepts the mask:
/// `(reply & SAGV_REPLY_MASK) == SAGV_REPLY_SAFE`, the
/// check `icl_pcode_restrict_qgv_points` passes to
/// `skl_pcode_request`.
pub const fn reply_accepted(data0: u32) -> bool {
    data0 & SAGV_REPLY_MASK == SAGV_REPLY_SAFE
}

/// The SAGV restrict request word for a set of allowed QGV
/// points: `ICL_PCODE_REQ_QGV_PT(points)` — the points mask
/// in bits [7:0]. The PSF field stays zero on Gen11.
pub const fn qgv_request_mask(allowed_points: u16) -> u32 {
    (allowed_points as u32) & SAGV_REQ_QGV_PT_MASK
}

/// Failure modes of a SAGV restrict request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SagvError {
    /// The mailbox transaction itself failed.
    Pcode(PcodeError),
    /// The punit refused the points mask.
    Rejected,
    /// The reply stayed POLL past the retry budget.
    Timeout,
}

impl From<PcodeError> for SagvError {
    fn from(e: PcodeError) -> Self {
        SagvError::Pcode(e)
    }
}

/// `icl_pcode_restrict_qgv_points` for display 11: send the
/// allowed-QGV-points mask to the punit and wait for a SAFE
/// reply, retrying POLL replies inside a 51 ms budget
/// (Linux's 1 ms base window plus its 50 ms fallback).
/// A REJECTED reply fails at once; a mailbox error fails at
/// once. The request word is `qgv_request_mask(points)`;
/// callers pass the mask the bandwidth state computed — this
/// function never invents one.
pub fn restrict_qgv_points<M: MmioWindow + ?Sized>(
    mmio: &M,
    points_mask: u32,
) -> Result<(), SagvError> {
    let budget = narf_time::wall::ns_to_cycles(51_000_000);
    let start = narf_time::now_cycles();
    loop {
        let (data0, _) = pcode_read(mmio, PCODE_CMD_SAGV_DE_MEM_SS_CONFIG, 0, 0, points_mask, 0)?;
        match decode_reply(data0) {
            SagvReply::Safe => {
                if !reply_accepted(data0) {
                    return Err(SagvError::Rejected);
                }
                return Ok(());
            }
            SagvReply::Rejected => return Err(SagvError::Rejected),
            SagvReply::Poll => {
                if narf_time::now_cycles().wrapping_sub(start) > budget {
                    return Err(SagvError::Timeout);
                }
                core::hint::spin_loop();
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the SAGV restrict conversation. The fake
    //! is a scripted pcode endpoint: the MAILBOX write runs
    //! the command at once (READY clears immediately) and
    //! DATA0 answers the next scripted reply dword. Expected
    //! values are hand-derived from `intel_bw.c` /
    //! `intel_pcode.c` — never recorded from the
    //! implementation under test.

    use super::*;
    use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_DATA1, PCODE_MAILBOX, PCODE_READY};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted pcode endpoint: `replies` is consumed one
    /// entry per MAILBOX write; once exhausted the endpoint
    /// keeps answering the last entry (so a stuck-POLL
    /// endpoint is scripted with a single POLL).
    #[derive(Debug)]
    pub struct SagvMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        replies: RefCell<Vec<u32>>,
        data0: RefCell<u32>,
    }

    impl SagvMmio {
        fn new(replies: Vec<u32>) -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                replies: RefCell::new(replies),
                data0: RefCell::new(0),
            }
        }
    }

    impl MmioWindow for SagvMmio {
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
                // SAGV control command; anything else is a
                // fixture bug, not hardware behaviour.
                debug_assert_eq!(val & 0xFF, PCODE_CMD_SAGV_DE_MEM_SS_CONFIG);
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

    fn smoke_sagv_command_and_reply_decode() -> TestResult {
        // The display-11 control command is 0xe, not the
        // Gen9 0x21 the watermark header once named.
        if PCODE_CMD_SAGV_DE_MEM_SS_CONFIG != 0x0E {
            return TestResult::Fail("SAGV control command must be 0x0E");
        }
        if SAGV_REQ_QGV_PT_MASK != 0xFF || SAGV_REPLY_MASK != 0xF {
            return TestResult::Fail("SAGV request/reply masks wrong");
        }
        if decode_reply(0x0) != SagvReply::Safe
            || decode_reply(0x1) != SagvReply::Poll
            || decode_reply(0x2) != SagvReply::Rejected
            || decode_reply(0x3) != SagvReply::Rejected
        {
            return TestResult::Fail("QGV reply decode wrong");
        }
        // The combined acceptance check covers the PSF field
        // too: a nonzero PSF nibble is not an acceptance.
        if !reply_accepted(0x0) || reply_accepted(0x4) || reply_accepted(0x1) {
            return TestResult::Fail("combined reply acceptance wrong");
        }
        // The request word carries the points mask in bits
        // [7:0] and nothing else.
        if qgv_request_mask(0x5) != 0x5 || qgv_request_mask(0x1FF) != 0xFF {
            return TestResult::Fail("QGV request mask wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_sagv",
        smoke_sagv_command_and_reply_decode
    );

    fn smoke_restrict_accepts_safe() -> TestResult {
        let mmio = SagvMmio::new(alloc::vec![0x0]);
        if restrict_qgv_points(&mmio, 0x5) != Ok(()) {
            return TestResult::Fail("a SAFE reply must accept the mask");
        }
        // The conversation: DATA0-in carries the mask, then
        // the mailbox word READY | 0x0E.
        let writes = mmio.writes.borrow();
        if !writes.contains(&(PCODE_DATA0, 0x5))
            || !writes.contains(&(PCODE_MAILBOX, PCODE_READY | 0x0E))
        {
            return TestResult::Fail("restrict must send the mask via the 0x0E mailbox command");
        }
        // DATA1 is written (zero) as part of the transaction.
        if !writes.contains(&(PCODE_DATA1, 0)) {
            return TestResult::Fail("restrict must write DATA1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_sagv",
        smoke_restrict_accepts_safe
    );

    fn smoke_restrict_retries_poll_then_accepts() -> TestResult {
        // POLL, POLL, SAFE: the request is re-sent until the
        // punit accepts it.
        let mmio = SagvMmio::new(alloc::vec![0x1, 0x1, 0x0]);
        if restrict_qgv_points(&mmio, 0x3) != Ok(()) {
            return TestResult::Fail("POLL then SAFE must accept the mask");
        }
        let mailbox_writes = mmio
            .writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == PCODE_MAILBOX)
            .count();
        if mailbox_writes != 3 {
            return TestResult::Fail("each POLL reply must re-send the request");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_sagv",
        smoke_restrict_retries_poll_then_accepts
    );

    fn smoke_restrict_rejected_fails_at_once() -> TestResult {
        let mmio = SagvMmio::new(alloc::vec![0x2]);
        if restrict_qgv_points(&mmio, 0x3) != Err(SagvError::Rejected) {
            return TestResult::Fail("a REJECTED reply must fail at once");
        }
        let mailbox_writes = mmio
            .writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == PCODE_MAILBOX)
            .count();
        if mailbox_writes != 1 {
            return TestResult::Fail("a REJECTED reply must not be retried");
        }
        // A SAFE QGV field with a nonzero PSF field is not an
        // acceptance either (the combined check fails).
        let mmio = SagvMmio::new(alloc::vec![0x4]);
        if restrict_qgv_points(&mmio, 0x3) != Err(SagvError::Rejected) {
            return TestResult::Fail("a nonzero PSF reply field must refuse the mask");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_sagv",
        smoke_restrict_rejected_fails_at_once
    );

    fn smoke_restrict_poll_timeout() -> TestResult {
        // A punit that never stops polling: the retry loop is
        // bounded by the 51 ms budget, not infinite.
        let mmio = SagvMmio::new(alloc::vec![0x1]);
        if restrict_qgv_points(&mmio, 0x3) != Err(SagvError::Timeout) {
            return TestResult::Fail("an endlessly POLL reply must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_sagv",
        smoke_restrict_poll_timeout
    );
}
