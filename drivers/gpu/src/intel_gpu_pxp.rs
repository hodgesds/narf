//! Xe PXP (Protected Xe Path) on the MTL/Arrow media GT, behind the strict
//! default-off `narf.intel.pxp=1` beside `narf.intel.media_gt=1` and
//! `narf.intel.gsc=1`. MIT Linux 7.4-rc4 drivers/gpu/drm/xe:
//! - xe_pxp.c: xe_pxp_init, pxp_prerequisites_done,
//!   xe_pxp_get_readiness_status, kcr_pxp_enable/disable, pxp_terminate_hw,
//!   pxp_prep_for_termination, pxp_terminate, pxp_terminate_complete,
//!   pxp_events_work, xe_pxp_irq_handler, __pxp_start_arb_session, pxp_start,
//!   xe_pxp_exec_queue_add/remove, pxp_invalidate_queues,
//!   xe_pxp_key_assign, xe_pxp_bo_key_check, xe_pxp_pm_suspend/resume;
//! - xe_pxp_submit.c: the VCS termination stream
//!   (pxp_emit_session_termination), gsccs_send_message with its 40 pending
//!   retries 50 ms apart, xe_pxp_submit_session_init and
//!   xe_pxp_submit_session_invalidation, pxp_pkt_submit (HZ: -ETIME);
//! - regs/xe_pxp_regs.h (KCR_INIT, KCR_SIP, KCR_GLOBAL_TERMINATE),
//!   regs/xe_irq_regs.h (the OTHER_KCR_INSTANCE causes),
//!   abi/gsc_pxp_commands_abi.h (PXP 4.3 INIT_SESSION and
//!   INVALIDATE_STREAM_KEY), xe_pxp_types.h and include/uapi/drm/xe_drm.h
//!   (DRM_XE_PXP_HWDRM_DEFAULT_SESSION, drm_xe_query_pxp_status).
//!
//! `Pxp` is `struct xe_pxp`'s software half: the status machine, the
//! activation/termination completions, the key instance and the queue list.
//! The uAPI reaches it through `UserBackend::pxp` for the readiness query,
//! key assignment and checks and exec queue add/remove. `Engine` is the
//! hardware half, driven by the GT runtime worker while GT1 runs: the ARB
//! session start, pxp_terminate_hw and the GSC messages. Linux runs those in
//! the ioctl's own context (pxp_start) or its events work; here the ioctl
//! posts the work and waits for the worker, which is the only owner of the
//! media GuC's queues.
//!
//! NARF deviations, all fail-closed:
//! - Every GT1 stop (GT reset, runtime park, system suspend, fault) runs
//!   xe_pxp_pm_suspend first, and the next GT1 start runs xe_pxp_pm_resume:
//!   a GRDOM_FULL of the media GT loses the KCR state just as a power-down
//!   does. A HW step that cannot finish before the stop fails as if its job
//!   had failed; a termination still awaiting its KCR completion is treated
//!   as complete, since resume always leaves NEEDS_TERMINATION.
//! - The VCS termination runs inline in a kernel context's ring (Linux: a
//!   GGTT batch). Both are privileged streams.
//! - The GSC client object sits at `CLIENT_VA` in its private PPGTT (Linux
//!   maps it at 0, which NARF's PPGTT builder keeps unmapped).
//! - The per-queue runtime-PM reference is the backend's PXP wakeref, held
//!   by the queue's list entry.
//! - xe_pxp_init failing fails the Linux probe; here PXP stays disabled.

use super::gsc::{check_and_update_pending, emit_header, read_out_header, GscError, HEADER};
use crate::intel_gpu_aux::MmioWindow;
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::task::Poll;
use narf_lib::sync::IrqSafeSpinLock;

/// Default-off opt-in for PXP, with the shared pre-`--` grammar of
/// `narf.intel.media_gt=1` and `narf.intel.gsc=1`.
pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, "narf.intel.pxp")
}

/// `narf.intel.pxp=1` beside an admitted GSC: xe_pxp_init needs the media
/// GT's GSCCS0 and GSC firmware (and, below media 35, the HuC).
pub(crate) fn admitted(
    platform: Option<crate::intel_gpu_gt::GtPlatform>,
    args: narf_boot::args::KernelCmdline<'_>,
) -> bool {
    super::gsc::admitted(platform, args) && requested(args)
}

/// regs/xe_pxp_regs.h, valid only on platforms with a media GT. All lie above
/// MEDIA_GT_GSI_LENGTH, so GT1's view reaches them at their absolute offsets.
pub(crate) const KCR_INIT: u64 = 0x3860f0;
const KCR_INIT_ALLOW_DISPLAY_ME_WRITES: u32 = 1 << 14;
/// kcr_pxp_set_status: REG_MASKED_FIELD_ENABLE / _DISABLE of
/// KCR_INIT_ALLOW_DISPLAY_ME_WRITES.
pub(crate) const KCR_ENABLE: u32 =
    KCR_INIT_ALLOW_DISPLAY_ME_WRITES << 16 | KCR_INIT_ALLOW_DISPLAY_ME_WRITES;
pub(crate) const KCR_DISABLE: u32 = KCR_INIT_ALLOW_DISPLAY_ME_WRITES << 16;
pub(crate) const KCR_SIP: u64 = 0x386260;
pub(crate) const KCR_GLOBAL_TERMINATE: u64 = 0x3860f8;

/// regs/xe_irq_regs.h irqs for OTHER_KCR_INSTANCE.
pub(crate) const KCR_PXP_STATE_TERMINATED: u32 = 1 << 1;
pub(crate) const KCR_APP_TERMINATED_PER_FW_REQ: u32 = 1 << 2;
pub(crate) const KCR_PXP_STATE_RESET_COMPLETE: u32 = 1 << 3;
/// xe_irq_enable_hwe's kcr_mask.
pub(crate) const KCR_EVENTS: u32 =
    KCR_PXP_STATE_TERMINATED | KCR_APP_TERMINATED_PER_FW_REQ | KCR_PXP_STATE_RESET_COMPLETE;

/// DRM_XE_PXP_HWDRM_DEFAULT_SESSION (xe_pxp.c ARB_SESSION).
pub(crate) const ARB_SESSION: u32 = 0xf;
/// enum drm_xe_pxp_session_type.
pub(crate) const TYPE_NONE: u64 = 0;
pub(crate) const TYPE_HWDRM: u64 = 1;
/// drm_xe_query_pxp_status.supported_session_types: BIT(DRM_XE_PXP_TYPE_HWDRM).
pub(crate) const SUPPORTED_SESSION_TYPES: u32 = 1 << TYPE_HWDRM;

/// PXP_ACTIVATION_TIMEOUT_MS and PXP_TERMINATION_TIMEOUT_MS.
pub(crate) const ACTIVATION_NS: u64 = 300_000_000;
pub(crate) const TERMINATION_NS: u64 = 500_000_000;
/// pxp_wait_for_session_state: xe_mmio_wait32's 250 us bound on KCR_SIP.
pub(crate) const SESSION_NS: u64 = 250_000;
/// dma_fence_wait_timeout(fence, false, HZ) for both submissions.
pub(crate) const JOB_NS: u64 = 1_000_000_000;
/// GSC_PENDING_RETRY_MAXCOUNT and GSC_PENDING_RETRY_PAUSE_MS.
pub(crate) const PENDING_RETRIES: u32 = 40;
pub(crate) const PENDING_RETRY_NS: u64 = 50_000_000;
/// NARF: the longest a queue add waits for the worker to run its own start
/// or termination (40 GSC submissions of HZ plus their pauses, with margin).
const OWN_WORK_NS: u64 = 60_000_000_000;

/// abi/gsc_pxp_commands_abi.h: PXP_APIVER(4, 3) and the command ids.
const PXP_API_4_3: u32 = 4 << 16 | 3;
const PXP43_CMDID_INVALIDATE_STREAM_KEY: u32 = 0x7;
const PXP43_CMDID_INIT_SESSION: u32 = 0x36;
const PXP43_INIT_SESSION_VALID: u32 = 1 << 0;
const PXP43_INIT_SESSION_APPID_SHIFT: u32 = 2;
const PXP43_INIT_SESSION_APPID_MASK: u32 = 0x3fffc;
const PXP43_INIT_SESSION_PROTECTION_ARB: u32 = 0x2;
/// pxp_cmd_header.stream_id fields of INVALIDATE_STREAM_KEY (APP_TYPE 0).
const PXP_CMDHDR_EXTDATA_SESSION_VALID: u32 = 1 << 0;
const PXP_CMDHDR_EXTDATA_SESSION_ID_SHIFT: u32 = 2;
const PXP_CMDHDR_EXTDATA_SESSION_ID_MASK: u32 = 0x3fffc;
/// struct pxp_cmd_header (packed, 16 bytes): api_version, command_id,
/// status / stream_id, buffer_len.
const PXP_CMD_HEADER: usize = 16;
/// sizeof(struct pxp43_create_arb_in) / _out.
pub(crate) const CREATE_ARB_IN: usize = 76;
pub(crate) const CREATE_ARB_OUT: usize = 48;
/// sizeof(struct pxp43_inv_stream_key_in) / _out.
pub(crate) const INV_STREAM_KEY_IN: usize = 28;
pub(crate) const INV_STREAM_KEY_OUT: usize = 20;

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

/// xe_pxp_submit_session_init's pxp43_create_arb_in for session `id`: the
/// 4.3 API, stream_id APPID(id) | VALID with APPTYPE 0, and ARB protection
/// for the default HWDRM session.
pub(crate) fn init_session(id: u32) -> [u8; CREATE_ARB_IN] {
    let mut message = [0u8; CREATE_ARB_IN];
    put32(&mut message, 0, PXP_API_4_3);
    put32(&mut message, 4, PXP43_CMDID_INIT_SESSION);
    put32(
        &mut message,
        8,
        (id << PXP43_INIT_SESSION_APPID_SHIFT) & PXP43_INIT_SESSION_APPID_MASK
            | PXP43_INIT_SESSION_VALID,
    );
    put32(&mut message, 12, (CREATE_ARB_IN - PXP_CMD_HEADER) as u32);
    if id == ARB_SESSION {
        put32(&mut message, 16, PXP43_INIT_SESSION_PROTECTION_ARB);
    }
    message
}

/// xe_pxp_submit_session_invalidation's pxp43_inv_stream_key_in: the 4.3
/// API, stream_id SESSION_VALID | APP_TYPE 0 | SESSION_ID(id).
pub(crate) fn invalidate_stream_key(id: u32) -> [u8; INV_STREAM_KEY_IN] {
    let mut message = [0u8; INV_STREAM_KEY_IN];
    put32(&mut message, 0, PXP_API_4_3);
    put32(&mut message, 4, PXP43_CMDID_INVALIDATE_STREAM_KEY);
    put32(
        &mut message,
        8,
        PXP_CMDHDR_EXTDATA_SESSION_VALID
            | (id << PXP_CMDHDR_EXTDATA_SESSION_ID_SHIFT) & PXP_CMDHDR_EXTDATA_SESSION_ID_MASK,
    );
    put32(
        &mut message,
        12,
        (INV_STREAM_KEY_IN - PXP_CMD_HEADER) as u32,
    );
    message
}

/// xe_pxp_submit.c PXP_BB_SIZE plus inout_size * 2: one page of batch, then
/// one page each for msg_in and msg_out (XE_PAGE_SIZE inout_size).
pub(crate) const CLIENT_PAGES: u32 = 3;
pub(crate) const MSG_IN: u64 = 4096;
pub(crate) const MSG_OUT: u64 = 8192;
pub(crate) const INOUT: usize = 4096;
/// The client object's address in its private PPGTT (NARF: not 0).
pub(crate) const CLIENT_VA: u64 = 0x10_0000;
/// The batch's length in bytes: emit_pxp_heci_cmd's nine dwords, rounded up
/// to the qword the PPGTT batch builder requires.
pub(crate) const BATCH_BYTES: u64 = 40;
/// include/linux/poison.h POISON_FREE (xe_gsc_poison_header).
const POISON: u8 = 0x6b;

/// emit_pxp_heci_cmd: GSC_HECI_CMD_PKT naming msg_in and msg_out in the
/// client's PPGTT, then MI_BATCH_BUFFER_END.
pub(crate) fn heci_batch(va: u64, size_in: u32, size_out: u32) -> [u32; 10] {
    let input = va + MSG_IN;
    let output = va + MSG_OUT;
    [
        super::gsc::GSC_HECI_CMD_PKT,
        input as u32,
        (input >> 32) as u32,
        size_in,
        output as u32,
        (output >> 32) as u32,
        size_out,
        0,
        MI_BATCH_BUFFER_END,
        0,
    ]
}

/// instructions/xe_mfx_commands.h: MFX_WAIT with the PXP and MFX sync
/// control flags (pxp_emit_wait's MFX_WAIT_PXP), and CRYPTO_KEY_EXCHANGE.
const MFX_WAIT_PXP: u32 = 3 << 29 | 1 << 27 | 1 << 9 | 1 << 8;
const CRYPTO_KEY_EXCHANGE: u32 = 3 << 29 | 2 << 27 | 6 << 24 | 9 << 16;
/// instructions/xe_mi_commands.h.
const MI_FLUSH_DW: u32 = 0x26 << 23;
const MI_FLUSH_DW_PROTECTED_MEM_EN: u32 = 1 << 22;
const MI_FLUSH_DW_STORE_INDEX: u32 = 1 << 21;
const MI_FLUSH_DW_OP_STOREDW: u32 = 1 << 14;
const MI_FLUSH_IMM_DW: u32 = 4 - 2;
const MI_FLUSH_DW_USE_GTT: u32 = 1 << 2;
const MI_SET_APPID: u32 = 0x0e << 23;
const MI_SET_APPID_SESSION_ID_MASK: u32 = 0x7f;
const MI_BATCH_BUFFER_END: u32 = 0x0a << 23;
/// xe_lrc.h LRC_PPHWSP_PXP_INVAL_SCRATCH_ADDR.
const PXP_INVAL_SCRATCH: u32 = 0x40 * 4;
pub(crate) const TERMINATION_WORDS: usize = 20;

/// xe_pxp_submit_session_termination's stream for session `id`:
/// pxp_emit_session_selection (wait, PXP off, MI_SET_APPID, wait, PXP on
/// with a PPHWSP scratch store, wait), the inline termination and a final
/// wait. Linux ends the GGTT batch with MI_BATCH_BUFFER_END; NARF runs the
/// same words in the ring ahead of its breadcrumb.
pub(crate) fn termination(id: u32) -> [u32; TERMINATION_WORDS] {
    [
        MFX_WAIT_PXP,
        0,
        MI_FLUSH_DW | MI_FLUSH_IMM_DW,
        0,
        0,
        0,
        MI_SET_APPID | (id & MI_SET_APPID_SESSION_ID_MASK),
        0,
        MFX_WAIT_PXP,
        0,
        MI_FLUSH_DW
            | MI_FLUSH_DW_PROTECTED_MEM_EN
            | MI_FLUSH_DW_OP_STOREDW
            | MI_FLUSH_DW_STORE_INDEX
            | MI_FLUSH_IMM_DW,
        PXP_INVAL_SCRATCH | MI_FLUSH_DW_USE_GTT,
        0,
        0,
        MFX_WAIT_PXP,
        0,
        CRYPTO_KEY_EXCHANGE,
        0,
        MFX_WAIT_PXP,
        0,
    ]
}

/// The only stream the kernel VCS termination job admits.
pub(crate) fn termination_valid(words: &[u32]) -> bool {
    words.len() == TERMINATION_WORDS
        && words == termination(words[6] & MI_SET_APPID_SESSION_ID_MASK)
}

/// Failures, each with the errno of the Linux branch it mirrors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PxpError {
    /// -ENODEV: PXP is disabled, or no engine to submit on.
    NoDevice,
    /// -EBUSY: the prerequisites are not done yet.
    Busy,
    /// -EIO: an error or suspended state, a nonzero firmware status, a
    /// failed job or lost MMIO.
    Io,
    /// -ETIMEDOUT: a completion wait, a KCR_SIP wait or the VCS fence.
    TimedOut,
    /// -ETIME: a GSCCS job did not finish within HZ.
    Time,
    /// -EEXIST: the ARB session was already in play.
    Exists,
    /// -EAGAIN: the GSC kept the message pending through every retry.
    Again,
    /// -ENOSPC: a message larger than its half of the client object.
    NoSpace,
    /// A reply refused by xe_gsc_read_out_header.
    Packet(GscError),
    /// -ENOMEM.
    NoMemory,
}

impl PxpError {
    /// The Linux errno of this branch.
    pub(crate) fn errno(self) -> i32 {
        match self {
            PxpError::NoDevice => -19,
            PxpError::Busy => -16,
            PxpError::Io => -5,
            PxpError::TimedOut => -110,
            PxpError::Time => -62,
            PxpError::Exists => -17,
            PxpError::Again => -11,
            PxpError::NoSpace => -28,
            PxpError::Packet(error) => error.errno(),
            PxpError::NoMemory => -12,
        }
    }

    /// The `FsError` an ioctl returns. ETIMEDOUT has no `FsError`; it is
    /// ETIME (`TimedOut`), as a GSC job timeout is.
    pub(crate) fn fs(self) -> narf_filesystem::FsError {
        use narf_filesystem::FsError;
        match self {
            PxpError::NoDevice => FsError::NoDevice,
            PxpError::Busy => FsError::Busy,
            PxpError::TimedOut | PxpError::Time => FsError::TimedOut,
            PxpError::Exists => FsError::AlreadyExists,
            PxpError::Again => FsError::WouldBlock,
            PxpError::NoSpace => FsError::NoSpace,
            PxpError::NoMemory => FsError::OutOfMemory,
            PxpError::Packet(GscError::Invalid) => FsError::InvalidData,
            PxpError::Io | PxpError::Packet(_) => crate::intel_gpu_user::io_error(),
        }
    }
}

/// xe_pxp_bo_key_check's refusals of a protected object.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// -EINVAL: the object is not protected.
    NotProtected,
    /// -ENOEXEC: the object was encrypted with an obsolete key.
    Stale,
}

/// `enum xe_pxp_status`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Error,
    NeedsTermination,
    NeedsAdditionalTermination,
    TerminationInProgress,
    ReadyToStart,
    StartInProgress,
    Active,
    Suspended,
}

/// xe_pxp_get_readiness_status's inputs as the worker last observed them
/// on a running GT1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// 0: GSC proxy init or HuC authentication via the GSC not done yet.
    Pending,
    /// 1: both done.
    Ready,
    /// -EIO: the GSC or HuC firmware is in an error state.
    Error,
}

/// xe_pxp_types.h `events.pending` bits.
const TERMINATION_REQUEST_IRQ: u32 = 1 << 0;
const TERMINATION_REQUEST_ON_RESUME: u32 = 1 << 1;
const TERMINATION_REQUEST: u32 = TERMINATION_REQUEST_IRQ | TERMINATION_REQUEST_ON_RESUME;
const TERMINATION_COMPLETE_IRQ: u32 = 1 << 2;

/// How a start or termination an ioctl asked the worker for ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Done(Result<(), PxpError>),
    /// The state changed under it: go back to wait_for_idle.
    Restart,
}

/// One PXP queue: its context and the runtime-PM reference it holds while
/// it is on the list (xe_pxp_exec_queue_add's xe_pm_runtime_get).
struct Member {
    context: Weak<crate::intel_gpu_user::UserContext>,
    _wakeref: Box<dyn core::any::Any + Send>,
}

struct Core {
    status: Status,
    /// `activation` / `termination` completions: true when done.
    activation_done: bool,
    termination_done: bool,
    /// A start / hardware termination an ioctl's pxp_start owes, by ticket.
    owe_start: Option<u64>,
    owe_termination: Option<u64>,
    ticket: u64,
    start_outcome: Option<(u64, Outcome)>,
    termination_outcome: Option<(u64, Outcome)>,
    events: u32,
    key_instance: u32,
    last_suspend_key_instance: u32,
    needs_termination_on_resume: bool,
    queues: Vec<Member>,
    readiness: Readiness,
    /// GT1 runs with KCR enabled: between init or resume and suspend.
    live: bool,
}

impl Core {
    fn next_ticket(&mut self) -> u64 {
        self.ticket = self.ticket.wrapping_add(1);
        self.ticket
    }

    /// mark_termination_in_progress.
    fn mark_termination_in_progress(&mut self) {
        self.termination_done = false;
        self.status = Status::TerminationInProgress;
    }

    /// pxp_prep_for_termination.
    fn prep_for_termination(&mut self) -> bool {
        if self.status == Status::Active {
            self.key_instance = self.key_instance.wrapping_add(1);
        }
        if self.status == Status::Suspended {
            return false;
        }
        if self.status == Status::TerminationInProgress {
            self.status = Status::NeedsAdditionalTermination;
            return false;
        }
        self.mark_termination_in_progress();
        true
    }

    /// pxp_terminate_complete.
    fn terminate_complete(&mut self) {
        match self.status {
            Status::TerminationInProgress => self.status = Status::ReadyToStart,
            Status::NeedsAdditionalTermination => self.status = Status::NeedsTermination,
            // Suspended: deferred to resume. Anything else is the source's
            // drm_err; the state is left alone.
            _ => {}
        }
        self.termination_done = true;
    }
}

/// pxp_invalidate_queues' second half: xe_exec_queue_kill on every queue
/// still alive (its admission closes; NARF never fabricates a completion of
/// a job already running), then the list entries and their runtime-PM
/// references go, outside the PXP lock.
fn kill(members: Vec<Member>) {
    for member in &members {
        if let Some(context) = member.context.upgrade() {
            context.request_ban();
        }
    }
    drop(members);
}

/// The hardware work the worker owes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Work {
    /// __pxp_start_arb_session for pxp_start's ticket.
    Start(u64),
    /// pxp_terminate_hw for pxp_start's NEEDS_TERMINATION ticket, or for the
    /// events work (`None`).
    Terminate(Option<u64>),
}

/// `struct xe_pxp`'s software state, shared by the uAPI and the worker.
pub struct Pxp {
    core: IrqSafeSpinLock<Core>,
}

impl core::fmt::Debug for Pxp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let core = self.core.lock();
        f.debug_struct("Pxp")
            .field("status", &core.status)
            .field("readiness", &core.readiness)
            .field("queues", &core.queues.len())
            .finish_non_exhaustive()
    }
}

/// xe_pxp_exec_queue_add's progress for one queue.
pub(crate) struct QueueAdd {
    member: Option<Member>,
    phase: Phase,
    termination_deadline: u64,
    activation_deadline: Option<u64>,
    own_deadline: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// pxp_start: xe_pxp_get_readiness_status.
    Start,
    /// pxp_start's wait_for_idle.
    WaitIdle,
    /// This queue's pxp_start began the ARB session start.
    OwnStart(u64),
    /// This queue's pxp_start began a hardware termination.
    OwnTermination(u64),
    /// __exec_queue_add.
    Add,
}

impl QueueAdd {
    /// Begin adding `context`, holding `wakeref` (the queue's runtime-PM
    /// reference) until the queue leaves the list.
    pub(crate) fn new(
        context: &Arc<crate::intel_gpu_user::UserContext>,
        wakeref: Box<dyn core::any::Any + Send>,
    ) -> Self {
        Self {
            member: Some(Member {
                context: Arc::downgrade(context),
                _wakeref: wakeref,
            }),
            phase: Phase::Start,
            termination_deadline: 0,
            activation_deadline: None,
            own_deadline: 0,
        }
    }

    fn wait_idle(&mut self, now: u64) {
        self.phase = Phase::WaitIdle;
        self.termination_deadline = now.saturating_add(TERMINATION_NS);
        self.activation_deadline = None;
    }
}

impl Pxp {
    /// xe_pxp_init after kcr_pxp_enable and the execution resources:
    /// NEEDS_TERMINATION, key instance 1, both completions done.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            core: IrqSafeSpinLock::new(Core {
                status: Status::NeedsTermination,
                activation_done: true,
                termination_done: true,
                owe_start: None,
                owe_termination: None,
                ticket: 0,
                start_outcome: None,
                termination_outcome: None,
                events: 0,
                key_instance: 1,
                last_suspend_key_instance: 1,
                needs_termination_on_resume: false,
                queues: Vec::new(),
                readiness: Readiness::Pending,
                live: true,
            }),
        })
    }

    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn status(&self) -> Status {
        self.core.lock().status
    }

    /// xe_pxp_get_readiness_status: 0 in progress, 1 ready, -EIO forever.
    pub(crate) fn readiness(&self) -> Result<u32, PxpError> {
        match self.core.lock().readiness {
            Readiness::Pending => Ok(0),
            Readiness::Ready => Ok(1),
            Readiness::Error => Err(PxpError::Io),
        }
    }

    /// xe_pxp_key_assign: the key iteration a new HWDRM object is marked with.
    pub(crate) fn key_assign(&self) -> u32 {
        self.core.lock().key_instance
    }

    /// xe_pxp_bo_key_check for an object marked with `instance` (0: not
    /// protected).
    pub(crate) fn key_check(&self, instance: u32) -> Result<(), KeyError> {
        if instance == 0 {
            return Err(KeyError::NotProtected);
        }
        if instance != self.core.lock().key_instance {
            return Err(KeyError::Stale);
        }
        Ok(())
    }

    /// PXP queues on the list (each holds a runtime-PM reference).
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn queues(&self) -> usize {
        self.core.lock().queues.len()
    }

    /// One step of xe_pxp_exec_queue_add: pxp_start (readiness, then the
    /// state machine from wait_for_idle, posting the start or termination
    /// it owes to the worker), then __exec_queue_add, which retries from
    /// the start while PXP is not active. `Pending` until the next poll.
    pub(crate) fn add_step(&self, add: &mut QueueAdd, now: u64) -> Poll<Result<(), PxpError>> {
        let mut core = self.core.lock();
        loop {
            match add.phase {
                Phase::Start => {
                    // get_readiness_status: 0 is -EBUSY, an error state -EIO.
                    match core.readiness {
                        Readiness::Error => return Poll::Ready(Err(PxpError::Io)),
                        Readiness::Pending => return Poll::Ready(Err(PxpError::Busy)),
                        Readiness::Ready => add.wait_idle(now),
                    }
                }
                Phase::WaitIdle => {
                    if !core.termination_done {
                        return if now >= add.termination_deadline {
                            Poll::Ready(Err(PxpError::TimedOut))
                        } else {
                            Poll::Pending
                        };
                    }
                    let deadline = *add
                        .activation_deadline
                        .get_or_insert(now.saturating_add(ACTIVATION_NS));
                    if !core.activation_done {
                        return if now >= deadline {
                            Poll::Ready(Err(PxpError::TimedOut))
                        } else {
                            Poll::Pending
                        };
                    }
                    match core.status {
                        Status::Error | Status::Suspended => return Poll::Ready(Err(PxpError::Io)),
                        Status::Active => add.phase = Phase::Add,
                        Status::ReadyToStart => {
                            core.status = Status::StartInProgress;
                            core.activation_done = false;
                            let ticket = core.next_ticket();
                            core.owe_start = Some(ticket);
                            add.phase = Phase::OwnStart(ticket);
                            add.own_deadline = now.saturating_add(OWN_WORK_NS);
                        }
                        Status::NeedsTermination => {
                            core.mark_termination_in_progress();
                            let ticket = core.next_ticket();
                            core.owe_termination = Some(ticket);
                            add.phase = Phase::OwnTermination(ticket);
                            add.own_deadline = now.saturating_add(OWN_WORK_NS);
                        }
                        // An action is in progress: wait for it again.
                        Status::StartInProgress
                        | Status::TerminationInProgress
                        | Status::NeedsAdditionalTermination => {
                            add.wait_idle(now);
                            return Poll::Pending;
                        }
                    }
                }
                Phase::OwnStart(ticket) => match core.start_outcome {
                    Some((done, outcome)) if done == ticket => {
                        core.start_outcome = None;
                        match outcome {
                            Outcome::Done(Ok(())) => add.phase = Phase::Add,
                            Outcome::Done(Err(error)) => return Poll::Ready(Err(error)),
                            Outcome::Restart => add.wait_idle(now),
                        }
                    }
                    _ if now >= add.own_deadline => return Poll::Ready(Err(PxpError::TimedOut)),
                    _ => return Poll::Pending,
                },
                Phase::OwnTermination(ticket) => match core.termination_outcome {
                    Some((done, outcome)) if done == ticket => {
                        core.termination_outcome = None;
                        match outcome {
                            Outcome::Done(Err(error)) => return Poll::Ready(Err(error)),
                            // goto wait_for_idle: the KCR completion follows.
                            Outcome::Done(Ok(())) | Outcome::Restart => add.wait_idle(now),
                        }
                    }
                    _ if now >= add.own_deadline => return Poll::Ready(Err(PxpError::TimedOut)),
                    _ => return Poll::Pending,
                },
                Phase::Add => match core.status {
                    Status::Active => {
                        let member = add.member.take().expect("one add per queue");
                        if core.queues.try_reserve(1).is_err() {
                            drop(core);
                            drop(member);
                            return Poll::Ready(Err(PxpError::NoMemory));
                        }
                        core.queues.push(member);
                        return Poll::Ready(Ok(()));
                    }
                    Status::Error | Status::Suspended => return Poll::Ready(Err(PxpError::Io)),
                    // -EBUSY: try again from the start.
                    _ => add.phase = Phase::Start,
                },
            }
        }
    }

    /// xe_pxp_exec_queue_remove: safe to call again for the same queue.
    pub(crate) fn exec_queue_remove(&self, context: &Arc<crate::intel_gpu_user::UserContext>) {
        let removed = {
            let mut core = self.core.lock();
            core.queues
                .iter()
                .position(|member| core::ptr::eq(member.context.as_ptr(), Arc::as_ptr(context)))
                .map(|at| core.queues.swap_remove(at))
        };
        drop(removed);
    }

    /// xe_pxp_irq_handler.
    pub(crate) fn irq(&self, iir: u32) {
        if iir == 0 {
            return;
        }
        let mut core = self.core.lock();
        if iir & (KCR_PXP_STATE_TERMINATED | KCR_APP_TERMINATED_PER_FW_REQ) != 0 {
            core.events |= TERMINATION_REQUEST_IRQ;
        }
        if iir & KCR_PXP_STATE_RESET_COMPLETE != 0 {
            core.events |= TERMINATION_COMPLETE_IRQ;
        }
    }

    /// The worker's readiness observation of a running GT1.
    pub(crate) fn publish(&self, readiness: Readiness) {
        self.core.lock().readiness = readiness;
    }

    /// Whether GT1 runs with KCR enabled for this PXP.
    pub(crate) fn live(&self) -> bool {
        self.core.lock().live
    }

    /// xe_pxp_pm_suspend before GT1 stops, after the worker's own hardware
    /// work finished or was aborted. A start an ioctl posted but the worker
    /// never began is abandoned (its waiter restarts and finds SUSPENDED),
    /// pending KCR requests are dropped as xe_pm_runtime_get_if_active drops
    /// them, and a termination still awaiting its KCR completion is treated
    /// as complete (GT1's reset ends it; resume leaves NEEDS_TERMINATION).
    pub(crate) fn suspend(&self) {
        let killed = {
            let mut core = self.core.lock();
            if !core.live {
                return;
            }
            core.live = false;
            if let Some(ticket) = core.owe_start.take() {
                core.activation_done = true;
                core.start_outcome = Some((ticket, Outcome::Restart));
            }
            if let Some(ticket) = core.owe_termination.take() {
                core.termination_outcome = Some((ticket, Outcome::Restart));
            }
            core.events = 0;
            let mut invalidate = false;
            match core.status {
                Status::Error
                | Status::ReadyToStart
                | Status::Suspended
                | Status::TerminationInProgress
                | Status::NeedsAdditionalTermination => {}
                // Abandoned above: no start ran.
                Status::StartInProgress => {}
                // PXP was never used since the last suspend.
                Status::NeedsTermination if core.key_instance == core.last_suspend_key_instance => {
                }
                Status::NeedsTermination | Status::Active => {
                    core.key_instance = core.key_instance.wrapping_add(1);
                    core.needs_termination_on_resume = true;
                    invalidate = true;
                }
            }
            core.status = Status::Suspended;
            core.termination_done = true;
            core.last_suspend_key_instance = core.key_instance;
            if core.readiness != Readiness::Error {
                core.readiness = Readiness::Pending;
            }
            if invalidate {
                core::mem::take(&mut core.queues)
            } else {
                Vec::new()
            }
        };
        kill(killed);
    }

    /// xe_pxp_pm_resume on a running GT1, after kcr_pxp_enable (`kcr_ok`).
    /// The termination owed from the suspend is prepared at once and runs
    /// as the events work's ON_RESUME request.
    pub(crate) fn resume(&self, kcr_ok: bool) {
        let mut core = self.core.lock();
        if core.live {
            return;
        }
        core.live = true;
        if !kcr_ok {
            core.status = Status::Error;
            return;
        }
        core.status = Status::NeedsTermination;
        if core.needs_termination_on_resume {
            core.needs_termination_on_resume = false;
            if core.prep_for_termination() {
                core.events |= TERMINATION_REQUEST_ON_RESUME;
            }
        }
    }

    /// The next hardware work: an ioctl's start, then its termination, then
    /// pxp_events_work. State-only events (a completion, a termination
    /// request while one runs) are applied here; the queues an IRQ
    /// termination kills are returned with it.
    fn next_work(&self) -> Option<(Work, Vec<Member>)> {
        let mut core = self.core.lock();
        if !core.live {
            return None;
        }
        if let Some(ticket) = core.owe_start.take() {
            return Some((Work::Start(ticket), Vec::new()));
        }
        if let Some(ticket) = core.owe_termination.take() {
            return Some((Work::Terminate(Some(ticket)), Vec::new()));
        }
        loop {
            let mut events = core::mem::take(&mut core.events);
            if events == 0 {
                return None;
            }
            // pxp_events_work: a resume request takes the IRQ one's place,
            // and a termination request drops a completion that came with it.
            let mut hw_only = false;
            if events & TERMINATION_REQUEST_ON_RESUME != 0 {
                events &= !TERMINATION_REQUEST_IRQ;
                hw_only = true;
            }
            if events & TERMINATION_REQUEST != 0 {
                if hw_only {
                    return Some((Work::Terminate(None), Vec::new()));
                }
                // pxp_terminate: the prep, then pxp_invalidate_queues.
                if core.prep_for_termination() {
                    let killed = core::mem::take(&mut core.queues);
                    return Some((Work::Terminate(None), killed));
                }
                continue;
            }
            if events & TERMINATION_COMPLETE_IRQ != 0 {
                core.terminate_complete();
            }
        }
    }

    /// The end of __pxp_start_arb_session for `ticket`, under pxp_start's
    /// lock: ACTIVE or ERROR, or NEEDS_TERMINATION and a restart when the
    /// state moved meanwhile.
    fn finish_start(&self, ticket: u64, result: Result<(), PxpError>) {
        let mut core = self.core.lock();
        core.activation_done = true;
        let outcome = if !core.live {
            // NARF: GT1 stopped under it; suspend already set the state.
            Outcome::Restart
        } else if core.status != Status::StartInProgress {
            core.status = Status::NeedsTermination;
            Outcome::Restart
        } else {
            core.status = if result.is_ok() {
                Status::Active
            } else {
                Status::Error
            };
            Outcome::Done(result)
        };
        core.start_outcome = Some((ticket, outcome));
    }

    /// The end of pxp_terminate_hw. A failure is ERROR with the termination
    /// complete; success waits for KCR_PXP_STATE_RESET_COMPLETE.
    fn finish_termination(&self, ticket: Option<u64>, result: Result<(), PxpError>) {
        let mut core = self.core.lock();
        let outcome = if !core.live {
            // NARF: GT1 stopped under it; suspend already set the state.
            Outcome::Restart
        } else {
            if result.is_err() {
                core.status = Status::Error;
                core.termination_done = true;
            }
            Outcome::Done(result)
        };
        if let Some(ticket) = ticket {
            core.termination_outcome = Some((ticket, outcome));
        }
    }
}

/// kcr_pxp_enable / kcr_pxp_disable through GT1's view. The running media
/// GuC holds XE_FW_GT.
pub(crate) fn kcr_set(mmio: &impl MmioWindow, enable: bool) {
    mmio.write32(KCR_INIT, if enable { KCR_ENABLE } else { KCR_DISABLE });
}

/// xe_pxp_get_readiness_status's firmware checks and
/// pxp_prerequisites_done: a GSC or HuC error state is -EIO; otherwise the
/// HuC must be authenticated via the GSC and the GSC proxy initialized.
/// Lost MMIO reads as not done, as a failed force_wake does.
pub(crate) fn readiness(gsc_error: bool, huc_error: bool, mmio: &impl MmioWindow) -> Readiness {
    if gsc_error || huc_error {
        return Readiness::Error;
    }
    let huc = super::gsc::huc_authenticated(mmio, super::gsc::HucAuth::Gsc);
    let proxy = super::gsc::load::proxy_init_done(mmio);
    if huc == Some(true) && proxy == Ok(true) {
        Readiness::Ready
    } else {
        Readiness::Pending
    }
}

/// The GSC client object (`gsc_res.bo`): CPU access to its three pages and
/// its address in the client's private PPGTT.
pub(crate) trait Client {
    fn va(&self) -> u64;
    fn read(&self, at: u64, bytes: &mut [u8]) -> Result<(), PxpError>;
    fn write(&self, at: u64, bytes: &[u8]) -> Result<(), PxpError>;
}

/// The production GSC client object: three private, unexported system pages
/// no handle or mapping names (Linux: XE_BO_FLAG_SYSTEM | PINNED |
/// NEEDS_UC, bound WB in the XE_VM_FLAG_GSC VM).
pub(crate) struct GemClient {
    object: Arc<crate::intel_gpu_gem::GemObject>,
    platform: crate::intel_gpu_gt::GtPlatform,
}

impl GemClient {
    pub(crate) fn new(platform: crate::intel_gpu_gt::GtPlatform) -> Result<Self, PxpError> {
        let gem = crate::intel_gpu_gem::GemState::new();
        let object = gem
            .create(u64::from(CLIENT_PAGES) * 4096, |_, _| Ok(()))
            .and_then(|handle| gem.object(handle))
            .map_err(|_| PxpError::NoMemory)?;
        Ok(Self { object, platform })
    }

    /// The client's private PPGTT with the object at `CLIENT_VA`, its batch
    /// at the object's start (xe_vm_bind_kernel_bo, then
    /// xe_sched_job_create(q, &batch_addr)). The GSC writes msg_out, so the
    /// mapping is writable.
    pub(crate) fn batch(&self) -> Result<crate::intel_gpu_exec::ResidentBatch, PxpError> {
        use crate::intel_gpu_exec::{ExecObject, ExecRequest};
        ExecRequest {
            context_id: 0,
            ring: 0,
            no_preempt: false,
            batch_va: CLIENT_VA,
            batch_len: BATCH_BYTES,
            objects: alloc::vec![ExecObject {
                object: self.object.clone(),
                va: CLIENT_VA,
                writable: true,
                asynchronous: false,
                capture: false,
            }],
        }
        .prepare_for_gt(self.platform)
        .map_err(|error| match error {
            narf_filesystem::FsError::OutOfMemory => PxpError::NoMemory,
            _ => PxpError::Io,
        })
    }
}

impl Client for GemClient {
    fn va(&self) -> u64 {
        CLIENT_VA
    }
    fn read(&self, at: u64, bytes: &mut [u8]) -> Result<(), PxpError> {
        self.object.read(at, bytes).map_err(|_| PxpError::Io)
    }
    fn write(&self, at: u64, bytes: &[u8]) -> Result<(), PxpError> {
        self.object.write(at, bytes).map_err(|_| PxpError::Io)
    }
}

/// The media GuC's PXP submissions, one outstanding at a time.
pub(crate) trait Port<C: Client> {
    /// pxp_pkt_submit: the client object's batch on the GSCCS0 PXP queue.
    fn submit_gsc(&mut self, client: &C) -> Result<(), PxpError>;
    /// xe_pxp_submit_session_termination's job on the first VCS.
    fn submit_termination(&mut self, words: &[u32]) -> Result<(), PxpError>;
    /// The outstanding job's fence: `None` while it runs.
    fn finished(&mut self) -> Option<Result<(), PxpError>>;
}

/// Which GSC message is in flight.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Message {
    InitSession,
    Invalidate,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Step {
    Idle,
    /// The VCS termination job.
    Vcs,
    /// pxp_wait_for_session_state(false) after it.
    TermSip,
    /// gsccs_send_message: a GSCCS job.
    Gsc,
    /// The GSC replied pending: 50 ms before the next submission.
    Retry,
    /// pxp_wait_for_session_state(true) after INIT_SESSION.
    StartSip,
}

fn read(mmio: &impl MmioWindow, reg: u64) -> Result<u32, PxpError> {
    let value = mmio.read32(reg);
    if value == u32::MAX {
        Err(PxpError::Io)
    } else {
        Ok(value)
    }
}

/// The worker's hardware half of PXP over the GSC client resources.
pub(crate) struct Engine<C: Client> {
    client: C,
    /// gsc_res.host_session_handle. An identifier, never key material, and
    /// still never logged.
    session: u64,
    work: Option<Work>,
    step: Step,
    message: Message,
    deadline: u64,
    retries: u32,
}

impl<C: Client> Engine<C> {
    /// xe_pxp_allocate_execution_resources' GSC half: the client object and
    /// xe_gsc_create_host_session_id's handle (bits 56..63 clear).
    pub(crate) fn new(client: C, session: u64) -> Self {
        Self {
            client,
            session: session & !(0xffu64 << 56),
            work: None,
            step: Step::Idle,
            message: Message::InitSession,
            deadline: 0,
            retries: 0,
        }
    }

    /// No hardware work is in flight.
    pub(crate) fn idle(&self) -> bool {
        self.work.is_none()
    }

    /// Run the owed hardware work by bounded steps. `Ready` once none is
    /// left; `begin` false only finishes work already in flight.
    pub(crate) fn poll<P: Port<C>>(
        &mut self,
        pxp: &Pxp,
        now: u64,
        port: &mut P,
        mmio: &impl MmioWindow,
        begin: bool,
    ) -> Poll<()> {
        loop {
            let progressed = match self.step {
                Step::Idle => {
                    if !begin {
                        return Poll::Ready(());
                    }
                    let Some((work, killed)) = pxp.next_work() else {
                        return Poll::Ready(());
                    };
                    kill(killed);
                    self.begin(work, pxp, now, port, mmio)
                }
                Step::Vcs => match self.job(now, port, PxpError::TimedOut) {
                    None => false,
                    Some(Ok(())) => {
                        self.deadline = now.saturating_add(SESSION_NS);
                        self.step = Step::TermSip;
                        true
                    }
                    Some(Err(error)) => self.finish(pxp, Err(error)),
                },
                Step::TermSip => match read(mmio, KCR_SIP) {
                    Err(error) => self.finish(pxp, Err(error)),
                    Ok(sip) if sip & 1 << ARB_SESSION == 0 => {
                        // Full HW cleanup, then the GSC cleans up its state.
                        mmio.write32(KCR_GLOBAL_TERMINATE, 1);
                        self.send(
                            pxp,
                            now,
                            port,
                            Message::Invalidate,
                            &invalidate_stream_key(ARB_SESSION),
                            INV_STREAM_KEY_OUT,
                        )
                    }
                    Ok(_) if now >= self.deadline => self.finish(pxp, Err(PxpError::TimedOut)),
                    Ok(_) => false,
                },
                Step::Gsc => match self.job(now, port, PxpError::Time) {
                    None => false,
                    Some(Ok(())) => self.replied(pxp, now, mmio),
                    Some(Err(error)) => self.finish(pxp, Err(error)),
                },
                Step::Retry if now < self.deadline => false,
                Step::Retry => {
                    self.retries -= 1;
                    if self.retries == 0 {
                        self.finish(pxp, Err(PxpError::Again))
                    } else {
                        self.submit(pxp, now, port)
                    }
                }
                Step::StartSip => match read(mmio, KCR_SIP) {
                    Err(error) => self.finish(pxp, Err(error)),
                    Ok(sip) if sip & 1 << ARB_SESSION != 0 => self.finish(pxp, Ok(())),
                    Ok(_) if now >= self.deadline => self.finish(pxp, Err(PxpError::TimedOut)),
                    Ok(_) => false,
                },
            };
            if !progressed {
                return Poll::Pending;
            }
        }
    }

    /// Finish the work in flight before GT1 stops. `true` once none is left.
    pub(crate) fn quiesce<P: Port<C>>(
        &mut self,
        pxp: &Pxp,
        now: u64,
        port: &mut P,
        mmio: &impl MmioWindow,
    ) -> bool {
        let _ = self.poll(pxp, now, port, mmio, false);
        self.idle()
    }

    /// GT1 stops without waiting: the work in flight fails as its job would.
    pub(crate) fn abort(&mut self, pxp: &Pxp) {
        if self.work.is_some() {
            self.finish(pxp, Err(PxpError::Io));
        }
    }

    fn begin<P: Port<C>>(
        &mut self,
        work: Work,
        pxp: &Pxp,
        now: u64,
        port: &mut P,
        mmio: &impl MmioWindow,
    ) -> bool {
        self.work = Some(work);
        match work {
            // __pxp_start_arb_session under the GuC's XE_FW_GT.
            Work::Start(_) => match read(mmio, KCR_SIP) {
                Err(error) => self.finish(pxp, Err(error)),
                Ok(sip) if sip & 1 << ARB_SESSION != 0 => self.finish(pxp, Err(PxpError::Exists)),
                Ok(_) => self.send(
                    pxp,
                    now,
                    port,
                    Message::InitSession,
                    &init_session(ARB_SESSION),
                    CREATE_ARB_OUT,
                ),
            },
            // pxp_terminate_hw: the VCS termination of the ARB session.
            Work::Terminate(_) => match port.submit_termination(&termination(ARB_SESSION)) {
                Err(error) => self.finish(pxp, Err(error)),
                Ok(()) => {
                    self.deadline = now.saturating_add(JOB_NS);
                    self.step = Step::Vcs;
                    true
                }
            },
        }
    }

    /// The outstanding job, bounded by HZ (`timeout` is its errno).
    fn job<P: Port<C>>(
        &mut self,
        now: u64,
        port: &mut P,
        timeout: PxpError,
    ) -> Option<Result<(), PxpError>> {
        match port.finished() {
            Some(result) => Some(result),
            None if now >= self.deadline => Some(Err(timeout)),
            None => None,
        }
    }

    /// gsccs_send_message up to the first submission: the GSC header and
    /// message in msg_in, a poisoned reply header and the HECI batch.
    fn send<P: Port<C>>(
        &mut self,
        pxp: &Pxp,
        now: u64,
        port: &mut P,
        message: Message,
        input: &[u8],
        output: usize,
    ) -> bool {
        let max = INOUT - HEADER;
        if input.len() > max || output > max {
            return self.finish(pxp, Err(PxpError::NoSpace));
        }
        let mut staged = alloc::vec![0u8; HEADER + input.len()];
        let at = match emit_header(
            &mut staged,
            super::gsc::HECI_PXP,
            self.session,
            input.len() as u32,
        ) {
            Ok(at) => at,
            Err(error) => return self.finish(pxp, Err(PxpError::Packet(error))),
        };
        staged[at..].copy_from_slice(input);
        let batch = heci_batch(
            self.client.va(),
            (at + input.len()) as u32,
            (at + output) as u32,
        );
        let mut words = [0u8; BATCH_BYTES as usize];
        for (index, word) in batch.iter().enumerate() {
            put32(&mut words, index * 4, *word);
        }
        let staged = self
            .client
            .write(MSG_IN, &staged)
            .and_then(|()| self.client.write(MSG_OUT, &[POISON; HEADER]))
            .and_then(|()| self.client.write(0, &words));
        if let Err(error) = staged {
            return self.finish(pxp, Err(error));
        }
        self.message = message;
        self.retries = PENDING_RETRIES;
        self.submit(pxp, now, port)
    }

    fn submit<P: Port<C>>(&mut self, pxp: &Pxp, now: u64, port: &mut P) -> bool {
        if let Err(error) = port.submit_gsc(&self.client) {
            return self.finish(pxp, Err(error));
        }
        self.deadline = now.saturating_add(JOB_NS);
        self.step = Step::Gsc;
        true
    }

    /// The GSC replied: a pending reply hands its message handle back and
    /// retries 50 ms later; otherwise the header is validated, the reply
    /// read (its buffer_len capped at the expected size) and msg_in
    /// poisoned, and the reply's status decides.
    fn replied(&mut self, pxp: &Pxp, now: u64, _mmio: &impl MmioWindow) -> bool {
        let mut reply = alloc::vec![0u8; INOUT];
        let mut input = [0u8; HEADER];
        if let Err(error) = self
            .client
            .read(MSG_OUT, &mut reply)
            .and_then(|()| self.client.read(MSG_IN, &mut input))
        {
            return self.finish(pxp, Err(error));
        }
        if check_and_update_pending(&mut input, &reply) {
            if let Err(error) = self.client.write(MSG_IN, &input) {
                return self.finish(pxp, Err(error));
            }
            self.deadline = now.saturating_add(PENDING_RETRY_NS);
            self.step = Step::Retry;
            return true;
        }
        let at = match read_out_header(&reply, PXP_CMD_HEADER as u32) {
            Ok(at) => at,
            Err(error) => return self.finish(pxp, Err(PxpError::Packet(error))),
        };
        if let Err(error) = self.client.write(MSG_IN, &[POISON; HEADER]) {
            return self.finish(pxp, Err(error));
        }
        // The reply stays in the object; only its status is read here.
        if u32_at(&reply, at + 8) != 0 {
            return self.finish(pxp, Err(PxpError::Io));
        }
        match self.message {
            Message::InitSession => {
                self.deadline = now.saturating_add(SESSION_NS);
                self.step = Step::StartSip;
                true
            }
            Message::Invalidate => self.finish(pxp, Ok(())),
        }
    }

    fn finish(&mut self, pxp: &Pxp, result: Result<(), PxpError>) -> bool {
        self.step = Step::Idle;
        match self.work.take() {
            Some(Work::Start(ticket)) => pxp.finish_start(ticket, result),
            Some(Work::Terminate(ticket)) => pxp.finish_termination(ticket, result),
            None => {}
        }
        true
    }
}

#[cfg(any(test, feature = "kernel-test"))]
impl Pxp {
    /// Fixture: publish readiness and settle in ACTIVE, as a completed
    /// termination and start on a running GT1 would leave it.
    pub(crate) fn activate_for_test(&self) {
        let mut core = self.core.lock();
        core.readiness = Readiness::Ready;
        core.status = Status::Active;
        core.activation_done = true;
        core.termination_done = true;
        core.events = 0;
        core.live = true;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_pxp_tests.rs"]
mod tests;
