//! PXP against a GSC firmware and KCR model. Every literal follows MIT Linux
//! 7.4-rc4: abi/gsc_pxp_commands_abi.h and abi/gsc_command_header_abi.h for
//! the packets, instructions/xe_{mi,mfx,gsc}_commands.h and xe_lrc.h for the
//! VCS termination and GSCCS batch, regs/xe_pxp_regs.h and regs/xe_irq_regs.h
//! for KCR, and xe_pxp.c / xe_pxp_submit.c for the state machine and timing.

use super::*;
use crate::intel_gpu_engine::{Engine as Hw, EngineSet};
use crate::intel_gpu_user::UserContext;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

const FWSTS1: u64 = 0x116c40;
const FWSTS5: u64 = 0x116c68;
const SIP: u32 = 1 << 15;
const SESSION: u64 = 0x0012_3456_789a_bcde;
const HANDLE: u64 = 0x0bad_cafe_0000_0042;
const MS: u64 = 1_000_000;

/// pxp43_create_arb_in for the default session: api 4.3, command 0x36,
/// stream_id APPID(0xf) | VALID = 0x3d, buffer_len 60, protection ARB.
const INIT_SESSION_BYTES: [u8; 20] = [
    0x03, 0x00, 0x04, 0x00, 0x36, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
];
/// pxp43_inv_stream_key_in: api 4.3, command 7, stream_id SESSION_VALID |
/// SESSION_ID(0xf) = 0x3d, buffer_len 12, rsvd[3] zero.
const INVALIDATE_BYTES: [u8; 16] = [
    0x03, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
];
/// pxp_emit_session_termination(0xf) + pxp_emit_wait without BB_END:
/// MFX_WAIT | PXP/MFX sync flags = 0x68000300, MI_FLUSH_DW | IMM_DW =
/// 0x13000002, MI_SET_APPID(0xf) = 0x0700000f, MI_FLUSH_DW | PROTECTED_MEM_EN
/// | STORE_INDEX | OP_STOREDW | IMM_DW = 0x13604002 at PPHWSP 0x100 | USE_GTT,
/// CRYPTO_KEY_EXCHANGE = 0x76090000.
const TERMINATION_STREAM: [u32; 20] = [
    0x6800_0300,
    0,
    0x1300_0002,
    0,
    0,
    0,
    0x0700_000f,
    0,
    0x6800_0300,
    0,
    0x1360_4002,
    0x0000_0104,
    0,
    0,
    0x6800_0300,
    0,
    0x7609_0000,
    0,
    0x6800_0300,
    0,
];

fn at32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn at64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// GT1's registers. Owner writes are logged; the models set bits silently.
#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl Regs {
    fn get(&self, reg: u64) -> u32 {
        *self.map.borrow().get(&reg).unwrap_or(&0)
    }
    fn set(&self, reg: u64, value: u32) {
        self.map.borrow_mut().insert(reg, value);
    }
    /// GSC proxy in PROXY_STATE_NORMAL and HuC authenticated via the GSC.
    fn prerequisites(&self) {
        self.set(FWSTS1, 1 << 9 | 5);
        self.set(FWSTS5, 1 << 19);
    }
}
impl MmioWindow for Regs {
    fn read32(&self, offset: u64) -> u32 {
        self.get(offset)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.writes.borrow_mut().push((offset, value));
        self.set(offset, value);
    }
}

/// The GSC client object: three pages at CLIENT_VA.
#[derive(Clone)]
struct Obj(Rc<RefCell<Vec<u8>>>);
impl Obj {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(vec![0; 3 * 4096])))
    }
    fn bytes(&self, at: u64, len: usize) -> Vec<u8> {
        self.0.borrow()[at as usize..at as usize + len].to_vec()
    }
}
impl Client for Obj {
    fn va(&self) -> u64 {
        CLIENT_VA
    }
    fn read(&self, at: u64, bytes: &mut [u8]) -> Result<(), PxpError> {
        bytes.copy_from_slice(&self.0.borrow()[at as usize..at as usize + bytes.len()]);
        Ok(())
    }
    fn write(&self, at: u64, bytes: &[u8]) -> Result<(), PxpError> {
        self.0.borrow_mut()[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default, Clone, Copy)]
struct Behaviour {
    /// Pending replies before the final one.
    pending: u32,
    /// pxp_cmd_header.status of the final reply.
    status: u32,
    /// intel_gsc_mtl_header.status of the final reply.
    header_status: u32,
    /// GSCCS jobs never finish.
    hang_gsc: bool,
    /// The VCS termination never finishes.
    hang_vcs: bool,
    /// INIT_SESSION succeeds without the session going in play.
    no_sip: bool,
    /// The VCS termination leaves the session in play.
    stuck_sip: bool,
}

/// One HECI packet the GSC received: its GSC header and PXP message.
struct Packet {
    header: Vec<u8>,
    message: Vec<u8>,
    batch: Vec<u32>,
}

/// GSC firmware behind GSCCS0 and the KCR session state behind VCS0.
struct Fw<'a> {
    regs: &'a Regs,
    b: Behaviour,
    packets: Vec<Packet>,
    terminations: Vec<Vec<u32>>,
    done: Option<Result<(), PxpError>>,
}
impl<'a> Fw<'a> {
    fn new(regs: &'a Regs, b: Behaviour) -> Self {
        Self {
            regs,
            b,
            packets: Vec::new(),
            terminations: Vec::new(),
            done: None,
        }
    }
}
impl Port<Obj> for Fw<'_> {
    fn submit_gsc(&mut self, client: &Obj) -> Result<(), PxpError> {
        let mut words = [0u8; 40];
        client.read(0, &mut words).unwrap();
        let batch: Vec<u32> = (0..10).map(|i| at32(&words, i * 4)).collect();
        // GSC_HECI_CMD_PKT naming msg_in / msg_out in the client's PPGTT.
        assert_eq!(batch[0], 0x4000_0006);
        let input = u64::from(batch[1]) | u64::from(batch[2]) << 32;
        let output = u64::from(batch[4]) | u64::from(batch[5]) << 32;
        let packet = client.bytes(input - CLIENT_VA, batch[3] as usize);
        self.packets.push(Packet {
            header: packet[..36].to_vec(),
            message: packet[36..].to_vec(),
            batch,
        });
        if self.b.hang_gsc {
            return Ok(());
        }
        let command = at32(&packet, 36 + 4);
        let pending = self.b.pending != 0;
        let reply_len = self.packets.last().unwrap().batch[6] as usize - 36;
        let mut reply = vec![0u8; 36 + reply_len];
        put32(&mut reply, 0, 0xa578_875a);
        reply[4] = 17;
        reply[6] = 1;
        put64(&mut reply, 8, at64(&packet, 8));
        put64(&mut reply, 16, if pending { HANDLE } else { 0 });
        put32(&mut reply, 24, (36 + reply_len) as u32);
        put32(&mut reply, 28, u32::from(pending));
        put32(
            &mut reply,
            32,
            if pending { 0 } else { self.b.header_status },
        );
        put32(&mut reply, 36, 4 << 16 | 3);
        put32(&mut reply, 40, command);
        put32(&mut reply, 44, if pending { 0 } else { self.b.status });
        put32(&mut reply, 48, (reply_len - 16) as u32);
        client.write(output - CLIENT_VA, &reply).unwrap();
        if pending {
            self.b.pending -= 1;
        } else if command == 0x36 && self.b.status == 0 && !self.b.no_sip {
            self.regs.set(KCR_SIP, self.regs.get(KCR_SIP) | SIP);
        }
        self.done = Some(Ok(()));
        Ok(())
    }
    fn submit_termination(&mut self, words: &[u32]) -> Result<(), PxpError> {
        self.terminations.push(words.to_vec());
        if self.b.hang_vcs {
            return Ok(());
        }
        if !self.b.stuck_sip {
            self.regs.set(KCR_SIP, self.regs.get(KCR_SIP) & !SIP);
        }
        self.done = Some(Ok(()));
        Ok(())
    }
    fn finished(&mut self) -> Option<Result<(), PxpError>> {
        self.done.take()
    }
}

/// The 36-byte intel_gsc_mtl_header of a PXP request of `payload` bytes.
fn request_header(payload: u32, handle: u64) -> Vec<u8> {
    let mut header = vec![0u8; 36];
    put32(&mut header, 0, 0xa578_875a);
    header[4] = 17;
    header[6] = 1;
    put64(&mut header, 8, SESSION | 17 << 56);
    put64(&mut header, 16, handle);
    put32(&mut header, 24, 36 + payload);
    header
}

fn context() -> Arc<UserContext> {
    UserContext::for_placements(EngineSet::of(&[Hw::Vcs0])).unwrap()
}

/// A fresh PXP whose prerequisites are done, in `status`.
fn ready(status: Status) -> Arc<Pxp> {
    let pxp = Pxp::new();
    pxp.publish(Readiness::Ready);
    pxp.core.lock().status = status;
    pxp
}

/// Run the worker until it has nothing left to do at `now`.
fn run(engine: &mut Engine<Obj>, pxp: &Pxp, now: u64, fw: &mut Fw<'_>, regs: &Regs) -> bool {
    engine.poll(pxp, now, fw, regs, true).is_ready()
}

fn smoke_pxp_option_grammar_and_linux_formats() -> TestResult {
    use narf_boot::args::KernelCmdline;
    const MTL: crate::intel_gpu_gt::GtPlatform =
        crate::intel_gpu_gt::GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    for line in [
        "",
        "narf.intel.pxp",
        "narf.intel.pxp=",
        "narf.intel.pxp=0",
        "narf.intel.pxp=1 narf.intel.pxp=1",
        "-- narf.intel.pxp=1",
        "narf.intel.pxp_x=1",
    ] {
        kt_assert!(!requested(KernelCmdline::new(line)));
    }
    kt_assert!(requested(KernelCmdline::new("quiet narf.intel.pxp=1 -- x")));
    let all = KernelCmdline::new("narf.intel.media_gt=1 narf.intel.gsc=1 narf.intel.pxp=1");
    kt_assert!(admitted(Some(MTL), all));
    // PXP sits on the GSC, which sits on the media GT.
    for line in [
        "narf.intel.pxp=1",
        "narf.intel.media_gt=1 narf.intel.pxp=1",
        "narf.intel.gsc=1 narf.intel.pxp=1",
        "narf.intel.media_gt=1 narf.intel.gsc=1",
    ] {
        kt_assert!(!admitted(Some(MTL), KernelCmdline::new(line)));
    }
    kt_assert!(!admitted(None, all));
    kt_assert!(!admitted(
        Some(crate::intel_gpu_gt::GtPlatform::Battlemage),
        all
    ));

    // regs/xe_pxp_regs.h and kcr_pxp_set_status's masked writes.
    kt_assert_eq!(
        (KCR_INIT, KCR_SIP, KCR_GLOBAL_TERMINATE),
        (0x3860f0, 0x386260, 0x3860f8)
    );
    let regs = Regs::default();
    kcr_set(&regs, true);
    kcr_set(&regs, false);
    kt_assert_eq!(
        &regs.writes.borrow()[..],
        &[(0x3860f0, 0x4000_4000), (0x3860f0, 0x4000_0000)]
    );
    kt_assert_eq!(KCR_EVENTS, 0xe);

    // abi/gsc_pxp_commands_abi.h.
    let init = init_session(ARB_SESSION);
    kt_assert_eq!(init.len(), 76);
    kt_assert_eq!(&init[..20], &INIT_SESSION_BYTES[..]);
    kt_assert!(init[20..].iter().all(|byte| *byte == 0));
    // A session other than the default one carries no ARB protection mode.
    kt_assert_eq!(at32(&init_session(3), 8), 3 << 2 | 1);
    kt_assert_eq!(at32(&init_session(3), 16), 0);
    let invalidate = invalidate_stream_key(ARB_SESSION);
    kt_assert_eq!(invalidate.len(), 28);
    kt_assert_eq!(&invalidate[..16], &INVALIDATE_BYTES[..]);
    kt_assert!(invalidate[16..].iter().all(|byte| *byte == 0));
    kt_assert_eq!((CREATE_ARB_OUT, INV_STREAM_KEY_OUT), (48, 20));

    // emit_pxp_heci_cmd: msg_in one page, msg_out two pages past the batch.
    kt_assert_eq!(
        heci_batch(CLIENT_VA, 112, 84),
        [
            0x4000_0006,
            0x10_1000,
            0,
            112,
            0x10_2000,
            0,
            84,
            0,
            0x0500_0000,
            0
        ]
    );

    // xe_pxp_submit_session_termination's stream, and the only one the
    // kernel VCS job admits.
    kt_assert_eq!(termination(ARB_SESSION), TERMINATION_STREAM);
    kt_assert!(termination_valid(&TERMINATION_STREAM));
    kt_assert!(termination_valid(&termination(1)));
    let mut forged = TERMINATION_STREAM;
    forged[11] = 0x1000; // a scratch store outside the PPHWSP slot
    kt_assert!(!termination_valid(&forged));
    kt_assert!(!termination_valid(&TERMINATION_STREAM[..18]));
    kt_assert!(!termination_valid(&[0x0500_0000, 0]));

    // The Linux errnos the uAPI returns.
    kt_assert_eq!(PxpError::TimedOut.errno(), -110);
    kt_assert_eq!(PxpError::Time.errno(), -62);
    kt_assert_eq!(PxpError::Again.errno(), -11);
    kt_assert_eq!(PxpError::Busy.fs(), narf_filesystem::FsError::Busy);
    kt_assert_eq!(PxpError::NoDevice.fs(), narf_filesystem::FsError::NoDevice);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_option_grammar_and_linux_formats
);

/// xe_pxp_get_readiness_status, then the first queue's pxp_start: the
/// NEEDS_TERMINATION of init runs pxp_terminate_hw (VCS termination,
/// KCR_SIP clear, KCR_GLOBAL_TERMINATE, INVALIDATE_STREAM_KEY), waits for
/// KCR_PXP_STATE_RESET_COMPLETE, then __pxp_start_arb_session sends
/// INIT_SESSION through two pending replies and waits for KCR_SIP.
fn smoke_pxp_arb_session_start_sends_the_linux_init_session_packet() -> TestResult {
    let regs = Regs::default();
    let obj = Obj::new();
    let pxp = Pxp::new();
    let mut engine = Engine::new(obj.clone(), SESSION | 0xab << 56);
    let mut fw = Fw::new(&regs, Behaviour::default());
    let ctx = context();

    // Prerequisites not done: 0, and a PXP queue is -EBUSY.
    pxp.publish(readiness(false, false, &regs));
    kt_assert_eq!(pxp.readiness(), Ok(0));
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert_eq!(pxp.add_step(&mut add, 0), Poll::Ready(Err(PxpError::Busy)));
    // Only one of the two: still in progress.
    regs.set(FWSTS1, 1 << 9 | 5);
    kt_assert_eq!(readiness(false, false, &regs), Readiness::Pending);
    regs.set(FWSTS1, 1 << 9 | 4);
    regs.set(FWSTS5, 1 << 19);
    kt_assert_eq!(readiness(false, false, &regs), Readiness::Pending);
    // A GSC or HuC firmware error is -EIO; lost MMIO is not done.
    kt_assert_eq!(readiness(true, false, &regs), Readiness::Error);
    kt_assert_eq!(readiness(false, true, &regs), Readiness::Error);
    regs.set(FWSTS1, u32::MAX);
    kt_assert_eq!(readiness(false, false, &regs), Readiness::Pending);
    regs.prerequisites();
    pxp.publish(readiness(false, false, &regs));
    kt_assert_eq!(pxp.readiness(), Ok(1));

    // pxp_start from NEEDS_TERMINATION: the worker owes pxp_terminate_hw.
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert!(pxp.add_step(&mut add, 0).is_pending());
    kt_assert_eq!(pxp.status(), Status::TerminationInProgress);
    regs.set(KCR_SIP, SIP);
    kt_assert!(run(&mut engine, &pxp, 0, &mut fw, &regs));
    kt_assert_eq!(&fw.terminations[..], &[TERMINATION_STREAM.to_vec()]);
    kt_assert_eq!(&regs.writes.borrow()[..], &[(KCR_GLOBAL_TERMINATE, 1)]);
    kt_assert_eq!(fw.packets.len(), 1);
    kt_assert_eq!(&fw.packets[0].header, &request_header(28, 0));
    kt_assert_eq!(&fw.packets[0].message[..16], &INVALIDATE_BYTES[..]);
    kt_assert_eq!(fw.packets[0].message.len(), 28);
    // The reply may be up to pxp43_inv_stream_key_out behind its header.
    kt_assert_eq!(fw.packets[0].batch[3], 36 + 28);
    kt_assert_eq!(fw.packets[0].batch[6], 36 + 20);
    // msg_in's header was poisoned after the reply was read.
    kt_assert_eq!(obj.bytes(MSG_IN, 36), vec![0x6b; 36]);
    // The termination waits for the KCR completion.
    kt_assert!(pxp.add_step(&mut add, 1).is_pending());
    kt_assert_eq!(pxp.status(), Status::TerminationInProgress);
    pxp.irq(KCR_PXP_STATE_RESET_COMPLETE);
    kt_assert!(run(&mut engine, &pxp, 1, &mut fw, &regs));
    kt_assert_eq!(pxp.status(), Status::ReadyToStart);

    // READY_TO_START: the waiter posts the ARB session start.
    kt_assert!(pxp.add_step(&mut add, 2).is_pending());
    kt_assert_eq!(pxp.status(), Status::StartInProgress);
    fw.b.pending = 2;
    let start = 10 * MS;
    kt_assert!(!run(&mut engine, &pxp, start, &mut fw, &regs));
    kt_assert_eq!(fw.packets.len(), 2);
    // GSC_PENDING_RETRY_PAUSE_MS between submissions.
    kt_assert!(!run(&mut engine, &pxp, start + 50 * MS - 1, &mut fw, &regs));
    kt_assert_eq!(fw.packets.len(), 2);
    kt_assert!(!run(&mut engine, &pxp, start + 50 * MS, &mut fw, &regs));
    kt_assert_eq!(fw.packets.len(), 3);
    kt_assert!(run(&mut engine, &pxp, start + 100 * MS, &mut fw, &regs));
    kt_assert_eq!(fw.packets.len(), 4);
    for (index, packet) in fw.packets[1..].iter().enumerate() {
        // The first submission carries no message handle; each retry hands
        // back the one the pending reply gave.
        let handle = if index == 0 { 0 } else { HANDLE };
        kt_assert_eq!(&packet.header, &request_header(76, handle));
        kt_assert_eq!(&packet.message[..20], &INIT_SESSION_BYTES[..]);
        kt_assert!(packet.message[20..].iter().all(|byte| *byte == 0));
        kt_assert_eq!(
            &packet.batch[..],
            &[
                0x4000_0006,
                0x10_1000,
                0,
                112,
                0x10_2000,
                0,
                84,
                0,
                0x0500_0000,
                0
            ]
        );
    }
    kt_assert_eq!(pxp.status(), Status::Active);
    kt_assert_eq!(
        pxp.add_step(&mut add, start + 100 * MS),
        Poll::Ready(Ok(()))
    );
    kt_assert_eq!(pxp.queues(), 1);
    // A second queue joins the running session without another start.
    let other = context();
    let mut second = QueueAdd::new(&other, Box::new(()));
    kt_assert_eq!(
        pxp.add_step(&mut second, start + 101 * MS),
        Poll::Ready(Ok(()))
    );
    kt_assert_eq!(fw.packets.len(), 4);
    kt_assert_eq!(pxp.queues(), 2);
    // xe_pxp_exec_queue_remove is safe to repeat.
    pxp.exec_queue_remove(&other);
    pxp.exec_queue_remove(&other);
    kt_assert_eq!(pxp.queues(), 1);
    kt_assert!(!other.banned() && !ctx.banned());
    // No KCR write besides the global terminate; the KCR enable belongs to
    // init and resume.
    kt_assert_eq!(regs.writes.borrow().len(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_arb_session_start_sends_the_linux_init_session_packet
);

/// xe_pxp_pm_suspend with an active session kills its queues and bumps the
/// key; xe_pxp_pm_resume enables KCR and runs the termination it deferred.
/// A PXP that was never used is suspended and resumed without one.
fn smoke_pxp_terminates_on_suspend_and_resume() -> TestResult {
    let regs = Regs::default();
    regs.prerequisites();
    let obj = Obj::new();
    let mut engine = Engine::new(obj, SESSION);
    let mut fw = Fw::new(&regs, Behaviour::default());

    // Never used: no key change, no termination on resume.
    let idle = Pxp::new();
    idle.suspend();
    kt_assert_eq!(idle.status(), Status::Suspended);
    kt_assert_eq!(idle.key_assign(), 1);
    idle.resume(true);
    kt_assert_eq!(idle.status(), Status::NeedsTermination);
    kt_assert!(run(&mut engine, &idle, 0, &mut fw, &regs));
    kt_assert!(fw.terminations.is_empty());

    let pxp = ready(Status::Active);
    let ctx = context();
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert_eq!(pxp.add_step(&mut add, 0), Poll::Ready(Ok(())));
    let key = pxp.key_assign();
    kt_assert_eq!(pxp.key_check(key), Ok(()));
    pxp.suspend();
    // Every PXP queue is killed and the key iteration moves on.
    kt_assert!(ctx.banned());
    kt_assert_eq!(pxp.queues(), 0);
    kt_assert_eq!(pxp.status(), Status::Suspended);
    kt_assert_eq!(pxp.key_check(key), Err(KeyError::Stale));
    kt_assert_eq!(pxp.key_check(0), Err(KeyError::NotProtected));
    // Suspended GT1: in progress, and a new queue is -EBUSY.
    kt_assert_eq!(pxp.readiness(), Ok(0));
    let later = context();
    let mut refused = QueueAdd::new(&later, Box::new(()));
    kt_assert_eq!(
        pxp.add_step(&mut refused, 1),
        Poll::Ready(Err(PxpError::Busy))
    );
    // Nothing runs on a stopped GT1, and a second suspend changes nothing.
    kt_assert!(run(&mut engine, &pxp, 1, &mut fw, &regs));
    kt_assert!(fw.terminations.is_empty());
    pxp.suspend();
    kt_assert_eq!(pxp.key_assign(), key + 1);

    // Resume: KCR enabled, then the deferred termination (hw only).
    kcr_set(&regs, true);
    pxp.resume(true);
    kt_assert_eq!(pxp.status(), Status::TerminationInProgress);
    regs.set(KCR_SIP, SIP);
    kt_assert!(run(&mut engine, &pxp, 2, &mut fw, &regs));
    kt_assert_eq!(&fw.terminations[..], &[TERMINATION_STREAM.to_vec()]);
    kt_assert_eq!(
        &regs.writes.borrow()[..],
        &[(KCR_INIT, 0x4000_4000), (KCR_GLOBAL_TERMINATE, 1)]
    );
    kt_assert_eq!(fw.packets.len(), 1);
    kt_assert_eq!(&fw.packets[0].message[..16], &INVALIDATE_BYTES[..]);
    // The resume termination is no new key iteration.
    kt_assert_eq!(pxp.key_assign(), key + 1);
    pxp.irq(KCR_PXP_STATE_RESET_COMPLETE);
    kt_assert!(run(&mut engine, &pxp, 3, &mut fw, &regs));
    kt_assert_eq!(pxp.status(), Status::ReadyToStart);
    // The next queue starts a new session.
    pxp.publish(readiness(false, false, &regs));
    let mut fresh = QueueAdd::new(&later, Box::new(()));
    kt_assert!(pxp.add_step(&mut fresh, 4).is_pending());
    kt_assert!(run(&mut engine, &pxp, 4, &mut fw, &regs));
    kt_assert_eq!(pxp.add_step(&mut fresh, 5), Poll::Ready(Ok(())));
    kt_assert_eq!(pxp.key_check(key + 1), Ok(()));

    // A failed KCR enable on resume is an error state.
    pxp.suspend();
    pxp.resume(false);
    kt_assert_eq!(pxp.status(), Status::Error);
    let mut failed = QueueAdd::new(&later, Box::new(()));
    pxp.publish(Readiness::Ready);
    kt_assert_eq!(pxp.add_step(&mut failed, 6), Poll::Ready(Err(PxpError::Io)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_terminates_on_suspend_and_resume
);

/// A KCR termination interrupt: pxp_prep_for_termination bumps the key,
/// pxp_invalidate_queues kills the queues, pxp_terminate_hw runs, and an
/// object marked before it fails xe_pxp_bo_key_check from then on.
fn smoke_pxp_key_check_refuses_a_stale_object_after_termination() -> TestResult {
    let regs = Regs::default();
    regs.prerequisites();
    let obj = Obj::new();
    let mut engine = Engine::new(obj, SESSION);
    let mut fw = Fw::new(&regs, Behaviour::default());
    let pxp = ready(Status::Active);
    let ctx = context();
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert_eq!(pxp.add_step(&mut add, 0), Poll::Ready(Ok(())));
    let stale = pxp.key_assign();
    kt_assert_eq!(pxp.key_check(stale), Ok(()));

    regs.set(KCR_SIP, SIP);
    pxp.irq(KCR_PXP_STATE_TERMINATED);
    kt_assert!(run(&mut engine, &pxp, 0, &mut fw, &regs));
    kt_assert!(ctx.banned());
    kt_assert_eq!(pxp.queues(), 0);
    kt_assert_eq!(pxp.status(), Status::TerminationInProgress);
    kt_assert_eq!(&fw.terminations[..], &[TERMINATION_STREAM.to_vec()]);
    kt_assert_eq!(regs.get(KCR_SIP) & SIP, 0);
    kt_assert_eq!(pxp.key_check(stale), Err(KeyError::Stale));
    let current = pxp.key_assign();
    kt_assert_eq!(current, stale + 1);
    kt_assert_eq!(pxp.key_check(current), Ok(()));

    // A second request while one runs needs one more termination; the
    // completion then leaves NEEDS_TERMINATION, with no second key bump.
    pxp.irq(KCR_APP_TERMINATED_PER_FW_REQ);
    kt_assert!(run(&mut engine, &pxp, 1, &mut fw, &regs));
    kt_assert_eq!(pxp.status(), Status::NeedsAdditionalTermination);
    kt_assert_eq!(fw.terminations.len(), 1);
    pxp.irq(KCR_PXP_STATE_RESET_COMPLETE);
    kt_assert!(run(&mut engine, &pxp, 2, &mut fw, &regs));
    kt_assert_eq!(pxp.status(), Status::NeedsTermination);
    kt_assert_eq!(pxp.key_assign(), current);
    // A request and a completion together: the completion is dropped.
    let both = ready(Status::Active);
    both.irq(KCR_PXP_STATE_TERMINATED | KCR_PXP_STATE_RESET_COMPLETE);
    kt_assert!(run(&mut engine, &both, 3, &mut fw, &regs));
    kt_assert_eq!(both.status(), Status::TerminationInProgress);

    // A termination whose VCS job never retires is ETIMEDOUT and ERROR;
    // the key stays invalidated and every later queue is -EIO.
    let hung = ready(Status::Active);
    let old = hung.key_assign();
    let mut fw = Fw::new(
        &regs,
        Behaviour {
            hang_vcs: true,
            ..Default::default()
        },
    );
    hung.irq(KCR_PXP_STATE_TERMINATED);
    kt_assert!(!run(&mut engine, &hung, 10 * MS, &mut fw, &regs));
    kt_assert!(!run(
        &mut engine,
        &hung,
        10 * MS + JOB_NS - 1,
        &mut fw,
        &regs
    ));
    kt_assert!(run(&mut engine, &hung, 10 * MS + JOB_NS, &mut fw, &regs));
    kt_assert_eq!(hung.status(), Status::Error);
    kt_assert_eq!(hung.key_check(old), Err(KeyError::Stale));
    let mut refused = QueueAdd::new(&ctx, Box::new(()));
    kt_assert_eq!(
        hung.add_step(&mut refused, 0),
        Poll::Ready(Err(PxpError::Io))
    );
    // A session that stays in play after the VCS termination: ETIMEDOUT
    // after 250 us, before any global terminate.
    let stuck = ready(Status::Active);
    regs.writes.borrow_mut().clear();
    let mut fw = Fw::new(
        &regs,
        Behaviour {
            stuck_sip: true,
            ..Default::default()
        },
    );
    regs.set(KCR_SIP, SIP);
    stuck.irq(KCR_PXP_STATE_TERMINATED);
    kt_assert!(!run(&mut engine, &stuck, 0, &mut fw, &regs));
    kt_assert!(!run(&mut engine, &stuck, SESSION_NS - 1, &mut fw, &regs));
    kt_assert!(run(&mut engine, &stuck, SESSION_NS, &mut fw, &regs));
    kt_assert_eq!(stuck.status(), Status::Error);
    kt_assert!(regs.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_key_check_refuses_a_stale_object_after_termination
);

/// __pxp_start_arb_session's failures reach pxp_start's caller with their
/// own errno and leave PXP in its error state.
fn smoke_pxp_start_failures_keep_linux_errnos() -> TestResult {
    let regs = Regs::default();
    regs.prerequisites();
    let ctx = context();
    let cases: [(Behaviour, bool, u64, PxpError); 6] = [
        // The session is already in play: -EEXIST before any message.
        (Behaviour::default(), true, 0, PxpError::Exists),
        // A nonzero PXP status in the reply: -EIO.
        (
            Behaviour {
                status: 0x100e,
                ..Default::default()
            },
            false,
            0,
            PxpError::Io,
        ),
        // A nonzero GSC header status: xe_gsc_read_out_header's -EINVAL.
        (
            Behaviour {
                header_status: 1,
                ..Default::default()
            },
            false,
            0,
            PxpError::Packet(GscError::Invalid),
        ),
        // A GSCCS job that never retires: -ETIME after HZ.
        (
            Behaviour {
                hang_gsc: true,
                ..Default::default()
            },
            false,
            JOB_NS,
            PxpError::Time,
        ),
        // Pending through all 40 submissions: -EAGAIN.
        (
            Behaviour {
                pending: 100,
                ..Default::default()
            },
            false,
            40 * PENDING_RETRY_NS,
            PxpError::Again,
        ),
        // INIT_SESSION succeeded but the session never went in play.
        (
            Behaviour {
                no_sip: true,
                ..Default::default()
            },
            false,
            SESSION_NS,
            PxpError::TimedOut,
        ),
    ];
    for (behaviour, in_play, end, error) in cases {
        regs.set(KCR_SIP, if in_play { SIP } else { 0 });
        let pxp = ready(Status::ReadyToStart);
        let mut engine = Engine::new(Obj::new(), SESSION);
        let mut fw = Fw::new(&regs, behaviour);
        let mut add = QueueAdd::new(&ctx, Box::new(()));
        kt_assert!(pxp.add_step(&mut add, 0).is_pending());
        let mut now = 0;
        while !run(&mut engine, &pxp, now, &mut fw, &regs) {
            kt_assert!(now < end);
            now += MS / 4;
        }
        kt_assert!(now >= end);
        kt_assert_eq!(pxp.status(), Status::Error);
        kt_assert_eq!(pxp.add_step(&mut add, now), Poll::Ready(Err(error)));
        if behaviour.pending != 0 {
            kt_assert_eq!(fw.packets.len(), PENDING_RETRIES as usize);
        }
        if in_play {
            kt_assert!(fw.packets.is_empty());
        }
        // Every later queue on this PXP is -EIO.
        let mut later = QueueAdd::new(&ctx, Box::new(()));
        kt_assert_eq!(
            pxp.add_step(&mut later, now),
            Poll::Ready(Err(PxpError::Io))
        );
        kt_assert_eq!(pxp.queues(), 0);
    }

    // pxp_start's own waits: a termination that never completes is
    // -ETIMEDOUT after 500 ms, and a start another queue posted makes a
    // second one wait for its activation.
    let pxp = ready(Status::TerminationInProgress);
    pxp.core.lock().termination_done = false;
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert!(pxp.add_step(&mut add, 0).is_pending());
    kt_assert!(pxp.add_step(&mut add, TERMINATION_NS - 1).is_pending());
    kt_assert_eq!(
        pxp.add_step(&mut add, TERMINATION_NS),
        Poll::Ready(Err(PxpError::TimedOut))
    );
    let pxp = ready(Status::ReadyToStart);
    let mut first = QueueAdd::new(&ctx, Box::new(()));
    let other = context();
    let mut second = QueueAdd::new(&other, Box::new(()));
    kt_assert!(pxp.add_step(&mut first, 0).is_pending());
    kt_assert!(pxp.add_step(&mut second, 0).is_pending());
    kt_assert_eq!(
        pxp.add_step(&mut second, ACTIVATION_NS),
        Poll::Ready(Err(PxpError::TimedOut))
    );
    // A suspend abandons the start nobody ran: its waiter sees -EIO.
    pxp.suspend();
    kt_assert_eq!(pxp.add_step(&mut first, 1), Poll::Ready(Err(PxpError::Io)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_start_failures_keep_linux_errnos
);

/// The runtime's GT1 stop with work in flight: quiesce finishes it, abort
/// fails it as its job would, and suspend then wins over its late result.
fn smoke_pxp_stop_quiesces_or_aborts_hardware_work() -> TestResult {
    let regs = Regs::default();
    regs.prerequisites();
    let ctx = context();
    let pxp = ready(Status::ReadyToStart);
    let mut engine = Engine::new(Obj::new(), SESSION);
    let mut fw = Fw::new(
        &regs,
        Behaviour {
            pending: 1,
            ..Default::default()
        },
    );
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert!(pxp.add_step(&mut add, 0).is_pending());
    kt_assert!(!run(&mut engine, &pxp, 0, &mut fw, &regs));
    // A quiesce does not take new work, but finishes this start.
    kt_assert!(!engine.quiesce(&pxp, 1, &mut fw, &regs));
    kt_assert!(engine.quiesce(&pxp, PENDING_RETRY_NS, &mut fw, &regs));
    kt_assert_eq!(pxp.status(), Status::Active);
    kt_assert_eq!(
        pxp.add_step(&mut add, PENDING_RETRY_NS),
        Poll::Ready(Ok(()))
    );

    // A start the stop cannot wait for: aborted (-EIO), then suspended.
    regs.set(KCR_SIP, 0);
    let pxp = ready(Status::ReadyToStart);
    let mut fw = Fw::new(
        &regs,
        Behaviour {
            hang_gsc: true,
            ..Default::default()
        },
    );
    let mut add = QueueAdd::new(&ctx, Box::new(()));
    kt_assert!(pxp.add_step(&mut add, 0).is_pending());
    kt_assert!(!run(&mut engine, &pxp, 0, &mut fw, &regs));
    engine.abort(&pxp);
    kt_assert!(engine.idle());
    kt_assert_eq!(pxp.status(), Status::Error);
    pxp.suspend();
    kt_assert_eq!(pxp.status(), Status::Suspended);
    kt_assert_eq!(pxp.add_step(&mut add, 1), Poll::Ready(Err(PxpError::Io)));
    // Resume from an error clears it: NEEDS_TERMINATION.
    pxp.resume(true);
    kt_assert_eq!(pxp.status(), Status::NeedsTermination);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_pxp",
    smoke_pxp_stop_quiesces_or_aborts_hardware_work
);
