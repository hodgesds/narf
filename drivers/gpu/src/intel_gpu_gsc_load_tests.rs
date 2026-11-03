//! The media GT's GSC worker against a GSC firmware model. Literal layouts
//! follow MIT Linux b90c984d: abi/gsc_command_header_abi.h (the 36-byte MTL
//! GSC header), abi/gsc_mkhi_commands_abi.h, abi/gsc_pxp_commands_abi.h,
//! abi/gsc_proxy_commands_abi.h, instructions/xe_gsc_commands.h and
//! regs/xe_gsc_regs.h; behaviour follows xe_gsc.c::gsc_work and its callees.

use super::*;
use crate::intel_gpu_gt::media::MediaWindow;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

const FWSTS1_REG: u64 = 0x116c40;
const FWSTS5_REG: u64 = 0x116c68;
const CSR_REG: u64 = 0x117004;
const TIMER_REG: u64 = 0x11ca28;
const WAKE_REQ: u64 = 0x38a618;
const WAKE_ACK: u64 = 0x380df8;
const HUC_GUC: u64 = 0x38c1dc;
const MARKER: u32 = 0xa578_875a;
const PRIVATE_AT: u32 = 0x0100_0000;
const PACKET_AT: u32 = 0x0050_0000;
const HUC_PACKET_AT: u32 = 0x0060_0000;
const CHANNEL_AT: u32 = 0x0070_0000;
const HUC_OBJECT: (u64, u32) = (0x0200_0000, 0x8000);
const MS: u64 = 1_000_000;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn at32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// The parse_gsc_layout-shaped `i915/mtl_gsc_1.bin` of the format fixtures:
/// boot1 BPDT whose RBE entry's CPD names RBEP.man (release 102.0.10.1499,
/// SVN 3). `len` is deliberately not a dword multiple.
fn gsc_image(len: usize) -> Vec<u8> {
    let mut image = vec![0u8; len];
    put32(&mut image, 32, 0x100);
    put32(&mut image, 36, 0x400);
    put32(&mut image, 0x100, 0x55aa);
    put16(&mut image, 0x104, 2);
    put32(&mut image, 0x100 + 24, 0x0002);
    put32(&mut image, 0x100 + 28, 0x10);
    put32(&mut image, 0x100 + 36, 1 << 18 | 0x0001);
    put32(&mut image, 0x100 + 40, 0x80);
    put32(&mut image, 0x100 + 44, 0x300);
    put32(&mut image, 0x180, 0x4450_4324);
    put32(&mut image, 0x184, 2);
    image[0x188] = 2;
    image[0x189] = 1;
    image[0x18a] = 20;
    for (index, (name, offset)) in [("FOO.man", 0x40u32), ("RBEP.man", 1 << 25 | 0x100)]
        .into_iter()
        .enumerate()
    {
        let at = 0x180 + 20 + index * 24;
        image[at..at + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut image, at + 12, offset);
    }
    put32(&mut image, 0x280, 4);
    for (field, value) in [102u16, 0, 10, 1499].into_iter().enumerate() {
        put16(&mut image, 0x280 + 36 + field * 2, value);
    }
    put32(&mut image, 0x280 + 44, 3);
    // Recognizable firmware bytes up to the odd tail.
    for (index, byte) in image[0x400..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7) | 1;
    }
    image
}

/// A GGTT object over shared words.
#[derive(Clone, Debug)]
struct Mem {
    base: u32,
    words: Rc<RefCell<Vec<u32>>>,
}
impl Mem {
    fn new(base: u32, pages: usize) -> Self {
        Self {
            base,
            words: Rc::new(RefCell::new(vec![0; pages * 1024])),
        }
    }
    fn bytes(&self, at: u64, len: usize) -> Vec<u8> {
        let words = self.words.borrow();
        let start = at as usize;
        let mut out = Vec::new();
        for word in &words[start / 4..(start + len).div_ceil(4)] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.drain(..start % 4);
        out.truncate(len);
        out
    }
    fn write(&self, at: u64, bytes: &[u8]) {
        assert_eq!(at % 4, 0);
        let mut words = self.words.borrow_mut();
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let slot = &mut words[at as usize / 4 + index];
            let mut word = slot.to_le_bytes();
            word[..chunk.len()].copy_from_slice(chunk);
            *slot = u32::from_le_bytes(word);
        }
    }
}
impl GpuBacking for Mem {
    fn coherent_for_device(&self) -> bool {
        true
    }
    fn ggtt_offset(&self) -> u32 {
        self.base
    }
    fn size_pages(&self) -> u32 {
        (self.words.borrow().len() / 1024) as u32
    }
    fn read32(&self, offset: u64) -> u32 {
        self.words.borrow()[offset as usize / 4]
    }
    fn write32(&self, offset: u64, value: u32) {
        self.words.borrow_mut()[offset as usize / 4] = value;
    }
}

/// BAR registers. Owner writes are logged; the GSC model sets status bits
/// without logging. The GSC wake acknowledgement follows its request.
#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    stuck_wake: bool,
}
impl Regs {
    fn get(&self, reg: u64) -> u32 {
        *self.map.borrow().get(&reg).unwrap_or(&0)
    }
    fn set(&self, reg: u64, value: u32) {
        self.map.borrow_mut().insert(reg, value);
    }
    fn writes(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
}
impl MmioWindow for Regs {
    fn read32(&self, offset: u64) -> u32 {
        self.get(offset)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.writes.borrow_mut().push((offset, value));
        self.set(offset, value);
        if offset == WAKE_REQ && !self.stuck_wake {
            self.set(WAKE_ACK, value & 1);
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Behaviour {
    hang_load: bool,
    no_init: bool,
    refuse: bool,
    compat: (u16, u16, u16),
    compat_status: u32,
    huc_pending: u32,
    huc_status: u32,
    huc_no_bit: bool,
    proxy_no_init: bool,
}

/// GSC firmware behind GSCCS0: GSC_FW_LOAD sets INIT_COMPLETE; MKHI, PXP
/// and proxy HECI packets get replies in the output half.
struct Gsc {
    regs: Rc<Regs>,
    memory: Vec<Mem>,
    image: Vec<u8>,
    b: Behaviour,
    jobs: Vec<Vec<u32>>,
    inputs: Vec<Vec<u8>>,
    done: Option<Result<(), LoadError>>,
    outstanding: bool,
}

fn reply_header(client: u8, payload: usize, flags: u32, handle: u64, status: u32) -> Vec<u8> {
    let mut header = vec![0u8; 36];
    put32(&mut header, 0, MARKER);
    header[4] = client;
    put16(&mut header, 6, 1);
    put64(&mut header, 16, handle);
    put32(&mut header, 24, (36 + payload) as u32);
    put32(&mut header, 28, flags);
    put32(&mut header, 32, status);
    header
}

fn proxy_header(kind: u32, length: u32, source: u32, destination: u32) -> Vec<u8> {
    let mut header = vec![0u8; 16];
    put32(&mut header, 0, kind | length << 16);
    put32(&mut header, 4, source);
    put32(&mut header, 8, destination);
    header
}

const GSC_TO_CSME: &[u8] = b"gsc->csme";
const CSME_TO_GSC: &[u8] = b"csme!!";

impl Gsc {
    fn find(&self, address: u64) -> (Mem, u64) {
        let mem = self
            .memory
            .iter()
            .find(|mem| {
                let base = u64::from(mem.base);
                (base..base + u64::from(mem.size_pages()) * 4096).contains(&address)
            })
            .expect("GGTT address of an owned object");
        (mem.clone(), address - u64::from(mem.base))
    }

    fn heci(&mut self, commands: &[u32]) -> Option<Result<(), LoadError>> {
        assert_eq!(commands.len(), 8);
        assert_eq!(commands[7], 0);
        let input_at = u64::from(commands[1]) | u64::from(commands[2]) << 32;
        let output_at = u64::from(commands[4]) | u64::from(commands[5]) << 32;
        let (input_mem, input_offset) = self.find(input_at);
        let input = input_mem.bytes(input_offset, commands[3] as usize);
        assert_eq!(at32(&input, 0), MARKER);
        assert_eq!(u16::from_le_bytes([input[6], input[7]]), 1);
        assert_eq!(
            at32(&input, 24),
            commands[3],
            "message_size covers the input"
        );
        self.inputs.push(input.clone());
        let (output, output_offset) = self.find(output_at);
        let reply = match input[4] {
            7 => {
                let mut payload = vec![0u8; 20];
                payload[..4].copy_from_slice(&[0x30, 0xc2, 0, 0]);
                put16(&mut payload, 4, self.b.compat.0);
                put16(&mut payload, 6, self.b.compat.1);
                put16(&mut payload, 8, self.b.compat.2);
                let mut reply = reply_header(7, 20, 0, 0, self.b.compat_status);
                reply.extend_from_slice(&payload);
                reply
            }
            17 => {
                if self.b.huc_pending > 0 {
                    self.b.huc_pending -= 1;
                    reply_header(17, 0, 1, 0xfeed_0000 + u64::from(self.b.huc_pending), 0)
                } else {
                    let mut out = vec![0u8; 16];
                    put32(&mut out, 0, 0x0004_0003);
                    put32(&mut out, 8, self.b.huc_status);
                    if matches!(self.b.huc_status, 0 | 0x4013) && !self.b.huc_no_bit {
                        self.regs
                            .set(FWSTS5_REG, self.regs.get(FWSTS5_REG) | 1 << 19);
                    }
                    let mut reply = reply_header(17, 16, 0, 0, 0);
                    reply.extend_from_slice(&out);
                    reply
                }
            }
            10 => {
                // xe_gsc_poison_header ran before this submission.
                assert_eq!(output.bytes(output_offset, 36), vec![0x6b; 36]);
                let kind = at32(&input, 36) & 0xff;
                let source = at32(&input, 40);
                if kind == 1 {
                    assert_eq!(source, 0x10000);
                    let mut reply = reply_header(10, 16 + GSC_TO_CSME.len(), 0, 0, 0);
                    reply.extend(proxy_header(2, GSC_TO_CSME.len() as u32, 0x20000, 0x30000));
                    reply.extend_from_slice(GSC_TO_CSME);
                    reply
                } else {
                    // The CSME reply, forwarded unchanged.
                    assert_eq!(source, 0x30000);
                    assert_eq!(&input[52..], CSME_TO_GSC);
                    if !self.b.proxy_no_init {
                        self.regs.set(FWSTS1_REG, self.regs.get(FWSTS1_REG) | 5);
                    }
                    let mut reply = reply_header(10, 16, 0, 0, 0);
                    reply.extend(proxy_header(3, 0, 0x20000, 0x10000));
                    reply
                }
            }
            client => panic!("unexpected HECI client {client}"),
        };
        output.write(output_offset, &reply);
        Some(Ok(()))
    }
}

impl Gsccs for Gsc {
    fn submit(&mut self, commands: &[u32]) -> Result<(), LoadError> {
        if self.b.refuse || self.outstanding {
            return Err(LoadError::Queue);
        }
        self.jobs.push(commands.to_vec());
        self.outstanding = true;
        self.done = match commands[0] {
            0x4040_0002 => {
                let private = self.find(u64::from(commands[1])).0;
                assert_eq!(commands[2], 0);
                assert_eq!(commands[3], 1024 | 1 << 31);
                // memcpy_fw: the image, then zeroes up to 4 MiB.
                assert_eq!(private.bytes(0, self.image.len()), self.image);
                assert_eq!(private.bytes(self.image.len() as u64, 2), [0, 0]);
                assert_eq!(private.read32(4 * 1024 * 1024 - 4), 0);
                if self.b.hang_load {
                    None
                } else {
                    if !self.b.no_init {
                        self.regs.set(FWSTS1_REG, 1 << 9);
                    }
                    Some(Ok(()))
                }
            }
            0x4000_0006 => self.heci(commands),
            other => panic!("unexpected GSCCS command {other:#x}"),
        };
        Ok(())
    }
    fn finished(&mut self) -> Option<Result<(), LoadError>> {
        let done = self.done.take();
        if done.is_some() {
            self.outstanding = false;
        }
        done
    }
}

/// The CSME end of the proxy (the MEI GSC proxy component's send/recv).
#[derive(Default)]
struct Csme {
    sent: Vec<Vec<u8>>,
    send_error: Option<i32>,
    short: bool,
}
impl CsmeProxy for Csme {
    fn send(&mut self, message: &[u8]) -> Result<usize, i32> {
        if let Some(errno) = self.send_error {
            return Err(errno);
        }
        self.sent.push(message.to_vec());
        Ok(message.len())
    }
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, i32> {
        let mut reply = proxy_header(2, CSME_TO_GSC.len() as u32, 0x30000, 0x20000);
        reply.extend_from_slice(CSME_TO_GSC);
        if self.short {
            reply.truncate(8);
        }
        buffer[..reply.len()].copy_from_slice(&reply);
        Ok(reply.len())
    }
}

struct Fixture {
    regs: Rc<Regs>,
    gsc: Gsc,
    huc: HucGsc<Mem>,
    channel: Mem,
    /// Monotonic time of each GSCCS submission.
    stamps: Vec<u64>,
}

/// A loadable GSC (fetched, parsed, private object and packet ready) beside
/// a HuC the media GuC authenticated; the GSC reports compatibility 102.1.0
/// unless `b` names another.
fn fixture(mut b: Behaviour) -> (Fixture, GscUc<Mem, Mem>) {
    if b.compat == (0, 0, 0) {
        b.compat = (102, 1, 0);
    }
    let regs = Rc::new(Regs::default());
    // HECI2 CSR with RDY and a stale RST; the HuC authenticated via the GuC.
    regs.set(CSR_REG, 0x18);
    regs.set(HUC_GUC, 1);
    let image = gsc_image(0x1002);
    let private = Mem::new(PRIVATE_AT, 1024);
    let packet = Mem::new(PACKET_AT, 2);
    let huc_packet = Mem::new(HUC_PACKET_AT, 2);
    let channel = Mem::new(CHANNEL_AT, 16);
    let mut owner = GscUc::init(Some(&image[..]));
    assert_eq!(owner.status(), Status::Available);
    assert_eq!(owner.add_proxy(None), Err(LoadError::NoDevice));
    assert_eq!(
        owner.init_post_hwconfig(true, Some(private.clone()), Some(packet.clone())),
        Ok(())
    );
    assert_eq!(owner.status(), Status::Loadable);
    let gsc = Gsc {
        regs: regs.clone(),
        memory: vec![private, packet, huc_packet.clone(), channel.clone()],
        image,
        b,
        jobs: Vec::new(),
        inputs: Vec::new(),
        done: None,
        outstanding: false,
    };
    let huc = HucGsc {
        status: HucStatus::Running,
        packet: Some(huc_packet),
        object: HUC_OBJECT,
    };
    (
        Fixture {
            regs,
            gsc,
            huc,
            channel,
            stamps: Vec::new(),
        },
        owner,
    )
}

/// Tick the worker 1 ms apart until it is idle; the time it became idle.
fn drive<C: CsmeProxy>(
    owner: &mut GscUc<Mem, Mem>,
    f: &mut Fixture,
    from: u64,
    mut csme: Option<&mut C>,
) -> u64 {
    for tick in 0..30_000u64 {
        let now = from + tick * MS;
        let before = f.gsc.jobs.len();
        let polled = owner.poll(
            now,
            &MediaWindow::new(&*f.regs),
            &mut f.gsc,
            &mut f.huc,
            csme.as_deref_mut(),
        );
        for _ in before..f.gsc.jobs.len() {
            f.stamps.push(now);
        }
        if polled.is_ready() {
            return now;
        }
    }
    panic!("GSC work made no progress");
}

fn no_csme() -> Option<&'static mut NoCsme> {
    None
}

/// NARF's real configuration (no MEI/CSME component): the GSC loads over
/// GSCCS, reports compatibility 102.1.0, authenticates the GuC-authenticated
/// HuC through the PXP client, then xe_gsc_proxy_start fails with -ENODEV
/// and gsc_work records LOAD_FAIL, after which load_start never reloads.
fn smoke_media_gsc_load_uploads_queries_authenticates_huc_and_stops_at_proxy() -> TestResult {
    let (mut f, mut owner) = fixture(Behaviour::default());
    let media = MediaWindow::new(&*f.regs);
    kt_assert_eq!(owner.release(), Some((Version::new(102, 0, 10, 1499), 3)));
    kt_assert!(owner.idle());
    kt_assert_eq!(owner.load_start(&media), Ok(()));
    kt_assert!(!owner.idle());
    kt_assert!(f.regs.writes().is_empty(), "load_start only reads");
    let done = drive(&mut owner, &mut f, 1_000 * MS, no_csme());
    // GSC_FW_LOAD of the 4 MiB private object, then the two HECI packets.
    kt_assert_eq!(
        f.gsc.jobs[0],
        vec![0x4040_0002, PRIVATE_AT, 0, 1024 | 1 << 31]
    );
    kt_assert_eq!(
        f.gsc.jobs[1],
        vec![0x4000_0006, PACKET_AT, 0, 40, PACKET_AT + 4096, 0, 4096, 0]
    );
    kt_assert_eq!(
        f.gsc.jobs[2],
        vec![
            0x4000_0006,
            HUC_PACKET_AT,
            0,
            64,
            HUC_PACKET_AT + 4096,
            0,
            4096,
            0
        ]
    );
    kt_assert_eq!(f.gsc.jobs.len(), 3);
    // MKHI GFX_SRV GET_HOST_COMPATIBILITY_VERSION from host session 0.
    let query = &f.gsc.inputs[0];
    kt_assert_eq!((query[4], &query[8..16]), (7, &[0u8; 8][..]));
    kt_assert_eq!(&query[36..40], &[0x30, 0x42, 0, 0]);
    // PXP 4.3 NEW_HUC_AUTH with the whole HuC object.
    let auth = &f.gsc.inputs[1];
    kt_assert_eq!(auth[4], 17);
    kt_assert_eq!(
        (
            at32(auth, 36),
            at32(auth, 40),
            at32(auth, 44),
            at32(auth, 48)
        ),
        (0x0004_0003, 0x3f, 0, 12)
    );
    kt_assert_eq!(
        (
            u64::from_le_bytes(auth[52..60].try_into().unwrap()),
            at32(auth, 60)
        ),
        HUC_OBJECT
    );
    kt_assert_eq!(owner.compatibility(), Some(Version::new(102, 1, 0, 0)));
    kt_assert_eq!(f.huc.status, HucStatus::Running);
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
    kt_assert_eq!(LoadError::NoDevice.errno(), -19);
    kt_assert!(owner.status().error() && owner.status().loadable());
    kt_assert!(!owner.proxy_started());
    kt_assert!(
        owner.private_retained(),
        "the GSC owns its memory until FLR"
    );
    // Wake, proxy interrupt enable then disable (never RST), wake release.
    kt_assert_eq!(
        f.regs.writes(),
        vec![
            (WAKE_REQ, 0x0001_0001),
            (CSR_REG, 0x09),
            (CSR_REG, 0x08),
            (WAKE_REQ, 0x0001_0000)
        ]
    );
    kt_assert_eq!(f.regs.get(FWSTS5_REG), 1 << 19);
    kt_assert!(owner.idle());
    // LOAD_FAIL is an error state: a later load_start (GT reset, resume)
    // never reloads, whatever the hardware reports.
    for loaded in [1 << 9, 0] {
        f.regs.set(FWSTS1_REG, loaded);
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        kt_assert!(owner.idle());
        drive(&mut owner, &mut f, done + MS, no_csme());
    }
    kt_assert_eq!(f.gsc.jobs.len(), 3);
    kt_assert_eq!(f.regs.writes().len(), 4);
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_load_uploads_queries_authenticates_huc_and_stops_at_proxy
);

/// Every refusal of xe_gsc_init / init_post_hwconfig / load_start /
/// gsc_upload keeps the media GT's HuC (authenticated via the GuC) as it
/// was and never submits HuC or proxy work.
fn smoke_media_gsc_load_refusals_leave_the_guc_huc_running() -> TestResult {
    // Status predicates (xe_uc_fw.h) and errnos.
    kt_assert!(Status::Disabled.error() && !Status::Disabled.available());
    kt_assert!(Status::Missing.error() && Status::Error(GscError::NoData).error());
    kt_assert!(Status::Available.available() && !Status::Available.loadable());
    kt_assert!(Status::InitFail(LoadError::NoMemory).error());
    kt_assert!(Status::Loadable.loadable() && !Status::Loadable.loaded());
    kt_assert!(Status::Transferred.loaded() && !Status::Transferred.error());
    kt_assert!(Status::Running.loaded() && !Status::Running.error());
    for (error, errno) in [
        (LoadError::Exists, -17),
        (LoadError::Time, -62),
        (LoadError::TimedOut, -110),
        (LoadError::Busy, -16),
        (LoadError::Io, -5),
        (LoadError::Invalid, -22),
        (LoadError::NoExec, -8),
        (LoadError::TooBig, -7),
        (LoadError::Protocol, -71),
        (LoadError::Packet(GscError::NoExec), -8),
        (LoadError::Packet(GscError::Invalid), -22),
        (LoadError::Packet(GscError::NoData), -61),
        (LoadError::Packet(GscError::Protocol), -71),
        (LoadError::Packet(GscError::NotCpd), -2),
        (LoadError::Packet(GscError::NoMemory), -12),
        (LoadError::Packet(GscError::Io), -5),
        (LoadError::Packet(GscError::TooLarge), -7),
        (LoadError::Csme(-104), -104),
        (LoadError::Queue, -16),
        (LoadError::Unavailable, -5),
        (LoadError::Wake, -5),
        (LoadError::NoMemory, -12),
    ] {
        kt_assert_eq!(error.errno(), errno);
    }

    // Disabled, missing and malformed images never reach the hardware.
    let regs = Regs::default();
    let media = MediaWindow::new(&regs);
    let mut disabled = GscUc::<Mem, Mem>::disabled();
    let mut missing = GscUc::<Mem, Mem>::init(None);
    let mut short = GscUc::<Mem, Mem>::init(Some(&[0u8; 79][..]));
    let mut unsigned_image = gsc_image(0x1002);
    put32(&mut unsigned_image, 0x100, 0x55ab);
    let mut unsigned = GscUc::<Mem, Mem>::init(Some(&unsigned_image[..]));
    kt_assert_eq!(missing.status(), Status::Missing);
    kt_assert_eq!(short.status(), Status::Error(GscError::NoData));
    kt_assert_eq!(unsigned.status(), Status::Error(GscError::Invalid));
    for owner in [&mut disabled, &mut missing, &mut short, &mut unsigned] {
        kt_assert_eq!(owner.add_proxy(Some(Mem::new(CHANNEL_AT, 16))), Ok(()));
        kt_assert_eq!(
            owner.init_post_hwconfig(
                true,
                Some(Mem::new(PRIVATE_AT, 1024)),
                Some(Mem::new(PACKET_AT, 2))
            ),
            Ok(())
        );
        kt_assert_eq!(owner.load_start(&media), Ok(()));
        kt_assert!(owner.idle() && owner.status().error());
    }
    kt_assert!(regs.writes().is_empty() && regs.map.borrow().is_empty());

    // init_post_hwconfig: no GSCCS0, no private object, a short one.
    let image = gsc_image(0x1002);
    for (gsccs, private, error) in [
        (false, Some(Mem::new(PRIVATE_AT, 1024)), LoadError::NoDevice),
        (true, None, LoadError::NoMemory),
        (true, Some(Mem::new(PRIVATE_AT, 1023)), LoadError::NoMemory),
    ] {
        let mut owner = GscUc::<Mem, Mem>::init(Some(&image[..]));
        kt_assert_eq!(
            owner.init_post_hwconfig(gsccs, private, Some(Mem::new(PACKET_AT, 2))),
            Err(error)
        );
        kt_assert_eq!(owner.status(), Status::InitFail(error));
        kt_assert_eq!(owner.load_start(&media), Ok(()));
        kt_assert!(owner.idle());
    }

    // GSC firmware that survived (GT reset, D3hot) is only re-classified.
    for (fwsts1, status) in [(1 << 9, Status::Transferred), (1 << 9 | 5, Status::Running)] {
        let (f, mut owner) = fixture(Behaviour::default());
        f.regs.set(FWSTS1_REG, fwsts1);
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        kt_assert_eq!(owner.status(), status);
        kt_assert!(owner.idle() && f.regs.writes().is_empty());
    }
    // Lost MMIO is never a loaded GSC.
    let (f, mut owner) = fixture(Behaviour::default());
    f.regs.set(FWSTS1_REG, u32::MAX);
    kt_assert_eq!(
        owner.load_start(&MediaWindow::new(&*f.regs)),
        Err(LoadError::Unavailable)
    );
    kt_assert!(owner.idle() && owner.status() == Status::Loadable);

    // Upload-path failures: each is LOAD_FAIL with its errno.
    let failure = |b: Behaviour, setup: &dyn Fn(&Regs)| {
        let (mut f, mut owner) = fixture(b);
        assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        setup(&f.regs);
        drive(&mut owner, &mut f, 0, no_csme());
        (f, owner)
    };
    // -EEXIST: loaded between load_start and the worker is RUNNING.
    let (f, owner) = failure(Behaviour::default(), &|regs| regs.set(FWSTS1_REG, 1 << 9));
    kt_assert_eq!(owner.status(), Status::Running);
    kt_assert!(f.gsc.jobs.is_empty() && !owner.private_retained());
    // GSC_FW_LOAD never retires: -ETIME after HZ, nothing else submitted.
    let (f, owner) = failure(
        Behaviour {
            hang_load: true,
            ..Behaviour::default()
        },
        &|_| {},
    );
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Time));
    kt_assert_eq!((f.gsc.jobs.len(), f.huc.status), (1, HucStatus::Running));
    kt_assert!(owner.private_retained());
    kt_assert_eq!(f.stamps, vec![0]);
    // The queue refuses the job.
    let (f, owner) = failure(
        Behaviour {
            refuse: true,
            ..Behaviour::default()
        },
        &|_| {},
    );
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Queue));
    kt_assert!(f.gsc.jobs.is_empty());
    // INIT_COMPLETE never appears: -ETIMEDOUT after 500 ms.
    let (mut f, mut owner) = fixture(Behaviour {
        no_init: true,
        ..Behaviour::default()
    });
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    let done = drive(&mut owner, &mut f, 0, no_csme());
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::TimedOut));
    kt_assert_eq!(done, 500 * MS);
    kt_assert_eq!(f.gsc.jobs.len(), 1);
    // A nonzero reply status (-EINVAL) and a foreign compatibility major
    // (-ENOEXEC, still reported) both stop before the HuC.
    for (b, error, found) in [
        (
            Behaviour {
                compat_status: 3,
                ..Behaviour::default()
            },
            GscError::Invalid,
            None,
        ),
        (
            Behaviour {
                compat: (103, 1, 0),
                ..Behaviour::default()
            },
            GscError::NoExec,
            Some(Version::new(103, 1, 0, 0)),
        ),
    ] {
        let (mut f, mut owner) = fixture(b);
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        drive(&mut owner, &mut f, 0, no_csme());
        kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Packet(error)));
        kt_assert_eq!(owner.compatibility(), found);
        kt_assert_eq!((f.gsc.jobs.len(), f.huc.status), (2, HucStatus::Running));
        kt_assert!(!f.regs.writes().contains(&(CSR_REG, 0x09)));
    }
    // An unacknowledged GSC wake ends the work after 50 ms (Linux would
    // proceed without the wake); an inherited request refuses at once.
    let (mut f, mut owner) = fixture(Behaviour::default());
    let regs = Rc::new(Regs {
        stuck_wake: true,
        ..Regs::default()
    });
    regs.set(CSR_REG, 0x18);
    f.regs = regs.clone();
    f.gsc.regs = regs;
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    let done = drive(&mut owner, &mut f, 0, no_csme());
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Wake));
    kt_assert_eq!(done, 50 * MS);
    kt_assert!(f.gsc.jobs.is_empty() && !owner.private_retained());
    kt_assert_eq!(
        f.regs.writes(),
        vec![(WAKE_REQ, 0x0001_0001), (WAKE_REQ, 0x0001_0000)]
    );
    let (mut f, mut owner) = fixture(Behaviour::default());
    f.regs.set(WAKE_REQ, 0x0001_0001);
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    drive(&mut owner, &mut f, 0, no_csme());
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Wake));
    kt_assert!(f.regs.writes().is_empty() && f.gsc.jobs.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_load_refusals_leave_the_guc_huc_running
);

/// xe_huc_auth(XE_HUC_AUTH_VIA_GSC) after a successful load: pending
/// replies hand their message handle back and retry 50 ms apart (five
/// submissions), OP_NOT_PERMITTED counts as authenticated, and every
/// failure is HuC LOAD_FAIL while the GSC load itself continues.
fn smoke_media_gsc_huc_auth_retries_failures_and_skips() -> TestResult {
    // Two pending replies, then success: three submissions 50 ms apart,
    // each resubmission carrying the last gsc_message_handle.
    let (mut f, mut owner) = fixture(Behaviour {
        huc_pending: 2,
        ..Behaviour::default()
    });
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    drive(&mut owner, &mut f, 0, no_csme());
    kt_assert_eq!(f.huc.status, HucStatus::Running);
    kt_assert_eq!(f.stamps, vec![0, 0, 0, 50 * MS, 100 * MS]);
    let handles: Vec<u64> = f.gsc.inputs[1..]
        .iter()
        .map(|input| u64::from_le_bytes(input[16..24].try_into().unwrap()))
        .collect();
    kt_assert_eq!(handles, vec![0, 0xfeed_0001, 0xfeed_0000]);
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));

    // Every outcome of the PXP reply and the HECI1_FWSTS5 bit.
    for (b, huc) in [
        // Already authenticated by an earlier GSC: OP_NOT_PERMITTED.
        (
            Behaviour {
                huc_status: 0x4013,
                ..Behaviour::default()
            },
            HucStatus::Running,
        ),
        // A PXP API error status is -EIO.
        (
            Behaviour {
                huc_status: 0x1002,
                ..Behaviour::default()
            },
            HucStatus::LoadFail,
        ),
        // Success without HUC_AUTH_DONE within 100 ms (-ETIMEDOUT).
        (
            Behaviour {
                huc_no_bit: true,
                ..Behaviour::default()
            },
            HucStatus::LoadFail,
        ),
        // Pending through all five submissions (-EBUSY).
        (
            Behaviour {
                huc_pending: 5,
                ..Behaviour::default()
            },
            HucStatus::LoadFail,
        ),
    ] {
        let (mut f, mut owner) = fixture(b);
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        drive(&mut owner, &mut f, 0, no_csme());
        kt_assert_eq!(f.huc.status, huc);
        // The GSC load reached the proxy start regardless.
        kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
        kt_assert!(f.regs.writes().contains(&(CSR_REG, 0x09)));
        if b.huc_pending == 5 {
            kt_assert_eq!(f.gsc.jobs.len(), 2 + 5);
            kt_assert_eq!(f.stamps[6], 200 * MS);
        }
    }

    // Skips: no GuC authentication, an already GSC-authenticated HuC, a HuC
    // that is not RUNNING or not staged, and a HuC without GSC headers.
    for (setup, huc, packet, submitted) in [
        (HUC_GUC, HucStatus::Running, true, false),
        (FWSTS5_REG, HucStatus::Running, true, false),
        (0, HucStatus::Loadable, true, false),
        (0, HucStatus::NotLoadable, true, false),
        (0, HucStatus::Running, false, false),
    ] {
        let (mut f, mut owner) = fixture(Behaviour::default());
        match setup {
            HUC_GUC => f.regs.set(HUC_GUC, 0),
            FWSTS5_REG => f.regs.set(FWSTS5_REG, 1 << 19),
            _ => {}
        }
        f.huc.status = huc;
        if !packet {
            f.huc.packet = None;
        }
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        drive(&mut owner, &mut f, 0, no_csme());
        kt_assert_eq!(f.gsc.jobs.len() == 3, submitted);
        let expected = match (setup, huc, packet) {
            // -ENODEV without huc->gsc_pkt is a failure.
            (0, HucStatus::Running, false) => HucStatus::LoadFail,
            _ => huc,
        };
        kt_assert_eq!(f.huc.status, expected);
        kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::NoDevice));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_huc_auth_retries_failures_and_skips
);

/// The GSC proxy up to and through a CSME component model: QUERY from the
/// KMD, the GSC's message relayed to the CSME, the CSME reply relayed back,
/// END and PROXY_STATE_NORMAL make the GSC RUNNING. A still-loaded GSC is
/// re-classified after a GT reset; one lost on resume reloads. Header
/// validation, CSME errors and an unbound component fail closed.
fn smoke_media_gsc_proxy_csme_boundary_and_reload_after_resume() -> TestResult {
    // validate_proxy_header in its check order.
    let header = |kind, length, source, destination, status| ProxyHeader {
        kind,
        length,
        source,
        destination,
        status,
    };
    let ok = header(2, 4, 0x20000, 0x30000, 0);
    kt_assert_eq!(validate_proxy_header(ok, 0x20000, 0x30000, 64), Ok(()));
    for (candidate, error) in [
        (header(2, 4, 0x20000, 0x10000, 0), LoadError::NoExec),
        (header(2, 4, 0x30000, 0x30000, 0), LoadError::NoExec),
        (header(2, 49, 0x20000, 0x30000, 0), LoadError::TooBig),
        (header(2, 0, 0x20000, 0x30000, 0), LoadError::Io),
        (header(0, 4, 0x20000, 0x30000, 0), LoadError::Io),
    ] {
        kt_assert_eq!(
            validate_proxy_header(candidate, 0x20000, 0x30000, 64),
            Err(error)
        );
    }
    // A status error matters only for messages to the KMD.
    kt_assert_eq!(
        validate_proxy_header(header(3, 0, 0x20000, 0x10000, 7), 0x20000, 0x10000, 64),
        Err(LoadError::Io)
    );
    kt_assert_eq!(
        validate_proxy_header(header(4, 0, 0x20000, 0x30000, 7), 0x20000, 0x30000, 64),
        Ok(())
    );
    kt_assert_eq!(
        ProxyHeader::parse(&proxy_header(2, 9, 0x20000, 0x30000)),
        header(2, 9, 0x20000, 0x30000, 0)
    );

    // The full proxy start with a bound CSME component.
    let (mut f, mut owner) = fixture(Behaviour::default());
    kt_assert_eq!(owner.add_proxy(Some(f.channel.clone())), Ok(()));
    let mut csme = Csme::default();
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    let done = drive(&mut owner, &mut f, 0, Some(&mut csme));
    kt_assert_eq!(owner.status(), Status::Running);
    kt_assert!(owner.proxy_started());
    kt_assert_eq!(f.huc.status, HucStatus::Running);
    kt_assert_eq!(f.gsc.jobs.len(), 5);
    // QUERY: GSC header (proxy client 10) and a KMD-to-GSC proxy header.
    let query = &f.gsc.inputs[2];
    kt_assert_eq!((query.len(), query[4]), (52, 10));
    kt_assert_eq!(&query[36..], &proxy_header(1, 0, 0x10000, 0x20000)[..]);
    // The GSC's message reached the CSME as proxy header plus payload.
    let mut relayed = proxy_header(2, GSC_TO_CSME.len() as u32, 0x20000, 0x30000);
    relayed.extend_from_slice(GSC_TO_CSME);
    kt_assert_eq!(csme.sent, vec![relayed]);
    kt_assert_eq!(f.gsc.inputs[3].len(), 36 + 16 + CSME_TO_GSC.len());
    kt_assert_eq!(
        f.gsc.jobs[4],
        vec![
            0x4000_0006,
            CHANNEL_AT,
            0,
            58,
            CHANNEL_AT + 32 * 1024,
            0,
            32 * 1024,
            0
        ]
    );
    // Interrupt enabled, its status cleared, and left enabled.
    kt_assert_eq!(
        f.regs.writes(),
        vec![
            (WAKE_REQ, 0x0001_0001),
            (CSR_REG, 0x09),
            (CSR_REG, 0x0b),
            (WAKE_REQ, 0x0001_0000)
        ]
    );
    // A HECI2 interrupt queues one more request (SW_PROXY), dropped while
    // the component is unbound.
    owner.proxy_irq(false);
    kt_assert!(owner.idle());
    owner.proxy_irq(true);
    f.regs.set(FWSTS1_REG, 1 << 9);
    let done = drive(&mut owner, &mut f, done + MS, Some(&mut csme));
    kt_assert_eq!(f.gsc.jobs.len(), 7);
    kt_assert_eq!(owner.status(), Status::Running);

    // GT reset: the GSC survived, nothing reloads.
    f.regs.set(FWSTS1_REG, 1 << 9 | 5);
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    kt_assert!(owner.idle());
    kt_assert_eq!(owner.status(), Status::Running);
    // Resume from a state that lost the GSC: a full reload.
    f.regs.set(FWSTS1_REG, 0);
    f.regs.set(FWSTS5_REG, 0);
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    let resumed = done + 10 * MS;
    drive(&mut owner, &mut f, resumed, Some(&mut csme));
    kt_assert_eq!(f.gsc.jobs.len(), 12);
    kt_assert_eq!(f.gsc.jobs[7][0], 0x4040_0002);
    kt_assert_eq!(owner.status(), Status::Running);
    kt_assert_eq!(f.regs.get(FWSTS5_REG), 1 << 19);

    // CSME failures and an incomplete proxy init are LOAD_FAIL with the
    // interrupt disabled again.
    for (csme, b, error) in [
        (
            Csme {
                send_error: Some(-104),
                ..Csme::default()
            },
            Behaviour::default(),
            LoadError::Csme(-104),
        ),
        (
            Csme {
                short: true,
                ..Csme::default()
            },
            Behaviour::default(),
            LoadError::Protocol,
        ),
        (
            Csme::default(),
            Behaviour {
                proxy_no_init: true,
                ..Behaviour::default()
            },
            LoadError::Io,
        ),
    ] {
        let mut csme = csme;
        let (mut f, mut owner) = fixture(b);
        kt_assert_eq!(owner.add_proxy(Some(f.channel.clone())), Ok(()));
        kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
        drive(&mut owner, &mut f, 0, Some(&mut csme));
        kt_assert_eq!(owner.status(), Status::LoadFail(error));
        kt_assert!(!owner.proxy_started());
        kt_assert_eq!(f.regs.get(CSR_REG) & 1, 0);
    }
    // A component that never binds: -EIO after 20 s.
    let (mut f, mut owner) = fixture(Behaviour::default());
    kt_assert_eq!(owner.add_proxy(Some(f.channel.clone())), Ok(()));
    kt_assert_eq!(owner.load_start(&MediaWindow::new(&*f.regs)), Ok(()));
    let done = drive(&mut owner, &mut f, 0, no_csme());
    kt_assert_eq!(owner.status(), Status::LoadFail(LoadError::Io));
    kt_assert_eq!(done, 20_000 * MS);
    kt_assert_eq!(f.gsc.jobs.len(), 3);
    // A channel smaller than both 32 KiB buffers is refused.
    let image = gsc_image(0x1002);
    let mut owner = GscUc::<Mem, Mem>::init(Some(&image[..]));
    kt_assert_eq!(
        owner.add_proxy(Some(Mem::new(CHANNEL_AT, 15))),
        Err(LoadError::NoMemory)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_proxy_csme_boundary_and_reload_after_resume
);

/// gsc_er_complete: only a loaded GSC whose GSCI_TIMER_STATUS reads
/// TIMER_EXPIRED wedges, and that drops the run's other actions.
fn smoke_media_gsc_er_complete_wedges_only_on_an_expired_timer() -> TestResult {
    for (fwsts1, timer, wedged) in [
        (0, 1, false),
        (1 << 9, 2, false),
        (1 << 9, 3, false),
        (1 << 9, 0, false),
        (1 << 9, 1, true),
    ] {
        let (mut f, mut owner) = fixture(Behaviour::default());
        f.regs.set(FWSTS1_REG, fwsts1);
        f.regs.set(TIMER_REG, timer);
        owner.er_complete_irq();
        owner.proxy_irq(true);
        drive(&mut owner, &mut f, 0, no_csme());
        kt_assert_eq!(owner.wedged(), wedged);
        kt_assert!(f.gsc.jobs.is_empty());
        kt_assert_eq!(f.regs.writes()[0], (WAKE_REQ, 0x0001_0001));
        kt_assert_eq!(*f.regs.writes().last().unwrap(), (WAKE_REQ, 0x0001_0000));
        // Without a component the queued SW_PROXY request is -ENODEV and
        // writes nothing; after a wedge it never ran.
        kt_assert_eq!(f.regs.writes().len(), 2);
        kt_assert_eq!(owner.status(), Status::Loadable);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_er_complete_wedges_only_on_an_expired_timer
);
