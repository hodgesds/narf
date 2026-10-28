//! Kernel smokes for the resume environment (`power/resume-env`,
//! issue #1000): the polled early block reader and the
//! verify-then-handoff driver of design §6.
//!
//! Fixture discipline, per lane: the virtio device model below
//! derives every queue address from the registers the reader
//! programs and speaks the ring formats from VirtIO 1.2 §2.6 /
//! §5.2.6 itself — it never reads the reader's layout constants —
//! and the first request's exact header bytes and descriptor
//! chain are pinned against the spec's framing. The tamper
//! matrix runs the design §11 acceptance shape: for every
//! tampered byte class, resume refuses *and* the recording hook
//! proves its unseal never ran, so no restored state was built
//! from an unverified image.
//!
//! The entropy seam, fixture anchor, and memory store are
//! compact copies of the suspend-service smokes' fixtures
//! (deliberately not shared: the two test modules evolve with
//! different lanes). The fixture anchor's secret derives from a
//! published label — custody theatre, labelled `AnchorKind::Test`
//! in every record; its one honest behaviour is presence.

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    attempt_resume, write_image, AnchorError, AnchorKind, EarlyBlkError, EarlyTransport,
    ImageStore, KeyCustodyAnchor, KeyEntropy, PolicyLevel, PolledBlkReader, RecordedPolicy,
    ResumePrompt, ResumeRefusal, Secret32, ServiceError, SlotRecord, SuspendService, UnwrapCtx,
    VerifiedResume, WrapCtx, WrappedSlot, WriteRequest,
};

// ── Scripted entropy seam (copy of the P1 fixture) ───────────────────

#[derive(Clone)]
struct ScriptedEntropy {
    present: Rc<Cell<bool>>,
    draws: Rc<Cell<u64>>,
}

impl ScriptedEntropy {
    fn new(present: bool) -> Self {
        Self {
            present: Rc::new(Cell::new(present)),
            draws: Rc::new(Cell::new(0)),
        }
    }
}

impl KeyEntropy for ScriptedEntropy {
    fn has_seed_grade(&self) -> bool {
        self.present.get()
    }

    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
        if !self.present.get() {
            out.fill(0);
            return Err(ServiceError::EntropyUnavailable);
        }
        let n = self.draws.get() + 1;
        self.draws.set(n);
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ n.wrapping_mul(0x2545_f491_4f6c_dd1d);
        for byte in out.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
        Ok(())
    }
}

// ── Fixture anchors ──────────────────────────────────────────────────

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// Fixture custody anchor: published secret, honest presence gate
/// (the P1 fixture, copied). Atomics keep it `Send + Sync` as the
/// production trait bound requires.
#[derive(Debug)]
struct TestAnchor {
    id: &'static str,
    secret: [u8; 32],
    presence: AtomicBool,
    wraps: AtomicU64,
}

impl TestAnchor {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            secret: hkdf32(b"narf-suspend/test-anchor-secret", id.as_bytes()),
            presence: AtomicBool::new(false),
            wraps: AtomicU64::new(0),
        }
    }

    fn grant_presence(&self) {
        self.presence.store(true, Ordering::SeqCst);
    }

    fn kek(&self, epoch: u64, counter: u64) -> [u8; 32] {
        let mut info = Vec::with_capacity(32);
        info.extend_from_slice(b"narf-suspend/test-anchor");
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(&counter.to_le_bytes());
        hkdf32(&self.secret, &info)
    }
}

impl KeyCustodyAnchor for TestAnchor {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Test
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        let counter = self.wraps.fetch_add(1, Ordering::SeqCst);
        let kek = self.kek(ctx.sms_epoch, counter);
        let mut nonce_info = Vec::with_capacity(16);
        nonce_info.extend_from_slice(b"nonce");
        nonce_info.extend_from_slice(&counter.to_le_bytes());
        let nonce_full = hkdf32(&kek, &nonce_info);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let mut aad = Vec::with_capacity(8 + self.id.len());
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(self.id.as_bytes());
        let mut ct = [0u8; 32];
        secret.with_bytes(|s| ct.copy_from_slice(s));
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::with_capacity(12 + 32 + 16);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        let mut params = counter.to_le_bytes().to_vec();
        params.extend_from_slice(self.id.as_bytes());
        Ok(WrappedSlot { params, blob })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        if !self.presence.load(Ordering::SeqCst) {
            return Err(AnchorError::Refused);
        }
        if slot.params.len() != 8 + self.id.len() || slot.blob.len() != 12 + 32 + 16 {
            return Err(AnchorError::Failed);
        }
        // Params are counter ‖ anchor id (see `wrap`); only the
        // counter prefix feeds the KEK. Copying the whole composite
        // buffer into this 8-byte array panics for any non-empty id.
        let mut counter_b = [0u8; 8];
        counter_b.copy_from_slice(&slot.params[..8]);
        let kek = self.kek(ctx.sms_epoch, u64::from_le_bytes(counter_b));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&slot.blob[..12]);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&slot.blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&slot.blob[44..]);
        let mut aad = Vec::with_capacity(8 + self.id.len());
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(self.id.as_bytes());
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

// ── Fixture anchor round-trip (direct) ───────────────────────────────
//
// The environment-level round-trips reach `TestAnchor::unwrap` only
// through `attempt_resume`; this smoke pins the anchor's own
// contract with a non-empty id: params are counter ‖ anchor id, and
// unwrap recovers exactly the wrapped secret. (Regression: unwrap
// once copied the whole composite params buffer into the 8-byte
// counter array, which panics for every non-empty id — CI run
// 40583019061, kernel-test on both arches.)

fn smoke_power_resume_env_test_anchor_round_trip() -> TestResult {
    let anchor = TestAnchor::new("primary");
    let secret = Secret32::mint([0x5a; 32]);
    let slot = match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("test anchor wrap failed"),
    };
    // The params really are the composite shape unwrap's length
    // guard validates: 8-byte counter prefix ‖ anchor id.
    if slot.params.len() != 8 + anchor.id.len() || &slot.params[8..] != anchor.id.as_bytes() {
        return TestResult::Fail("wrapped params are not counter ‖ anchor id");
    }
    if slot.blob.len() != 12 + 32 + 16 {
        return TestResult::Fail("wrapped blob is not nonce ‖ ciphertext ‖ tag");
    }
    // Presence not granted: refuse, don't unwrap.
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &slot) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("unwrap without presence was not refused"),
    }
    anchor.grant_presence();
    let recovered = match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &slot) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("unwrap of a well-formed slot failed"),
    };
    let mut secret_b = [0u8; 32];
    secret.with_bytes(|s| secret_b.copy_from_slice(s));
    let mut recovered_b = [0u8; 32];
    recovered.with_bytes(|s| recovered_b.copy_from_slice(s));
    if recovered_b != secret_b {
        return TestResult::Fail("unwrapped secret differs from the wrapped secret");
    }
    // A second wrap takes the next counter: the params differ, and
    // that slot round-trips too.
    let slot2 = match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("second test anchor wrap failed"),
    };
    if slot2.params == slot.params {
        return TestResult::Fail("successive wraps share one params identity");
    }
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &slot2) {
        Ok(s) => {
            let mut b = [0u8; 32];
            s.with_bytes(|x| b.copy_from_slice(x));
            if b != secret_b {
                return TestResult::Fail("second slot unwrapped to a different secret");
            }
        }
        Err(_) => return TestResult::Fail("second slot did not unwrap"),
    }
    // The KEK binds the epoch: the same slot under another epoch's
    // context fails the AEAD, indistinguishably from tampering.
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 2 }, &slot) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("slot unwrapped under the wrong epoch"),
    }
    // Malformed shapes fail closed — Failed, never a panic: params
    // missing the id, params with a trailing byte, a flipped counter
    // byte (wrong KEK), and a truncated blob.
    let mut no_id = slot.clone();
    no_id.params.truncate(8);
    let mut trailing = slot.clone();
    trailing.params.push(0);
    let mut wrong_counter = slot.clone();
    wrong_counter.params[0] ^= 0xff;
    let mut short_blob = slot.clone();
    short_blob.blob.truncate(12 + 32);
    for bad in [no_id, trailing, wrong_counter, short_blob] {
        match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &bad) {
            Err(AnchorError::Failed) => {}
            _ => return TestResult::Fail("malformed slot did not fail closed"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_test_anchor_round_trip);

/// An anchor of a kind no fixture image enrolls. Its `unwrap`
/// counts calls: the environment must never even attempt a
/// pairing whose kind matches no slot.
struct OtherKindAnchor {
    unwrap_calls: AtomicU64,
}

impl KeyCustodyAnchor for OtherKindAnchor {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Tpm
    }

    fn wrap(&self, _ctx: &WrapCtx, _secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        Err(AnchorError::Unavailable)
    }

    fn unwrap(&self, _ctx: &UnwrapCtx, _slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        Err(AnchorError::Unavailable)
    }
}

// ── Fixture store + prompt ───────────────────────────────────────────

/// In-memory image store with tamper helpers (the P1 fixture's
/// shape; `flip_byte` goes through the lock so it works through
/// a shared reference mid-test).
#[derive(Debug)]
struct MemImageStore {
    data: IrqSafeSpinLock<Vec<u8>>,
}

impl MemImageStore {
    fn new(len: usize) -> Self {
        Self {
            data: IrqSafeSpinLock::new(alloc::vec![0u8; len]),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.data.lock().clone()
    }

    fn flip_byte(&self, offset: u64) {
        self.data.lock()[offset as usize] ^= 0xff;
    }
}

impl ImageStore for MemImageStore {
    fn len_bytes(&self) -> u64 {
        self.data.lock().len() as u64
    }

    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        let start = offset as usize;
        let end = start
            .checked_add(out.len())
            .ok_or(ServiceError::Truncated)?;
        let data = self.data.lock();
        if end > data.len() {
            return Err(ServiceError::Truncated);
        }
        out.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
        let start = offset as usize;
        let end = start.checked_add(data.len()).ok_or(ServiceError::Store)?;
        let mut store = self.data.lock();
        if end > store.len() {
            return Err(ServiceError::Store);
        }
        store[start..end].copy_from_slice(data);
        Ok(())
    }

    fn flush(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}

/// Records every prompt line, in order, for the §6.2 phrasing
/// assertions (claims announced as attempts; facts only after
/// verification).
#[derive(Default)]
struct RecordingPrompt {
    lines: Vec<alloc::string::String>,
}

impl RecordingPrompt {
    fn said_attempt(&self) -> bool {
        self.lines.iter().any(|l| l.contains("attempting resume"))
    }

    fn said_verified(&self) -> bool {
        self.lines.iter().any(|l| l.contains("image verified"))
    }
}

impl ResumePrompt for RecordingPrompt {
    fn say(&mut self, line: &str) {
        self.lines.push(alloc::string::String::from(line));
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

// Format offsets pinned against power spec §3.3, as in the P1
// smokes: header page, then manifest pages, then hook region,
// then chunks.
const POLICY_BYTE_OFFSET: u64 = 36; // magic 8 + version 4 + image_id 16 + sms_epoch 8
const MANIFEST_OFFSET: u64 = 4096;
const STORE_LEN: usize = 3 * 1024 * 1024;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push((i.wrapping_mul(7) % 251) as u8);
    }
    img
}

fn token_policy() -> RecordedPolicy {
    RecordedPolicy {
        level: PolicyLevel::Token,
        policy_epoch: 7,
    }
}

/// Seal a token-policy image with one enrolled test anchor into
/// a fresh store; returns the store, the anchor (presence NOT
/// granted), and the plaintext.
fn sealed_token_image(image_len: usize) -> (MemImageStore, TestAnchor, Vec<u8>) {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let anchor = TestAnchor::new("primary");
    svc.enroll(&anchor).expect("enroll");
    let image = pattern_image(image_len);
    let mut store = MemImageStore::new(STORE_LEN);
    svc.seal_image(&mut store, token_policy(), &image)
        .expect("seal");
    (store, anchor, image)
}

// ── Fixture virtio-blk device model ──────────────────────────────────
//
// Register offsets per VirtIO 1.2 §4.2.2, ring formats per §2.6,
// request framing per §5.2.6 — restated here from the spec, not
// imported from the reader under test. The model derives every
// queue address from the registers the reader programs, walks
// chains by the spec's descriptor format, and completes requests
// synchronously on notify (the shape QEMU presents for cached
// virtio-blk reads). Anything off-spec is recorded as a fault for
// the tests to assert on.

const RAM_LEN: usize = 256 * 1024;
const DMA_BASE: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DevEvent {
    Reset,
    FeaturesWritten(u32, u32),
    QueueReady,
    DriverOk,
    Notify(u32),
}

#[derive(Clone, Debug, PartialEq)]
struct FirstRequest {
    header: [u8; 16],
    /// (addr, len, flags, next) per descriptor, in chain order.
    descs: Vec<(u64, u32, u16, u16)>,
}

#[derive(Clone)]
struct Knobs {
    magic_ok: bool,
    version: u32,
    device_id: u32,
    /// Device-features word 1 (bit 0 = VIRTIO_F_VERSION_1).
    features_high: u32,
    queue_num_max: u16,
    capacity_override: Option<u64>,
    wedged: bool,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            magic_ok: true,
            version: 2,
            device_id: 2,
            features_high: 1,
            queue_num_max: 16,
            capacity_override: None,
            wedged: false,
        }
    }
}

#[derive(Default)]
struct ModelRegs {
    status: u32,
    feat_sel: u32,
    drv_feat_sel: u32,
    queue_sel: u32,
    queue_num: u16,
    queue_ready: bool,
    desc: u64,
    driver: u64,
    device: u64,
    used_idx: u16,
}

struct FixtureDevice {
    ram: Rc<RefCell<Vec<u8>>>,
    disk: Rc<RefCell<Vec<u8>>>,
    log: Rc<RefCell<Vec<DevEvent>>>,
    faults: Rc<RefCell<Vec<&'static str>>>,
    first_request: Rc<RefCell<Option<FirstRequest>>>,
    knobs: Knobs,
}

impl FixtureDevice {
    fn new(disk: Vec<u8>) -> Self {
        Self {
            ram: Rc::new(RefCell::new(alloc::vec![0u8; RAM_LEN])),
            disk: Rc::new(RefCell::new(disk)),
            log: Rc::new(RefCell::new(Vec::new())),
            faults: Rc::new(RefCell::new(Vec::new())),
            first_request: Rc::new(RefCell::new(None)),
            knobs: Knobs::default(),
        }
    }

    fn transport(&self) -> FixtureTransport {
        FixtureTransport {
            regs: RefCell::new(ModelRegs::default()),
            ram: self.ram.clone(),
            disk: self.disk.clone(),
            log: self.log.clone(),
            faults: self.faults.clone(),
            first_request: self.first_request.clone(),
            knobs: self.knobs.clone(),
        }
    }

    fn open(&self) -> Result<PolledBlkReader<FixtureTransport>, EarlyBlkError> {
        PolledBlkReader::open(self.transport(), DMA_BASE, RAM_LEN)
    }
}

struct FixtureTransport {
    regs: RefCell<ModelRegs>,
    ram: Rc<RefCell<Vec<u8>>>,
    disk: Rc<RefCell<Vec<u8>>>,
    log: Rc<RefCell<Vec<DevEvent>>>,
    faults: Rc<RefCell<Vec<&'static str>>>,
    first_request: Rc<RefCell<Option<FirstRequest>>>,
    knobs: Knobs,
}

impl FixtureTransport {
    fn fault(&self, msg: &'static str) {
        self.faults.borrow_mut().push(msg);
    }

    fn rd16(&self, phys: u64) -> u16 {
        let mut b = [0u8; 2];
        self.dma_read(phys, &mut b);
        u16::from_le_bytes(b)
    }

    fn capacity(&self) -> u64 {
        self.knobs
            .capacity_override
            .unwrap_or_else(|| (self.disk.borrow().len() / 512) as u64)
    }

    /// Process every published avail entry, synchronously.
    fn process_notify(&self) {
        if self.knobs.wedged {
            return; // the wedged device: notify seen, never served
        }
        let (ready, desc, drv, dev, qnum) = {
            let r = self.regs.borrow();
            (r.queue_ready, r.desc, r.driver, r.device, r.queue_num)
        };
        if !ready {
            self.fault("notify before queue ready");
            return;
        }
        loop {
            let avail_idx = self.rd16(drv + 2);
            let used = self.regs.borrow().used_idx;
            if used == avail_idx {
                break;
            }
            let slot = used % qnum;
            let head = self.rd16(drv + 4 + 2 * u64::from(slot));
            let written = self.process_chain(desc, head);
            // Used element first, then the index (§2.6.7 order).
            let mut elem = [0u8; 8];
            elem[..4].copy_from_slice(&u32::from(head).to_le_bytes());
            elem[4..].copy_from_slice(&written.to_le_bytes());
            self.dma_write(dev + 4 + 8 * u64::from(slot), &elem);
            let next = used.wrapping_add(1);
            self.dma_write(dev + 2, &next.to_le_bytes());
            self.regs.borrow_mut().used_idx = next;
        }
    }

    /// Walk one chain, serve the read, write the status byte;
    /// returns the used-element length (device-written bytes).
    fn process_chain(&self, desc_base: u64, head: u16) -> u32 {
        let mut descs: Vec<(u64, u32, u16, u16)> = Vec::new();
        let mut idx = head;
        loop {
            let mut raw = [0u8; 16];
            self.dma_read(desc_base + 16 * u64::from(idx), &mut raw);
            let addr = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
            let next = u16::from_le_bytes(raw[14..].try_into().unwrap());
            descs.push((addr, len, flags, next));
            if flags & 1 == 0 {
                break;
            }
            idx = next;
            if descs.len() > 8 {
                self.fault("chain too long");
                break;
            }
        }
        if self.first_request.borrow().is_none() {
            let mut header = [0u8; 16];
            if !descs.is_empty() {
                self.dma_read(descs[0].0, &mut header);
            }
            *self.first_request.borrow_mut() = Some(FirstRequest {
                header,
                descs: descs.clone(),
            });
        }
        if descs.len() != 3 {
            self.fault("chain is not header/data/status");
            return 0;
        }
        let (h, d, s) = (descs[0], descs[1], descs[2]);
        if h.1 != 16 || h.2 & 2 != 0 {
            self.fault("header descriptor shape");
        }
        if d.2 & 2 == 0 {
            self.fault("data descriptor not device-writable");
        }
        if s.1 != 1 || s.2 & 2 == 0 {
            self.fault("status descriptor shape");
        }
        let mut hdr = [0u8; 16];
        self.dma_read(h.0, &mut hdr);
        let ty = u32::from_le_bytes(hdr[..4].try_into().unwrap());
        let sector = u64::from_le_bytes(hdr[8..].try_into().unwrap());
        if ty != 0 {
            self.fault("request is not T_IN");
        }
        let mut status = 0u8; // VIRTIO_BLK_S_OK
        let start = (sector * 512) as usize;
        let len = d.1 as usize;
        let bytes = {
            let disk = self.disk.borrow();
            if start + len > disk.len() {
                status = 1; // VIRTIO_BLK_S_IOERR
                None
            } else {
                Some(disk[start..start + len].to_vec())
            }
        };
        if let Some(bytes) = bytes {
            self.dma_write(d.0, &bytes);
        }
        self.dma_write(s.0, &[status]);
        d.1 + 1
    }
}

impl EarlyTransport for FixtureTransport {
    fn read_u32(&self, offset: u64) -> u32 {
        match offset {
            0x000 => {
                if self.knobs.magic_ok {
                    0x7472_6976
                } else {
                    0
                }
            }
            0x004 => self.knobs.version,
            0x008 => self.knobs.device_id,
            0x010 => match self.regs.borrow().feat_sel {
                0 => 0, // no block features offered
                1 => self.knobs.features_high,
                _ => 0,
            },
            0x034 => u32::from(self.knobs.queue_num_max),
            0x070 => self.regs.borrow().status,
            0x100 => self.capacity() as u32,
            0x104 => (self.capacity() >> 32) as u32,
            _ => 0,
        }
    }

    fn write_u32(&self, offset: u64, value: u32) {
        match offset {
            0x014 => self.regs.borrow_mut().feat_sel = value,
            0x020 => {
                let sel = self.regs.borrow().drv_feat_sel;
                self.log
                    .borrow_mut()
                    .push(DevEvent::FeaturesWritten(sel, value));
            }
            0x024 => self.regs.borrow_mut().drv_feat_sel = value,
            0x030 => self.regs.borrow_mut().queue_sel = value,
            0x038 => self.regs.borrow_mut().queue_num = value as u16,
            0x044 => {
                if value == 1 {
                    self.regs.borrow_mut().queue_ready = true;
                    self.log.borrow_mut().push(DevEvent::QueueReady);
                }
            }
            0x050 => {
                self.log.borrow_mut().push(DevEvent::Notify(value));
                self.process_notify();
            }
            0x070 => {
                if value == 0 {
                    *self.regs.borrow_mut() = ModelRegs::default();
                    self.log.borrow_mut().push(DevEvent::Reset);
                } else {
                    self.regs.borrow_mut().status = value;
                    if value & 4 != 0 {
                        self.log.borrow_mut().push(DevEvent::DriverOk);
                    }
                }
            }
            0x080 => {
                let mut r = self.regs.borrow_mut();
                r.desc = (r.desc & !0xffff_ffff) | u64::from(value);
            }
            0x084 => {
                let mut r = self.regs.borrow_mut();
                r.desc = (r.desc & 0xffff_ffff) | (u64::from(value) << 32);
            }
            0x090 => {
                let mut r = self.regs.borrow_mut();
                r.driver = (r.driver & !0xffff_ffff) | u64::from(value);
            }
            0x094 => {
                let mut r = self.regs.borrow_mut();
                r.driver = (r.driver & 0xffff_ffff) | (u64::from(value) << 32);
            }
            0x0a0 => {
                let mut r = self.regs.borrow_mut();
                r.device = (r.device & !0xffff_ffff) | u64::from(value);
            }
            0x0a4 => {
                let mut r = self.regs.borrow_mut();
                r.device = (r.device & 0xffff_ffff) | (u64::from(value) << 32);
            }
            _ => {}
        }
    }

    fn dma_read(&self, phys: u64, out: &mut [u8]) {
        let ram = self.ram.borrow();
        let start = phys as usize;
        if start + out.len() > ram.len() {
            self.fault("dma read out of range");
            out.fill(0);
            return;
        }
        out.copy_from_slice(&ram[start..start + out.len()]);
    }

    fn dma_write(&self, phys: u64, data: &[u8]) {
        let mut ram = self.ram.borrow_mut();
        let start = phys as usize;
        if start + data.len() > ram.len() {
            self.fault("dma write out of range");
            return;
        }
        ram[start..start + data.len()].copy_from_slice(data);
    }
}

// ── Early reader smokes ──────────────────────────────────────────────

fn smoke_power_resume_reader_handshake_order() -> TestResult {
    let dev = FixtureDevice::new(pattern_image(64 * 1024));
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    if reader.capacity_sectors() != 128 {
        return TestResult::Fail("capacity does not match the fixture disk");
    }
    if reader.queue_size() != 16 {
        return TestResult::Fail("queue size was not negotiated to the cap");
    }
    let log = dev.log.borrow();
    let pos = |ev: &DevEvent| log.iter().position(|e| e == ev);
    let (reset, feat, ready, ok) = (
        pos(&DevEvent::Reset),
        pos(&DevEvent::FeaturesWritten(1, 1)),
        pos(&DevEvent::QueueReady),
        pos(&DevEvent::DriverOk),
    );
    if pos(&DevEvent::FeaturesWritten(0, 0)).is_none() {
        return TestResult::Fail("driver features word 0 was never written");
    }
    match (reset, feat, ready, ok) {
        (Some(a), Some(b), Some(c), Some(d)) if a < b && b < c && c < d => {}
        _ => return TestResult::Fail("handshake events out of order"),
    }
    if !dev.faults.borrow().is_empty() {
        return TestResult::Fail("device model recorded faults during open");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_handshake_order);

fn smoke_power_resume_reader_round_trip() -> TestResult {
    let disk = pattern_image(256 * 1024);
    let dev = FixtureDevice::new(disk.clone());
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    // Whole sectors at an unaligned sector index.
    let mut out = alloc::vec![0u8; 1024];
    if reader.read_sectors(3, &mut out).is_err() {
        return TestResult::Fail("sector read failed");
    }
    if out.as_slice() != &disk[1536..2560] {
        return TestResult::Fail("sector read returned wrong bytes");
    }
    // Offset-general read at exactly the sealed-body shape
    // (mid-page offset, sub-sector length).
    let mut body = alloc::vec![0u8; 72];
    if reader.read_exact(4024, &mut body).is_err() {
        return TestResult::Fail("unaligned read_exact failed");
    }
    if body.as_slice() != &disk[4024..4096] {
        return TestResult::Fail("unaligned read_exact returned wrong bytes");
    }
    // A read far larger than the staging buffer, mid-disk offset.
    let mut big = alloc::vec![0u8; 200_000];
    if reader.read_exact(100, &mut big).is_err() {
        return TestResult::Fail("large read_exact failed");
    }
    if big.as_slice() != &disk[100..200_100] {
        return TestResult::Fail("large read_exact returned wrong bytes");
    }
    if reader.len_bytes() != disk.len() as u64 {
        return TestResult::Fail("store length does not match capacity");
    }
    if !dev.faults.borrow().is_empty() {
        return TestResult::Fail("device model recorded faults during reads");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_round_trip);

fn smoke_power_resume_reader_first_request_framing() -> TestResult {
    // The first request's bytes are pinned against VirtIO 1.2
    // §5.2.6 (header: type u32 ‖ reserved u32 ‖ sector u64) and
    // §2.6 (descriptor chain), as recorded by the device model —
    // the masking-defeating pin: reader and model cannot agree
    // on a wrong frame here, because the expectation is literals.
    let disk = pattern_image(64 * 1024);
    let dev = FixtureDevice::new(disk.clone());
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let mut out = alloc::vec![0u8; 512];
    if reader.read_sectors(3, &mut out).is_err() {
        return TestResult::Fail("read failed");
    }
    if out.as_slice() != &disk[1536..2048] {
        return TestResult::Fail("read returned wrong bytes");
    }
    let first = match dev.first_request.borrow().clone() {
        Some(f) => f,
        None => return TestResult::Fail("device model saw no request"),
    };
    let mut want_header = [0u8; 16];
    want_header[8..16].copy_from_slice(&3u64.to_le_bytes());
    if first.header != want_header {
        return TestResult::Fail("request header is not the spec frame for T_IN sector 3");
    }
    if first.descs.len() != 3 {
        return TestResult::Fail("request chain is not three descriptors");
    }
    let (h, d, s) = (first.descs[0], first.descs[1], first.descs[2]);
    if h.1 != 16 || h.2 != 1 || h.3 != 1 {
        return TestResult::Fail("header descriptor is not (len 16, NEXT, -> 1)");
    }
    if d.1 != 512 || d.2 != 3 || d.3 != 2 {
        return TestResult::Fail("data descriptor is not (len 512, NEXT|WRITE, -> 2)");
    }
    if s.1 != 1 || s.2 != 2 || s.3 != 0 {
        return TestResult::Fail("status descriptor is not (len 1, WRITE, end)");
    }
    if h.0 == d.0 || d.0 == s.0 || h.0 == s.0 {
        return TestResult::Fail("descriptor addresses alias");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_first_request_framing);

fn smoke_power_resume_reader_refusals() -> TestResult {
    // Bad magic: nothing at the window.
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.magic_ok = false;
    match dev.open() {
        Err(EarlyBlkError::BadMagic) => {}
        _ => return TestResult::Fail("bad magic was not refused as BadMagic"),
    }
    // Legacy transport version.
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.version = 1;
    match dev.open() {
        Err(EarlyBlkError::LegacyVersion(1)) => {}
        _ => return TestResult::Fail("legacy version was not refused"),
    }
    // A virtio device that is not a block device.
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.device_id = 3;
    match dev.open() {
        Err(EarlyBlkError::NotBlockDevice(3)) => {}
        _ => return TestResult::Fail("non-block device was not refused"),
    }
    // No VIRTIO_F_VERSION_1 on offer.
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.features_high = 0;
    match dev.open() {
        Err(EarlyBlkError::FeaturesRefused) => {}
        _ => return TestResult::Fail("missing VERSION_1 was not refused"),
    }
    // No queue at all, and a queue too small for a chain.
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.queue_num_max = 0;
    match dev.open() {
        Err(EarlyBlkError::QueueUnusable(0)) => {}
        _ => return TestResult::Fail("zero queue was not refused"),
    }
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.queue_num_max = 2;
    match dev.open() {
        Err(EarlyBlkError::QueueUnusable(2)) => {}
        _ => return TestResult::Fail("two-deep queue was not refused"),
    }
    // Zero-capacity device.
    let dev = FixtureDevice::new(Vec::new());
    match dev.open() {
        Err(EarlyBlkError::NoCapacity) => {}
        _ => return TestResult::Fail("zero capacity was not refused"),
    }
    // DMA window too small for queue + one bounce sector.
    let dev = FixtureDevice::new(pattern_image(8192));
    match PolledBlkReader::open(dev.transport(), DMA_BASE, 512) {
        Err(EarlyBlkError::MemoryTooSmall) => {}
        _ => return TestResult::Fail("undersized DMA window was not refused"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_refusals);

fn smoke_power_resume_reader_out_of_range_and_ioerr() -> TestResult {
    let disk = pattern_image(8 * 512);
    let dev = FixtureDevice::new(disk);
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    // Beyond capacity: the reader must refuse *before* notifying.
    let mut out = alloc::vec![0u8; 512];
    match reader.read_sectors(8, &mut out) {
        Err(EarlyBlkError::OutOfRange) => {}
        _ => return TestResult::Fail("out-of-range read was not refused"),
    }
    if dev
        .log
        .borrow()
        .iter()
        .any(|e| matches!(e, DevEvent::Notify(_)))
    {
        return TestResult::Fail("an out-of-range read still notified the device");
    }
    // Capacity claims more than the media holds: the device
    // itself errors, and the reader surfaces the status byte.
    let mut dev = FixtureDevice::new(pattern_image(8 * 512));
    dev.knobs.capacity_override = Some(12);
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    match reader.read_sectors(10, &mut out) {
        Err(EarlyBlkError::DeviceError(1)) => {}
        _ => return TestResult::Fail("device IOERR was not surfaced"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_out_of_range_and_ioerr);

fn smoke_power_resume_reader_wedged_times_out() -> TestResult {
    // The wedged device acknowledges the handshake but never
    // completes a request: the bounded poll must turn that into
    // a typed refusal, not a hung resume. (This smoke spins the
    // full poll bound by construction.)
    let mut dev = FixtureDevice::new(pattern_image(8192));
    dev.knobs.wedged = true;
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let mut out = alloc::vec![0u8; 512];
    match reader.read_sectors(0, &mut out) {
        Err(EarlyBlkError::Timeout) => {}
        _ => return TestResult::Fail("wedged device did not time out"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_reader_wedged_times_out);

// ── Resume environment smokes ────────────────────────────────────────

impl MemImageStore {
    fn set_byte(&self, offset: u64, value: u8) {
        self.data.lock()[offset as usize] = value;
    }
}

fn smoke_power_resume_env_round_trip_over_reader() -> TestResult {
    let (store, anchor, image) = sealed_token_image(5000);
    let dev = FixtureDevice::new(store.bytes());
    let reader = match dev.open() {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("reader open failed"),
    };
    anchor.grant_presence();
    let mut prompt = RecordingPrompt::default();
    let anchors: [&dyn KeyCustodyAnchor; 1] = [&anchor];
    let verified = match attempt_resume(&reader, &anchors, &mut prompt) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("resume over the polled reader refused a valid image"),
    };
    if verified.policy().level != PolicyLevel::Token {
        return TestResult::Fail("authenticated policy is not the sealed token policy");
    }
    if verified.hook_region_len() != 0 {
        return TestResult::Fail("hookless image reports a hook region");
    }
    match verified.read_all(&reader) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("verified image content does not round-trip"),
    }
    // Prompt discipline: an attempt line, then — only after
    // verification — the verified line, in that order.
    let attempt_at = prompt
        .lines
        .iter()
        .position(|l| l.contains("attempting resume"));
    let verified_at = prompt
        .lines
        .iter()
        .position(|l| l.contains("image verified"));
    match (attempt_at, verified_at) {
        (Some(a), Some(v)) if a < v => {}
        _ => return TestResult::Fail("prompt lines missing or out of order"),
    }
    if prompt.lines[attempt_at.unwrap()].contains("verified") {
        return TestResult::Fail("the attempt line states verification as a fact");
    }
    if !dev.faults.borrow().is_empty() {
        return TestResult::Fail("device model recorded faults during resume");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_round_trip_over_reader);

fn smoke_power_resume_env_off_without_anchors() -> TestResult {
    // An OFF image resumes with no anchors at all (P1's negative
    // control at the environment level): the path is chosen by
    // the recorded policy, and the header seal still verifies
    // under the published derivation.
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    let image = pattern_image(2048);
    let mut store = MemImageStore::new(STORE_LEN);
    let off = RecordedPolicy {
        level: PolicyLevel::Off,
        policy_epoch: 3,
    };
    if svc.seal_image(&mut store, off, &image).is_err() {
        return TestResult::Fail("OFF seal failed");
    }
    let mut prompt = RecordingPrompt::default();
    let verified = match attempt_resume(&store, &[], &mut prompt) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("OFF resume refused"),
    };
    if verified.policy() != off {
        return TestResult::Fail("authenticated policy is not the sealed OFF record");
    }
    match verified.read_all(&store) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("OFF image content does not round-trip"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_off_without_anchors);

fn smoke_power_resume_env_blank_store_is_no_image() -> TestResult {
    // A blank partition is the cold-boot case, and it must not
    // even reach the attempt announcement.
    let store = MemImageStore::new(STORE_LEN);
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&store, &[], &mut prompt) {
        Err(ResumeRefusal::NoImage) => {}
        _ => return TestResult::Fail("blank store was not refused as NoImage"),
    }
    if prompt.said_attempt() || prompt.said_verified() {
        return TestResult::Fail("a blank store produced attempt/verified lines");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_blank_store_is_no_image);

fn smoke_power_resume_env_factor_classes() -> TestResult {
    let (store, anchor, _image) = sealed_token_image(1024);
    // No anchors at all for a wrapped image: FactorUnavailable,
    // and crucially NOT a silent trip down the OFF path.
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&store, &[], &mut prompt) {
        Err(ResumeRefusal::FactorUnavailable) => {}
        _ => return TestResult::Fail("wrapped image without anchors was not FactorUnavailable"),
    }
    // An anchor of the wrong kind: never even attempted.
    let other = OtherKindAnchor {
        unwrap_calls: AtomicU64::new(0),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&store, &[&other], &mut prompt) {
        Err(ResumeRefusal::FactorUnavailable) => {}
        _ => return TestResult::Fail("wrong-kind anchor was not FactorUnavailable"),
    }
    if other.unwrap_calls.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("the environment attempted a non-matching anchor kind");
    }
    // Right kind, presence not granted: FactorRefused.
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&store, &[&anchor], &mut prompt) {
        Err(ResumeRefusal::FactorRefused) => {}
        _ => return TestResult::Fail("presence refusal was not FactorRefused"),
    }
    if prompt.said_verified() {
        return TestResult::Fail("a refused resume produced a verified line");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_factor_classes);

// ── The handoff gate + hook region (design §11 acceptance shape) ─────
//
// `run_handoff` models the boot handoff honestly: the verified
// image is delivered to restored state only after the hook gate —
// an image carrying a hook region must see its fixture hook blob
// unseal under the image's own hook key first. The spy records
// whether unseal ran and whether anything was delivered, so each
// tamper case pins *both* halves of the acceptance: refusal, and
// no restored state built from an unverified image.

const FIXTURE_HOOK_NAME: &str = "fixture-hook";
const HOOK_REGION_LEN: usize = 4096;
/// Hook region offset in the crafted image: header page + one
/// manifest page (the crafted image has exactly one chunk).
const HOOK_OFFSET_CRAFTED: u64 = 8192;
/// First chunk offset in the crafted image (region follows it).
const CHUNK_OFFSET_HOOKED: u64 = HOOK_OFFSET_CRAFTED + 4096;

fn fixture_hook_state() -> [u8; 48] {
    let mut s = [0u8; 48];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i * 11 % 253) as u8;
    }
    s
}

/// The fixture hook region: one blob in fixture framing —
/// nonce ‖ ciphertext ‖ tag under the per-hook key, AAD = the
/// hook name — followed by zeros to the region's full length.
fn fixture_hook_region(smk: &Secret32) -> Vec<u8> {
    let key = crate::suspend_service::derive_hook_key(smk, FIXTURE_HOOK_NAME);
    let mut region = alloc::vec![0u8; HOOK_REGION_LEN];
    let nonce = [0x03u8; 12];
    let mut ct = fixture_hook_state().to_vec();
    let tag = chacha20_poly1305_seal(&key, &nonce, FIXTURE_HOOK_NAME.as_bytes(), &mut ct);
    region[..12].copy_from_slice(&nonce);
    region[12..60].copy_from_slice(&ct);
    region[60..76].copy_from_slice(&tag);
    region
}

/// An image with a real enrolled slot and a 4096-byte hook
/// region, written through the image writer directly (the
/// service passes an empty region until P2's registry lands).
fn hooked_image() -> (MemImageStore, TestAnchor, Vec<u8>) {
    let anchor = TestAnchor::new("hooks");
    let sms = Secret32::mint([0x51; 32]);
    let smk = Secret32::mint([0x9d; 32]);
    let wrapped = anchor.wrap(&WrapCtx { sms_epoch: 1 }, &sms).expect("wrap");
    let record = SlotRecord {
        kind: AnchorKind::Test,
        epoch: 1,
        params: wrapped.params,
        blob: wrapped.blob,
    };
    let region = fixture_hook_region(&smk);
    let image = pattern_image(1000);
    let mut store = MemImageStore::new(STORE_LEN);
    let req = WriteRequest {
        policy: token_policy(),
        sms: &sms,
        sms_epoch: 1,
        slots: &[record],
        smk: &smk,
        image_id: [0x42; 16],
        smk_wrap_nonce: [0x05; 12],
        image: &image,
        hook_region: &region,
    };
    write_image(&mut store, &req).expect("write_image");
    (store, anchor, image)
}

#[derive(PartialEq, Debug)]
enum HandoffOutcome {
    Delivered,
    Refused(ResumeRefusal),
    HookRefused,
}

#[derive(Default)]
struct HandoffSpy {
    unseal_calls: Cell<u32>,
    delivered: Cell<bool>,
}

fn fixture_hook_unseals(store: &dyn ImageStore, verified: &VerifiedResume) -> bool {
    let mut head = alloc::vec![0u8; 76];
    if store.read_exact(HOOK_OFFSET_CRAFTED, &mut head).is_err() {
        return false;
    }
    let key = verified.hook_key(FIXTURE_HOOK_NAME);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&head[..12]);
    let mut ct = head[12..60].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&head[60..76]);
    chacha20_poly1305_open(&key, &nonce, FIXTURE_HOOK_NAME.as_bytes(), &mut ct, &tag)
        && ct == fixture_hook_state()
}

fn run_handoff(
    store: &dyn ImageStore,
    anchors: &[&dyn KeyCustodyAnchor],
    prompt: &mut RecordingPrompt,
    spy: &HandoffSpy,
) -> (HandoffOutcome, Option<VerifiedResume>) {
    let verified = match attempt_resume(store, anchors, prompt) {
        Ok(v) => v,
        Err(r) => return (HandoffOutcome::Refused(r), None),
    };
    if verified.hook_region_len() > 0 {
        spy.unseal_calls.set(spy.unseal_calls.get() + 1);
        if !fixture_hook_unseals(store, &verified) {
            return (HandoffOutcome::HookRefused, None);
        }
    }
    spy.delivered.set(true);
    (HandoffOutcome::Delivered, Some(verified))
}

fn smoke_power_resume_env_hook_region_round_trip() -> TestResult {
    let (store, anchor, image) = hooked_image();
    anchor.grant_presence();
    let mut prompt = RecordingPrompt::default();
    let spy = HandoffSpy::default();
    let (outcome, verified) = run_handoff(&store, &[&anchor], &mut prompt, &spy);
    if outcome != HandoffOutcome::Delivered {
        return TestResult::Fail("hooked image did not reach delivery");
    }
    if !spy.delivered.get() || spy.unseal_calls.get() != 1 {
        return TestResult::Fail("hook gate did not run exactly once before delivery");
    }
    let verified = match verified {
        Some(v) => v,
        None => return TestResult::Fail("delivery without a verified image"),
    };
    if verified.hook_region_len() != HOOK_REGION_LEN as u64 {
        return TestResult::Fail("authenticated hook-region length is wrong");
    }
    match verified.read_all(&store) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("hooked image content does not round-trip"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_hook_region_round_trip);

fn smoke_power_resume_env_tamper_matrix() -> TestResult {
    // Every case runs the §11 shape on the hooked image: the
    // refusal class is asserted, the hook's unseal is asserted
    // never to have run (verification failures) or to have run
    // and failed (hook blob), and delivery is asserted never
    // to have happened.
    let run_case = |tamper: &dyn Fn(&MemImageStore)| -> (HandoffOutcome, HandoffSpy) {
        let (store, anchor, _image) = hooked_image();
        tamper(&store);
        anchor.grant_presence();
        let mut prompt = RecordingPrompt::default();
        let spy = HandoffSpy::default();
        let (outcome, _) = run_handoff(&store, &[&anchor], &mut prompt, &spy);
        (outcome, spy)
    };

    // Header claim byte: the policy level, rewritten to OFF.
    // The claims now direct the OFF path, whose derivation
    // cannot open the seal the token policy made — wholesale
    // authentication failure, no oracle about which check.
    let (outcome, spy) = run_case(&|store| {
        store.set_byte(POLICY_BYTE_OFFSET, PolicyLevel::Off.code());
    });
    if outcome != HandoffOutcome::Refused(ResumeRefusal::AuthenticationFailed) {
        return TestResult::Fail("policy-byte tamper was not an authentication refusal");
    }
    if spy.unseal_calls.get() != 0 || spy.delivered.get() {
        return TestResult::Fail("policy-byte tamper reached unseal or delivery");
    }

    // Chunk ciphertext byte.
    let (outcome, spy) = run_case(&|store| {
        store.flip_byte(CHUNK_OFFSET_HOOKED + 100);
    });
    if outcome != HandoffOutcome::Refused(ResumeRefusal::AuthenticationFailed) {
        return TestResult::Fail("chunk tamper was not an authentication refusal");
    }
    if spy.unseal_calls.get() != 0 || spy.delivered.get() {
        return TestResult::Fail("chunk tamper reached unseal or delivery");
    }

    // Manifest tag byte.
    let (outcome, spy) = run_case(&|store| {
        store.flip_byte(MANIFEST_OFFSET + 10);
    });
    if outcome != HandoffOutcome::Refused(ResumeRefusal::AuthenticationFailed) {
        return TestResult::Fail("manifest tamper was not an authentication refusal");
    }
    if spy.unseal_calls.get() != 0 || spy.delivered.get() {
        return TestResult::Fail("manifest tamper reached unseal or delivery");
    }

    // Hook-region blob byte: the pipeline authenticates the
    // region's *extent*, the blob's AEAD authenticates its
    // content — so verification passes, the gate's unseal runs,
    // fails, and delivery is refused there. Any of the three
    // behaving otherwise breaks the design's layering.
    let (outcome, spy) = run_case(&|store| {
        store.flip_byte(HOOK_OFFSET_CRAFTED + 20);
    });
    if outcome != HandoffOutcome::HookRefused {
        return TestResult::Fail("hook-blob tamper was not refused at the hook gate");
    }
    if spy.unseal_calls.get() != 1 || spy.delivered.get() {
        return TestResult::Fail("hook-blob tamper did not stop at exactly one failed unseal");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_resume_env_tamper_matrix);
