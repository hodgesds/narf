//! Kernel smokes for the suspend state-hook registry and the
//! seal/unseal fan-outs (`power/suspend-service` hooks, issue #998,
//! design §5).
//!
//! The fixtures pin the contract's security properties, not the
//! happy path: a failed seal aborts the suspend with no image
//! committed; every blob is verified in staging before any hook's
//! `unseal` runs, so a tampered critical blob aborts the resume
//! with zero callbacks; a tampered non-critical blob reaches its
//! hook only as the fact `Invalid` (no bytes), and the fixture
//! hook refuses to install anything for it; a blob transplanted
//! from another image fails its AEAD (image-bound AAD/nonce); an
//! anchor blob does not open under a different epoch secret.
//!
//! The entropy seam, fixture anchor, and memory store are mirrors
//! of the P1 fixtures in `suspend_service_tests.rs` (each test
//! module carries its own on purpose). The fixture anchor's secret
//! is derived from a published label — custody theatre, labelled
//! `AnchorKind::Test` — with one honest behaviour: presence.
//!
//! The two consumer fixtures are the design's named first
//! customers, in fixture shape: a LUKS-style key-custody hook
//! (anchor mode, critical — §5.3) and a volunteer session driver
//! (image mode, non-critical).

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::rc::Rc;
use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    __reset_hooks_for_test, decode_hook_region, derive_hook_anchor_key, off_policy_sms,
    parse_claims, register_suspend_state_hook, registered_hooks, run_unseal_fanout,
    suspend_state_hook_count, AnchorError, AnchorKind, BlobOutcome, ImageStore, KeyCustodyAnchor,
    KeyEntropy, PolicyLevel, RecordedPolicy, SealCtx, SealError, Secret32, ServiceError,
    SuspendService, SuspendStateHook, UnsealCtx, UnsealFanoutError, UnsealOutcome, UnwrapCtx,
    WrapCtx, WrappedSlot, MAX_HOOK_STATE_LEN,
};

// ── Scripted entropy seam (mirror of the P1 fixture) ─────────────────

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

// ── Fixture anchor (mirror of the P1 fixture) ────────────────────────

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

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

// ── Fixture store (mirror of the P1 fixture, plus splice helpers) ────

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

    fn flip_byte(&self, offset: u64) {
        self.data.lock()[offset as usize] ^= 0xff;
    }

    fn bytes(&self, offset: u64, len: usize) -> Vec<u8> {
        let data = self.data.lock();
        data[offset as usize..offset as usize + len].to_vec()
    }

    fn write_bytes(&self, offset: u64, bytes: &[u8]) {
        let mut data = self.data.lock();
        data[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
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

// ── Shared helpers ───────────────────────────────────────────────────

const STORE_LEN: usize = 3 * 1024 * 1024;
/// Header page (4096) + one manifest page (4096) — the images here
/// have a single chunk, so the hook region starts at 8192 (pinned
/// against power spec §3.3's layout, as in the P1 fixtures).
const HOOK_REGION_OFFSET: u64 = 8192;

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

fn enrolled_service() -> (SuspendService<ScriptedEntropy>, TestAnchor) {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let anchor = TestAnchor::new("primary");
    svc.enroll(&anchor).expect("enroll");
    (svc, anchor)
}

/// Recover the epoch SMS through the fixture anchor, the way the
/// resume environment's factor unwrap does.
fn unwrap_sms(store: &MemImageStore, anchor: &TestAnchor) -> Secret32 {
    let claims = parse_claims(store).expect("claims");
    let record = &claims.slots[0];
    anchor
        .unwrap(
            &UnwrapCtx {
                sms_epoch: claims.sms_epoch,
            },
            &record.wrapped(),
        )
        .expect("sms unwrap")
}

/// Offset (store-absolute) of `name`'s sealed bytes, found by
/// decoding the region the writer actually wrote.
fn blob_store_offset(store: &MemImageStore, region_len: usize, name: &str) -> u64 {
    let region = store.bytes(HOOK_REGION_OFFSET, region_len);
    let blobs = decode_hook_region(&region).expect("region decodes");
    let mut at = HOOK_REGION_OFFSET + 4; // u32 count
    for blob in &blobs {
        let entry_sealed_at = at + 2 + blob.name.len() as u64 + 1 + 4;
        if blob.name == name {
            return entry_sealed_at;
        }
        at = entry_sealed_at + blob.sealed.len() as u64;
    }
    panic!("blob {name} not in region");
}

// ── Consumer fixtures (the design's named first customers) ───────────

/// Ordered event log shared by the hooks of one test.
#[derive(Debug)]
struct EventLog {
    events: IrqSafeSpinLock<Vec<String>>,
}

// Manual: `IrqSafeSpinLock` has no `Default` impl.
impl Default for EventLog {
    fn default() -> Self {
        Self {
            events: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

impl EventLog {
    fn push(&self, ev: &str) {
        self.events.lock().push(String::from(ev));
    }

    fn snapshot(&self) -> Vec<String> {
        self.events.lock().clone()
    }
}

/// LUKS-style key custody (design §5.3's canonical anchor-mode
/// customer): holds a 32-byte volume key; on suspend it re-seals
/// the key through the service in anchor mode. Critical: if its
/// blob fails verification it refuses — the installed key is left
/// untouched and the fan-out aborts before any delivery.
#[derive(Debug)]
struct LuksCustodyHook {
    log: Arc<EventLog>,
    key: IrqSafeSpinLock<[u8; 32]>,
    rekeys: AtomicU64,
    refusals: AtomicU64,
}

impl LuksCustodyHook {
    fn new(log: Arc<EventLog>, key: [u8; 32]) -> Self {
        Self {
            log,
            key: IrqSafeSpinLock::new(key),
            rekeys: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        }
    }
}

impl SuspendStateHook for LuksCustodyHook {
    fn name(&self) -> &str {
        "luks-key-custody"
    }

    fn critical(&self) -> bool {
        true
    }

    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError> {
        self.log.push("seal:luks-key-custody");
        let key = *self.key.lock();
        ctx.seal_anchor(&key)?;
        Ok(())
    }

    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError> {
        self.log.push("unseal:luks-key-custody");
        match ctx.take_anchor() {
            BlobOutcome::Restored(bytes) => {
                if bytes.len() != 32 {
                    return Err(SealError::BadState("volume key length"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                *self.key.lock() = key;
                Ok(())
            }
            BlobOutcome::Missing => {
                // First-class outcome (design §5.2 rule 2): the
                // epoch moved on — re-key rather than fail.
                *self.key.lock() = [0xEE; 32];
                self.rekeys.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            BlobOutcome::Invalid => {
                // Refuse: never install unverified key material.
                self.refusals.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }
}

/// A volunteer session driver (image mode, non-critical): seals a
/// session blob (sequence counter + nonce); on `Invalid` it records
/// the refusal and keeps its pre-suspend state untouched.
#[derive(Debug)]
struct SessionDriverHook {
    log: Arc<EventLog>,
    state: IrqSafeSpinLock<Vec<u8>>,
    refusals: AtomicU64,
    unseal_calls: AtomicU64,
}

impl SessionDriverHook {
    fn new(log: Arc<EventLog>, state: Vec<u8>) -> Self {
        Self {
            log,
            state: IrqSafeSpinLock::new(state),
            refusals: AtomicU64::new(0),
            unseal_calls: AtomicU64::new(0),
        }
    }
}

impl SuspendStateHook for SessionDriverHook {
    fn name(&self) -> &str {
        "fixture-session-driver"
    }

    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError> {
        self.log.push("seal:fixture-session-driver");
        let state = self.state.lock().clone();
        ctx.seal_image(&state)?;
        Ok(())
    }

    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError> {
        self.log.push("unseal:fixture-session-driver");
        self.unseal_calls.fetch_add(1, Ordering::SeqCst);
        match ctx.take_image() {
            BlobOutcome::Restored(bytes) => {
                *self.state.lock() = bytes.to_vec();
                Ok(())
            }
            BlobOutcome::Missing => Ok(()),
            BlobOutcome::Invalid => {
                self.refusals.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }
}

/// Configurable hook for the failure-mode fixtures.
#[derive(Debug)]
struct FixtureHook {
    name: &'static str,
    critical: bool,
    behaviour: Behaviour,
    log: Arc<EventLog>,
    outcomes: IrqSafeSpinLock<Vec<String>>,
}

#[derive(Debug)]
enum Behaviour {
    Image(Vec<u8>),
    Nothing,
    Fail,
    Oversize,
}

impl SuspendStateHook for FixtureHook {
    fn name(&self) -> &str {
        self.name
    }

    fn critical(&self) -> bool {
        self.critical
    }

    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError> {
        self.log.push(&alloc::format!("seal:{}", self.name));
        match &self.behaviour {
            Behaviour::Image(bytes) => {
                ctx.seal_image(bytes)?;
                Ok(())
            }
            Behaviour::Nothing => Ok(()),
            Behaviour::Fail => Err(SealError::Refused("fixture seal failure")),
            Behaviour::Oversize => {
                let big = alloc::vec![0xABu8; MAX_HOOK_STATE_LEN + 1];
                ctx.seal_image(&big)?;
                Ok(())
            }
        }
    }

    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError> {
        self.log.push(&alloc::format!("unseal:{}", self.name));
        let describe = |o: BlobOutcome| match o {
            BlobOutcome::Restored(b) => alloc::format!("restored:{}", b.len()),
            BlobOutcome::Missing => String::from("missing"),
            BlobOutcome::Invalid => String::from("invalid"),
        };
        let mut out = self.outcomes.lock();
        out.push(alloc::format!("image:{}", describe(ctx.take_image())));
        out.push(alloc::format!("anchor:{}", describe(ctx.take_anchor())));
        Ok(())
    }
}

fn fixture_hook(
    name: &'static str,
    critical: bool,
    behaviour: Behaviour,
    log: Arc<EventLog>,
) -> Arc<FixtureHook> {
    Arc::new(FixtureHook {
        name,
        critical,
        behaviour,
        log,
        outcomes: IrqSafeSpinLock::new(Vec::new()),
    })
}

// ── (a) Registry: idempotent replace by name ─────────────────────────

fn smoke_hook_registry_replaces_by_name() -> TestResult {
    __reset_hooks_for_test();
    let log = Arc::new(EventLog::default());
    let first = fixture_hook("dup", false, Behaviour::Nothing, log.clone());
    let second: Arc<dyn SuspendStateHook> =
        fixture_hook("dup", false, Behaviour::Nothing, log.clone());
    register_suspend_state_hook(first.clone());
    register_suspend_state_hook(second.clone());
    if suspend_state_hook_count() != 1 {
        return TestResult::Fail("re-registration by name must replace, not append");
    }
    let snapshot = registered_hooks();
    if !Arc::ptr_eq(&snapshot[0], &second) {
        return TestResult::Fail("registry kept the first hook, not the replacement");
    }
    __reset_hooks_for_test();
    if suspend_state_hook_count() != 0 {
        return TestResult::Fail("registry reset failed");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_registry_replaces_by_name);

// ── (b) Round trip: seal → image → verify → unseal ───────────────────

fn smoke_hook_round_trip_through_image() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let luks = Arc::new(LuksCustodyHook::new(log.clone(), [0x42; 32]));
    let driver = Arc::new(SessionDriverHook::new(
        log.clone(),
        alloc::vec![0x10, 0x20, 0x30, 0x40],
    ));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![luks.clone(), driver.clone()];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    let (_id, report) = match svc.seal_image_with_hooks(&mut store, token_policy(), &image, &hooks)
    {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("seal_image_with_hooks failed"),
    };
    // Seal fan-out order: reverse registration.
    let events = log.snapshot();
    if events[0] != "seal:fixture-session-driver" || events[1] != "seal:luks-key-custody" {
        return TestResult::Fail("seal fan-out did not run in reverse registration order");
    }
    if report.sealed.len() != 2
        || report.sealed[0].image_len != Some(4)
        || report.sealed[1].anchor_len != Some(32)
    {
        return TestResult::Fail("seal report does not describe both blobs");
    }
    // Mutate the live state so restoration is observable.
    *driver.state.lock() = alloc::vec![0xFF];
    *luks.key.lock() = [0x00; 32];

    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open_with_anchor failed"),
    };
    if opened.hook_region_len() == 0 {
        return TestResult::Fail("hook region length is zero for a hooked image");
    }
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify_all failed"),
    };
    // The bulk image still reads back exactly.
    let plain = match trusted.read_all(&store) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("read_all failed"),
    };
    if plain != image {
        return TestResult::Fail("bulk image did not round-trip alongside the hook region");
    }
    let sms = unwrap_sms(&store, &anchor);
    let report = match run_unseal_fanout(&trusted, &store, &sms, &hooks, &|_| true) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unseal fan-out failed"),
    };
    // Unseal fan-out order: forward registration.
    let events = log.snapshot();
    let unseal_events: Vec<&String> = events.iter().filter(|e| e.starts_with("unseal:")).collect();
    if unseal_events.len() != 2
        || unseal_events[0] != "unseal:luks-key-custody"
        || unseal_events[1] != "unseal:fixture-session-driver"
    {
        return TestResult::Fail("unseal fan-out did not run in forward registration order");
    }
    if *driver.state.lock() != alloc::vec![0x10, 0x20, 0x30, 0x40] {
        return TestResult::Fail("driver state was not restored byte-for-byte");
    }
    if *luks.key.lock() != [0x42; 32] {
        return TestResult::Fail("LUKS key was not restored byte-for-byte");
    }
    if report.entries.len() != 2
        || report.entries[0].outcome != UnsealOutcome::Delivered
        || report.entries[1].outcome != UnsealOutcome::Delivered
        || !report.orphaned_blobs.is_empty()
    {
        return TestResult::Fail("unseal report does not show two clean deliveries");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_round_trip_through_image);

// ── (c) Tampered non-critical blob: refused, others proceed ──────────

fn smoke_hook_tampered_blob_refused_others_proceed() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let luks = Arc::new(LuksCustodyHook::new(log.clone(), [0x42; 32]));
    let driver = Arc::new(SessionDriverHook::new(log.clone(), alloc::vec![1, 2, 3]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![luks.clone(), driver.clone()];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    let (_id, _r) = match svc.seal_image_with_hooks(&mut store, token_policy(), &image, &hooks) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("seal failed"),
    };
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let region_len = opened.hook_region_len() as usize;
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify failed"),
    };
    // Flip one ciphertext byte of the *driver's* blob.
    let at = blob_store_offset(&store, region_len, "fixture-session-driver");
    store.flip_byte(at);
    // Sentinel: the driver must not overwrite this with bad state.
    *driver.state.lock() = alloc::vec![0x5E];
    let sms = unwrap_sms(&store, &anchor);
    let report = match run_unseal_fanout(&trusted, &store, &sms, &hooks, &|_| true) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("non-critical tamper must not abort the fan-out"),
    };
    if driver.refusals.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("driver hook did not record the Invalid refusal");
    }
    if *driver.state.lock() != alloc::vec![0x5E] {
        return TestResult::Fail("driver installed state from a tampered blob");
    }
    if *luks.key.lock() != [0x42; 32] {
        return TestResult::Fail("untampered critical hook did not restore");
    }
    if report.entries[1].outcome != UnsealOutcome::Delivered {
        return TestResult::Fail("driver entry should be Delivered (it handled the refusal)");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_tampered_blob_refused_others_proceed);

// ── (d) Tampered critical blob: abort before ANY delivery ───────────

fn smoke_hook_tampered_critical_blob_aborts_before_delivery() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let luks = Arc::new(LuksCustodyHook::new(log.clone(), [0x42; 32]));
    let driver = Arc::new(SessionDriverHook::new(log.clone(), alloc::vec![1, 2, 3]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![luks.clone(), driver.clone()];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store, token_policy(), &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("seal failed");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let region_len = opened.hook_region_len() as usize;
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify failed"),
    };
    let at = blob_store_offset(&store, region_len, "luks-key-custody");
    store.flip_byte(at);
    let sms = unwrap_sms(&store, &anchor);
    match run_unseal_fanout(&trusted, &store, &sms, &hooks, &|_| true) {
        Err(UnsealFanoutError::CriticalBlobInvalid { hook, .. }) if hook == "luks-key-custody" => {}
        _ => return TestResult::Fail("tampered critical blob did not abort the fan-out"),
    }
    // Verify-before-deliver: not one unseal callback ran.
    let events = log.snapshot();
    if events.iter().any(|e| e.starts_with("unseal:")) {
        return TestResult::Fail("an unseal callback ran despite the critical staging failure");
    }
    if driver.unseal_calls.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("driver unseal ran despite the abort");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power",
    smoke_hook_tampered_critical_blob_aborts_before_delivery
);

// ── (e) Seal failure aborts the suspend; nothing is committed ────────

fn smoke_hook_seal_failure_aborts_suspend() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    let log = Arc::new(EventLog::default());
    let good = fixture_hook(
        "good",
        false,
        Behaviour::Image(alloc::vec![7, 7, 7]),
        log.clone(),
    );
    let bad = fixture_hook("bad", false, Behaviour::Fail, log.clone());
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![good, bad];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    match svc.seal_image_with_hooks(&mut store, token_policy(), &image, &hooks) {
        Err(ServiceError::HookSealAborted) => {}
        _ => return TestResult::Fail("a failing seal did not abort with HookSealAborted"),
    }
    // No image was committed: the header was never written, so the
    // store does not even parse as an image.
    if parse_claims(&store).is_ok() {
        return TestResult::Fail("an aborted seal left a parseable image behind");
    }
    let _ = anchor;
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_seal_failure_aborts_suspend);

// ── (f) Oversize state is refused by the context ─────────────────────

fn smoke_hook_oversize_state_refused() -> TestResult {
    let (mut svc, _anchor) = enrolled_service();
    let log = Arc::new(EventLog::default());
    let big = fixture_hook("big", false, Behaviour::Oversize, log.clone());
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![big];
    let image = pattern_image(64);
    let mut store = MemImageStore::new(STORE_LEN);
    // The context refuses the oversize seal (StateTooLarge), the
    // hook propagates it, and the suspend aborts.
    match svc.seal_image_with_hooks(&mut store, token_policy(), &image, &hooks) {
        Err(ServiceError::HookSealAborted) => {}
        _ => return TestResult::Fail("oversize hook state did not abort the seal"),
    }
    if parse_claims(&store).is_ok() {
        return TestResult::Fail("oversize abort left an image behind");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_oversize_state_refused);

// ── (g) Hook absent at seal time: Missing is a first-class outcome ──

fn smoke_hook_missing_blob_is_first_class() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let present = fixture_hook(
        "present",
        false,
        Behaviour::Image(alloc::vec![1, 2]),
        log.clone(),
    );
    let late = fixture_hook("late", false, Behaviour::Nothing, log.clone());
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    let seal_hooks: Vec<Arc<dyn SuspendStateHook>> = vec![present.clone()];
    if svc
        .seal_image_with_hooks(&mut store, token_policy(), &image, &seal_hooks)
        .is_err()
    {
        return TestResult::Fail("seal failed");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify failed"),
    };
    let sms = unwrap_sms(&store, &anchor);
    let unseal_hooks: Vec<Arc<dyn SuspendStateHook>> = vec![present.clone(), late.clone()];
    let report = match run_unseal_fanout(&trusted, &store, &sms, &unseal_hooks, &|_| true) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unseal fan-out failed"),
    };
    let late_outcomes = late.outcomes.lock();
    if late_outcomes.len() != 2
        || late_outcomes[0] != "image:missing"
        || late_outcomes[1] != "anchor:missing"
    {
        return TestResult::Fail("late hook did not receive Missing for both modes");
    }
    let present_outcomes = present.outcomes.lock();
    if present_outcomes[0] != "image:restored:2" {
        return TestResult::Fail("present hook did not receive its restored blob");
    }
    if report.entries.len() != 2 {
        return TestResult::Fail("report should carry both hooks");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_missing_blob_is_first_class);

// ── (h) Device did not resume: hook is skipped, resume continues ────

fn smoke_hook_device_down_skips_unseal() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let luks = Arc::new(LuksCustodyHook::new(log.clone(), [0x42; 32]));
    let driver = Arc::new(SessionDriverHook::new(log.clone(), alloc::vec![9, 9]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![luks.clone(), driver.clone()];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store, token_policy(), &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("seal failed");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify failed"),
    };
    let sms = unwrap_sms(&store, &anchor);
    let report = match run_unseal_fanout(&trusted, &store, &sms, &hooks, &|name| {
        name != "fixture-session-driver"
    }) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unseal fan-out failed"),
    };
    if driver.unseal_calls.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("hook of a down device was unsealed");
    }
    if report.entries[1].outcome != UnsealOutcome::SkippedDeviceDown {
        return TestResult::Fail("report does not mark the skipped hook");
    }
    if *luks.key.lock() != [0x42; 32] {
        return TestResult::Fail("remaining hook did not restore");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_device_down_skips_unseal);

// ── (i) Transplanted blob (other image) fails verification ──────────

fn smoke_hook_transplanted_blob_refused() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let driver = Arc::new(SessionDriverHook::new(log.clone(), alloc::vec![4, 5, 6]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![driver.clone()];
    let image = pattern_image(1024);

    // Image A.
    let mut store_a = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store_a, token_policy(), &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("seal A failed");
    }
    // Image B (fresh SMK + image id), same hook, same state bytes.
    let mut store_b = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store_b, token_policy(), &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("seal B failed");
    }
    // Splice A's driver blob over B's (identical layout/lengths).
    let opened_b = match svc.open_with_anchor(&store_b, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open B failed"),
    };
    let region_len = opened_b.hook_region_len() as usize;
    let region_a = store_a.bytes(HOOK_REGION_OFFSET, region_len);
    store_b.write_bytes(HOOK_REGION_OFFSET, &region_a);
    let trusted_b = match opened_b.verify_all(&store_b) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify B failed (bulk image must be unaffected)"),
    };
    *driver.state.lock() = alloc::vec![0x5E];
    let sms = unwrap_sms(&store_b, &anchor);
    let report = match run_unseal_fanout(&trusted_b, &store_b, &sms, &hooks, &|_| true) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("transplant must degrade, not abort (non-critical)"),
    };
    if driver.refusals.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("transplanted blob was not refused as Invalid");
    }
    if *driver.state.lock() != alloc::vec![0x5E] {
        return TestResult::Fail("transplanted state was installed");
    }
    if report.entries[0].outcome != UnsealOutcome::Delivered {
        return TestResult::Fail("report should show the hook handled the refusal");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_transplanted_blob_refused);

// ── (j) Anchor blobs are bound to the epoch secret ───────────────────

fn smoke_hook_anchor_blob_binds_epoch_secret() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let log = Arc::new(EventLog::default());
    let luks = Arc::new(LuksCustodyHook::new(log.clone(), [0x77; 32]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![luks.clone()];
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store, token_policy(), &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("seal failed");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed"),
    };
    let region_len = opened.hook_region_len() as usize;
    let region = store.bytes(HOOK_REGION_OFFSET, region_len);
    let blobs = match decode_hook_region(&region) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("region did not decode"),
    };
    if blobs.len() != 1 || blobs[0].name != "luks-key-custody" {
        return TestResult::Fail("expected exactly the LUKS anchor blob");
    }
    let blob = &blobs[0];
    let (ct, tag) = blob.sealed.split_at(blob.sealed.len() - 16);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);
    let image_id = opened.claims().image_id;
    // AAD mirrors the writer's: image_id ‖ mode(1) ‖ name.
    let mut aad = Vec::new();
    aad.extend_from_slice(&image_id);
    aad.push(1u8);
    aad.extend_from_slice(b"luks-key-custody");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&image_id[..12]);
    // The right epoch secret opens it.
    let sms = unwrap_sms(&store, &anchor);
    let key = derive_hook_anchor_key(&sms, "luks-key-custody");
    let mut plain = ct.to_vec();
    if !chacha20_poly1305_open(&key, &nonce, &aad, &mut plain, &tag_arr) {
        return TestResult::Fail("anchor blob did not open under its epoch secret");
    }
    if plain != alloc::vec![0x77u8; 32] {
        return TestResult::Fail("anchor blob plaintext mismatch");
    }
    // A different secret (a rotated epoch's SMS) does not.
    let other = Secret32::mint([0x09; 32]);
    let wrong_key = derive_hook_anchor_key(&other, "luks-key-custody");
    let mut plain2 = ct.to_vec();
    if chacha20_poly1305_open(&wrong_key, &nonce, &aad, &mut plain2, &tag_arr) {
        return TestResult::Fail("anchor blob opened under a foreign epoch secret");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_anchor_blob_binds_epoch_secret);

// ── (k) OFF policy: hooks run through the same machinery ────────────

fn smoke_hook_off_policy_round_trip() -> TestResult {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    let log = Arc::new(EventLog::default());
    let driver = Arc::new(SessionDriverHook::new(log.clone(), alloc::vec![8, 8, 8]));
    let hooks: Vec<Arc<dyn SuspendStateHook>> = vec![driver.clone()];
    let off = RecordedPolicy {
        level: PolicyLevel::Off,
        policy_epoch: 3,
    };
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image_with_hooks(&mut store, off, &image, &hooks)
        .is_err()
    {
        return TestResult::Fail("OFF hooked seal failed");
    }
    *driver.state.lock() = alloc::vec![0xFF];
    let opened = match svc.open_off(&store) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open_off failed"),
    };
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify failed"),
    };
    let report = match run_unseal_fanout(&trusted, &store, &off_policy_sms(), &hooks, &|_| true) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("OFF unseal fan-out failed"),
    };
    if *driver.state.lock() != alloc::vec![8, 8, 8] {
        return TestResult::Fail("OFF-policy hook state did not round-trip");
    }
    if report.entries[0].outcome != UnsealOutcome::Delivered {
        return TestResult::Fail("OFF report should show delivery");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_hook_off_policy_round_trip);

// ── (k) Fixture anchor round-trip ────────────────────────────────────
//
// The fixture anchor honours the custody trait's params contract with
// a non-empty id: params are counter ‖ anchor id, and unwrap recovers
// exactly the wrapped secret. (Regression: unwrap once copied the
// whole composite params buffer into the 8-byte counter array, which
// panicked for every non-empty id — CI run 40529560496, kernel-test
// aarch64 job 122352402605, in smoke_hook_transplanted_blob_refused.
// The P1 mirror of this fixture was fixed the same way in PR #1133.)

fn smoke_hook_test_anchor_round_trip() -> TestResult {
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
kernel_test_in!("power", smoke_hook_test_anchor_round_trip);
