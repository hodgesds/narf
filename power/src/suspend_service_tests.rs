//! Kernel smokes for the suspend service (`power/suspend-service`,
//! issue #997).
//!
//! The fixtures pin the security properties of the design, not the
//! happy path: key generation refuses without seed-grade entropy
//! (scripted seam, both states); AEAD tampering — ciphertext byte,
//! policy-metadata byte, slot blob, manifest tag, wrapped SMK,
//! truncation, wrong-epoch key — fails wholesale; epoch rotation
//! invalidates the previous epoch's wrappings; and a full
//! enroll → wrap → seal → verify → unwrap round-trip runs against
//! the fixture anchor.
//!
//! The fixture anchor and store live here, in the test module, on
//! purpose: the test anchor's secret is derived from a *published*
//! label (anyone can recompute it — it is custody theatre, labelled
//! `AnchorKind::Test` in every record), and its one honest behaviour
//! is presence: `unwrap` refuses until the fixture grants it.

extern crate alloc;

use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_block::{BlockDeviceSync, BlockIoError};
use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    parse_claims, AnchorError, AnchorKind, BlockStore, ImageStore, KeyCustodyAnchor, KeyEntropy,
    PolicyLevel, RecordedPolicy, Secret32, ServiceError, SlotArea, SuspendService, UnwrapCtx,
    WrapCtx, WrappedSlot,
};

// ── Scripted entropy seam ────────────────────────────────────────────

/// Scripts the seed-grade surface's two states. Fills are
/// deterministic but distinct per call (an LCG stream seeded by the
/// call counter), so successive draws (SMS, SMK, image id, nonce)
/// genuinely differ and the constructions are really exercised.
/// State sits behind `Rc` so a test keeps a control handle after
/// moving the seam into the service.
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

    fn set_present(&self, present: bool) {
        self.present.set(present);
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

// ── Fixture anchor ───────────────────────────────────────────────────

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// Fixture custody anchor: published secret, honest presence gate.
/// See the module docs before trusting it with anything (don't).
/// Atomics, not `Cell`: `KeyCustodyAnchor` is `Send + Sync`
/// (`anchor.rs:104`), and a `Cell` field makes the whole fixture
/// anchor `!Sync` (CI E0277 at the impl site and at both `unwrap`
/// call sites). The atomics keep the same single-threaded
/// observable behaviour — presence starts refused, each wrap takes
/// a fresh counter — while satisfying the production trait bound.
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
            secret: hkdf32(b"narf-suspend/test-anchor-published-secret", id.as_bytes()),
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
        // Params double as the anchor's public "credential id":
        // counter ‖ anchor id, so two enrolled anchors never share
        // a (kind, params) identity.
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
        counter_b.copy_from_slice(&slot.params);
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

// ── Fixture store ────────────────────────────────────────────────────

/// In-memory image store with tamper helpers for the negatives.
///
/// Interior mutability is required, not a style choice:
/// `ImageStore::write_all` takes `&self` (the production
/// `BlockStore` writes through an `Arc<dyn BlockDeviceSync>` the
/// same way), so a plain `Vec` field cannot be written through the
/// trait (CI E0596 at the `write_all` body). The bytes sit behind
/// the same `IrqSafeSpinLock` the `RamBlockDevice` fixture below
/// uses for exactly this `&self`-write contract.
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

    fn flip_byte(&mut self, offset: u64) {
        self.data.lock()[offset as usize] ^= 0xff;
    }

    fn set_byte(&mut self, offset: u64, value: u8) {
        self.data.lock()[offset as usize] = value;
    }

    fn truncate(&mut self, len: usize) {
        self.data.lock().truncate(len);
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

/// RAM-backed `BlockDeviceSync` with a configurable LBA size, so
/// the service's block-layer store (`BlockStore`) is exercised
/// through the real trait surface — whole-LBA transfers only —
/// instead of the offset-general `MemImageStore` above. The two
/// stores have different contracts, and a fixture that only models
/// the permissive one cannot see alignment failures in the other.
#[derive(Debug)]
struct RamBlockDevice {
    lba_size: u32,
    data: IrqSafeSpinLock<Vec<u8>>,
}

impl RamBlockDevice {
    fn new(lba_size: u32, bytes: usize) -> Self {
        Self {
            lba_size,
            data: IrqSafeSpinLock::new(alloc::vec![0u8; bytes]),
        }
    }
}

impl BlockDeviceSync for RamBlockDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }

    fn capacity(&self) -> u64 {
        self.data.lock().len() as u64 / u64::from(self.lba_size)
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let start = (lba * u64::from(self.lba_size)) as usize;
        let len = n_blocks as usize * self.lba_size as usize;
        if out.len() < len {
            return Err(BlockIoError::BufferTooSmall);
        }
        let data = self.data.lock();
        let end = start.checked_add(len).ok_or(BlockIoError::OutOfRange)?;
        if end > data.len() {
            return Err(BlockIoError::OutOfRange);
        }
        out[..len].copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        let start = (lba * u64::from(self.lba_size)) as usize;
        let len = n_blocks as usize * self.lba_size as usize;
        if data.len() < len {
            return Err(BlockIoError::BufferTooSmall);
        }
        let mut store = self.data.lock();
        let end = start.checked_add(len).ok_or(BlockIoError::OutOfRange)?;
        if end > store.len() {
            return Err(BlockIoError::OutOfRange);
        }
        store[start..end].copy_from_slice(&data[..len]);
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

// Format offsets pinned against power spec §3.3 (header page, then
// manifest pages, then chunks; preamble field order as written).
const POLICY_BYTE_OFFSET: u64 = 36; // magic 8 + version 4 + image_id 16 + sms_epoch 8
const MANIFEST_OFFSET: u64 = 4096;
const FIRST_CHUNK_OFFSET: u64 = 8192; // header page + one manifest page (<= 256 chunks)
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

/// A service with epoch 1 established and one test anchor enrolled.
fn enrolled_service() -> (SuspendService<ScriptedEntropy>, TestAnchor) {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let anchor = TestAnchor::new("primary");
    svc.enroll(&anchor).expect("enroll");
    (svc, anchor)
}

// ── (a) Keygen refusal without seed-grade entropy ────────────────────

fn smoke_power_suspend_keygen_refuses_without_entropy() -> TestResult {
    let entropy = ScriptedEntropy::new(false);
    let mut svc = SuspendService::new(entropy.clone());
    if svc.entropy_available() {
        return TestResult::Fail("scripted entropy should start absent");
    }
    match svc.create_epoch() {
        Err(ServiceError::EntropyUnavailable) => {}
        _ => return TestResult::Fail("create_epoch did not refuse without seed-grade entropy"),
    }
    if svc.current_epoch().is_some() {
        return TestResult::Fail("a refused keygen left an epoch behind");
    }
    // Flip the seam: the same call now succeeds.
    entropy.set_present(true);
    match svc.create_epoch() {
        Ok(1) => {}
        _ => return TestResult::Fail("create_epoch failed with seed-grade entropy present"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_keygen_refuses_without_entropy);

fn smoke_power_suspend_seal_refuses_without_entropy() -> TestResult {
    let entropy = ScriptedEntropy::new(true);
    let mut svc = SuspendService::new(entropy.clone());
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    let anchor = TestAnchor::new("primary");
    if svc.enroll(&anchor).is_err() {
        return TestResult::Fail("enroll failed");
    }
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    // Enrollment is done; sealing still draws the per-image key from
    // the seam, so killing entropy must refuse the seal too.
    entropy.set_present(false);
    match svc.seal_image(&mut store, token_policy(), &image) {
        Err(ServiceError::EntropyUnavailable) => {}
        _ => return TestResult::Fail("seal_image did not refuse without seed-grade entropy"),
    }
    // And an OFF-policy seal draws the same way (uniform machinery).
    let off = RecordedPolicy {
        level: PolicyLevel::Off,
        policy_epoch: 7,
    };
    match svc.seal_image(&mut store, off, &image) {
        Err(ServiceError::EntropyUnavailable) => {}
        _ => return TestResult::Fail("OFF seal did not refuse without seed-grade entropy"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_seal_refuses_without_entropy);

fn smoke_power_suspend_seal_requires_epoch_and_slots() -> TestResult {
    let image = pattern_image(64);
    let mut store = MemImageStore::new(STORE_LEN);
    // No epoch at all.
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    match svc.seal_image(&mut store, token_policy(), &image) {
        Err(ServiceError::NoEpoch) => {}
        _ => return TestResult::Fail("seal without an epoch did not fail closed (NoEpoch)"),
    }
    // Epoch but no enrolled slot.
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    match svc.seal_image(&mut store, token_policy(), &image) {
        Err(ServiceError::NoSlotsEnrolled) => {}
        _ => return TestResult::Fail("seal without slots did not fail closed (NoSlotsEnrolled)"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_seal_requires_epoch_and_slots);

// ── (d) Full round-trip ──────────────────────────────────────────────

fn smoke_power_suspend_round_trip() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    // 2 full chunks + a partial: exercises multi-chunk manifest and
    // the short final chunk.
    let image = pattern_image(2 * 1024 * 1024 + 12_345);
    let mut store = MemImageStore::new(STORE_LEN);
    let image_id = match svc.seal_image(&mut store, token_policy(), &image) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("seal_image failed"),
    };
    if image_id == [0u8; 16] {
        return TestResult::Fail("image id was not drawn from the entropy seam");
    }
    // Presence not granted: the anchor must refuse, and the service
    // must surface that refusal rather than unwrap anyway.
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::Anchor(AnchorError::Refused)) => {}
        _ => return TestResult::Fail("unwrap without presence was not refused"),
    }
    anchor.grant_presence();
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open_with_anchor failed with presence granted"),
    };
    // The authenticated claims: policy record included.
    if opened.claims().policy != token_policy() {
        return TestResult::Fail("authenticated policy record does not match the sealed policy");
    }
    if opened.claims().sms_epoch != 1 {
        return TestResult::Fail("authenticated SMS epoch is not 1");
    }
    if opened.image_len() != image.len() as u64 || opened.chunk_count() != 3 {
        return TestResult::Fail("authenticated image shape is wrong");
    }
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify_all failed on an untampered image"),
    };
    // Per-chunk delivery, then whole-image reassembly.
    let mut reassembled = Vec::new();
    for index in 0..trusted.chunk_count() {
        if trusted.read_chunk(&store, index, &mut reassembled).is_err() {
            return TestResult::Fail("read_chunk failed on a verified image");
        }
    }
    if reassembled != image {
        return TestResult::Fail("round-tripped image differs from the sealed image");
    }
    match trusted.read_all(&store) {
        Ok(all) if all == image => {}
        _ => return TestResult::Fail("read_all differs from the sealed image"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_round_trip);

fn smoke_power_suspend_off_round_trip() -> TestResult {
    // OFF needs no epoch and no slots — but the machinery, the
    // entropy draw, and the authenticated record are the same.
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    let image = pattern_image(5000);
    let mut store = MemImageStore::new(STORE_LEN);
    let off = RecordedPolicy {
        level: PolicyLevel::Off,
        policy_epoch: 3,
    };
    if svc.seal_image(&mut store, off, &image).is_err() {
        return TestResult::Fail("OFF seal failed");
    }
    // The anchor path must refuse an OFF image (and vice versa the
    // OFF path refuses wrapped images — checked below).
    let anchor = TestAnchor::new("primary");
    anchor.grant_presence();
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::PolicyMismatch) => {}
        _ => return TestResult::Fail("anchor path did not refuse an OFF image"),
    }
    let opened = match svc.open_off(&store) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open_off failed on an OFF image"),
    };
    if opened.claims().policy.level != PolicyLevel::Off {
        return TestResult::Fail("OFF image did not record OFF (honest labelling)");
    }
    if opened.claims().sms_epoch != 0 {
        return TestResult::Fail("OFF image recorded a nonzero SMS epoch");
    }
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("OFF verify_all failed"),
    };
    match trusted.read_all(&store) {
        Ok(all) if all == image => {}
        _ => return TestResult::Fail("OFF round-trip content differs"),
    }
    // Vice versa: open_off on a wrapped image refuses.
    let (mut svc2, anchor2) = enrolled_service();
    anchor2.grant_presence();
    let mut store2 = MemImageStore::new(STORE_LEN);
    if svc2
        .seal_image(&mut store2, token_policy(), &image)
        .is_err()
    {
        return TestResult::Fail("wrapped seal failed");
    }
    match svc2.open_off(&store2) {
        Err(ServiceError::PolicyMismatch) => {}
        _ => return TestResult::Fail("OFF path did not refuse a wrapped image"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_off_round_trip);

// ── (b) AEAD tamper negatives ────────────────────────────────────────

fn smoke_power_suspend_tamper_chunk_ciphertext() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(5000);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    store.flip_byte(FIRST_CHUNK_OFFSET + 100);
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("header should still open (tamper is in a chunk)"),
    };
    match opened.verify_all(&store) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("flipped chunk ciphertext byte was not caught"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_tamper_chunk_ciphertext);

fn smoke_power_suspend_tamper_policy_byte() -> TestResult {
    let image = pattern_image(2048);
    // Variant 1: downgrade attempt, Token (2) -> Off (0). The open
    // path must fail closed (the service will not even attempt the
    // OFF derivation against a record it can no longer trust).
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed (variant 1)");
    }
    store.flip_byte(POLICY_BYTE_OFFSET); // 0x02 ^ 0xff = 0xfd: unknown code
    match svc.open_with_anchor(&store, &anchor) {
        Err(_) => {}
        Ok(_) => return TestResult::Fail("bit-flipped policy byte opened (variant 1)"),
    }
    // Variant 2: a *targeted* rewrite to Off (0x00) — the downgrade
    // an attacker actually wants. Caught at the claim check.
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed (variant 2)");
    }
    store.set_byte(POLICY_BYTE_OFFSET, 0);
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::PolicyMismatch) => {}
        _ => return TestResult::Fail("policy rewritten to OFF was not refused"),
    }
    // Variant 3: rewrite Token (2) -> TokenTpm (3). Still a wrapped
    // policy, so the flow proceeds — and dies at the AEAD layer,
    // because the policy byte is inside both the SMK-wrap AAD and
    // the header seal's AAD. Wholesale failure, as designed.
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed (variant 3)");
    }
    store.set_byte(POLICY_BYTE_OFFSET, 3);
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("policy byte tamper was not caught by AEAD (variant 3)"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_tamper_policy_byte);

fn smoke_power_suspend_tamper_manifest_tag() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(4096);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    store.flip_byte(MANIFEST_OFFSET + 3);
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("header should still open (tamper is in the manifest)"),
    };
    match opened.verify_all(&store) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("flipped manifest tag was not caught by the Merkle root"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_tamper_manifest_tag);

fn smoke_power_suspend_tamper_slot_blob() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // Preamble layout (spec §3.3): fixed fields end at 45; record
    // count (4) -> first record at 49: kind 1 + epoch 8 + params_len
    // 4 = params at 62; the test anchor's params are 15 bytes
    // (counter 8 + id "primary" 7), so the blob length sits at 77
    // and the blob itself at 81 (nonce 12, then ciphertext). Flip
    // inside the blob's ciphertext.
    store.flip_byte(81 + 20);
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::Anchor(AnchorError::Failed)) => {}
        _ => return TestResult::Fail("flipped slot blob byte was not caught by the anchor AEAD"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_tamper_slot_blob);

fn smoke_power_suspend_tamper_wrapped_smk() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(1024);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // After the first record (49 + 1 + 8 + 4 + 15 + 4 + 60 = 141):
    // wrap nonce at 141..153, wrapped SMK ciphertext at 153..185.
    store.flip_byte(157);
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("flipped wrapped-SMK byte was not caught"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_tamper_wrapped_smk);

fn smoke_power_suspend_truncated_image() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(100_000);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // Truncated mid-chunk: header parses, body authenticates, but
    // the store ends before the authenticated length.
    store.truncate(50_000);
    match svc.open_with_anchor(&store, &anchor) {
        Err(_) => {}
        Ok(_) => return TestResult::Fail("mid-chunk truncated image opened"),
    }
    // Truncated inside the header page: claims themselves refuse.
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed (short store)");
    }
    store.truncate(100);
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::Truncated) => {}
        _ => return TestResult::Fail("header-truncated image was not refused as Truncated"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_truncated_image);

// ── (c) Epoch rotation ───────────────────────────────────────────────

fn smoke_power_suspend_epoch_rotation() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    let image = pattern_image(3000);
    let mut store_a = MemImageStore::new(STORE_LEN);
    let id_a = match svc.seal_image(&mut store_a, token_policy(), &image) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("epoch-1 seal failed"),
    };
    // Rotate: new SMS under the same anchor, epoch becomes current.
    match svc.rotate_epoch(&[&anchor]) {
        Ok(2) => {}
        _ => return TestResult::Fail("rotate_epoch did not produce epoch 2"),
    }
    if svc.current_epoch() != Some(2) {
        return TestResult::Fail("current epoch is not 2 after rotation");
    }
    let mut store_b = MemImageStore::new(STORE_LEN);
    if svc
        .seal_image(&mut store_b, token_policy(), &image)
        .is_err()
    {
        return TestResult::Fail("epoch-2 seal failed");
    }
    let claims_b = match parse_claims(&store_b) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("epoch-2 claims did not parse"),
    };
    if claims_b.sms_epoch != 2 {
        return TestResult::Fail("epoch-2 image does not record SMS epoch 2");
    }
    // The epoch-1 SMS — legitimately unwrapped from image A's own
    // slot — must not open image B: the wrap key derives from the
    // SMS *and the epoch*, so the old wrapping is dead for the new
    // epoch even with the right factor in hand.
    let claims_a = match parse_claims(&store_a) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("epoch-1 claims did not parse"),
    };
    let sms1 = match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &claims_a.slots[0].wrapped()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("could not unwrap epoch-1 SMS for the negative"),
    };
    match crate::suspend_service::open_with_sms(&store_b, claims_b.clone(), &sms1) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("epoch-1 SMS opened an epoch-2 image"),
    }
    // And the epoch-1 slot record itself refuses to unwrap under an
    // epoch-2 context (the anchor binds the epoch into its KEK).
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 2 }, &claims_a.slots[0].wrapped()) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("epoch-1 slot unwrapped under an epoch-2 context"),
    }
    // The new image opens normally, and the old image still opens
    // under its retained epoch (rotation is not revocation).
    let trusted_b = match svc.open_with_anchor(&store_b, &anchor) {
        Ok(o) => match o.verify_all(&store_b) {
            Ok(t) => t,
            Err(_) => return TestResult::Fail("epoch-2 verify_all failed"),
        },
        Err(_) => return TestResult::Fail("epoch-2 image did not open"),
    };
    match trusted_b.read_all(&store_b) {
        Ok(all) if all == image => {}
        _ => return TestResult::Fail("epoch-2 image content differs"),
    }
    match svc.open_with_anchor(&store_a, &anchor) {
        Ok(o) => match o.verify_all(&store_a) {
            Ok(_) => {}
            Err(_) => return TestResult::Fail("epoch-1 image no longer verifies after rotation"),
        },
        Err(_) => return TestResult::Fail("epoch-1 image no longer opens after rotation"),
    }
    // Retirement: epoch 1 is pinned by its outstanding image until
    // the image is consumed; the current epoch never retires.
    match svc.retire_epoch(1) {
        Err(ServiceError::EpochInUse) => {}
        _ => return TestResult::Fail("retire of an epoch with an outstanding image succeeded"),
    }
    match svc.retire_epoch(2) {
        Err(ServiceError::EpochIsCurrent) => {}
        _ => return TestResult::Fail("retire of the current epoch succeeded"),
    }
    svc.note_image_consumed(&id_a);
    match svc.retire_epoch(1) {
        Ok(()) => {}
        _ => return TestResult::Fail("retire of a consumed epoch failed"),
    }
    if svc.slot_area().records_for(1).is_some() {
        return TestResult::Fail("retired epoch still present in the slot area");
    }
    match svc.open_with_anchor(&store_a, &anchor) {
        Ok(o) => match o.verify_all(&store_a) {
            // The image on disk is intact; the *service* no longer
            // retains epoch 1, but the anchor path resolves slots
            // from the image itself — opening still works here
            // because the record travels with the image. Retirement
            // governs the machine's own slot mirror (slot area),
            // asserted above.
            Ok(_) => {}
            Err(_) => return TestResult::Fail("retired-epoch image failed verification"),
        },
        Err(_) => return TestResult::Fail("retired-epoch image did not open"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_epoch_rotation);

fn smoke_power_suspend_revoke_slot() -> TestResult {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    let primary = TestAnchor::new("primary");
    let backup = TestAnchor::new("backup");
    let rec_primary = match svc.enroll(&primary) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("enroll primary failed"),
    };
    if svc.enroll(&backup).is_err() {
        return TestResult::Fail("enroll backup failed");
    }
    primary.grant_presence();
    backup.grant_presence();
    let image = pattern_image(777);
    let mut store = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // Both factors open the image (backup enrolment works).
    if svc.open_with_anchor(&store, &backup).is_err() {
        return TestResult::Fail("backup anchor could not open the image");
    }
    // Revoke the primary's slot in the *store*: the slot area loses
    // it. (The already-written image carries its own record copy —
    // revocation governs future seals and the machine mirror.)
    match svc.revoke_slot(1, AnchorKind::Test, &rec_primary.params) {
        Ok(()) => {}
        _ => return TestResult::Fail("revoke_slot failed"),
    }
    let area = svc.slot_area();
    match area.records_for(1) {
        Some(records) if records.len() == 1 => {}
        _ => return TestResult::Fail("slot area does not show exactly the backup slot"),
    }
    // A fresh seal now embeds only the backup's record.
    let mut store2 = MemImageStore::new(STORE_LEN);
    if svc.seal_image(&mut store2, token_policy(), &image).is_err() {
        return TestResult::Fail("post-revoke seal failed");
    }
    match parse_claims(&store2) {
        Ok(claims) if claims.slots.len() == 1 => {}
        _ => return TestResult::Fail("post-revoke image does not carry exactly one slot"),
    }
    if svc.open_with_anchor(&store2, &backup).is_err() {
        return TestResult::Fail("backup could not open the post-revoke image");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_revoke_slot);

// ── Slot-area codec ──────────────────────────────────────────────────

fn smoke_power_suspend_slot_area_codec() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    if svc.rotate_epoch(&[&anchor]).is_err() {
        return TestResult::Fail("rotate failed");
    }
    let area = svc.slot_area();
    let bytes = area.serialize();
    match SlotArea::parse(&bytes) {
        Ok(parsed) if parsed == area => {}
        _ => return TestResult::Fail("slot area did not round-trip"),
    }
    // Strict parser: every mutilation is Malformed, never a panic.
    for bad in [
        &b""[..],
        &b"NARFSLT2"[..],
        &bytes[..bytes.len() - 1],
        &bytes[..12],
    ] {
        if SlotArea::parse(bad).is_ok() {
            return TestResult::Fail("slot area parser accepted a mutilated input");
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    if SlotArea::parse(&trailing).is_ok() {
        return TestResult::Fail("slot area parser accepted trailing garbage");
    }
    // A hostile record count must be refused before allocation.
    let mut hostile = b"NARFSLT1".to_vec();
    hostile.extend_from_slice(&1u32.to_le_bytes());
    hostile.extend_from_slice(&1u64.to_le_bytes());
    hostile.extend_from_slice(&u32::MAX.to_le_bytes());
    if SlotArea::parse(&hostile).is_ok() {
        return TestResult::Fail("slot area parser accepted a hostile record count");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_slot_area_codec);

// ── Block-layer store ────────────────────────────────────────────────

fn smoke_power_suspend_block_store_round_trip() -> TestResult {
    let (mut svc, anchor) = enrolled_service();
    anchor.grant_presence();
    // 512-byte LBAs: the sealed header body sits at header-page
    // offset 4024, which is not LBA-aligned at this geometry, so
    // the open path exercises BlockStore's bounced unaligned reads.
    // (MemImageStore is offset-general and cannot see that class of
    // failure; that is why this fixture goes through the block
    // trait instead.)
    let dev = Arc::new(RamBlockDevice::new(512, STORE_LEN));
    let mut store = BlockStore::new(dev);
    let image = pattern_image(5000);
    if svc.seal_image(&mut store, token_policy(), &image).is_err() {
        return TestResult::Fail("seal through BlockStore failed");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open through BlockStore failed"),
    };
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify_all through BlockStore failed"),
    };
    match trusted.read_all(&store) {
        Ok(all) if all == image => TestResult::Pass,
        _ => TestResult::Fail("BlockStore round-trip content differs"),
    }
}
kernel_test_in!("power", smoke_power_suspend_block_store_round_trip);
