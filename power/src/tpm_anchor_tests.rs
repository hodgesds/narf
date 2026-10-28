//! Fixtures for the suspend service's TPM custody anchor
//! (`power/suspend-service/tpm-anchor`, issue #1002, design
//! §8.3).
//!
//! The TPM on the other side of the anchor is
//! `narf_drivers_tpm::fixture_tpm::FixtureTpm` — a spec-shaped
//! command core that computes policy digests, PCR composites,
//! and NV counter transitions itself (the #946 scripting
//! discipline) — so these fixtures pin the anchor's *security
//! properties*, not a transcript: the seal → resume-unseal round
//! trip through the real service; PCR drift after sealing
//! refuses as a factor refusal, not a malfunction; a dead
//! transport is `Unavailable` and leaves the other factors'
//! policies untouched; token+TPM-style composition needs both
//! shares; a tampered sealed blob fails closed in the no-oracle
//! bucket; and the NV epoch counter is monotonic across anchor
//! instances.

extern crate alloc;

use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_drivers_tpm::devfs_bridge::TpmTransport;
use narf_drivers_tpm::fixture_tpm::started_fixture;
use narf_drivers_tpm::tpm2::commands as tpm_cmds;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    AnchorError, AnchorKind, ImageStore, KeyCustodyAnchor, KeyEntropy, PolicyLevel, RecordedPolicy,
    Secret32, ServiceError, SuspendService, TpmAnchor, UnwrapCtx, WrapCtx, WrappedSlot,
};

// ── Scripted entropy seam (mirror of suspend_service_tests) ──────

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

// ── In-memory image store (mirror of suspend_service_tests) ──────

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

// ── A partner factor for the composition fixture ────────────────
//
// A minimal AEAD anchor of the fixture-anchor species (published
// construction, HKDF + ChaCha20-Poly1305 like the P1 test
// anchor): it honestly wraps and unwraps, and it is labelled
// AnchorKind::Token in records because the composition fixture
// stands it in the token factor's place. It exists so the TPM
// anchor's composition property is proven against a *second,
// independent* factor rather than against itself.

#[derive(Debug)]
struct PartnerAnchor {
    wraps: AtomicU64,
}

impl PartnerAnchor {
    fn new() -> Self {
        Self {
            wraps: AtomicU64::new(0),
        }
    }

    fn kek(&self, epoch: u64, counter: u64) -> [u8; 32] {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(b"narf-suspend/tpm-anchor-test-partner");
        ikm.extend_from_slice(&epoch.to_le_bytes());
        ikm.extend_from_slice(&counter.to_le_bytes());
        let prk = hkdf_extract(None, &ikm);
        let okm = hkdf_expand(&prk, b"partner-kek", 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&okm);
        out
    }
}

impl KeyCustodyAnchor for PartnerAnchor {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Token
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        let counter = self.wraps.fetch_add(1, Ordering::Relaxed);
        let kek = self.kek(ctx.sms_epoch, counter);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        let mut ct = [0u8; 32];
        secret.with_bytes(|b| ct.copy_from_slice(b));
        let mut aad = Vec::new();
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(b"partner");
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::with_capacity(60);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        Ok(WrappedSlot {
            params: counter.to_le_bytes().to_vec(),
            blob,
        })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        if slot.params.len() != 8 || slot.blob.len() != 60 {
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
        let mut aad = Vec::new();
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(b"partner");
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

/// A transport that always fails: the TPM-less machine, from the
/// anchor's side of the seam.
#[derive(Debug)]
struct DeadTransport;

impl TpmTransport for DeadTransport {
    fn submit(&self, _cmd: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────

const STORE_LEN: usize = 3 * 1024 * 1024;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push((i.wrapping_mul(7) % 251) as u8);
    }
    img
}

fn tpm_policy() -> RecordedPolicy {
    RecordedPolicy {
        level: PolicyLevel::Tpm,
        policy_epoch: 7,
    }
}

fn xor32(a: &Secret32, b: &Secret32) -> [u8; 32] {
    let mut out = [0u8; 32];
    a.with_bytes(|x| {
        b.with_bytes(|y| {
            for i in 0..32 {
                out[i] = x[i] ^ y[i];
            }
        })
    });
    out
}

fn secret_eq(a: &Secret32, b: &[u8; 32]) -> bool {
    a.with_bytes(|x| x == b)
}

/// A service with epoch 1 established and the TPM anchor over
/// `tpm` enrolled.
fn tpm_enrolled_service(
    tpm: &Arc<dyn TpmTransport>,
) -> (SuspendService<ScriptedEntropy>, TpmAnchor) {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let anchor = TpmAnchor::with_transport(tpm.clone());
    svc.enroll(&anchor).expect("enroll");
    (svc, anchor)
}

// ── (1) Seal → resume-unseal round trip through the service ─────

fn smoke_tpm_anchor_service_round_trip() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let (mut svc, anchor) = tpm_enrolled_service(&transport);
    let record = &svc.slot_area().epochs[0].records[0];
    if record.kind != AnchorKind::Tpm {
        return TestResult::Fail("enrolled slot is not recorded as the TPM kind");
    }
    let mut store = MemImageStore::new(STORE_LEN);
    let image = pattern_image(5000);
    if svc.seal_image(&mut store, tpm_policy(), &image).is_err() {
        return TestResult::Fail("seal_image failed under the TPM policy");
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open_with_anchor failed on the sealing PCR state"),
    };
    if opened.claims().policy != tpm_policy() {
        return TestResult::Fail("authenticated policy record does not match the sealed policy");
    }
    let trusted = match opened.verify_all(&store) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("verify_all failed on an untampered image"),
    };
    match trusted.read_all(&store) {
        Ok(all) if all == image => {}
        _ => return TestResult::Fail("round-tripped image differs from the sealed image"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_service_round_trip
);

// ── (2) PCR drift after sealing refuses ──────────────────────────

fn smoke_tpm_anchor_pcr_drift_refuses() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let (mut svc, anchor) = tpm_enrolled_service(&transport);
    let mut store = MemImageStore::new(STORE_LEN);
    let image = pattern_image(1024);
    if svc.seal_image(&mut store, tpm_policy(), &image).is_err() {
        return TestResult::Fail("seal_image failed under the TPM policy");
    }
    // The boot chain moves on: PCR 4 is extended after sealing
    // (a different kernel was measured). Unseal must refuse as a
    // factor refusal — the TPM answered, and its answer is no.
    let resp = transport
        .submit(&tpm_cmds::pcr_extend_sha256(4, &[0x5A; 32]))
        .unwrap_or_default();
    if tpm_cmds::response_rc(&resp) != Some(0) {
        return TestResult::Fail("fixture PCR extend failed");
    }
    match svc.open_with_anchor(&store, &anchor) {
        Err(ServiceError::Anchor(AnchorError::Refused)) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("PCR drift did not surface as an anchor refusal");
        }
        Ok(_) => return TestResult::Fail("PCR drift did not refuse the unseal"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_pcr_drift_refuses
);

// ── (3) Absent TPM: Unavailable, other factors unaffected ───────

fn smoke_tpm_anchor_absent_unavailable() -> TestResult {
    let dead: Arc<dyn TpmTransport> = Arc::new(DeadTransport);
    let dead_anchor = TpmAnchor::with_transport(dead);
    if dead_anchor.epoch().is_some() {
        return TestResult::Fail("a dead transport reported an epoch");
    }
    match dead_anchor.advance_epoch() {
        Err(AnchorError::Unavailable) => {}
        _ => return TestResult::Fail("advance over a dead transport was not Unavailable"),
    }

    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    // Enrollment through the absent TPM fails as Unavailable…
    match svc.enroll(&dead_anchor) {
        Err(ServiceError::Anchor(AnchorError::Unavailable)) => {}
        _ => return TestResult::Fail("enroll over a dead transport was not Unavailable"),
    }
    // …and the service is unharmed: another factor enrolls, seals,
    // and opens on the same service and epoch. Absence is a
    // property of the TPM factor, never of the machine's resume.
    let partner = PartnerAnchor::new();
    if svc.enroll(&partner).is_err() {
        return TestResult::Fail("partner enroll failed after the TPM refusal");
    }
    let mut store = MemImageStore::new(STORE_LEN);
    let image = pattern_image(2048);
    let policy = RecordedPolicy {
        level: PolicyLevel::Token,
        policy_epoch: 7,
    };
    if svc.seal_image(&mut store, policy, &image).is_err() {
        return TestResult::Fail("seal under the partner factor failed");
    }
    let opened = match svc.open_with_anchor(&store, &partner) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open through the partner factor failed"),
    };
    match opened.verify_all(&store) {
        Ok(t) if t.read_all(&store).map(|all| all == image).unwrap_or(false) => {}
        _ => return TestResult::Fail("partner-factor image did not verify"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_absent_unavailable
);

// ── (4) Composition: both shares required ────────────────────────

fn smoke_tpm_anchor_composition_both_required() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let tpm_anchor = TpmAnchor::with_transport(transport.clone());
    let partner = PartnerAnchor::new();
    let ctx = WrapCtx { sms_epoch: 3 };

    // AND-composition by XOR split (design §8.5's shape at the
    // anchor layer; chained-slot storage is P8's): the SMS is
    // split into two shares, one sealed to the TPM under the
    // PCR policy, one wrapped by the partner factor. Neither
    // share is, or reveals, the SMS.
    let sms = Secret32::mint([0xA5; 32]);
    let share_tpm = Secret32::mint([0x3C; 32]);
    let share_partner_bytes = xor32(&sms, &share_tpm);
    let share_partner = Secret32::mint(share_partner_bytes);

    let tpm_slot = match tpm_anchor.wrap(&ctx, &share_tpm) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("TPM wrap of its share failed"),
    };
    let partner_slot = match partner.wrap(&ctx, &share_partner) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("partner wrap of its share failed"),
    };

    // Each factor alone recovers only its share.
    let uctx = UnwrapCtx { sms_epoch: 3 };
    let back_tpm = match tpm_anchor.unwrap(&uctx, &tpm_slot) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("TPM unwrap of its share failed"),
    };
    if !secret_eq(&back_tpm, &[0x3C; 32]) || secret_eq(&back_tpm, &[0xA5; 32]) {
        return TestResult::Fail("TPM share did not round-trip as a share");
    }
    let back_partner = match partner.unwrap(&uctx, &partner_slot) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("partner unwrap of its share failed"),
    };
    if !secret_eq(&back_partner, &share_partner_bytes) {
        return TestResult::Fail("partner share did not round-trip");
    }
    if xor32(&back_tpm, &back_partner) != [0xA5; 32] {
        return TestResult::Fail("the two shares did not recompose the SMS");
    }

    // And the composition honours the TPM factor's refusal: once
    // the PCR state drifts, the TPM share is gone and the SMS is
    // unrecoverable even with the partner share in hand.
    let resp = transport
        .submit(&tpm_cmds::pcr_extend_sha256(9, &[0xC3; 32]))
        .unwrap_or_default();
    if tpm_cmds::response_rc(&resp) != Some(0) {
        return TestResult::Fail("fixture PCR extend failed");
    }
    match tpm_anchor.unwrap(&uctx, &tpm_slot) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("drifted PCRs did not refuse the composed unwrap"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_composition_both_required
);

// ── (5) Tampered sealed blob fails closed ────────────────────────

fn smoke_tpm_anchor_tampered_blob_fails_closed() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm;
    let anchor = TpmAnchor::with_transport(transport);
    let ctx = WrapCtx { sms_epoch: 5 };
    let secret = Secret32::mint([0x11; 32]);
    let slot = match anchor.wrap(&ctx, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    let uctx = UnwrapCtx { sms_epoch: 5 };

    // Flip a byte in the sealed object's public half: the TPM's
    // load integrity check must turn it away (Failed — the
    // no-oracle bucket), never a panic, never a refusal that
    // would tell an attacker which check fired.
    let mut tampered = slot.clone();
    let last = tampered.blob.len() - 1;
    tampered.blob[last] ^= 0xFF;
    match anchor.unwrap(&uctx, &tampered) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("public-half tamper was not Failed"),
    }
    // Flip a byte in the private half.
    let mut tampered = slot.clone();
    tampered.blob[2] ^= 0xFF;
    match anchor.unwrap(&uctx, &tampered) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("private-half tamper was not Failed"),
    }
    // Corrupt the params version.
    let mut tampered = slot.clone();
    tampered.params[0] = 0x7F;
    match anchor.unwrap(&uctx, &tampered) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("params-version tamper was not Failed"),
    }
    // The wrong epoch context is refused before the TPM is used.
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 6 }, &slot) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("epoch-mismatched unwrap was not Failed"),
    }
    // The untampered slot still unwraps — the negatives above
    // are properties of the bytes, not of a wedged anchor.
    match anchor.unwrap(&uctx, &slot) {
        Ok(s) if secret_eq(&s, &[0x11; 32]) => {}
        _ => return TestResult::Fail("untampered slot no longer unwraps"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_tampered_blob_fails_closed
);

// ── (6) NV epoch: monotonic, survives anchor instances ──────────

fn smoke_tpm_anchor_nv_epoch() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm;
    let anchor = TpmAnchor::with_transport(transport.clone());
    if anchor.epoch().is_some() {
        return TestResult::Fail("epoch reported before the counter exists");
    }
    match anchor.advance_epoch() {
        Ok(Some(1)) => {}
        _ => return TestResult::Fail("first advance did not yield epoch 1"),
    }
    match anchor.advance_epoch() {
        Ok(Some(2)) => {}
        _ => return TestResult::Fail("second advance did not yield epoch 2"),
    }
    // A fresh anchor over the same TPM sees the same counter:
    // the epoch lives in the TPM's NV, not in the anchor.
    let anchor2 = TpmAnchor::with_transport(transport);
    if anchor2.epoch() != Some(2) {
        return TestResult::Fail("epoch did not survive anchor reconstruction");
    }
    // The wrap-time epoch is bound into the slot params.
    let secret = Secret32::mint([0x22; 32]);
    let slot = match anchor2.wrap(&WrapCtx { sms_epoch: 2 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    let mut recorded = [0u8; 8];
    recorded.copy_from_slice(&slot.params[6..14]);
    if u64::from_be_bytes(recorded) != 2 {
        return TestResult::Fail("slot params do not record the wrap-time epoch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-anchor",
    smoke_tpm_anchor_nv_epoch
);
