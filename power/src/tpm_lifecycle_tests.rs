//! Fixtures for the suspend service's TPM lifecycle surface
//! (`power/suspend-service/tpm-lifecycle`, issue #1003, design
//! §8.3/§4.3).
//!
//! The TPM is the same spec-shaped `FixtureTpm` the anchor
//! fixtures use — now with its power-state, Clear, and
//! dictionary-attack semantics modelled — so these fixtures
//! pin the lifecycle *contracts*: the startup-state matrix
//! (restored / fresh / already started), the shutdown fallback
//! that reports lost continuity instead of hiding it, Clear
//! invalidating sealed slots (and the epoch counter with
//! them) in a way re-provisioning to the same number cannot
//! resurrect, the epoch counter's three certifiable states,
//! and the DA accounting in which policy failures never count
//! and lockout refusals never amplify.

extern crate alloc;

use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;

use narf_drivers_tpm::devfs_bridge::TpmTransport;
use narf_drivers_tpm::fixture_tpm::{started_fixture, FixtureTpm};
use narf_drivers_tpm::tpm2::commands as tpm_cmds;
use narf_drivers_tpm::tpm2::{
    TPM_CC_SHUTDOWN, TPM_RC_AUTH_FAIL, TPM_RC_FAILURE, TPM_RC_LOCKOUT, TPM_RC_POLICY_FAIL,
    TPM_RC_SUCCESS, TPM_SU_CLEAR, TPM_SU_STATE,
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    classify_refusal, AnchorError, EpochState, ImageStore, KeyCustodyAnchor, KeyEntropy,
    PolicyLevel, RecordedPolicy, Secret32, ServiceError, ShutdownOutcome, StartupOutcome,
    SuspendService, TpmAnchor, TpmLifecycle, TpmLifecycleError, TpmRefusal, UnwrapCtx, WrapCtx,
};

// ── Mirrors of the anchor fixtures' seams ───────────────────────

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

/// A transport that always fails: the TPM-less machine.
#[derive(Debug)]
struct DeadTransport;

impl TpmTransport for DeadTransport {
    fn submit(&self, _cmd: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

/// A transport that forwards everything to the fixture except
/// Shutdown frames, which it answers with `TPM_RC_FAILURE` —
/// a TPM whose state save (or shutdown generally) is broken,
/// staged to pin the lifecycle's fallback reporting.
#[derive(Debug)]
struct ShutdownSaboteur {
    inner: Arc<FixtureTpm>,
    state_only: bool,
}

impl TpmTransport for ShutdownSaboteur {
    fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()> {
        if cmd.len() >= 12 {
            let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
            let su = u16::from_be_bytes([cmd[10], cmd[11]]);
            if cc == TPM_CC_SHUTDOWN && (!self.state_only || su == TPM_SU_STATE) {
                let mut resp = alloc::vec![0u8; 10];
                resp[0..2].copy_from_slice(&cmd[0..2]);
                resp[2..6].copy_from_slice(&10u32.to_be_bytes());
                resp[6..10].copy_from_slice(&TPM_RC_FAILURE.to_be_bytes());
                return Ok(resp);
            }
        }
        self.inner.submit(cmd)
    }
}

const STORE_LEN: usize = 3 * 1024 * 1024;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push((i.wrapping_mul(7) % 251) as u8);
    }
    img
}

fn rc_of(t: &Arc<dyn TpmTransport>, cmd: &[u8]) -> Option<u32> {
    let resp = t.submit(cmd).ok()?;
    tpm_cmds::response_rc(&resp)
}

// ── (1) The startup-state matrix ─────────────────────────────────

fn smoke_tpm_lifecycle_startup_matrix() -> TestResult {
    let tpm = Arc::new(FixtureTpm::new());
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let lifecycle = TpmLifecycle::with_transport(transport.clone());

    // A never-started TPM has no saved state: Fresh.
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Fresh) => {}
        _ => return TestResult::Fail("unstarted TPM did not start Fresh"),
    }
    if !tpm.is_started() {
        return TestResult::Fail("TPM not started after Fresh startup");
    }
    // Give the PCR state content, then run an orderly cycle.
    if rc_of(&transport, &tpm_cmds::pcr_extend_sha256(4, &[0x2A; 32])) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("PCR extend failed");
    }
    let pcr_at_suspend = tpm.pcr(4);
    match lifecycle.shutdown_for_suspend() {
        Ok(ShutdownOutcome::StateSaved) => {}
        _ => return TestResult::Fail("orderly shutdown did not report StateSaved"),
    }
    if tpm.is_started() {
        return TestResult::Fail("TPM still started after Shutdown");
    }
    // Between Shutdown and Startup the TPM refuses work.
    if rc_of(&transport, &tpm_cmds::get_random(8)) == Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("TPM accepted a command between Shutdown and Startup");
    }
    // Restored — and the PCR state is continuous across the
    // cycle, which is the whole reason the shutdown was STATE.
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Restored) => {}
        _ => return TestResult::Fail("STATE cycle did not report Restored"),
    }
    if tpm.pcr(4) != pcr_at_suspend {
        return TestResult::Fail("PCR state did not survive the STATE cycle");
    }
    // An orderly CLEAR shutdown leaves nothing to restore.
    if rc_of(&transport, &tpm_cmds::shutdown(TPM_SU_CLEAR)) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("raw CLEAR shutdown failed");
    }
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Fresh) => {}
        _ => return TestResult::Fail("CLEAR shutdown cycle did not start Fresh"),
    }
    if tpm.pcr(4) != [0u8; 32] {
        return TestResult::Fail("CLEAR startup did not reset the PCRs");
    }
    // A pulled plug: power loss with no Shutdown at all.
    if rc_of(&transport, &tpm_cmds::pcr_extend_sha256(4, &[0x2A; 32])) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("PCR extend failed");
    }
    tpm.simulate_power_loss();
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Fresh) => {}
        _ => return TestResult::Fail("dirty power loss did not start Fresh"),
    }
    // The running TPM is not disturbed by a second opinion.
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::AlreadyStarted) => {}
        _ => return TestResult::Fail("started TPM did not report AlreadyStarted"),
    }
    // Absence is an error class, never an outcome.
    let dead: Arc<dyn TpmTransport> = Arc::new(DeadTransport);
    let dead_lifecycle = TpmLifecycle::with_transport(dead);
    if dead_lifecycle.startup_for_resume() != Err(TpmLifecycleError::Unavailable) {
        return TestResult::Fail("dead transport startup was not Unavailable");
    }
    if dead_lifecycle.shutdown_for_suspend() != Err(TpmLifecycleError::Unavailable) {
        return TestResult::Fail("dead transport shutdown was not Unavailable");
    }
    if dead_lifecycle.epoch_state() != Err(TpmLifecycleError::Unavailable) {
        return TestResult::Fail("dead transport epoch_state was not Unavailable");
    }
    if dead_lifecycle.lockout_state() != Err(TpmLifecycleError::Unavailable) {
        return TestResult::Fail("dead transport lockout_state was not Unavailable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_startup_matrix
);

// ── (2) Shutdown fallback reports lost continuity ────────────────

fn smoke_tpm_lifecycle_shutdown_fallback() -> TestResult {
    // STATE shutdown refused, CLEAR accepted: the suspend
    // proceeds, the loss is reported, the resume starts Fresh.
    let tpm = started_fixture();
    let saboteur: Arc<dyn TpmTransport> = Arc::new(ShutdownSaboteur {
        inner: tpm.clone(),
        state_only: true,
    });
    let lifecycle = TpmLifecycle::with_transport(saboteur);
    match lifecycle.shutdown_for_suspend() {
        Ok(ShutdownOutcome::StateContinuityLost) => {}
        _ => return TestResult::Fail("refused STATE shutdown was not StateContinuityLost"),
    }
    if tpm.is_started() {
        return TestResult::Fail("fallback CLEAR shutdown did not land");
    }
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Fresh) => {}
        _ => return TestResult::Fail("post-fallback resume did not start Fresh"),
    }
    // Both shutdowns refused: a malfunction, and nothing was
    // shut down behind the caller's back.
    let tpm2 = started_fixture();
    let saboteur2: Arc<dyn TpmTransport> = Arc::new(ShutdownSaboteur {
        inner: tpm2.clone(),
        state_only: false,
    });
    let lifecycle2 = TpmLifecycle::with_transport(saboteur2);
    if lifecycle2.shutdown_for_suspend() != Err(TpmLifecycleError::Failed) {
        return TestResult::Fail("doubly refused shutdown was not Failed");
    }
    if !tpm2.is_started() {
        return TestResult::Fail("TPM was shut down despite both shutdowns failing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_shutdown_fallback
);

// ── (3) Clear invalidates slots — permanently ────────────────────

fn smoke_tpm_lifecycle_clear_invalidates_slots() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm;
    let anchor = TpmAnchor::with_transport(transport.clone());
    let lifecycle = TpmLifecycle::with_transport(transport.clone());

    match anchor.advance_epoch() {
        Ok(Some(1)) => {}
        _ => return TestResult::Fail("first epoch advance did not yield 1"),
    }
    if lifecycle.epoch_state() != Ok(EpochState::Present(1)) {
        return TestResult::Fail("epoch_state did not report Present(1)");
    }
    let secret = Secret32::mint([0x44; 32]);
    let slot = match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("wrap failed before Clear"),
    };
    let uctx = UnwrapCtx { sms_epoch: 1 };
    if anchor.unwrap(&uctx, &slot).is_err() {
        return TestResult::Fail("unwrap failed before Clear");
    }

    // The ownership event: TPM2_Clear under the platform auth.
    if rc_of(&transport, &tpm_cmds::clear()) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("fixture Clear failed");
    }
    // The counter is gone with the owner hierarchy's NV…
    if lifecycle.epoch_state() != Ok(EpochState::Absent) {
        return TestResult::Fail("epoch_state after Clear was not Absent");
    }
    if anchor.epoch().is_some() {
        return TestResult::Fail("anchor reported an epoch after Clear");
    }
    // …and the slot is dead — in the no-oracle Failed bucket,
    // not a refusal: there is no policy left to evaluate, the
    // seed that minted the blob no longer exists.
    match anchor.unwrap(&uctx, &slot) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("slot survived TPM2_Clear"),
    }
    // Re-provisioning mints a NEW counter under the NEW seed.
    // It reaches the same number — and the old slot stays dead.
    // The number was never the slot's life; the seed was.
    match anchor.advance_epoch() {
        Ok(Some(1)) => {}
        _ => return TestResult::Fail("post-Clear advance did not re-provision epoch 1"),
    }
    if lifecycle.epoch_state() != Ok(EpochState::Present(1)) {
        return TestResult::Fail("epoch_state after re-provisioning was not Present(1)");
    }
    match anchor.unwrap(&uctx, &slot) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("re-provisioned counter resurrected the cleared slot"),
    }
    // The machine is not wedged: a fresh enrollment unwraps.
    let slot2 = match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("post-Clear wrap failed"),
    };
    match anchor.unwrap(&uctx, &slot2) {
        Ok(s) if s.with_bytes(|b| *b == [0x44; 32]) => {}
        _ => return TestResult::Fail("post-Clear slot did not unwrap"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_clear_invalidates_slots
);

// ── (4) Epoch states, and what NV surgery does not do ────────────

fn smoke_tpm_lifecycle_epoch_states() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm;
    let anchor = TpmAnchor::with_transport(transport.clone());
    let lifecycle = TpmLifecycle::with_transport(transport.clone());
    let idx = narf_drivers_tpm::tpm2::nv::NV_IDX_SUSPEND_EPOCH;

    // Never provisioned.
    if lifecycle.epoch_state() != Ok(EpochState::Absent) {
        return TestResult::Fail("unprovisioned counter was not Absent");
    }
    // Defined but never incremented.
    let define = narf_drivers_tpm::tpm2::nv::NARF_SUSPEND_EPOCH_NV.define_space_cmd();
    if rc_of(&transport, &define) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("counter define failed");
    }
    if lifecycle.epoch_state() != Ok(EpochState::Uninitialized) {
        return TestResult::Fail("defined-unwritten counter was not Uninitialized");
    }
    match anchor.advance_epoch() {
        Ok(Some(1)) => {}
        _ => return TestResult::Fail("advance over a defined counter did not yield 1"),
    }
    if lifecycle.epoch_state() != Ok(EpochState::Present(1)) {
        return TestResult::Fail("incremented counter was not Present(1)");
    }
    // Wrap a slot, then perform NV surgery: undefine the
    // counter and re-provision it to the same value. The
    // lifecycle reports the absence honestly while it lasts —
    // and the slot survives the surgery, because NV state is
    // accounting, not custody. (Clear, which couples the
    // counter flush to a seed change, is the invalidation
    // event; see the Clear fixture.)
    let secret = Secret32::mint([0x55; 32]);
    let slot = match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    if rc_of(&transport, &tpm_cmds::nv_undefine_space(idx)) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("counter undefine failed");
    }
    if lifecycle.epoch_state() != Ok(EpochState::Absent) {
        return TestResult::Fail("undefined counter was not Absent");
    }
    if anchor.epoch().is_some() {
        return TestResult::Fail("anchor reported an epoch for an undefined counter");
    }
    if rc_of(&transport, &define) != Some(TPM_RC_SUCCESS)
        || rc_of(&transport, &tpm_cmds::nv_increment(idx)) != Some(TPM_RC_SUCCESS)
    {
        return TestResult::Fail("counter re-provisioning failed");
    }
    if lifecycle.epoch_state() != Ok(EpochState::Present(1)) {
        return TestResult::Fail("re-provisioned counter was not Present(1)");
    }
    match anchor.unwrap(&UnwrapCtx { sms_epoch: 1 }, &slot) {
        Ok(s) if s.with_bytes(|b| *b == [0x55; 32]) => {}
        _ => return TestResult::Fail("NV surgery alone killed a slot (it must not)"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_epoch_states
);

// ── (5) DA accounting: counted, attributed, never amplified ─────

fn smoke_tpm_lifecycle_lockout_accounting() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let anchor = TpmAnchor::with_transport(transport.clone());
    let lifecycle = TpmLifecycle::with_transport(transport.clone());

    match lifecycle.lockout_state() {
        Ok(s) if s.failed_tries == 0 && s.max_auth_fail == 32 && !s.in_lockout() => {}
        _ => return TestResult::Fail("fresh TPM lockout accounting is wrong"),
    }
    if anchor.last_response_code().is_some() {
        return TestResult::Fail("fresh anchor already has a response code");
    }
    // Stage the machine an operator can create: an owner auth
    // was provisioned (the anchor presents the empty value and
    // now fails auth), and a low DA threshold.
    tpm.set_owner_auth(b"provisioned-owner");
    if rc_of(
        &transport,
        &tpm_cmds::dictionary_attack_parameters(3, 600, 600),
    ) != Some(TPM_RC_SUCCESS)
    {
        return TestResult::Fail("DA parameter staging failed");
    }
    if lifecycle.lockout_state().map(|s| s.max_auth_fail) != Ok(3) {
        return TestResult::Fail("staged DA threshold not visible in the accounting");
    }
    let secret = Secret32::mint([0x66; 32]);
    // Each wrap attempt costs exactly one counted failure, is
    // attributed Auth from the recorded code, and lands in the
    // anchor's no-oracle bucket (AUTH_FAIL is not one of the
    // two codes the anchor calls Refused).
    for want in 1..=3u32 {
        match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
            Err(AnchorError::Failed) => {}
            _ => return TestResult::Fail("auth-failing wrap was not the Failed bucket"),
        }
        if anchor.last_response_code() != Some(TPM_RC_AUTH_FAIL) {
            return TestResult::Fail("auth failure was not recorded as TPM_RC_AUTH_FAIL");
        }
        if classify_refusal(TPM_RC_AUTH_FAIL) != Some(TpmRefusal::Auth) {
            return TestResult::Fail("AUTH_FAIL not attributed as an auth refusal");
        }
        match lifecycle.lockout_state() {
            Ok(s) if s.failed_tries == want => {}
            _ => return TestResult::Fail("failedTries did not count the auth failure"),
        }
    }
    if !lifecycle
        .lockout_state()
        .map(|s| s.in_lockout())
        .unwrap_or(false)
    {
        return TestResult::Fail("TPM not in lockout at the threshold");
    }
    // In lockout the refusal class changes — and retrying does
    // not amplify it: the counter does not move, however often
    // the attempt is repeated. This is the resume discipline
    // the accounting exists to prove safe to *not* retry.
    for _ in 0..3 {
        match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret) {
            Err(AnchorError::Refused) => {}
            _ => return TestResult::Fail("lockout wrap was not Refused"),
        }
        if anchor.last_response_code() != Some(TPM_RC_LOCKOUT) {
            return TestResult::Fail("lockout refusal was not recorded as TPM_RC_LOCKOUT");
        }
        if classify_refusal(TPM_RC_LOCKOUT) != Some(TpmRefusal::Lockout) {
            return TestResult::Fail("LOCKOUT not attributed as a lockout refusal");
        }
        match lifecycle.lockout_state() {
            Ok(s) if s.failed_tries == 3 => {}
            _ => return TestResult::Fail("lockout retries amplified failedTries"),
        }
    }
    // Recovery is the lockout-authorized reset — an operator
    // act. After it, the factor works again once the staged
    // auth mismatch is undone.
    if lifecycle.reset_lockout() != Ok(()) {
        return TestResult::Fail("lockout reset failed");
    }
    match lifecycle.lockout_state() {
        Ok(s) if s.failed_tries == 0 && !s.in_lockout() => {}
        _ => return TestResult::Fail("lockout state not cleared by the reset"),
    }
    tpm.set_owner_auth(b"");
    if anchor.wrap(&WrapCtx { sms_epoch: 1 }, &secret).is_err() {
        return TestResult::Fail("wrap still fails after lockout reset and auth restore");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_lockout_accounting
);

// ── (6) Policy failures are not auth failures ────────────────────

fn smoke_tpm_lifecycle_policy_failures_never_count() -> TestResult {
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    let anchor = TpmAnchor::with_transport(transport.clone());
    let lifecycle = TpmLifecycle::with_transport(transport.clone());
    let secret = Secret32::mint([0x77; 32]);
    let slot = match anchor.wrap(&WrapCtx { sms_epoch: 2 }, &secret) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    // Drift the measured state and fail the unwrap repeatedly.
    if rc_of(&transport, &tpm_cmds::pcr_extend_sha256(9, &[0xC3; 32])) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("PCR extend failed");
    }
    for _ in 0..3 {
        match anchor.unwrap(&UnwrapCtx { sms_epoch: 2 }, &slot) {
            Err(AnchorError::Refused) => {}
            _ => return TestResult::Fail("PCR-drift unwrap was not Refused"),
        }
        if anchor.last_response_code() != Some(TPM_RC_POLICY_FAIL) {
            return TestResult::Fail("policy refusal was not recorded as TPM_RC_POLICY_FAIL");
        }
        if classify_refusal(TPM_RC_POLICY_FAIL) != Some(TpmRefusal::Policy) {
            return TestResult::Fail("POLICY_FAIL not attributed as a policy refusal");
        }
    }
    // Part 1 §19: a policy failure is not an auth failure. The
    // DA counter is exactly where it was — repeated resume
    // failures against drifted PCRs can never lock the TPM.
    match lifecycle.lockout_state() {
        Ok(s) if s.failed_tries == 0 => {}
        _ => return TestResult::Fail("policy failures leaked into the DA accounting"),
    }
    if tpm.failed_tries() != 0 {
        return TestResult::Fail("fixture counted a policy failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_policy_failures_never_count
);

// ── (7) A STATE cycle keeps the service's TPM factor ─────────────

fn smoke_tpm_lifecycle_state_cycle_keeps_factor() -> TestResult {
    // Seal under a measured boot state (PCR 4 extended before
    // enrollment), suspend with an orderly STATE shutdown,
    // resume: the factor opens the image.
    let tpm = started_fixture();
    let transport: Arc<dyn TpmTransport> = tpm.clone();
    if rc_of(&transport, &tpm_cmds::pcr_extend_sha256(4, &[0x5A; 32])) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("PCR extend failed");
    }
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    if svc.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed");
    }
    let anchor = TpmAnchor::with_transport(transport.clone());
    if svc.enroll(&anchor).is_err() {
        return TestResult::Fail("enroll failed");
    }
    let lifecycle = TpmLifecycle::with_transport(transport.clone());
    let mut store = MemImageStore::new(STORE_LEN);
    let image = pattern_image(4096);
    let policy = RecordedPolicy {
        level: PolicyLevel::Tpm,
        policy_epoch: 7,
    };
    if svc.seal_image(&mut store, policy, &image).is_err() {
        return TestResult::Fail("seal_image failed");
    }
    match lifecycle.shutdown_for_suspend() {
        Ok(ShutdownOutcome::StateSaved) => {}
        _ => return TestResult::Fail("suspend shutdown was not StateSaved"),
    }
    match lifecycle.startup_for_resume() {
        Ok(StartupOutcome::Restored) => {}
        _ => return TestResult::Fail("resume startup was not Restored"),
    }
    let opened = match svc.open_with_anchor(&store, &anchor) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("open failed after a STATE cycle"),
    };
    match opened.verify_all(&store) {
        Ok(t) if t.read_all(&store).map(|all| all == image).unwrap_or(false) => {}
        _ => return TestResult::Fail("image did not verify after a STATE cycle"),
    }

    // The same machine, but the cycle loses the saved state
    // (power died mid-suspend): the resume starts Fresh, the
    // PCR state is gone, and the TPM factor refuses — the
    // image's other factors, if any, are the resume's path.
    let tpm2 = started_fixture();
    let transport2: Arc<dyn TpmTransport> = tpm2.clone();
    if rc_of(&transport2, &tpm_cmds::pcr_extend_sha256(4, &[0x5A; 32])) != Some(TPM_RC_SUCCESS) {
        return TestResult::Fail("PCR extend failed (contrast)");
    }
    let mut svc2 = SuspendService::new(ScriptedEntropy::new(true));
    if svc2.create_epoch().is_err() {
        return TestResult::Fail("create_epoch failed (contrast)");
    }
    let anchor2 = TpmAnchor::with_transport(transport2.clone());
    if svc2.enroll(&anchor2).is_err() {
        return TestResult::Fail("enroll failed (contrast)");
    }
    let lifecycle2 = TpmLifecycle::with_transport(transport2);
    let mut store2 = MemImageStore::new(STORE_LEN);
    if svc2.seal_image(&mut store2, policy, &image).is_err() {
        return TestResult::Fail("seal_image failed (contrast)");
    }
    tpm2.simulate_power_loss();
    match lifecycle2.startup_for_resume() {
        Ok(StartupOutcome::Fresh) => {}
        _ => return TestResult::Fail("contrast resume was not Fresh"),
    }
    match svc2.open_with_anchor(&store2, &anchor2) {
        Err(ServiceError::Anchor(AnchorError::Refused)) => {}
        _ => return TestResult::Fail("fresh-started TPM did not refuse the pre-suspend slot"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/tpm-lifecycle",
    smoke_tpm_lifecycle_state_cycle_keeps_factor
);
