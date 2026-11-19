//! mac80211 MLME retries in the station join (net/mac80211/mlme.c):
//! `IEEE80211_AUTH_MAX_TRIES` / `IEEE80211_ASSOC_MAX_TRIES`, a retry at once
//! after a TX status without ACK, a retry after the reply timeout, and the
//! join grant renewed per try only once it expired (`mt7921_mgd_prepare_tx`).
use super::*;
use crate::mt7921::association::Security;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::ApSaePwe;

fn roc_acquire(frame: &[u8]) -> bool {
    frame.len() == 76 && frame[34..36] == [0x27, 0] && frame[56] == 0
}
fn roc_abort(frame: &[u8]) -> bool {
    frame.len() == 64 && frame[34..36] == [0x27, 0] && frame[56] == 0
}
fn authentication(algorithm: u8) -> impl Fn(&[u8]) -> bool {
    move |frame| frame.len() >= 30 && frame[0] == 0xb0 && frame[24..26] == [algorithm, 0]
}
/// A (Re)Association Request to the fixture AP (`wmm_tests::AP`).
fn association(frame: &[u8]) -> bool {
    frame.len() >= 28 && frame[0] == 0x00 && frame[16..22] == [2, 1, 2, 3, 4, 5]
}
const MAX_TRIES: usize = super::super::join::MLME_MAX_TRIES as usize;

/// The station's non-scatter frames from `from` that `kind` selects.
fn sent(session: &Session<Model>, from: usize, kind: impl Fn(&[u8]) -> bool) -> Vec<Vec<u8>> {
    session.backend.frames[from..]
        .iter()
        .filter(|(scatter, frame)| !*scatter && kind(frame))
        .map(|(_, frame)| frame.clone())
        .collect()
}

/// CNM firmware (`MT792x_FW_CAP_CNM`): every MLME try passes the join grant.
/// `interval_ms` overrides the granted interval (0: as requested).
fn with_cnm(session: &mut Session<Model>, interval_ms: u32) -> Result<Arc<RocModel>, &'static str> {
    let base = firmware(32);
    session.firmware =
        Firmware::prepare(&base.patch, &p2p::wm_features(0x80)).map_err(|_| "CNM firmware")?;
    let roc = Arc::new(RocModel::default());
    roc.interval_ms.store(interval_ms, Ordering::Release);
    session.backend.roc = Some(roc.clone());
    Ok(roc)
}

fn grants(session: &Session<Model>, from: usize) -> (usize, usize) {
    (
        sent(session, from, roc_acquire).len(),
        sent(session, from, roc_abort).len(),
    )
}

fn open_join(session: &mut Session<Model>, bss: &ScanBss) -> Result<u16, Error> {
    run(session.associate_station(bss, b"narf", Security::Open, test_permission(), &[]))
}

/// The AP takes (and ACKs) the first SAE Commit, but its Commit reply is
/// lost. After `IEEE80211_AUTH_TIMEOUT_SAE` the station re-sends the
/// identical Commit (`ieee80211_auth` re-sends `auth_data->data`), the AP
/// answers it, and the join completes. The retry comes after the 2 s grant
/// expired, so it takes a new grant; the Confirm reuses that live grant.
fn lost_commit_reply() -> Result<(), &'static str> {
    let (mut session, bss) =
        super::pmf_tests::prepared(super::pmf_tests::sae_ap(ApSaePwe::HashToElement));
    with_cnm(&mut session, 0)?;
    session.backend.lost_replies = 1;
    let start = session.backend.frames.len();
    if super::pmf_tests::join(&mut session, &bss, super::pmf_tests::sae()) != Ok(42) {
        return Err("SAE join did not survive a lost Commit reply");
    }
    let sae = sent(&session, start, authentication(3));
    if sae.len() != 3 || sae[0] != sae[1] || sae[1][26..28] != [1, 0] || sae[2][26..28] != [2, 0] {
        return Err("lost Commit reply was not answered by one identical Commit retry");
    }
    // Commit try 1, Commit try 2 (expired grant), association; the stale
    // grant, authentication end and association end are each aborted.
    if grants(&session, start) != (3, 3) {
        return Err("SAE retry did not renew the expired join grant exactly once");
    }
    if session.backend.access_point.as_ref().map(|ap| ap.phase())
        != Some(narf_wifi_fixtures::ApPhase::Authorized)
    {
        return Err("AP did not authorize the station after the retry");
    }
    Ok(())
}
fn mt76_sae_lost_commit_reply_resends_the_identical_commit_and_joins() -> TestResult {
    lost_commit_reply().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join/retry",
    mt76_sae_lost_commit_reply_resends_the_identical_commit_and_joins
);

/// The first Open System Authentication is lost on air: its TX status has
/// no ACK and the AP never saw it. mac80211 retries at once
/// (`auth_data->timeout = jiffies - 1`), not after a reply timeout: with a
/// 50 ms grant (shorter than `IEEE80211_AUTH_TIMEOUT_SHORT`) the retry
/// still finds the first grant live.
fn unacked_authentication() -> Result<(), &'static str> {
    let (mut session, bss) = super::wmm_tests::prepared(true, false);
    with_cnm(&mut session, 50)?;
    session.backend.unacked_management = 1;
    let start = session.backend.frames.len();
    if open_join(&mut session, &bss).is_err() {
        return Err("open join did not survive a non-ACKed Authentication");
    }
    let auth = sent(&session, start, authentication(0));
    if auth.len() != 2 || auth[0] != auth[1] || sent(&session, start, association).len() != 1 {
        return Err("non-ACKed Authentication was not re-sent exactly once");
    }
    if grants(&session, start) != (2, 2) {
        return Err("immediate retry did not reuse the live join grant");
    }
    Ok(())
}
fn mt76_unacked_authentication_is_retried_at_once_on_the_live_grant() -> TestResult {
    unacked_authentication().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join/retry",
    mt76_unacked_authentication_is_retried_at_once_on_the_live_grant
);

/// After `IEEE80211_AUTH_MAX_TRIES` (every reply lost) and
/// `IEEE80211_ASSOC_MAX_TRIES` (every request unacknowledged) the join
/// times out; nothing is sent past the third try and no grant is left.
fn gives_up() -> Result<(), &'static str> {
    let (mut session, bss) = super::wmm_tests::prepared(true, false);
    with_cnm(&mut session, 0)?;
    session.backend.lost_replies = usize::MAX;
    let start = session.backend.frames.len();
    if open_join(&mut session, &bss) != Err(Error::Timeout) {
        return Err("authentication with every reply lost did not time out");
    }
    if sent(&session, start, authentication(0)).len() != MAX_TRIES
        || !sent(&session, start, association).is_empty()
    {
        return Err("authentication not given up after IEEE80211_AUTH_MAX_TRIES");
    }
    let (acquired, aborted) = grants(&session, start);
    if acquired == 0 || acquired != aborted {
        return Err("authentication give-up left a join grant");
    }

    let (mut session, bss) = super::wmm_tests::prepared(true, false);
    with_cnm(&mut session, 0)?;
    session.backend.unacked_kind = Some(0x00);
    session.backend.unacked_management = usize::MAX;
    let start = session.backend.frames.len();
    if open_join(&mut session, &bss) != Err(Error::Timeout) {
        return Err("association with every request unacknowledged did not time out");
    }
    if sent(&session, start, authentication(0)).len() != 1
        || sent(&session, start, association).len() != MAX_TRIES
    {
        return Err("association not given up after IEEE80211_ASSOC_MAX_TRIES");
    }
    let (acquired, aborted) = grants(&session, start);
    if acquired == 0 || acquired != aborted {
        return Err("association give-up left a join grant");
    }
    Ok(())
}
fn mt76_join_gives_up_after_the_mac80211_try_limits() -> TestResult {
    gives_up().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/join/retry",
    mt76_join_gives_up_after_the_mac80211_try_limits
);
