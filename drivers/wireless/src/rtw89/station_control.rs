// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B one-shot MAC0/PHY0 station controls. No packet/CMAC/DMA activation.
use super::{
    factory::Factory,
    mac::ChipId,
    power::{self, Io},
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
pub(super) type Error = power::Error;

#[derive(Clone)]
pub(super) struct Admission {
    closed: Arc<AtomicBool>,
    teardown: Arc<AtomicBool>,
    publication: Arc<IrqSafeSpinLock<()>>,
}
pub(super) struct Disconnect {
    admission: Admission,
}
impl Drop for Disconnect {
    fn drop(&mut self) {
        let _publication = self.admission.publication.lock();
        self.admission.teardown.store(false, Ordering::Release);
    }
}
impl Admission {
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.publication, &other.publication)
    }
    pub(super) fn new() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            teardown: Arc::new(AtomicBool::new(false)),
            publication: Arc::new(IrqSafeSpinLock::new(())),
        }
    }
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.closed() {
            Err(Error::Terminal)
        } else {
            Ok(())
        }
    }
    pub(super) fn run<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let _publication = self.publication.lock();
        self.check()?;
        operation()
    }
    pub(super) fn close(&self) {
        let _publication = self.publication.lock();
        self.closed.store(true, Ordering::Release);
    }
    pub(super) fn teardown_pending(&self) -> bool {
        self.teardown.load(Ordering::Acquire)
    }
    pub(super) fn begin_disconnect(&self) -> Result<Disconnect, Error> {
        let _publication = self.publication.lock();
        if self.teardown.load(Ordering::Acquire) {
            return Err(Error::Terminal);
        }
        self.teardown.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        Ok(Disconnect {
            admission: self.clone(),
        })
    }
}

/// Current authority encloses the entire register transaction. Commands retain
/// their exact sequence/identity through real terminal transport and successful
/// DONE_ACK where requested. `admission` is checked again after waits and held
/// around the final native publication; None is terminal cleanup only.
#[async_trait::async_trait]
pub(super) trait Interface: Io + Send {
    /// Validate the exact retained B owner and complete register aperture
    /// before the first station write, including0x4001f for nonsecure tables.
    fn preflight(&mut self, indirect: bool) -> Result<(), Error>;
    fn with_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error>;
    async fn command(
        &mut self,
        category: u8,
        class: u8,
        function: u8,
        body: &[u8],
        done_ack: bool,
        admission: Option<&Admission>,
    ) -> Result<(), Error>;
}

/// Only this retained controller constructs a peer binding. Its invalidation
/// precedes terminal disconnect/cancellation, so a late command completion can
/// never revive an earlier packet peer. This is no radio/power authority.
#[derive(Clone)]
pub(super) struct Peer {
    own: [u8; 6],
    peer: [u8; 6],
    valid: Arc<AtomicBool>,
    admission: Admission,
    qos: Arc<AtomicBool>,
    /// QoS DATA TIDs admitted after WMM setup: bit0 (BE/TID0) for the WMM
    /// recipe, all eight for the signed all-AC program.
    tids: Arc<core::sync::atomic::AtomicU8>,
}
impl Peer {
    pub(super) fn own(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn bssid(&self) -> [u8; 6] {
        self.peer
    }
    pub(super) fn mac_id(&self) -> u8 {
        0
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        self.admission.check()?;
        if self.valid.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Error::Terminal)
        }
    }
    pub(super) fn admits(&self, frame: &[u8]) -> bool {
        self.current().is_ok()
            && frame.len() >= 24
            && frame[4..10] == self.peer
            && frame[10..16] == self.own
            && (frame[0] != 0x88
                || self.qos.load(Ordering::Acquire)
                    && frame.get(25) == Some(&0)
                    && frame.get(24).is_some_and(|control| {
                        control & 0xf8 == 0
                            && self.tids.load(Ordering::Acquire) & (1 << control) != 0
                    }))
    }
    fn invalidate(&self) {
        self.tids.store(0, Ordering::Release);
        self.qos.store(false, Ordering::Release);
        self.valid.store(false, Ordering::Release);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    Passive,
    PeerPrepared,
    Associated,
    Stopped,
    Failed,
}
pub(super) struct Controller {
    own: [u8; 6],
    secure: bool,
    phase: Phase,
    peer: Option<Peer>,
    admission: Option<Admission>,
}
struct Attempt {
    admission: Admission,
    peer: Option<Peer>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            if let Some(peer) = &self.peer {
                peer.invalidate();
            }
            self.admission.close();
        }
    }
}
impl Controller {
    pub(super) fn new(factory: &Factory) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Terminal)?;
        if identity.chip() != ChipId::Rtl8852B {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            own: identity.mac(),
            secure: identity.fuses().enabled(),
            phase: Phase::New,
            peer: None,
            admission: None,
        })
    }
    pub(super) fn own(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn phase(&self) -> Phase {
        if self.admission.as_ref().is_some_and(Admission::closed) && self.phase != Phase::Stopped {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peer(&self) -> Option<Peer> {
        self.peer.as_ref().filter(|p| p.current().is_ok()).cloned()
    }
    pub(super) fn invalidate(&mut self) {
        self.phase = Phase::Failed;
        if let Some(peer) = &self.peer {
            peer.invalidate();
        }
    }
    pub(super) async fn initialize(
        &mut self,
        io: &mut impl Interface,
        admission: &Admission,
    ) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Failed;
        self.admission = Some(admission.clone());
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: None,
            armed: true,
        };
        checked(io, Some(admission), |io| {
            io.preflight(!self.secure)?;
            if read(io, 0xc000)? & (1 << 29) != 0 {
                return Err(Error::Unsupported);
            }
            port(io, false)?;
            crypto_off(io)?;
            if !self.secure {
                tables(io)?;
            }
            Ok(())
        })?;
        command(io, 9, 8, &codec::pause(false), false, Some(admission)).await?;
        pause_applied(io, false, Some(admission)).await?;
        command(io, 8, 4, &codec::role(false), true, Some(admission)).await?;
        command(io, 8, 0, &codec::join(false), true, Some(admission)).await?;
        command(
            io,
            6,
            0,
            &codec::cam(self.own, [0; 6], 0, false, true),
            true,
            Some(admission),
        )
        .await?;
        command(io, 5, 2, &codec::default_cctl(), true, Some(admission)).await?;
        command(io, 5, 2, &codec::fixed_cctl(), true, Some(admission)).await?;
        edca(io, false, Some(admission)).await?;
        checked(io, Some(admission), awake)?;
        admission.run(|| {
            self.phase = Phase::Passive;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn prepare_peer(
        &mut self,
        io: &mut impl Interface,
        bssid: [u8; 6],
        admission: &Admission,
    ) -> Result<Peer, Error> {
        if self.phase() != Phase::Passive
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
            || self.peer.is_some()
            || !unicast(bssid)
            || bssid == self.own
        {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let peer = Peer {
            own: self.own,
            peer: bssid,
            valid: Arc::new(AtomicBool::new(false)),
            admission: admission.clone(),
            qos: Arc::new(AtomicBool::new(false)),
            tids: Arc::new(core::sync::atomic::AtomicU8::new(0)),
        };
        self.peer = Some(peer.clone());
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: Some(peer.clone()),
            armed: true,
        };
        command(
            io,
            6,
            0,
            &codec::cam(self.own, bssid, 0, false, true),
            true,
            Some(admission),
        )
        .await?;
        admission.run(|| {
            peer.valid.store(true, Ordering::Release);
            self.phase = Phase::PeerPrepared;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(peer)
    }
    pub(super) async fn commit_peer(
        &mut self,
        io: &mut impl Interface,
        bssid: [u8; 6],
        aid: u16,
        short_slot: bool,
        admission: &Admission,
    ) -> Result<(), Error> {
        if self.phase() != Phase::PeerPrepared
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
            || !(1..=2007).contains(&aid)
            || self
                .peer
                .as_ref()
                .is_none_or(|p| p.peer != bssid || p.current().is_err())
        {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: self.peer.clone(),
            armed: true,
        };
        command(io, 5, 2, &codec::fixed_cctl(), true, Some(admission)).await?;
        command(io, 8, 0, &codec::join(true), true, Some(admission)).await?;
        command(
            io,
            6,
            0,
            &codec::cam(self.own, bssid, aid, true, true),
            true,
            Some(admission),
        )
        .await?;
        edca(io, short_slot, Some(admission)).await?;
        checked(io, Some(admission), |io| {
            awake(io)?;
            crypto_off(io)?;
            port(io, true)
        })?;
        admission.run(|| {
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn configure_wmm(
        &mut self,
        io: &mut impl Interface,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &Admission,
    ) -> Result<(), Error> {
        let rows = codec::wmm_edca(p, short).ok_or(Error::Unsupported)?;
        if self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.clone().ok_or(Error::Terminal)?;
        peer.current()?;
        if peer.qos.load(Ordering::Acquire) {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: Some(peer.clone()),
            armed: true,
        };
        for row in rows {
            command(io, 9, 15, &row, true, Some(admission)).await?;
        }
        admission.run(|| {
            peer.current()?;
            peer.tids.store(1, Ordering::Release);
            peer.qos.store(true, Ordering::Release);
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// Admit TID0..7 on an already WMM-configured peer. Callers grant this
    /// only under the signed all-AC QoS operating program.
    pub(super) fn admit_all_tids(&self, admission: &Admission) -> Result<(), Error> {
        if self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.as_ref().ok_or(Error::Terminal)?;
        admission.run(|| {
            peer.current()?;
            if !peer.qos.load(Ordering::Acquire) {
                return Err(Error::Terminal);
            }
            peer.tids.store(0xff, Ordering::Release);
            Ok(())
        })
    }
    /// Live AP EDCA change on an admitted QoS peer (mac80211
    /// `ieee80211_sta_wmm_params` -> `rtw89_ops_conf_tx` ->
    /// `__rtw89_conf_tx` -> `rtw89_fw_h2c_set_edca` per AC). The QoS token
    /// stays valid while the four rows are reprogrammed, as in Linux; a
    /// failed/cancelled update invalidates the peer and closes admission.
    pub(super) async fn update_wmm(
        &mut self,
        io: &mut impl Interface,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &Admission,
    ) -> Result<(), Error> {
        let rows = codec::wmm_edca(p, short).ok_or(Error::Unsupported)?;
        if self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.clone().ok_or(Error::Terminal)?;
        peer.current()?;
        if !peer.qos.load(Ordering::Acquire) {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: Some(peer.clone()),
            armed: true,
        };
        for row in rows {
            command(io, 9, 15, &row, true, Some(admission)).await?;
        }
        admission.run(|| {
            peer.current()?;
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn disconnect(
        &mut self,
        io: &mut impl Interface,
        admission: &Admission,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::New | Phase::Stopped)
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let reservation = if admission.teardown_pending() {
            None
        } else {
            Some(admission.begin_disconnect()?)
        };
        self.invalidate(); // before any awaited or native disconnect operation
        admission.close();
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: self.peer.clone(),
            armed: true,
        };
        checked(io, None, |io| port(io, false))?;
        command(io, 8, 0, &codec::join(false), true, None).await?;
        let peer = self.peer.as_ref().map_or([0; 6], |p| p.peer);
        command(
            io,
            6,
            0,
            &codec::cam(self.own, peer, 0, false, false),
            true,
            None,
        )
        .await?;
        command(io, 8, 4, &codec::role(true), true, None).await?;
        command(io, 9, 8, &codec::pause(true), false, None).await?;
        pause_applied(io, true, None).await?;
        self.phase = Phase::Stopped;
        attempt.armed = false;
        drop(reservation);
        Ok(())
    }
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
fn checked<I: Interface, T>(
    io: &mut I,
    admission: Option<&Admission>,
    operation: impl FnOnce(&mut I) -> Result<T, Error>,
) -> Result<T, Error> {
    if let Some(admission) = admission {
        admission.run(|| io.with_current(operation))
    } else {
        io.with_current(operation)
    }
}
fn read(io: &mut impl Io, register: u32) -> Result<u32, Error> {
    let value = io.read32(register)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
/// Source mac.c::check_cpwm_state / ps.c::fw_leave_lps_check for MACID0.
/// Caller encloses both actual reads in its current-capability/publication
/// scope. This observes awake state; it never enters PS or invents a wake ACK.
pub(super) fn awake(io: &mut impl Io) -> Result<(), Error> {
    if read(io, 0x1e8)? & (1 << 31) != 0 || read(io, 0xca0c)? & 0xe != 0 {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}
fn modify(io: &mut impl Io, register: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, register)?;
    io.write32(register, (old & !mask) | (value & mask))?;
    if read(io, register)? & mask != value & mask {
        return Err(Error::Terminal);
    }
    Ok(())
}
fn port(io: &mut impl Io, associated: bool) -> Result<(), Error> {
    // Port0 STA only, no autonomous beacon/force-TX or TSF offload service.
    let mask = (3 << 10) | (1 << 12) | (1 << 9) | (1 << 3) | (1 << 4) | (1 << 2);
    let value = (1 << 2) | if associated { (2 << 10) | (1 << 4) } else { 0 };
    modify(io, 0xc400, mask, value)
}
fn crypto_off(io: &mut impl Io) -> Result<(), Error> {
    modify(io, 0x9d00, 31, 0)?; // TX encryption and all hardware decryption
    modify(io, 0x9d04, 3, 0) // retain original MPDU: no appended MIC/ICV
}
fn tables(io: &mut impl Io) -> Result<(), Error> {
    for index in 0..4 {
        io.write32(0xc04, 0x1880_0000 + index * 4)?;
        io.write32(0x40000, 0)?;
        if read(io, 0x40000)? != 0 {
            return Err(Error::Terminal);
        }
    }
    io.write32(0xc04, 0x1884_0000)?;
    for (index, value) in [4, 0x400a_0004, 0, 0, 0, 0x0e43_000b, 0, 0x000b_8109]
        .into_iter()
        .enumerate()
    {
        io.write32(0x40000 + index as u32 * 4, value)?;
        if read(io, 0x40000 + index as u32 * 4)? != value {
            return Err(Error::Terminal);
        }
    }
    Ok(())
}
async fn command(
    io: &mut impl Interface,
    class: u8,
    function: u8,
    body: &[u8],
    done_ack: bool,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    if let Some(admission) = admission {
        admission.check()?;
    }
    io.command(1, class, function, body, done_ack, admission)
        .await?;
    if let Some(admission) = admission {
        admission.check()?;
    }
    Ok(())
}
async fn pause_applied(
    io: &mut impl Interface,
    paused: bool,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    // Linux reg.h R_AX_SS_MACID_PAUSE_0 / mac.c band1_enable_ax read
    // the actual scheduler pause bitmap. MACID_PAUSE requests RECV_ACK,
    // not DONE_ACK; neither CH12 retirement nor reception proves this bit.
    // The extra bounded applied-state fence is required by this one-shot STA.
    let start = io.now_us();
    loop {
        if checked(io, admission, |io| read(io, 0x9eb0))? & 1 == u32::from(paused) {
            return Ok(());
        }
        if io.now_us().saturating_sub(start) >= 10_000 {
            return Err(Error::Timeout);
        }
        if let Some(admission) = admission {
            admission.check()?;
        }
        io.delay_us(10).await;
    }
}
async fn edca(
    io: &mut impl Interface,
    short: bool,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    for category in 0..4 {
        command(io, 9, 15, &codec::edca(category, short), true, admission).await?;
    }
    Ok(())
}
#[path = "station_control/codec.rs"]
mod codec;

pub(super) fn profile_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8852B MAC0 PHY0 STA MACID0 TX-A RX-AB legacy1 softwarecrypto v1");
    hash.update(&codec::default_cctl());
    hash.update(&codec::fixed_cctl());
    hash.update(&codec::edca(0, false));
    hash.update(&codec::edca(0, true));
    hash.update(b"SEC_ENG_CTRL[4:0]=0 SEC_MPDU_PROC[1:0]=0 no security CAM keys");
    hash.finalize()
}
pub(super) fn wmm_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B WMM v2 AP response-bound; BE/TID0 negotiated legacy DATA raw26 halfwords13; noHT/BA/UAPSD/TSPEC; source H2C MAC9 class15 fourAC ACK; BE ECWmin>=5 max>=10 AIFSN>=3 TXOP0 SIFS10 long20/short9; noAP ACM BE; bounded AIFS8bit");
    hash.update(b"TXWD_INFO0 DATA_RATE[24:16] USE_RATE DISDATAFB; common response rate intersection; management/EAPOL CCK1");
    hash.update(&[11, 10, 9, 8, 7, 6, 3, 5, 4, 2, 1, 0]);
    hash.update(&narf_wireless::wmm::INFORMATION);
    hash.finalize()
}
/// Emitter program added by `radio_policy::Program::QosAll`.
pub(super) fn qos_all_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B WMM all-AC v1; cfg80211_classify8021d RFC8325 DSCP; mac80211 ieee802_1d_to_ac + ACM downgrade; TID0..7 QoS raw26");
    hash.update(b"rtw89_core_get_qsel BE0=0 BK0=1 VI0=2 VO0=3; rtw89_core_get_ch_dma ACH0..3; TXWD_BODY2 TID_INDICATE tids2,3,5,7; DMA_STOP1 ACH0..3+CH8+WPDMA");
    hash.update(b"single in-flight host strict priority VO>VI>BE>BK; per-AC EDCA rows unchanged from WMM v2; no BA/A-MPDU");
    hash.update(&[0, 1, 1, 0, 2, 2, 3, 3]);
    hash.finalize()
}
pub(super) fn wmm_admit(p: narf_wireless::wmm::Parameters, short: bool) -> Result<(), Error> {
    codec::wmm_edca(p, short)
        .map(|_| ())
        .ok_or(Error::Unsupported)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_control/tests.rs"]
pub(super) mod tests;
