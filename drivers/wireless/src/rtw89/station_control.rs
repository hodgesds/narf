// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A/B one-shot MAC0/PHY0 station controls. No packet/CMAC/DMA activation.
//!
//! RTL8852A takes RTL8852B's station codec: `rtw8852a_chip_info` has the
//! same `h2c_cctl_func_id` (`H2C_FUNC_MAC_CCTLINFO_UD`, 0x2),
//! `bacam_num` 2 / `bacam_ver` RTW89_BACAM_V0 and `addrcam_ver` 0 as
//! RTL8852B (Linux `rtw8852a.c:2434..2437,2472` @ 05441d6).
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
    pub(super) fn same(&self, other: &Self) -> bool {
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
    /// The retained radio's current typed primary is a 5GHz channel (the
    /// band-dependent CMAC lowest rate, SIFS and slot). Default 2.4GHz.
    fn ghz5(&mut self) -> bool {
        false
    }
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
    /// HE peer RA completed under the current association admission.
    he: Arc<AtomicBool>,
    /// QoS DATA TIDs admitted after WMM setup: bit0 (BE/TID0) for the WMM
    /// recipe, all eight for the signed all-AC program.
    tids: Arc<core::sync::atomic::AtomicU8>,
}
impl Peer {
    pub(super) fn admission_same(&self, admission: &Admission) -> bool {
        self.admission.same(admission)
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.valid, &other.valid) && self.own == other.own && self.peer == other.peer
    }
    pub(super) fn qos_ready(&self) -> bool {
        self.qos.load(Ordering::Acquire)
    }
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
        self.admits_profile(frame, false)
    }
    pub(super) fn admits_amsdu(&self, frame: &[u8]) -> bool {
        super::packet_format::amsdu(frame)
            && frame.get(16..22) == Some(self.peer.as_slice())
            && frame.get(1).is_some_and(|fc| fc & 0x80 == 0)
            && self.admits_profile(frame, true)
    }
    fn admits_profile(&self, frame: &[u8], amsdu: bool) -> bool {
        self.current().is_ok()
            && frame.len() >= 24
            && frame[4..10] == self.peer
            && frame[10..16] == self.own
            && (frame[1] & 0x80 == 0
                || frame[0] == 0x88
                    && self.he.load(Ordering::Acquire)
                    && frame.get(26..30) == Some(&super::he_htc::CONTROL))
            && (frame[0] != 0x88
                || self.qos.load(Ordering::Acquire)
                    && frame.get(25) == Some(&0)
                    && frame.get(24).is_some_and(|control| {
                        control & if amsdu { 0x68 } else { 0xe8 } == 0
                            && (control & 0x10 != 0) == (frame[1] & 0x80 != 0)
                            && self.tids.load(Ordering::Acquire) & (1 << (control & 7)) != 0
                    }))
    }
    fn invalidate(&self) {
        self.tids.store(0, Ordering::Release);
        self.qos.store(false, Ordering::Release);
        self.he.store(false, Ordering::Release);
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
    /// RTL8852A/B or RTL8852C: selects the CMAC control-table H2C
    /// (`h2c_cctl_func_id` `CCTLINFO_UD` / `CCTLINFO_UD_V1`).
    chip: ChipId,
    own: [u8; 6],
    secure: bool,
    phase: Phase,
    peer: Option<Peer>,
    admission: Option<Admission>,
    /// Static BA CAM entries (`rtw8852b bacam_num = 2`): owning TID.
    /// Static BA CAM owners: `bacam_num` 2 on A/B, 8 on C (only the first
    /// `bacam_num()` slots are used).
    ba_cam: [Option<u8>; 8],
    /// Random scan address currently in the address CAM SMA.
    scan: Option<[u8; 6]>,
    /// Committed association identifier (firmware-swap restore input).
    aid: Option<u16>,
    /// Last accepted `H2C_FUNC_OUTSRC_RA_MACIDCFG` body, replayed by
    /// `rtw89_wow_swap_fw` -> `rtw89_phy_ra_assoc`.
    ra: Option<[u8; 16]>,
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
        let chip = identity.chip();
        // RTL8851B takes B's station codec: `rtw8851b_chip_info` has the
        // same `h2c_cctl_func_id` (CCTLINFO_UD), `bacam_num` 2 /
        // `bacam_ver` RTW89_BACAM_V0 and `addrcam_ver` 0 as RTL8852B.
        // RTL8852A takes the same codec on the same fields
        // (`rtw8852a.c:2434..2437,2472` @ 05441d6).
        if !matches!(
            chip,
            ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
        ) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            chip,
            own: identity.mac(),
            secure: identity.fuses().enabled(),
            phase: Phase::New,
            peer: None,
            admission: None,
            ba_cam: [None; 8],
            scan: None,
            aid: None,
            ra: None,
        })
    }
    pub(super) fn own(&self) -> [u8; 6] {
        self.own
    }
    /// NHM noise monitoring is supported only on RTL8852A (Linux
    /// `rtw8852a.c:2419` `chip->support_noise`; `nhm::SUPPORT_NOISE_8852A`).
    /// This owner is the NHM caller the step-1 model was waiting for:
    /// entry points stay gated on this, never on the bare chip id.
    pub(super) fn supports_noise(&self) -> bool {
        self.chip == ChipId::Rtl8852A && super::nhm::SUPPORT_NOISE_8852A
    }
    /// fw.c `rtw89_fw_h2c_default_cmac_tbl` (class 5, `h2c_cctl_func_id`).
    fn default_cctl(&self) -> (u8, [u8; 68]) {
        if self.chip == ChipId::Rtl8852C {
            (codec::CCTL_V1, codec::default_cctl_v1())
        } else {
            (2, codec::default_cctl())
        }
    }
    /// fw.c `rtw89_fw_h2c_assoc_cmac_tbl` (class 5, `h2c_cctl_func_id`).
    fn fixed_cctl(&self, ghz5: bool) -> (u8, [u8; 68]) {
        if self.chip == ChipId::Rtl8852C {
            (codec::CCTL_V1, codec::fixed_cctl_v1(ghz5))
        } else {
            (2, codec::fixed_cctl(ghz5))
        }
    }
    /// `rtw8852a/b_chip_info.bacam_num` 2 / `rtw8852c_chip_info.bacam_num` 8.
    fn bacam_num(&self) -> usize {
        if self.chip == ChipId::Rtl8852C {
            8
        } else {
            2
        }
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
        self.ba_cam = [None; 8];
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
        // core.c `rtw89_core_start` -> `rtw89_fw_h2c_init_ba_cam`: C
        // (`RTW89_BACAM_V0_EXT`) arms its 8 dynamic BA CAM entries
        // (`bacam_num`..+`bacam_dynamic_num`, uid 0..7) with DONE_ACK.
        if self.chip == ChipId::Rtl8852C {
            for uid in 0..8u8 {
                let body = codec::init_ba_cam_v0_ext(8 + uid, uid);
                command(io, 0xc, 0, &body, true, Some(admission)).await?;
            }
        }
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
        let (function, body) = self.default_cctl();
        command(io, 5, function, &body, true, Some(admission)).await?;
        let ghz5 = io.ghz5();
        let (function, body) = self.fixed_cctl(ghz5);
        command(io, 5, function, &body, true, Some(admission)).await?;
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
            || self.scan.is_some()
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
            he: Arc::new(AtomicBool::new(false)),
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
    /// `rtw89_core_scan_start` / `rtw89_core_scan_complete` ->
    /// `rtw89_fw_h2c_cam`: point the passive address CAM SMA at a random
    /// scan address, or (`None`) back at the own address. A failed or
    /// cancelled update closes admission like every other controller step.
    pub(super) async fn scan_address(
        &mut self,
        io: &mut impl Interface,
        address: Option<[u8; 6]>,
        admission: &Admission,
    ) -> Result<(), Error> {
        let sma = address.unwrap_or(self.own);
        if self.phase() != Phase::Passive
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
            || self.peer.is_some()
            || address.is_some() == self.scan.is_some()
            || !unicast(sma)
        {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: None,
            armed: true,
        };
        command(
            io,
            6,
            0,
            &codec::cam(sma, [0; 6], 0, false, true),
            true,
            Some(admission),
        )
        .await?;
        admission.run(|| {
            self.scan = address;
            self.phase = Phase::Passive;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
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
        let ghz5 = io.ghz5();
        let (function, body) = self.fixed_cctl(ghz5);
        command(io, 5, function, &body, true, Some(admission)).await?;
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
            self.aid = Some(aid);
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// Associated-station facts a firmware swap restores: peer, AID and
    /// whether WMM (QoS NULL) is negotiated.
    pub(super) fn restore_facts(&self) -> Option<(Peer, u16, bool)> {
        if self.phase() != Phase::Associated {
            return None;
        }
        let peer = self.peer()?;
        let wmm = peer.qos_ready();
        Some((peer, self.aid?, wmm))
    }
    /// The station half of `wow.c::rtw89_wow_swap_fw` on a freshly
    /// downloaded image: `ROLE_MAINTAIN(FW_RESTORE)`, the assoc CMAC table
    /// (`fixed_cctl`, as `commit_peer`), `JOIN_INFO` connected, the AX v0
    /// address CAM (no `upd_mode` field) and, when firmware RA was handed
    /// over, `rtw89_phy_ra_assoc` with the retained body. `cam` is the
    /// address CAM body (security/WoL fields included by the caller).
    /// BSS colour and the UL-TB power offset are BB/MAC registers that the
    /// WCPU download does not reset; EDCA, BA CAM and WMM rows likewise.
    pub(super) async fn restore(
        &mut self,
        io: &mut impl Interface,
        cam: &[u8; 60],
        admission: &Admission,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.clone().ok_or(Error::Terminal)?;
        peer.current()?;
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: Some(peer.clone()),
            armed: true,
        };
        command(io, 8, 4, &codec::role_restore(), true, Some(admission)).await?;
        let ghz5 = io.ghz5();
        let (function, body) = self.fixed_cctl(ghz5);
        command(io, 5, function, &body, true, Some(admission)).await?;
        command(io, 8, 0, &codec::join(true), true, Some(admission)).await?;
        command(io, 6, 0, cam, true, Some(admission)).await?;
        if let Some(ra) = self.ra {
            admission.check()?;
            io.command(2, 1, 0, &ra, false, Some(admission)).await?;
        }
        admission.run(|| {
            peer.current()?;
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// The plain associated address CAM body `commit_peer` installed.
    pub(super) fn associated_cam(&self) -> Option<[u8; 60]> {
        let (peer, aid, _) = self.restore_facts()?;
        Some(codec::cam(self.own, peer.peer, aid, true, true))
    }
    pub(super) async fn configure_wmm(
        &mut self,
        io: &mut impl Interface,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &Admission,
    ) -> Result<(), Error> {
        let rows = codec::wmm_edca(p, short, io.ghz5()).ok_or(Error::Unsupported)?;
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
    /// `rtw89_core_acquire_sta_ba_entry` / `rtw89_core_release_sta_ba_entry`
    /// then `rtw89_fw_h2c_ba_cam` (DONE_ACK). When no static entry is
    /// available (and the TID is not 0/5 for replacement) Linux sends
    /// nothing: hardware creates a dynamic BA CAM entry itself.
    pub(super) async fn configure_ba(
        &mut self,
        io: &mut impl Interface,
        valid: bool,
        tid: u8,
        buf: u16,
        ssn: u16,
        admission: &Admission,
    ) -> Result<(), Error> {
        if tid > 7
            || self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.clone().ok_or(Error::Terminal)?;
        peer.current()?;
        let cams = &self.ba_cam[..self.bacam_num()];
        let entry = if valid {
            match cams.iter().position(Option::is_none) {
                Some(index) => Some(index),
                None if tid == 0 || tid == 5 => {
                    cams.iter().position(|owner| !matches!(owner, Some(0 | 5)))
                }
                None => None,
            }
        } else {
            cams.iter().position(|owner| *owner == Some(tid))
        };
        let Some(entry) = entry else {
            return Ok(());
        };
        self.ba_cam[entry] = valid.then_some(tid);
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: admission.clone(),
            peer: Some(peer.clone()),
            armed: true,
        };
        let body = if self.chip == ChipId::Rtl8852C {
            codec::ba_cam_v0_ext(valid, entry as u8, tid, buf, ssn)
        } else {
            codec::ba_cam(valid, entry as u8, tid, buf, ssn)
        };
        command(io, 0xc, 0, &body, true, Some(admission)).await?;
        admission.run(|| {
            peer.current()?;
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// `rtw89_phy_ra_assoc` -> `rtw89_fw_h2c_ra`: hand rate selection for
    /// the WMM-configured peer to firmware RA. Linux requests neither
    /// receive nor done ACK for this H2C.
    pub(super) async fn configure_ra(
        &mut self,
        io: &mut impl Interface,
        rates: u16,
        ht: Option<codec::HtRa>,
        he: Option<codec::HeRa>,
        admission: &Admission,
    ) -> Result<(), Error> {
        let body = match (ht, he) {
            (Some(ht), Some(he)) => codec::ra_he(rates, ht, he),
            // 6GHz: HE without HT (`link_sta->ht_cap` absent).
            (None, Some(he)) => codec::ra_he6(rates, he),
            (ht, None) => codec::ra_ht(rates, ht),
        }
        .ok_or(Error::Unsupported)?;
        self.configure_ra_body(io, body, he.is_some(), admission)
            .await
    }
    /// [`Self::configure_ra`] on an admitted 40/80MHz channel
    /// (`codec::ra_wide`: `bw_cap`, bandwidth SGI and the VHT branch).
    pub(super) async fn configure_ra_wide(
        &mut self,
        io: &mut impl Interface,
        rates: u16,
        ht: codec::HtRa,
        he: Option<codec::HeRa>,
        wide: codec::WideRa,
        admission: &Admission,
    ) -> Result<(), Error> {
        let body = codec::ra_wide(rates, ht, he, wide).ok_or(Error::Unsupported)?;
        self.configure_ra_body(io, body, he.is_some(), admission)
            .await
    }
    async fn configure_ra_body(
        &mut self,
        io: &mut impl Interface,
        body: [u8; 16],
        he: bool,
        admission: &Admission,
    ) -> Result<(), Error> {
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
        admission.check()?;
        io.command(2, 1, 0, &body, false, Some(admission)).await?;
        admission.run(|| {
            peer.current()?;
            self.ra = Some(body);
            peer.he.store(he, Ordering::Release);
            self.phase = Phase::Associated;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// mac80211 `IEEE80211_AMPDU_TX_OPERATIONAL`/`TX_STOP_*` ->
    /// `rtw89_ops_ampdu_action`: `rtw89_chip_h2c_ampdu_cmac_tbl` is NULL in
    /// `rtw8852b_chip_ops` (no H2C), then `rtw89_phy_ra_recalc_agg_limit`
    /// writes `R_AX_AMPDU_AGG_LIMIT` (0xc610) `B_AX_RA_TRY_RATE_AGG_LMT_MASK`
    /// [23:16] = clamp(min agg_num, 1, 256) - 1, or 0x3f with no TX session.
    pub(super) fn configure_agg_limit(
        &mut self,
        io: &mut impl Interface,
        agg_num: Option<u16>,
        admission: &Admission,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Associated
            || self.admission.as_ref().is_none_or(|a| !a.same(admission))
        {
            return Err(Error::Terminal);
        }
        let peer = self.peer.clone().ok_or(Error::Terminal)?;
        let limit = agg_num.map_or(0x3f, |n| u32::from(n.clamp(1, 256) - 1));
        checked(io, Some(admission), |io| {
            peer.current()?;
            modify(io, 0xc610, 0xff << 16, limit << 16)
        })
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
        let rows = codec::wmm_edca(p, short, io.ghz5()).ok_or(Error::Unsupported)?;
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
pub(super) fn checked<I: Interface, T>(
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
pub(super) fn read(io: &mut impl Io, register: u32) -> Result<u32, Error> {
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
pub(super) fn modify(io: &mut impl Io, register: u32, mask: u32, value: u32) -> Result<(), Error> {
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
pub(super) fn crypto_off(io: &mut impl Io) -> Result<(), Error> {
    modify(io, 0x9d00, 31, 0)?; // TX encryption and all hardware decryption
    modify(io, 0x9d04, 3, 0) // retain original MPDU: no appended MIC/ICV
}
fn tables(io: &mut impl Io) -> Result<(), Error> {
    tables_at(io, 0)
}
/// Nonsecure AX `rtw89_mac_dmac_tbl_init` + `rtw89_mac_cmac_tbl_init` for
/// one MACID, each indirect word read back.
pub(super) fn tables_at(io: &mut impl Io, macid: u8) -> Result<(), Error> {
    let (dmac, cmac, words) = codec::table_init(macid);
    for address in dmac {
        io.write32(0xc04, address)?;
        io.write32(0x40000, 0)?;
        if read(io, 0x40000)? != 0 {
            return Err(Error::Terminal);
        }
    }
    io.write32(0xc04, cmac)?;
    for (index, value) in words.into_iter().enumerate() {
        io.write32(0x40000 + index as u32 * 4, value)?;
        if read(io, 0x40000 + index as u32 * 4)? != value {
            return Err(Error::Terminal);
        }
    }
    Ok(())
}
pub(super) async fn command(
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
    pause_applied_at(io, 0, paused, admission).await
}
pub(super) async fn pause_applied_at(
    io: &mut impl Interface,
    macid: u8,
    paused: bool,
    admission: Option<&Admission>,
) -> Result<(), Error> {
    let (register, bit) = codec::pause_register(macid);
    // Linux reg.h R_AX_SS_MACID_PAUSE_0 / mac.c band1_enable_ax read
    // the actual scheduler pause bitmap. MACID_PAUSE requests RECV_ACK,
    // not DONE_ACK; neither CH12 retirement nor reception proves this bit.
    // The extra bounded applied-state fence is required by this one-shot STA.
    let start = io.now_us();
    loop {
        if (checked(io, admission, |io| read(io, register))? & bit != 0) == paused {
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
    let ghz5 = io.ghz5();
    for category in 0..4 {
        command(
            io,
            9,
            15,
            &codec::edca(category, short, ghz5),
            true,
            admission,
        )
        .await?;
    }
    Ok(())
}
#[path = "station_control/monitor.rs"]
mod monitor;
pub(super) use monitor::initialize as initialize_monitor;
#[path = "station_control/codec.rs"]
pub(super) mod codec;
pub(super) use codec::{HeRa, HtRa, VhtRa, WideRa};

pub(super) fn profile_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8852B MAC0 PHY0 STA MACID0 TX-A RX-AB legacy1 softwarecrypto v1");
    hash.update(&codec::default_cctl());
    hash.update(&codec::fixed_cctl(false));
    hash.update(&codec::edca(0, false, false));
    hash.update(&codec::edca(0, true, false));
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
/// Emitter program added by `radio_policy::Program::Ht`.
pub(super) fn ht_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B HT20 v1; HT cap SGI20 LDPC RXSTBC1 ampdu64K density0 RX MCS0..15 TX MCS0..7; no HT40/greenfield/TXSTBC/A-MPDU");
    hash.update(b"RA mode CCK|OFDM|HT mask HT1SS|SUBOFDM|SUBCCK, SGI20/LDPC from negotiation, STBC0, SS1; RX 20MHz MCS0..15 admitted");
    hash.update(&super::station_control::local_ht().capability_body());
    hash.finalize()
}
/// Emitter program added by `radio_policy::Program::He`.
pub(super) fn he_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B HE20 v2; rtw89_init_he_cap 2.4GHz STA restricted: HTC-HE; no 40MHz/BSR/OPS/A-MSDU-in-A-MPDU/STBC-TX/DCM-NSS2/beamformee/NG16/codebook/MaxNc; RX 2SS TX 1SS HE-MCS0..11");
    hash.update(b"HE +HTC raw30 Order+EOSP CAS 0x1b; host CCMP excludes HT Control/Order/EOSP from AAD; MACID0 AX RA report gates insertion at MCS>2; no EAPOL/ARP/DHCP/ICMP; reset clears RA state");
    hash.update(b"TXWD INFO1 A_CTRL_BSR for +HTC, BODY3 BK on every A-Control form change; no mixed-header hardware aggregates");
    hash.update(b"RA mode HE|CCK|OFDM mask HE1SS|SUBOFDM|SUBCCK from peer RX map, SGI20 from HT, LDPC/DCM from peer HE PHY, STBC0, SS1, ER0, no fixed GI/LTF");
    hash.update(b"data TXWD INFO0 DATA_ER when HE operation allows ER SU; RX HE NSS1/NSS2 MCS0..11 20MHz GI/LTF 0..5; HE TB/ER SU autonomous responses measured");
    hash.update(
        &local_he()
            .map(|he| he.capability_body())
            .unwrap_or_default(),
    );
    hash.finalize()
}
/// Emitter program added by `radio_policy::Program::Ampdu`.
pub(super) fn ampdu_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B originator BA v1; mac80211 agg-tx ADDBA request immediate policy A-MSDU-capable buf64 HT / buf128+ADDBA-ext HE timeout0 SSN=next QoS SN; ADDBA_RESP_INTERVAL 1s; HT_AGG_MAX_RETRIES 15; DELBA initiator on teardown/EAPOL");
    hash.update(b"data TXWD BODY3 AGG_EN, INFO1 MAX_AGGNUM=agg_num-1, INFO2 AMPDU_DENSITY=peer HT MPDU density; R_AX_AMPDU_AGG_LIMIT 0xc610[23:16]=min agg_num-1 else 0x3f; h2c_ampdu_cmac_tbl NULL on 8852B");
    hash.update(&[super::packet_core::AGG_WINDOW as u8]);
    hash.finalize()
}
/// Local HE capability: Linux `rtw89_init_he_cap` for a 2.4GHz station,
/// restricted to the retained TX-A/RX-AB 20MHz profile. Bits needing
/// 40MHz (`wide_channels`), a second TX path (STBC TX, DCM TX NSS2), HE
/// buffer-status reports (BSR), power save (OPS), RX A-MSDU (`aggregation`)
/// or beamforming feedback (`rtw89_mac_bf_assoc` sounding: SU beamformee,
/// NG16, codebook, triggered SU feedback, MaxNc) are clear.
pub(super) fn local_he() -> Option<narf_wireless::association::he::LocalHe> {
    const MAC: [u8; 6] = [
        0x01, // HTC_HE; host TX/RX admit HE A-Control
        0x08, // TF_MAC_PAD_DUR_16US
        0x02, // ALL_ACK
        0x10, // MAX_AMPDU_LEN_EXP_EXT_2
        0x00, // no OPS / AMSDU_IN_AMPDU
        0x80, // HT_VHT_TRIG_FRAME_RX
    ];
    const PHY: [u8; 11] = [
        0x00, // 20MHz only (no 40MHz-in-2.4GHz / 40-80MHz-in-5GHz bit)
        0x70, // DEVICE_CLASS_A | LDPC_CODING_IN_PAYLOAD | HE_LTF_AND_GI_0_8US
        0x1a, // NDP_4x_LTF_AND_3_2US | STBC_RX_UNDER_80MHZ | DOPPLER_TX
        0x1b, // DCM_MAX_CONST_RX_16_QAM | DCM_MAX_CONST_TX_16_QAM (NSS1)
        0x00, 0x00, 0x20, // PARTIAL_BW_EXT_RANGE
        0x06, // POWER_BOOST_FACTOR_SUPP | HE_SU_MU_PPDU_4XLTF_AND_08_US_GI
        0x91, // ER_SU_4XLTF_08 | ER_SU_1XLTF_08 | DCM_MAX_RU_996
        0xbd, // >16 SIGB | TX/RX 1024QAM <242 RU | full-BW SU in MU | 16us padding
        0x00,
    ];
    // RX MCS0..11 on both RX paths, TX MCS0..11 on the single TX path.
    narf_wireless::association::he::LocalHe::new(MAC, PHY, 0xfffa, 0xfffe).ok()
}
/// `local_he` with the core.c `rtw89_init_he_cap` HE PHY cap0 channel-width
/// bit of the band: `CHANNEL_WIDTH_SET_40MHZ_IN_2G` on 2.4GHz,
/// `CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G` on 5GHz (RTL8852B
/// `support_bandwidths` has no 160MHz). Every other bit is `local_he`'s.
/// Offered only for an admitted wide operating channel (`wide_phy`).
pub(super) fn local_he_wide(ghz5: bool) -> Option<narf_wireless::association::he::LocalHe> {
    use narf_wireless::association::he::LocalHe;
    let base = local_he()?;
    let narrow = base.capability();
    let mut phy = narrow.phy_capability();
    phy[0] = if ghz5 { 0x04 } else { 0x02 };
    LocalHe::new(narrow.mac_capability(), phy, 0xfffa, 0xfffe).ok()
}
/// One-stream (RTL8851B, `hal->rx_nss` = `tx_nss` = 1) HE/VHT MCS maps:
/// MCS0..11 (HE) / MCS0..9 (VHT) on NSS1 only (core.c `rtw89_init_he_cap`
/// / `rtw89_init_vht_cap` fill `rx_nss` streams, the rest "not supported").
const ONE_STREAM_MAP: u16 = 0xfffe;
/// `local_he` on the one-path RTL8851B: the same restricted MAC/PHY bits
/// with HE-MCS0..11 RX and TX on NSS1 only.
pub(super) fn local_he_1ss() -> Option<narf_wireless::association::he::LocalHe> {
    use narf_wireless::association::he::LocalHe;
    let he = local_he()?;
    let base = he.capability();
    LocalHe::new(
        base.mac_capability(),
        base.phy_capability(),
        ONE_STREAM_MAP,
        ONE_STREAM_MAP,
    )
    .ok()
}
/// `local_he_wide` on the one-path RTL8851B (rtw8851b.c
/// `support_bandwidths` 20/40/80MHz, no 160MHz), NSS1 maps.
pub(super) fn local_he_wide_1ss(ghz5: bool) -> Option<narf_wireless::association::he::LocalHe> {
    use narf_wireless::association::he::LocalHe;
    let he = local_he_wide(ghz5)?;
    let wide = he.capability();
    LocalHe::new(
        wide.mac_capability(),
        wide.phy_capability(),
        ONE_STREAM_MAP,
        ONE_STREAM_MAP,
    )
    .ok()
}
/// `local_vht80` on the one-path RTL8851B: VHT-MCS0..9 RX and TX on NSS1.
pub(super) fn local_vht80_1ss() -> Option<narf_wireless::association::phy::LocalVht> {
    let factor = local_ht().capability_body()[2] & 3;
    narf_wireless::association::phy::LocalVht::new(
        ONE_STREAM_MAP,
        ONE_STREAM_MAP,
        true,
        true,
        factor,
    )
    .ok()
    .map(|vht| vht.with_ldpc(true, true).with_rx_stbc(true))
}
/// RTL8851B HE20 emitter program: [`he_fingerprint`]'s recipe over the
/// one-stream capability body (`local_he_1ss`).
pub(super) fn he_fingerprint_1ss() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(
        b"RTL8851B HE20 v1; he_fingerprint recipe with RX 1SS TX 1SS HE-MCS0..11 (rx_nss 1)",
    );
    hash.update(&he_fingerprint());
    hash.update(
        &local_he_1ss()
            .map(|he| he.capability_body())
            .unwrap_or_default(),
    );
    hash.finalize()
}
/// RTL8851B wide-channel station capability bound by every RTL8851B
/// 40/80MHz record identity: the HT40 / one-stream VHT80 / HE-wide bodies
/// `wide_phy` offers on the one-path chip.
pub(super) fn wide_fingerprint_1ss() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8851B wide station v1; wide_fingerprint recipe with rtw89_init_vht_cap / rtw89_init_he_cap RX 1SS TX 1SS (rx_nss 1); no 160MHz");
    hash.update(&wide_fingerprint());
    if let Some(vht) = local_vht80_1ss() {
        hash.update(&vht.capability_body());
    }
    for ghz5 in [false, true] {
        hash.update(
            &local_he_wide_1ss(ghz5)
                .map(|he| he.capability_body())
                .unwrap_or_default(),
        );
    }
    hash.finalize()
}
/// Wide-channel station capability bound by every 40/80MHz record identity
/// (`radio_policy::Board::new_noninitial`): the exact HT40/VHT80/HE-wide
/// bodies `wide_phy` may offer on such a channel.
pub(super) fn wide_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B wide station v1; rtw89_init_ht_cap SUP_WIDTH_20_40 DSSSCCK40 SGI40; rtw89_init_vht_cap 5GHz SGI80 RXLDPC RXSTBC1 RX2SS TX1SS MCS0..9; HE PHY cap0 40MHz-2G / 40-80MHz-5G; offered only on the admitted chandef");
    hash.update(b"RA rtw89_phy_ra_sta_update HE>VHT>HT branch; BW_CAP link bandwidth 40/80; SGI HT SGI_40 / VHT SHORT_GI_80; VHT mask get_mcs_ra_mask(9,1) & VHT1SS|SUBOFDM|SUBCCK; LDPC peer; STBC0 SS1");
    if let Some(ht) = local_ht40() {
        hash.update(&ht.capability_body());
    }
    if let Some(vht) = local_vht80() {
        hash.update(&vht.capability_body());
    }
    for ghz5 in [false, true] {
        hash.update(
            &local_he_wide(ghz5)
                .map(|he| he.capability_body())
                .unwrap_or_default(),
        );
    }
    hash.finalize()
}
/// Local 20/40MHz HT capability: `local_ht` plus the core.c
/// `rtw89_init_ht_cap` width bits `SUP_WIDTH_20_40 | DSSSCCK40 | SGI_40`.
/// Every non-width field (MCS sets, A-MPDU factor/density, LDPC, RX STBC1,
/// no TX STBC/greenfield/large A-MSDU) is `local_ht`'s.
pub(super) fn local_ht40() -> Option<narf_wireless::association::phy::LocalHt> {
    use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt};
    let narrow = local_ht().capability_body();
    let mut mcs = [0; 10];
    mcs.copy_from_slice(&narrow[3..13]);
    let gi = HtGi {
        rx20: true,
        tx20: true,
        rx40: true,
        tx40: true,
    };
    Some(
        LocalHt::new(
            mcs,
            mcs,
            HtWidth::TwentyForty,
            gi,
            narrow[2] & 3,
            narrow[2] >> 2 & 7,
        )
        .ok()?
        .with_ldpc(true, true)
        .with_rx_stbc(true)
        .with_dsss_cck40(true),
    )
}
/// Local VHT80 capability on 5GHz: core.c `rtw89_init_vht_cap` restricted to
/// the retained TX-A/RX-AB profile: VHT-MCS0..9 RX on both paths and TX on
/// the single path (`hal->rx_nss` 2 / `tx_nss` 1 maps), SHORT_GI_80, RXLDPC
/// and RXSTBC_1. Cleared like the HT/HE profiles: TXSTBC (second TX path),
/// SU/MU beamformee and STS (no sounding feedback owner), HTC_VHT (no VHT
/// A-Control), the large `max_vht_mpdu_cap` (no large RX A-MSDU promise) and
/// the A-MPDU length exponent beyond the HT factor; no 160MHz on RTL8852B.
pub(super) fn local_vht80() -> Option<narf_wireless::association::phy::LocalVht> {
    let factor = local_ht().capability_body()[2] & 3;
    narf_wireless::association::phy::LocalVht::new(0xfffa, 0xfffe, true, true, factor)
        .ok()
        .map(|vht| vht.with_ldpc(true, true).with_rx_stbc(true))
}
/// RTL8852C local VHT160 capability: `local_vht80` plus the core.c
/// `rtw89_init_vht_cap` bits RTL8852C gets from `support_bandwidths &
/// BIT(NL80211_CHAN_WIDTH_160)`: `SUPP_CHAN_WIDTH_160MHZ` (Supported Channel
/// Width Set 1, contiguous 160 only; no 80+80) and `SHORT_GI_160`. VHT has
/// one MCS map for every width, so the 160MHz rates are the same
/// VHT-MCS0..9 RX two-stream / TX one-stream maps. Offered only for an
/// admitted C 160MHz chandef (`wide_phy`); never on RTL8852B.
pub(super) fn local_vht160() -> Option<narf_wireless::association::phy::LocalVht> {
    local_vht80().map(|vht| vht.with_160mhz(true, true))
}
/// RTL8852C 5GHz HE160 capability: `local_he_wide(true)` plus the core.c
/// `rtw89_init_he_cap` `support_bandwidths & BIT(NL80211_CHAN_WIDTH_160)`
/// bits: PHY cap0 `CHANNEL_WIDTH_SET_160MHZ_IN_5G`, cap8
/// `20MHZ_IN_160MHZ_HE_PPDU | 80MHZ_IN_160MHZ_HE_PPDU` and the 160MHz
/// HE-MCS/NSS set (`rx_mcs_160`/`tx_mcs_160` = the 80MHz maps, restricted
/// like them: RX MCS0..11 on both paths, TX on one). cap4
/// `BEAMFORMEE_MAX_STS_ABOVE_80MHZ_4` stays clear with the rest of the
/// beamformee bits (no sounding feedback owner).
pub(super) fn local_he160() -> Option<narf_wireless::association::he::LocalHe> {
    use narf_wireless::association::he::LocalHe;
    let base = local_he_wide(true)?;
    let wide = base.capability();
    let mut phy = wide.phy_capability();
    phy[8] |= 0x04 | 0x08;
    LocalHe::new(wide.mac_capability(), phy, 0xfffa, 0xfffe)
        .ok()?
        .with_160mhz(0xfffa, 0xfffe)
        .ok()
}
/// RTL8852C 160MHz station capability bound by every C 160MHz record
/// identity (`radio_policy_c::Board::new`): the exact HT40/VHT160/HE160
/// bodies `wide_phy` may offer on such a channel and the 160MHz RA recipe.
pub(super) fn wide160_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"C 160MHz station v1; rtw89_init_vht_cap SUPP_CHAN_WIDTH_160MHZ SHORT_GI_160 (same MCS maps); rtw89_init_he_cap PHY cap0 160MHz-5G cap8 20/80MHz-in-160 HE PPDU, mcs_160 = mcs_80; offered only on the admitted C 160MHz chandef");
    hash.update(b"RA rtw89_phy_ra_sta_update IEEE80211_STA_RX_BW_160 BW_CAP RTW89_CHANNEL_WIDTH_160 SGI VHT SHORT_GI_160; HE fix_giltf RTL8852C 160 SGI_4XHE08 if peer SU/MU 4xLTF 0.8us else 2XHE08; RX bound RTW89_CHANNEL_WIDTH_160");
    if let Some(ht) = local_ht40() {
        hash.update(&ht.capability_body());
    }
    if let Some(vht) = local_vht160() {
        hash.update(&vht.capability_body());
    }
    hash.update(
        &local_he160()
            .map(|he| he.capability_body())
            .unwrap_or_default(),
    );
    hash.finalize()
}
/// Local PHY for joining the AP at `primary` over an admitted 40/80MHz
/// (RTL8852C: also 5GHz 160MHz) operating channel, and that exact channel.
/// Mirrors mac80211 `ieee80211_determine_ap_chan` (the chandef is the
/// narrower of the AP's HT/VHT/HE operation and the local capability):
/// candidates are tried from widest (5GHz VHT160, VHT80, then HT40), and one
/// is used only when its selected chandef is exactly a profile in
/// `admitted` (a signed wide record whose host rule currently permits it).
/// The VHT160/HE160 candidate exists only when `admitted` holds a 160MHz
/// profile containing `primary` (only the RTL8852C `admitted_wide` lists
/// one) and is used only when its selected chandef is that 160MHz profile;
/// otherwise the 80MHz/40MHz candidates are tried unchanged. `None` keeps
/// the 20MHz join unchanged. HE is added (`local_he_wide`/`local_he160`)
/// only when `he` (the signed HE program). `one_stream` (RTL8851B) offers
/// the NSS1 VHT/HE bodies (`local_vht80_1ss`/`local_he_wide_1ss`); its
/// `admitted_wide` never lists a 160MHz profile.
pub(super) fn wide_phy(
    ies: &[u8],
    primary: u8,
    he: bool,
    one_stream: bool,
    admitted: &[super::operating_channel::Profile],
) -> Option<(
    narf_wireless::association::phy::LocalPhy,
    super::operating_channel::Profile,
)> {
    use super::operating_channel::Width as Bw;
    use narf_wireless::association::phy::{LocalPhy, Offer, Width};
    if admitted.is_empty() {
        return None;
    }
    let ghz5 = primary > 14;
    let ht = local_ht40()?;
    let c160 = ghz5
        && admitted
            .iter()
            .any(|p| p.width() == Bw::Mhz160 && p.subchannels().any(|ch| ch == primary));
    let mut candidates = alloc::vec::Vec::new();
    if c160 && !one_stream {
        let mut local = LocalPhy::vht160(ht, local_vht160()?).ok()?;
        if he {
            local = local.with_he(local_he160()?).ok()?;
        }
        candidates.push((local, true));
    }
    if ghz5 {
        let vht = if one_stream {
            local_vht80_1ss()?
        } else {
            local_vht80()?
        };
        candidates.push((LocalPhy::vht80(ht, vht).ok()?, false));
    }
    candidates.push((LocalPhy::ht40(ht).ok()?, false));
    for (mut local, wide160) in candidates {
        if he && !wide160 {
            let he = if one_stream {
                local_he_wide_1ss(ghz5)?
            } else {
                local_he_wide(ghz5)?
            };
            local = local.with_he(he).ok()?;
        }
        let Ok(Some(offer)) = Offer::from_elements(local, ies, primary) else {
            continue;
        };
        if offer.discontiguous() {
            continue;
        }
        let width = match offer.width() {
            Width::Forty if !wide160 => Bw::Mhz40,
            Width::Eighty if !wide160 => Bw::Mhz80,
            Width::OneSixty if wide160 => Bw::Mhz160,
            _ => continue,
        };
        let center = offer.center_channel();
        let profile = if width == Bw::Mhz160 {
            super::operating_channel::Profile::new_5ghz_160(primary)
        } else {
            super::operating_channel::Profile::new_wide(primary, width, center > primary)
        };
        let Some(profile) = profile.filter(|p| p.center() == center) else {
            continue;
        };
        if admitted.contains(&profile) {
            return Some((local, profile));
        }
    }
    None
}
/// Local HT20 capability (Linux `rtw89_init_ht_cap` restricted to the
/// retained TX-A/RX-AB 20MHz profile).
pub(super) fn local_ht() -> narf_wireless::association::phy::LocalHt {
    narf_wireless::association::phy::LocalHt::siso20(true, true)
        .with_ldpc(true, true)
        .with_rx_stbc(true)
}
/// Emitter program added by `radio_policy::Program::FirmwareRa`.
pub(super) fn firmware_ra_fingerprint() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"B firmware RA v1; H2C OUTSRC cat2 class1 func0 RA_MACIDCFG AX no-CSI; rtw89_phy_ra_sta_update legacy CCK|OFDM mask &= OFDM|SUBCCK, recover; 20MHz SS1 MACID0 UPD_ALL init_rate_lv0");
    hash.update(b"data TXWD INFO0 USE_RATE=0 DISDATAFB=0; INFO1 DATA_RTY_LOWEST_RATE=lowest negotiated; management/EAPOL CCK1 fixed");
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
pub(super) fn wmm_admit(
    p: narf_wireless::wmm::Parameters,
    short: bool,
    ghz5: bool,
) -> Result<(), Error> {
    codec::wmm_edca(p, short, ghz5)
        .map(|_| ())
        .ok_or(Error::Unsupported)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_control/tests.rs"]
pub(super) mod tests;
