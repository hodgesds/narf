// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B AP-mode MAC/firmware control owner for one AP link on MAC0,
//! port0, MACID0 with address/BSSID CAM entry 0, and its AP-client peers.
//!
//! Sources (Linux rtw89):
//! - mac.c `rtw89_mac_vif_init`/`_deinit`, `rtw89_mac_port_update` and
//!   every `rtw89_mac_port_cfg_*` step, `rtw89_mac_bcn_drop`,
//!   `rtw89_mac_check_packet_ctrl`, `rtw89_mac_stop_ap`,
//!   `rtw89_mac_dmac_tbl_init`/`_cmac_tbl_init`, `rtw89_mac_set_macid_pause`;
//! - mac80211.c `rtw89_ops_start_ap`/`_stop_ap`, `BSS_CHANGED_BEACON`;
//! - core.c `rtw89_core_sta_link_add`/`_assoc`/`_disconnect`/`_remove`
//!   (AP branches), `rtw89_acquire_mac_id` (lowest free of
//!   `RTW89_MAX_MAC_ID_NUM`);
//! - cam.c `rtw89_cam_init_addr_cam`/`_deinit_addr_cam`
//!   (`rtw89_cam_get_avail_addr_cam`, `acam_num` 128 on RTL8852B);
//! - fw.c `rtw89_fw_h2c_default_cmac_tbl`/`_assoc_cmac_tbl`, `_cam`,
//!   `_role_maintain`, `_join_info`, `_update_beacon`, `_macid_pause`, `_ra`.
//!
//! This owner holds no radio/power/channel authority: it runs over the
//! same retained `station_control::Interface` (current device capability
//! around every register transaction, exact H2C DONE_ACK) and is
//! fail-closed like the station controller. Host crypto is retained
//! (`crypto_off`, `RTW89_ADDR_CAM_SEC_NORMAL` with no security entries), so
//! per-peer keys stay with the host RSNA owner. The native AP data path
//! (multi-peer TXWD MACID/port, RX MACID classification, HIQ/CH9 ring),
//! the public AP controls and a signed AP channel/power admission are not
//! part of this owner.
use super::{
    ap_wire::{self, ApLink, UpdMode},
    factory::Factory,
    mac::ChipId,
    power::Io,
    station_control::{self as control, codec, Admission, Interface},
};
use alloc::vec::Vec;

type Error = control::Error;

/// `RTW89_MAX_MAC_ID_NUM` (RTL8852B `support_macid_num`).
pub(super) const MAX_MAC_ID: usize = 128;
/// RTL8852B `acam_num`.
pub(super) const ADDR_CAM_NUM: usize = 128;
/// mac.c `BCN_INTERVAL` (used while `beacon_int` is 0).
pub(super) const BCN_INTERVAL: u16 = 100;
const BCN_ERLY_DEF: u32 = 160;
const BCN_SETUP_DEF: u32 = 2;
const BCN_HOLD_DEF: u32 = 200;
const BCN_MASK_DEF: u32 = 0;
const TBTT_ERLY_DEF: u16 = 5;
const TBTT_AGG_DEF: u16 = 1;
const BCN_ERLY_SET_DLY_US: u64 = 10 * 2;

// AX port0 / MAC0 registers (reg.h); port0 adds no `port * 0x40` offset.
const PORT_CFG: u32 = 0xc400;
const TBTT_PROHIB: u32 = 0xc404;
const BCN_AREA: u32 = 0xc408;
const BCN_EARLY: u32 = 0xc40c;
const TBTT_EARLY: u32 = 0xc40e;
const TBTT_AGG: u32 = 0xc412;
const BCN_SPACE: u32 = 0xc414;
const DTIM_CTRL: u32 = 0xc426;
const BCN_CNT_TMR: u32 = 0xc434;
const BCN_DROP_ALL: u32 = 0xc560;
const HGQ_WINDOW: u32 = 0xc590;
const MBSSID_DROP: u32 = 0xc63c;
const BSS_COLOR: u32 = 0xc6a0;
const PTCL_DBG_INFO: u32 = 0xc6f0;
const PTCL_DBG: u32 = 0xc6f4;
const MD_TSFT_STMP_CTL: u32 = 0xca08;
const BCN_PSR_RPT: u32 = 0xce84;

const BRK_SETUP: u32 = 1 << 16;
const TBTT_PROHIB_EN: u32 = 1 << 13;
const BCNTX_EN: u32 = 1 << 12;
const NET_TYPE_MASK: u32 = 3 << 10;
const TSFTR_RST: u32 = 1 << 5;
const RX_BSSID_FIT_EN: u32 = 1 << 4;
const TSF_UDT_EN: u32 = 1 << 3;
const PORT_FUNC_EN: u32 = 1 << 2;
const TXBCN_RPT_EN: u32 = 1 << 1;
const RXBCN_RPT_EN: u32 = 1;
const TBTT_HOLD_MASK: u32 = 0x0fff_0000;
const TBTT_SETUP_MASK: u32 = 0xff;
const BCN_MSK_AREA_MASK: u32 = 0x0fff_0000;
const BCNERLY_MASK: u32 = 0xfff;
const TBTTERLY_MASK: u16 = 0xfff;
const TBTT_AGG_NUM_MASK: u16 = 0xff00;
const BCN_SPACE_MASK: u32 = 0xffff;
const DTIM_NUM_MASK: u16 = 0xff00;
const UPD_HGQMD_TIMIE: u8 = 0b11;
const BSS_COLOR_P0_MASK: u32 = 0x3f;
const PORT_DROP_SHIFT: u32 = 16;
const BCAID_P0_MASK: u32 = 0x7ff;
const PTCL_DBG_EN: u32 = 1 << 8;
const PTCL_DBG_SEL_MASK: u32 = 0xff;
const PTCL_DBG_BCNQ_NUM0: u32 = 8;
const PTCL_DBG_BCNQ_NUM1: u32 = 9;

/// The `ieee80211_bss_conf` facts `rtw89_mac_port_update` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PortConfig {
    /// `beacon_int` in TU; 0 selects `BCN_INTERVAL`.
    pub(super) beacon_interval: u16,
    /// `dtim_period` (0 before `start_ap`).
    pub(super) dtim_period: u8,
}
impl PortConfig {
    /// `add_interface` time: no beacon interval or DTIM period yet.
    pub(super) const IDLE: Self = Self {
        beacon_interval: 0,
        dtim_period: 0,
    };
    fn interval(&self) -> u16 {
        if self.beacon_interval == 0 {
            BCN_INTERVAL
        } else {
            self.beacon_interval
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    /// `rtw89_mac_vif_init` completed (`add_interface`).
    Ready,
    /// `rtw89_ops_start_ap` completed; beacons may be published.
    Started,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ApPeer {
    pub(super) addr: [u8; 6],
    pub(super) macid: u8,
    /// Address-CAM index while associated.
    pub(super) addr_cam: Option<u8>,
    pub(super) aid: u16,
}

/// Fixed-size index allocator: lowest clear bit (`find_first_zero_bit`).
#[derive(Clone, Copy, Debug)]
struct Bitmap([u32; 4]);
impl Bitmap {
    fn acquire(&mut self, limit: usize) -> Option<u8> {
        let index = (0..limit).find(|&i| self.0[i / 32] & (1 << (i % 32)) == 0)?;
        self.0[index / 32] |= 1 << (index % 32);
        Some(index as u8)
    }
    fn release(&mut self, index: u8) {
        let index = usize::from(index);
        self.0[index / 32] &= !(1 << (index % 32));
    }
}

/// Closes admission unless disarmed (same fail-closed rule as the station
/// controller: a partial firmware/MAC transition is never reused).
struct Armed(Option<Admission>);
impl Drop for Armed {
    fn drop(&mut self) {
        if let Some(admission) = self.0.take() {
            admission.close();
        }
    }
}
impl Armed {
    fn disarm(mut self) {
        self.0 = None;
    }
}

pub(super) struct ApController {
    own: [u8; 6],
    secure: bool,
    phase: Phase,
    admission: Option<Admission>,
    link: ApLink,
    config: PortConfig,
    macids: Bitmap,
    addr_cams: Bitmap,
    peers: Vec<ApPeer>,
}

impl ApController {
    pub(super) fn new(factory: &Factory) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Terminal)?;
        if identity.chip() != ChipId::Rtl8852B {
            return Err(Error::Unsupported);
        }
        Ok(Self::with_identity(
            identity.mac(),
            identity.fuses().enabled(),
        ))
    }
    fn with_identity(own: [u8; 6], secure: bool) -> Self {
        // The AP vif holds MACID0, address CAM 0 and BSSID CAM 0.
        let mut macids = Bitmap([0; 4]);
        let mut addr_cams = Bitmap([0; 4]);
        macids.acquire(MAX_MAC_ID);
        addr_cams.acquire(ADDR_CAM_NUM);
        Self {
            own,
            secure,
            phase: Phase::New,
            admission: None,
            link: ApLink::new(0, 0, 0, 0).expect("MACID0/port0/MAC0/WMM0"),
            config: PortConfig::IDLE,
            macids,
            addr_cams,
            peers: Vec::new(),
        }
    }
    pub(super) fn own(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn link(&self) -> ApLink {
        self.link
    }
    pub(super) fn config(&self) -> PortConfig {
        self.config
    }
    pub(super) fn phase(&self) -> Phase {
        if self.admission.as_ref().is_some_and(Admission::closed) && self.phase != Phase::Stopped {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peers(&self) -> &[ApPeer] {
        &self.peers
    }
    pub(super) fn peer(&self, addr: [u8; 6]) -> Option<ApPeer> {
        self.peers.iter().find(|p| p.addr == addr).copied()
    }
    fn admitted(&self, admission: &Admission, phase: Phase) -> Result<(), Error> {
        if self.phase() != phase || self.admission.as_ref().is_none_or(|a| !a.same(admission)) {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    fn vif_cam(&self, valid: bool) -> [u8; 60] {
        codec::cam_entry(&codec::Cam {
            macid: self.link.mac_id,
            port: self.link.port,
            addr_idx: 0,
            bssid_idx: 0,
            net_type: ap_wire::NET_TYPE_AP_MODE,
            valid,
            bssid_valid: valid,
            sma: self.own,
            // AP `rtwvif_link->bssid` is the own address.
            tma: self.own,
            bssid: self.own,
            aid: 0,
        })
    }
    fn peer_cam(&self, peer: &ApPeer, valid: bool) -> [u8; 60] {
        codec::cam_entry(&codec::Cam {
            macid: peer.macid,
            port: self.link.port,
            addr_idx: peer.addr_cam.unwrap_or(0),
            bssid_idx: 0,
            net_type: ap_wire::NET_TYPE_AP_MODE,
            valid,
            bssid_valid: true,
            sma: self.own,
            tma: peer.addr,
            bssid: self.own,
            aid: peer.aid,
        })
    }

    /// `rtw89_ops_add_interface` -> `rtw89_mac_vif_init` for the AP vif.
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
        let armed = Armed(Some(admission.clone()));
        let secure = self.secure;
        control::checked(io, Some(admission), |io| {
            io.preflight(!secure)?;
            control::crypto_off(io)
        })?;
        port_update(io, admission, PortConfig::IDLE).await?;
        if !secure {
            control::checked(io, Some(admission), |io| control::tables_at(io, 0))?;
        }
        macid_pause(io, 0, false, admission).await?;
        let link = self.link;
        cmd(
            io,
            8,
            4,
            &link.role_maintain(None, UpdMode::Create),
            admission,
        )
        .await?;
        cmd(io, 8, 0, &link.join_info(None, true), admission).await?;
        cmd(io, 6, 0, &self.vif_cam(true), admission).await?;
        cmd(io, 5, 2, &codec::default_cctl_at(0, true), admission).await?;
        // RTL8852B `h2c_default_dmac_tbl` is NULL.
        admission.run(|| {
            self.phase = Phase::Ready;
            Ok(())
        })?;
        armed.disarm();
        Ok(())
    }

    /// `rtw89_ops_start_ap`: port program with the BSS beacon interval and
    /// DTIM period, vif assoc CMAC table, role TYPE_CHANGE, join and CAM.
    /// `rtw89_chip_rfk_channel` belongs to the channel/power admission.
    pub(super) async fn start(
        &mut self,
        io: &mut impl Interface,
        config: PortConfig,
        admission: &Admission,
    ) -> Result<(), Error> {
        self.admitted(admission, Phase::Ready)?;
        if config.beacon_interval == 0 || config.dtim_period == 0 {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let armed = Armed(Some(admission.clone()));
        port_update(io, admission, config).await?;
        let ghz5 = io.ghz5();
        let link = self.link;
        cmd(
            io,
            5,
            2,
            &codec::fixed_cctl_at(ghz5, 0, link.port, Some(false)),
            admission,
        )
        .await?;
        cmd(
            io,
            8,
            4,
            &link.role_maintain(None, UpdMode::TypeChange),
            admission,
        )
        .await?;
        cmd(io, 8, 0, &link.join_info(None, true), admission).await?;
        cmd(io, 6, 0, &self.vif_cam(true), admission).await?;
        admission.run(|| {
            self.config = config;
            self.phase = Phase::Started;
            Ok(())
        })?;
        armed.disarm();
        Ok(())
    }

    /// `BSS_CHANGED_BEACON` / `set_tim` -> `rtw89_fw_h2c_update_beacon`
    /// with the whole `ieee80211_beacon_get_tim` frame.
    pub(super) async fn publish_beacon(
        &mut self,
        io: &mut impl Interface,
        beacon: &[u8],
        tim_at: usize,
        admission: &Admission,
    ) -> Result<(), Error> {
        self.admitted(admission, Phase::Started)?;
        let ghz2 = !io.ghz5();
        let body = self
            .link
            .beacon_update(beacon, tim_at, ghz2, false)
            .map_err(|_| Error::Unsupported)?;
        let armed = Armed(Some(admission.clone()));
        cmd(io, 5, 5, &body, admission).await?;
        armed.disarm();
        Ok(())
    }

    /// `rtw89_core_sta_link_add` AP branch: acquire the lowest free MACID,
    /// unpause it, `ROLE_MAINTAIN(CREATE)` as `SELF_ROLE_AP_CLIENT` and the
    /// default CMAC table. Returns the peer MACID.
    pub(super) async fn add_peer(
        &mut self,
        io: &mut impl Interface,
        addr: [u8; 6],
        admission: &Admission,
    ) -> Result<u8, Error> {
        self.admitted(admission, Phase::Started)?;
        if addr == [0; 6] || addr[0] & 1 != 0 || addr == self.own || self.peer(addr).is_some() {
            return Err(Error::Unsupported);
        }
        let macid = self.macids.acquire(MAX_MAC_ID).ok_or(Error::Busy)?;
        self.phase = Phase::Failed;
        let armed = Armed(Some(admission.clone()));
        self.peers.push(ApPeer {
            addr,
            macid,
            addr_cam: None,
            aid: 0,
        });
        macid_pause(io, macid, false, admission).await?;
        let link = self.link;
        cmd(
            io,
            8,
            4,
            &link.role_maintain(Some(macid), UpdMode::Create),
            admission,
        )
        .await?;
        cmd(io, 5, 2, &codec::default_cctl_at(macid, true), admission).await?;
        admission.run(|| {
            self.phase = Phase::Started;
            Ok(())
        })?;
        armed.disarm();
        Ok(macid)
    }

    /// `rtw89_core_sta_link_assoc` AP branch: address CAM, assoc CMAC
    /// table, `JOIN_INFO` connected, CAM `CON_DISCONN` with the AID, then
    /// `rtw89_phy_ra_assoc` (`ra` is a MACID0 RA body from the station
    /// codec; the peer MACID is inserted here).
    pub(super) async fn associate_peer(
        &mut self,
        io: &mut impl Interface,
        addr: [u8; 6],
        aid: u16,
        ra: [u8; 16],
        admission: &Admission,
    ) -> Result<(), Error> {
        self.admitted(admission, Phase::Started)?;
        let index = self
            .peers
            .iter()
            .position(|p| p.addr == addr && p.addr_cam.is_none())
            .ok_or(Error::Unsupported)?;
        if !(1..=2007).contains(&aid)
            || self
                .peers
                .iter()
                .any(|p| p.addr_cam.is_some() && p.aid == aid)
        {
            return Err(Error::Unsupported);
        }
        let cam = self.addr_cams.acquire(ADDR_CAM_NUM).ok_or(Error::Busy)?;
        self.phase = Phase::Failed;
        let armed = Armed(Some(admission.clone()));
        self.peers[index].addr_cam = Some(cam);
        self.peers[index].aid = aid;
        let peer = self.peers[index];
        let ghz5 = io.ghz5();
        let link = self.link;
        cmd(
            io,
            5,
            2,
            &codec::fixed_cctl_at(ghz5, peer.macid, link.port, Some(true)),
            admission,
        )
        .await?;
        cmd(
            io,
            8,
            0,
            &link.join_info(Some(peer.macid), false),
            admission,
        )
        .await?;
        cmd(io, 6, 0, &self.peer_cam(&peer, true), admission).await?;
        admission.check()?;
        io.command(
            2,
            1,
            0,
            &codec::ra_at(peer.macid, ra),
            false,
            Some(admission),
        )
        .await?;
        admission.run(|| {
            self.phase = Phase::Started;
            Ok(())
        })?;
        armed.disarm();
        Ok(())
    }

    /// `rtw89_core_sta_link_disconnect` + `_remove` AP branches: release
    /// the address CAM (valid cleared before the CAM H2C), assoc CMAC
    /// table, `JOIN_INFO` disconnect (`NET_TYPE_NO_LINK`), CAM, then
    /// `ROLE_MAINTAIN(REMOVE)` and release the MACID.
    pub(super) async fn remove_peer(
        &mut self,
        io: &mut impl Interface,
        addr: [u8; 6],
        admission: &Admission,
    ) -> Result<(), Error> {
        self.admitted(admission, Phase::Started)?;
        let index = self
            .peers
            .iter()
            .position(|p| p.addr == addr)
            .ok_or(Error::Unsupported)?;
        self.phase = Phase::Failed;
        let armed = Armed(Some(admission.clone()));
        let peer = self.peers[index];
        let link = self.link;
        if let Some(cam) = peer.addr_cam {
            let ghz5 = io.ghz5();
            cmd(
                io,
                5,
                2,
                &codec::fixed_cctl_at(ghz5, peer.macid, link.port, Some(true)),
                admission,
            )
            .await?;
            cmd(io, 8, 0, &link.join_info(Some(peer.macid), true), admission).await?;
            cmd(io, 6, 0, &self.peer_cam(&peer, false), admission).await?;
            self.addr_cams.release(cam);
            self.peers[index].addr_cam = None;
        }
        cmd(
            io,
            8,
            4,
            &link.role_maintain(Some(peer.macid), UpdMode::Remove),
            admission,
        )
        .await?;
        admission.run(|| {
            self.macids.release(peer.macid);
            self.peers.remove(index);
            self.phase = Phase::Started;
            Ok(())
        })?;
        armed.disarm();
        Ok(())
    }

    /// `rtw89_ops_stop_ap` (`rtw89_mac_stop_ap` = port `func_sw` with
    /// beacon drop, vif assoc CMAC table, `JOIN_INFO`) followed by
    /// `rtw89_mac_vif_deinit` (`ROLE_MAINTAIN(REMOVE)`, CAM invalid). Every
    /// peer must already be removed (mac80211 removes stations first).
    pub(super) async fn stop(
        &mut self,
        io: &mut impl Interface,
        admission: &Admission,
    ) -> Result<(), Error> {
        self.admitted(admission, Phase::Started)?;
        if !self.peers.is_empty() {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let armed = Armed(Some(admission.clone()));
        func_sw(io, admission, self.config).await?;
        let ghz5 = io.ghz5();
        let link = self.link;
        cmd(
            io,
            5,
            2,
            &codec::fixed_cctl_at(ghz5, 0, link.port, Some(false)),
            admission,
        )
        .await?;
        cmd(io, 8, 0, &link.join_info(None, true), admission).await?;
        cmd(
            io,
            8,
            4,
            &link.role_maintain(None, UpdMode::Remove),
            admission,
        )
        .await?;
        cmd(io, 6, 0, &self.vif_cam(false), admission).await?;
        admission.run(|| {
            self.phase = Phase::Stopped;
            Ok(())
        })?;
        armed.disarm();
        Ok(())
    }
}

async fn cmd(
    io: &mut impl Interface,
    class: u8,
    function: u8,
    body: &[u8],
    admission: &Admission,
) -> Result<(), Error> {
    control::command(io, class, function, body, true, Some(admission)).await
}

/// `rtw89_mac_set_macid_pause` (RECV_ACK only) plus the applied-bit fence.
async fn macid_pause(
    io: &mut impl Interface,
    macid: u8,
    paused: bool,
    admission: &Admission,
) -> Result<(), Error> {
    control::command(
        io,
        9,
        8,
        &codec::pause_at(macid, paused),
        false,
        Some(admission),
    )
    .await?;
    control::pause_applied_at(io, macid, paused, Some(admission)).await
}

fn set32(io: &mut impl Io, register: u32, bits: u32) -> Result<(), Error> {
    control::modify(io, register, bits, bits)
}
fn clear32(io: &mut impl Io, register: u32, bits: u32) -> Result<(), Error> {
    control::modify(io, register, bits, 0)
}
fn mask32(io: &mut impl Io, register: u32, mask: u32, value: u32) -> Result<(), Error> {
    control::modify(io, register, mask, value << mask.trailing_zeros())
}
fn mask16(io: &mut impl Io, register: u32, mask: u16, value: u16) -> Result<(), Error> {
    let old = io.read16(register)?;
    let new = old & !mask | (value << mask.trailing_zeros()) & mask;
    io.write16(register, new)?;
    if io.read16(register)? & mask != new & mask {
        return Err(Error::Terminal);
    }
    Ok(())
}

/// `rtw89_mac_check_packet_ctrl`: select the PTCL debug beacon-queue
/// counter and wait (1 ms steps, 100 ms) for the port's field to drain.
/// Linux only warns on a timeout; so does this owner (the following
/// `TBTT_PROHIB_EN` clear and the 2 ms settle still run).
async fn packet_ctrl(
    io: &mut impl Interface,
    admission: &Admission,
    select: u32,
) -> Result<(), Error> {
    control::checked(io, Some(admission), |io| {
        mask32(io, PTCL_DBG, PTCL_DBG_SEL_MASK, select)?;
        set32(io, PTCL_DBG, PTCL_DBG_EN)
    })?;
    io.delay_us(100).await;
    let start = io.now_us();
    loop {
        let info = control::checked(io, Some(admission), |io| control::read(io, PTCL_DBG_INFO))?;
        if info & 3 == 0 || io.now_us().saturating_sub(start) >= 100_000 {
            return Ok(());
        }
        admission.check()?;
        io.delay_us(1000).await;
    }
}

/// `rtw89_mac_port_cfg_func_sw` for an AP port: nothing unless
/// `PORT_FUNC_EN`; then `rtw89_mac_bcn_drop`, wait `beacon_int + 1` ms,
/// clear `PORT_FUNC_EN | BRK_SETUP`, strobe `TSFTR_RST`, zero the beacon
/// counter timer. (The RTL8852A-only backup/early resets do not apply.)
async fn func_sw(
    io: &mut impl Interface,
    admission: &Admission,
    config: PortConfig,
) -> Result<(), Error> {
    let enabled = control::checked(io, Some(admission), |io| control::read(io, PORT_CFG))?
        & PORT_FUNC_EN
        != 0;
    if !enabled {
        return Ok(());
    }
    control::checked(io, Some(admission), |io| {
        set32(io, BCN_DROP_ALL, 1)?; // BIT(port)
        mask32(io, TBTT_PROHIB, TBTT_SETUP_MASK, 1)?;
        mask32(io, BCN_AREA, BCN_MSK_AREA_MASK, 0)?;
        mask32(io, TBTT_PROHIB, TBTT_HOLD_MASK, 0)?;
        mask32(io, BCN_EARLY, BCNERLY_MASK, 2)?;
        mask16(io, TBTT_EARLY, TBTTERLY_MASK, 1)?;
        mask32(io, BCN_SPACE, BCN_SPACE_MASK, 1)?;
        set32(io, PORT_CFG, BCNTX_EN)
    })?;
    packet_ctrl(io, admission, PTCL_DBG_BCNQ_NUM0).await?;
    packet_ctrl(io, admission, PTCL_DBG_BCNQ_NUM1).await?; // port0 only
    control::checked(io, Some(admission), |io| {
        clear32(io, BCN_DROP_ALL, 1)?;
        clear32(io, PORT_CFG, TBTT_PROHIB_EN)
    })?;
    io.delay_us(2000).await;
    // `msleep(beacon_int + 1)` with the current `bss_conf->beacon_int`.
    io.delay_us((u64::from(config.beacon_interval) + 1) * 1000)
        .await;
    control::checked(io, Some(admission), |io| {
        clear32(io, PORT_CFG, PORT_FUNC_EN | BRK_SETUP)?;
        // TSFTR_RST is a strobe and BCN_CNT_TMR a counter: no readback.
        let cfg = control::read(io, PORT_CFG)?;
        io.write32(PORT_CFG, cfg | TSFTR_RST)?;
        io.write32(BCN_CNT_TMR, 0)
    })
}

/// `rtw89_mac_port_update` for the AP port0/MAC0 link in source order.
/// `rtw89_mac_port_tsf_resync_all` is a no-op with a single AP vif (it
/// is its own sync source).
pub(super) async fn port_update(
    io: &mut impl Interface,
    admission: &Admission,
    config: PortConfig,
) -> Result<(), Error> {
    func_sw(io, admission, config).await?;
    control::checked(io, Some(admission), |io| {
        clear32(io, PORT_CFG, TXBCN_RPT_EN)?;
        clear32(io, PORT_CFG, RXBCN_RPT_EN)?;
        mask32(
            io,
            PORT_CFG,
            NET_TYPE_MASK,
            u32::from(ap_wire::NET_TYPE_AP_MODE),
        )?;
        set32(io, PORT_CFG, TBTT_PROHIB_EN | BRK_SETUP)?; // bcn_prct
        clear32(io, PORT_CFG, RX_BSSID_FIT_EN)?; // rx_sw: not INFRA/ADHOC
        clear32(io, PORT_CFG, TSF_UDT_EN)?; // rx_sync_by_nettype
        set32(io, PORT_CFG, BCNTX_EN)?; // tx_sw_by_nettype: AP
        mask32(io, BCN_SPACE, BCN_SPACE_MASK, u32::from(config.interval()))?;
        io.write8(HGQ_WINDOW, 16)?; // hiq_win: AP_MODE
        if io.read8(HGQ_WINDOW)? != 16 {
            return Err(Error::Terminal);
        }
        let md = io.read8(MD_TSFT_STMP_CTL)?;
        io.write8(MD_TSFT_STMP_CTL, md | UPD_HGQMD_TIMIE)?;
        mask16(io, DTIM_CTRL, DTIM_NUM_MASK, u16::from(config.dtim_period))?;
        // hiq_drop: clear BIT(port) of PORT_DROP_4_0 and, on port0, BIT(0).
        let drop = control::read(io, MBSSID_DROP)?;
        io.write32(MBSSID_DROP, drop & !(1 << PORT_DROP_SHIFT) & !1)?;
        mask32(io, TBTT_PROHIB, TBTT_SETUP_MASK, BCN_SETUP_DEF)?;
        mask32(io, TBTT_PROHIB, TBTT_HOLD_MASK, BCN_HOLD_DEF)?;
        mask32(io, BCN_AREA, BCN_MSK_AREA_MASK, BCN_MASK_DEF)?;
        mask16(io, TBTT_EARLY, TBTTERLY_MASK, TBTT_ERLY_DEF)?;
        mask16(io, TBTT_AGG, TBTT_AGG_NUM_MASK, TBTT_AGG_DEF)?;
        mask32(io, BSS_COLOR, BSS_COLOR_P0_MASK, 0)?; // no HE BSS colour
                                                      // mbssid: AP_MODE returns before touching R_AX_MBSSID_CTRL.
        set32(io, PORT_CFG, PORT_FUNC_EN)
    })?;
    io.delay_us(BCN_ERLY_SET_DLY_US).await;
    control::checked(io, Some(admission), |io| {
        mask32(io, BCN_EARLY, BCNERLY_MASK, BCN_ERLY_DEF)?;
        // bcn_psr_rpt: transmitted BSSID, `bssid_index` 0.
        mask32(io, BCN_PSR_RPT, BCAID_P0_MASK, 0)
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ap_control_tests.rs"]
mod tests;
