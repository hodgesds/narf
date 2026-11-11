// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE branch of the retained native packet/station owner.
//!
//! The 88EE owner in `packet.rs` dispatches here for the 8821AE profile; the
//! linked rings, one-outstanding-frame rule, host receipts, stop and
//! quiescence are shared. Chip-specific: 64-byte `rtl8821ae/trx.h` TX ring
//! entries (descriptor dwords 0..=9, buffer dword 10, next dword 12), the
//! 8821AE RX status fields, `rtl8821ae_hw_init`'s DMA release (`REG_CR` word
//! `0x2ff`, `REG_PCIE_CTRL_REG + 1 = 0`), the `rtl8821ae/fw.c` H2C mailbox
//! and LPS commands, `_rtl8821ae_download_rsvd_page` /
//! `rtl8821ae_set_fw_rsvdpagepkt`, `rtl8821ae_set_network_type` and the
//! 8821AE interrupt profile.
//!
//! Station profile: 2.4 GHz legacy (CCK/OFDM) 20 MHz, MACID 0, software
//! CCMP (`SECR = 0`). Ordinary unicast DATA runs with firmware rate
//! adaptation inside the installed RA mask exactly as `rtl_get_tcb_desc`
//! (no `USE_RATE`, fallback enabled, highest legacy rate); everything else
//! keeps the forced driver rate with fallback disabled. The `NAPC` envelope
//! admits a measured TXAGC index for every station rate, so any rate the
//! firmware picks inside the mask is power-admitted (unlike 88EE, whose
//! fixed-rate NEPC needs the separate NEFB continuation). No HT, A-MPDU,
//! short GI is admitted on this profile. ERP / RTS-threshold protection
//! follows `_rtl_query_protection_mode` (RTS/CTS or CTS-to-self at
//! `DESC_RATE24M`, whose power the same `NAPC` permission admits).
//!
//! C2H packets (`rpt_sel`) are parsed as `rtl_c2h_content_parsing`: V1 TX
//! reports complete the `SPE_RPT` request of the outstanding EAPOL/Null
//! frame (`rtl_set_tx_report`), RA reports record `rtldm->tx_rate`
//! (`rtl8821ae_c2h_ra_report_handler`) for the DM step's
//! `rtl8821ae_dm_update_init_rate`.
use super::super::super::rtl8821ae::{c2h, h2c, mac, station as hw, trx, wow};
use super::{
    extent, queue, Delivery, Error, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep, OWN,
    RX_BASE, RX_BUFFER, RX_BYTES, TX_BASES, TX_BYTES,
};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// `RATR_INX_WIRELESS_MC`: descriptor RATE_ID for frames without a station
/// mask (`_rtl_txrate_selectmode`; 8821AE has no `RTL_SPEC_NEW_RATEID`).
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `_rtl8821ae_download_rsvd_page`: up to five uploads, 20 × 10 us polls.
const RSVD_ATTEMPTS: usize = 5;
const BCN_VALID_POLLS: usize = 20;
/// `_rtl8821ae_hw_configure`: `reg_bcn_ctrl_val = 0x1d`.
const BCN_CTRL_AFTER_INIT: u8 = 0x1d;

/// One C2H TX report matched to the frame whose descriptor requested it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxReport {
    /// Delivery id of the reported frame.
    pub id: u64,
    /// `st == 0` (`rtl_tx_status(hw, skb, st == 0)`).
    pub acked: bool,
    pub retry: u8,
}

pub(in super::super) struct State {
    pub(super) mailbox: h2c::Mailbox,
    pub(super) receive: mac::ReceiveConfig,
    /// `rtlpriv->tx_report` sequence state.
    reports: c2h::TxReportState,
    /// `SW_DEFINE` and delivery id of frames awaiting their TX report
    /// (`tx_report->queue`); bounded, oldest dropped as Linux's 3 s purge.
    waiting: Vec<(u16, u64)>,
    /// Latest matched TX report.
    report: Option<TxReport>,
    /// `rtldm->tx_rate` from the last RA report (0xff in Linux until one
    /// arrives) and whether `rtl8821ae_dm_update_init_rate` is still due.
    ra_rate: Option<u8>,
    ra_due: bool,
    /// `mac->min_space_cfg` (`REG_AMPDU_MIN_SPACE` software cache).
    pub(super) min_space_cfg: u8,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            mailbox: h2c::Mailbox::default(),
            receive: mac::ReceiveConfig {
                rcr: mac::RCR,
                bcn_ctrl: BCN_CTRL_AFTER_INIT,
            },
            reports: c2h::TxReportState::default(),
            waiting: Vec::new(),
            report: None,
            ra_rate: None,
            ra_due: false,
            min_space_cfg: 0,
        }
    }
    /// `rtl_c2h_content_parsing` for the packets this profile consumes.
    /// BT info/MP reports are ignored: boards with the BT function are not
    /// admitted, so `btc_ops` never runs.
    fn c2h(&mut self, packet: &[u8]) {
        match c2h::parse(packet) {
            Ok(c2h::Event::TxReport { sn, st, retry }) => {
                self.reports.record(sn);
                if let Some(at) = self.waiting.iter().position(|(s, _)| *s == sn) {
                    let (_, id) = self.waiting.remove(at);
                    self.report = Some(TxReport {
                        id,
                        acked: st == 0,
                        retry,
                    });
                }
            }
            Ok(c2h::Event::RaReport { hw_rate, .. }) => {
                self.ra_rate = Some(hw_rate);
                self.ra_due = true;
            }
            _ => {}
        }
    }
}

/// `rtl_is_tx_report_skb`: an EAPOL frame (`ether_type` read after the
/// MAC header and the 6-byte SNAP prefix; with software crypto no
/// `hw_key` IV is skipped, so a protected frame never matches) or a
/// (QoS) Null function frame.
pub(super) fn wants_report(frame: &[u8]) -> bool {
    if frame.len() < 24 || frame[0] & 0x0c != 0x08 {
        return false;
    }
    let subtype = frame[0] & 0xf0;
    if subtype == 0x40 || subtype == 0xc0 {
        return true;
    }
    let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
    frame.len() >= header + 8 && frame[header + 6..header + 8] == [0x88, 0x8e]
}

/// Bound on outstanding TX-report requests (the 6-bit `SW_DEFINE` space).
const REPORT_WAIT: usize = 64;
/// Maximum C2H bytes inspected (`C2H_DATA_OFFSET` plus the V1 TX report).
const C2H_BYTES: usize = 16;

fn closed(admission: Option<&super::super::station::Admission>) -> bool {
    admission.is_some_and(|control| control.closed.load(Ordering::Acquire))
}

/// `rtl8821ae_update_hal_rate_mask` `ratr_index` (stored as
/// `sta_entry->ratr_index`) for an H2C payload built by
/// [`h2c::rate_mask`]: the payload's `arfr_id` identifies the mode.
fn ratr_index(payload: &[u8; 7]) -> Option<u8> {
    match payload[1] & 0x7f {
        8 => Some(6),  // RATR_INX_WIRELESS_B
        6 => Some(4),  // RATR_INX_WIRELESS_GB
        1 => Some(0),  // RATR_INX_WIRELESS_NGB (WIRELESS_MODE_N_24G)
        7 => Some(5),  // RATR_INX_WIRELESS_G (WIRELESS_MODE_A)
        5 => Some(1),  // RATR_INX_WIRELESS_NG (WIRELESS_MODE_N_5G)
        10 => Some(8), // RATR_INX_WIRELESS_AC_5N (WIRELESS_MODE_AC_5G)
        _ => None,
    }
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// `mac->min_space_cfg` for `rtl8821ae::ht::timing`.
    pub(crate) fn rtl8821ae_min_space_cfg(&self) -> u8 {
        self.packet.ae.min_space_cfg
    }
    pub(crate) fn set_rtl8821ae_min_space_cfg(&mut self, value: u8) {
        self.packet.ae.min_space_cfg = value;
    }
    pub(super) fn ae_validate_rings(&self) -> Result<(), Error> {
        for (queue, ring) in self.tx.iter().enumerate() {
            ring.sync();
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            if self.io.read32(TX_BASES[queue])? != base {
                return Err(Error::Readback);
            }
            for slot in 0..self.depth {
                let at = slot * TX_BYTES;
                if ring.read32(at)? & OWN != 0
                    || ring.read32(at + 40)? != 0
                    || ring.read32(at + 44)? != 0
                    || ring.read32(at + 48)? != base + (((slot + 1) % self.depth) * TX_BYTES) as u32
                    || ring.read32(at + 52)? != 0
                {
                    return Err(Error::Descriptor);
                }
            }
        }
        // RX ring: shared 32-byte layout, buffer at dword 6 (as 88EE).
        let receive = self.receive.as_ref().ok_or(Error::State)?;
        receive.sync();
        if self.io.read32(RX_BASE)? != extent(receive, self.depth * RX_BYTES, 256)? {
            return Err(Error::Readback);
        }
        for (slot, buffer) in self.buffers.iter().enumerate() {
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if receive.read32(slot * RX_BYTES)? != RX_BUFFER as u32 | OWN | end
                || receive.read32(slot * RX_BYTES + 24)? != extent(buffer, RX_BUFFER, 4)?
                || receive.read32(slot * RX_BYTES + 28)? != 0
            {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }

    /// `rtl8821ae_hw_init` tail on the retained owner: software crypto
    /// (`SECR` 0), queues unpaused and IRQ masks clear are proven, bus
    /// mastering is opened, then `REG_CR` word `0x2ff` and
    /// `REG_PCIE_CTRL_REG + 1 = 0`. `rtl_op_add_interface` then runs
    /// `rtl8821ae_set_network_type(STATION)` without a link, which is the
    /// first `HW_VAR_RCR` write and settles the MAC-table-rewritten RCR.
    pub(super) fn ae_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.rtl8821ae_power.is_none()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(false, || self.ae_validate_rings())?;
        if self.io.read8(0x680)? != 0
            || self.io.read8(0x522)? != 0
            || self.io.read32(0xb0)? != 0
            || self.io.read32(0xb8)? != 0
        {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        self.io.write16(0x100, mac::CR_RUNNING)?;
        self.io.write8(0x301, 0)?;
        if self.io.read8(0x100)? != 0xff
            || self.io.read8(0x101)? != 0x02
            || self.io.read8(0x301)? != 0
        {
            return Err(Error::Readback);
        }
        hw::network_type_station(&self.io, &mut self.packet.ae.receive, false)?;
        if self.io.read32(mac::REG_RCR)? != mac::RCR & !(mac::RCR_CBSSID_DATA | mac::RCR_CBSSID_BCN)
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// Linux `rtl8821ae_hw_init` leaves `fw_current_inpsmode = false` and
    /// `fw_ps_state = FW_PS_STATE_ALL_ON_8821AE`; nothing is sent. Only a
    /// powered MAC (`REG_CR != 0xEA`) is accepted.
    pub(super) fn ae_awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        if self.io.read8(0x100)? == 0xea {
            return Err(Error::RadioOff);
        }
        Ok(())
    }

    /// Authentication-time `BSS_CHANGED_BSSID` / `BASIC_RATES` / ERP and
    /// `set_channel_access`: BSSID, RRSR, slot, SIFS, `set_qos` rows and
    /// preamble.
    pub(super) fn ae_prepare_peer(
        &mut self,
        peer: [u8; 6],
        rates: u16,
        basic: u16,
        capability: u16,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        if peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Packet);
        }
        self.phase = Phase::Failed;
        hw::set_bssid(&self.io, peer)?;
        let five_ghz = self.rtl8821ae_five_ghz();
        hw::configure_rates(&self.io, rates, basic, capability, false, five_ghz)?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` for 8821AE: CAM reset,
    /// `HW_VAR_KEEP_ALIVE` (10), `rtl8821ae_set_network_type` with the link
    /// (CBSSID on), then `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`:
    /// `HW_VAR_AID`, `_rtl8821ae_download_rsvd_page(false)` and the MSRRPT
    /// connect report. The firmware RA mask follows separately
    /// (`install_rate_mask`). Linux logs and continues when BCN_VALID never
    /// sets; here that is a terminal `CommandTimeout`.
    pub(super) async fn ae_complete_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        let pages = hw::reserved_pages(self.local().ok_or(Error::State)?, peer, aid)?;
        let mut buffer = self.io.allocate_packet(pages.len())?;
        let address = extent(&buffer, pages.len(), 4)?;
        let end = u64::from(address) + pages.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        self.io.authority(true, || {
            buffer.write_bytes(0, &pages)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.reserved = Some(buffer);
        self.phase = Phase::Failed;
        // core.c: rtl_cam_reset_all_entry before the link is marked.
        self.io.write32(hw::REG_CAMCMD, 0xc000_0000)?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.packet
            .ae
            .mailbox
            .fill(&self.io, h2c::H2C_KEEP_ALIVE_CTRL, &[0xff, 10])
            .await?;
        hw::network_type_station(&self.io, &mut self.packet.ae.receive, true)?;
        hw::set_aid(&self.io, aid)?;
        self.ae_download_rsvd_page(address, pages.len() as u16, admission, &policy, false)
            .await?;
        if closed(admission) {
            return Err(Error::State);
        }
        policy(self)?;
        self.packet
            .ae
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(true))
            .await?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// `_rtl8821ae_download_rsvd_page(hw, false)` with
    /// `rtl8821ae_set_fw_rsvdpagepkt(hw, false, false)` /
    /// `rtl_cmd_send_packet` on BEACON_QUEUE descriptor 0
    /// (`rtl8821ae_tx_fill_cmddesc`, `rtl8821ae_tx_polling` BIT(4)) and the
    /// `H2C_8821AE_RSVDPAGE` location command after every upload.
    /// `whole` is the `enter_pnp_sleep` WoWLAN form
    /// (`_rtl8821ae_download_rsvd_page(hw, true)`): the AOAC location
    /// command follows each upload, a station that was sending beacons
    /// repeats the upload as `b_dl_finished`, and `REG_CR + 1` BIT(0) stays
    /// set.
    async fn ae_download_rsvd_page(
        &mut self,
        address: u32,
        length: u16,
        admission: Option<&super::super::station::Admission>,
        policy: &impl Fn(&Self) -> Result<(), Error>,
        whole: bool,
    ) -> Result<(), Error> {
        let cr = self.io.read8(0x101)?;
        self.io.write8(0x101, cr | 1)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ae.receive.bcn_ctrl, 0, 1 << 3)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ae.receive.bcn_ctrl, 1 << 4, 0)?;
        let txq = self.io.read8(hw::REG_FWHW_TXQ_CTRL + 2)?;
        self.io.write8(hw::REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
        let descriptor = hw::command_descriptor(length, address);
        // A rejoin reuses the descriptor whose earlier upload BCN_VALID
        // proved; within one download Linux overwrites descriptor 0 too.
        let mut proven = !self.packet.retired.is_empty();
        let mut valid = false;
        for _ in 0..RSVD_ATTEMPTS {
            let status = self.io.read8(hw::REG_TDECTRL + 2)?;
            if status == 0xff {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            self.io.write8(hw::REG_TDECTRL + 2, status | 1)?;
            {
                let _publication = admission.map(|control| control.publication.lock());
                if closed(admission) {
                    return Err(Error::State);
                }
                policy(self)?;
                let ring = &mut self.tx[0];
                self.io.authority(true, || {
                    ring.sync();
                    if ring.read32(0)? & OWN != 0 && !proven {
                        return Err(Error::Descriptor);
                    }
                    for (word, value) in descriptor.into_iter().enumerate() {
                        ring.write32(word * 4, value)?;
                    }
                    ring.sync();
                    ring.write32(0, descriptor[0] | OWN)?;
                    ring.sync();
                    Ok(())
                })?;
                self.io.kick(1 << 4)?;
            }
            proven = true;
            self.packet
                .ae
                .mailbox
                .fill(
                    &self.io,
                    h2c::H2C_RSVDPAGE,
                    &h2c::rsvdpage_location(
                        hw::PSPOLL_PG,
                        hw::NULL_PG,
                        hw::QOSNULL_PG,
                        hw::BT_QOSNULL_PG,
                    ),
                )
                .await?;
            if whole {
                self.packet
                    .ae
                    .mailbox
                    .fill(&self.io, wow::H2C_AOAC_RSVDPAGE, &wow::aoac_rsvdpage())
                    .await?;
            }
            for poll in 0..=BCN_VALID_POLLS {
                if poll != 0 {
                    self.io.delay_us(10).await;
                }
                let status = self.io.read8(hw::REG_TDECTRL + 2)?;
                if status == 0xff {
                    return Err(Error::Access(super::super::AccessError::Gone));
                }
                if status & 1 != 0 {
                    valid = true;
                    break;
                }
            }
            if valid {
                break;
            }
        }
        if valid && whole && txq & (1 << 6) != 0 {
            // `send_beacon`: the same packet again as `b_dl_finished`
            // (no location commands).
            valid = false;
            for _ in 0..RSVD_ATTEMPTS {
                let status = self.io.read8(hw::REG_TDECTRL + 2)?;
                self.io.write8(hw::REG_TDECTRL + 2, status | 1)?;
                {
                    let _publication = admission.map(|control| control.publication.lock());
                    if closed(admission) {
                        return Err(Error::State);
                    }
                    policy(self)?;
                    let ring = &mut self.tx[0];
                    self.io.authority(true, || {
                        ring.sync();
                        for (word, value) in descriptor.into_iter().enumerate() {
                            ring.write32(word * 4, value)?;
                        }
                        ring.sync();
                        ring.write32(0, descriptor[0] | OWN)?;
                        ring.sync();
                        Ok(())
                    })?;
                    self.io.kick(1 << 4)?;
                }
                for poll in 0..=BCN_VALID_POLLS {
                    if poll != 0 {
                        self.io.delay_us(10).await;
                    }
                    let status = self.io.read8(hw::REG_TDECTRL + 2)?;
                    if status == 0xff {
                        return Err(Error::Access(super::super::AccessError::Gone));
                    }
                    if status & 1 != 0 {
                        valid = true;
                        break;
                    }
                }
                if valid {
                    break;
                }
            }
        }
        if valid {
            self.io.write8(hw::REG_TDECTRL + 2, 1)?;
        }
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ae.receive.bcn_ctrl, 1 << 3, 0)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ae.receive.bcn_ctrl, 0, 1 << 4)?;
        if txq & (1 << 6) != 0 {
            self.io.write8(hw::REG_FWHW_TXQ_CTRL + 2, txq)?;
        }
        if !whole {
            let cr = self.io.read8(0x101)?;
            self.io.write8(0x101, cr & !1)?;
        }
        if valid {
            Ok(())
        } else {
            Err(Error::CommandTimeout)
        }
    }

    /// `rtl8821ae_update_hal_rate_mask`: `H2C_8821AE_RA_MASK` then
    /// `_rtl8821ae_set_bcn_ctrl_reg(BIT(3), 0)`; `sta_entry->ratr_index`
    /// is retained for the data descriptors' RATE_ID.
    pub(super) async fn ae_install_rate_mask(
        &mut self,
        payload: [u8; 7],
        admission: Option<&super::super::station::Admission>,
    ) -> Result<(), Error> {
        let index = ratr_index(&payload).ok_or(Error::Packet)?;
        // The firmware RA may only pick rates whose measured power the
        // signed `NAPC` permission admits: the installed mask must be a
        // non-empty subset of the admitted set (refused otherwise, never
        // silently narrowed, so the Linux mask/ratr_index pair stays exact).
        let rates = h2c::mask_rates(&payload).ok_or(Error::Packet)?;
        let admitted = self.rtl8821ae_power.ok_or(Error::State)?.admitted_rates();
        if rates == 0 || rates & !admitted != 0 {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        if closed(admission) {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet
            .ae
            .mailbox
            .fill(&self.io, h2c::H2C_RA_MASK, &payload)
            .await?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ae.receive.bcn_ctrl, 1 << 3, 0)?;
        self.packet.rate_mask = Some(index);
        self.phase = Phase::Running;
        Ok(())
    }

    /// Take the latest C2H TX report (`rtl_tx_report_handler` match).
    pub(super) fn ae_take_tx_report(&mut self) -> Option<TxReport> {
        self.packet.ae.report.take()
    }

    /// `rtl_check_tx_report_acked` without the 3 s timeout (the caller's
    /// deadline owns it): every requested report has arrived.
    pub(super) fn ae_tx_reports_settled(&self) -> bool {
        self.packet.ae.reports.all_acked()
    }

    /// `rtldm->tx_rate` (`DESC_RATE*`) from the last C2H RA report.
    pub(super) fn ae_ra_rate(&self) -> Option<u8> {
        self.packet.ae.ra_rate
    }

    /// `rtl8821ae_dm_update_init_rate` for a pending RA report, run by the
    /// DM step inside the envelope's current authority (Linux runs it from
    /// `c2hcmd_wq`). Returns whether a report was applied.
    pub(super) fn ae_update_init_rate(&mut self) -> Result<bool, Error> {
        if !self.packet.ae.ra_due {
            return Ok(false);
        }
        let rate = self.packet.ae.ra_rate.ok_or(Error::State)?;
        let swing = self.rtl8821ae_power.ok_or(Error::State)?.swing();
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        super::super::super::rtl8821ae::channel::update_init_rate(&self.io, swing, rate)?;
        self.packet.ae.ra_due = false;
        self.phase = Phase::Running;
        Ok(true)
    }

    /// `HW_VAR_FW_LPS_ACTION(true)` → `_rtl8821ae_fwlps_enter`.
    pub(super) async fn ae_enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        // Coexistence holds LPS off while BT owns the shared antenna
        // outright (`rtl8821ae/coex.rs`): a held-off enter is a
        // successful no-op, not an error — `leisure` stays false, so
        // callers read the true power state and can retry once BT
        // releases the antenna.
        if let Some(coex) = self.rtl8821ae_coex.as_deref() {
            if !coex.lps_allowed() {
                return Ok(());
            }
        }
        self.phase = Phase::Failed;
        h2c::fwlps_enter(&self.io, &mut self.packet.ae.mailbox).await?;
        self.packet.leisure = true;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `HW_VAR_FW_LPS_ACTION(false)` → `_rtl8821ae_fwlps_leave`.
    pub(super) async fn ae_leave_leisure(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.packet.leisure {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        h2c::fwlps_leave(&self.io, &mut self.packet.ae.mailbox).await?;
        self.packet.leisure = false;
        self.phase = Phase::Running;
        Ok(())
    }

    /// Disassociation registers and reports: leave LPS, then
    /// `rtl8821ae_set_network_type(STATION)` without a link (CBSSID off),
    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)` (MSRRPT only) and the
    /// mac80211 `BSS_CHANGED_BSSID` zero BSSID. Linux leaves AID alone.
    pub(super) async fn ae_disconnected(&mut self) -> Result<(), Error> {
        if core::mem::take(&mut self.packet.leisure) {
            h2c::fwlps_leave(&self.io, &mut self.packet.ae.mailbox).await?;
        }
        hw::network_type_station(&self.io, &mut self.packet.ae.receive, false)?;
        self.packet
            .ae
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(false))
            .await?;
        hw::set_bssid(&self.io, [0; 6])
    }

    /// `rtl_op_suspend` → `rtl_op_stop` → `rtl_pci_stop` →
    /// `rtl8821ae_card_disable` with `support_remote_wakeup &&
    /// enter_pnp_sleep` on the linked station, in Linux order: WKFM CAM
    /// patterns (`_rtl_add_wowlan_patterns`), `rtl_lps_leave`,
    /// `disable_interrupt`, clear `REG_MCUTST_WOWLAN`,
    /// `rtl8821ae_set_fw_related_for_wowlan(true)` (WoWLAN image, H2C box
    /// and FW PS state reset), `_rtl8821ae_dynamic_rqpn(0xE0, 0x3,
    /// 0x80c20d0d)`, `rtl8821ae_set_fw_global_info_cmd`,
    /// `_rtl8821ae_download_rsvd_page(true)`, `HW_VAR_AID`, MSRRPT connect,
    /// `set_fw_wowlan_mode(true)`, keep-alive, disconnect decision, the RX
    /// DMA drain, the APS/SYS_CLKR/RSV_CTRL MCU hold,
    /// `set_fw_remote_wake_ctrl_cmd(1)` (last H2C) and the PCIe TX DMA stop.
    ///
    /// `pairwise`/`group` are the `rt_enc_alg` values Linux records in
    /// `rtlpriv->sec`; this software-CCMP profile is Linux's `sw_crypto`
    /// case (`rtl_op_set_key` returns before setting them), so the caller
    /// passes `NO_ENCRYPTION`. `reset_trx_ring` only rewinds host ring
    /// indices for the next normal start; here the stopped rings are
    /// retired and the resume is a fresh generation, so there is nothing to
    /// rewind. On success the RX-idle and TX-DMA-idle polls plus cleared bus
    /// mastering are the host DMA retirement proof (`Stopped`, unpublished)
    /// and the MAC/firmware are left running. Any error leaves `Failed`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn ae_wow_card_disable(
        &mut self,
        config: &narf_wireless::WowlanConfig,
        image: &[u8],
        bssid: [u8; 6],
        aid: u16,
        pairwise: u8,
        group: u8,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let own = self.local().ok_or(Error::State)?;
        if !self.transmit_ready() || self.packet.reserved.is_none() {
            return Err(Error::State);
        }
        wow::validate(config)?;
        let pages = wow::whole_reserved_pages(own, bssid, aid)?;
        self.phase = Phase::Failed;
        wow::program_patterns(&self.io, config, own).await?;
        if core::mem::take(&mut self.packet.leisure) {
            h2c::fwlps_leave(&self.io, &mut self.packet.ae.mailbox).await?;
        }
        self.packet.interrupts = false;
        self.io.write32(0xb0, 0)?;
        self.io.write32(0xb8, 0)?;
        self.io.write8(wow::REG_MCUTST_WOWLAN, 0)?;
        super::super::super::rtl8821ae::fw::load(&self.io, image, true)
            .await
            .map_err(|_| Error::CommandTimeout)?;
        self.packet.ae.mailbox = h2c::Mailbox::default();
        wow::dynamic_rqpn(
            &self.io,
            wow::WOW_BOUNDARY,
            wow::WOW_NPQ_RQPN,
            wow::WOW_RQPN,
        )
        .await?;
        self.packet
            .ae
            .mailbox
            .fill(
                &self.io,
                wow::H2C_AOAC_GLOBAL_INFO,
                &wow::global_info(pairwise, group),
            )
            .await?;
        // The joined body stays retained beside the whole-packet body: the
        // beacon descriptor may still name it until this upload is proven.
        let mut buffer = self.io.allocate_packet(pages.len())?;
        let address = extent(&buffer, pages.len(), 4)?;
        let end = u64::from(address) + pages.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .chain(self.packet.reserved.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        self.io.authority(true, || {
            buffer.write_bytes(0, &pages)?;
            buffer.sync();
            Ok(())
        })?;
        if let Some(joined) = self.packet.reserved.replace(buffer) {
            self.packet.retired.push(joined);
        }
        self.ae_download_rsvd_page(address, pages.len() as u16, None, &policy, true)
            .await?;
        hw::set_aid(&self.io, aid)?;
        let mailbox = &mut self.packet.ae.mailbox;
        mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(true))
            .await?;
        mailbox
            .fill(&self.io, wow::H2C_WO_WLAN, &wow::wowlan_mode(true))
            .await?;
        mailbox
            .fill(&self.io, wow::H2C_KEEP_ALIVE_CTRL, &wow::keep_alive(true))
            .await?;
        mailbox
            .fill(
                &self.io,
                wow::H2C_DISCONNECT_DECISION,
                &wow::disconnect_decision(true),
            )
            .await?;
        wow::drain_rx_dma(&self.io).await?;
        wow::hold_mcu(&self.io)?;
        self.packet
            .ae
            .mailbox
            .fill(
                &self.io,
                wow::H2C_REMOTE_WAKE_CTRL,
                &wow::remote_wake_ctrl(true),
            )
            .await?;
        wow::stop_tx_dma(&self.io).await?;
        if self.io.read8(wow::REG_RXDMA_CONTROL)? & 1 << 1 == 0 {
            return Err(Error::PacketTimeout);
        }
        self.io.master(false)?;
        self.packet.rate_mask = None;
        self.packet.vht_highest = None;
        self.phase = Phase::Stopped;
        self.published = false;
        Ok(())
    }

    /// `rtl8821ae_enable_interrupt` (with `int_clear`) on a running owner.
    pub(super) fn ae_enable_interrupts(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(true, || Ok(()))?;
        self.packet.interrupts = true;
        h2c::enable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HIMR)? != h2c::IRQ_MASK0
            || self.io.read32(h2c::REG_HIMRE)? != h2c::IRQ_MASK1
            || self.io.read32(h2c::REG_HSIMR)? != h2c::SYS_IRQ_MASK
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// One `_rtl_pci_interrupt` recognition pass for the 8821AE profile.
    pub(super) fn ae_recognize_interrupts(
        &mut self,
    ) -> Result<super::super::super::irq::Recognized, Error> {
        if self.phase != Phase::Running || !self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let (inta, intb) = h2c::service_interrupt(&self.io)?;
        self.phase = Phase::Running;
        Ok(super::super::super::irq::Recognized { inta, intb })
    }

    /// `rtl8821ae_tx_fill_desc` for one first+last MPDU (no early
    /// mode): forced `hw_rate` with fallback disabled, or (`adaptive`,
    /// ordinary unicast DATA with an installed mask) firmware RA with
    /// fallback; BW 20; on an HT link (`packet.ht`) the data SGI bit for
    /// `hw_rate > DESC_RATEMCS0` (`_rtl_query_shortgi`), AGG_EN +
    /// MAX_AGG_NUM 0x1f for an operational BA session's QoS DATA
    /// (`IEEE80211_TX_CTL_AMPDU`) and the peer's `ampdu_density`; RTS/CTS or
    /// CTS-to-self from the
    /// selected protection mode, no hardware key, HWSEQ for non-QoS
    /// frames, MACID 0, RATE_ID the installed `ratr_index` for unicast (MC
    /// otherwise) and `SPE_RPT`/`SW_DEFINE` for EAPOL and Null frames.
    pub(super) fn ae_submit(
        &mut self,
        frame: &[u8],
        rate: u8,
        aggregate: Option<(u8, bool)>,
        adaptive: bool,
        short_gi: bool,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        let ht = self.packet.ht;
        let highest = if ht {
            super::super::super::rtl8821ae::ht::DESC_RATEMCS7
        } else {
            trx::DESC_RATE54M
        };
        if !ht && (aggregate.is_some() || short_gi) || rate > highest {
            return Err(Error::Packet);
        }
        let (queue, poll, selector) = queue(
            frame,
            self.packet.local.ok_or(Error::State)?,
            self.packet.qos,
        )?;
        let id = self.packet.serial.checked_add(1).ok_or(Error::State)?;
        let mut buffer = self.io.allocate_packet(frame.len())?;
        let address = extent(&buffer, frame.len(), 4)?;
        let end = u64::from(address) + frame.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        let destination = if (2..=5).contains(&queue) {
            &frame[16..22]
        } else {
            &frame[4..10]
        };
        let multicast = destination[0] & 1 != 0;
        // rtl_get_tcb_desc: ordinary unicast DATA (rates[0].idx != 0, not
        // Null) leaves use_driver_rate/disable_ratefallback clear and sets
        // hw_rate to the mode's highest rate (`_rtl_get_highest_n_rate`
        // MCS7 for a 1T1R HT peer, else 11M for B, 54M otherwise);
        // the firmware RA owns the rate inside the installed mask.
        // `sta` is the AP addressed by addr1, so RATE_ID is its
        // `ratr_index` whatever the DA.
        let adaptive = match self.packet.rate_mask {
            Some(index) if adaptive => {
                if frame[4] & 1 != 0 || frame[0] & 0x0c != 0x08 || frame[0] & 0x40 != 0 {
                    return Err(Error::Packet);
                }
                Some(index)
            }
            None if adaptive => return Err(Error::State),
            _ => None,
        };
        // AC_5G: `_rtl_get_vht_highest_n_rate`.
        let hw_rate = match adaptive {
            Some(8) => self.packet.vht_highest.ok_or(Error::State)?,
            Some(0 | 1) => super::super::super::rtl8821ae::ht::DESC_RATEMCS7,
            Some(6) => 0x03,
            Some(_) => trx::DESC_RATE54M,
            None => rate,
        };
        // Every rate the descriptor can put on air — the forced/initial
        // `hw_rate`, the firmware-RA mask (checked at install) and the
        // `DESC_RATE24M` RTS/CTS-to-self rate — must hold an admitted
        // measured index in the current `NAPC` permission.
        let permission = self.rtl8821ae_power.ok_or(Error::State)?;
        if !super::super::super::rtl8821ae::vht::admits(&permission, hw_rate)
            || (self.packet.protection != super::super::super::protection::Mode::None
                && !permission.admits(trx::DESC_RATE24M))
        {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        let wide40 = self.packet.width.is_some() && !multicast && hw_rate > trx::DESC_RATE54M;
        // `current_chan_bw` 80: `_rtl_query_bandwidth_mode` /
        // `rtl8821ae_bw_mapping` / `rtl8821ae_sc_mapping` (`rtl8821ae::vht`).
        let eighty = if permission.operating().width
            == super::super::super::rtl8821ae::envelope::Width::W80
        {
            let bw = super::super::super::rtl8821ae::vht::data_bw(hw_rate, multicast);
            let sc = super::super::super::rtl8821ae::vht::sub_carrier(&permission.operating(), bw)
                .ok_or(Error::State)?;
            Some((bw, sc))
        } else {
            None
        };
        let tx_report = wants_report(frame).then(|| self.packet.ae.reports.next_sn());
        let params = trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id: match (adaptive, self.packet.rate_mask) {
                (Some(index), _) => index,
                (None, Some(index)) if !multicast => index,
                _ => RATR_INX_WIRELESS_MC,
            },
            hw_rate,
            use_driver_rate: adaptive.is_none(),
            disable_fallback: adaptive.is_none(),
            // hw_rate > DESC_RATEMCS0 ? use_shortgi : use_shortpreamble.
            short: short_gi && hw_rate > super::super::super::rtl8821ae::ht::DESC_RATEMCS0,
            // rtl8821ae_bw_mapping / rtl8821ae_sc_mapping at
            // `current_chan_bw` 20_40: `_rtl_query_bandwidth_mode` gives a
            // 40 MHz packet for unicast above 54M; a 20 MHz packet names
            // the primary (cur_40_prime_sc LOWER 2 / UPPER 1).
            data_bw: eighty.map_or(u8::from(wide40), |(bw, _)| bw),
            sub_carrier: match self.packet.width {
                _ if eighty.is_some() => eighty.map_or(0, |(_, sc)| sc),
                Some(g) if !wide40 => {
                    if g.prime() == 1 {
                        2
                    } else {
                        1
                    }
                }
                _ => 0,
            },
            ampdu: aggregate.is_some_and(|(_, operational)| operational),
            ampdu_density: aggregate.map_or(0, |(density, _)| density),
            sec_type: 0,
            qos_data: frame[0] == 0x88,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast,
            protection: match self.packet.protection {
                super::super::super::protection::Mode::None => 0,
                super::super::super::protection::Mode::RtsCts => 1,
                super::super::super::protection::Mode::CtsToSelf => 2,
            },
            tx_report,
            buffer_len: frame.len() as u16,
            buffer_addr: address,
        };
        let descriptor = trx::TxDesc::fill(&params);
        let mut prefix = [0u32; 10];
        prefix.copy_from_slice(&descriptor.dw[..10]);
        let slot = self.packet.next[queue];
        self.io.authority(true, || {
            buffer.write_bytes(0, frame)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.pending = Some(Pending {
            buffer,
            id,
            queue,
            slot,
            length: frame.len(),
            prefix,
        });
        self.packet.serial = id;
        if let Some(sn) = tx_report {
            let waiting = &mut self.packet.ae.waiting;
            if waiting.len() == REPORT_WAIT {
                waiting.remove(0);
            }
            waiting.try_reserve(1).map_err(|_| Error::Memory)?;
            waiting.retain(|(s, _)| *s != sn);
            waiting.push((sn, id));
        }
        self.phase = Phase::Failed;
        let ring = &mut self.tx[queue];
        self.io.authority(true, || {
            ring.sync();
            let offset = slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Err(Error::Descriptor);
            }
            // clear_pci_tx_desc_content covers the 40-byte descriptor; the
            // buffer address is dword 10 and dword 12's next pointer stays.
            for (word, value) in descriptor.dw[..11].iter().copied().enumerate() {
                ring.write32(offset + word * 4, value)?;
            }
            ring.sync();
            ring.write32(offset, descriptor.dw[0] | OWN)?;
            ring.sync();
            Ok(())
        })?;
        self.io.kick(poll)?;
        self.phase = Phase::Running;
        Ok(id)
    }

    /// Host receipt of the pending 8821AE descriptor: OWN clear with the
    /// stable size/queue/buffer words and the linked next pointer intact.
    pub(super) fn ae_delivery(&mut self) -> Result<Option<Delivery>, Error> {
        let Some(pending) = self.packet.pending.as_ref() else {
            return Ok(None);
        };
        let ring = &self.tx[pending.queue];
        let address = extent(&pending.buffer, pending.length, 4)?;
        let delivery = self.io.authority(true, || {
            ring.sync();
            let offset = pending.slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Ok(None);
            }
            for word in [0, 1, 7] {
                if ring.read32(offset + word * 4)? != pending.prefix[word] {
                    return Err(Error::Descriptor);
                }
            }
            if ring.read32(offset + 40)? != address
                || ring.read32(offset + 44)? != 0
                || ring.read32(offset + 48)?
                    != ring.address() as u32 + (((pending.slot + 1) % self.depth) * TX_BYTES) as u32
                || ring.read32(offset + 52)? != 0
            {
                return Err(Error::Descriptor);
            }
            pending.buffer.sync();
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(pending.length)
                .map_err(|_| Error::Memory)?;
            bytes.resize(pending.length, 0);
            pending.buffer.read_bytes(0, &mut bytes)?;
            Ok(Some(Delivery {
                id: pending.id,
                bytes,
            }))
        })?;
        if delivery.is_some() {
            let queue = pending.queue;
            self.packet.next[queue] = (pending.slot + 1) % self.depth;
            self.packet.pending = None;
        }
        Ok(delivery)
    }

    /// One `_rtl_pci_rx_interrupt` step with `rtl8821ae_rx_query_desc`
    /// fields. C2H report buffers (`rpt_sel`) are parsed and consumed
    /// (`rtl_c2hcmd_enqueue`); frames outside the legacy 20 MHz profile are
    /// consumed and dropped. With PHYST the `query_rxphystatus` PWDB is
    /// decoded from the PHY status at `rx_bufshift` (Linux's `p_drvinfo`).
    pub(super) fn ae_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let slot = self.packet.receive;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let channel = self.rtl8821ae_power.ok_or(Error::State)?.channel();
        let ht = self.packet.ht;
        let forty = self.packet.width.is_some();
        let eighty = self.rtl8821ae_power.is_some_and(|p| {
            p.operating().width == super::super::super::rtl8821ae::envelope::Width::W80
        });
        let vht = self.packet.vht_highest.is_some();
        let (consumed, packet, report) = self.io.authority(true, || {
            ring.sync();
            let offset = slot * RX_BYTES;
            let mut dw = [0u32; 8];
            for (word, value) in dw.iter_mut().enumerate() {
                *value = ring.read32(offset + word * 4)?;
            }
            let Some(status) = trx::RxStatus::parse(&dw) else {
                return Ok((false, None, None));
            };
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if dw[0] & (1 << 30) != end || dw[6] != extent(buffer, RX_BUFFER, 4)? || dw[7] != 0 {
                return Err(Error::Descriptor);
            }
            let length = usize::from(status.length);
            let start = status.drvinfo_size + status.shift;
            if !status.c2h
                && (length < 4 || start.checked_add(length).is_none_or(|n| n > RX_BUFFER))
            {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            let mut report = None;
            if status.c2h && length >= c2h::C2H_DATA_OFFSET && start + length <= RX_BUFFER {
                buffer.sync();
                let mut bytes = [0u8; C2H_BYTES];
                let take = length.min(C2H_BYTES);
                buffer.read_bytes(start, &mut bytes[..take])?;
                report = Some((bytes, take));
            }
            // HT link: MCS0-7 (1T1R) and A-MPDU members (the station BA
            // owner gates them) up to a 7935-byte A-MSDU MPDU.
            // VHT link: VHT 1SS MCS0-9 (`rtl8821ae_get_rx_vht_nss` 1).
            let rate_ok = status.rate <= trx::DESC_RATE54M
                || ht
                    && status.is_ht()
                    && status.rate <= super::super::super::rtl8821ae::ht::DESC_RATEMCS7
                || vht
                    && status.is_vht()
                    && status.vht_nss() == 1
                    && (super::super::super::rtl8821ae::vht::DESC_RATEVHT1SS_MCS0
                        ..=super::super::super::rtl8821ae::vht::DESC_RATEVHT1SS_MCS9)
                        .contains(&status.rate);
            let longest = if ht {
                26 + 16 + narf_wireless::amsdu::Limit::Ht7935.bytes() + 4
            } else {
                2304 + 4
            };
            if !status.c2h
                && !status.hw_error()
                && (!status.ampdu || ht)
                && rate_ok
                && (status.bw == 0 || forty && status.bw == 1 || eighty && status.bw == 2)
                && (24..=longest).contains(&length)
            {
                buffer.sync();
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length - 4)
                    .map_err(|_| Error::Memory)?;
                bytes.resize(length - 4, 0);
                buffer.read_bytes(start, &mut bytes)?;
                let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
                // Protected frames keep IV/ciphertext/MIC: SECR 0 means the
                // hardware never decrypts (SWDEC set).
                if fc & 0x400 == 0 && bytes[22] & 15 == 0 && (fc & 0x4000 == 0 || !status.decrypted)
                {
                    let pwdb = if status.physt {
                        if status.drvinfo_size < trx::PHY_STATUS_PWDB_BYTES {
                            return Err(Error::Descriptor);
                        }
                        let mut phy = [0u8; trx::PHY_STATUS_PWDB_BYTES];
                        buffer.read_bytes(status.shift, &mut phy)?;
                        Some(trx::rx_pwdb(&phy, trx::is_cck(status.rate)))
                    } else {
                        None
                    };
                    // Linux reports `is_short_gi = !SPLCP` for rate
                    // statistics only; every GI is advertised, so nothing
                    // is gated on it here.
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: status.is_ht(),
                        short_gi: false,
                        width40: status.bw == 1,
                        aggregated: status.ampdu,
                        pwdb,
                        antenna_mux: None,
                    });
                }
            }
            for word in 1..6 {
                ring.write32(offset + word * 4, 0)?;
            }
            buffer.sync();
            ring.sync();
            ring.write32(offset, RX_BUFFER as u32 | end | OWN)?;
            ring.sync();
            Ok((true, packet, report))
        })?;
        if let Some((bytes, take)) = report {
            self.packet.ae.c2h(&bytes[..take]);
        }
        if consumed {
            self.packet.receive = (slot + 1) % self.depth;
        }
        self.phase = Phase::Running;
        Ok(ReceiveStep { consumed, packet })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_ae_tests.rs"]
mod tests;
