// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE branch of the retained linked-ring packet owner.
//!
//! Mounted as `prepare::packet::be8723` (it needs the owner's private ring
//! storage); the chip facts it composes live beside it in `rtl8723be/`. The
//! rings are the RTL8821AE linked geometry (`trx.h`: 64-byte TX entries with
//! the buffer at dword 10 and the next link at dword 12, the 32-byte in-ring
//! RX descriptor with the buffer at dword 6), so ring validation and the TX
//! host receipt are the 8821AE ones (`packet_ae.rs`); the 8723BE pieces are:
//!
//! - Release (`rtl8723be_hw_init` tail): `REG_CR` word `0x2ff` (deferred by
//!   `prepare` until bus mastering), then `REG_PCIE_CTRL_REG + 1 = 0`;
//!   `rtl_op_add_interface` then runs `rtl8723be_set_network_type(STATION)`
//!   without a link.
//! - TX (`rtl_pci_tx`, `rtl_get_tcb_desc`, `rtl8723be_tx_fill_desc`): one
//!   outstanding first+last MPDU, OWN written last, then the queue doorbell.
//!   Ordinary unicast DATA under the installed RA mask leaves USE_RATE /
//!   DISFB clear at `_rtl_get_highest_n_rate` (`dm.useramask` is set by
//!   `rtl8723be_dm_init_rate_adaptive_mask`), RATE_ID from `mac->mode`
//!   (`_rtl_txrate_selectmode`: NGB 0 / GB 4 / B 6, MC 7 without a link),
//!   MACID 0; EAPOL and (QoS) Null DATA request a TX report
//!   (`rtl_set_tx_report`, `SW_DEFINE = (sn & 0x3f) << 2`). Every rate the
//!   descriptor can put on air must be admitted by the `NAPC` permission.
//! - RX (`_rtl_pci_rx_interrupt`, `rtl8723be_rx_query_desc`): the payload
//!   at `drvinfo + shift`, legacy 20 MHz frames (MCS0-7 / A-MPDU only on an
//!   HT link); `rpt_sel` buffers are C2H packets queued for
//!   [`Prepared::be8723_service_c2h`], which runs `rtl_c2h_content_parsing`
//!   through the coexistence owner (`rtl8723be::coex`), as Linux's
//!   `c2hcmd_wq` does after the RX interrupt.
//! - Interrupts: `rtl8723be_{enable,disable}_interrupt` and the
//!   `_rtl_pci_interrupt` recognition pass ([`h2c::service_interrupt`]).
//! - Every H2C goes through the coexistence owner's mailbox (the chip's
//!   single `last_hmeboxnum`); leisure PS is `rtl_lps_set_psmode` through
//!   `coex::Owner::lps_{enter,leave}` (`btc_lps_notify` + the BT LPS form of
//!   `rtl8723be_set_fw_pwrmode_cmd`).
//! - Join: `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`: `HW_VAR_AID`,
//!   `_rtl8723be_download_rsvd_page` (BCN_VALID polled, up to five uploads)
//!   over [`rsvd_page::pages`], then the MSRRPT connect report.
//! - Stop: `btc_halt_notify`, then the stopped owner's DMA idle proof
//!   (`RTL8723_NIC_LPS_ENTER_FLOW`'s TX-buffer-empty / RXDMA-idle
//!   conditions); `rtl8723be_card_disable` is the rebuild's power-down.
use super::super::super::rtl8723be::{dm, h2c, packet::C2hQueue, rsvd_page, station as hw, trx};
use super::{
    extent, queue, Error, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep, OWN,
    RX_BUFFER, RX_BYTES, TX_BYTES,
};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// `RATR_INX_WIRELESS_*` (`wifi.h`) the station descriptor names.
const RATR_INX_WIRELESS_NGB: u8 = 0;
const RATR_INX_WIRELESS_GB: u8 = 4;
const RATR_INX_WIRELESS_B: u8 = 6;
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `_rtl8723be_hw_configure`: `reg_bcn_ctrl_val = 0x1d`.
const BCN_CTRL_AFTER_INIT: u8 = 0x1d;
/// `_rtl8723be_download_rsvd_page`: up to five uploads, 20 × 10 us polls.
const RSVD_ATTEMPTS: usize = 5;
const BCN_VALID_POLLS: usize = 20;
/// `_rtl8723be_init_mac` `REG_CR` word.
const CR_RUNNING: u16 = 0x02ff;
/// Bound on queued C2H packets awaiting [`Prepared::be8723_service_c2h`].
const C2H_QUEUE: usize = 32;

/// The 8723BE state of the retained owner.
pub(in super::super) struct State {
    /// `rtlpci->receive_config` / `reg_bcn_ctrl_val` caches.
    pub(in super::super) receive: hw::ReceiveConfig,
    /// Peer, `mac->bw_40` and `ratr_index` of the installed RA mask.
    pub(in super::super) link: Option<(h2c::Peer, bool, u8)>,
    /// `rtlpriv->ra.ratr_state` (`DM_RATR_STA_INIT` 0).
    pub(in super::super) ratr_state: u8,
    /// `bss_conf->use_short_preamble` / `use_short_slot` as programmed.
    pub(in super::super) erp_timing: Option<(bool, bool)>,
    /// `rtlpriv->tx_report.sn`.
    report_sn: u16,
    /// Latest C2H TX report (`sn`, acknowledged).
    pub(in super::super) report: Option<(u16, bool)>,
    /// RX C2H packets awaiting the coexistence dispatch.
    pub(in super::super) c2h: C2hQueue,
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            receive: hw::ReceiveConfig {
                rcr: super::super::super::rtl8723be::mac::RCR,
                bcn_ctrl: BCN_CTRL_AFTER_INIT,
            },
            link: None,
            ratr_state: 0,
            erp_timing: None,
            report_sn: 0,
            report: None,
            c2h: C2hQueue::default(),
        }
    }
}

fn closed(admission: Option<&super::super::station::Admission>) -> bool {
    admission.is_some_and(|control| control.closed.load(Ordering::Acquire))
}

/// `sta_entry->ratr_index` set by `rtl8723be_update_hal_rate_mask` for the
/// peer's `wireless_mode`.
fn ratr_index(peer: &h2c::Peer) -> u8 {
    match peer.mode() {
        h2c::WirelessMode::N24 => RATR_INX_WIRELESS_NGB,
        h2c::WirelessMode::G => RATR_INX_WIRELESS_GB,
        h2c::WirelessMode::B => RATR_INX_WIRELESS_B,
    }
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    fn be8723_coex(&mut self) -> Result<&mut super::super::super::rtl8723be::coex::Owner, Error> {
        self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)
    }

    /// `rtl8723be_hw_init` tail on the retained owner: software crypto
    /// (`SECR` 0), queues unpaused and IRQ masks clear are proven, bus
    /// mastering is opened, then `REG_CR` word `0x2ff` and
    /// `REG_PCIE_CTRL_REG + 1 = 0`, then `rtl8723be_set_network_type(STATION)`
    /// without a link over the configured radio's trimmed RCR.
    pub(super) fn be8723_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.rtl8723be_power.is_none()
            || self.rtl8723be_coex.is_none()
        {
            return Err(Error::State);
        }
        let rcr = self
            .rtl8723be
            .as_deref()
            .map(|(_, radio)| radio.receive_config)
            .ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.io.authority(false, || self.ae_validate_rings())?;
        if self.io.read8(0x680)? != 0
            || self.io.read8(0x522)? != 0
            || self.io.read32(h2c::REG_HIMR)? != 0
            || self.io.read32(h2c::REG_HIMRE)? != 0
        {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        self.io.write16(0x100, CR_RUNNING)?;
        self.io.write8(0x301, 0)?;
        if self.io.read8(0x100)? != 0xff
            || self.io.read8(0x101)? != 0x02
            || self.io.read8(0x301)? != 0
        {
            return Err(Error::Readback);
        }
        self.packet.be8723.receive.rcr = rcr;
        hw::network_type_station(&self.io, &mut self.packet.be8723.receive, false)?;
        self.packet.next = [0; 7];
        self.packet.receive = 0;
        self.phase = Phase::Running;
        Ok(())
    }

    /// Linux `rtl8723be_hw_init` leaves the firmware awake
    /// (`fw_current_inpsmode` false); nothing is sent. Only a powered MAC
    /// (`REG_CR != 0xEA`) is accepted.
    pub(super) fn be8723_awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        if self.io.read8(0x100)? == 0xea {
            return Err(Error::RadioOff);
        }
        Ok(())
    }

    /// `rtl_pci_tx` for one frame (see the module documentation).
    pub(super) fn be8723_submit(
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
            trx::DESC_RATEMCS7
        } else {
            trx::DESC_RATE54M
        };
        if frame.len() < 24
            || !ht && (aggregate.is_some() || short_gi)
            || aggregate.is_some_and(|(density, _)| density > 7)
            || aggregate.is_some() && frame[0] != 0x88
            || rate > highest
        {
            return Err(Error::Packet);
        }
        let permission = self.rtl8723be_power.ok_or(Error::State)?;
        let op = permission.operating();
        let data = frame[0] & 0x0c == 0x08;
        let nullfunc = data && matches!(frame[0] & 0xf0, 0x40 | 0xc0);
        let special = super::ee92::special_data(frame);
        // rtl_get_tcb_desc: ordinary unicast DATA (rix != 0, not Null or a
        // `rtl_is_special_data` frame) hands the rate to the firmware RA.
        let adaptive = adaptive && !special && !nullfunc;
        let link = match self.packet.be8723.link {
            Some((peer, _, _)) if adaptive => {
                if frame[4] & 1 != 0 || !data {
                    return Err(Error::Packet);
                }
                Some(peer)
            }
            None if adaptive => return Err(Error::State),
            _ => None,
        };
        let hw_rate = match link {
            Some(peer) => match peer.mode() {
                h2c::WirelessMode::N24 => trx::DESC_RATEMCS7,
                h2c::WirelessMode::B => 0x03,
                h2c::WirelessMode::G => trx::DESC_RATE54M,
            },
            None if special => trx::DESC_RATE1M,
            None => rate,
        };
        let protection = self.packet.protection;
        let protect = protection != super::super::super::protection::Mode::None;
        if !permission.admits(hw_rate) || protect && !permission.admits(0x08) {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
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
        let rate_id = match self.packet.be8723.link {
            Some((_, _, index)) => index,
            None => RATR_INX_WIRELESS_MC,
        };
        let tx_report = super::ae::wants_report(frame).then(|| {
            let sn = (self.packet.be8723.report_sn.wrapping_add(1) & 0x3f) << 2;
            self.packet.be8723.report_sn = self.packet.be8723.report_sn.wrapping_add(1);
            sn
        });
        let bw_40 = op.forty();
        // `_rtl_query_protection_mode`: CTS-to-self sets `rts_enable` and
        // `cts_enable`, RTS/CTS `rts_enable` only; both at `DESC_RATE24M`
        // with sub-carrier 0 (the TCB is zeroed otherwise).
        let (rts_enable, cts_enable) = match protection {
            super::super::super::protection::Mode::None => (false, false),
            super::super::super::protection::Mode::RtsCts => (true, false),
            super::super::super::protection::Mode::CtsToSelf => (true, true),
        };
        let descriptor = trx::TxDesc::fill(&trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id,
            hw_rate,
            use_driver_rate: link.is_none(),
            disable_fallback: link.is_none(),
            use_shortgi: short_gi,
            use_shortpreamble: false,
            bw_40,
            // `_rtl_query_bandwidth_mode`: a unicast HT packet above 54M on
            // a 40 MHz station.
            packet_bw_40: bw_40 && ht && !multicast && hw_rate > trx::DESC_RATE54M,
            cur_40_prime_sc: op.grant_prime_sc(),
            ampdu: aggregate.is_some_and(|(_, operational)| operational),
            ampdu_density: aggregate.map_or(0, |(density, _)| density),
            sec_type: 0,
            qos_data: frame[0] == 0x88,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast,
            rts_enable,
            cts_enable,
            rts_rate: if protect { 0x08 } else { 0 },
            rts_sc: 0,
            rts_use_shortpreamble: false,
            rts_use_shortgi: false,
            tx_report,
            buffer_len: frame.len() as u16,
            buffer_addr: address,
        });
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

    /// One `_rtl_pci_rx_interrupt` step with `rtl8723be_rx_query_desc`
    /// fields; C2H buffers are queued for [`Self::be8723_service_c2h`].
    pub(super) fn be8723_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let slot = self.packet.receive;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let permission = self.rtl8723be_power.ok_or(Error::State)?;
        let channel = permission.channel();
        let forty = permission.operating().forty();
        let ht = self.packet.ht;
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
            if start.checked_add(length).is_none_or(|n| n > RX_BUFFER) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            let mut report = None;
            if status.c2h {
                buffer.sync();
                let mut bytes = [0u8; super::super::super::rtl8723be::btc::C2H_MAX];
                let take = length.min(bytes.len());
                buffer.read_bytes(start, &mut bytes[..take])?;
                report = Some((bytes, take));
            }
            let rate_ok = if status.is_ht {
                ht && (trx::DESC_RATEMCS0..=trx::DESC_RATEMCS7).contains(&status.rate)
            } else {
                status.rate <= trx::DESC_RATE54M
            };
            let longest = if ht {
                26 + 16 + narf_wireless::amsdu::Limit::Ht7935.bytes() + 4
            } else {
                2304 + 4
            };
            if !status.c2h
                && !status.hw_error()
                && (!status.ampdu || ht)
                && rate_ok
                && (status.bw == 0 || forty && status.bw == 1)
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
                // Software CCMP: protected frames keep IV/ciphertext/MIC.
                if fc & 0x400 == 0 && bytes[22] & 15 == 0 && (fc & 0x4000 == 0 || !status.decrypted)
                {
                    // `_rtl8723be_query_rxphystatus` `rx_pwdb_all` from the
                    // PHY status ahead of the frame (`dm::rx_pwdb`).
                    let pwdb = if status.physt && status.drvinfo_size >= 8 {
                        let mut phy = [0u8; 8];
                        buffer.read_bytes(status.shift, &mut phy)?;
                        dm::rx_pwdb(&phy, status.is_cck())
                    } else {
                        None
                    };
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: status.is_ht,
                        short_gi: false,
                        width40: status.bw == 1,
                        aggregated: status.ampdu,
                        pwdb,
                        antenna_mux: None,
                    });
                }
            }
            let mut arm = [0u32; 8];
            trx::rx_arm(
                &mut arm,
                extent(buffer, RX_BUFFER, 4)?,
                RX_BUFFER as u16,
                end != 0,
            );
            for (word, value) in arm.iter().copied().enumerate().skip(1) {
                ring.write32(offset + word * 4, value)?;
            }
            buffer.sync();
            ring.sync();
            ring.write32(offset, arm[0])?;
            ring.sync();
            Ok((true, packet, report))
        })?;
        if let Some((bytes, take)) = report {
            // `rtl_c2hcmd_enqueue`: bounded, the oldest dropped.
            if self.packet.be8723.c2h.len() >= C2H_QUEUE {
                self.packet.be8723.c2h.pop();
            }
            self.packet.be8723.c2h.push(&bytes[..take]);
        }
        if consumed {
            self.packet.receive = (slot + 1) % self.depth;
        }
        self.phase = Phase::Running;
        Ok(ReceiveStep { consumed, packet })
    }

    /// `rtl_c2hcmd_launcher`: every queued RX C2H packet through
    /// `rtl_c2h_content_parsing` on the coexistence owner (BT info / MP
    /// reports drive the coexistence algorithm, whose MP waits poll the same
    /// queue); a TX report is recorded (`rtl_tx_report_handler`). Returns
    /// the number of packets dispatched.
    pub(crate) async fn be8723_service_c2h(&mut self) -> Result<usize, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let mut served = 0;
        while let Some((n, pkt)) = self.packet.be8723.c2h.pop() {
            self.phase = Phase::Failed;
            let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
            let outcome = coex
                .c2h(&self.io, &mut self.packet.be8723.c2h, &pkt[..n])
                .await?;
            if let super::super::super::rtl8723be::coex::C2h::TxReport { sn, st, .. } = outcome {
                self.packet.be8723.report = Some((sn, st == 0));
            }
            self.phase = Phase::Running;
            served += 1;
        }
        Ok(served)
    }

    /// `rtl8723be_enable_interrupt` on a running owner whose vector is bound.
    pub(super) fn be8723_enable_interrupts(&mut self) -> Result<(), Error> {
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

    /// One `_rtl_pci_interrupt` recognition pass for the 8723BE profile.
    pub(super) fn be8723_recognize_interrupts(
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

    /// Authentication-time `BSS_CHANGED_BSSID` (`HW_VAR_BSSID`),
    /// `BASIC_RATES` / ERP and `rtl8723be_update_channel_access_setting` /
    /// `rtl8723be_set_qos` ([`hw::configure_rates`], `ht_enable` false until
    /// the association).
    pub(super) fn be8723_prepare_peer(
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
        let timing = hw::configure_rates(&self.io, rates, basic, capability, None, false)?;
        self.packet.be8723.erp_timing = Some(timing);
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` for 8723BE:
    /// `rtl_cam_reset_all_entry`, `HW_VAR_KEEP_ALIVE` (10,
    /// `H2C_8723B_KEEP_ALIVE_CTRL`), `rtl8723be_set_network_type` with the
    /// link (CBSSID on), `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`
    /// (`HW_VAR_AID`, `_rtl8723be_download_rsvd_page`, MSRRPT connect), then
    /// `btc_mediastatus_notify(RT_MEDIA_CONNECT)`. The firmware RA mask
    /// follows separately (`be8723_install_rate_mask`). Linux logs and
    /// continues when BCN_VALID never sets; here that is a terminal
    /// `CommandTimeout`.
    pub(super) async fn be8723_complete_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() || self.packet.leisure {
            return Err(Error::State);
        }
        if !(1..=2007).contains(&aid) || peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Packet);
        }
        let local = self.packet.local.ok_or(Error::State)?;
        let pages = rsvd_page::pages(local, peer, aid).ok_or(Error::Packet)?;
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
        self.io.write32(hw::REG_CAMCMD, hw::CAM_RESET)?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.rtl8723be_coex
            .as_deref_mut()
            .ok_or(Error::State)?
            .mailbox
            .fill(&self.io, h2c::H2C_KEEP_ALIVE_CTRL, &[0xff, 10])
            .await?;
        hw::network_type_station(&self.io, &mut self.packet.be8723.receive, true)?;
        hw::set_aid(&self.io, aid)?;
        self.be8723_download_rsvd_page(address, pages.len() as u16, admission, &policy)
            .await?;
        if closed(admission) {
            return Err(Error::State);
        }
        policy(self)?;
        self.rtl8723be_coex
            .as_deref_mut()
            .ok_or(Error::State)?
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(true))
            .await?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.be8723_media_status(true).await?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `btc_mediastatus_notify` (`core.c:1181`) with the link state the
    /// coexistence algorithm reads (`halbtc_get`: station link, current
    /// channel and width from the `NAPC` permission) and the `ps.c` LPS
    /// link gate.
    async fn be8723_media_status(&mut self, connect: bool) -> Result<(), Error> {
        use super::super::super::btcoex::btc::{ChanBw, WifiMode};
        let permission = self.rtl8723be_power.ok_or(Error::State)?;
        let mode = match self.packet.be8723.link.map(|(peer, _, _)| peer.mode()) {
            Some(h2c::WirelessMode::B) => WifiMode::B,
            Some(h2c::WirelessMode::G) => WifiMode::G,
            _ => WifiMode::N,
        };
        let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
        let mut wifi = coex.btc.wifi;
        wifi.station_linked = connect;
        wifi.current_channel = permission.operating().grant_channel().unwrap_or(0);
        wifi.chan_bw = if permission.operating().forty() {
            ChanBw::Ht20_40
        } else {
            ChanBw::Ht20
        };
        wifi.mode = mode;
        coex.update_wifi(wifi);
        coex.lps.linked = connect;
        coex.lps.report_linked = connect;
        coex.media_status(&self.io, &mut self.packet.be8723.c2h, connect)
            .await?;
        Ok(())
    }

    /// `_rtl8723be_download_rsvd_page` with `rtl8723be_set_fw_rsvdpagepkt`
    /// / `rtl_cmd_send_packet` on BEACON_QUEUE descriptor 0
    /// (`rtl8723be_tx_fill_cmddesc`, `rtl8723be_tx_polling` BIT(4)) and the
    /// `H2C_8723B_RSVDPAGE` location command after every upload.
    async fn be8723_download_rsvd_page(
        &mut self,
        address: u32,
        length: u16,
        admission: Option<&super::super::station::Admission>,
        policy: &impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let cr = self.io.read8(0x101)?;
        self.io.write8(0x101, cr | 1)?;
        let receive = &mut self.packet.be8723.receive;
        h2c::set_bcn_ctrl(&self.io, &mut receive.bcn_ctrl, 0, 1 << 3)?;
        h2c::set_bcn_ctrl(&self.io, &mut receive.bcn_ctrl, 1 << 4, 0)?;
        let txq = self.io.read8(hw::REG_FWHW_TXQ_CTRL + 2)?;
        self.io.write8(hw::REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
        let mut descriptor = trx::TxDesc::fill_cmd(length, address);
        descriptor.set_own(false);
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
                    for (word, value) in descriptor.dw[..11].iter().copied().enumerate() {
                        ring.write32(word * 4, value)?;
                    }
                    ring.sync();
                    ring.write32(0, descriptor.dw[0] | OWN)?;
                    ring.sync();
                    Ok(())
                })?;
                self.io.kick(1 << 4)?;
            }
            proven = true;
            self.rtl8723be_coex
                .as_deref_mut()
                .ok_or(Error::State)?
                .mailbox
                .fill(&self.io, h2c::H2C_RSVDPAGE, &h2c::RSVDPAGE_LOCATION)
                .await?;
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
        if valid {
            self.io.write8(hw::REG_TDECTRL + 2, 1)?;
        }
        let receive = &mut self.packet.be8723.receive;
        h2c::set_bcn_ctrl(&self.io, &mut receive.bcn_ctrl, 1 << 3, 0)?;
        h2c::set_bcn_ctrl(&self.io, &mut receive.bcn_ctrl, 0, 1 << 4)?;
        if txq & (1 << 6) != 0 {
            self.io.write8(hw::REG_FWHW_TXQ_CTRL + 2, txq)?;
        }
        let cr = self.io.read8(0x101)?;
        self.io.write8(0x101, cr & !1)?;
        if valid {
            Ok(())
        } else {
            Err(Error::CommandTimeout)
        }
    }

    /// `rtl8723be_update_hal_rate_mask` for the station peer at `level`:
    /// `H2C_8723B_RA_MASK` then `_rtl8723be_set_bcn_ctrl_reg(BIT(3), 0)`.
    /// The firmware RA may only pick rates the permission admits: a mask
    /// whose rates ([`h2c::mask_rates`]) are not a non-empty subset of
    /// `admitted` is refused, never narrowed.
    pub(super) async fn be8723_install_rate_mask(
        &mut self,
        peer: h2c::Peer,
        bw40: bool,
        level: u8,
        update_bw: bool,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        let admitted = self.rtl8723be_power.ok_or(Error::State)?.admitted_rates() as u32;
        let payload = h2c::rate_mask(&peer, bw40, level, update_bw);
        let rates = h2c::mask_rates(&payload).ok_or(Error::Packet)?;
        if rates == 0 || rates & !admitted != 0 {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        self.phase = Phase::Failed;
        self.rtl8723be_coex
            .as_deref_mut()
            .ok_or(Error::State)?
            .mailbox
            .fill(&self.io, h2c::H2C_RA_MASK, &payload)
            .await?;
        h2c::set_bcn_ctrl(
            &self.io,
            &mut self.packet.be8723.receive.bcn_ctrl,
            1 << 3,
            0,
        )?;
        let index = ratr_index(&peer);
        self.packet.be8723.link = Some((peer, bw40, index));
        self.packet.be8723.ratr_state = level;
        self.packet.rate_mask = Some(index);
        self.phase = Phase::Running;
        Ok(())
    }

    /// The composed part of `rtl8723be_dm_watchdog` (firmware out of power
    /// save): `rtl8723be_dm_refresh_rate_adaptive_mask` ([`dm::ra_state`]
    /// over the smoothed `undec_sm_pwdb`; a level change re-sends the mask
    /// with `update_bw`), then `rtl_watchdog_wq_callback`'s
    /// `btc_periodical` through the coexistence owner (with the queued C2H
    /// first, as `c2hcmd_wq` runs ahead of it; the coexistence step also
    /// runs in leisure PS, the DM step does not). The other DM steps keep
    /// their `rtl8723be_hw_init` table values. Returns whether a mask was
    /// sent.
    pub(super) async fn be8723_dm_watchdog(
        &mut self,
        undec_sm_pwdb: i64,
        now_ms: u64,
    ) -> Result<bool, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.be8723_service_c2h().await?;
        let mut refreshed = false;
        // The DM step runs only with the firmware out of power save;
        // `btc_periodical` runs from `rtl_watchdog_wq_callback` either way.
        if let (Some((peer, bw40, _)), false) = (self.packet.be8723.link, self.packet.leisure) {
            if let Some(state) = dm::ra_state(undec_sm_pwdb, self.packet.be8723.ratr_state) {
                self.be8723_install_rate_mask(peer, bw40, state, true)
                    .await?;
                refreshed = true;
            }
        }
        self.phase = Phase::Failed;
        let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
        let mut wifi = coex.btc.wifi;
        wifi.undec_sm_pwdb = undec_sm_pwdb as i32;
        coex.update_wifi(wifi);
        coex.watchdog(&self.io, &mut self.packet.be8723.c2h, now_ms)
            .await?;
        self.phase = Phase::Running;
        Ok(refreshed)
    }

    /// `rtl_lps_set_psmode(EAUTOPS)` through the coexistence owner (the
    /// station applied `rtl_lps_enter_core`'s gates). A coexistence hold-off
    /// (no `SETPWRMODE` sent) is a successful no-op: `leisure` stays false.
    pub(super) async fn be8723_enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
        coex.lps.enter_allowed = true;
        let sent = coex.lps_enter(&self.io).await?;
        self.packet.leisure = sent.is_some();
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_lps_set_psmode(EACTIVE)` through the coexistence owner.
    pub(super) async fn be8723_leave_leisure(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.packet.leisure {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.rtl8723be_coex
            .as_deref_mut()
            .ok_or(Error::State)?
            .lps_leave(&self.io)
            .await?;
        self.packet.leisure = false;
        self.phase = Phase::Running;
        Ok(())
    }

    /// Disassociation: leave LPS, `rtl8723be_set_network_type(STATION)`
    /// without a link (MSR NOLINK, CBSSID off),
    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)` (MSRRPT only),
    /// `btc_mediastatus_notify(RT_MEDIA_DISCONNECT)` and the mac80211
    /// `BSS_CHANGED_BSSID` zero BSSID. The RA link is withdrawn. The caller
    /// holds the owner in `Phase::Failed`.
    pub(super) async fn be8723_disconnected(&mut self) -> Result<(), Error> {
        if core::mem::take(&mut self.packet.leisure) {
            self.rtl8723be_coex
                .as_deref_mut()
                .ok_or(Error::State)?
                .lps_leave(&self.io)
                .await?;
        }
        self.packet.be8723.link = None;
        self.packet.be8723.ratr_state = 0;
        self.packet.be8723.erp_timing = None;
        hw::network_type_station(&self.io, &mut self.packet.be8723.receive, false)?;
        self.rtl8723be_coex
            .as_deref_mut()
            .ok_or(Error::State)?
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(false))
            .await?;
        self.be8723_media_status(false).await?;
        hw::set_bssid(&self.io, [0; 6])
    }

    /// DMA retirement proof for a stopped owner (`rtl_pci_stop`): first
    /// `btc_halt_notify` through the coexistence owner, then, with TX paused
    /// (`REG_TXPAUSE = 0xff`), host TX DMA stopped (`REG_PCIE_CTRL_REG + 1 =
    /// 0xff`) and bus mastering cleared by `stop_packets`, the
    /// `RTL8723_NIC_LPS_ENTER_FLOW` idle conditions `rtl8723be_card_disable`
    /// starts from: `0x5f8..=0x5fb` zero (TX packet buffer empty, 5000 × 10
    /// us) and `REG_RXDMA_CONTROL` BIT(1) (RXDMA idle, 100 × 10 us). A
    /// timeout leaves every mapping retained. Success allows the published
    /// rings and buffers to be unmapped; the card disable itself
    /// (`power_runtime::disable_rtl8723be`) is the rebuild's power-down.
    pub(super) async fn be8723_quiesce(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Stopped || !self.published {
            return Err(Error::State);
        }
        if let Some(coex) = self.rtl8723be_coex.as_deref_mut() {
            coex.halt(&self.io).await?;
        }
        if self.io.read8(0x522)? != 0xff || self.io.read8(0x301)? != 0xff {
            return Err(Error::Readback);
        }
        let mut empty = false;
        for _ in 0..5000 {
            let word = self.io.read32(0x5f8)?;
            if word == u32::MAX {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            if word == 0 {
                empty = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        let mut idle = false;
        for _ in 0..100 {
            if self.io.read8(0x286)? & 2 != 0 {
                idle = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        if !empty || !idle {
            return Err(Error::PacketTimeout);
        }
        self.published = false;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_owner_tests.rs"]
mod tests;
