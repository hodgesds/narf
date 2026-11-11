// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE branch of the retained linked-ring packet owner.
//!
//! Mounted as `prepare::packet::de92` (it needs the owner's private ring
//! storage); the chip facts it composes live beside it in `rtl8192de/`.
//! The rings are the 88EE linked geometry (`prepare::Chip::Rtl8192de`:
//! 64-byte TX entries with the buffer at dword 8 and the next link at byte
//! 40, the 32-byte in-ring RX descriptor with the buffer at dword 6), so
//! ring validation, the TX host receipt (`delivery`: OWN clear with the
//! stable words intact) and the terminal stop are the shared ones; the 92D
//! pieces are:
//!
//! - Release (`_rtl92de_init_mac`): the ring `*_DESA` bases are written
//!   after the MAC IO release (`configure_rtl8192de`'s `power_on` re-issued
//!   `REG_CR = 0` / `0x2ff` after `prepare` programmed them, so they are
//!   re-written and read back here, in Linux order), bus mastering is
//!   opened, then `REG_CR` word `0x2ff` and `REG_PCIE_CTRL_REG + 1 = 0`;
//!   `rtl_op_add_interface` then runs `rtl92de_set_network_type(STATION)`
//!   without a link.
//! - TX (`rtl_pci_tx`, `rtl_get_tcb_desc`, `rtl92de_tx_fill_desc`,
//!   `rtl92de_tx_polling`): one outstanding first+last MPDU from
//!   [`trx::TxDesc::fill`], OWN written last, then the `REG_PCIE_CTRL_REG`
//!   `BIT(hw_queue)` doorbell. Ordinary unicast DATA under the installed RA
//!   mask leaves USE_RATE / DISFB clear (`dm.useramask` is set by
//!   `rtl92de_init_sw_vars`), RATE_ID from `mac->mode`
//!   (`_rtl_txrate_selectmode`: GB 4 / B 6, MC 7 without a link), MACID 0;
//!   EAPOL and (QoS) Null DATA request a TX report (`SPE_RPT`, `SW_DEFINE =
//!   (sn & 0x3f) << 2`). `ppsc->fwctrl_lps` is false (`rtl92de_mod_params`),
//!   so no frame takes the LPS hardware-sequence rule. Every rate the
//!   descriptor can put on air must be admitted by the `N92D` permission.
//!   The composition is the 2.4 GHz legacy station: no HT rate, A-MPDU or
//!   SGI is admitted.
//! - RX (`_rtl_pci_rx_interrupt`, `rtl92d_rx_query_desc`): the payload at
//!   `drvinfo + shift` of the RX buffer (the in-ring descriptor is not in
//!   the buffer), legacy 20 MHz frames. The 92D RX descriptor has no C2H
//!   bit and the PHY-status `rx_pwdb_all` decode is not composed (no RSSI
//!   is reported; Linux's 92DE watchdog has its RA refresh commented out).
//! - Interrupts: [`mac::enable_interrupt`] / [`mac::disable_interrupt`] and
//!   the `_rtl_pci_interrupt` pass over `rtl92de_interrupt_recognized`
//!   (`ISR & irq_mask[0]`, W1C; `intb` 0) at `0x120`/`0x124`/`0x128`.
//! - Leisure PS: `rtl92de_mod_params.fwctrl_lps = false`, so
//!   `rtl_lps_enter_core` returns at its first gate and nothing is sent;
//!   software LPS (`swctrl_lps`, `rtl_swlps_*`) is not composed.
//! - Join: `rtl_cam_reset_all_entry`, `rtl92de_set_network_type` with the
//!   link, then `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`: `HW_VAR_AID`,
//!   the `REG_CR + 1` / BCN_CTRL / `0x422` envelope around
//!   `rtl92d_set_fw_rsvdpagepkt` (`_rtl92d_cmd_send_packet` on BEACON_QUEUE
//!   descriptor 0 with `rtl92de_tx_fill_cmddesc`, the `BIT(4)` beacon
//!   doorbell, then `H2C_RSVDPAGE`), then `H2C_JOINBSSRPT(1)`. The 92D sets
//!   no `HW_VAR_KEEP_ALIVE` (its `set_hw_reg` has no such case) and has no
//!   BCN_VALID receipt.
//! - RA: `rtl92d_update_hal_rate_mask` (`H2C_RA_MASK`) bounded by the
//!   permission's admitted rates; no BCN_CTRL write follows on this chip.
//! - Card disable: `rtl92de_card_disable` with its DMA retirement proof.
use super::super::super::rtl8192de::{
    h2c, mac, packet::rate_index_for_mode, power, rate::WirelessMode, rsvd_page, station as hw,
    trx, Band, MacPhyMode, RfType,
};
use super::{
    extent, queue, Error, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep, OWN, RX_BASE,
    RX_BUFFER, RX_BYTES, TX_BASES, TX_BYTES,
};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// `RATR_INX_WIRELESS_MC` (`_rtl_txrate_selectmode` without a station).
const RATR_INX_WIRELESS_MC: u8 = h2c::RATR_INX_WIRELESS_MC;
/// `rtl92de_tx_polling(BEACON_QUEUE)`.
const BEACON_POLL: u16 = 1 << 4;
/// `REG_CR` / `REG_TXPAUSE` / `REG_PCIE_CTRL_REG`.
const REG_CR: u16 = 0x0100;
const REG_TXPAUSE: u16 = 0x0522;
const REG_PCIE_CTRL_REG: u16 = 0x0300;
/// `REG_SYS_FUNC_EN + 1` after `_rtl92de_poweroff_adapter` (`FEN_DCORE`
/// dropped).
const SYS_FUNC_EN_OFF: u8 = 0x51;

/// The per-function chip facts the configured radio fixes
/// (`rtl92de_hw_init` / `rtl92d_read_eeprom_info`), bound by
/// `configure_rtl8192de`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct Facts {
    /// Trimmed `rtlpci->receive_config`.
    pub(in super::super) receive_config: u32,
    /// `rtlhal->macphymode`.
    pub(in super::super) mode: MacPhyMode,
    /// `rtlhal->interfaceindex` (the PCI function).
    pub(in super::super) interface_index: u8,
    /// `rtlphy->rf_type`.
    pub(in super::super) rf_type: RfType,
}

/// The 92D state of the retained owner.
pub(in super::super) struct State {
    /// Chip facts of the configured radio.
    pub(in super::super) facts: Option<Facts>,
    /// `rtlhal->fw_version` of the downloaded image (`HW_VAR_BASIC_RATE`
    /// writes `REG_INIRTS_RATE_SEL` only above `0xe`).
    pub(in super::super) fw_version: u16,
    /// `rtl8192d/fw_common.c` H2C mailbox (`last_hmeboxnum`).
    pub(in super::super) mailbox: h2c::Mailbox,
    /// `rtlpci->reg_bcn_ctrl_val`.
    pub(in super::super) bcn: hw::BcnCtrl,
    /// `rtlpci->receive_config` once `HW_VAR_RCR` changed it.
    pub(in super::super) receive_config: Option<u32>,
    /// Peer, `mac->bw_40` and `ratr_index` of the installed RA mask.
    pub(in super::super) link: Option<(h2c::Peer, bool, u8)>,
    /// `bss_conf->use_short_preamble` / `use_short_slot` as programmed.
    pub(in super::super) erp_timing: Option<(bool, bool)>,
    /// `rtlpriv->tx_report.sn`.
    report_sn: u16,
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            facts: None,
            fw_version: 0,
            mailbox: h2c::Mailbox::new(),
            bcn: hw::BcnCtrl::default(),
            receive_config: None,
            link: None,
            erp_timing: None,
            report_sn: 0,
        }
    }
}

fn closed(admission: Option<&super::super::station::Admission>) -> bool {
    admission.is_some_and(|control| control.closed.load(Ordering::Acquire))
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    fn de92_facts(&self) -> Result<Facts, Error> {
        self.packet.de92.facts.ok_or(Error::State)
    }

    /// Record the downloaded image's `rtlhal->fw_version` (the
    /// `rtl92d_download_fw` header read).
    pub(crate) fn bind_rtl8192de_firmware(&mut self, version: u16) {
        self.packet.de92.fw_version = version;
    }

    /// `mac->cur_40_prime_sc` of the admitted operating point.
    pub(crate) fn rtl8192de_prime_sc(&self) -> u8 {
        self.rtl8192de_power
            .map_or(0, |permission| permission.operating().prime_sc())
    }

    /// `_rtl92de_init_mac`'s `*_DESA` writes, the DMA release and
    /// `rtl92de_set_network_type(STATION)` without a link (see the module
    /// documentation). Interrupt masks stay clear (polled owner).
    pub(super) fn de92_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.packet.de92.facts.is_none()
            || self.rtl8192de_power.is_none()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        for (address, ring) in TX_BASES.iter().zip(&self.tx) {
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            self.io.write32(*address, base)?;
        }
        let base = extent(
            self.receive.as_ref().ok_or(Error::State)?,
            self.depth * RX_BYTES,
            256,
        )?;
        self.io.write32(RX_BASE, base)?;
        self.io.authority(false, || self.validate_rings())?;
        if self.io.read32(mac::REG_HIMR)? != 0 || self.io.read32(mac::REG_HIMRE)? != 0 {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        self.io.write16(REG_CR, 0x02ff)?;
        self.io.write8(REG_PCIE_CTRL_REG + 1, 0)?;
        self.io.write8(REG_TXPAUSE, 0)?;
        if self.io.read8(REG_CR)? != 0xff
            || self.io.read8(REG_CR + 1)? != 0x02
            || self.io.read8(REG_PCIE_CTRL_REG + 1)? != 0
            || self.io.read8(REG_TXPAUSE)? != 0
        {
            return Err(Error::Readback);
        }
        self.de92_network_type(false)?;
        self.packet.next = [0; 7];
        self.packet.receive = 0;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl92de_set_network_type(NL80211_IFTYPE_STATION)` with the cached
    /// `receive_config` (the radio is on while the owner runs).
    fn de92_network_type(&mut self, linked: bool) -> Result<(), Error> {
        let mut rcr = match self.packet.de92.receive_config {
            Some(rcr) => rcr,
            None => self.de92_facts()?.receive_config,
        };
        let result = hw::set_network_type(
            &self.io,
            &mut rcr,
            &mut self.packet.de92.bcn,
            hw::MediaKind::Station,
            linked,
            true,
        );
        self.packet.de92.receive_config = Some(rcr);
        result
    }

    /// Linux `rtl92de_hw_init` leaves the firmware awake
    /// (`fw_current_inpsmode` false); nothing is sent. Only a powered MAC
    /// (`REG_CR != 0xEA`) is accepted.
    pub(super) fn de92_awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        if self.io.read8(REG_CR)? == 0xea {
            return Err(Error::RadioOff);
        }
        Ok(())
    }

    /// `rtl_pci_tx` for one frame (see the module documentation).
    pub(super) fn de92_submit(
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
        if frame.len() < 24
            || self.packet.ht
            || aggregate.is_some()
            || short_gi
            || rate > trx::DESC_RATE54M
        {
            return Err(Error::Packet);
        }
        let facts = self.de92_facts()?;
        let permission = self.rtl8192de_power.ok_or(Error::State)?;
        let op = permission.operating();
        if op.is_5ghz() {
            return Err(Error::State);
        }
        let data = frame[0] & 0x0c == 0x08;
        let nullfunc = data && matches!(frame[0] & 0xf0, 0x40 | 0xc0);
        let special = super::ee92::special_data(frame);
        // rtl_get_tcb_desc: ordinary unicast DATA (not Null or a
        // `rtl_is_special_data` frame) hands the rate to the firmware RA.
        let adaptive = adaptive && !special && !nullfunc;
        let link = match self.packet.de92.link {
            Some((peer, _, _)) if adaptive => {
                if frame[4] & 1 != 0 || !data {
                    return Err(Error::Packet);
                }
                Some(peer)
            }
            None if adaptive => return Err(Error::State),
            _ => None,
        };
        // `_rtl_get_highest_n_rate` for a legacy peer: 11M for B, 54M for G.
        let hw_rate = match link {
            Some(peer) if peer.mode == WirelessMode::B => 0x03,
            Some(_) => trx::DESC_RATE54M,
            None if special => trx::DESC_RATE1M,
            None => rate,
        };
        let protection = self.packet.protection;
        let protect = protection != super::super::super::protection::Mode::None;
        // `_rtl_query_protection_mode`: RTS/CTS-to-self at `DESC_RATE24M`.
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
        let rate_id = match self.packet.de92.link {
            Some((_, _, index)) => index,
            None => RATR_INX_WIRELESS_MC,
        };
        let sw_define = super::ae::wants_report(frame).then(|| {
            self.packet.de92.report_sn = self.packet.de92.report_sn.wrapping_add(1);
            (self.packet.de92.report_sn & 0x3f) << 2
        });
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
            use_shortgi: false,
            use_shortpreamble: false,
            bw_40: op.forty(),
            packet_bw_40: false,
            cur_40_prime_sc: op.prime_sc(),
            ampdu: false,
            ampdu_density: 0,
            sec_type: 0,
            qos_data: frame[0] == 0x88,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            rts_enable,
            cts_enable,
            rts_rate: if protect { 0x08 } else { 0 },
            rts_sc: 0,
            rts_stbc: false,
            rts_use_shortpreamble: false,
            rts_use_shortgi: false,
            buffer_len: frame.len() as u16,
            buffer_addr: address,
            band_5g: false,
            dual_mac_dual_phy: facts.mode == MacPhyMode::DualMacDualPhy,
            fwctrl_lps: false,
            rdg_en: false,
            spe_rpt: sw_define.is_some(),
            sw_define: sw_define.unwrap_or(0),
        });
        let mut prefix = [0u32; 10];
        prefix.copy_from_slice(&descriptor.dw[..10]);
        self.io.authority(true, || {
            buffer.write_bytes(0, frame)?;
            buffer.sync();
            Ok(())
        })?;
        let slot = self.packet.next[queue];
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
            // clear_pci_tx_desc_content covers the first 40 bytes; dword
            // 10's next link stays.
            for (word, value) in prefix.iter().copied().enumerate().skip(1) {
                ring.write32(offset + word * 4, value)?;
            }
            ring.write32(offset, prefix[0])?;
            ring.sync();
            ring.write32(offset, prefix[0] | OWN)?;
            ring.sync();
            Ok(())
        })?;
        self.io.kick(poll)?;
        self.phase = Phase::Running;
        Ok(id)
    }

    /// One `_rtl_pci_rx_interrupt` iteration over the in-ring descriptor
    /// with `rtl92d_rx_query_desc` fields.
    pub(super) fn de92_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let channel = self.rtl8192de_power.ok_or(Error::State)?.channel();
        let slot = self.packet.receive;
        let depth = self.depth;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let buffer_addr = extent(buffer, RX_BUFFER, 4)?;
        let offset = slot * RX_BYTES;
        let consumed = self.io.authority(true, || {
            ring.sync();
            let mut dw = [0u32; 8];
            for (word, value) in dw.iter_mut().enumerate() {
                *value = ring.read32(offset + word * 4)?;
            }
            let Some(status) = trx::RxStatus::parse(&dw) else {
                return Ok(None);
            };
            let last = slot + 1 == depth;
            if (dw[0] >> 30) & 1 != u32::from(last) || dw[6] != buffer_addr || dw[7] != 0 {
                return Err(Error::Descriptor);
            }
            let length = usize::from(status.length);
            // `_rtl_pci_rx_interrupt`: `skb_reserve(drvinfo + shift)`; the
            // in-ring descriptor is not part of the RX buffer.
            let start = status.drvinfo_size + status.shift;
            if start.checked_add(length).is_none_or(|n| n > RX_BUFFER) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            if !status.hw_error()
                && !status.is_ht
                && !status.ampdu
                && status.bw == 0
                && status.rate <= trx::DESC_RATE54M
                && (24..=2304 + 4).contains(&length)
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
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: false,
                        short_gi: false,
                        width40: false,
                        aggregated: false,
                        pwdb: None,
                        antenna_mux: None,
                    });
                }
            }
            let mut arm = [0u32; 8];
            trx::rx_arm(&mut arm, buffer_addr, RX_BUFFER as u16, last);
            for (word, value) in arm.iter().copied().enumerate().skip(1) {
                ring.write32(offset + word * 4, value)?;
            }
            buffer.sync();
            ring.sync();
            ring.write32(offset, arm[0])?;
            ring.sync();
            Ok(Some(packet))
        })?;
        let Some(packet) = consumed else {
            self.phase = Phase::Running;
            return Ok(ReceiveStep {
                consumed: false,
                packet: None,
            });
        };
        self.packet.receive = (slot + 1) % depth;
        self.phase = Phase::Running;
        Ok(ReceiveStep {
            consumed: true,
            packet,
        })
    }

    /// `rtl92de_enable_interrupt`; only a running owner whose vector is
    /// bound may unmask.
    pub(super) fn de92_enable_interrupts(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(true, || Ok(()))?;
        self.packet.interrupts = true;
        mac::enable_interrupt(&self.io)?;
        if self.io.read32(mac::REG_HIMR)? != mac::IRQ_MASK.0
            || self.io.read32(mac::REG_HIMRE)? != mac::IRQ_MASK.1
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl92de_disable_interrupt`.
    pub(super) fn de92_disable_interrupts(&mut self) -> Result<(), Error> {
        self.packet.interrupts = false;
        mac::disable_interrupt(&self.io)?;
        if self.io.read32(mac::REG_HIMR)? != 0 || self.io.read32(mac::REG_HIMRE)? != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }

    /// One `_rtl_pci_interrupt` pass: mask, `rtl92de_interrupt_recognized`
    /// (HISR under `irq_mask[0]`, W1C; `intb` 0), unmask. An all-ones
    /// status means the function vanished.
    pub(super) fn de92_recognize_interrupts(
        &mut self,
    ) -> Result<super::super::super::irq::Recognized, Error> {
        if self.phase != Phase::Running || !self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        mac::disable_interrupt(&self.io)?;
        let raw = self.io.read32(mac::REG_HISR)?;
        if raw == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        let inta = raw & mac::IRQ_MASK.0;
        self.io.write32(mac::REG_HISR, inta)?;
        mac::enable_interrupt(&self.io)?;
        self.phase = Phase::Running;
        Ok(super::super::super::irq::Recognized { inta, intb: 0 })
    }

    /// Authentication-time `BSS_CHANGED_BSSID` (`HW_VAR_BSSID`) and
    /// `BASIC_RATES` / ERP / `rtl92d_update_channel_access_setting`
    /// ([`hw::configure_rates`], `ht_enable` false until the association)
    /// at the programmed `cur_40_prime_sc`.
    pub(super) fn de92_prepare_peer(
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
        let prime_sc = self.rtl8192de_prime_sc();
        let fw_version = self.packet.de92.fw_version;
        self.phase = Phase::Failed;
        hw::set_bssid(&self.io, peer)?;
        hw::configure_rates(
            &self.io,
            hw::RateConfig {
                rates,
                basic,
                capability,
                erp: None,
                ht: false,
                prime_sc,
                fw_version,
                cisco: false,
            },
        )?;
        self.packet.de92.erp_timing = Some(super::super::super::rtl8192ee::station::erp_timing(
            capability, None,
        ));
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` for 8192DE (see the
    /// module documentation). The firmware RA mask follows separately
    /// (`de92_install_rate_mask`). The reserved-page body stays owned by
    /// the claim (`packet.reserved`) until a quiescence proof.
    pub(super) async fn de92_complete_peer(
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
        let pages = rsvd_page::pages(local, peer, aid)?;
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
        mac::cam_reset(&self.io)?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.de92_network_type(true)?;
        // HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT).
        hw::set_aid(&self.io, aid)?;
        let cr = self.io.read8(REG_CR + 1)?;
        self.io.write8(REG_CR + 1, cr | 1)?;
        let bcn = &mut self.packet.de92.bcn;
        bcn.set(&self.io, 0, 1 << 3)?;
        bcn.set(&self.io, 1 << 4, 0)?;
        let txq = self.io.read8(mac::REG_FWHW_TXQ_CTRL + 2)?;
        self.io
            .write8(mac::REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
        // `rtl92de_tx_fill_cmddesc` on 2.4 GHz without firmware LPS; OWN is
        // published last below.
        let descriptor = trx::TxDesc::fill_cmd(pages.len() as u16, address, false, false);
        {
            let _publication = admission.map(|control| control.publication.lock());
            if closed(admission) {
                return Err(Error::State);
            }
            policy(self)?;
            // A rejoin reuses beacon descriptor 0, as Linux's
            // `_rtl92d_cmd_send_packet` does; its earlier body is retired.
            let proven = !self.packet.retired.is_empty();
            let ring = &mut self.tx[0];
            self.io.authority(true, || {
                ring.sync();
                if ring.read32(0)? & OWN != 0 && !proven {
                    return Err(Error::Descriptor);
                }
                for (word, value) in descriptor.dw[..10].iter().copied().enumerate().skip(1) {
                    ring.write32(word * 4, value)?;
                }
                ring.sync();
                ring.write32(0, descriptor.dw[0] | OWN)?;
                ring.sync();
                Ok(())
            })?;
            self.io.kick(BEACON_POLL)?;
        }
        self.packet
            .de92
            .mailbox
            .fill(
                &self.io,
                h2c::H2C_RSVDPAGE,
                &rsvd_page::RSVDPAGE_LOCATION,
                true,
            )
            .await?;
        let bcn = &mut self.packet.de92.bcn;
        bcn.set(&self.io, 1 << 3, 0)?;
        bcn.set(&self.io, 0, 1 << 4)?;
        if txq & (1 << 6) != 0 {
            self.io.write8(mac::REG_FWHW_TXQ_CTRL + 2, txq)?;
        }
        self.io.write8(REG_CR + 1, cr & !1)?;
        if closed(admission) {
            return Err(Error::State);
        }
        policy(self)?;
        h2c::joinbss(
            &mut self.packet.de92.mailbox,
            &self.io,
            h2c::MEDIA_CONNECT,
            true,
        )
        .await?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl92d_update_hal_rate_mask(sta, level)` for the station peer (MAC
    /// id 0). The firmware RA may only pick rates the permission admits: a
    /// mask whose rate bits (`[27:0]`) are not a non-empty subset of the
    /// admitted set is refused, never narrowed
    /// ([`h2c::update_hal_rate_mask`]). The descriptor rate id is the
    /// `_rtl_txrate_selectmode` mode index (a station stores none).
    pub(super) async fn de92_install_rate_mask(
        &mut self,
        peer: h2c::Peer,
        bw40: bool,
        level: u8,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        if peer.ap_or_adhoc || !matches!(peer.mode, WirelessMode::B | WirelessMode::G) {
            return Err(Error::Packet);
        }
        let rf_type = self.de92_facts()?.rf_type;
        let admitted = self.rtl8192de_power.ok_or(Error::State)?.admitted_rates() as u32;
        self.phase = Phase::Failed;
        h2c::update_hal_rate_mask(
            &mut self.packet.de92.mailbox,
            &self.io,
            &h2c::RateSelection {
                peer: &peer,
                rf_type,
                band: Band::On2Ghz,
                bw40,
                rssi_level: level,
            },
            admitted,
            true,
        )
        .await?;
        let index = rate_index_for_mode(peer.mode);
        self.packet.de92.link = Some((peer, bw40, index));
        self.packet.rate_mask = Some(index);
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_lps_set_psmode(EAUTOPS)` on 92DE: `rtl_lps_enter_core` returns at
    /// `!ppsc->fwctrl_lps` (`rtl92de_mod_params.fwctrl_lps = false`), so this
    /// is a successful no-op and `leisure` stays false.
    pub(super) async fn de92_enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        Ok(())
    }

    /// Disassociation: `rtl92de_set_network_type(STATION)` without a link
    /// (MSR stays INFRA, CBSSID off), `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_
    /// DISCONNECT)` (only the report: AID and the reserved page are
    /// connect-only) and the mac80211 `BSS_CHANGED_BSSID` zero BSSID. The RA
    /// link is withdrawn. The caller holds the owner in `Phase::Failed`.
    pub(super) async fn de92_disconnected(&mut self) -> Result<(), Error> {
        self.packet.leisure = false;
        self.packet.de92.link = None;
        self.packet.de92.erp_timing = None;
        self.de92_network_type(false)?;
        h2c::joinbss(
            &mut self.packet.de92.mailbox,
            &self.io,
            h2c::MEDIA_DISCONNECT,
            true,
        )
        .await?;
        hw::set_bssid(&self.io, [0; 6])
    }

    /// Card disable with its DMA retirement proof for a stopped owner.
    ///
    /// Linux `rtl92de_card_disable` has no DMA-idle poll (the 92D sources
    /// define no TX packet-buffer-empty or RXDMA-idle status, as for 92C).
    /// With `stop_packets` having paused TX (`0x522 = 0xff`), stopped host
    /// DMA (`0x301 = 0xff`), cleared the CR DMA enables and bus mastering:
    ///
    /// 1. every published non-beacon TX descriptor has OWN clear (nothing is
    ///    left for the engine to fetch; the command-beacon descriptor may
    ///    keep OWN, as Linux);
    /// 2. `rtl92de_card_disable` ([`power::card_disable`]): media status
    ///    UNSPECIFIED, TX DMA stop, RF off, BB reset, TX/RX DMA stop,
    ///    `REG_CR = 0`, then `_rtl92de_poweroff_adapter` when
    ///    `rtl92d_phy_check_poweroff` allows (the other MAC is off);
    /// 3. a non-posted read-back: `REG_SYS_FUNC_EN + 1 == 0x51` after a
    ///    power-off, else `REG_CR == 0` and `REG_PCIE_CTRL_REG + 1 == 0xff`.
    ///
    /// Any disagreement leaves every mapping retained. Success allows the
    /// published rings and buffers to be unmapped. The owner is not
    /// restartable afterwards.
    pub(super) async fn de92_quiesce(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Stopped || !self.published {
            return Err(Error::State);
        }
        let facts = self.de92_facts()?;
        if self.io.read8(REG_TXPAUSE)? != 0xff
            || self.io.read8(REG_PCIE_CTRL_REG + 1)? != 0xff
            || self.io.read8(REG_CR)? & 0xcf != 0
        {
            return Err(Error::Readback);
        }
        let depth = self.depth;
        let tx = &self.tx;
        self.io.authority(false, || {
            for ring in tx.iter().skip(1) {
                ring.sync();
                for slot in 0..depth {
                    if ring.read32(slot * TX_BYTES)? & OWN != 0 {
                        return Err(Error::PacketTimeout);
                    }
                }
            }
            Ok(())
        })?;
        let powered_off = power::card_disable(
            &self.io,
            facts.mode,
            facts.interface_index,
            &mut self.packet.de92.bcn,
        )
        .await?;
        let fen = self
            .io
            .read8(super::super::super::rtl8192de::fw::REG_SYS_FUNC_EN + 1)?;
        if fen == 0xff && self.io.read32(0)? == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        let idle = if powered_off {
            fen == SYS_FUNC_EN_OFF
        } else {
            self.io.read8(REG_CR)? == 0 && self.io.read8(REG_PCIE_CTRL_REG + 1)? == 0xff
        };
        if !idle {
            return Err(Error::Readback);
        }
        self.published = false;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_owner_tests.rs"]
mod tests;
