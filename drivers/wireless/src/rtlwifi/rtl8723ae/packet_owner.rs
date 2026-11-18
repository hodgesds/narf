// SPDX-License-Identifier: GPL-2.0-or-later
//! AE native20MHz packet/H2C branch (NASR1 legacy or NASR2 HT20).
//! Exact rtl8723ae/trx.c fields,
//! hw.c IRQ literals/network/join envelope, fw.c reserved bytes/mailbox.
//! Shared linked-memory publication/host-DD receipts are retained, never
//! interpreted as on-air ACK. LPS and reset/reclamation stay unadmitted.
use super::super::super::rtl8723ae::{h2c, ps, station as hw, trx};
use super::{
    extent, queue, Error, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep, RX_BUFFER,
    RX_BYTES, TX_BYTES,
};
use alloc::vec::Vec;

/// `RATR_INX_WIRELESS_MC` (`_rtl_txrate_selectmode` without a station).
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `RTL_PCI_MAX_RX_QUEUE`-free 8723AE: `REG_PCIE_CTRL_REG` (TX doorbell).
const REG_PCIE_CTRL_REG: u16 = 0x0300;
/// `rtl8723e_tx_polling(BEACON_QUEUE)`.
const BEACON_POLL: u16 = 1 << 4;
/// `rtl8723e_set_fw_rsvdpagepkt` `u1rsvdpageloc`: probe response page 4,
/// PS-Poll page 2, Null page 3.
pub(crate) const RSVDPAGE_LOCATION: [u8; 3] = [4, 2, 3];

/// The 8723AE state of the retained owner.
pub(in super::super) struct State {
    /// Programmed station channel (set by the 8723AE channel step).
    pub(in super::super) channel: Option<u8>,
    c2h_pending: bool,
    traffic: super::super::super::watchdog_traffic::History,
    observed_pwdb: bool,
    peer_mac: Option<[u8; 6]>,
    pub(in super::super) beacons: u32,
    pub(in super::super) min_space_cfg: u8,
    /// Original calibration/coexistence Box and its one AE H2C rotation.
    pub(in super::super) coex:
        Option<alloc::boxed::Box<super::super::super::rtl8723ae::coex::Owner>>,
    /// `rtlpci->reg_bcn_ctrl_val`.
    pub(in super::super) bcn: ps::BcnCtrl,
    /// Peer, `mac->bw_40` and `ratr_index` of the installed `H2C_RA_MASK`.
    pub(in super::super) link: Option<(h2c::Peer, bool, u8)>,
    /// `rtlpci->receive_config` once `HW_VAR_RCR` changed it (else the
    /// configured radio's trimmed value).
    pub(in super::super) receive_config: Option<u32>,
    /// `bss_conf->use_short_preamble` / `use_short_slot` as last programmed
    /// at association, for beacon `BSS_CHANGED_ERP_*` updates.
    pub(in super::super) erp_timing: Option<(bool, bool)>,
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            channel: None,
            c2h_pending: false,
            traffic: super::super::super::watchdog_traffic::History::default(),
            observed_pwdb: false,
            peer_mac: None,
            beacons: 0,
            min_space_cfg: 0,
            coex: None,
            bcn: ps::BcnCtrl::default(),

            link: None,

            receive_config: None,
            erp_timing: None,
        }
    }
}

fn read_words<const N: usize>(ring: &impl Memory, offset: usize) -> Result<[u32; N], Error> {
    let mut dw = [0u32; N];
    for (word, value) in dw.iter_mut().enumerate() {
        *value = ring.read32(offset + word * 4)?;
    }
    Ok(dw)
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// RAM-only negotiated metadata after the real source prepare/start
    /// prefix. No physical peer, firmware ACK or registration is inferred.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn ae_fixture_negotiated_ht(
        &mut self,
        peer: [u8; 6],
        enabled: bool,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running
            || enabled
                && !self
                    .ae8723
                    .as_ref()
                    .is_some_and(|state| state.program.ht20())
        {
            return Err(Error::State);
        }
        self.packet.ht = enabled;
        self.packet.qos = enabled;
        self.packet.ae8723.peer_mac = Some(peer);
        Ok(())
    }
    /// Model device writes into the ORIGINAL retained RX slot; the real
    /// parser, bounded copy and descriptor rearm execute immediately after.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn ae_fixture_rx_slot(
        &mut self,
        bytes: &[u8],
        word1: u32,
        word3: u32,
    ) -> Result<ReceiveStep, Error> {
        let slot = self.packet.receive;
        let buffer = &mut self.buffers[slot];
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        self.io.authority(true, || {
            buffer.write_bytes(0, bytes)?;
            buffer.sync();
            ring.write32(slot * RX_BYTES + 4, word1)?;
            ring.write32(slot * RX_BYTES + 12, word3)?;
            ring.write32(
                slot * RX_BYTES,
                bytes.len() as u32 | if slot + 1 == self.depth { 1 << 30 } else { 0 } | 1 << 27,
            )?;
            ring.sync();
            Ok(())
        })?;
        self.ae8723_receive_step()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn ae_fixture_pending_words(&self) -> Option<[u32; 10]> {
        self.packet.pending.as_ref().map(|pending| pending.prefix)
    }
    /// Bind the actual original coex/mailbox before its first source access.
    /// The whole Prepared is already in the retained regular Mutex; any
    /// failure/drop leaves it Failed with all DMA/origin/command state owned.
    pub(in crate::rtlwifi) async fn configure_rtl8723ae_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared || !self.rtl8723ae() || self.packet.local.is_some() {
            return Err(Error::State);
        }
        let state = self.ae8723.as_ref().ok_or(Error::State)?;
        let program = state.program.clone();
        let grant = state.grant;
        let binding = program.prepared().clone();
        let domain = binding.current_domain()?;
        if program.grant_for(&domain)? != grant {
            return Err(Error::State);
        }
        let bcn = state.bcn.ok_or(Error::State)?;
        if state.receive != Some(binding.receive_config()) || bcn != 0x1f {
            return Err(Error::Readback);
        }
        self.phase = Phase::Failed;
        binding.transfer_coex(&mut self.packet.ae8723.coex).await?;
        self.packet
            .ae8723
            .coex
            .as_mut()
            .ok_or(Error::State)?
            .mech_init(&self.io)
            .await
            .map_err(coex_error)?;
        self.packet.ae8723.bcn = ps::BcnCtrl(bcn);
        self.packet.ae8723.channel = Some(grant.channel());
        self.packet.ae8723.receive_config = Some(binding.receive_config());
        hw::network_type_station(
            &self.io,
            self.packet
                .ae8723
                .receive_config
                .as_mut()
                .ok_or(Error::State)?,
            &mut self.packet.ae8723.bcn,
            false,
        )?;
        // Actual factory identity was already programmed/observed in cold
        // setup; do not synthesize a replacement MAC or replay cold tables.
        for (index, expected) in binding.factory().mac.into_iter().enumerate() {
            if self
                .io
                .read8(super::super::super::rtl8723ae::mac::REG_MACID + index as u16)?
                != expected
            {
                return Err(Error::Readback);
            }
        }
        if self.io.read8(ps::REG_CR)? & 0xcf != 0
            || self.io.read32(h2c::REG_HIMR)? != 0
            || self.io.read32(h2c::REG_HIMRE)? != 0
        {
            return Err(Error::Readback);
        }
        self.packet.local = Some(binding.factory().mac);
        self.ae8723.as_mut().ok_or(Error::State)?.mac_ready = true;
        self.phase = Phase::MacConfigured;
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn ae_fixture_coex(
        &self,
    ) -> Option<(usize, bool, Option<u32>, Option<u32>)> {
        self.packet.ae8723.coex.as_ref().map(|owner| {
            (
                owner.as_ref() as *const _ as usize,
                owner.mech_init_set,
                owner.rf_origin_1e,
                owner.rf_origin_1f,
            )
        })
    }
    fn ae8723_version(&self) -> Result<super::super::super::rtl8723ae::version::Version, Error> {
        self.ae8723
            .as_ref()
            .map(|state| state.program.prepared().adapter().version)
            .ok_or(Error::State)
    }
    async fn ae8723_h2c(&mut self, id: u8, payload: &[u8]) -> Result<(), Error> {
        self.packet
            .ae8723
            .coex
            .as_mut()
            .ok_or(Error::State)?
            .mailbox
            .fill(&self.io, id, payload)
            .await?;
        Ok(())
    }
    /// Open the owned linked rings: bus mastering, then the deferred
    /// `REG_CR = 0x2ff`. Interrupt masks stay clear (polled owner).
    pub(super) fn ae8723_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.packet.ae8723.channel.is_none()
            || self.ae8723.is_none()
        {
            return Err(Error::State);
        }
        super::super::super::rtl8723ae::radio_switch::on(&self.io, self.ae8723_version()?)?;
        self.phase = Phase::Failed;
        self.io.authority(false, || self.validate_rings())?;
        if self.io.read32(h2c::REG_HIMR)? != 0 || self.io.read32(h2c::REG_HIMRE)? != 0 {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        self.io.write16(ps::REG_CR, 0x02ff)?;
        self.io.write8(ps::REG_TXPAUSE, 0)?;
        if self.io.read8(ps::REG_CR)? != 0xff
            || self.io.read8(ps::REG_CR + 1)? != 0x02
            || self.io.read8(ps::REG_TXPAUSE)? != 0
        {
            return Err(Error::Readback);
        }
        self.packet.next = [0; 7];
        self.packet.receive = 0;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_pci_tx` (`rtl_get_tcb_desc` + `rtl8723e_tx_fill_desc`) for one
    /// frame. `adaptive` marks ordinary unicast DATA once the
    /// `rtl8723e_update_hal_rate_mask` link is installed: USE_RATE clear
    /// (the firmware RA of MACID 0 picks the rate), starting at
    /// `_rtl_get_highest_n_rate` (MCS7 on this 1T1R HT20 profile; 11M for
    /// a B peer, 54M for G). With
    /// `dm.useramask` every DATA frame of the link names RATE_ID from
    /// `mac->mode` (`_rtl_txrate_selectmode`, no NEW_RATEID: NGB 0 / GB 4 /
    /// B 6), MACID 0. `rtl_is_special_data` (EAPOL / ARP / DHCP) gets rix 0
    /// from `_rtl_rc_get_rate`, i.e. `use_driver_rate` at `DESC_RATE1M`; a
    /// (QoS) Null DATA frame keeps `use_driver_rate` at the caller's rate
    /// (`rtl8723e_tx_fill_desc`, unlike 92EE, writes USE_RATE as given). The
    /// 8723AE descriptor never sets DISFB (`set_tx_desc_disable_fb(0)`).
    /// The separately qualified profile stays20MHz. Operational sender BA
    /// and TX aggregation are refused: a host descriptor completion cannot
    /// supply the successful on-air TX status that starts the source session.
    /// `short_gi` is `_rtl_query_shortgi` (the data SGI bit). Protection is
    /// `_rtl_query_protection_mode` at `DESC_RATE24M`. Every rate the
    /// descriptor can put on air must be in the `N8723AE` admitted set.
    pub(super) fn ae8723_submit(
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
        let qualified_ht = self
            .ae8723
            .as_ref()
            .is_some_and(|state| state.program.ht20());
        if self.packet.width.is_some()
            || aggregate.is_some()
            || (!qualified_ht && (self.packet.ht || short_gi))
        {
            return Err(Error::Packet);
        }
        let ht = qualified_ht && self.packet.ht;
        let highest = if ht {
            trx::DESC_RATEMCS0 + 7
        } else {
            trx::DESC_RATE54M
        };
        if !(24..=2304).contains(&frame.len())
            || !ht && (aggregate.is_some() || short_gi)
            || aggregate.is_some_and(|(density, _)| density > 7)
            || aggregate.is_some() && frame[0] != 0x88
            || rate > highest
        {
            return Err(Error::Packet);
        }
        let multicast_ra = frame[4] & 1 != 0;
        let data = frame[0] & 0x0c == 0x08;
        let special = super::ee92::special_data(frame);
        let nullfunc = data && matches!(frame[0] & 0xf0, 0x40 | 0xc0);
        let adaptive = adaptive && !special && !nullfunc;
        let link = match self.packet.ae8723.link {
            Some((peer, _, _)) if adaptive => {
                if multicast_ra || !data {
                    return Err(Error::Packet);
                }
                Some(peer)
            }
            None if adaptive => return Err(Error::State),
            _ => None,
        };
        let hw_rate = match link {
            Some(peer) => match peer.mode {
                h2c::WirelessMode::N24 if ht => trx::DESC_RATEMCS0 + 7,
                h2c::WirelessMode::N24 => return Err(Error::Packet),
                h2c::WirelessMode::B => trx::DESC_RATE11M,
                h2c::WirelessMode::G => trx::DESC_RATE54M,
            },
            None if special => trx::DESC_RATE1M,
            None => rate,
        };
        let protection = match self.packet.protection {
            super::super::super::protection::Mode::None => 0,
            super::super::super::protection::Mode::RtsCts => 1,
            super::super::super::protection::Mode::CtsToSelf => 2,
        };
        let permission = self.ae8723.as_ref().ok_or(Error::State)?.grant.permission();
        if permission.admitted_rates() & (1u64 << hw_rate) == 0
            || protection != 0 && permission.admitted_rates() & (1u64 << trx::DESC_RATE24M) == 0
        {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        let rate_id = match self.packet.ae8723.link {
            Some((_, _, index)) if data => index,
            _ => RATR_INX_WIRELESS_MC,
        };
        let bw40 = false;
        let prime_sc = 0;
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
        let prefix = trx::fill(&trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id,
            hw_rate,
            use_driver_rate: link.is_none(),
            short: short_gi,
            bw_40: bw40,
            packet_bw_40: bw40 && ht && !multicast && hw_rate > trx::DESC_RATE54M,
            prime_sc,
            ampdu: aggregate.is_some_and(|(_, operational)| operational),
            ampdu_density: aggregate.map_or(0, |(density, _)| density),
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast,
            qos_data: frame[0] == 0x88,
            protection,
            buffer_addr: address,
            ..Default::default()
        });
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
            if trx::own(ring.read32(offset)?) {
                return Err(Error::Descriptor);
            }
            // clear_pci_tx_desc_content keeps dword 10's next link.
            for (word, value) in prefix.iter().copied().enumerate().skip(1) {
                ring.write32(offset + word * 4, value)?;
            }
            ring.write32(offset, prefix[0])?;
            ring.sync();
            let mut first = prefix;
            trx::set_own(&mut first, true);
            ring.write32(offset, first[0])?;
            ring.sync();
            Ok(())
        })?;
        self.io.kick(poll)?;
        self.phase = Phase::Running;
        Ok(id)
    }

    /// One `_rtl_pci_rx_interrupt` iteration over the in-ring descriptor.
    pub(super) fn ae8723_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let channel = self.packet.ae8723.channel.ok_or(Error::State)?;
        let cck_highpwr = self
            .ae8723
            .as_ref()
            .ok_or(Error::State)?
            .program
            .prepared()
            .cck_high_power();
        let ht = self.packet.ht
            && self
                .ae8723
                .as_ref()
                .is_some_and(|state| state.program.ht20());
        let highest_mcs = trx::DESC_RATEMCS0 + 7;
        let longest = if ht {
            super::super::super::rtl8723ae::ht::LONGEST_RX
        } else {
            2304 + 4
        };
        let slot = self.packet.receive;
        let depth = self.depth;
        let local = self.packet.local;
        let peer = self.packet.ae8723.peer_mac;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let buffer_addr = extent(buffer, RX_BUFFER, 4)?;
        let offset = slot * RX_BYTES;
        let consumed = self.io.authority(true, || {
            ring.sync();
            let dw: [u32; 8] = read_words(ring, offset)?;
            let Some(status) = trx::RxStatus::parse(&dw) else {
                return Ok(None);
            };
            let last = slot + 1 == depth;
            if (dw[0] >> 30) & 1 != u32::from(last) || dw[6] != buffer_addr || dw[7] != 0 {
                return Err(Error::Descriptor);
            }
            let length = usize::from(status.length);
            let start = status.payload_offset();
            if start.checked_add(length).is_none_or(|n| n > RX_BUFFER) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            let mcs = (trx::DESC_RATEMCS0..=highest_mcs).contains(&status.rate);
            let rate_ok = if status.ht {
                ht && mcs
            } else {
                status.rate <= trx::DESC_RATE54M
            };
            if !status.hw_error()
                && (ht || !status.ampdu)
                && !status.bw_40
                && rate_ok
                && ((if ht { 24 } else { 28 })..=longest).contains(&length)
            {
                buffer.sync();
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length - 4)
                    .map_err(|_| Error::Memory)?;
                bytes.resize(length - 4, 0);
                buffer.read_bytes(start, &mut bytes)?;
                let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
                let bar = ht
                    && bytes.len() == 20
                    && bytes[0] == 0x84
                    && bytes[1] & 0xc7 == 0
                    && bytes[16] & 6 == 4
                    && bytes[17] >> 4 < 8
                    && bytes[18] & 15 == 0
                    && local.is_some_and(|mac| bytes[4..10] == mac)
                    && peer.is_some_and(|mac| bytes[10..16] == mac);
                // Software CCMP: protected frames keep IV/ciphertext/MIC.
                if bar
                    || (bytes.len() >= 24
                        && fc & 0x400 == 0
                        && bytes[22] & 15 == 0
                        && (fc & 0x4000 == 0 || !status.decrypted))
                {
                    // `_rtl8723e_translate_rx_signal_stuff` →
                    // `_rtl8723e_query_rxphystatus` `rx_pwdb_all` from the
                    // driver-info PHY status ahead of the frame.
                    let pwdb = if status.physt && status.drvinfo_size >= 8 {
                        let mut phy = [0u8; 8];
                        buffer.read_bytes(status.shift, &mut phy)?;
                        trx::rx_pwdb(&phy, status.is_cck(), cck_highpwr)
                    } else {
                        None
                    };
                    // `rtl8723e_rx_query_desc`: `is_ht` from RXHT and
                    // `rx_is40mhzpacket` from the BW bit; no SGI flag is
                    // reported on this chip.
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: status.ht,
                        short_gi: false,
                        width40: status.ht && status.bw_40,
                        aggregated: status.ampdu,
                        pwdb,
                        antenna_mux: None,
                    });
                }
            }
            let mut arm = [0u32; 8];
            trx::rx_arm(&mut arm, buffer_addr, RX_BUFFER as u16, last);
            for (word, value) in arm.iter().copied().enumerate().skip(1) {
                ring.write32(offset + word * 4, value)?;
            }
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
        if let Some(frame) = packet.as_ref() {
            if frame.bytes[0] & 0x0c == 0x08 && frame.bytes[4] & 1 == 0 {
                self.packet.ae8723.traffic.observe_unicast_data_rx();
            }
            if self.packet.ae8723.peer_mac.is_some_and(|peer| {
                frame
                    .bytes
                    .get(16..22)
                    .is_some_and(|bssid| bssid == peer.as_slice())
            }) {
                self.packet.ae8723.observed_pwdb |= frame.pwdb.is_some();
                if self.packet.ae8723.link.is_some()
                    && frame.bytes.len() > 40
                    && matches!(frame.bytes[0], 0x80 | 0x50)
                {
                    self.packet.ae8723.beacons = self.packet.ae8723.beacons.saturating_add(1);
                }
            }
        }
        self.packet.receive = (slot + 1) % depth;
        self.phase = Phase::Running;
        Ok(ReceiveStep {
            consumed: true,
            packet,
        })
    }

    /// `rtl8723e_enable_interrupt`; only a running owner whose vector is
    /// bound may unmask.
    pub(super) fn ae8723_enable_interrupts(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(true, || Ok(()))?;
        self.packet.interrupts = true;
        h2c::enable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HIMR)? != h2c::IRQ_MASK0
            || self.io.read32(h2c::REG_HIMRE)? != h2c::IRQ_MASK1
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl8723e_disable_interrupt`.
    pub(super) fn ae8723_disable_interrupts(&mut self) -> Result<(), Error> {
        self.packet.interrupts = false;
        h2c::disable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HIMR)? != 0 || self.io.read32(h2c::REG_HIMRE)? != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }

    /// One `_rtl_pci_interrupt` pass: mask, `rtl8723e_interrupt_recognized`
    /// (HISR under `irq_mask[0]`, W1C; HISRE untouched so `intb` is 0),
    /// unmask. An all-ones status means the function vanished.
    pub(super) fn ae8723_recognize_interrupts(
        &mut self,
    ) -> Result<super::super::super::irq::Recognized, Error> {
        if self.phase != Phase::Running || !self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        h2c::disable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HISR)? == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        let inta = h2c::recognize(&self.io)?;
        self.ae8723_observe_isr(inta);
        h2c::enable_interrupt(&self.io)?;
        self.phase = Phase::Running;
        Ok(super::super::super::irq::Recognized { inta, intb: 0 })
    }

    fn ae8723_observe_isr(&mut self, inta: u32) {
        self.packet.ae8723.c2h_pending |= inta & (1 << 10) != 0;
        // pci.c increments once per BK/BE/VI/VO DOK cause, not per kick
        // and never from management/command descriptor host retirement.
        self.packet
            .ae8723
            .traffic
            .observe_tx_dok((inta & 0x3c).count_ones());
    }
    /// Deferred AE-only MMIO C2H route. Polled owners inspect the same
    /// source ISR bit; no packet/report ID is reinterpreted as a TX ACK.
    pub(in super::super) fn ae8723_service_c2h(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let status = self.io.read32(h2c::REG_HISR)?;
        if status == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        if status & h2c::IRQ_MASK0 != 0 {
            let inta = h2c::recognize(&self.io)?;
            self.ae8723_observe_isr(inta);
        }
        if !self.packet.ae8723.c2h_pending {
            return Ok(());
        }
        self.phase = Phase::Failed;
        let outcome = super::super::super::rtl8723ae::c2h::drain(&self.io)?;
        if let super::super::super::rtl8723ae::c2h::Outcome::Dispatched(
            super::super::super::rtl8723ae::c2h::Event::BtInfo(info),
        ) = outcome
        {
            self.packet
                .ae8723
                .coex
                .as_mut()
                .ok_or(Error::State)?
                .ingest(&info);
            // Generic btc_periodical has no 8723A algorithm dispatch. Do
            // not apply the pass-1 coarse TDMA matrix as a hardware program.
        }
        self.packet.ae8723.c2h_pending = false;
        self.phase = Phase::Running;
        Ok(())
    }
    /// Actual legacy source coex mechanism, using observed station PWDB and
    /// this owner's real TX/RX period counts. No fabricated RSSI sample.
    pub(in super::super) async fn ae8723_coex_watchdog(
        &mut self,
        pwdb: i64,
        now_ms: u64,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure {
            return Err(Error::State);
        }
        if !self.packet.ae8723.observed_pwdb {
            return Ok(());
        }
        let traffic = self
            .packet
            .ae8723
            .traffic
            .snapshot(self.packet.ae8723.link.is_some());
        let version = self.ae8723_version()?;
        let inputs = super::super::super::rtl8723ae::dm::MechInputs {
            wifi: super::super::super::rtl8723ae::coex::WifiTraffic {
                busy: traffic.busy,
                tx_busy: traffic.tx_busy,
                rx_busy: traffic.rx_busy,
                legacy: !self.packet.ht,
                bw40: false,
                bt30: false,
            },
            linked: self.packet.ae8723.link.is_some(),
            pwdb: pwdb.try_into().map_err(|_| Error::State)?,
            now_ms,
            a_cut: version.is_8723_a_cut(),
        };
        self.phase = Phase::Failed;
        self.packet
            .ae8723
            .coex
            .as_mut()
            .ok_or(Error::State)?
            .run_mechanism(&self.io, inputs)
            .await
            .map_err(coex_error)?;
        self.packet.ae8723.traffic.finish_period();
        self.phase = Phase::Running;
        Ok(())
    }
    /// No AE reset/DMA-reclamation receipt is composed by this profile.
    pub(super) async fn ae8723_quiesce(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    pub(super) async fn ae8723_enter_leisure(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    pub(super) async fn ae8723_leave_leisure(&mut self) -> Result<(), Error> {
        if self.packet.leisure {
            return Err(Error::State);
        }
        Ok(())
    }
    /// `rtl8723e_update_hal_rate_mask` for the station peer at `level`. The
    /// firmware RA may only pick rates the owner's permission admits: a mask
    /// whose rate bits (`[27:0]` of the RA word) are not a non-empty subset
    /// of `admitted` is refused, never narrowed.
    pub(super) async fn ae8723_install_rate_mask(
        &mut self,
        peer: h2c::Peer,
        bw40: bool,
        level: u8,
        admitted: u32,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        let qualified_ht = self
            .ae8723
            .as_ref()
            .is_some_and(|state| state.program.ht20());
        if bw40
            || peer.sgi40
            || peer.rx_mask[1] != 0
            || (!qualified_ht
                && (peer.mode == h2c::WirelessMode::N24 || peer.rx_mask != [0; 2] || peer.sgi20))
            || (peer.mode == h2c::WirelessMode::N24 && (!self.packet.ht || peer.rx_mask[0] == 0))
        {
            return Err(Error::Packet);
        }
        let payload = h2c::rate_mask(&peer, false, level);
        let word = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let rates = word & 0x0fff_ffff;
        if rates == 0 || rates & !admitted != 0 {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        self.phase = Phase::Failed;
        self.ae8723_h2c(h2c::H2C_RA_MASK, &payload).await?;
        self.packet.ae8723.link = Some((peer, bw40, (word >> 28) as u8));
        self.phase = Phase::Running;
        Ok(())
    }

    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)` — `HW_VAR_AID`,
    /// `REG_CR + 1` BIT(0), BCN_CTRL `(0, BIT(3))` / `(BIT(4), 0)`, `0x422`
    /// BIT(6) cleared, `rtl8723e_set_fw_rsvdpagepkt` (`rtl_cmd_send_packet` on
    /// beacon descriptor 0 with `rtl8723e_tx_fill_cmddesc`, the
    /// `BIT(4)` beacon doorbell, then `H2C_RSVDPAGE` `{4, 2, 3}`), BCN_CTRL
    /// `(BIT(3), 0)` / `(0, BIT(4))`, `0x422` restored when it had BIT(6),
    /// `REG_CR + 1` restored, then `H2C_JOINBSSRPT(1)`. The 8723AE has no
    /// BCN_VALID receipt (Linux sends the location right after the
    /// doorbell); the body stays owned by the claim (`packet.reserved`)
    /// until a quiescence proof.
    pub(super) async fn ae8723_join_report(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: &impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        let local = self.packet.local.ok_or(Error::State)?;
        let pages = super::super::super::rtl8723ae::reserved::build(local, peer, aid)?;
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
        let closed = |a: Option<&super::super::station::Admission>| {
            a.is_some_and(|c| c.closed.load(core::sync::atomic::Ordering::Acquire))
        };
        self.ae8723_network_type(true)?;
        ps::set_aid(&self.io, aid)?;
        let cr = self.io.read8(ps::REG_CR + 1)?;
        self.io.write8(ps::REG_CR + 1, cr | 1)?;
        let bcn = &mut self.packet.ae8723.bcn;
        bcn.set(&self.io, 0, 1 << 3)?;
        bcn.set(&self.io, 1 << 4, 0)?;
        let txq = self.io.read8(ps::REG_FWHW_TXQ_CTRL + 2)?;
        self.io.write8(ps::REG_FWHW_TXQ_CTRL + 2, txq & !(1 << 6))?;
        let mut words = trx::fill_cmd(pages.len() as u16, address, false);
        {
            let _publication = admission.map(|control| control.publication.lock());
            if closed(admission) {
                return Err(Error::State);
            }
            policy(self)?;
            // A rejoin reuses beacon descriptor 0, as Linux's
            // rtl_cmd_send_packet does; its earlier body is retired.
            let proven = !self.packet.retired.is_empty();
            let ring = &mut self.tx[0];
            self.io.authority(true, || {
                ring.sync();
                if trx::own(ring.read32(0)?) && !proven {
                    return Err(Error::Descriptor);
                }
                for (word, value) in words.iter().copied().enumerate().skip(1) {
                    ring.write32(word * 4, value)?;
                }
                ring.sync();
                trx::set_own(&mut words, true);
                ring.write32(0, words[0])?;
                ring.sync();
                Ok(())
            })?;
            self.io.kick(BEACON_POLL)?;
        }
        self.ae8723_h2c(h2c::H2C_RSVDPAGE, &RSVDPAGE_LOCATION)
            .await?;
        let bcn = &mut self.packet.ae8723.bcn;
        bcn.set(&self.io, 1 << 3, 0)?;
        bcn.set(&self.io, 0, 1 << 4)?;
        if txq & (1 << 6) != 0 {
            self.io.write8(ps::REG_FWHW_TXQ_CTRL + 2, txq)?;
        }
        self.io.write8(ps::REG_CR + 1, cr & !1)?;
        if closed(admission) {
            return Err(Error::State);
        }
        policy(self)?;
        self.ae8723_h2c(h2c::H2C_JOINBSSRPT, &h2c::joinbss(h2c::MEDIA_CONNECT))
            .await?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl8723e_set_network_type(NL80211_IFTYPE_STATION)` with the cached
    /// `receive_config`.
    fn ae8723_network_type(&mut self, linked: bool) -> Result<(), Error> {
        let mut rcr = match self.packet.ae8723.receive_config {
            Some(rcr) => rcr,
            None => self
                .ae8723
                .as_ref()
                .and_then(|state| state.receive)
                .ok_or(Error::State)?,
        };
        let result =
            hw::network_type_station(&self.io, &mut rcr, &mut self.packet.ae8723.bcn, linked);
        self.packet.ae8723.receive_config = Some(rcr);
        result
    }

    /// Linux `rtl8723e_hw_init` leaves the firmware awake
    /// (`fw_current_inpsmode` false); nothing is sent. Only a powered MAC
    /// (`REG_CR != 0xEA`) is accepted.
    pub(super) fn ae8723_awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        super::super::super::rtl8723ae::radio_switch::on(&self.io, self.ae8723_version()?)
    }

    /// Authentication-time `BSS_CHANGED_BSSID` (`HW_VAR_BSSID`),
    /// `BASIC_RATES` / ERP and `rtl8723e_update_channel_access_setting` /
    /// `rtl8723e_set_qos` ([`hw::configure_rates`], `ht_enable` false until
    /// the association) at the programmed `cur_40_prime_sc`.
    pub(super) fn ae8723_prepare_peer(
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
        let prime_sc = 0;
        self.phase = Phase::Failed;
        hw::set_bssid(&self.io, peer)?;
        self.packet.ae8723.peer_mac = Some(peer);
        self.packet.ae8723.observed_pwdb = false;
        hw::configure_rates(&self.io, rates, basic, capability, None, false, prime_sc)?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` for RTL8723AE:
    /// `rtl_cam_reset_all_entry` (AE KEEP_ALIVE callback is unimplemented), then `rtl8723e_set_network_type` with the
    /// link and `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`
    /// ([`Self::ae8723_join_report`]). The firmware RA mask follows
    /// separately (`ae8723_install_rate_mask`, Linux's `update_rate_tbl` in
    /// the same branch).
    pub(super) async fn ae8723_complete_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let closed = |a: Option<&super::super::station::Admission>| {
            a.is_some_and(|c| c.closed.load(core::sync::atomic::Ordering::Acquire))
        };
        if !self.transmit_ready() || self.packet.reserved.is_some() || self.packet.leisure {
            return Err(Error::State);
        }
        if !(1..=2007).contains(&aid) || peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Packet);
        }
        self.phase = Phase::Failed;
        self.io.write32(hw::REG_CAMCMD, hw::CAM_RESET)?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        self.ae8723_join_report(peer, aid, admission, &policy)
            .await?;
        if closed(admission) {
            self.phase = Phase::Failed;
            return Err(Error::State);
        }
        Ok(())
    }

    /// Disassociation (`BSS_CHANGED_ASSOC` with `!assoc`): leave LPS
    /// (`rtl_lps_leave`: RPWM RF on, `FW_PS_ACTIVE_MODE`), then
    /// `rtl8723e_set_network_type(STATION)` without a link (MSR NOLINK,
    /// CBSSID off), `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)` (only
    /// the report: AID and the reserved page are connect-only) and the
    /// mac80211 `BSS_CHANGED_BSSID` zero BSSID. The RA link is withdrawn.
    /// The caller holds the owner in `Phase::Failed`.
    pub(super) async fn ae8723_disconnected(&mut self) -> Result<(), Error> {
        if self.packet.leisure {
            return Err(Error::State);
        }
        self.packet.ae8723.link = None;
        self.packet.ae8723.peer_mac = None;
        self.packet.ae8723.beacons = 0;
        self.packet.ae8723.erp_timing = None;
        self.ae8723_network_type(false)?;
        self.ae8723_h2c(h2c::H2C_JOINBSSRPT, &h2c::joinbss(h2c::MEDIA_DISCONNECT))
            .await?;
        hw::set_bssid(&self.io, [0; 6])
    }
}

fn coex_error(error: super::super::super::rtl8723ae::coex::Error) -> Error {
    use super::super::super::rtl8723ae::coex::Error as Coex;
    match error {
        Coex::CommandTimeout => Error::CommandTimeout,
        Coex::Access => Error::Access(super::super::AccessError::Access),
        Coex::State => Error::State,
    }
}
