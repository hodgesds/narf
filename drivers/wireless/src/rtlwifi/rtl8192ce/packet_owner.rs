// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE branch of the retained linked-ring packet owner.
//!
//! Mounted as `prepare::packet::ce92` (it needs the owner's private ring
//! storage); the chip facts it composes live beside it in `rtl8192ce/`.
//! The rings are the 88EE linked geometry (`prepare::Chip::Rtl8192ce`, next
//! link at byte 40, RX descriptor in the ring with the buffer at dword 6),
//! so publication, the TX host receipt (`delivery`: OWN clear with the
//! stable words intact) and the terminal stop are shared; the 92C pieces
//! are:
//!
//! - Release (`_rtl92ce_init_mac` `REG_CR = 0x2ff`, deferred by `prepare`
//!   until the owner opens its rings after bus mastering). The 92C has no
//!   `REG_PCIE_CTRL_REG + 1` DMA stop (it is only the TX polling doorbell).
//! - TX (`rtl_pci_tx`, `rtl92ce_tx_fill_desc`, `rtl92ce_tx_polling`): the
//!   40-byte descriptor from [`trx::fill`] with OWN written last, then the
//!   `REG_PCIE_CTRL_REG` `BIT(hw_queue)` doorbell. Station profile here: one
//!   outstanding frame, forced legacy driver rate, `RATR_INX_WIRELESS_MC`,
//!   macid 0 (`dm.useramask` is set on PCI by
//!   `rtl92c_dm_init_rate_adaptive_mask`), no protection/aggregation/SGI.
//! - RX (`_rtl_pci_rx_interrupt`, `rtl92ce_rx_query_desc`): the 32-byte
//!   in-ring descriptor ([`trx::RxStatus`]), the payload at `drvinfo +
//!   shift`, re-armed by [`trx::rx_arm`]. HT/A-MPDU frames are consumed and
//!   dropped (no HT station profile yet). PHY status is not decoded here.
//! - Interrupts: [`h2c::enable_interrupt`] / [`h2c::disable_interrupt`] /
//!   [`h2c::recognize`] (`0x120`/`0x124`/`0x128`).
//! - Leisure PS: `HW_VAR_FW_LPS_ACTION` (enter: `fw_current_inpsmode`,
//!   `HW_VAR_H2C_FW_PWRMODE(fwctrl_psmode = FW_PS_DTIM_MODE)` with the 88C
//!   `rtl92c_dm_rf_saving(hw, true)`, RPWM `0x02`; leave: RPWM `0x0c`,
//!   `FW_PS_ACTIVE_MODE`, status clear).
//! - Join: `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)` (`HW_VAR_AID`, the
//!   CR/BCN_CTRL/`0x422` envelope around `rtl92c_set_fw_rsvdpagepkt`, then
//!   `H2C_JOINBSSRPT`), preceded by `_rtl92ce_set_media_status(STATION)`.
//! - DM watchdog: the composed part of `rtl92c_dm_watchdog`.
//! - Card disable: `rtl92ce_card_disable` with its DMA retirement proof.
use super::super::super::rtl8192ce::{h2c, ps, trx};
use super::{
    extent, queue, Error, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep, RX_BUFFER,
    RX_BYTES, TX_BYTES,
};
use alloc::vec::Vec;

/// `RATR_INX_WIRELESS_MC` (`_rtl_txrate_selectmode` without a station).
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `RTL_PCI_MAX_RX_QUEUE`-free 92CE: `REG_PCIE_CTRL_REG` (TX doorbell).
const REG_PCIE_CTRL_REG: u16 = 0x0300;
/// `rtl92ce_tx_polling(BEACON_QUEUE)`.
const BEACON_POLL: u16 = 1 << 4;
/// `rtl92c_set_fw_rsvdpagepkt` `u1rsvdpageloc`: probe response page 4,
/// PS-Poll page 2, Null page 3.
pub(crate) const RSVDPAGE_LOCATION: [u8; 3] = [4, 2, 3];
/// `HW_VAR_FW_LPS_ACTION` RPWM values.
const RPWM_RF_OFF: u8 = 0x02;
const RPWM_RF_ON: u8 = 0x0c;

/// The 92C state of the retained owner.
pub(in super::super) struct State {
    /// Programmed station channel (set by the 92CE channel step).
    pub(in super::super) channel: Option<u8>,
    /// `rtl8192c/fw_common.c` H2C mailbox (`last_hmeboxnum`).
    pub(in super::super) mailbox: h2c::Mailbox,
    /// `rtlpci->reg_bcn_ctrl_val`.
    pub(in super::super) bcn: ps::BcnCtrl,
    /// `rtl92c_dm_rf_saving` state (88C).
    pub(in super::super) rf_saving: ps::RfSaving,
    /// Peer, `mac->bw_40` and `ratr_index` of the installed `H2C_RA_MASK`.
    pub(in super::super) link: Option<(h2c::Peer, bool, u8)>,
    /// Latest `rtl92c_dm_false_alarm_counter_statistics`.
    pub(in super::super) false_alarm: ps::FalseAlarm,
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            channel: None,
            mailbox: h2c::Mailbox::new(),
            bcn: ps::BcnCtrl::default(),
            rf_saving: ps::RfSaving::new(),
            link: None,
            false_alarm: ps::FalseAlarm::default(),
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
    fn ce92_version(&self) -> Result<super::super::super::rtl8192ce::version::Version, Error> {
        self.rtl8192ce
            .as_deref()
            .map(|(_, radio)| radio.version)
            .ok_or(Error::State)
    }

    /// Open the owned linked rings: bus mastering, then the deferred
    /// `REG_CR = 0x2ff`. Interrupt masks stay clear (polled owner).
    pub(super) fn ce92_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.packet.ce92.channel.is_none()
            || self.rtl8192ce.is_none()
        {
            return Err(Error::State);
        }
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

    /// `rtl_pci_tx` for one forced-rate legacy frame.
    pub(super) fn ce92_submit(&mut self, frame: &[u8], rate: u8) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        if rate > trx::DESC_RATE54M
            || self.packet.protection != super::super::super::protection::Mode::None
        {
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
        let prefix = trx::fill(&trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id: RATR_INX_WIRELESS_MC,
            hw_rate: rate,
            use_driver_rate: true,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast: destination[0] & 1 != 0,
            qos_data: frame[0] == 0x88,
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
    pub(super) fn ce92_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let channel = self.packet.ce92.channel.ok_or(Error::State)?;
        let slot = self.packet.receive;
        let depth = self.depth;
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
            if !status.hw_error()
                && !status.ht
                && !status.ampdu
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

    /// `rtl92ce_enable_interrupt`; only a running owner whose vector is
    /// bound may unmask.
    pub(super) fn ce92_enable_interrupts(&mut self) -> Result<(), Error> {
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

    /// `rtl92ce_disable_interrupt`.
    pub(super) fn ce92_disable_interrupts(&mut self) -> Result<(), Error> {
        self.packet.interrupts = false;
        h2c::disable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HIMR)? != 0 || self.io.read32(h2c::REG_HIMRE)? != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }

    /// One `_rtl_pci_interrupt` pass: mask, `rtl92ce_interrupt_recognized`
    /// (HISR under `irq_mask[0]`, W1C; HISRE untouched so `intb` is 0),
    /// unmask. An all-ones status means the function vanished.
    pub(super) fn ce92_recognize_interrupts(
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
        h2c::enable_interrupt(&self.io)?;
        self.phase = Phase::Running;
        Ok(super::super::super::irq::Recognized { inta, intb: 0 })
    }

    /// Card disable with its DMA retirement proof for a stopped owner.
    ///
    /// Linux `rtl92ce_card_disable` has no DMA-idle poll: the 92C sources
    /// define no TX packet-buffer-empty or RXDMA-idle status, so the 88EE
    /// `0x5f8`/`0x286` polls are not applied. The proof composed here, with
    /// `stop_packets` having paused TX (`0x522 = 0xff`), cleared the CR DMA
    /// enables and bus mastering:
    ///
    /// 1. every published non-beacon TX descriptor has OWN clear
    ///    (`rtl92ce_is_tx_desc_closed`: nothing is left for the engine to
    ///    fetch; the command-beacon descriptor may keep OWN, as Linux);
    /// 2. `_rtl92ce_set_media_status(UNSPECIFIED)` then
    ///    `_rtl92ce_poweroff_adapter` ([`ps::poweroff_adapter`]), whose
    ///    `REG_SYS_FUNC_EN + 1 = 0x51` drops the digital-core enable
    ///    (`FEN_DCORE`) that holds the MAC DMA engines;
    /// 3. a non-posted read of `REG_SYS_FUNC_EN + 1` returning `0x51`: PCIe
    ///    ordering keeps any earlier device write ahead of that completion.
    ///
    /// Any disagreement leaves every mapping retained (and the owner
    /// stopped). Success allows the published rings and buffers to be
    /// unmapped. The owner is not restartable afterwards (power is off).
    pub(super) async fn ce92_quiesce(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Stopped || !self.published {
            return Err(Error::State);
        }
        let version = self.ce92_version()?;
        if self.io.read8(ps::REG_TXPAUSE)? != 0xff || self.io.read8(ps::REG_CR)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        let depth = self.depth;
        let tx = &self.tx;
        self.io.authority(false, || {
            for ring in tx.iter().skip(1) {
                ring.sync();
                for slot in 0..depth {
                    if trx::own(ring.read32(slot * TX_BYTES)?) {
                        return Err(Error::PacketTimeout);
                    }
                }
            }
            Ok(())
        })?;
        ps::set_media_status(&self.io, &mut self.packet.ce92.bcn, false)?;
        ps::poweroff_adapter(&self.io, version).await?;
        let fen = self
            .io
            .read8(super::super::super::rtl8192ce::fw::REG_SYS_FUNC_EN + 1)?;
        if fen == 0xff && self.io.read32(0)? == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        if fen != 0x51 {
            return Err(Error::Readback);
        }
        self.published = false;
        Ok(())
    }

    /// `HW_VAR_FW_LPS_ACTION(true)`: `fw_current_inpsmode`, then
    /// `HW_VAR_H2C_FW_PWRMODE(FW_PS_DTIM_MODE)` — on 88C (not 92C-serial)
    /// preceded by `rtl92c_dm_rf_saving(hw, true)` — then RPWM RF off.
    pub(super) async fn ce92_enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        let version = self.ce92_version()?;
        self.phase = Phase::Failed;
        self.packet.leisure = true;
        if !version.is_92c_serial() {
            self.packet.ce92.rf_saving.run(&self.io, true, 0)?;
        }
        self.packet
            .ce92
            .mailbox
            .fill(
                &self.io,
                h2c::H2C_SETPWRMODE,
                &h2c::pwrmode(h2c::FW_PS_DTIM_MODE),
            )
            .await?;
        h2c::set_rpwm(&self.io, RPWM_RF_OFF).await?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `HW_VAR_FW_LPS_ACTION(false)`: RPWM RF on,
    /// `HW_VAR_H2C_FW_PWRMODE(FW_PS_ACTIVE_MODE)`, status clear.
    pub(super) async fn ce92_leave_leisure(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.packet.leisure {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        h2c::set_rpwm(&self.io, RPWM_RF_ON).await?;
        self.packet
            .ce92
            .mailbox
            .fill(
                &self.io,
                h2c::H2C_SETPWRMODE,
                &h2c::pwrmode(h2c::FW_PS_ACTIVE_MODE),
            )
            .await?;
        self.packet.leisure = false;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl92ce_update_hal_rate_mask` for the station peer at `level`. The
    /// firmware RA may only pick rates the owner's permission admits: a mask
    /// whose rate bits (`[27:0]` of the RA word) are not a non-empty subset
    /// of `admitted` is refused, never narrowed.
    pub(super) async fn ce92_install_rate_mask(
        &mut self,
        peer: h2c::Peer,
        bw40: bool,
        level: u8,
        admitted: u32,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        let rf_type = self.ce92_version()?.rf_type();
        let payload = h2c::rate_mask(&peer, rf_type, bw40, level);
        let word = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let rates = word & 0x0fff_ffff;
        if rates == 0 || rates & !admitted != 0 {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        self.phase = Phase::Failed;
        self.packet
            .ce92
            .mailbox
            .fill(&self.io, h2c::H2C_RA_MASK, &payload)
            .await?;
        self.packet.ce92.link = Some((peer, bw40, (word >> 28) as u8));
        self.phase = Phase::Running;
        Ok(())
    }

    /// The composed part of `rtl92c_dm_watchdog` (only while the firmware
    /// is out of power save): `rtl92c_dm_false_alarm_counter_statistics`
    /// and `rtl92c_dm_dynamic_bb_powersaving` (`rssi_val_min =
    /// undec_sm_pwdb` for a linked station; on 88C `rtl92c_dm_rf_saving(hw,
    /// false)`, nothing on 92C). Linux's watchdog has
    /// `rtl92c_dm_refresh_rate_adaptive_mask` commented out, so the RA mask
    /// is never refreshed here. Not composed: `rtl92c_dm_pwdb_monitor`,
    /// `rtl92c_dm_dig`, dynamic TX power, TX-power tracking (no
    /// `txpower_tracking` owner), BT coexist (never admitted) and EDCA
    /// turbo; their registers keep the `rtl92ce_hw_init` values.
    pub(super) fn ce92_dm_watchdog(&mut self, undec_sm_pwdb: i64) -> Result<bool, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.packet.leisure {
            return Ok(false);
        }
        let version = self.ce92_version()?;
        self.phase = Phase::Failed;
        self.packet.ce92.false_alarm = ps::false_alarm(&self.io)?;
        if !version.is_92c_serial() {
            self.packet
                .ce92
                .rf_saving
                .run(&self.io, false, undec_sm_pwdb)?;
        }
        self.phase = Phase::Running;
        Ok(true)
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` hardware order for a
    /// station: `_rtl92ce_set_media_status(STATION, linked)`, then
    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)` — `HW_VAR_AID`,
    /// `REG_CR + 1` BIT(0), BCN_CTRL `(0, BIT(3))` / `(BIT(4), 0)`, `0x422`
    /// BIT(6) cleared, `rtl92c_set_fw_rsvdpagepkt` (`rtl_cmd_send_packet` on
    /// beacon descriptor 0 with `rtl92ce_tx_fill_cmddesc`, the
    /// `BIT(4)` beacon doorbell, then `H2C_RSVDPAGE` `{4, 2, 3}`), BCN_CTRL
    /// `(BIT(3), 0)` / `(0, BIT(4))`, `0x422` restored when it had BIT(6),
    /// `REG_CR + 1` restored, then `H2C_JOINBSSRPT(1)`. The 92C has no
    /// BCN_VALID receipt (Linux sends the location right after the
    /// doorbell); the body stays owned by the claim (`packet.reserved`)
    /// until a quiescence proof.
    pub(super) async fn ce92_join_report(
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
        let pages = super::super::super::station_control::reserved_pages(local, peer, aid)?;
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
        ps::set_media_status(&self.io, &mut self.packet.ce92.bcn, true)?;
        ps::set_aid(&self.io, aid)?;
        let cr = self.io.read8(ps::REG_CR + 1)?;
        self.io.write8(ps::REG_CR + 1, cr | 1)?;
        let bcn = &mut self.packet.ce92.bcn;
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
        self.packet
            .ce92
            .mailbox
            .fill(&self.io, h2c::H2C_RSVDPAGE, &RSVDPAGE_LOCATION)
            .await?;
        let bcn = &mut self.packet.ce92.bcn;
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
        self.packet
            .ce92
            .mailbox
            .fill(
                &self.io,
                h2c::H2C_JOINBSSRPT,
                &h2c::joinbss(h2c::MEDIA_CONNECT),
            )
            .await?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)` after leaving LPS
    /// (mac80211 leaves PS before the report), then
    /// `_rtl92ce_set_media_status(STATION)` with the link down
    /// (`MSR_NOLINK`) and `HW_VAR_AID` 0. The RA mask is withdrawn.
    pub(super) async fn ce92_leave_report(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.packet.leisure {
            self.ce92_leave_leisure().await?;
        }
        self.phase = Phase::Failed;
        self.packet
            .ce92
            .mailbox
            .fill(
                &self.io,
                h2c::H2C_JOINBSSRPT,
                &h2c::joinbss(h2c::MEDIA_DISCONNECT),
            )
            .await?;
        ps::set_media_status(&self.io, &mut self.packet.ce92.bcn, false)?;
        ps::set_aid(&self.io, 0)?;
        self.packet.ce92.link = None;
        self.phase = Phase::Running;
        Ok(())
    }
}
