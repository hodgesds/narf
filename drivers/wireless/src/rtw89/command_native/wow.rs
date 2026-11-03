// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Reversible RTL8852B WoW TRX halt/restart on the one retained Native
//! (`wow.c::rtw89_wow_enable_trx_{pre,post}` / `disable_trx_{pre,post}`).
//! The owner keeps PCI bus mastering, every ring/buffer mapping, the IRQ
//! vector and its MSI binding; only the HIMR mask is cleared while the WoW
//! firmware owns the radio. Any failure terminalizes through `fail`, whose
//! existing closure earns the `dma_stop` proof for the cold path.
use super::*;
use crate::rtw89::{
    lps_packets::{Packets, Stage},
    power, radio_init, rx_packet,
    station_control::Admission,
    wow_security,
    wow_trx::{self, CpuIoRx, Ring, Snapshot},
    wow_wire,
};
use alloc::vec::Vec;

/// Bound on waiting for in-flight CH12 commands before the halt rewinds it.
const H2C_DRAIN_US: u64 = 10_000;

/// Progress of one WoW TRX window.
pub(super) enum Trx {
    /// `enable_trx_pre` done: host TX halted, CH12 open, RX filtered out.
    Quiesced(Snapshot),
    /// `enable_trx_post` done: HCI off, host indices and ring bases reset.
    Parked(Snapshot, Vec<Ring>),
    /// `disable_trx_pre` done: indices cleared, HCI and channels re-opened.
    Restarted(Snapshot),
}

impl Native {
    /// True while a WoW TRX window is open; packet producers and station RX
    /// polling are refused.
    pub(in crate::rtw89) fn wow_trx_open(&self) -> bool {
        self.wow_trx.is_some()
    }
    /// True only between `enable_trx_post` and `disable_trx_pre`, when the
    /// HCI DMA engines are off and CH12 cannot carry a command.
    pub(super) fn wow_parked(&self) -> bool {
        matches!(self.wow_trx, Some(Trx::Parked(..)))
    }
    fn wow_failed<T>(&mut self, error: wow_trx::Error) -> Result<T, power::Error> {
        self.wow_trx = None;
        self.fail();
        Err(match error {
            wow_trx::Error::Register(error) => error,
            wow_trx::Error::Unsupported => power::Error::Unsupported,
            wow_trx::Error::Timeout | wow_trx::Error::TxBusy | wow_trx::Error::Queue => {
                power::Error::Timeout
            }
            _ => power::Error::Access,
        })
    }
    /// `rtw89_wow_enable_trx_pre` on a started, transmit-quiet RTL8852B
    /// station outside LPS. Refusing preconditions leave the station awake
    /// and untouched (`Busy`/`Terminal`); a register failure terminalizes.
    pub(in crate::rtw89) async fn wow_trx_enter_pre(&mut self) -> Result<(), power::Error> {
        if self.chip != ChipId::Rtl8852B
            || self.state != State::Active
            || !self.station_runtime.started()
            || self.station_runtime.monitor.is_some()
            || self.wow_trx.is_some()
            || self.sleep_blocked
            || self.sleep_reset.is_some()
        {
            return Err(power::Error::Terminal);
        }
        self.ordinary_current()?;
        let core = self
            .station_runtime
            .core
            .as_mut()
            .ok_or(power::Error::Terminal)?;
        core.wow_halt().map_err(|_| power::Error::Busy)?;
        match wow_trx::enter_pre(&mut self.io).await {
            Ok(snapshot) => {
                self.wow_trx = Some(Trx::Quiesced(snapshot));
                Ok(())
            }
            Err(error) => self.wow_failed(error),
        }
    }
    /// `rtw89_wow_enable_trx_post` once the WoW firmware runs: HIMR off
    /// (`rtw89_hci_disable_intr`), every CH12 command consumed, then the
    /// register sequence with `rtw89_pci_ops_reset` (host TX/RX/CH12
    /// indices rewound, ring bases re-published, nothing released).
    pub(in crate::rtw89) async fn wow_trx_enter_post(
        &mut self,
        cpu_io_rx: CpuIoRx,
    ) -> Result<(), power::Error> {
        let Some(Trx::Quiesced(snapshot)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        if self.irq.is_some() {
            if let Err(error) = crate::rtw89::irq::Mask::disable(&mut self.io) {
                return self.wow_failed(error.into());
            }
        }
        // Retire every consumed H2C before the CH12 host index rewinds
        // (Linux `rtw89_pci_release_fwcmd` drops unconsumed ones instead).
        let start = self.io.now_us();
        loop {
            if self.poll().is_err() {
                return self.wow_failed(wow_trx::Error::Queue);
            }
            if self.queue.pending() == 0 {
                break;
            }
            if self.io.now_us().saturating_sub(start) >= H2C_DRAIN_US {
                return self.wow_failed(wow_trx::Error::Queue);
            }
            self.io.delay_us(50).await;
        }
        let rings = match self.wow_rewind() {
            Ok(rings) => rings,
            Err(error) => return self.wow_failed(error),
        };
        if let Err(error) = wow_trx::enter_post(&mut self.io, cpu_io_rx, &rings).await {
            return self.wow_failed(error);
        }
        self.wow_trx = Some(Trx::Parked(snapshot, rings));
        Ok(())
    }
    /// Host halves of `rtw89_pci_reset_trx_rings` + `rtw89_pci_ops_reset`.
    fn wow_rewind(&mut self) -> Result<Vec<Ring>, wow_trx::Error> {
        let mut rings = Vec::new();
        let core = self
            .station_runtime
            .core
            .as_mut()
            .ok_or(wow_trx::Error::State)?;
        for (channel, regs, address, depth) in
            core.wow_rewind().map_err(|_| wow_trx::Error::Queue)?
        {
            rings.push(Ring::Tx {
                channel,
                regs,
                address,
                depth,
            });
        }
        self.queue.rewind().map_err(|_| wow_trx::Error::Queue)?;
        let ring = self.ring.as_ref().ok_or(wow_trx::Error::State)?;
        rings.push(Ring::Tx {
            channel: usize::from(crate::rtw89::dma::TXCH_CH12),
            regs: self.regs,
            address: ring.dma_addr().raw(),
            depth: self.depth,
        });
        for (regs, address, depth) in self
            .receive
            .wow_rewind()
            .map_err(|_| wow_trx::Error::State)?
        {
            rings.push(Ring::Rx {
                regs,
                address,
                depth,
            });
        }
        Ok(rings)
    }
    /// `rtw89_wow_disable_trx_pre`: clear device indices, reset BD-RAM,
    /// re-open HCI and the awake channels, restore the awake MAC forwarding,
    /// prove every published index zero, then `rtw89_hci_enable_intr`. The
    /// AOAC report read belongs to the firmware-swap owner.
    pub(in crate::rtw89) async fn wow_trx_leave_pre(&mut self) -> Result<(), power::Error> {
        let Some(Trx::Parked(snapshot, rings)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        let Some(rewind) = wow_trx::Rewind::for_chip(self.chip) else {
            return self.wow_failed(wow_trx::Error::State);
        };
        if let Err(error) = wow_trx::leave_pre(&mut self.io, &snapshot, &rings, rewind).await {
            return self.wow_failed(error);
        }
        if let Some(binding) = self.irq.as_ref() {
            if let Err(error) = binding.start(&mut self.io) {
                return self.wow_failed(error.into());
            }
        }
        self.wow_trx = Some(Trx::Restarted(snapshot));
        Ok(())
    }
    /// `rtw89_wow_disable_trx_post` after the normal firmware is restored:
    /// awake PPDU status and RX filters, then packet producers resume.
    pub(in crate::rtw89) fn wow_trx_leave_post(&mut self) -> Result<(), power::Error> {
        let Some(Trx::Restarted(snapshot)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        if let Err(error) = wow_trx::leave_post(&mut self.io, snapshot) {
            return self.wow_failed(error);
        }
        let resumed = self
            .station_runtime
            .core
            .as_mut()
            .map(|core| core.wow_resume());
        if !matches!(resumed, Some(Ok(()))) {
            return self.wow_failed(wow_trx::Error::State);
        }
        Ok(())
    }
    /// A firmware image may replace the running one: RTL8852B with host TX
    /// halted (`Quiesced`, the WoW image) or HCI restarted after the WoW
    /// window (`Restarted`, the normal image), and every H2C consumed. AX
    /// non-C chips keep interrupts enabled across the download
    /// (`rtw89_wow_swap_fw` `disable_intr_for_dlfw = false`).
    pub(in crate::rtw89) fn wow_swappable(&self) -> bool {
        self.chip == ChipId::Rtl8852B
            && self.state == State::Active
            && matches!(self.wow_trx, Some(Trx::Quiesced(_) | Trx::Restarted(_)))
            && self.queue.pending() == 0
    }
    /// After `Firmware::swap` returned: the fresh image counts H2C sequences
    /// from zero again (`__rtw89_fw_download` clears `h2c_seq`/`rec_seq`),
    /// and C2H already retained from the replaced image is dropped so no
    /// stale ACK can satisfy a new command.
    pub(in crate::rtw89) fn wow_firmware_loaded(&mut self) -> Result<(), power::Error> {
        if !self.wow_swappable() {
            self.fail();
            return Err(power::Error::Terminal);
        }
        self.runtime_sequence = 0;
        self.station_runtime
            .backlog
            .retain(|event| !matches!(event, rx_packet::Event::Firmware(_)));
        Ok(())
    }
    /// `rtw89_phy_init_rf_reg(rtwdev, true)` on the fresh image: the RF
    /// A/B firmware register pages of the retained signed tables, no RF I/O.
    pub(in crate::rtw89) async fn wow_rf_pages(
        &mut self,
        assets: &crate::rtw89::radio_assets::Assets,
    ) -> Result<(), power::Error> {
        if !self.wow_swappable() {
            return Err(power::Error::Terminal);
        }
        let qualified = self
            .factory
            .as_ref()
            .and_then(radio_init::Qualified::from_factory)
            .ok_or(power::Error::Terminal)?;
        let pages =
            radio_init::noio_pages(qualified, assets).map_err(|_| power::Error::Unsupported)?;
        for (path, bytes) in pages.iter().enumerate() {
            for (page, chunk) in bytes.chunks(2000).enumerate() {
                if let Err(error) = self
                    .transmit_radio_page(path as u8, page as u8, chunk)
                    .await
                {
                    self.fail();
                    return Err(match error {
                        radio_init::Error::Register(error) => error,
                        _ => power::Error::Access,
                    });
                }
            }
        }
        Ok(())
    }
    /// `rtw89_fw_h2c_general_pkt` on the fresh image: PS-Poll, NULL and QoS
    /// NULL packet offloads (`H2C_FUNC_PACKET_OFLD` ADD + its C2H response)
    /// then `GENERAL_PKT` with DONE_ACK, through station admission.
    pub(in crate::rtw89) async fn wow_general_packets(
        &mut self,
        packets: &mut Packets,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        let permit = station::Permit::Station(admission);
        while matches!(packets.stage(), Stage::Add(_)) {
            let body = packets.begin_add().map_err(|_| power::Error::Terminal)?;
            let (id, op) = packets.pending().ok_or(power::Error::Terminal)?;
            // Drop only obsolete offload responses before the new request.
            self.station_runtime.backlog.retain(|event| {
                !matches!(event, rx_packet::Event::Firmware(m)
                    if (m.category, m.class, m.function) == (1, 1, 2))
            });
            self.runtime_command(1, 9, 1, &body, true, permit).await?;
            packets
                .command_done(id, op)
                .map_err(|_| power::Error::Terminal)?;
            let response = self.wow_offload_response(id, op).await?;
            if !packets
                .response(&response)
                .map_err(|_| power::Error::Terminal)?
            {
                return Err(power::Error::Access);
            }
        }
        let body = packets.general().map_err(|_| power::Error::Terminal)?;
        self.runtime_command(1, 0, 1, &body, true, permit).await?;
        packets
            .general_done(body)
            .map_err(|_| power::Error::Terminal)
    }
    /// The copied C2H MAC1/OFLD1/function2 response for one offload request.
    async fn wow_offload_response(&mut self, id: u8, op: u8) -> Result<Vec<u8>, power::Error> {
        let start = self.io.now_us();
        loop {
            let mut found = None;
            let mut index = 0;
            while index < self.station_runtime.backlog.len() {
                let matched = matches!(&self.station_runtime.backlog[index],
                    rx_packet::Event::Firmware(m)
                        if (m.category, m.class, m.function) == (1, 1, 2)
                            && crate::rtw89::lps_wire::packet_response(&m.bytes, id, op));
                if matched {
                    if found.is_some() {
                        return Err(power::Error::Access);
                    }
                    if let Some(rx_packet::Event::Firmware(m)) =
                        self.station_runtime.backlog.remove(index)
                    {
                        found = Some(m.bytes);
                    }
                } else {
                    index += 1;
                }
            }
            if let Some(bytes) = found {
                return Ok(bytes);
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(power::Error::Timeout);
            }
            self.io.delay_us(50).await;
            self.poll().map_err(|_| power::Error::Access)?;
            let batch = self
                .rx_hardware_step(32)
                .map_err(|_| power::Error::Access)?;
            for event in batch.events {
                self.retain_event(event)?;
            }
        }
    }
}

/// `H2C_CL_MAC_ADDR_CAM_UPDATE` / `H2C_FUNC_MAC_ADDR_CAM_UPD`.
const H2C_CL_MAC_ADDR_CAM: u8 = 0x6;

impl Native {
    /// One `H2C_CAT_MAC` command inside an open WoW window while CH12 runs
    /// (`Quiesced` or `Restarted`), under station admission. `done` is the
    /// Linux DONE_ACK flag of that command.
    pub(in crate::rtw89) async fn wow_command(
        &mut self,
        class: u8,
        function: u8,
        body: &[u8],
        done: bool,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        if !matches!(self.wow_trx, Some(Trx::Quiesced(_) | Trx::Restarted(_))) {
            return Err(power::Error::Terminal);
        }
        self.runtime_command(
            1,
            class,
            function,
            body,
            done,
            station::Permit::Station(admission),
        )
        .await
    }
    /// `rtw89_fw_h2c_cam(RTW89_ROLE_INFO_CHANGE)` (AX v0 body, DONE_ACK).
    pub(in crate::rtw89) async fn wow_addr_cam(
        &mut self,
        cam: &[u8; 60],
        admission: &Admission,
    ) -> Result<(), power::Error> {
        self.wow_command(H2C_CL_MAC_ADDR_CAM, 0, cam, true, admission)
            .await
    }
    /// `rtw89_cam_send_sec_key_cmd` for each entry (RECV_ACK only), or the
    /// zero-key overwrite of each when `clear`.
    pub(in crate::rtw89) async fn wow_sec_cam(
        &mut self,
        entries: &[wow_security::Entry],
        clear: bool,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        for entry in entries {
            let body = if clear { entry.cleared() } else { entry.body() };
            self.wow_command(
                wow_wire::H2C_CL_MAC_SEC_CAM,
                wow_wire::H2C_FUNC_MAC_SEC_UPD,
                &body[..],
                false,
                admission,
            )
            .await?;
        }
        Ok(())
    }
    /// `rtw89_mac_hw_mgnt_sec`: set or clear `B_AX_{UC,BMC}_MGNT_DEC` and
    /// prove the result by read-back. Clearing re-proves the awake
    /// host-crypto state (no management decryption by the MAC).
    pub(in crate::rtw89) fn wow_mgnt_sec(&mut self, enable: bool) -> Result<(), power::Error> {
        use crate::rtw89::mac_runtime_regs::R_AX_SEC_ENG_CTRL;
        if self.wow_trx.is_none() {
            return Err(power::Error::Terminal);
        }
        let result = (|| {
            let value = self.read32(R_AX_SEC_ENG_CTRL)?;
            let next = if enable {
                value | wow_security::MGNT_DEC
            } else {
                value & !wow_security::MGNT_DEC
            };
            self.write32(R_AX_SEC_ENG_CTRL, next)?;
            let mask = self.read32(R_AX_SEC_ENG_CTRL)? & wow_security::MGNT_DEC;
            if mask != if enable { wow_security::MGNT_DEC } else { 0 } {
                return Err(power::Error::Access);
            }
            Ok(())
        })();
        if result.is_err() {
            self.wow_trx = None;
            self.fail();
        }
        result
    }
    /// The copied bytes (C2H header included) of the next firmware message
    /// `(category, class, function)`, waited for at most 400 ms while CH12
    /// runs. Used for the AOAC report (`rtw89_mac_c2h_wow_aoac_rpt`).
    pub(in crate::rtw89) async fn wow_c2h(
        &mut self,
        category: u8,
        class: u8,
        function: u8,
    ) -> Result<Vec<u8>, power::Error> {
        if !matches!(self.wow_trx, Some(Trx::Quiesced(_) | Trx::Restarted(_))) {
            return Err(power::Error::Terminal);
        }
        let start = self.io.now_us();
        loop {
            let index = self.station_runtime.backlog.iter().position(|event| {
                matches!(event, rx_packet::Event::Firmware(m)
                    if (m.category, m.class, m.function) == (category, class, function))
            });
            if let Some(index) = index {
                if let Some(rx_packet::Event::Firmware(m)) =
                    self.station_runtime.backlog.remove(index)
                {
                    return Ok(m.bytes);
                }
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(power::Error::Timeout);
            }
            self.io.delay_us(50).await;
            self.poll().map_err(|_| power::Error::Access)?;
            let batch = self
                .rx_hardware_step(32)
                .map_err(|_| power::Error::Access)?;
            for event in batch.events {
                self.retain_event(event)?;
            }
        }
    }
}
