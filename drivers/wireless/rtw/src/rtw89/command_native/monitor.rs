// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Same-Native receive-only monitor adapter. No ordinary packet Core/peer is
//! created and CMAC TX stays disabled even while WCPU command DMA is active.
use super::*;
use crate::rtw89::{monitor, monitor_wire as wire, power, rx_packet, station_control as control};
use alloc::{sync::Arc, vec::Vec};
pub(super) struct Mode {
    desired: Arc<monitor::Desired>,
    selection: monitor::Selection,
    admission: control::Admission,
    observed: bool,
}
pub(in crate::rtw89) struct Port<'a>(&'a mut Native);
impl Native {
    pub(in crate::rtw89) fn monitor_prepare(
        &mut self,
        desired: Arc<monitor::Desired>,
        admission: control::Admission,
    ) -> Result<(), power::Error> {
        // The monitor owner programs RTL8852B-only RX filter/PHY state.
        if self.chip != ChipId::Rtl8852B {
            return Err(power::Error::Unsupported);
        }
        self.with_ordinary_current(|native| {
            let selection = desired.snapshot();
            if selection.mode != wire::IFTYPE
                || !desired.current(selection)
                || native.station_runtime.monitor.is_some()
                || native.station_runtime.core.is_some()
                || native.station_runtime.peer.is_some()
                || native.station_runtime.started()
                || native.sleep_blocked
                || native.sleep_reset.is_some()
                || native.io.read32(0xc000)? & wire::CMAC_TX != 0
            {
                return Err(power::Error::Terminal);
            }
            admission.check()?;
            // Retain original mode/source before any awaited firmware command.
            native.station_runtime.monitor = Some(Mode {
                desired,
                selection,
                admission,
                observed: false,
            });
            Ok(())
        })
    }
    pub(in crate::rtw89) fn monitor_access(&mut self) -> Port<'_> {
        Port(self)
    }
    pub(super) fn monitor_request_current(
        &mut self,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.monitor_current()?;
        if self
            .station_runtime
            .monitor
            .as_ref()
            .is_none_or(|mode| !mode.admission.same(admission))
        {
            return Err(power::Error::Terminal);
        }
        Ok(())
    }
    pub(super) fn monitor_current(&mut self) -> Result<(), power::Error> {
        self.with_ordinary_current(|native| {
            let mode = native
                .station_runtime
                .monitor
                .as_ref()
                .ok_or(power::Error::Terminal)?;
            mode.admission.check()?;
            if !mode.desired.current(mode.selection)
                || native.sleep_blocked
                || native.sleep_reset.is_some()
                || native.station_runtime.core.is_some()
                || native.station_runtime.peer.is_some()
                || native.station_runtime.started()
                || native.io.read32(0xc000)? & wire::CMAC_TX != 0
            {
                return Err(power::Error::Terminal);
            }
            control::awake(&mut native.io)?;
            // Polled monitor has no MSI binding yet still observes the actual
            // source fatal register; a missing interrupt cannot keep copies live.
            let fatal = native.io.read32(crate::rtw89::irq::R_AX_HISR0)?;
            if fatal
                & (crate::rtw89::irq::B_AX_HALT_C2H_INT_EN
                    | crate::rtw89::irq::B_AX_WDT_TIMEOUT_INT_EN)
                != 0
            {
                return Err(power::Error::Terminal);
            }
            if mode.observed {
                let filter = native.io.read32(wire::RX_FILTER)?;
                if wire::receive_filter(filter) != Some(filter)
                    || filter & wire::SNIFFER == 0
                    || native.io.read32(0x9d00)? & 31 != 0
                    || native.io.read32(0x9d04)? & 3 != 0
                    || wire::port(native.io.read32(0xc400)?) != Some(native.io.read32(0xc400)?)
                {
                    return Err(power::Error::Access);
                }
                for address in wire::FORWARD {
                    if native.io.read32(address)? != wire::TO_HOST {
                        return Err(power::Error::Access);
                    }
                }
            }
            Ok(())
        })
    }
    pub(in crate::rtw89) fn monitor_source(
        &mut self,
        epoch: monitor::Epoch,
    ) -> Result<monitor::Source, power::Error> {
        self.monitor_current()?;
        let mode = self
            .station_runtime
            .monitor
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        if !mode.observed {
            return Err(power::Error::Terminal);
        }
        // SAFETY: source was minted only by this exact Native's completed full
        // RFK/observed-channel/nonemitting monitor owner; fields stay original.
        Ok(unsafe {
            monitor::Source::new(
                self.authority,
                self.ordinary
                    .as_ref()
                    .ok_or(power::Error::Terminal)?
                    .b()
                    .ok_or(power::Error::Unsupported)?
                    .clone(),
                mode.desired.clone(),
                mode.selection,
                mode.admission.clone(),
                epoch,
            )
        })
    }
}
// SAFETY: Port exclusively borrows the retained actual Native/FW/rings. All
// operations retain original qualification, device, role and admission, and
// check CMAC TX disabled. No reconstructed BAR/producer or name-follow exists.
unsafe impl monitor::Io for Port<'_> {
    fn current(
        &mut self,
        admission: &control::Admission,
        selection: monitor::Selection,
    ) -> Result<(), power::Error> {
        self.0.monitor_current()?;
        let mode = self
            .0
            .station_runtime
            .monitor
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        if !mode.admission.same(admission) || mode.selection != selection {
            return Err(power::Error::Terminal);
        }
        Ok(())
    }
    async fn program(
        &mut self,
        admission: &control::Admission,
        selection: monitor::Selection,
    ) -> Result<(), power::Error> {
        self.current(admission, selection)?;
        let identity = self.0.identity().ok_or(power::Error::Terminal)?;
        control::initialize_monitor(
            &mut self.0.station_access(),
            identity.mac(),
            identity.fuses().enabled(),
            admission,
        )
        .await?;
        self.current(admission, selection)
    }
    async fn observed_channel(
        &mut self,
        admission: &control::Admission,
        selection: monitor::Selection,
    ) -> Result<[u32; 4], power::Error> {
        let mut words = [0; 4];
        for (index, (path, address)) in [(0, 0x18), (0, 0x10018), (1, 0x18), (1, 0x10018)]
            .into_iter()
            .enumerate()
        {
            self.current(admission, selection)?;
            // SAFETY: same serialized actual B Native/current full RFK source;
            // read-only SWSI/direct observation, no retune/calibration/emission.
            words[index] = unsafe { self.0.read_rf(path, address, 0xfffff).await }?;
        }
        self.current(admission, selection)?;
        if !wire::observed_channel(words, selection.primary) {
            return Err(power::Error::Access);
        }
        self.0
            .station_runtime
            .monitor
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .observed = true;
        Ok(words)
    }
    fn retire_prefix(
        &mut self,
        admission: &control::Admission,
        selection: monitor::Selection,
    ) -> Result<bool, power::Error> {
        self.current(admission, selection)?;
        self.0.station_runtime.backlog.clear();
        // Two actual finite RX rings (depth<=256). Partial/dropped descriptors
        // count as progress; no pre-active copied input becomes current capture.
        for _ in 0..8 {
            let batch = self
                .0
                .rx_hardware_step(256)
                .map_err(|_| power::Error::Access)?;
            self.current(admission, selection)?;
            if !batch.consumed {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn receive(
        &mut self,
        admission: &control::Admission,
        selection: monitor::Selection,
        budget: usize,
    ) -> Result<Vec<Vec<u8>>, power::Error> {
        self.current(admission, selection)?;
        let irq = self.0.irq_service()?;
        if irq.fatal() || irq.stuck || irq.rx_unavailable {
            return Err(power::Error::Terminal);
        }
        let batch = self
            .0
            .rx_hardware_step(budget)
            .map_err(|_| power::Error::Access)?;
        let mut frames = Vec::new();
        for event in batch.events {
            if let rx_packet::Event::Wifi(_, bytes) = event {
                frames.push(bytes);
            }
        }
        self.0.irq_rearm()?;
        self.current(admission, selection)?;
        Ok(frames)
    }
    fn stop(&mut self) -> Result<(), power::Error> {
        // Device-only stop remains possible after the original RF source dies.
        // Existing fail/retire_dma retains mappings unless actual stop is proved.
        self.0.fail();
        Ok(())
    }
}
