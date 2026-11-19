// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained child of prepared_8922a: retain its original owner alongside checked
//! ring/RX storage, with no ordinary Prepared API exposed through this wrapper.
use super::Prepared8922a;
use crate::rtw89::pci_pre_init_8922a::checked as preinit;
use crate::rtw89::{checked_fwdl_8922a as checked, cold_8922a as cold, fwdl_be};
use core::mem::ManuallyDrop;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::DmaBuffer;

pub(in crate::rtw89) struct CheckedPrepared {
    // A failed/cancelled wrapper never drops legacy Prepared DMA owners.
    // Explicit checked terminal stop is the only path that drops this base.
    base: ManuallyDrop<alloc::boxed::Box<Prepared8922a>>,
    base_live: bool,
    cold: cold::Cold,
    dma: checked::Owner<DmaBuffer>,
    preinit: preinit::Preinit,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    system: crate::rtw89::mac_system_8922a::System,
    trx: crate::rtw89::trx_8922a::Trx,
    mailbox: crate::rtw89::be_mailbox::Mailbox,
    phycap: Option<crate::rtw89::be_mailbox::Receipt>,
    control: crate::rtw89::be_control::Control,
    scheduler: crate::rtw89::be_scheduler::Scheduler,
}
impl CheckedPrepared {
    /// # Safety
    /// Exact original N22O/BE MLME command producer while packet-prepared and
    /// still closed. Source ACK flags are preserved; REC proves receipt only.
    pub(in crate::rtw89) unsafe fn send_mlme(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        grant: &crate::rtw89::be_packet_qualification::Ordinary,
        radio: &crate::rtw89::native_radio_be::Radio,
        command: crate::rtw89::link_h2c_8922a::LinkCmd,
        body: &[u8],
    ) -> Result<(), crate::rtw89::be_control::Error> {
        if !self.control_ready()
            || self.dma.packet_phase()
                != Some(crate::rtw89::checked_fwdl_8922a::packet::Phase::Inactive)
            || command.rec_ack && command.done_ack
        {
            return Err(crate::rtw89::be_control::Error::State);
        }
        // SAFETY: retained same closed original checked owner; current N22O
        // surrounds every scalar, descriptor memory and RX credit operation.
        let native = unsafe { checked::Native::new(region, &self.authority) }
            .cancel_with(cancel)
            .qualify_scope(crate::rtw89::be_qualification::Grant::Packet(grant, radio));
        let mut port = ControlPort {
            owner: &mut self.dma,
            io: native,
        };
        let result = if command.rec_ack {
            // SAFETY: caller supplies the exact source REC-only command on
            // this original inactive owner. Native invokes Radio/N22W,
            // N22O and PCI around every scalar/DMA operation; Control checks
            // payload bounds and the exact receipt tuple independently of RP.
            unsafe { self.control.send_rec(&mut port, command.cmd, body, 1000) }
        } else if command.done_ack {
            // SAFETY: same original current source/transport scope; this
            // branch preserves the command's requested DONE bit. Control
            // requires successful matching DONE and separate RP consumption;
            // all original mappings stay retained on failure/cancellation.
            unsafe { self.control.send_done(&mut port, command.cmd, body, 1000) }
        } else {
            // SAFETY: same original current source/transport scope and
            // checked payload bounds. This source command requests no ACK;
            // passing None neither substitutes a report nor invents firmware
            // acceptance. Errors poison this owner below without releasing DMA.
            unsafe { self.control.send(&mut port, command.cmd, body, None) }
        };
        if result.is_err() {
            self.poison_radio();
        }
        result.map(|_| ())
    }
    pub(in crate::rtw89) fn packet_preflight(
        &mut self,
        io: &mut impl crate::rtw89::checked_fwdl_8922a::packet::Port,
        own: [u8; 6],
    ) -> Result<(), checked::Error> {
        if !self.control_ready() || self.control.state() != crate::rtw89::be_control::State::Idle {
            return Err(checked::Error::State);
        }
        let result = self.dma.packet_preflight(io, own);
        if result.is_err() {
            self.poison_radio();
        }
        result
    }
    /// # Safety
    /// Actual original Cold, Prepared and ALL probe ring/RX mappings of one
    /// RTL8922A move here. No Rtw89Device field may retain a second droppable
    /// copy or producer view. No concurrent worker/reset/removal. The Cold
    /// receipt came from its full checked power/BB prefix on this function.
    /// The separate retained BE supervisor is the native caller; legacy
    /// pci::bring_up_registers cannot supply these temporal/ownership facts.
    pub(in crate::rtw89) unsafe fn adopt(
        base: alloc::boxed::Box<Prepared8922a>,
        cold: cold::Cold,
        storage: checked::Storage<DmaBuffer>,
        tx_depth: u16,
        rx_depth: u16,
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Self {
        let preinit = preinit::Preinit::new(base.chip_version());
        // SAFETY: caller moved complete original ring/RX ownership. Legacy
        // Prepared mappings stay pinned until a permanent verified held stop.
        let dma =
            unsafe { checked::Owner::adopt(storage, alloc::vec::Vec::new(), tx_depth, rx_depth) };
        Self {
            base: ManuallyDrop::new(base),
            base_live: true,
            cold,
            dma,
            preinit,
            device,
            authority,
            system: crate::rtw89::mac_system_8922a::System::default(),
            trx: crate::rtw89::trx_8922a::Trx::default(),
            mailbox: crate::rtw89::be_mailbox::Mailbox::default(),
            phycap: None,
            control: crate::rtw89::be_control::Control::default(),
            scheduler: crate::rtw89::be_scheduler::Scheduler::default(),
        }
    }
    pub(in crate::rtw89) fn reset_program(
        &mut self,
        io: &mut impl cold::Regs,
    ) -> Result<(), checked::Error> {
        if !self.base_live {
            return Err(checked::Error::State);
        }
        let result = (|| {
            self.cold
                .observe_dma_entry(io)
                .map_err(|_| checked::Error::State)?;
            self.preinit
                .dle_hfc(io)
                .map_err(|_| checked::Error::State)?;
            self.preinit
                .recovery(io)
                .map_err(|_| checked::Error::State)?;
            self.dma.reset_program(io)?;
            self.dma.reset_current(io)?;
            self.preinit.settings(io).map_err(|_| checked::Error::State)
        })();
        if result.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result?;
        // The held configuration and source BDRAM clear are not a fresh
        // retirement epoch. Keep all original Prepared DMA owners intact;
        // the wrapper exposes no old station/data producer or infallible kick.
        // Keep every existing ordinary transport/firmware readiness gate closed.
        self.base.rings_programmed = false;
        self.base.firmware = None;
        self.base.channel = None;
        Ok(())
    }
    /// Only this retained original preinit + ring owner may enable PCI BME,
    /// then source CH12/global DMA. No caller-supplied readiness boolean.
    pub(in crate::rtw89) fn enable_ch12(
        &mut self,
        io: &mut impl cold::Regs,
        cancel: &core::sync::atomic::AtomicBool,
    ) -> Result<(), checked::Error> {
        if !self.base_live {
            return Err(checked::Error::State);
        }
        let result = (|| {
            self.cold
                .observe_dma_entry(io)
                .map_err(|_| checked::Error::State)?;
            self.dma.reset_current(io)?;
            self.preinit.ready(io).map_err(|_| checked::Error::State)?;
            use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
            let command = crate::rtw88::pci_park::invoke(&self.authority, || {
                if cancel.load(core::sync::atomic::Ordering::Acquire) {
                    return Err(());
                }
                narf_bus::pci::read_command(&self.authority, &self.device).map_err(|_| ())
            })
            .map_err(|_| checked::Error::Identity)?
            .map_err(|_| checked::Error::Identity)?;
            if command == u16::MAX
                || command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE
            {
                return Err(checked::Error::Identity);
            }
            io.current()?;
            crate::rtw88::pci_park::master_with(
                |bits| {
                    crate::rtw88::pci_park::invoke(&self.authority, || {
                        if cancel.load(core::sync::atomic::Ordering::Acquire) {
                            return Err(());
                        }
                        narf_bus::pci::set_command(&self.authority, &self.device, bits)
                            .map_err(|_| ())
                    })
                    .map_err(|_| ())?
                },
                || {
                    crate::rtw88::pci_park::invoke(&self.authority, || {
                        if cancel.load(core::sync::atomic::Ordering::Acquire) {
                            return Err(());
                        }
                        narf_bus::pci::read_command(&self.authority, &self.device).map_err(|_| ())
                    })
                    .map_err(|_| ())?
                },
            )
            .map_err(|_| checked::Error::Identity)?;
            self.preinit.ready(io).map_err(|_| checked::Error::State)?;
            // SAFETY: the retained checked DLE/HFC/PCI producer, ring/base/index
            // receipts and same original PCI BME readback all succeeded above.
            unsafe { self.dma.enable_ch12(io) }
        })();
        if result.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result
    }
    /// # Safety
    /// Original signed/fuse-selected NORMAL and BBMCU0 plans, actual checked
    /// enable prerequisites, exclusive same-controller owner. No retry after
    /// uncertainty and no recursive Rtw89Device/Prepared source-lock callback.
    pub(in crate::rtw89) unsafe fn download(
        &mut self,
        io: &mut checked::Native<'_>,
        normal: &fwdl_be::Suit<'_>,
        bb: &fwdl_be::Suit<'_>,
    ) -> Result<(), cold::Error> {
        if !self.base_live {
            return Err(cold::Error::Terminal);
        }
        let result = {
            // SAFETY: caller's stage facts plus checked Owner DMA receipt;
            // direct disjoint borrows live under this one outer lock.
            let port = unsafe { checked::Port::new(&mut self.dma, io) };
            match port {
                Ok(mut port) => self.cold.download(&mut port, normal, bb),
                Err(_) => {
                    let error = cold::Error::MissingDmaBridge;
                    self.cold.poison(error);
                    Err(error)
                }
            }
        };
        if result.is_err() {
            self.dma.poison()
        }
        result
    }
    /// Permanently stop this exact controller and release all original maps.
    /// A failed receipt retains both ring storage and old Prepared payloads.
    pub(in crate::rtw89) fn stop_release(
        &mut self,
        io: checked::Native<'_>,
    ) -> Result<checked::Storage<DmaBuffer>, checked::Error> {
        let storage = io.retire(&mut self.dma)?;
        if self.base_live {
            // SAFETY: same original controller is positively stopped/idle with
            // WCPU held and wrapper terminal. No future method can enable DMA;
            // this is the sole drop of the retained original Prepared owner.
            unsafe { ManuallyDrop::drop(&mut self.base) };
            self.base_live = false;
        }
        Ok(storage)
    }
    pub(in crate::rtw89) fn secure_fuses(&self) -> crate::rtw89::secure::Fuses {
        self.base.secure_fuses()
    }
    /// The original completed single-attempt FWDL owner is the only producer
    /// of this closed system stage. No ordinary Prepared readiness is set.
    pub(in crate::rtw89) fn configure_system(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
    ) -> Result<(), crate::rtw89::mac_system_8922a::Error> {
        use crate::rtw89::mac_system_8922a as sys;
        if !self.base_live
            || self.cold.state() != cold::State::FirmwareDownloaded
            || self.dma.state() != checked::State::Enabled
        {
            return Err(sys::Error::FirmwareRequired);
        }
        // SAFETY: retained original one-shot owner; same live function/BAR,
        // completed NORMAL+BBMCU0 download, all mappings still owned and no
        // ordinary producer/IRQ. The passed region is re-bound below.
        let mut guard =
            unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        self.dma
            .dma_current(&mut guard)
            .map_err(|_| sys::Error::DmaState)?;
        // SAFETY: same original function and live mapping just checked by the
        // retained DMA identity; no other BAR producer can run in this borrow.
        let mut io = unsafe { sys::NativeRegs::new(region, &self.authority) }.cancel_with(cancel);
        // SAFETY: actual retained Cold FWDL completion and same-controller DMA
        // receipt above, complete checked closed power tuple verified inside.
        let r = unsafe { self.system.configure(&mut io) };
        if r.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        r
    }
    /// Source SCC/TRX configuration under a positive HAXI stop. This retains
    /// the original RP-consumed FWDL allocations and enables no ordinary DMA.
    pub(in crate::rtw89) fn configure_trx(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
    ) -> Result<(), crate::rtw89::trx_8922a::Error> {
        use crate::rtw89::{mac_system_8922a as sys, trx_8922a as trx};
        if !self.base_live
            || self.cold.state() != cold::State::FirmwareDownloaded
            || self.system.state() != sys::State::SystemConfigured
        {
            return Err(trx::Error::State);
        }
        // SAFETY: sole original retained DMA owner, live original capability
        // and mapping, no producer/IRQ; checked DMA entry binds the same BAR.
        let mut dma_io =
            unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let result = (|| {
            self.dma
                .stop_for_trx(&mut dma_io)
                .map_err(|_| trx::Error::State)?;
            // SAFETY: same original BAR/cap just bound by retained DMA; original
            // source System stage completed, MAC0 packets closed/MAC1 off.
            let mut io = unsafe { trx::Native::new(region, &self.authority, cancel) };
            // SAFETY: original fresh completed FWDL/System state above, actual
            // pending-RP drain and held HAXI/idle receipt, all maps retained.
            unsafe { self.trx.configure(&mut io, self.base.chip_version()) }?;
            self.trx.current(&mut io)?;
            // SAFETY: actual retained checked SCC/TRX completion on the same
            // source. Restore CH12/global DMA only; ordinary TX/WPDMA stay off.
            unsafe { self.dma.resume_ch12_after_trx(&mut dma_io) }.map_err(|_| trx::Error::State)
        })();
        if result.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result
    }
    /// Bounded firmware-only control RX on the original retained native owner.
    /// Ordinary Prepared RX/station APIs remain unavailable through this type.
    pub(in crate::rtw89) fn poll_firmware(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        budget: usize,
    ) -> Result<checked::FirmwareRx, checked::Error> {
        if !self.base_live
            || self.cold.state() != cold::State::FirmwareDownloaded
            || self.system.state() != crate::rtw89::mac_system_8922a::State::SystemConfigured
            || self.trx.state() != crate::rtw89::trx_8922a::State::ConfiguredClosed
        {
            return Err(checked::Error::State);
        }
        // SAFETY: exact retained native stages above, all original mappings
        // owned once, no competing RX/IRQ/producer/reset; DMA rebinds the BAR.
        let mut io = unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let result = io.receive_firmware(&mut self.dma, budget);
        if result.is_err() {
            self.cold.poison(cold::Error::Terminal);
        }
        result
    }
    pub(in crate::rtw89) fn query_phycap(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        features: crate::rtw89::rfk::be_features::Features,
    ) -> Result<(), checked::Error> {
        if !self.base_live
            || self.phycap.is_some()
            || self.cold.state() != cold::State::FirmwareDownloaded
            || self.system.state() != crate::rtw89::mac_system_8922a::State::SystemConfigured
            || self.trx.state() != crate::rtw89::trx_8922a::State::ConfiguredClosed
        {
            return Err(checked::Error::State);
        }
        // SAFETY: same retained complete native stages, every original DMA
        // mapping stays owned, exclusive mailbox and no IRQ/reset/producer.
        let native = unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let mut port = MailboxPort {
            owner: &mut self.dma,
            io: native,
        };
        let result = self
            .mailbox
            .query(&mut port, features, self.device.id.device);
        match result {
            Ok(receipt) => {
                self.phycap = Some(receipt);
                Ok(())
            }
            Err(error) => {
                self.dma.poison();
                self.cold.poison(cold::Error::Terminal);
                Err(error.into())
            }
        }
    }
    fn control_ready(&self) -> bool {
        self.base_live
            && self.phycap.is_some()
            && self.cold.state() == cold::State::FirmwareDownloaded
            && self.system.state() == crate::rtw89::mac_system_8922a::State::SystemConfigured
            && self.trx.state() == crate::rtw89::trx_8922a::State::ConfiguredClosed
    }
    pub(in crate::rtw89) fn partial_radio_ready(&self) -> Result<(), crate::rtw89::power::Error> {
        if self.control_ready() {
            Ok(())
        } else {
            Err(crate::rtw89::power::Error::Terminal)
        }
    }
    pub(in crate::rtw89) fn phycap(&self) -> Option<&crate::rtw89::be_mailbox::Receipt> {
        self.phycap.as_ref()
    }
    pub(in crate::rtw89) fn pending_rfk(&self) -> Option<crate::rtw89::rfk::be_rfk::ReportKind> {
        match self.control.state() {
            crate::rtw89::be_control::State::Awaiting { kind, .. } => Some(kind),
            _ => None,
        }
    }
    pub(in crate::rtw89) fn poison_radio(&mut self) {
        self.control.poison();
        self.dma.poison();
        self.cold.poison(cold::Error::Terminal);
    }
    /// Actual retained native CH12 control transport; no legacy Prepared or
    /// ordinary packet API is exposed. Report ownership survives the call.
    /// # Safety
    /// Caller holds the current semantic grant for this actual command. Any
    /// RF/table/calibration command must run under the full signed program,
    /// channel/coexistence envelope at every effect; this stage/PHY capability
    /// alone does not authorize it. Failed/dropped outer operations are
    /// terminal and cannot reconstruct a new control owner or retry sequence.
    pub(in crate::rtw89) unsafe fn send_h2c(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        command: crate::rtw89::fwcmd_8922a::H2cCmd,
        payload: &[u8],
        expected: Option<crate::rtw89::rfk::be_rfk::ReportKind>,
    ) -> Result<crate::rtw89::fwcmd_8922a::FramedH2c, crate::rtw89::be_control::Error> {
        self.send_h2c_with(region, cancel, command, payload, expected, None)
    }
    /// # Safety
    /// Same original command-semantic contract as send_h2c, with the exact
    /// original N22P grant bound to this owner's actual retained source facts.
    /// Each scalar and descriptor/RX-memory effect independently invokes it.
    pub(in crate::rtw89) unsafe fn send_h2c_qualified(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        command: crate::rtw89::fwcmd_8922a::H2cCmd,
        payload: &[u8],
        expected: Option<crate::rtw89::rfk::be_rfk::ReportKind>,
        grant: &crate::rtw89::be_qualification::Partial,
    ) -> Result<crate::rtw89::fwcmd_8922a::FramedH2c, crate::rtw89::be_control::Error> {
        self.send_h2c_with(
            region,
            cancel,
            command,
            payload,
            expected,
            Some(crate::rtw89::be_qualification::Grant::Partial(grant)),
        )
    }
    /// # Safety
    /// Same exact original semantic ownership as send_h2c_qualified; the
    /// scope is borrowed from the selected retained N22P/N22W owner. A DONE
    /// acknowledgement is requested only for source commands that ask for it.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::rtw89) unsafe fn send_h2c_scoped(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        command: crate::rtw89::fwcmd_8922a::H2cCmd,
        payload: &[u8],
        expected: Option<crate::rtw89::rfk::be_rfk::ReportKind>,
        grant: crate::rtw89::be_qualification::Grant<'_>,
        done: bool,
    ) -> Result<crate::rtw89::fwcmd_8922a::FramedH2c, crate::rtw89::be_control::Error> {
        self.send_h2c_flags(
            region,
            cancel,
            command,
            payload,
            expected,
            Some(grant),
            done,
        )
    }
    fn send_h2c_with(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        command: crate::rtw89::fwcmd_8922a::H2cCmd,
        payload: &[u8],
        expected: Option<crate::rtw89::rfk::be_rfk::ReportKind>,
        grant: Option<crate::rtw89::be_qualification::Grant<'_>>,
    ) -> Result<crate::rtw89::fwcmd_8922a::FramedH2c, crate::rtw89::be_control::Error> {
        self.send_h2c_flags(region, cancel, command, payload, expected, grant, false)
    }
    #[allow(clippy::too_many_arguments)]
    fn send_h2c_flags(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        command: crate::rtw89::fwcmd_8922a::H2cCmd,
        payload: &[u8],
        expected: Option<crate::rtw89::rfk::be_rfk::ReportKind>,
        grant: Option<crate::rtw89::be_qualification::Grant<'_>>,
        done: bool,
    ) -> Result<crate::rtw89::fwcmd_8922a::FramedH2c, crate::rtw89::be_control::Error> {
        if !self.control_ready() {
            return Err(crate::rtw89::be_control::Error::State);
        }
        if done && expected.is_some() {
            self.poison_radio();
            return Err(crate::rtw89::be_control::Error::Geometry);
        }
        // SAFETY: actual retained complete closed stages/PHY receipt above,
        // exclusive original mappings and no reset/IRQ/other producer.
        let native = unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let native = if let Some(grant) = grant {
            native.qualify_scope(grant)
        } else {
            native
        };
        let mut port = ControlPort {
            owner: &mut self.dma,
            io: native,
        };
        let result = if done {
            // SAFETY: callers provide the actual command-semantic source
            // scope; Native retains that borrowed scope and invokes current
            // original PCI for each scalar/DMA effect on these retained rings.
            // Control bounds the payload and checks successful exact DONE plus
            // independent RP consumption; no RFK report is substituted.
            unsafe { self.control.send_done(&mut port, command, payload, 1000) }
        } else {
            // SAFETY: same actual original command/current-source contract
            // and retained native rings. Control bounds the payload and binds
            // any requested RFK report to this exact command; source commands
            // without ACK keep their flags. Failure poisons and retains DMA.
            unsafe { self.control.send(&mut port, command, payload, expected) }
        };
        if result.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result
    }
    pub(in crate::rtw89) fn await_rfk_report(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        kind: crate::rtw89::rfk::be_rfk::ReportKind,
        timeout_ms: u64,
    ) -> Result<crate::rtw89::rfk::be_rfk::Report, crate::rtw89::be_control::Error> {
        self.await_rfk_report_with(region, cancel, kind, timeout_ms, None)
    }
    pub(in crate::rtw89) fn await_rfk_report_qualified(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        kind: crate::rtw89::rfk::be_rfk::ReportKind,
        timeout_ms: u64,
        grant: &crate::rtw89::be_qualification::Partial,
    ) -> Result<crate::rtw89::rfk::be_rfk::Report, crate::rtw89::be_control::Error> {
        self.await_rfk_report_with(
            region,
            cancel,
            kind,
            timeout_ms,
            Some(crate::rtw89::be_qualification::Grant::Partial(grant)),
        )
    }
    pub(in crate::rtw89) fn await_rfk_report_scoped(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        kind: crate::rtw89::rfk::be_rfk::ReportKind,
        timeout_ms: u64,
        grant: crate::rtw89::be_qualification::Grant<'_>,
    ) -> Result<crate::rtw89::rfk::be_rfk::Report, crate::rtw89::be_control::Error> {
        self.await_rfk_report_with(region, cancel, kind, timeout_ms, Some(grant))
    }
    fn await_rfk_report_with(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        kind: crate::rtw89::rfk::be_rfk::ReportKind,
        timeout_ms: u64,
        grant: Option<crate::rtw89::be_qualification::Grant<'_>>,
    ) -> Result<crate::rtw89::rfk::be_rfk::Report, crate::rtw89::be_control::Error> {
        if !self.control_ready() {
            return Err(crate::rtw89::be_control::Error::State);
        }
        // SAFETY: same retained stages/original mappings as send_h2c, no
        // competing producer; pending identity is owned inside self.control.
        let native = unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let native = if let Some(grant) = grant {
            native.qualify_scope(grant)
        } else {
            native
        };
        let mut port = ControlPort {
            owner: &mut self.dma,
            io: native,
        };
        let result = self.control.await_report(&mut port, kind, timeout_ms);
        if result.is_err() || self.control.state() == crate::rtw89::be_control::State::Failed {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result
    }
    pub(in crate::rtw89) fn scheduler(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        resume: Option<u32>,
    ) -> Result<u32, checked::Error> {
        self.scheduler_with(region, cancel, resume, None)
    }
    pub(in crate::rtw89) fn scheduler_qualified(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        resume: Option<u32>,
        grant: &crate::rtw89::be_qualification::Partial,
    ) -> Result<u32, checked::Error> {
        self.scheduler_with(
            region,
            cancel,
            resume,
            Some(crate::rtw89::be_qualification::Grant::Partial(grant)),
        )
    }
    pub(in crate::rtw89) fn scheduler_scoped(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        resume: Option<u32>,
        grant: crate::rtw89::be_qualification::Grant<'_>,
    ) -> Result<u32, checked::Error> {
        self.scheduler_with(region, cancel, resume, Some(grant))
    }
    fn scheduler_with(
        &mut self,
        region: &narf_bus::MmioRegion,
        cancel: &core::sync::atomic::AtomicBool,
        resume: Option<u32>,
        grant: Option<crate::rtw89::be_qualification::Grant<'_>>,
    ) -> Result<u32, checked::Error> {
        if !self.control_ready() {
            return Err(checked::Error::State);
        }
        // SAFETY: original complete native closed stages/PHY receipt, all DMA
        // owned, exclusive scheduler operation and no competing producer.
        let native = unsafe { checked::Native::new(region, &self.authority) }.cancel_with(cancel);
        let native = if let Some(grant) = grant {
            native.qualify_scope(grant)
        } else {
            native
        };
        let mut port = MailboxPort {
            owner: &mut self.dma,
            io: native,
        };
        let result = if let Some(saved) = resume {
            self.scheduler.resume(&mut port, saved).map(|()| saved)
        } else {
            self.scheduler.pause(&mut port)
        };
        if result.is_err() {
            self.dma.poison();
            self.cold.poison(cold::Error::Terminal);
        }
        result.map_err(checked::Error::from)
    }
}
struct ControlPort<'a, 'b> {
    owner: &'a mut checked::Owner<DmaBuffer>,
    io: checked::Native<'b>,
}
impl crate::rtw89::be_control::Interface for ControlPort<'_, '_> {
    fn active(&mut self) -> Result<(), crate::rtw89::power::Error> {
        self.owner.dma_current(&mut self.io).map_err(control_error)
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<(), crate::rtw89::power::Error> {
        let mut packet = narf_io::alloc_coherent_masked(
            bytes.len(),
            narf_lib::id::DomainId::DRIVER_0,
            crate::rtw89::tx_8922a::BUFFER_DMA_MASK,
        )
        .map_err(|_| crate::rtw89::power::Error::Access)?;
        packet.as_mut_slice().copy_from_slice(bytes); // fresh unpublished owned allocation
        self.io
            .submit_command(self.owner, packet)
            .map(|_| ())
            .map_err(control_error)
    }
    fn consumed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.owner.reclaim(&mut self.io).map_err(control_error)?;
        Ok(self.owner.held().1 == 0)
    }
    fn receive(&mut self) -> Result<checked::FirmwareRx, crate::rtw89::power::Error> {
        self.io
            .receive_firmware(self.owner, 256)
            .map_err(control_error)
    }
}
fn control_error(error: checked::Error) -> crate::rtw89::power::Error {
    match error {
        checked::Error::Io(error) => error,
        _ => crate::rtw89::power::Error::Access,
    }
}
/// Direct disjoint original-owner borrows, no Rtw89Device/source callbacks.
struct MailboxPort<'a, 'b> {
    owner: &'a mut checked::Owner<DmaBuffer>,
    io: checked::Native<'b>,
}
impl crate::rtw89::be_mailbox::Interface for MailboxPort<'_, '_> {
    fn active(&mut self) -> Result<(), crate::rtw89::power::Error> {
        self.owner
            .dma_current(&mut self.io)
            .map_err(|error| match error {
                checked::Error::Io(error) => error,
                _ => crate::rtw89::power::Error::Access,
            })
    }
}
impl crate::rtw89::be_scheduler::Interface for MailboxPort<'_, '_> {
    fn active(&mut self) -> Result<(), crate::rtw89::power::Error> {
        crate::rtw89::be_mailbox::Interface::active(self)
    }
}
impl cold::Regs for MailboxPort<'_, '_> {
    fn binding(&self) -> cold::Binding {
        self.io.binding()
    }
    fn current(&mut self) -> Result<(), crate::rtw89::power::Error> {
        self.io.current()
    }
    fn read8(&mut self, a: u32) -> Result<u8, crate::rtw89::power::Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, crate::rtw89::power::Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, crate::rtw89::power::Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), crate::rtw89::power::Error> {
        self.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), crate::rtw89::power::Error> {
        self.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), crate::rtw89::power::Error> {
        self.io.write32(a, v)
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, t: u64) -> Result<(), crate::rtw89::power::Error> {
        self.io.poll32(a, m, v, t)
    }
    fn delay_us(&mut self, u: u64) -> Result<(), crate::rtw89::power::Error> {
        self.io.delay_us(u)
    }
}
