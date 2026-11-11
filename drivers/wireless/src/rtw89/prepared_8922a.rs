// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Prepared 8922A owner — chip-row step 5 (Prepared wiring).
//!
//! The production composition point for the RTL8922A pieces built in
//! steps 1–4: the chip container (`chip_8922a`), the BE factory
//! identity (`efuse_be::BeFactory`), the station owner
//! (`station_8922a`), the BE DMA control sequence + ring programming
//! (`dma_be`, `dma_8922a`), the BE data + H2C transport (`tx_8922a`),
//! the G7 CCTL / RA-v1 builders (`cctl_g7`, `ra_mask`), and the EHT
//! cap maps (`eht`). `pci::bring_up` constructs this owner for a
//! probed 8922A device and retains it on `Rtw89Device`; nothing here
//! runs before probe admission.
//!
//! Linux order composed here (`pci_be.c:493`, `pci.c:1884` —
//! `rtw89_pci_ops_mac_pre_init_be` / `rtw89_pci_ops_reset`,
//! torvalds/linux @ 05441d6):
//!
//! 1. `pre_init_dma_before_reset` — wpdma off, trxdma off,
//!    `clr_idx_all`, idle polls, `mode_op` (8922AE tuning).
//! 2. The caller's MAC reset (NOT owned here: debounce, LDO-low-
//!    power, PCIe-setting, SER-setting, and the full
//!    `rtw8922a_pwr_on_func` tail live with the future mac_pre_init
//!    owner).
//! 3. `pre_init_dma_after_reset` — `rst_bdram_set`, bound poll,
//!    `txdma_ch(false)`, `txdma_fw_ch(true)`, trxdma on.
//! 4. `program_rings` — `rtw89_pci_reset_trx_rings`: NUM/DESA per
//!    ring, RX doorbell seed `len - 1`, `init_wp_16sel`.
//! 5. `post_init_dma` — the `dma_be::post_init_dma` tail
//!    (trxdma RX on, wpdma on, `txdma_ch(true)`,
//!    `txdma_fw_ch(true)`, `configure_mit`).
//! 6. `admit_station` — MACID, G7 default + assoc CCTL, BA-CAM map,
//!    EHT facet from the chip default (`EhtStation::new_8922ae`),
//!    and, on 6 GHz, the 6 GHz power program
//!    (`station_8922a::SixGhzAdmission` → `SixGhzProgram`:
//!    client power type + regd.c TPE constraint, 20 MHz only).
//! 7. `prepare_data` / `kick_data` (CH0..11) and `prepare_h2c` /
//!    `kick_h2c` (CH12), then `observe_data_rp` /
//!    `observe_data_report` for completions.
//!
//! What this owner deliberately does NOT own (later steps):
//! - MLO multi-link, legacy-mode admission.
//! - The register-level 6 GHz TX-power program
//!   (`rtw8922a_set_txpwr`: by-rate / limit / limit-RU pages on
//!   BE registers, shape, diff, ref, SAR-diff) and the wide-6 GHz
//!   TPE rearrange (40/80/160 MHz): admission records the
//!   20 MHz primary-subchannel TPE constraint (`SixGhzProgram`)
//!   the program consumes, but nothing here writes power
//!   registers.
//! - Firmware download (`prepared::load` selects the image; the
//!   download plan + secure loader are a separate lane).
//!
//! What this owner DOES own since the remainder lane:
//! - FWCMD header framing for H2C bodies
//!   (`fwcmd_8922a::frame_h2c`, type/category/class/func/
//!   sequence, via the shared `H2cSeqAllocator`): the station
//!   owner builds CCTL/BA-CAM/RA bodies, this owner frames them
//!   and records the identity per retained buffer
//!   (`retain_h2c`), and the C2H completion path releases a
//!   buffer on its matching ack (`release_h2c_by_ack`, surfaced
//!   in `Outcome::h2c_released`).
//! - The TXWD_INFO v2 fill (`prepare_data_with_info`):
//!   `txrx_be::fill_txwd_info_v2` output appended after the v2
//!   body with BODY0 bit 22 set. Plain `prepare_data` still
//!   clears the bit (no info block).
//! - The mac_pre_init owner (`mac_pre_init_8922a`): the MAC
//!   reset (`reset_pwr_state`) + full `pwr_on_func` tail run in
//!   `pci::bring_up` between the power-on head and the EFUSE
//!   factory read — Linux `rtw89_chip_info_setup` order
//!   (`core.c:7388..7409`: chip-ver read, `rtw89_mac_pwr_on`,
//!   then `rtw89_chip_efuse_info_setup`) — and the retained
//!   chip version (`record_chip_ver` / `chip_ver`).
//!
//! DMA retention contract: a submitted data frame's header + frame
//! `DmaBuffer`s are retained here (keyed by their DMA addresses)
//! until the matching RPQ release retires them — the TXBD-consumption
//! half (`observe_data_rp`) alone never frees. A `kick` failure
//! after a successful `prepare` leaks that slot's reservation and
//! its retained buffers (the slot is reserved but unpublished, so no
//! RPQ will ever arrive for it); the owner stays usable for the
//! remaining slots.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::DmaBuffer;

use super::bacam_v1;
use super::completion_8922a;
use super::dma::{TxBd, DEFAULT_RXBD_NUM, TXCH_NUM};
use super::dma_8922a;
use super::dma_be::{self, Regs};
use super::efuse_be::BeFactory;
use super::eht::{EhtOperation, EhtStation, EHT_8922A};
use super::fwcmd_8922a::{self, FramedH2c, H2cCmd, Released};
use super::h2c::H2cSeqAllocator;
use super::irq_be::BindingBe;
use super::mac_pre_init_8922a::{self, HalChipVer};
use super::power;
use super::ra_mask::{self, StationCaps};
use super::rx_packet::Ack;
use super::station_8922a::{self, Request, Station};
use super::tx_8922a::{self, H2cPrepared, PrepareArgs, Prepared, Retained, TXWD_INFO_SIZE};
use super::tx_transport::Completion;

/// Maximum BE data-header bytes: 32-byte TXWD_BODY_V2 + 32-byte
/// TXWD_INFO_V2 + 8-byte WP info + at most 10 v1 address-info
/// entries × 6 bytes. A submitter allocates this much header DMA
/// before `prepare_data` / `prepare_data_with_info`, then copies
/// only the built length (`Prepared::header.len()`).
pub(super) const MAX_HEADER_BYTES: usize = 132;

/// `RTW89_PCI_MULTITAG` (`pci.h:1131`): consumed CH12 buffers the
/// release path keeps back before freeing.
pub(super) const FWCMD_MULTITAG: usize = 8;

/// Prepared-owner failures. Every variant is a refusal; a refused
/// call leaves no partially-programmed artifact behind except the
/// documented kick-after-prepare slot leak (see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// BE DMA ring programming / sequencing failure.
    Dma(dma_8922a::Error),
    /// BE data / H2C transport failure.
    Transport(tx_8922a::Error),
    /// Station admission / BA-CAM failure.
    Station(station_8922a::Error),
    /// RA mask computation / encoding failure.
    Ra(ra_mask::Error),
    /// The fail-closed EHT facet (`EhtStation::new_8922ae`) could
    /// not be built, so no station can be admitted.
    EhtUnavailable,
    /// Rings not programmed yet (`program_rings` not called, or
    /// `stop_dma` ran since).
    NotProgrammed,
    /// No admitted station owns this MACID.
    NoStation,
    /// Out of DMA-coherent memory (ring allocation, header/frame
    /// allocation, or transport-owner construction).
    NoMemory,
    /// This device has no 8922A Prepared owner (not an 8922A probe).
    NoOwner,
    /// Capability invoke failed (authority lapsed).
    Authority,
    /// Interrupt bind failed (no free vector, MSI programming
    /// failed). `Unsupported` cannot occur for BE: the v2 mask is
    /// infallible, unlike the AX `Mask::config` refusal.
    Irq(super::irq::Error),
    /// C2H completion worker failure (ring desync, fatal
    /// firmware state, bad budget, unprogrammed rings).
    Completion(completion_8922a::Error),
    /// `irq_start` with a binding already installed.
    AlreadyArmed,
    /// MMIO failure during an interrupt start/service/rearm step.
    /// Unreachable through `MmioRegs` (infallible); reachable only
    /// through a failing [`super::irq::Regs`] in tests.
    IrqIo(power::Error),
}

impl From<dma_8922a::Error> for Error {
    fn from(error: dma_8922a::Error) -> Self {
        Error::Dma(error)
    }
}

impl From<tx_8922a::Error> for Error {
    fn from(error: tx_8922a::Error) -> Self {
        Error::Transport(error)
    }
}

impl From<station_8922a::Error> for Error {
    fn from(error: station_8922a::Error) -> Self {
        Error::Station(error)
    }
}

impl From<ra_mask::Error> for Error {
    fn from(error: ra_mask::Error) -> Self {
        Error::Ra(error)
    }
}

/// BAR2-backed [`Regs`] for the production path: the `pci::bring_up`
/// owner passes its mapped BAR2 here. The caller owns the BAR2
/// window exclusively; every address is a BAR2 offset.
pub(super) struct MmioRegs<'a>(pub(super) &'a MmioRegion);

impl Regs for MmioRegs<'_> {
    fn read32(&mut self, address: u32) -> u32 {
        // SAFETY: caller's owned-BAR2 contract; `address` is a
        // BAR2 offset inside the mapped window.
        unsafe { self.0.read32(address as u64) }
    }

    fn write32(&mut self, address: u32, value: u32) {
        // SAFETY: same.
        unsafe { self.0.write32(address as u64, value) }
    }

    fn write16(&mut self, address: u32, value: u16) {
        // SAFETY: same.
        unsafe { self.0.write16(address as u64, value) }
    }
}

/// [`super::irq::Regs`] over the same BAR2 window, for the v2
/// interrupt mask/enable/disable/recognize programs. Infallible:
/// BAR2 MMIO cannot fail, so every op reports `Ok`.
impl super::irq::Regs for MmioRegs<'_> {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        Ok(<Self as Regs>::read32(self, address))
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        <Self as Regs>::write32(self, address, value);
        Ok(())
    }
}

/// [`mac_pre_init_8922a::Regs`] over the same BAR2 window, for
/// the MAC reset / pwr_on tail / chip-version read. Infallible:
/// BAR2 MMIO cannot fail; the tail's polls are bounded
/// attempt-count loops over these reads.
impl mac_pre_init_8922a::Regs for MmioRegs<'_> {
    fn read8(&mut self, address: u32) -> u8 {
        // SAFETY: caller's owned-BAR2 contract; `address` is a
        // BAR2 offset inside the mapped window.
        unsafe { self.0.read8(address as u64) }
    }

    fn read32(&mut self, address: u32) -> u32 {
        <Self as Regs>::read32(self, address)
    }

    fn write8(&mut self, address: u32, value: u8) {
        // SAFETY: same.
        unsafe { self.0.write8(address as u64, value) }
    }

    fn write32(&mut self, address: u32, value: u32) {
        <Self as Regs>::write32(self, address, value)
    }
}

/// [`super::fwdl_be::Regs`] over the same BAR2 window, for the BE
/// firmware-download preparation and WCPU control. Infallible like the
/// other ports; `R_BE_BOOT_REASON` needs the 16-bit accessors.
impl super::fwdl_be::Regs for MmioRegs<'_> {
    fn read16(&mut self, address: u32) -> u16 {
        // SAFETY: caller's owned-BAR2 contract; `address` is a
        // BAR2 offset inside the mapped window.
        unsafe { self.0.read16(address as u64) }
    }

    fn read32(&mut self, address: u32) -> u32 {
        <Self as Regs>::read32(self, address)
    }

    fn write16(&mut self, address: u32, value: u16) {
        // SAFETY: same.
        unsafe { self.0.write16(address as u64, value) }
    }

    fn write32(&mut self, address: u32, value: u32) {
        <Self as Regs>::write32(self, address, value)
    }
}

/// The prepared 8922A device: factory identity, admitted stations,
/// BE data + H2C transport owners, and ring state. Constructed by
/// `pci::bring_up` for a probed 8922A device and retained on
/// `Rtw89Device`; the transport sequence runs when the mac_pre_init
/// owner drives it (see module docs).
pub(crate) struct Prepared8922a {
    factory: BeFactory,
    chip_version: u8,
    pool: station_8922a::MacIdPool,
    stations: Vec<Station>,
    data: tx_8922a::DataTx,
    h2c: tx_8922a::H2cTx,
    rings_programmed: bool,
    /// Installed v2 interrupt binding, if `irq_start` armed one.
    /// `None` until then: no MSI is delivered and `irq_service`
    /// reports nothing (polled mode).
    irq: Option<BindingBe>,
    /// Submitted data frames' DMA buffers, keyed by
    /// (header DMA, frame DMA); freed on RPQ release.
    data_retained: Vec<(u64, u64, DmaBuffer, DmaBuffer)>,
    /// Firmware-command sequence allocator shared by every
    /// framed H2C command this owner submits.
    h2c_seq: H2cSeqAllocator,
    /// Submitted H2C buffers, each with the FWCMD identity the
    /// firmware echoes in its C2H ack. A buffer leaves this list
    /// only on its ack (see `release_h2c_by_ack`).
    h2c_retained: Vec<(FramedH2c, DmaBuffer)>,
    /// Every kicked CH12 buffer in TXBD order (Linux
    /// `rtwpci->h2c_queue`). `Some` owns a buffer freed on TXBD
    /// consumption (FWDL header / section packets — no firmware
    /// ack exists for them); `None` marks an ack-retained H2C
    /// whose buffer lives in `h2c_retained`.
    fwcmd_in_flight: VecDeque<Option<DmaBuffer>>,
    /// Consumed CH12 buffers still held back by the multi-tag
    /// window (Linux `rtwpci->h2c_release_queue`).
    fwcmd_release: VecDeque<DmaBuffer>,
    /// Core chip version read during the MAC pre-init
    /// (`mac_pre_init_8922a::read_chip_ver`). `None` until the
    /// pre-init runs — the pci owner records it, not the probe
    /// path, so the field is set exactly once per bring-up.
    chip_ver: Option<HalChipVer>,
    /// C2H completion worker state (RPQ/RXQ host write pointers
    /// + RXQ assembly). Rebuilt by `program_rings` at the
    ///   programmed depths, reset by `stop_dma`.
    completion: completion_8922a::Worker,
}

impl Prepared8922a {
    /// Empty owner for one probed 8922A device: twelve 256-deep data
    /// queues (ACH0..7, CH8..11) and one 256-deep CH12 H2C ring
    /// (Linux allocates `RTW89_PCI_TXBD_NUM_MAX` = 256 for every TX
    /// channel, `dma_8922a::TXBD_NUM_MAX`). No station admitted, no
    /// rings programmed.
    pub(super) fn new(factory: BeFactory, chip_version: u8) -> Result<Self, Error> {
        Ok(Self {
            factory,
            chip_version,
            pool: station_8922a::MacIdPool::new(),
            stations: Vec::new(),
            data: tx_8922a::DataTx::new()?,
            h2c: tx_8922a::H2cTx::new(tx_8922a::DATA_RING_DEPTH)?,
            rings_programmed: false,
            irq: None,
            data_retained: Vec::new(),
            h2c_seq: H2cSeqAllocator::new(),
            h2c_retained: Vec::new(),
            fwcmd_in_flight: VecDeque::new(),
            fwcmd_release: VecDeque::new(),
            chip_ver: None,
            completion: completion_8922a::Worker::new(DEFAULT_RXBD_NUM, DEFAULT_RXBD_NUM)
                .map_err(Error::Completion)?,
        })
    }

    /// Factory identity read at probe (MAC, RFE, crystal, country,
    /// PHY-cap window, cut, thermal K).
    pub(super) fn factory(&self) -> &BeFactory {
        &self.factory
    }

    /// Fuse-selected secure-download state for this device: the BE
    /// secure fuses read at probe (`efuse_be::read_secure`), in the
    /// form `DownloadPlan::new` consumes. The firmware-download
    /// owner builds the plan from the registry image + these fuses +
    /// `Blacklist::upstream(Rtl8922A)`; until that owner exists no
    /// image is trusted or downloaded on this path.
    pub(super) fn secure_fuses(&self) -> super::secure::Fuses {
        super::secure::Fuses::from_be(super::mac::ChipId::Rtl8922A, self.factory.secure)
    }

    /// Own MAC, from the BE factory identity.
    pub(super) fn mac(&self) -> [u8; 6] {
        self.factory.mac
    }

    /// Chip-version field from `R_AX_SYS_CFG1` (Linux `cv`, read
    /// for every generation — `core.c:7134`).
    pub(super) fn chip_version(&self) -> u8 {
        self.chip_version
    }

    /// EHT operation profile for this chip (`eht::EHT_8922A`):
    /// 320 MHz widths programmable, max MPDU 7991, MCS/NSS maps
    /// from `eht_cap` — not from the 160 MHz chip bandwidth mask.
    pub(super) fn eht_profile(&self) -> EhtOperation {
        EHT_8922A
    }

    /// True once `program_rings` has run and `stop_dma` has not.
    pub(super) fn rings_programmed(&self) -> bool {
        self.rings_programmed
    }

    /// True once `irq_start` has armed an interrupt binding.
    pub(super) fn irq_armed(&self) -> bool {
        self.irq.is_some()
    }

    /// `rtw89_pci_request_irq` + `rtw89_pci_ops_start` for the
    /// admitted 8922A device: bind one MSI vector to `line` and
    /// enable the v2 interrupt mask. Returns the CPU vector.
    /// Refused when a binding is already installed or the rings
    /// are not programmed yet — the future mac_pre_init/start
    /// owner calls this after `program_rings` + `post_init_dma`,
    /// so completions can only fire for rings that exist. A
    /// bind failure leaves no binding behind; a mask-enable
    /// failure releases the just-bound vector again.
    pub(super) fn irq_start(
        &mut self,
        device: &BusDevice,
        authority: &Cap<BusDeviceCap, Write>,
        line: &Arc<super::irq::Line>,
        regs: &mut impl super::irq::Regs,
    ) -> Result<u8, Error> {
        if self.irq.is_some() {
            return Err(Error::AlreadyArmed);
        }
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        let binding = BindingBe::bind(device, authority, line).map_err(Error::Irq)?;
        if let Err(error) = binding.start(&mut *regs) {
            binding.release(&mut *regs, authority);
            return Err(Error::IrqIo(error));
        }
        let vector = binding.vector();
        self.irq = Some(binding);
        Ok(vector)
    }

    /// Worker half of the Linux hard/threaded handlers: mask, then
    /// recognize and acknowledge enabled sources. Without a binding
    /// the worker is in polled mode and nothing is reported. The
    /// classified events are the C2H lane's input: `rpq` / `rx`
    /// schedule the RPQ / RXQ drain, `rx_unavailable` re-arms RX,
    /// and a fatal event ends the current run.
    pub(super) fn irq_service(
        &mut self,
        regs: &mut impl super::irq::Regs,
    ) -> Result<super::irq::Events, Error> {
        let Some(binding) = self.irq.as_ref() else {
            return Ok(super::irq::Events::default());
        };
        binding
            .service(regs)
            .map(|isrs| isrs.events())
            .map_err(Error::IrqIo)
    }

    /// NAPI-completion re-enable after RPQ/RXQ were drained.
    /// Without a binding this is a no-op.
    pub(super) fn irq_rearm(&mut self, regs: &mut impl super::irq::Regs) -> Result<(), Error> {
        let Some(binding) = self.irq.as_ref() else {
            return Ok(());
        };
        binding.rearm(regs).map_err(Error::IrqIo)
    }

    /// C2H completion worker (chip-row step 7): drain the RPQ
    /// then RXQ rings for the `events` `irq_service` classified,
    /// in Linux `rtw89_pci_napi_poll` order, over the
    /// caller-supplied probe-allocated RX buffers (`rxq` /
    /// `rpq`, exactly the programmed depths each). The caller
    /// syncs each buffer for the CPU before the call and back
    /// for the device after; the worker clears consumed
    /// RXBD-info headers itself. TX completions free their
    /// retained DMA buffers here; WIFI frames arrive admitted
    /// for a retained station only. `Outcome::rearm` tells the
    /// caller to run `irq_rearm` when work done is under
    /// budget. Refused unless the rings are programmed; a
    /// fatal event (`halt_c2h` / watchdog) drains nothing.
    pub(super) fn complete(
        &mut self,
        regs: &mut impl Regs,
        events: super::irq::Events,
        rxq: &mut [&mut [u8]],
        rpq: &mut [&mut [u8]],
        budget: usize,
    ) -> Result<completion_8922a::Outcome, Error> {
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        if events.fatal() {
            return Err(Error::Completion(completion_8922a::Error::Halted));
        }
        if budget == 0 || budget > 256 {
            return Err(Error::Completion(completion_8922a::Error::Budget));
        }
        let mut outcome = completion_8922a::Outcome {
            rx_unavailable: events.rx_unavailable,
            ..Default::default()
        };
        let mut remaining = budget;
        if events.rpq {
            let rpq_out = self
                .completion
                .drain_rpq(regs, rpq, remaining, &mut self.data)
                .map_err(Error::Completion)?;
            outcome.dropped += rpq_out.dropped_records + rpq_out.dropped_buffers;
            for done in rpq_out.completions {
                let receipt = completion_8922a::TxReceipt {
                    header_dma: done.resource.header_dma,
                    frame_dma: done.resource.frame_dma,
                    status: done.status,
                };
                self.release_data(receipt.header_dma, receipt.frame_dma);
                outcome.tx.push(receipt);
            }
            remaining = remaining.saturating_sub(rpq_out.work);
            outcome.work_done += rpq_out.work;
        }
        if events.rx {
            let admitted: Vec<u8> = self.stations.iter().map(|station| station.macid).collect();
            let rxq_out = self
                .completion
                .drain_rxq(regs, rxq, remaining, &admitted)
                .map_err(Error::Completion)?;
            outcome.dropped += rxq_out.dropped;
            outcome.frames.extend(rxq_out.frames);
            for routed in &rxq_out.c2h {
                if let Some(ack) = &routed.ack {
                    if let Some(released) = self.release_h2c_by_ack(ack) {
                        outcome.h2c_released.push(released);
                    }
                }
            }
            outcome.c2h.extend(rxq_out.c2h);
            outcome.ppdu.extend(rxq_out.ppdu);
            outcome.work_done += rxq_out.work;
        }
        outcome.rearm = outcome.work_done < budget;
        Ok(outcome)
    }

    /// `rtw89_pci_ops_stop` + `rtw89_pci_free_irq`: HIMR off, MSI
    /// off, then drain and return the vector (or quarantine it when
    /// MSI cannot be proven disabled). Idempotent: releasing an
    /// unarmed owner is a no-op.
    pub(super) fn irq_release(
        &mut self,
        regs: &mut impl super::irq::Regs,
        authority: &Cap<BusDeviceCap, Write>,
    ) {
        if let Some(binding) = self.irq.take() {
            binding.release(regs, authority);
        }
    }

    /// Pre-init DMA, first half (`pci_be.c:493`, before the caller's
    /// MAC reset). See [`dma_8922a::pre_init_dma_before_reset`].
    pub(super) fn pre_init_dma_before_reset(
        &self,
        regs: &mut impl Regs,
        rxq_len: u16,
        rpq_len: u16,
    ) -> Result<(), Error> {
        dma_8922a::pre_init_dma_before_reset(regs, rxq_len, rpq_len).map_err(Error::Dma)
    }

    /// Pre-init DMA, second half (`pci_be.c:493`, after the caller's
    /// MAC reset). See [`dma_8922a::pre_init_dma_after_reset`].
    pub(super) fn pre_init_dma_after_reset(&self, regs: &mut impl Regs) -> Result<(), Error> {
        dma_8922a::pre_init_dma_after_reset(regs).map_err(Error::Dma)
    }

    /// Post-init DMA tail (`dma_be::post_init_dma`): trxdma RX on,
    /// wpdma on, `txdma_ch(true)`, `txdma_fw_ch(true)`,
    /// `configure_mit`.
    pub(super) fn post_init_dma(&self, regs: &mut impl Regs) {
        dma_be::post_init_dma(regs);
    }

    /// Program all 13 TX rings then both RX rings, then the
    /// WP-select block (`rtw89_pci_reset_trx_rings`, `pci.c:1776`).
    /// Marks the rings programmed; a later `stop_dma` clears the
    /// mark. `tx_phys` / `rx_phys` are the probe-allocated ring
    /// bases; `tx_len` / `rx_len` are the ring depths (Linux maxima
    /// 256 unless the caller deliberately sizes smaller). The
    /// completion worker is rebuilt at the programmed RX depths
    /// before any register is written, so a bad depth refuses
    /// without touching hardware.
    pub(super) fn program_rings(
        &mut self,
        regs: &mut impl Regs,
        tx_phys: &[u64; TXCH_NUM],
        rx_phys: &[u64; 2],
        tx_len: u16,
        rx_len: u16,
    ) -> Result<(), Error> {
        let worker = completion_8922a::Worker::new(rx_len, rx_len).map_err(Error::Completion)?;
        dma_8922a::reset_trx_rings(regs, tx_phys, rx_phys, tx_len, rx_len)?;
        // `rtw89_pci_ops_reset` (pci.c:1877): after the ring reset
        // every queued CH12 buffer is released (`release_all`).
        self.h2c.reset();
        self.release_fwcmd(self.fwcmd_in_flight.len(), true);
        self.completion = worker;
        self.rings_programmed = true;
        Ok(())
    }

    /// LV1-reset stop half (`pci_be.c:669`): `ctrl_dma_all(false)`
    /// + IO-idle poll. Clears the programmed mark.
    pub(super) fn stop_dma(&mut self, regs: &mut impl Regs) -> Result<(), Error> {
        let result = dma_8922a::stop_dma(regs).map_err(Error::Dma);
        if result.is_ok() {
            self.rings_programmed = false;
            self.completion.reset();
        }
        result
    }

    /// Admit one EHT station with the chip-default facet
    /// (`EhtStation::new_8922ae`: advertised EHT caps from
    /// `eht_cap`, TX EHT overrides off). Returns the allocated
    /// MACID. The station record — its G7 default + assoc CCTL
    /// tables and BA-CAM map — is retained until
    /// [`Self::release_station`].
    pub(super) fn admit_station(&mut self, req: &Request) -> Result<u8, Error> {
        let facet = EhtStation::new_8922ae().ok_or(Error::EhtUnavailable)?;
        let station = station_8922a::admit(&self.factory, facet, &mut self.pool, req)?;
        let macid = station.macid;
        self.stations.push(station);
        Ok(macid)
    }

    /// Admitted station by MACID, if any.
    pub(super) fn station(&self, macid: u8) -> Option<&Station> {
        self.stations.iter().find(|station| station.macid == macid)
    }

    /// Release a station: its MACID returns to the pool and its
    /// record is dropped. Idempotent: releasing an unknown MACID
    /// is a no-op.
    pub(super) fn release_station(&mut self, macid: u8) {
        if let Some(index) = self
            .stations
            .iter()
            .position(|station| station.macid == macid)
        {
            let station = self.stations.remove(index);
            station.release_macid(&mut self.pool);
        }
    }

    /// EHT contribution to the BE TXWD_INFO block for one admitted
    /// station: (info4 bits, info7 bits). `None` when the MACID is
    /// not admitted or the facet cannot encode its NLTF value.
    pub(super) fn txwd_info_eht(&self, macid: u8) -> Option<(u32, u32)> {
        self.station(macid)?.txwd_info_eht()
    }

    /// Fill the BE RA v1 command for one admitted station
    /// (`ra_mask::build`): fresh station update (`upd` flags
    /// false), single-link pass-1 PHY index 0 (Linux
    /// `phy.c:498`: `ra->band_num = rtwvif_link->phy_idx`).
    pub(super) fn station_ra(&self, macid: u8, caps: &StationCaps) -> Result<[u32; 6], Error> {
        if self.station(macid).is_none() {
            return Err(Error::NoStation);
        }
        ra_mask::build(caps, macid, 0, false, false).map_err(Error::Ra)
    }

    /// Acquire a BA-CAM bitmap slot for one admitted station's
    /// BlockAck session (`BaCam::acquire`); the index feeds
    /// [`Self::ba_h2c`].
    pub(super) fn acquire_bacam(&mut self, macid: u8, tid: u8) -> Result<usize, Error> {
        let station = self
            .stations
            .iter_mut()
            .find(|station| station.macid == macid)
            .ok_or(Error::NoStation)?;
        station
            .bacam
            .acquire(tid)
            .map_err(|error| Error::Station(station_8922a::Error::BaCam(error)))
    }

    /// Build a BA-CAM v1 H2C body for one admitted station's
    /// BlockAck session. `bitmap_idx` must come from
    /// [`Self::acquire_bacam`].
    pub(super) fn ba_h2c(
        &self,
        macid: u8,
        tid: u32,
        bmap_size: u32,
        ssn: u32,
        bitmap_idx: u32,
    ) -> Result<bacam_v1::BaCamH2c, Error> {
        let station = self.station(macid).ok_or(Error::NoStation)?;
        station
            .ba_h2c(tid, bmap_size, ssn, bitmap_idx)
            .map_err(Error::Station)
    }

    /// Release a BA-CAM bitmap slot acquired via
    /// [`Self::acquire_bacam`].
    pub(super) fn release_bacam(&mut self, macid: u8, idx: usize) -> Result<(), Error> {
        let station = self
            .stations
            .iter_mut()
            .find(|station| station.macid == macid)
            .ok_or(Error::NoStation)?;
        station
            .bacam
            .release(idx)
            .map_err(|error| Error::Station(station_8922a::Error::BaCam(error)))
    }

    /// Reserve a data slot, build the header, and fill the TXBD —
    /// without publishing or ringing the doorbell (see
    /// [`tx_8922a::DataTx::prepare`]). Refused unless the rings
    /// are programmed and `args.mac_id` is an admitted station.
    /// No TXWD_INFO block follows (BODY0 bit 22 cleared).
    pub(super) fn prepare_data(&mut self, args: PrepareArgs<'_>) -> Result<Prepared, Error> {
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        if self.station(args.mac_id).is_none() {
            return Err(Error::NoStation);
        }
        self.data.prepare(args).map_err(Error::Transport)
    }

    /// Like [`Self::prepare_data`], but appends the caller-filled
    /// 32-byte TXWD_INFO v2 block (`txrx_be::fill_txwd_info_v2`
    /// output) after the v2 body and leaves BODY0 bit 22
    /// (WDINFO_EN) set.
    pub(super) fn prepare_data_with_info(
        &mut self,
        args: PrepareArgs<'_>,
        info: &[u8; TXWD_INFO_SIZE],
    ) -> Result<Prepared, Error> {
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        if self.station(args.mac_id).is_none() {
            return Err(Error::NoStation);
        }
        self.data
            .prepare_with_info(args, info)
            .map_err(Error::Transport)
    }

    /// Publish a prepared frame and ring its doorbell. The caller
    /// must have placed `prepared.header` into header DMA memory
    /// and synced it first. Returns the new host WP.
    pub(super) fn kick_data(
        &mut self,
        regs: &mut impl Regs,
        prepared: &Prepared,
    ) -> Result<u16, Error> {
        self.data.kick(regs, prepared).map_err(Error::Transport)
    }

    /// Apply a TX ring read-pointer update: retire every
    /// DMA-complete frame up to `rp`, returning their retained
    /// addresses. The caller frees them only after the matching
    /// RPQ release (see [`Self::observe_data_report`]).
    pub(super) fn observe_data_rp(
        &mut self,
        regs: &mut impl Regs,
        channel: u8,
    ) -> Result<Vec<Completion<Retained>>, Error> {
        self.data
            .observe_rp(regs, channel)
            .map_err(Error::Transport)
    }

    /// Apply one RPQ record (Linux's original 4-byte format):
    /// retire the matching frame once its TXBD consumption is
    /// also observed. Returns the completion only when both
    /// halves have arrived.
    pub(super) fn observe_data_report(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<Completion<Retained>>, Error> {
        self.data.observe_report(bytes).map_err(Error::Transport)
    }

    /// Fill the TXBD at the CH12 write pointer for one
    /// caller-framed H2C buffer — without advancing WP or ringing
    /// the doorbell. Refused unless the rings are programmed.
    pub(super) fn prepare_h2c(
        &mut self,
        bd: &mut [TxBd],
        buf_dma: u64,
        buf_len: usize,
    ) -> Result<H2cPrepared, Error> {
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        self.h2c
            .prepare_h2c(bd, buf_dma, buf_len)
            .map_err(Error::Transport)
    }

    /// Advance the CH12 WP past a prepared buffer and ring the
    /// CH12 doorbell. A stale or double kick is refused.
    pub(super) fn kick_h2c(
        &mut self,
        regs: &mut impl Regs,
        prepared: &H2cPrepared,
    ) -> Result<u16, Error> {
        self.h2c.kick_h2c(regs, prepared).map_err(Error::Transport)
    }

    /// Retain a submitted data frame's DMA buffers until RPQ
    /// release. Called by the submitter after a successful
    /// `prepare_data` (before `kick_data`); if `prepare_data`
    /// itself fails the buffers are dropped by the submitter and
    /// nothing is published.
    pub(super) fn retain_data(&mut self, header: DmaBuffer, frame: DmaBuffer) {
        let header_dma = header.dma_addr().raw();
        let frame_dma = frame.dma_addr().raw();
        self.data_retained
            .push((header_dma, frame_dma, header, frame));
    }

    /// Release a completed frame's retained DMA buffers (the
    /// `observe_data_report` completion's addresses). True when
    /// an entry matched; false means the addresses were never
    /// retained (or already released) — never an error.
    pub(super) fn release_data(&mut self, header_dma: u64, frame_dma: u64) -> bool {
        if let Some(index) = self
            .data_retained
            .iter()
            .position(|(header, frame, _, _)| *header == header_dma && *frame == frame_dma)
        {
            self.data_retained.remove(index);
            true
        } else {
            false
        }
    }

    /// Frame one H2C body with the FWCMD header
    /// (`fwcmd_8922a::frame_h2c`): 8-byte header + body into
    /// `out`, the sequence allocated from the shared allocator.
    /// Returns the command identity and the total wire length.
    /// Refused when `out` is too small or the payload cannot fit
    /// the 14-bit total-length field — never truncated. The
    /// caller places the framed bytes into H2C DMA memory, calls
    /// `prepare_h2c` + `kick_h2c`, then retains the buffer with
    /// `retain_h2c(framed, buf)`.
    pub(super) fn frame_h2c(
        &self,
        cmd: H2cCmd,
        payload: &[u8],
        rec_ack: bool,
        done_ack: bool,
        out: &mut [u8],
    ) -> Option<(FramedH2c, usize)> {
        fwcmd_8922a::frame_h2c(&self.h2c_seq, cmd, payload, rec_ack, done_ack, out)
    }

    /// Retain a submitted H2C buffer, keyed by the FWCMD
    /// identity `frame_h2c` returned, until the C2H completion
    /// path releases it on its matching ack
    /// (`release_h2c_by_ack`).
    pub(super) fn retain_h2c(&mut self, framed: FramedH2c, buf: DmaBuffer) {
        self.h2c_retained.push((framed, buf));
    }

    /// Record one just-prepared CH12 buffer in TXBD order (Linux
    /// `rtw89_pci_fwcmd_submit` queues the skb on `h2c_queue`).
    /// `Some(buf)` is freed once the chip consumes its TXBD (FWDL
    /// header + section packets); `None` stands for an H2C whose
    /// buffer `retain_h2c` keeps until its ack.
    pub(super) fn retain_fwcmd(&mut self, buf: Option<DmaBuffer>) {
        self.fwcmd_in_flight.push_back(buf);
    }

    /// `__rtw89_pci_check_and_reclaim_tx_fwcmd_resource`
    /// (`pci.c:1234`): observe the CH12 read pointer, move every
    /// consumed buffer to the release queue, free all but the
    /// last `RTW89_PCI_MULTITAG`, and return the free CH12 TXBD
    /// count. `rtw89_h2c_tx` refuses a submit when it is zero.
    pub(super) fn reclaim_fwcmd(&mut self, regs: &mut impl Regs) -> Result<u16, Error> {
        if !self.rings_programmed {
            return Err(Error::NotProgrammed);
        }
        let cnt = self.h2c.observe_rp(regs).map_err(Error::Transport)?;
        self.release_fwcmd(usize::from(cnt), false);
        Ok(self.h2c.avail())
    }

    /// Buffers kicked on CH12 and not yet consumed, plus consumed
    /// ones still held by the multi-tag window.
    pub(super) fn fwcmd_held(&self) -> (usize, usize) {
        (self.fwcmd_in_flight.len(), self.fwcmd_release.len())
    }

    /// `rtw89_pci_release_fwcmd` (`pci.c:100`).
    fn release_fwcmd(&mut self, cnt: usize, release_all: bool) {
        for _ in 0..cnt {
            match self.fwcmd_in_flight.pop_front() {
                Some(Some(buf)) => self.fwcmd_release.push_back(buf),
                Some(None) => {}
                None => break,
            }
        }
        let keep = if release_all { 0 } else { FWCMD_MULTITAG };
        while self.fwcmd_release.len() > keep {
            drop(self.fwcmd_release.pop_front());
        }
    }

    /// Release the retained H2C buffer whose FWCMD identity
    /// `ack` echoes, reporting its DONE_ACK return code (or
    /// `None` for a REC_ACK). `None` when no retained buffer
    /// matches — an unmatched ack releases nothing.
    pub(super) fn release_h2c_by_ack(&mut self, ack: &Ack) -> Option<Released> {
        let index = self
            .h2c_retained
            .iter()
            .position(|(framed, _)| fwcmd_8922a::matches_ack(ack, framed))?;
        let (framed, buf) = self.h2c_retained.remove(index);
        drop(buf);
        Some(Released {
            framed,
            result: ack.result,
        })
    }

    /// Record the core chip version read during the MAC
    /// pre-init (`mac_pre_init_8922a::read_chip_ver`). Called by
    /// the pci owner once per bring-up, after it runs the reset +
    /// tail and reads the chip version.
    pub(super) fn record_chip_ver(&mut self, ver: HalChipVer) {
        self.chip_ver = Some(ver);
    }

    /// The core chip version read during the MAC pre-init, if
    /// the pre-init has run.
    pub(super) fn chip_ver(&self) -> Option<HalChipVer> {
        self.chip_ver
    }
}
