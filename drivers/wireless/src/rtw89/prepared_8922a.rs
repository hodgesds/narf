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
//! MLO composition (see the "MLO model" section below):
//! `admit_mld` retains `MldStation`s alongside the shared
//! `MacIdPool`; per-link BA-CAM acquire/H2C/release,
//! per-link RA (phy index = link instance index), and
//! per-link TXWD EHT fields route through the designated
//! link; `release_mld_link` / `release_mld` tear links down
//! one at a time or whole.
//!
//! VIF composition lives here too: `add_vif` holds one VIF
//! record per interface (main MACID + port, Linux
//! `rtw89_ops_add_interface` order), and the station-mode
//! TDLS peer takes the VIF's main MACID (`admit_tdls_peer`)
//! instead of a pool MACID.
//!
//! What this owner deliberately does NOT own (later steps):
//! - Legacy-mode admission.
//! - The register-level 6 GHz TX-power program
//!   (`rtw8922a_set_txpwr`: by-rate / limit / limit-RU pages on
//!   BE registers, shape, diff, ref, SAR-diff) and the wide-6 GHz
//!   TPE rearrange (40/80/160 MHz): admission records the
//!   20 MHz primary-subchannel TPE constraint (`SixGhzProgram`)
//!   the program consumes, but nothing here writes power
//!   registers.
//! - Firmware download (`prepared::load` selects the image; the
//!   download plan + secure loader are a separate lane).
//! - Link-lifecycle H2Cs (role-maintain / DMAC / join-info /
//!   CAM around link add/assoc/disconnect, issue #1918) are
//!   built by `link_h2c_8922a.rs` from the MLD / station
//!   records admitted here plus a per-link VIF context; the
//!   MLD composition here still builds CCTL + BA-CAM bodies
//!   only and never sends them. Still open: this owner must
//!   allocate the per-instance CAM entries and hold the
//!   per-instance VIF-link contexts (own link address, CAM
//!   indices) the transition composers consume, and frame +
//!   send the bodies over CH12 — the transport lane.
//!
//! ## MLO model (Linux grounding)
//!
//! The MLD model is the station owner's (`station_8922a.rs`,
//! torvalds/linux master `7475ea8b`); the VIF paths below
//! were read from current torvalds/linux master
//! (`drivers/net/wireless/realtek/rtw89`, codebrowser,
//! November 2026) and carry the line numbers as read there:
//!
//! - VIF: `rtw89_ops_add_interface` (`mac80211.c:165`)
//!   acquires one MACID (`rtw89_acquire_mac_id`, which
//!   searches only the 16 base slots while MLO is on,
//!   `core.c:5731`) and one port (bitmap over
//!   `RTW89_PORT_NUM` = 5, `core.h:592`), then
//!   `rtw89_init_vif` (`core.c:5755`) precomputes the link
//!   instances: instance `index` gets
//!   `mac_id = mac_id + index * support_mld_num` (16),
//!   `mac_idx = RTW89_MAC_0 + index`,
//!   `phy_idx = RTW89_PHY_0 + index` (`RTW89_PHY_0` = 0),
//!   and every instance shares the one port ("multi-link use
//!   the same port id on different HW bands"). Removal
//!   (`mac80211.c:239`) releases the main MACID
//!   (`rtw89_vif_get_main_macid` = `links_inst[0].mac_id`,
//!   `core.h:6237`) and the main port.
//! - Station-mode peer: `__rtw89_ops_sta_add`
//!   (`mac80211.c:479`) takes the VIF's main MACID for a
//!   TDLS peer on a station-mode VIF ("for station mode,
//!   assign the mac_id from itself", `mac80211.c:495`);
//!   every other station acquires a fresh pool MACID. The
//!   AP peer on a station-mode VIF is therefore a pool
//!   station, not a VIF-MACID station.
//! - Per-link RA: `rtw89_phy_ra_sta_update` (`phy.c:498`)
//!   reports `ra->band_num = rtwvif_link->phy_idx`, and the
//!   station link is bound to the VIF link instance of the
//!   same index (`rtw89_init_sta`, `core.c:5790`), so a
//!   link's RA phy index is its instance index.
//!
//! Deliberate differences from Linux:
//! - The pool keeps the full 32-slot range for single-link
//!   admission (the station owner's documented difference);
//!   a VIF reserves only its base slot, not the strided
//!   `base + 16` slot, so a VIF's second link instance has a
//!   precomputed identity but no pool reservation yet — the
//!   per-instance VIF-link contexts (own address, CAM indices)
//!   the link-lifecycle builders (`link_h2c_8922a`, #1918)
//!   consume are still to be held here.
//! - A TDLS peer release never frees the VIF's MACID here.
//!   Linux `__rtw89_ops_sta_remove` (`mac80211.c:622`)
//!   releases the shared main MACID bit for TDLS peers,
//!   which would free the VIF's own MACID while the VIF is
//!   still up; this owner keeps the base reserved until
//!   `remove_vif`, so a peer release only drops the peer
//!   record.
//! - A TDLS MLD (an MLD peer taking the VIF main MACID as
//!   its base) is not admitted: `admit_mld` always takes
//!   its base from the pool. That composition is a
//!   follow-up once a TDLS MLD need is established.
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
use super::station_8922a::{self, LinkRequest, MldStation, Request, Station};
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
    /// No admitted MLD owns this base MACID.
    NoMld,
    /// No VIF owns this main MACID (or address).
    NoVif,
    /// A VIF with this address is already admitted.
    VifExists,
    /// Out of hardware ports (`RTW89_PORT_NUM` VIFs admitted).
    NoPort,
    /// TDLS peer admission on a VIF that is not station-mode
    /// (Linux `__rtw89_ops_sta_add` takes the VIF main MACID
    /// only for a TDLS peer on a station-mode VIF).
    NotStationMode,
    /// TDLS peer request's port disagrees with its VIF's port
    /// (Linux programs one port id per VIF into every assoc
    /// CCTL).
    PortMismatch,
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

/// Hardware port count (`RTW89_PORT_NUM`, Linux `core.h:592`:
/// `RTW89_PORT_0`..`RTW89_PORT_4`). One port per VIF; all of
/// a VIF's link instances share it (`rtw89_init_vif`,
/// `core.c:5755`).
const RTW89_PORT_NUM: usize = 5;

/// Role of an admitted VIF: the two roles Linux's
/// station-add/remove paths branch on (`__rtw89_ops_sta_add`
/// / `__rtw89_ops_sta_remove`, `mac80211.c`). Monitor, P2P,
/// mesh, and AP-VLAN roles are not modeled: this owner
/// composes station + AP only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VifRole {
    /// Station-mode VIF (`NL80211_IFTYPE_STATION`).
    Station,
    /// AP-mode VIF (`NL80211_IFTYPE_AP`).
    Ap,
}

/// One admitted VIF: its address, role, and the one MACID +
/// port Linux `rtw89_ops_add_interface` (`mac80211.c:165`)
/// acquires for it. The main MACID is the base
/// (`rtw89_vif_get_main_macid` = `links_inst[0].mac_id`,
/// `core.h:6237`); link instance `index` precomputes
/// `base + index * MLD_MACID_STRIDE`, `mac_idx = index`,
/// `phy_idx = index` (`rtw89_init_vif`, `core.c:5755`) —
/// but only the base slot is reserved in the shared pool
/// (see the module docs). The VIF owns its base slot until
/// [`Prepared8922a::remove_vif`]; TDLS peers admitted
/// against it share the base without owning it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Vif {
    /// Interface address.
    pub(super) addr: [u8; 6],
    /// VIF role.
    pub(super) role: VifRole,
    /// Base MACID acquired for this VIF (its main MACID).
    pub(super) base_macid: u8,
    /// Hardware port acquired for this VIF.
    pub(super) port: u8,
}

impl Vif {
    /// The VIF's main MACID (`rtw89_vif_get_main_macid`).
    pub(super) fn main_macid(self) -> u8 {
        self.base_macid
    }

    /// The VIF's main port (`rtw89_vif_get_main_port`,
    /// `core.h:6243`).
    pub(super) fn main_port(self) -> u8 {
        self.port
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
    /// Admitted MLD stations, keyed by base MACID
    /// (`MldStation::base_macid`).
    mlds: Vec<MldStation>,
    /// Admitted VIFs, keyed by main MACID
    /// (`Vif::base_macid`).
    vifs: Vec<Vif>,
    /// TDLS peers admitted at a VIF's main MACID: single-link
    /// station records that share the VIF's base slot without
    /// owning it (see [`Self::admit_tdls_peer`]).
    vif_peers: Vec<Station>,
    /// Hardware ports held by admitted VIFs
    /// (`RTW89_PORT_NUM` slots, lowest free first).
    ports_used: [bool; RTW89_PORT_NUM],
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
    /// Outcome of the firmware download `pci::bring_up` ran
    /// (`Rtw89Device::boot_8922a`); `None` until it runs.
    firmware: Option<Result<(), super::pci::Boot8922aError>>,
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
            mlds: Vec::new(),
            vifs: Vec::new(),
            vif_peers: Vec::new(),
            ports_used: [false; RTW89_PORT_NUM],
            data: tx_8922a::DataTx::new()?,
            h2c: tx_8922a::H2cTx::new(tx_8922a::DATA_RING_DEPTH)?,
            rings_programmed: false,
            irq: None,
            data_retained: Vec::new(),
            h2c_seq: H2cSeqAllocator::new(),
            h2c_retained: Vec::new(),
            fwcmd_in_flight: VecDeque::new(),
            fwcmd_release: VecDeque::new(),
            firmware: None,
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
            let admitted: Vec<u8> = self.admitted_macids();
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

    /// Admitted single-link station by MACID, if any: a pool
    /// station or a VIF TDLS peer (both are plain
    /// single-link records). MLD links are NOT visible here —
    /// use [`Self::mld`] + [`MldStation::link`] for those, so
    /// a link MACID can never take the single-link BA-CAM /
    /// RA path by accident.
    pub(super) fn station(&self, macid: u8) -> Option<&Station> {
        self.stations
            .iter()
            .chain(self.vif_peers.iter())
            .find(|station| station.macid == macid)
    }

    /// Mutable access to an admitted single-link station by
    /// MACID (pool station or VIF TDLS peer, as in
    /// [`Self::station`]).
    fn station_mut(&mut self, macid: u8) -> Option<&mut Station> {
        if let Some(index) = self
            .stations
            .iter()
            .position(|station| station.macid == macid)
        {
            return Some(&mut self.stations[index]);
        }
        if let Some(index) = self
            .vif_peers
            .iter()
            .position(|station| station.macid == macid)
        {
            return Some(&mut self.vif_peers[index]);
        }
        None
    }

    /// True when `macid` is admitted anywhere on this owner:
    /// a pool station, a VIF TDLS peer, or any link of any
    /// admitted MLD. Data submit (`prepare_data`) and the RX
    /// drain admit on this, not on [`Self::station`] alone,
    /// so frames to an MLD link MACID are accepted.
    fn is_admitted(&self, macid: u8) -> bool {
        self.station(macid).is_some()
            || self
                .mlds
                .iter()
                .any(|mld| mld.links.iter().flatten().any(|link| link.macid() == macid))
    }

    /// Every admitted MACID on this owner, for the RX drain's
    /// admission list: pool stations, VIF TDLS peers, and
    /// every link of every admitted MLD.
    fn admitted_macids(&self) -> Vec<u8> {
        let mut macids: Vec<u8> = self
            .stations
            .iter()
            .chain(self.vif_peers.iter())
            .map(|station| station.macid)
            .collect();
        for mld in &self.mlds {
            for link in mld.links.iter().flatten() {
                macids.push(link.macid());
            }
        }
        macids
    }

    /// Release a station: its MACID returns to the pool and its
    /// record is dropped — except for a VIF TDLS peer, whose
    /// record is dropped but whose MACID stays with the VIF
    /// (see [`Self::admit_tdls_peer`]). Idempotent: releasing
    /// an unknown MACID is a no-op. Releasing an MLD link
    /// MACID here is also a no-op: links release through
    /// [`Self::release_mld_link`] / [`Self::release_mld`].
    pub(super) fn release_station(&mut self, macid: u8) {
        if let Some(index) = self
            .stations
            .iter()
            .position(|station| station.macid == macid)
        {
            let station = self.stations.remove(index);
            station.release_macid(&mut self.pool);
            return;
        }
        if let Some(index) = self
            .vif_peers
            .iter()
            .position(|station| station.macid == macid)
        {
            self.vif_peers.remove(index);
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
        let station = self.station_mut(macid).ok_or(Error::NoStation)?;
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
        let station = self.station_mut(macid).ok_or(Error::NoStation)?;
        station
            .bacam
            .release(idx)
            .map_err(|error| Error::Station(station_8922a::Error::BaCam(error)))
    }

    // ── MLD composition ──────────────────────────────────────────
    //
    // The MLD owner (`station_8922a::admit_mld`) owns the
    // per-link records; this owner retains them alongside the
    // shared `MacIdPool` and routes the per-link firmware
    // artifacts through the designated link, exactly as Linux
    // builds BA-CAM from the designated link
    // (`rtw89_fw_h2c_ba_cam_v1`, `fw.c:2922`) and assoc per
    // link (`__rtw89_ops_sta_assoc`, `mac80211.c`).

    /// Admit one EHT MLD station with the chip-default facet
    /// (`EhtStation::new_8922ae`), retaining its
    /// `MldStation` alongside the shared `MacIdPool`.
    /// Returns the MLD base MACID; link instance `index`
    /// owns `base + index * MLD_MACID_STRIDE`. The record is
    /// retained until [`Self::release_mld`]; a refused
    /// request consumes no MACID.
    pub(super) fn admit_mld(
        &mut self,
        mld_addr: [u8; 6],
        links: &[LinkRequest<'_>],
    ) -> Result<u8, Error> {
        let facet = EhtStation::new_8922ae().ok_or(Error::EhtUnavailable)?;
        let mld = station_8922a::admit_mld(&self.factory, facet, &mut self.pool, mld_addr, links)?;
        let base_macid = mld.base_macid;
        self.mlds.push(mld);
        Ok(base_macid)
    }

    /// Admitted MLD by base MACID, if any.
    pub(super) fn mld(&self, base_macid: u8) -> Option<&MldStation> {
        self.mlds.iter().find(|mld| mld.base_macid == base_macid)
    }

    /// Mutable access to an admitted MLD by base MACID.
    fn mld_mut(&mut self, base_macid: u8) -> Option<&mut MldStation> {
        self.mlds
            .iter_mut()
            .find(|mld| mld.base_macid == base_macid)
    }

    /// Admit one more link to an admitted MLD (Linux
    /// `__rtw89_ops_set_sta_links`: set-link, link-add,
    /// link-assoc). The new link takes the lowest free
    /// instance index, whose MACID slot was already reserved
    /// by the MLD base allocation. Returns the new link's
    /// MACID. A refused request leaves the MLD untouched.
    pub(super) fn add_mld_link(
        &mut self,
        base_macid: u8,
        link: &LinkRequest<'_>,
    ) -> Result<u8, Error> {
        let facet = EhtStation::new_8922ae().ok_or(Error::EhtUnavailable)?;
        let index = self
            .mlds
            .iter()
            .position(|mld| mld.base_macid == base_macid)
            .ok_or(Error::NoMld)?;
        // Disjoint field borrows: the link slot out of `mlds`,
        // the factory for the new link's CCTLs.
        let mld = &mut self.mlds[index];
        mld.add_link(&self.factory, facet, &mut self.pool, link)
            .map_err(Error::Station)
    }

    /// Remove one link from an admitted MLD (Linux
    /// `__rtw89_ops_clr_sta_links`: disassoc, disconnect,
    /// remove, unset-link). Returns the removed link's
    /// MACID, which returns to the pool; the MLD survives
    /// on the remaining link. Release the link's BA-CAM
    /// slots before removing it when it is the designated
    /// link: its map goes away with it.
    pub(super) fn release_mld_link(&mut self, base_macid: u8, link_id: u8) -> Result<u8, Error> {
        let index = self
            .mlds
            .iter()
            .position(|mld| mld.base_macid == base_macid)
            .ok_or(Error::NoMld)?;
        // Disjoint field borrows: the link slot out of `mlds`,
        // the pool for the freed MACID.
        let mld = &mut self.mlds[index];
        let link = mld
            .remove_link(&mut self.pool, link_id)
            .map_err(Error::Station)?;
        Ok(link.macid())
    }

    /// Release a whole MLD: every remaining link's MACID
    /// returns to the pool and the record is dropped.
    /// Idempotent: releasing an unknown base MACID is a
    /// no-op.
    pub(super) fn release_mld(&mut self, base_macid: u8) {
        if let Some(index) = self
            .mlds
            .iter()
            .position(|mld| mld.base_macid == base_macid)
        {
            let mld = self.mlds.remove(index);
            mld.release_all(&mut self.pool);
        }
    }

    /// Acquire a BA-CAM bitmap slot for a BlockAck session on
    /// the MLD's designated link (`MldStation::acquire_bacam`);
    /// the index feeds [`Self::ba_h2c_mld`].
    pub(super) fn acquire_bacam_mld(&mut self, base_macid: u8, tid: u8) -> Result<usize, Error> {
        let mld = self.mld_mut(base_macid).ok_or(Error::NoMld)?;
        mld.acquire_bacam(tid).map_err(Error::Station)
    }

    /// Build a BA-CAM v1 H2C body for one of the MLD's
    /// designated link's BlockAck sessions: MLD on,
    /// band-select from the designated link's MAC index
    /// (Linux `rtw89_fw_h2c_ba_cam_v1`). `bitmap_idx` must
    /// come from [`Self::acquire_bacam_mld`].
    pub(super) fn ba_h2c_mld(
        &self,
        base_macid: u8,
        tid: u32,
        bmap_size: u32,
        ssn: u32,
        bitmap_idx: u32,
    ) -> Result<bacam_v1::BaCamH2c, Error> {
        let mld = self.mld(base_macid).ok_or(Error::NoMld)?;
        mld.ba_h2c(tid, bmap_size, ssn, bitmap_idx)
            .map_err(Error::Station)
    }

    /// Release a BA-CAM bitmap slot acquired via
    /// [`Self::acquire_bacam_mld`] on the designated link.
    pub(super) fn release_bacam_mld(&mut self, base_macid: u8, idx: usize) -> Result<(), Error> {
        let mld = self.mld_mut(base_macid).ok_or(Error::NoMld)?;
        mld.release_bacam(idx).map_err(Error::Station)
    }

    /// Fill the BE RA v1 command for one admitted MLD link
    /// (`ra_mask::build`): fresh station update (`upd` flags
    /// false), phy index = the link's instance index (Linux
    /// `phy.c:498`: `ra->band_num = rtwvif_link->phy_idx`;
    /// `rtw89_init_vif` gives `phy_idx = RTW89_PHY_0 +
    /// index`, `RTW89_PHY_0` = 0).
    pub(super) fn station_ra_mld(
        &self,
        base_macid: u8,
        link_id: u8,
        caps: &StationCaps,
    ) -> Result<[u32; 6], Error> {
        let mld = self.mld(base_macid).ok_or(Error::NoMld)?;
        let link = mld
            .link(link_id)
            .ok_or(Error::Station(station_8922a::Error::LinkNotFound))?;
        ra_mask::build(caps, link.macid(), link.index as u8, false, false).map_err(Error::Ra)
    }

    /// EHT contribution to the BE TXWD_INFO block for one
    /// admitted MLD link: (info4 bits, info7 bits) from that
    /// link's facet. `None` when the MLD or link is not
    /// admitted, or the facet cannot encode its NLTF value.
    pub(super) fn txwd_info_eht_mld(&self, base_macid: u8, link_id: u8) -> Option<(u32, u32)> {
        self.mld(base_macid)?.txwd_info_eht(link_id)
    }

    // ── VIF composition ──────────────────────────────────────────
    //
    // The VIF record is the interface Linux
    // `rtw89_ops_add_interface` creates: one MACID + one port
    // from the shared pools, link instances precomputed off
    // the base (see the module docs). The station-mode TDLS
    // peer is the one station that does NOT take a pool
    // MACID.

    /// Admit one VIF: acquire the lowest free pool MACID as
    /// its base (main MACID) and the lowest free hardware
    /// port, in Linux `rtw89_ops_add_interface` order (MACID
    /// first, then port). Returns the main MACID. A refused
    /// request — pool exhausted, no port free, or a VIF with
    /// this address already admitted — consumes nothing: a
    /// port failure after a MACID allocation frees the MACID
    /// again.
    pub(super) fn add_vif(&mut self, addr: [u8; 6], role: VifRole) -> Result<u8, Error> {
        if self.vifs.iter().any(|vif| vif.addr == addr) {
            return Err(Error::VifExists);
        }
        let base_macid = self.pool.alloc().map_err(Error::Station)?;
        let port = match self
            .ports_used
            .iter()
            .position(|used| !*used)
            .map(|index| index as u8)
        {
            Some(port) => port,
            None => {
                self.pool.free(base_macid);
                return Err(Error::NoPort);
            }
        };
        self.ports_used[port as usize] = true;
        self.vifs.push(Vif {
            addr,
            role,
            base_macid,
            port,
        });
        Ok(base_macid)
    }

    /// Admitted VIF by main MACID, if any.
    pub(super) fn vif(&self, main_macid: u8) -> Option<&Vif> {
        self.vifs.iter().find(|vif| vif.base_macid == main_macid)
    }

    /// Admitted VIF by interface address, if any.
    pub(super) fn vif_by_addr(&self, addr: [u8; 6]) -> Option<&Vif> {
        self.vifs.iter().find(|vif| vif.addr == addr)
    }

    /// Admit a TDLS peer on a station-mode VIF at the VIF's
    /// main MACID (Linux `__rtw89_ops_sta_add`,
    /// `mac80211.c:495`: "for station mode, assign the
    /// mac_id from itself"). The peer takes no pool MACID:
    /// the VIF's base slot is already marked used, and the
    /// peer record is retained in [`Self::vif_peers`] so
    /// releasing it never frees the VIF's MACID (see the
    /// module docs for the deliberate difference from
    /// Linux's remove path). Returns the MACID — the VIF's
    /// main MACID. The request's port must be the VIF's
    /// port: Linux programs one port id per VIF into every
    /// assoc CCTL.
    pub(super) fn admit_tdls_peer(
        &mut self,
        vif_main_macid: u8,
        req: &Request,
    ) -> Result<u8, Error> {
        let vif = self.vif(vif_main_macid).ok_or(Error::NoVif)?;
        if vif.role != VifRole::Station {
            return Err(Error::NotStationMode);
        }
        if req.port != vif.port {
            return Err(Error::PortMismatch);
        }
        let facet = EhtStation::new_8922ae().ok_or(Error::EhtUnavailable)?;
        let station = station_8922a::admit_with_macid(&self.factory, facet, req, vif.base_macid)?;
        let macid = station.macid;
        self.vif_peers.push(station);
        Ok(macid)
    }

    /// Remove a VIF: its base MACID returns to the pool and
    /// its port is freed (Linux `rtw89_ops_remove_interface`
    /// releases `rtw89_vif_get_main_macid` + the main port).
    /// Any TDLS peers admitted against it dissolve with it:
    /// their records die here, and the base returns to the
    /// pool exactly once. Idempotent: removing an unknown
    /// main MACID is a no-op.
    pub(super) fn remove_vif(&mut self, main_macid: u8) {
        if let Some(index) = self
            .vifs
            .iter()
            .position(|vif| vif.base_macid == main_macid)
        {
            let vif = self.vifs.remove(index);
            self.vif_peers
                .retain(|station| station.macid != vif.base_macid);
            self.ports_used[vif.port as usize] = false;
            self.pool.free(vif.base_macid);
        }
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
        if !self.is_admitted(args.mac_id) {
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
        if !self.is_admitted(args.mac_id) {
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

    /// Record the firmware download outcome (`pci::bring_up`).
    pub(super) fn record_firmware(&mut self, outcome: Result<(), super::pci::Boot8922aError>) {
        self.firmware = Some(outcome);
    }

    /// True once the WCPU + BBMCU0 firmware reported FreeRTOS ready.
    pub(super) fn firmware_ready(&self) -> bool {
        matches!(self.firmware, Some(Ok(())))
    }

    /// The firmware download outcome, if it ran.
    pub(super) fn firmware(&self) -> Option<Result<(), super::pci::Boot8922aError>> {
        self.firmware
    }

    /// The core chip version read during the MAC pre-init, if
    /// the pre-init has run.
    pub(super) fn chip_ver(&self) -> Option<HalChipVer> {
        self.chip_ver
    }
}
