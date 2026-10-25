//! AMD ACP 6.3 SoundWire binding: the ACP's SDW manager instances,
//! bound for the SoundWire configurations of 1022:15e2 rev 0x63 that
//! [`crate::acp63`] leaves unbound (its probe requires the PDM mux;
//! SoundWire-only pin configurations decline there and this driver is
//! the next candidate — reachable once the candidate-walking probe
//! dispatcher, PR #852, is on main; until then this binding is
//! registered but inert, see audio spec §3.2).
//!
//! The manager register model and the immediate-command framing are
//! the ACP SDW manager's, as in Linux `drivers/soundwire/amd_manager.c`
//! / `amd_manager.h` (the same model the excised ACP6 codec-link
//! scaffold encoded; this module is self-contained and does not depend
//! on it). The generic bus logic — enumeration, register access,
//! stream setup — lives in [`crate::soundwire`].
//!
//! Scope notes, stated plainly:
//! - Only the SDW0 manager instance is bound (the instance the ACP
//!   pin configurations wire to the codec link on Phoenix laptops).
//! - Pin configurations where PDM and SoundWire coexist are *not*
//!   claimed here: the PDM driver owns the function then. Composing
//!   both on one function is a follow-up to #780.
//! - Enumerated codecs are published as sound cards with the generic
//!   codec conversation; the ACP SDW DMA engine that moves PCM
//!   payload between host memory and the manager is a separate
//!   hardware block and is likewise a follow-up to #780.

use crate::soundwire::{
    Bus, CodecCard, SdwError, StreamConfig, Transport, BROADCAST_DEV_NUM, GENERIC_CODEC_PROFILE,
};
use alloc::{sync::Arc, vec::Vec};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

// ACP function registers shared with the PDM path (offsets as in
// `crate::acp63`, which owns the PDM binding of the same function).
const RESET: u64 = 0x1000;
const CONTROL: u64 = 0x1004;
const ZSC: u64 = 0x1014;
const POWER_CONTROL: u64 = 0x1024;
const POWER_STATUS: u64 = 0x1028;
const PIN_CONFIG: u64 = 0x1440;

/// ACP SoundWire manager registers (instance-relative; the SDW0
/// instance base is BAR0 + `MANAGER_OFFSET`). Names follow Linux
/// `amd_manager.h`'s `ACP_SW_*` registers.
mod regs {
    /// SDW0 manager base offset within BAR0 (`SDW_MANAGER_REG_OFFSET`).
    pub const MANAGER_OFFSET: u64 = 0xC00;
    /// `ACP_SW_EN` — write 1 to enable the manager.
    pub const SW_EN: u64 = 0x3000;
    /// `ACP_SW_EN_STATUS` — nonzero once the manager is enabled.
    pub const SW_EN_STATUS: u64 = 0x3004;
    /// `ACP_SW_FRAMESIZE` — `(rows_idx << 3) | cols_idx`.
    pub const SW_FRAMESIZE: u64 = 0x3008;
    /// `ACP_SW_BUS_RESET_CTRL` — bus reset handshake (1 = request,
    /// reads 2 = done, write 0 = clear).
    pub const SW_BUS_RESET_CTRL: u64 = 0x3188;
    /// `ACP_SW_IMM_CMD_UPPER_WORD`.
    pub const SW_IMM_CMD_UPPER: u64 = 0x3230;
    /// `ACP_SW_IMM_CMD_LOWER_QWORD`.
    pub const SW_IMM_CMD_LOWER: u64 = 0x3234;
    /// `ACP_SW_IMM_RESP_UPPER_WORD`.
    pub const SW_IMM_RESP_UPPER: u64 = 0x3238;
    /// `ACP_SW_IMM_RESP_LOWER_QWORD`: bit 0 = ACK
    /// (`AMD_SDW_MCP_RESP_ACK`), bits [14:7] carry the read data byte.
    pub const SW_IMM_RESP_LOWER: u64 = 0x323C;
    /// `ACP_SW_IMM_CMD_STS` — bit 0 = IMM_RES_VALID, bit 1 =
    /// IMM_CMD_BUSY. Writing IMM_RES_VALID clears the valid bit.
    pub const SW_IMM_CMD_STS: u64 = 0x3240;
    /// `ACP_SW_STATE_CHANGE_STATUS_MASK_0TO7`.
    pub const SW_IRQ_MASK_0TO7: u64 = 0x3264;
    /// `ACP_SW_STATE_CHANGE_STATUS_MASK_8TO11`.
    pub const SW_IRQ_MASK_8TO11: u64 = 0x3268;
    /// `ACP_SW_ERROR_INTR_MASK`.
    pub const SW_ERROR_INTR_MASK: u64 = 0x3270;

    pub const BUS_RESET_REQ: u32 = 1;
    pub const BUS_RESET_DONE: u32 = 2;
    pub const BUS_RESET_CLEAR: u32 = 0;
    pub const IMM_RES_VALID: u32 = 1;
    pub const IMM_CMD_BUSY: u32 = 2;
    pub const RESP_ACK: u32 = 1;
    /// `AMD_SDW_MCP_CMD_COMMAND` values (upper word bits [14:12]).
    pub const MCP_CMD_READ: u32 = 2 << 12;
    pub const MCP_CMD_WRITE: u32 = 3 << 12;
    /// State-change IRQ masks (all categories), from `amd_manager.h`.
    pub const IRQ_MASK_0TO7: u32 = 0x7777_7777;
    pub const IRQ_MASK_8TO11: u32 = 0x000C_7777;
    pub const IRQ_ERROR_MASK: u32 = 0xFF;
    /// Default frame shape (`AMD_SDW_DEFAULT_ROWS/COLS`): 50 rows ×
    /// 10 columns. Linux's `amd_sdw_set_frameshape` encodes the shape
    /// as spec Table B4 indices; index 0 is the 50×10 entry.
    pub const DEFAULT_ROWS: u32 = 50;
    pub const DEFAULT_COLS: u32 = 10;
}

/// Pack one immediate command into the manager's two-word format
/// (`amd_sdw_ctl_word_prep`): upper = device [11:8] | command
/// [14:12] | register address high byte [7:0]; lower = register
/// address low byte [31:24] | write data [14:7].
fn imm_words(dev: u8, addr: u32, write: Option<u8>) -> (u32, u32) {
    let command = if write.is_some() {
        regs::MCP_CMD_WRITE
    } else {
        regs::MCP_CMD_READ
    };
    let upper = ((dev as u32 & 0xF) << 8) | command | ((addr >> 8) & 0xFF);
    let data = match write {
        Some(data) => data as u32,
        None => 0,
    };
    let lower = ((addr & 0xFF) << 24) | (data << 7);
    (upper, lower)
}

fn wait(predicate: impl FnMut() -> bool) -> bool {
    narf_scheduler::responsive_spin_until(predicate, Deadline::after_ms(100))
}

/// The ACP SDW0 manager as a [`Transport`]: immediate commands over
/// the manager's IMM_CMD register pair, with every poll bounded and
/// every failure mapped to a closed [`SdwError`].
#[derive(Debug)]
pub struct AcpSdwTransport {
    mmio: MmioRegion,
}

impl AcpSdwTransport {
    /// Wrap the ACP function's BAR0. The caller owns the function
    /// (probe claimed it) and has powered the ACP up.
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }

    fn read_mgr(&self, offset: u64) -> u32 {
        // SAFETY: The transport owns the probed ACP function's BAR0;
        // manager offsets are fixed and inside the validated window
        // (probe checked the BAR covers the manager register block).
        unsafe { self.mmio.read32(regs::MANAGER_OFFSET + offset) }
    }

    fn write_mgr(&self, offset: u64, value: u32) {
        // SAFETY: Same ownership as `read_mgr`.
        unsafe { self.mmio.write32(regs::MANAGER_OFFSET + offset, value) }
    }

    fn wait_mgr(&self, offset: u64, predicate: impl Fn(u32) -> bool) -> bool {
        wait(|| predicate(self.read_mgr(offset)))
    }

    /// Enable the manager, reset the bus, program the default frame
    /// shape and unmask state-change/error interrupts. Mirrors
    /// `amd_init_sdw_manager` + `amd_enable_sdw_manager` +
    /// `amd_enable_sdw_interrupts`.
    pub fn init_manager(&self) -> Result<(), SdwError> {
        self.write_mgr(regs::SW_EN, 1);
        if !self.wait_mgr(regs::SW_EN_STATUS, |value| value != 0) {
            return Err(SdwError::Timeout);
        }
        self.bus_reset()?;
        // The manager comes out of bus reset disabled on this
        // hardware; cycle EN before programming the frame shape.
        self.write_mgr(regs::SW_EN, 0);
        if !self.wait_mgr(regs::SW_EN_STATUS, |value| value == 0) {
            return Err(SdwError::Timeout);
        }
        self.write_mgr(regs::SW_EN, 1);
        if !self.wait_mgr(regs::SW_EN_STATUS, |value| value != 0) {
            return Err(SdwError::Timeout);
        }
        self.write_mgr(regs::SW_FRAMESIZE, 0);
        self.write_mgr(regs::SW_IRQ_MASK_0TO7, regs::IRQ_MASK_0TO7);
        self.write_mgr(regs::SW_IRQ_MASK_8TO11, regs::IRQ_MASK_8TO11);
        self.write_mgr(regs::SW_ERROR_INTR_MASK, regs::IRQ_ERROR_MASK);
        Ok(())
    }

    /// Disable the manager (used when a probe declines after init).
    pub fn disable_manager(&self) {
        self.write_mgr(regs::SW_EN, 0);
        let _ = self.wait_mgr(regs::SW_EN_STATUS, |value| value == 0);
    }
}

impl Transport for AcpSdwTransport {
    fn xfer(&self, dev: u8, addr: u32, write: Option<u8>) -> Result<Option<u8>, SdwError> {
        if dev > BROADCAST_DEV_NUM {
            return Err(SdwError::InvalidDevice);
        }
        if addr > 0xFFFF {
            return Err(SdwError::InvalidAddress);
        }
        // No previous command may be outstanding or unacknowledged.
        if !self.wait_mgr(regs::SW_IMM_CMD_STS, |value| {
            value & (regs::IMM_RES_VALID | regs::IMM_CMD_BUSY) == 0
        }) {
            return Err(SdwError::Timeout);
        }
        let (upper, lower) = imm_words(dev, addr, write);
        self.write_mgr(regs::SW_IMM_CMD_UPPER, upper);
        self.write_mgr(regs::SW_IMM_CMD_LOWER, lower);
        if !self.wait_mgr(regs::SW_IMM_CMD_STS, |value| {
            value & regs::IMM_RES_VALID != 0
        }) {
            return Err(SdwError::Timeout);
        }
        // The response upper word carries no byte for register-sized
        // commands; read it anyway so the pair is drained in order.
        let _ = self.read_mgr(regs::SW_IMM_RESP_UPPER);
        let resp_lower = self.read_mgr(regs::SW_IMM_RESP_LOWER);
        self.write_mgr(regs::SW_IMM_CMD_STS, regs::IMM_RES_VALID);
        if !self.wait_mgr(regs::SW_IMM_CMD_STS, |value| {
            value & regs::IMM_RES_VALID == 0
        }) {
            return Err(SdwError::Timeout);
        }
        if resp_lower & regs::RESP_ACK == 0 {
            // The command completed on the wire; nobody acknowledged
            // it (no peripheral there, or a NAK).
            return Err(SdwError::NoResponse);
        }
        Ok(match write {
            Some(_) => None,
            None => Some(((resp_lower >> 7) & 0xFF) as u8),
        })
    }

    fn bus_reset(&self) -> Result<(), SdwError> {
        self.write_mgr(regs::SW_BUS_RESET_CTRL, regs::BUS_RESET_REQ);
        if !self.wait_mgr(regs::SW_BUS_RESET_CTRL, |value| {
            value == regs::BUS_RESET_DONE
        }) {
            return Err(SdwError::Timeout);
        }
        self.write_mgr(regs::SW_BUS_RESET_CTRL, regs::BUS_RESET_CLEAR);
        if !self.wait_mgr(regs::SW_BUS_RESET_CTRL, |value| value == 0) {
            return Err(SdwError::Timeout);
        }
        Ok(())
    }

    fn frame_shape(&self) -> (u32, u32) {
        (regs::DEFAULT_ROWS, regs::DEFAULT_COLS)
    }
}

/// Power the ACP up and reset it, mirroring the first half of
/// `acp63::Controller::init` (the PDM driver performs the same steps
/// when it probes first and declines, leaving the block in sleep, so
/// this binding cannot assume the state it finds).
fn power_up(mmio: MmioRegion) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    // SAFETY: Probe has exclusively claimed this function and its BAR;
    // fixed offsets are inside the ACP register window.
    let state = unsafe { mmio.read32(POWER_STATUS) };
    if state == u32::MAX {
        return Err(ProbeError::BadDevice);
    }
    if state != 0 {
        if state & 3 != 1 {
            // SAFETY: Same ownership as above.
            unsafe {
                mmio.write32(POWER_CONTROL, 1);
            }
        }
        // SAFETY: Same ownership as above.
        if !wait(|| unsafe { mmio.read32(POWER_STATUS) } == 0) {
            return Err(ProbeError::BadDevice);
        }
    }
    // SAFETY: Same ownership as above.
    unsafe {
        mmio.write32(CONTROL, 1);
        mmio.write32(ZSC, 0);
        mmio.write32(RESET, 1);
    }
    // SAFETY: Same ownership as above.
    if !wait(|| unsafe { mmio.read32(RESET) } & 0x10001 != 0) {
        return Err(ProbeError::BadDevice);
    }
    // SAFETY: Same ownership as above.
    unsafe {
        mmio.write32(RESET, 0);
    }
    // SAFETY: Same ownership as above.
    if !wait(|| unsafe { mmio.read32(RESET) } == 0) {
        return Err(ProbeError::BadDevice);
    }
    Ok(())
}

#[derive(Debug)]
struct Bound {
    cards: Vec<Arc<CodecCard<AcpSdwTransport>>>,
    capture_card: u32,
}

static BOUND: IrqSafeSpinLock<Option<Bound>> = IrqSafeSpinLock::new(None);

/// Whether the ACP SoundWire binding has probed and published cards.
pub fn is_probed() -> bool {
    BOUND
        .lock()
        .as_ref()
        .is_some_and(|bound| !bound.cards.is_empty())
}

/// Number of SDW codec cards this binding has published.
pub fn published_cards() -> usize {
    BOUND.lock().as_ref().map_or(0, |bound| bound.cards.len())
}

/// The first published SDW card with a capture endpoint, if any.
pub fn capture_card() -> Option<u32> {
    BOUND.lock().as_ref().map(|bound| bound.capture_card)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    let revision =
        narf_bus::pci::read_config32(&cap, &device, 8).map_err(|_| ProbeError::BadDevice)? as u8;
    if device.id.vendor != crate::acp63::VENDOR
        || device.id.device != crate::acp63::DEVICE
        || device.id.class != 0x048000
        || revision != crate::acp63::REVISION
    {
        return Err(ProbeError::NotForThisDriver);
    }
    if BOUND.lock().is_some() || crate::acp63::is_probed() {
        // Already bound, or the PDM driver owns the function (a
        // coexisting PDM+SDW wiring; composing both is a follow-up).
        return Err(ProbeError::NotForThisDriver);
    }
    crate::native_pci::power_on(&device, &cap)?;
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| ProbeError::BadDevice)?;
    // SAFETY: Bus probing has exclusively claimed this function and its BAR.
    let mmio = unsafe { narf_bus::bar::map_bar(&device, 0) }.map_err(|_| ProbeError::BadDevice)?;
    if mmio.len < regs::MANAGER_OFFSET + regs::SW_ERROR_INTR_MASK + 4 {
        return Err(ProbeError::BadDevice);
    }
    power_up(mmio)?;
    // SAFETY: The ACP is powered and reset; PIN_CONFIG is a fixed
    // register inside the validated window.
    if crate::acp63::pin_config_has_pdm(unsafe { mmio.read32(PIN_CONFIG) }) {
        // PDM wiring present: the PDM binding owns this configuration
        // (it declined only on firmware grounds; SDW coexistence on a
        // PDM mux is the follow-up composition, not a silent claim).
        return Err(ProbeError::NotForThisDriver);
    }
    let transport = AcpSdwTransport::new(mmio);
    if transport.init_manager().is_err() {
        // Leave no powered-but-dead manager behind, mirroring the
        // empty-enumeration path below (disable waits are ignored,
        // so this is safe on a stuck manager).
        transport.disable_manager();
        return Err(ProbeError::BadDevice);
    }
    let mut bus = Bus::new(transport);
    let enumerated = match bus.enumerate() {
        Ok(found) => found
            .iter()
            .map(|peripheral| peripheral.dev_num)
            .collect::<Vec<u8>>(),
        Err(_) => {
            bus.transport().disable_manager();
            return Err(ProbeError::BadDevice);
        }
    };
    if enumerated.is_empty() {
        // Fail closed: no codec answered, publish nothing.
        bus.transport().disable_manager();
        return Err(ProbeError::NotForThisDriver);
    }
    // Generic-profile stream parameters for the manager's default
    // clocking: 50×10 frame = 500 bit-slots per frame at a 4.8 MHz
    // bus clock is 9600 frames/s, so a 48 kHz sample lands every
    // 100 slots. The word length matches the card's S16LE profile.
    let stream = StreamConfig {
        word_length: 16,
        sample_interval: 100,
    };
    let shared = Arc::new(IrqSafeSpinLock::new(bus));
    let mut cards = Vec::new();
    let mut capture_card = None;
    for dev_num in enumerated {
        let card = Arc::new(CodecCard::new(
            shared.clone(),
            dev_num,
            GENERIC_CODEC_PROFILE,
            stream,
        ));
        let info = narf_drivers_sound::CardInfo {
            index: 0,
            driver: "acp63-sdw",
            id: "ACP63SDW",
            name: "AMD ACP 6.3 SoundWire Codec",
            playback_count: u32::from(GENERIC_CODEC_PROFILE.sink.is_some()),
            capture_count: u32::from(GENERIC_CODEC_PROFILE.source.is_some()),
        };
        let index =
            narf_drivers_sound::register_hardware_card_at(info, card.clone(), Some(device.addr));
        if capture_card.is_none() {
            capture_card = Some(index);
        }
        cards.push(card);
    }
    *BOUND.lock() = Some(Bound {
        cards,
        capture_card: capture_card.unwrap_or(0),
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "acp63-sdw".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(crate::acp63::VENDOR),
        pci_did: Some(crate::acp63::DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "acp63-sdw",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: crate::acp63::VENDOR,
            device: crate::acp63::DEVICE,
        },
        probe,
    });
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::soundwire::regs as sdw;
    use alloc::{boxed::Box, collections::BTreeMap};
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_io::{alloc_coherent, DmaBuffer};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::id::DomainId;

    static MODEL: IrqSafeSpinLock<usize> = IrqSafeSpinLock::new(0);
    static REGISTERED: AtomicBool = AtomicBool::new(false);

    /// A modelled ACP SDW manager + one modelled peripheral, living in
    /// a fake BAR window. The pump plays the hardware: it mirrors EN
    /// into EN_STATUS, completes the bus-reset handshake, and answers
    /// IMM commands from the peripheral model.
    struct Model {
        mmio: MmioRegion,
        cpu: usize,
        present: bool,
        en_stuck: bool,
        id: [u8; 6],
        assigned: Option<u8>,
        regs: BTreeMap<u32, u8>,
        responded: bool,
        valid_seen: bool,
        last_upper: u32,
        last_lower: u32,
    }

    impl Model {
        fn read(&self, offset: u64) -> u32 {
            // SAFETY: Fixture owns the fake MMIO allocation for the
            // whole test; offsets are the manager/function registers.
            unsafe { self.mmio.read32(offset) }
        }
        fn write(&self, offset: u64, value: u32) {
            // SAFETY: Same ownership as `read`.
            unsafe { self.mmio.write32(offset, value) }
        }
        fn mgr(&self, offset: u64) -> u64 {
            regs::MANAGER_OFFSET + offset
        }
        /// Answer a pending IMM command, if one is written and no
        /// response is outstanding.
        fn answer_imm(&mut self) {
            if self.responded {
                // Retire a completed response on the pump pass after
                // the transport has had a pass to observe it (the
                // transport's clear write is indistinguishable in a
                // plain memory model, so retirement is pump-timed).
                if self.valid_seen {
                    self.write(self.mgr(regs::SW_IMM_CMD_STS), 0);
                    self.responded = false;
                    self.valid_seen = false;
                } else {
                    self.valid_seen = true;
                }
                return;
            }
            let upper = self.read(self.mgr(regs::SW_IMM_CMD_UPPER));
            if upper & 0x3000 == 0 {
                return;
            }
            let lower = self.read(self.mgr(regs::SW_IMM_CMD_LOWER));
            self.last_upper = upper;
            self.last_lower = lower;
            let dev = ((upper >> 8) & 0xF) as u8;
            let addr = ((upper & 0xFF) << 8) | ((lower >> 24) & 0xFF);
            let is_write = upper & regs::MCP_CMD_WRITE == regs::MCP_CMD_WRITE;
            let mut ack = false;
            let mut data = 0u8;
            if self.present {
                if dev == 0 && self.assigned.is_none() {
                    if is_write && addr == sdw::SCP_DEVNUMBER {
                        self.assigned = Some(((lower >> 7) & 0xF) as u8);
                        ack = true;
                    } else if !is_write && (sdw::SCP_DEVID_0..sdw::SCP_DEVID_0 + 6).contains(&addr)
                    {
                        data = self.id[(addr - sdw::SCP_DEVID_0) as usize];
                        ack = true;
                    }
                } else if Some(dev) == self.assigned {
                    if is_write {
                        self.regs.insert(addr, ((lower >> 7) & 0xFF) as u8);
                        ack = true;
                    } else if addr == sdw::SCP_DEVNUMBER {
                        data = dev;
                        ack = true;
                    } else if (sdw::SCP_DEVID_0..sdw::SCP_DEVID_0 + 6).contains(&addr) {
                        data = self.id[(addr - sdw::SCP_DEVID_0) as usize];
                        ack = true;
                    } else {
                        data = self.regs.get(&addr).copied().unwrap_or(0);
                        ack = true;
                    }
                }
            }
            let resp = if ack {
                regs::RESP_ACK | ((data as u32) << 7)
            } else {
                0
            };
            self.write(self.mgr(regs::SW_IMM_RESP_UPPER), 0);
            self.write(self.mgr(regs::SW_IMM_RESP_LOWER), resp);
            self.write(self.mgr(regs::SW_IMM_CMD_UPPER), 0);
            self.write(self.mgr(regs::SW_IMM_CMD_LOWER), 0);
            self.write(self.mgr(regs::SW_IMM_CMD_STS), regs::IMM_RES_VALID);
            self.responded = true;
        }
    }

    fn pump() {
        let pointer = MODEL.lock();
        if *pointer == 0 {
            return;
        }
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all
        // test leases are dropped.
        let model = unsafe { &mut *(*pointer as *mut Model) };
        if model.cpu != narf_lib::percpu::current_cpu() {
            return;
        }
        if !model.en_stuck {
            let en = model.read(model.mgr(regs::SW_EN));
            model.write(model.mgr(regs::SW_EN_STATUS), en);
        }
        if model.read(model.mgr(regs::SW_BUS_RESET_CTRL)) == regs::BUS_RESET_REQ {
            model.write(model.mgr(regs::SW_BUS_RESET_CTRL), regs::BUS_RESET_DONE);
        }
        model.answer_imm();
    }

    struct Fixture {
        model: Box<Model>,
        _memory: DmaBuffer,
    }

    impl Fixture {
        fn new(present: bool, en_stuck: bool) -> Self {
            let memory = alloc_coherent(0x11000, DomainId::DRIVER_0)
                .unwrap_or_else(|_| panic!("fake BAR allocation"));
            let mmio = MmioRegion {
                phys: memory.phys_addr(),
                virt: memory.cpu_mut_ptr::<u8>() as u64,
                len: memory.len() as u64,
                kind: narf_bus::bar::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            let mut fixture = Self {
                model: Box::new(Model {
                    mmio,
                    cpu: narf_lib::percpu::current_cpu(),
                    present,
                    en_stuck,
                    id: [0x10, 0x02, 0x5D, 0x07, 0x11, 0x00],
                    assigned: None,
                    regs: BTreeMap::new(),
                    responded: false,
                    valid_seen: false,
                    last_upper: 0,
                    last_lower: 0,
                }),
                _memory: memory,
            };
            *MODEL.lock() = &mut *fixture.model as *mut Model as usize;
            if !REGISTERED.swap(true, Ordering::AcqRel) {
                narf_scheduler::sleep_pumps::register_nested_only(pump);
            }
            fixture
        }
        fn transport(&self) -> AcpSdwTransport {
            AcpSdwTransport::new(self.model.mmio)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            *MODEL.lock() = 0;
        }
    }

    fn manager_init_and_imm_framing() -> TestResult {
        let fixture = Fixture::new(true, false);
        let transport = fixture.transport();
        if transport.init_manager() != Ok(()) {
            return TestResult::Fail("manager init failed");
        }
        if fixture.model.read(regs::MANAGER_OFFSET + regs::SW_EN) != 1
            || fixture
                .model
                .read(regs::MANAGER_OFFSET + regs::SW_FRAMESIZE)
                != 0
            || fixture
                .model
                .read(regs::MANAGER_OFFSET + regs::SW_IRQ_MASK_0TO7)
                != regs::IRQ_MASK_0TO7
            || fixture
                .model
                .read(regs::MANAGER_OFFSET + regs::SW_IRQ_MASK_8TO11)
                != regs::IRQ_MASK_8TO11
            || fixture
                .model
                .read(regs::MANAGER_OFFSET + regs::SW_ERROR_INTR_MASK)
                != regs::IRQ_ERROR_MASK
        {
            return TestResult::Fail("manager init register state");
        }
        // A DevID_0 read at the enumeration address: exact IMM words.
        if transport.xfer(0, sdw::SCP_DEVID_0, None) != Ok(Some(0x10)) {
            return TestResult::Fail("DevID read failed");
        }
        if fixture.model.last_upper != regs::MCP_CMD_READ
            || fixture.model.last_lower != (sdw::SCP_DEVID_0 << 24)
        {
            return TestResult::Fail("read IMM framing mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw", manager_init_and_imm_framing);

    fn imm_write_framing_and_enumeration() -> TestResult {
        let fixture = Fixture::new(true, false);
        let transport = fixture.transport();
        if transport.init_manager() != Ok(()) {
            return TestResult::Fail("manager init failed");
        }
        // The DEVNUMBER assignment write, framed exactly.
        if transport.xfer(0, sdw::SCP_DEVNUMBER, Some(1)) != Ok(None) {
            return TestResult::Fail("DEVNUMBER write failed");
        }
        if fixture.model.last_upper != regs::MCP_CMD_WRITE
            || fixture.model.last_lower != ((sdw::SCP_DEVNUMBER << 24) | (1 << 7))
        {
            return TestResult::Fail("write IMM framing mismatch");
        }
        // The peripheral now answers at 1 and no longer at 0.
        if transport.xfer(1, sdw::SCP_DEVID_0, None) != Ok(Some(0x10)) {
            return TestResult::Fail("assigned peripheral unreachable");
        }
        if transport.xfer(0, sdw::SCP_DEVID_0, None) != Err(SdwError::NoResponse) {
            return TestResult::Fail("enumeration address must be empty after assignment");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw", imm_write_framing_and_enumeration);

    fn bus_enumeration_over_acp_transport() -> TestResult {
        let fixture = Fixture::new(true, false);
        let transport = fixture.transport();
        if transport.init_manager() != Ok(()) {
            return TestResult::Fail("manager init failed");
        }
        let mut bus = Bus::new(transport);
        match bus.enumerate() {
            Ok(found) => {
                if found.len() != 1
                    || found[0].dev_num != 1
                    || found[0].id.mfg_id != 0x025D
                    || found[0].id.part_id != 0x0711
                {
                    return TestResult::Fail("enumeration over ACP transport mismatch");
                }
            }
            Err(_) => return TestResult::Fail("enumeration over ACP transport failed"),
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw", bus_enumeration_over_acp_transport);

    fn absent_peripheral_and_stuck_manager_fail_closed() -> TestResult {
        let fixture = Fixture::new(false, false);
        let transport = fixture.transport();
        if transport.init_manager() != Ok(()) {
            return TestResult::Fail("manager init failed");
        }
        if transport.xfer(0, sdw::SCP_DEVID_0, None) != Err(SdwError::NoResponse) {
            return TestResult::Fail("absent peripheral must not ACK");
        }
        let mut bus = Bus::new(transport);
        match bus.enumerate() {
            Ok([]) => {}
            _ => return TestResult::Fail("absent peripheral must enumerate empty"),
        }
        drop(bus);
        drop(fixture);
        let fixture = Fixture::new(true, true);
        let transport = fixture.transport();
        if transport.init_manager() != Err(SdwError::Timeout) {
            return TestResult::Fail("stuck manager enable must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "audio/acp63-sdw",
        absent_peripheral_and_stuck_manager_fail_closed
    );
}
