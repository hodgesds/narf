// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO transport bridge.
//!
//! Owned F0/F1 register/RAM and F2 packet adapter over `SdioFunction`.
//! Reference: Linux brcmfmac/{bcmsdh,sdio}.c. F1 words use CMD53 with
//! the 32-bit backplane access flag. F2 RX uses fixed reads, TX follows
//! incrementing writes; mailbox handling bounds readiness and flow control.
//! Multi-byte F1/F2 extents follow Linux `sdio_io_rw_ext_helper` (the
//! `sdio_memcpy_{from,to}io` / `sdio_readsb` path brcmfmac's
//! `brcmf_sdiod_ramrw`, `brcmf_sdiod_recv_pkt` and `brcmf_sdiod_send_pkt`
//! use): on a multi-block card, whole blocks go as block-mode CMD53, which
//! the SDHCI host runs through ADMA2/SDMA when it admitted host DMA, and
//! the remainder as byte-mode commands.

#![allow(dead_code)]

use narf_drivers_sdio::sdhci::cmd::{cmd52_arg, cmd53_arg};
use narf_drivers_sdio::sdio::function::{SdioError, SdioFunction};

use super::transport::{Function, PacketTransport, Transport, TransportError};
use super::{chipclk, sdio};

#[path = "sdio_ap_packet.rs"]
mod ap_packet;
#[path = "sdio_pm.rs"]
mod pm;
#[path = "sdio_stop.rs"]
mod stop;

/// Maximum byte-mode CMD53 command extent (zero count encodes512).
pub const CYW43439_F2_MAX_BURST: usize = 512;

/// SDIO F2 block size, matching Linux bcmsdh.c (F1 uses64).
pub const CYW43439_SDIO_BLOCK_SIZE: u16 = 512;
const F1_BLOCK_SIZE: u16 = 64;

// ── Argument-word encoders (pure functions for test coverage) ─────────

/// Build the CMD52 argument for a CYW43439 function read.
/// Adapts from the `Transport` `Function` enum to SDIO function index.
pub fn bridge_cmd52_read_arg(function: Function, address: u32) -> u32 {
    cmd52_arg(false, function as u8, false, address, 0)
}

/// Build the CMD52 argument for a CYW43439 function write.
pub fn bridge_cmd52_write_arg(function: Function, address: u32, data: u8) -> u32 {
    cmd52_arg(true, function as u8, false, address, data)
}

/// Build the CMD53 argument for a CYW43439 bulk read (byte mode, auto-increment).
pub fn bridge_cmd53_read_arg(function: Function, address: u32, len: u16) -> u32 {
    // 512 encodes as 0; cap at 512.
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(false, function as u8, false, true, address, count)
}

/// Build the CMD53 argument for a CYW43439 bulk write (byte mode, auto-increment).
pub fn bridge_cmd53_write_arg(function: Function, address: u32, len: u16) -> u32 {
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(true, function as u8, false, true, address, count)
}

/// Map a `SdioError` onto a `TransportError` for the
/// `Transport` trait surface.
/// Linux `sdio_io_rw_ext_helper` blocks per command: 511 (CMD53 count
/// field) bounded by the host's per-command transfer limit.
fn max_blocks(block: usize) -> usize {
    (narf_drivers_sdio::pio::MAX_TRANSFER / block).min(511)
}

/// Linux `sdio_io_rw_ext_helper` read side. `block` is the function's
/// current block size, which is also its byte-mode maximum here
/// (`sdio_max_byte_size`: F1 64, F2 512). `increment` false is
/// `sdio_readsb` (fixed FIFO address).
fn read_ext<F: SdioFunction>(
    func: &mut F,
    function: u8,
    mut address: u32,
    increment: bool,
    block: usize,
    buf: &mut [u8],
) -> Result<(), SdioError> {
    let mut done = 0;
    if func.multi_block() && buf.len() > block {
        while buf.len() - done >= block {
            let blocks = ((buf.len() - done) / block).min(max_blocks(block));
            let size = blocks * block;
            let chunk = &mut buf[done..done + size];
            if increment {
                func.cmd53_block_read(function, address, block as u16, blocks as u16, chunk)?;
            } else {
                func.cmd53_block_read_fixed(function, address, block as u16, blocks as u16, chunk)?;
            }
            done += size;
            if increment {
                address += size as u32;
            }
        }
    }
    while done < buf.len() {
        let size = (buf.len() - done).min(block);
        let chunk = &mut buf[done..done + size];
        if increment {
            func.cmd53_read(function, address, chunk)?;
            address += size as u32;
        } else {
            func.cmd53_read_fixed(function, address, chunk)?;
        }
        done += size;
    }
    Ok(())
}

/// Linux `sdio_io_rw_ext_helper` write side (incrementing, as
/// `sdio_memcpy_toio`).
fn write_ext<F: SdioFunction>(
    func: &mut F,
    function: u8,
    mut address: u32,
    block: usize,
    buf: &[u8],
) -> Result<(), SdioError> {
    let mut done = 0;
    if func.multi_block() && buf.len() > block {
        while buf.len() - done >= block {
            let blocks = ((buf.len() - done) / block).min(max_blocks(block));
            let size = blocks * block;
            func.cmd53_block_write(
                function,
                address,
                block as u16,
                blocks as u16,
                &buf[done..done + size],
            )?;
            done += size;
            address += size as u32;
        }
    }
    while done < buf.len() {
        let size = (buf.len() - done).min(block);
        func.cmd53_write(function, address, &buf[done..done + size])?;
        done += size;
        address += size as u32;
    }
    Ok(())
}

fn map_err(e: SdioError) -> TransportError {
    match e {
        SdioError::ResponseError(_) => TransportError::BadFraming,
        SdioError::LengthOverflow => TransportError::LengthOverflow,
        SdioError::BadFunction => TransportError::AddressOverflow,
        SdioError::HostError => TransportError::Timeout,
        SdioError::NotEnabled => TransportError::NotReady,
        SdioError::AddressOverflow => TransportError::AddressOverflow,
        SdioError::Unsupported => TransportError::NotReady,
        SdioError::Denied => TransportError::Denied,
        SdioError::Busy => TransportError::Busy,
    }
}

/// SDIO-backed CYW43439 transport adapter.
///
/// `F` is any type that implements `SdioFunction` — in production
/// it wraps the SDHCI host; in tests it is a `MockSdio`.
pub struct SdioTransport<F: SdioFunction> {
    proof: Option<alloc::sync::Arc<crate::brcmfmac::provision::Proof>>,
    func: F,
    packet_core: Option<u32>,
    rx_pending: bool,
    flow_stopped: bool,
    failed: bool,
    stopped: bool,
    /// Card-interrupt wake when the host delivers F1/F2 interrupts.
    interrupt: Option<alloc::sync::Arc<crate::brcmfmac::irq::Signal>>,
    /// Save-restore idle dongle sleep (`brcmf_sdio_bus_sleep`), when enabled.
    sleep: Option<Sleep>,
    /// System suspend held (`sdio_pm.rs`); the FIFO is not touched.
    suspended: Option<pm::Suspended>,
}

/// `bus->sleeping` plus the watchdog idle accounting.
#[derive(Clone, Copy, Debug)]
struct Sleep {
    asleep: bool,
    /// Last bus activity, ms.
    active_ms: u64,
    /// Card-interrupt count when the dongle went to sleep.
    interrupts_at_sleep: u64,
}

/// `SBSDIO_FUNC1_WAKEUPCTRL` and its HT-wait bit.
const F1_WAKEUP_CTRL: u32 = 0x1_001e;
const WAKEUP_HT_WAIT: u8 = 1 << 1;
/// `SDIO_CCCR_BRCM_CARDCAP`: CMD14 support + extension (no AOS no-decode).
const CCCR_BRCM_CARDCAP: u32 = 0xf0;
const CARDCAP_CMD14: u8 = (1 << 1) | (1 << 2);
/// Chipcommon `pmucapabilities` (PMU rev in [7:0]) and `sr_control1`.
const CC_PMU_CAPABILITIES: u32 = 0x1800_0604;
const CC_SR_CONTROL1: u32 = 0x1800_0508;
/// `BRCMF_WD_POLL` (10 ms) x (`BRCMF_IDLE_INTERVAL` 1 + 1): the watchdog
/// sleeps once `idlecount > idletime`.
const IDLE_MS: u64 = 20;
/// KSO readback bounded by sdio.c `PMU_MAX_TRANSITION_DLY` (1 s).
const KSO_TIMEOUT_US: u64 = 1_000_000;

fn now_ms() -> u64 {
    narf_time::monotonic_ns() / 1_000_000
}

impl<F: SdioFunction> core::fmt::Debug for SdioTransport<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioTransport")
            .field("failed", &self.failed)
            .field("packet_core", &self.packet_core)
            .finish_non_exhaustive()
    }
}
impl<F: SdioFunction> SdioTransport<F> {
    pub fn new(func: F) -> Self {
        Self {
            proof: None,
            func,
            packet_core: None,
            rx_pending: false,
            flow_stopped: false,
            failed: false,
            stopped: false,
            interrupt: None,
            sleep: None,
            suspended: None,
        }
    }
    pub(crate) fn qualify(
        mut self,
        proof: alloc::sync::Arc<crate::brcmfmac::provision::Proof>,
    ) -> Self {
        self.proof = Some(proof);
        self
    }
    fn check_qualification(&mut self) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        if self
            .proof
            .as_ref()
            .is_some_and(|proof| proof.validate().is_err())
        {
            self.failed = true;
            return Err(TransportError::NotReady);
        }
        Ok(())
    }
    /// F1 is enabled before any backplane command. The host retains matching
    /// enable/block-size state; raw CCCR writes cannot bypass its lifecycle.
    pub fn prepare(&mut self) -> Result<(), TransportError> {
        self.check_qualification()?;
        self.func.enable_func(1).map_err(map_err)?;
        self.func
            .set_block_size(1, F1_BLOCK_SIZE)
            .map_err(map_err)?;
        self.func
            .set_block_size(2, CYW43439_SDIO_BLOCK_SIZE)
            .map_err(map_err)
    }
    pub fn enable_wlan(&mut self) -> Result<(), TransportError> {
        self.check_qualification()?;
        self.func.enable_func(2).map_err(map_err)
    }
    pub fn read_backplane(&mut self, address: u32) -> Result<u32, TransportError> {
        self.window(address)?;
        self.read32(Function::Backplane, address & 0x7fff)
    }
    pub fn write_backplane(&mut self, address: u32, value: u32) -> Result<(), TransportError> {
        self.window(address)?;
        self.write32(Function::Backplane, address & 0x7fff, value)
    }
    fn window(&mut self, address: u32) -> Result<(), TransportError> {
        self.check_qualification()?;
        for write in super::backplane::window_writes(address) {
            self.func
                .cmd52_write(1, write.address, write.data)
                .map_err(map_err)?;
        }
        Ok(())
    }
    /// Linux sdio.c firmware callback: publish protocol v4 before enabling
    /// F2, and latch core mailbox/frame indications; then claim F1 and F2
    /// card interrupts (`brcmf_sdiod_intr_register`) when the host has a
    /// line. Without one the owner keeps polling.
    pub fn initialize_packets(&mut self, core: u32) -> Result<(), TransportError> {
        if !crate::brcmfmac::chip::valid_address(core) {
            return Err(TransportError::AddressOverflow);
        }
        self.write_backplane(core + 0x48, 4 << 16)?;
        self.enable_wlan()?;
        self.write_backplane(core + 0x24, 0xf0 | (1 << 29))?;
        self.packet_core = Some(core);
        let signal = crate::brcmfmac::irq::Signal::new();
        let raised = signal.clone();
        if self
            .func
            .enable_card_interrupt(
                (1 << 1) | (1 << 2),
                alloc::sync::Arc::new(move || raised.raise()),
            )
            .map_err(map_err)?
        {
            self.interrupt = Some(signal);
        }
        Ok(())
    }
    /// Linux `brcmf_sdio_kso_init` + `brcmf_chip_sr_capable` (43439: PMU
    /// rev >= 17 and chipcommon `sr_control1` != 0) + `brcmf_sdio_sr_init`,
    /// enabling idle dongle sleep. Only with delivered card interrupts: a
    /// polled bus would wake the dongle on every poll. `Ok(false)` leaves
    /// the dongle awake (non-SR chips' clock-drop idle is not ported).
    pub fn initialize_sleep(&mut self, sdio_core_rev: u8) -> Result<bool, TransportError> {
        if self.interrupt.is_none() || self.packet_core.is_none() {
            return Ok(false);
        }
        if sdio_core_rev >= 12 {
            let value = self
                .func
                .cmd52_read(1, sdio::F1_SLEEP_CSR)
                .map_err(map_err)?;
            if value & chipclk::sleep::KSO == 0 {
                self.func
                    .cmd52_write(1, sdio::F1_SLEEP_CSR, value | chipclk::sleep::KSO)
                    .map_err(map_err)?;
            }
        } else {
            return Ok(false);
        }
        let pmu_rev = self.read_backplane(CC_PMU_CAPABILITIES)? & 0xff;
        if pmu_rev < 17 || self.read_backplane(CC_SR_CONTROL1)? == 0 {
            return Ok(false);
        }
        let wake = self.func.cmd52_read(1, F1_WAKEUP_CTRL).map_err(map_err)?;
        self.func
            .cmd52_write(1, F1_WAKEUP_CTRL, wake | WAKEUP_HT_WAIT)
            .map_err(map_err)?;
        self.func
            .cmd52_write(0, CCCR_BRCM_CARDCAP, CARDCAP_CMD14)
            .map_err(map_err)?;
        self.func
            .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, chipclk::FORCE_HT_REQ)
            .map_err(map_err)?;
        self.sleep = Some(Sleep {
            asleep: false,
            active_ms: now_ms(),
            interrupts_at_sleep: 0,
        });
        Ok(true)
    }
    /// `brcmf_sdio_kso_control`: write KSO, then read back (synced to the
    /// 32 kHz PMU clock) until KSO (and DEVON on wake) match.
    fn kso(&mut self, on: bool) -> Result<(), TransportError> {
        let value = if on { chipclk::sleep::KSO } else { 0 };
        self.func
            .cmd52_write(1, sdio::F1_SLEEP_CSR, value)
            .map_err(map_err)?;
        let (mask, expected) = if on {
            let both = chipclk::sleep::KSO | chipclk::sleep::DEV_ON;
            // usleep_range(2000, 3000) before the first readback.
            let settle = narf_time::Deadline::after_us(2_000);
            narf_scheduler::responsive_spin_until(|| false, settle);
            (both, both)
        } else {
            (chipclk::sleep::KSO, 0)
        };
        let mut failure = None;
        let ok = narf_scheduler::responsive_spin_until(
            || match self.func.cmd52_read(1, sdio::F1_SLEEP_CSR) {
                Ok(read) => read & mask == expected,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(KSO_TIMEOUT_US),
        );
        if let Some(error) = failure {
            return Err(map_err(error));
        }
        if !ok {
            return Err(TransportError::Timeout);
        }
        Ok(())
    }
    /// `brcmf_sdio_bus_sleep(.., false, ..)`: KSO wake, then HT available.
    fn wake(&mut self) -> Result<(), TransportError> {
        let Some(sleep) = self.sleep else {
            return Ok(());
        };
        if sleep.asleep {
            self.kso(true)?;
            let mut failure = None;
            let ok = narf_scheduler::responsive_spin_until(
                || match self.func.cmd52_read(1, sdio::F1_CHIPCLK_CTRL) {
                    Ok(read) => read & chipclk::HT_AVAIL != 0,
                    Err(error) => {
                        failure = Some(error);
                        true
                    }
                },
                narf_time::Deadline::after_us(KSO_TIMEOUT_US),
            );
            if let Some(error) = failure {
                return Err(map_err(error));
            }
            if !ok {
                return Err(TransportError::Timeout);
            }
        }
        self.sleep = Some(Sleep {
            asleep: false,
            active_ms: now_ms(),
            ..sleep
        });
        Ok(())
    }
    /// `brcmf_sdio_bus_sleep(.., true, ..)` on SR chips: keep an ALP request
    /// if none is outstanding, then clear KSO.
    fn enter_sleep(&mut self) -> Result<(), TransportError> {
        let clock = self
            .func
            .cmd52_read(1, sdio::F1_CHIPCLK_CTRL)
            .map_err(map_err)?;
        if clock & 0x1f == 0 {
            self.func
                .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, 0x08)
                .map_err(map_err)?;
        }
        self.kso(false)?;
        let interrupts = self.interrupt.as_ref().map_or(0, |s| s.count());
        if let Some(sleep) = self.sleep.as_mut() {
            sleep.asleep = true;
            sleep.interrupts_at_sleep = interrupts;
        }
        Ok(())
    }
    /// Whether the dongle is in save-restore sleep.
    pub fn asleep(&self) -> bool {
        self.sleep.is_some_and(|s| s.asleep)
    }
    fn mailbox(&mut self) -> Result<(), TransportError> {
        let core = self.packet_core.ok_or(TransportError::NotReady)?;
        let status = self.read_backplane(core + 0x20)?;
        if status == u32::MAX || status & 0xff00 != 0 {
            return Err(TransportError::ChipFlowError);
        }
        // FC_CHANGE is W1C; STATE reflects the current global stop state.
        if status & 0x20 != 0 {
            self.write_backplane(core + 0x20, 0x20)?;
            // A second CHANGE may race the ACK. Linux treats either STATE
            // or a reasserted CHANGE as stopped until the next debounce.
            self.flow_stopped = self.read_backplane(core + 0x20)? & 0x30 != 0;
        } else {
            self.flow_stopped = status & 0x10 != 0;
        }
        let pending = status & ((1 << 6) | (1 << 7) | (1 << 29));
        if pending != 0 {
            self.write_backplane(core + 0x20, pending)?;
        }
        if status & (1 << 7) != 0 {
            let data = self.read_backplane(core + 0x4c)?;
            self.write_backplane(core + 0x40, 2)?; // SMB_INT_ACK.
            if data & 0x10 != 0 {
                return Err(TransportError::NotReady);
            }
            if data & 0xa != 0 && (data >> 16) & 255 != 4 {
                return Err(TransportError::BadFraming);
            }
            if data & 1 != 0 {
                self.rx_pending = true;
            }
        }
        if status & (1 << 6) != 0 {
            self.rx_pending = true;
        }
        Ok(())
    }
    fn receive_inner(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.mailbox()?;
        if !self.rx_pending {
            return Ok(0);
        }
        if buffer.len() < 64 {
            return Err(TransportError::LengthOverflow);
        }
        self.window(0x1800_0000)?;
        self.func
            .cmd53_read_fixed(2, 0x8000, &mut buffer[..64])
            .map_err(map_err)?;
        let length = usize::from(u16::from_le_bytes([buffer[0], buffer[1]]));
        let inverted = u16::from_le_bytes([buffer[2], buffer[3]]);
        if length == 0 && inverted == 0 {
            self.rx_pending = false;
            return Ok(0);
        }
        if length < 12 || !(length as u16) != inverted || length > super::runtime::MAX_PACKET {
            return Err(TransportError::BadFraming);
        }
        let physical = length.max(64).next_multiple_of(4);
        if physical > buffer.len() {
            return Err(TransportError::LengthOverflow);
        }
        if physical > 64 {
            read_ext(
                &mut self.func,
                2,
                0x8000,
                false,
                usize::from(CYW43439_SDIO_BLOCK_SIZE),
                &mut buffer[64..physical],
            )
            .map_err(map_err)?;
        }
        Ok(length)
    }
}
impl<F: SdioFunction> crate::brcmfmac::chip::Backplane for SdioTransport<F> {
    fn read32(&mut self, address: u32) -> Result<u32, crate::brcmfmac::chip::Error> {
        self.read_backplane(address)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), crate::brcmfmac::chip::Error> {
        self.write_backplane(address, value)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
}
impl<F: SdioFunction> Transport for SdioTransport<F> {
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError> {
        self.check_qualification()?;
        let mut bytes = [0; 4];
        if function == Function::Backplane && address < 0x10000 {
            if address & 3 != 0 || address & 0x7fff > 0x7ffc {
                return Err(TransportError::AddressOverflow);
            }
            self.func
                .cmd53_read(1, address | 0x8000, &mut bytes)
                .map_err(map_err)?;
        } else {
            self.read_burst(function, address, &mut bytes)?;
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if function == Function::Backplane && address < 0x10000 {
            if address & 3 != 0 || address & 0x7fff > 0x7ffc {
                return Err(TransportError::AddressOverflow);
            }
            self.func
                .cmd53_write(1, address | 0x8000, &value.to_le_bytes())
                .map_err(map_err)
        } else {
            self.write_burst(function, address, &value.to_le_bytes())
        }
    }
    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &mut [u8],
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if address > 0x1ffff || buf.len() > (0x20000 - address) as usize {
            return Err(TransportError::AddressOverflow);
        }
        if function == Function::Bus || buf.len() == 1 {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self
                    .func
                    .cmd52_read(function as u8, address + i as u32)
                    .map_err(map_err)?;
            }
        } else {
            let stride = if function == Function::Backplane {
                usize::from(F1_BLOCK_SIZE)
            } else {
                512
            };
            read_ext(&mut self.func, function as u8, address, true, stride, buf)
                .map_err(map_err)?;
        }
        Ok(())
    }
    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &[u8],
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if address > 0x1ffff || buf.len() > (0x20000 - address) as usize {
            return Err(TransportError::AddressOverflow);
        }
        if function == Function::Bus || buf.len() == 1 {
            for (i, &b) in buf.iter().enumerate() {
                let at = address + i as u32;
                if function == Function::Bus && at == super::sdio::CCCR_IO_ENABLE {
                    for number in 1..=7 {
                        if b & (1 << number) != 0 {
                            self.func.enable_func(number).map_err(map_err)?;
                        }
                    }
                } else {
                    self.func
                        .cmd52_write(function as u8, at, b)
                        .map_err(map_err)?;
                }
            }
        } else {
            let stride = if function == Function::Backplane {
                usize::from(F1_BLOCK_SIZE)
            } else {
                512
            };
            write_ext(&mut self.func, function as u8, address, stride, buf).map_err(map_err)?;
        }
        Ok(())
    }
}
impl<F: SdioFunction + Send> PacketTransport for SdioTransport<F> {
    fn transmit_ap_packet(
        &mut self,
        packet: &[u8],
        original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<(), TransportError> {
        SdioTransport::transmit_ap_packet(self, packet, original)
    }
    fn transmit_ap_control(
        &mut self,
        packet: &[u8],
        original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<(), TransportError> {
        SdioTransport::transmit_ap_control(self, packet, original)
    }
    fn completed_prefix(&mut self) -> Result<bool, TransportError> {
        self.check_qualification()?;
        // A sleeping/no-IRQ fast return is not an actual FIFO observation.
        self.wake()?;
        self.mailbox()?;
        Ok(!self.rx_pending)
    }
    fn ap_source(&self) -> Option<crate::brcmfmac::ap_source::Source> {
        if self.failed || self.stopped {
            return None;
        }
        crate::brcmfmac::ap_source::Source::sdio(self.func.source()?, self.proof.as_ref()?.clone())
    }
    fn confirmed_stop(&mut self) -> Result<(), TransportError> {
        SdioTransport::confirmed_stop(self)
    }
    fn suspend(&mut self, wake: bool) -> Result<(), TransportError> {
        SdioTransport::suspend_bus(self, wake)
    }
    fn resume(&mut self) -> Result<(), TransportError> {
        SdioTransport::resume_bus(self)
    }
    fn wowl_supported(&mut self) -> bool {
        SdioTransport::wowl_supported(self)
    }
    fn interrupt(&self) -> Option<alloc::sync::Arc<crate::brcmfmac::irq::Signal>> {
        self.interrupt.clone()
    }
    fn interrupt_serviced(&mut self) {
        if self.interrupt.is_some() && !self.failed && self.suspended.is_none() {
            self.func.rearm_card_interrupt();
        }
    }
    /// `brcmf_sdio_bus_watchdog` idle path: sleep once the bus has been
    /// idle for `IDLE_MS`.
    fn idle(&mut self) {
        let Some(sleep) = self.sleep else {
            return;
        };
        if self.failed
            || self.suspended.is_some()
            || sleep.asleep
            || now_ms().saturating_sub(sleep.active_ms) < IDLE_MS
        {
            return;
        }
        if self.enter_sleep().is_err() {
            self.failed = true;
        }
    }
    fn receive_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        if self.suspended.is_some() {
            return Ok(0);
        }
        // A sleeping dongle raises a card interrupt when it has work; the
        // backstop timer alone must not wake it.
        if let Some(sleep) = self.sleep.filter(|s| s.asleep) {
            if self.interrupt.as_ref().map_or(0, |s| s.count()) == sleep.interrupts_at_sleep {
                return Ok(0);
            }
        }
        let result = self.wake().and_then(|()| self.receive_inner(buffer));
        if let (Ok(n), Some(sleep)) = (&result, self.sleep.as_mut()) {
            if *n != 0 {
                sleep.active_ms = now_ms();
            }
        }
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn transmit_packet(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        if self.suspended.is_some() {
            return Err(TransportError::Busy);
        }
        if packet.len() < 12 || packet.len() > super::runtime::MAX_PACKET || packet.len() % 4 != 0 {
            return Err(TransportError::LengthOverflow);
        }
        if let Err(error) = self.wake().and_then(|()| self.mailbox()) {
            self.failed = true;
            return Err(error);
        }
        if self.flow_stopped {
            return Err(TransportError::Busy);
        }
        self.window(0x1800_0000)?;
        // Linux uses incrementing memcpy_toio for F2 TX and fixed readsb
        // for F2 RX: whole blocks in block mode on a multi-block card, then
        // byte-mode commands of at most 512 bytes.
        if let Err(error) = write_ext(
            &mut self.func,
            2,
            0x8000,
            usize::from(CYW43439_SDIO_BLOCK_SIZE),
            packet,
        )
        .map_err(map_err)
        {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sdio_bridge_tests.rs"]
mod runtime_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Argument-word round-trip against reference ─────────────────────

    fn smoke_bridge_cmd52_read_backplane() -> TestResult {
        // Read from F1 (backplane) address 0x000A — same as soypat/cyw43439
        // sdio.go F1_SBADDRLOW read sequence.
        let arg = bridge_cmd52_read_arg(Function::Backplane, 0x000A);
        // Read bit should be clear.
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit must be 0");
        }
        // Function 1.
        if (arg >> 28) & 7 != 1 {
            return TestResult::Fail("function must be 1 (backplane)");
        }
        // Address field (bits 25:9).
        if (arg >> 9) & 0x1_FFFF != 0x000A {
            return TestResult::Fail("address mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_read_backplane
    );

    fn smoke_bridge_cmd52_write_io_enable() -> TestResult {
        // Write IO_ENABLE to enable F2 — matches Embassy cyw43 SDIO init.
        // CCCR IO_ENABLE = 0x02, data = 0x04 (bit 2 = F2 enable).
        let arg = bridge_cmd52_write_arg(Function::Bus, 0x02, 0x04);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 0 {
            return TestResult::Fail("function must be 0 (CCCR/Bus)");
        }
        if (arg >> 9) & 0x1_FFFF != 0x02 {
            return TestResult::Fail("IO_ENABLE address mismatch");
        }
        if arg & 0xFF != 0x04 {
            return TestResult::Fail("IO_ENABLE data byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_write_io_enable
    );

    fn smoke_bridge_cmd53_wlan_burst() -> TestResult {
        // 256-byte bulk write to F2, address 0 — matches soypat/cyw43439
        // wlan.go TX path and Embassy cyw43 send_packet().
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 256);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 2 {
            return TestResult::Fail("function must be 2 (WLAN)");
        }
        // byte mode: block bit = 0.
        if (arg >> 27) & 1 != 0 {
            return TestResult::Fail("block-mode bit must be 0 for byte mode");
        }
        // auto-increment: incr bit = 1.
        if (arg >> 26) & 1 != 1 {
            return TestResult::Fail("auto-increment must be 1");
        }
        if arg & 0x1FF != 256 {
            return TestResult::Fail("byte count mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_wlan_burst
    );

    fn smoke_bridge_cmd53_512_encodes_zero() -> TestResult {
        // Per SDIO spec: count field = 0 means 512 bytes in byte mode.
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 512);
        if arg & 0x1FF != 0 {
            return TestResult::Fail("count=512 should encode as 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_512_encodes_zero
    );
}
