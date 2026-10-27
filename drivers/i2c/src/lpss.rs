//! Intel PCH LPSS I2C controller — Synopsys DesignWare core, INT3xxx /
//! 80860Fxx / 808622xx ACPI HIDs.
//!
//! Stage-1 implementation — discovery + MMIO mapping + LPSS ungate +
//! DW I2C programming + PIO transactions.
//!
//! Bus speed: when any device on the bus declares a
//! `ConnectionSpeed` in its `_CRS` `I2cSerialBus` descriptor, the
//! composed speed (#772, `crate::dw_speed`) is programmed at
//! `enable()` — but only on HIDs whose DW input clock is grounded
//! (see [`ic_clk_khz_for_hid`]); the counts are never derived from
//! a guessed clock. With no declaration, or an ungrounded clock,
//! the fixed constants below are programmed, as before #772.
//!
//! What "LPSS" means here
//! ----------------------
//! Intel's "Low-Power Sub-System" wraps the same DesignWare APB I2C IP
//! AMD FCH uses, but adds:
//! - An LPSS-private register page above the DW core (at offset 0x200;
//!   holds PCH-specific clock-gating + reset bits).
//! - On modern silicon (Tiger Lake / Alder Lake / Raptor Lake), the
//!   controllers are presented through ACPI as MMIO platform devices
//!   ("LPSS-ACPI" mode).
//!
//! Sources (all public, cited per the project's GPL-2.0-or-later
//! relicense):
//! - Linux `drivers/i2c/busses/i2c-designware-platdrv.c` — the
//!   `dw_i2c_acpi_match` table is the authoritative source for the
//!   HID list below.
//! - Linux `drivers/acpi/acpi_lpss.c` and `drivers/mfd/intel-lpss.c` —
//!   LPSS register layout + ACPI-presented LPSS device wiring.
//! - Intel "Tiger Lake Platform Controller Hub EDS Vol 2", "Alder
//!   Lake-P PCH EDS" — LPSS register set + IC_COMP_TYPE confirmation.
//! - Synopsys "DW_apb_i2c Databook" — DW core register map.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::resource::ResourceItem;
use narf_lib::mutex::Mutex as AsyncMutex;
use narf_memory::PhysAddr;

use crate::dw::{DwRegs, MmioDwRegs};
use crate::{I2cBus, I2cError, I2cOp};

// ── ACPI HIDs we recognise ─────────────────────────────────────────

const LPSS_I2C_HIDS: &[&str] = &[
    // Tiger Lake / Alder Lake / Raptor Lake
    "INT34B7", "INT34BA", "INT34C5", // Skylake / Kaby Lake era
    "INT3446", "INT3447", // Haswell / Broadwell
    "INT33C2", "INT33C3", "INT3432", "INT3433", // Lakefield / Jasper Lake
    "INTC1009", "INTC1010", // Older PCI-mode LPSS (Baytrail / Apollo Lake)
    "80860F41", "808622C1",
];

// ── DW I2C register offsets ────────────────────────────────────────
const IC_CON: u64 = 0x00;
const IC_TAR: u64 = 0x04;
const IC_DATA_CMD: u64 = 0x10;
const IC_SS_SCL_HCNT: u64 = 0x14;
const IC_SS_SCL_LCNT: u64 = 0x18;
const IC_FS_SCL_HCNT: u64 = 0x1c;
const IC_FS_SCL_LCNT: u64 = 0x20;
const IC_INTR_MASK: u64 = 0x30;
const IC_RAW_INTR_STAT: u64 = 0x34;
const IC_RX_TL: u64 = 0x38;
const IC_TX_TL: u64 = 0x3c;
const IC_CLR_INTR: u64 = 0x40;
const IC_CLR_TX_ABRT: u64 = 0x54;
const IC_ENABLE: u64 = 0x6c;
const IC_STATUS: u64 = 0x70;
const IC_RXFLR: u64 = 0x78;
const IC_TX_ABRT_SOURCE: u64 = 0x80;
const IC_ENABLE_STATUS: u64 = 0x9c;
const IC_COMP_TYPE: u64 = 0xfc;

// ── LPSS Private Registers ─────────────────────────────────────────
const LPSS_PRIV_OFFSET: u64 = 0x200;
const LPSS_PRIV_RESETS: u64 = LPSS_PRIV_OFFSET + 0x04;
const LPSS_PRIV_REMAP_ADDR: u64 = LPSS_PRIV_OFFSET + 0x40;

// ── IC_CON bits ────────────────────────────────────────────────────
const IC_CON_MASTER_MODE: u32 = 1 << 0;
const IC_CON_SPEED_FAST: u32 = 0b10 << 1; // 400 kHz
const IC_CON_IC_SLAVE_DISABLE: u32 = 1 << 6;
const IC_CON_RESTART_EN: u32 = 1 << 5;

// ── IC_DATA_CMD bits ───────────────────────────────────────────────
const DATA_CMD_READ: u32 = 1 << 8;
const DATA_CMD_STOP: u32 = 1 << 9;

// ── IC_RAW_INTR_STAT bits ──────────────────────────────────────────
const INTR_TX_ABRT: u32 = 1 << 6;

// ── IC_STATUS bits ─────────────────────────────────────────────────
const STATUS_ACTIVITY: u32 = 1 << 0;
const STATUS_TFNF: u32 = 1 << 1; // TX FIFO not full
const STATUS_TFE: u32 = 1 << 2; // TX FIFO empty
const STATUS_RFNE: u32 = 1 << 3; // RX FIFO not empty

// ── IC_COMP_TYPE expected value ────────────────────────────────────
const DW_COMP_TYPE_MAGIC: u32 = 0x4457_0140;

// ── DW_apb_i2c clock + timing constants ────────────────────────────
// Nominal 100 kHz / 400 kHz defaults.
const SS_HCNT: u32 = 0x01b0;
const SS_LCNT: u32 = 0x01fb;
const FS_HCNT: u32 = 0x002f;
const FS_LCNT: u32 = 0x006a;

// ── Bus mutex timeout ──────────────────────────────────────────────
const TRANSFER_TIMEOUT_POLLS: u32 = 100_000;

/// One Intel LPSS I2C controller.
///
/// Generic over the register backend `R` (the `DwRegs` seam in
/// `crate::dw`): production uses `MmioDwRegs`; fixtures plug the
/// behavioural DW model so the transfer state machine can run
/// end-to-end without silicon (#1029).
pub struct LpssI2c<R = MmioDwRegs> {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    regs: R,
    irq_vector: Option<u8>,
    bus: AsyncMutex<()>,
    enabled: AtomicBool,
    last_target: AtomicU8,
    /// DW core input clock in kHz for this controller's HID, when
    /// grounded ([`ic_clk_khz_for_hid`]). `None` = not grounded;
    /// speed-derived programming is then disabled (#772).
    ic_clk_khz: Option<u32>,
    /// Composed `_CRS` bus speed for this controller's bus
    /// (#772), set by probe via [`crate::dw_speed::bus_speed_hz`]
    /// before `enable()`. `None` = nothing on the bus declares a
    /// speed; `enable()` keeps the fixed default constants.
    bus_speed_hz: Option<u32>,
}

/// DW input clock (kHz) per ACPI HID, grounded in Linux
/// `drivers/mfd/intel-lpss-acpi.c`'s `intel_lpss_platform_info`
/// table (`clk_rate` of the matching `*_i2c_info`):
/// - `INT3446` / `INT3447` (Sunrise Point I2C) → `spt_i2c_info`,
///   120 MHz.
/// - `INT34B7` (Cannon Lake-lineage I2C, incl. Tiger Lake) →
///   `cnl_i2c_info`, 216 MHz.
///
/// Every other HID in [`LPSS_I2C_HIDS`] returns `None` here: the
/// sources above do not pin a rate for them (several are
/// PCI-mode or predate the table), so #772 speed programming
/// stays off for those controllers rather than deriving counts
/// from a guessed clock. Extend the table only with a cited
/// rate, per HID.
pub fn ic_clk_khz_for_hid(hid: &str) -> Option<u32> {
    match hid {
        "INT3446" | "INT3447" => Some(120_000),
        "INT34B7" => Some(216_000),
        _ => None,
    }
}

impl<R> core::fmt::Debug for LpssI2c<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LpssI2c")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .field("mmio_len", &self.mmio_len)
            .field("irq_vector", &self.irq_vector)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish()
    }
}

impl LpssI2c<MmioDwRegs> {
    pub fn new(name: String, mmio_base: PhysAddr, mmio_len: u64, irq_vector: Option<u8>) -> Self {
        Self::with_regs(
            name,
            mmio_base,
            mmio_len,
            irq_vector,
            MmioDwRegs::new(mmio_base),
        )
    }
}

impl<R: DwRegs> LpssI2c<R> {
    /// Construct a controller over a caller-supplied register
    /// backend. This is the fixture seam (#1029): production goes
    /// through [`LpssI2c::new`], which builds the `MmioDwRegs`
    /// backend; smokes pass the behavioural DW model instead.
    /// `mmio_base` is retained for diagnostics + bounds assertions;
    /// all register traffic goes through `regs`.
    pub fn with_regs(
        name: String,
        mmio_base: PhysAddr,
        mmio_len: u64,
        irq_vector: Option<u8>,
        regs: R,
    ) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            regs,
            irq_vector,
            bus: AsyncMutex::new(()),
            enabled: AtomicBool::new(false),
            last_target: AtomicU8::new(0xff),
            ic_clk_khz: None,
            bus_speed_hz: None,
        }
    }

    /// Record the DW input clock for this controller (#772), in
    /// kHz — see [`ic_clk_khz_for_hid`]. Probe calls this before
    /// `enable()`.
    pub fn set_ic_clk_khz(&mut self, ic_clk_khz: Option<u32>) {
        self.ic_clk_khz = ic_clk_khz;
    }

    /// Record the composed `_CRS` bus speed for this controller's
    /// bus (#772). Probe calls this before `enable()`; `None`
    /// (the default) keeps the fixed-constant programming.
    pub fn set_bus_speed_hz(&mut self, speed_hz: Option<u32>) {
        self.bus_speed_hz = speed_hz;
    }

    /// The bus speed recorded by [`Self::set_bus_speed_hz`], for
    /// probe logging.
    pub fn bus_speed_hz(&self) -> Option<u32> {
        self.bus_speed_hz
    }

    /// # Safety
    /// `off + 4` must lie within the MMIO window described by
    /// `self.mmio_base..self.mmio_base + self.mmio_len`, and that window
    /// must be a valid, mapped DW I2C register region. The caller is
    /// responsible for any ordering/exclusivity required by the register.
    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: `off` is a register offset the caller has
        // guaranteed lies inside the window (see the `# Safety`
        // contract above), and the backend upholds the DwRegs
        // contract for that window.
        unsafe { self.regs.read32(off) }
    }

    /// # Safety
    /// `off + 4` must lie within the MMIO window described by
    /// `self.mmio_base..self.mmio_base + self.mmio_len`, and that window
    /// must be a valid, mapped DW I2C register region. The caller is
    /// responsible for any ordering/exclusivity required by the register.
    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: `off` is a register offset the caller has
        // guaranteed lies inside the window (see the `# Safety`
        // contract above), and the backend upholds the DwRegs
        // contract for that window.
        unsafe { self.regs.write32(off, val) }
    }

    /// Read IC_COMP_TYPE and confirm we're talking to a DW I2C IP.
    /// Ungates the LPSS core first so the register file responds.
    pub fn probe_component_type(&self) -> Result<(), I2cError> {
        // SAFETY: probe-time, exclusive access to the MMIO window.
        unsafe {
            // Un-gate LPSS core
            self.write32(LPSS_PRIV_RESETS, 0);
            self.write32(LPSS_PRIV_RESETS, 0x7); // FUNC | APB | IDMA
                                                 // Program Remap Address (64-bit)
            self.write32(
                LPSS_PRIV_REMAP_ADDR,
                (self.mmio_base.raw() & 0xFFFFFFFF) as u32,
            );
            self.write32(
                LPSS_PRIV_REMAP_ADDR + 4,
                (self.mmio_base.raw() >> 32) as u32,
            );
        }

        // SAFETY: IC_COMP_TYPE is a fixed DW I2C register offset well within
        // the mapped MMIO window; probe runs serially so we have exclusive
        // access to the register file.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ct = unsafe { self.read32(IC_COMP_TYPE) };
        if ct == DW_COMP_TYPE_MAGIC {
            Ok(())
        } else {
            Err(I2cError::BadHardware)
        }
    }

    /// Program the controller as a 7-bit master with restart
    /// enabled.
    ///
    /// Timing: when probe recorded both a composed `_CRS` bus
    /// speed ([`Self::set_bus_speed_hz`], #772) and a grounded
    /// input clock ([`Self::set_ic_clk_khz`]), the SCL counts are
    /// derived via [`crate::dw_speed::timings_for`] and
    /// `IC_CON.SPEED` selects the composed mode; otherwise the
    /// fixed 400 kHz constants are programmed, byte-for-byte the
    /// pre-#772 behaviour.
    pub fn enable(&self) -> Result<(), I2cError> {
        let (speed_bits, ss_hcnt, ss_lcnt, fs_hcnt, fs_lcnt) =
            match (self.bus_speed_hz, self.ic_clk_khz) {
                (Some(hz), Some(ic_clk_khz)) => {
                    let t = crate::dw_speed::timings_for(ic_clk_khz, hz);
                    (
                        t.mode.ic_con_speed_bits(),
                        t.ss_hcnt,
                        t.ss_lcnt,
                        t.fs_hcnt,
                        t.fs_lcnt,
                    )
                }
                _ => (IC_CON_SPEED_FAST, SS_HCNT, SS_LCNT, FS_HCNT, FS_LCNT),
            };
        // SAFETY: bus mutex held externally or run serially during probe.
        unsafe {
            self.write32(IC_ENABLE, 0);
            for _ in 0..1000 {
                if self.read32(IC_ENABLE_STATUS) & 1 == 0 {
                    break;
                }
            }
            self.write32(
                IC_CON,
                IC_CON_MASTER_MODE | speed_bits | IC_CON_IC_SLAVE_DISABLE | IC_CON_RESTART_EN,
            );
            self.write32(IC_SS_SCL_HCNT, ss_hcnt);
            self.write32(IC_SS_SCL_LCNT, ss_lcnt);
            self.write32(IC_FS_SCL_HCNT, fs_hcnt);
            self.write32(IC_FS_SCL_LCNT, fs_lcnt);
            self.write32(IC_RX_TL, 0);
            self.write32(IC_TX_TL, 0);
            self.write32(IC_INTR_MASK, 0);
            let _ = self.read32(IC_CLR_INTR);
            self.write32(IC_ENABLE, 1);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub fn disable(&self) {
        // SAFETY: IC_ENABLE is a fixed DW I2C register offset within the
        // mapped MMIO window; clearing it disables the controller.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.write32(IC_ENABLE, 0);
        }
        self.enabled.store(false, Ordering::Release);
    }

    fn program_target(&self, addr: u8) {
        // SAFETY: all offsets (IC_ENABLE, IC_ENABLE_STATUS, IC_TAR) are fixed
        // DW I2C register offsets within the mapped MMIO window; the caller
        // (transfer) holds the bus mutex, so access is exclusive.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.write32(IC_ENABLE, 0);
            for _ in 0..1000 {
                if self.read32(IC_ENABLE_STATUS) & 1 == 0 {
                    break;
                }
            }
            self.write32(IC_TAR, (addr as u32) & 0x7f);
            self.write32(IC_ENABLE, 1);
        }
        self.last_target.store(addr, Ordering::Release);
    }

    fn check_abort(&self) -> Result<(), I2cError> {
        // SAFETY: IC_RAW_INTR_STAT is a fixed DW I2C register offset within
        // the mapped MMIO window; called only from transfer with the bus
        // mutex held, so access is exclusive.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let raw = unsafe { self.read32(IC_RAW_INTR_STAT) };
        if raw & INTR_TX_ABRT != 0 {
            // SAFETY: IC_TX_ABRT_SOURCE is a fixed register offset within the
            // mapped MMIO window; exclusive access via the bus mutex.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let src = unsafe { self.read32(IC_TX_ABRT_SOURCE) };
            // SAFETY: IC_CLR_TX_ABRT is a fixed register offset within the
            // mapped MMIO window; reading it clears the abort latch.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let _ = unsafe { self.read32(IC_CLR_TX_ABRT) };
            if src & 0b1001 != 0 {
                Err(I2cError::Nack)
            } else if src & (1 << 12) != 0 {
                Err(I2cError::ArbLost)
            } else {
                Err(I2cError::Abort(src))
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl<R: DwRegs> I2cBus for LpssI2c<R> {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(I2cError::BadHardware);
        }
        let _bus_guard = self.bus.lock().await;

        if self.last_target.load(Ordering::Acquire) != addr {
            self.program_target(addr);
        }

        let total_ops = ops.len();
        for (i, op) in ops.iter_mut().enumerate() {
            let is_last = i + 1 == total_ops;
            match op {
                I2cOp::Write(data) => {
                    let len = data.len();
                    for (j, &byte) in data.iter().enumerate() {
                        let last_byte = j + 1 == len;
                        let mut cmd = byte as u32;
                        if is_last && last_byte {
                            cmd |= DATA_CMD_STOP;
                        }
                        wait_until(
                            || {
                                self.check_abort()?;
                                // SAFETY: IC_STATUS is a fixed register offset
                                // within the mapped MMIO window; bus mutex held.
                                // SAFETY: Valid MMIO bounds or trusted driver environment
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
                        // SAFETY: IC_DATA_CMD is a fixed register offset within
                        // the mapped MMIO window; bus mutex held and TFNF was
                        // just observed, so the TX FIFO has room.
                        // SAFETY: Valid MMIO bounds or trusted driver environment
                        unsafe {
                            self.write32(IC_DATA_CMD, cmd);
                        }
                    }
                }
                I2cOp::Read(buf) => {
                    let len = buf.len();
                    let mut issued = 0usize;
                    let mut received = 0usize;
                    while received < len {
                        while issued < len {
                            // SAFETY: IC_STATUS is a fixed register offset
                            // within the mapped MMIO window; bus mutex held.
                            // SAFETY: Valid MMIO bounds or trusted driver environment
                            let tfnf = unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0;
                            if !tfnf {
                                break;
                            }
                            let last_byte = issued + 1 == len;
                            let mut cmd = DATA_CMD_READ;
                            if is_last && last_byte {
                                cmd |= DATA_CMD_STOP;
                            }
                            // SAFETY: IC_DATA_CMD is a fixed register offset
                            // within the mapped MMIO window; bus mutex held and
                            // TFNF was just observed, so the TX FIFO has room.
                            // SAFETY: Valid MMIO bounds or trusted driver environment
                            unsafe {
                                self.write32(IC_DATA_CMD, cmd);
                            }
                            issued += 1;
                        }
                        wait_until(
                            || {
                                self.check_abort()?;
                                // SAFETY: IC_STATUS is a fixed register offset
                                // within the mapped MMIO window; bus mutex held.
                                // SAFETY: Valid MMIO bounds or trusted driver environment
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_RFNE != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
                        // SAFETY: IC_RXFLR is a fixed register offset within the
                        // mapped MMIO window; bus mutex held.
                        // SAFETY: Valid MMIO bounds or trusted driver environment
                        let avail = unsafe { self.read32(IC_RXFLR) } as usize;
                        let take = avail.min(len - received);
                        for _ in 0..take {
                            // SAFETY: IC_DATA_CMD is a fixed register offset
                            // within the mapped MMIO window; `take <= avail` so
                            // the RX FIFO holds an unread byte; bus mutex held.
                            // SAFETY: Valid MMIO bounds or trusted driver environment
                            buf[received] = unsafe { self.read32(IC_DATA_CMD) } as u8;
                            received += 1;
                        }
                    }
                }
            }
        }

        wait_until(
            || {
                self.check_abort()?;
                // SAFETY: IC_STATUS is a fixed register offset within the
                // mapped MMIO window; bus mutex held.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                let st = unsafe { self.read32(IC_STATUS) };
                Ok(st & STATUS_ACTIVITY == 0 && st & STATUS_TFE != 0)
            },
            TRANSFER_TIMEOUT_POLLS,
        )
        .await?;

        self.check_abort()?;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

async fn wait_until<F>(mut cond: F, max_polls: u32) -> Result<(), I2cError>
where
    F: FnMut() -> Result<bool, I2cError>,
{
    for _ in 0..max_polls {
        if cond()? {
            return Ok(());
        }
        narf_scheduler::yield_now().await;
    }
    Err(I2cError::Timeout)
}

// ── Discovery ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CtrlResources {
    mmio_base: u64,
    mmio_len: u64,
    gsi: Option<u32>,
    irq_flags: u8,
}

fn decode_ctrl_crs(path: &str) -> Option<CtrlResources> {
    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut mmio: Option<(u64, u64)> = None;
    let mut gsi: Option<u32> = None;
    let mut irq_flags: u8 = 0;
    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } => {
                if mmio.is_none() {
                    mmio = Some((base as u64, length as u64));
                }
            }
            ResourceItem::Memory32 { min, length, .. } => {
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace32 {
                kind: 0,
                min,
                length,
                ..
            } => {
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace64 {
                kind: 0,
                min,
                length,
                ..
            } => {
                if mmio.is_none() {
                    mmio = Some((min, length));
                }
            }
            ResourceItem::ExtendedIrq { flags, gsis } => {
                if let Some(&g) = gsis.first() {
                    gsi = Some(g);
                    irq_flags = flags;
                }
            }
            _ => {}
        }
    }
    let (mmio_base, mmio_len) = mmio?;
    Some(CtrlResources {
        mmio_base,
        mmio_len,
        gsi,
        irq_flags,
    })
}

pub fn probe_all() -> usize {
    let mut count = 0usize;
    for &hid in LPSS_I2C_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            if probe_one(hid, &node.path).is_some() {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(hid: &str, path: &str) -> Option<()> {
    use core::fmt::Write;

    let res = decode_ctrl_crs(path)?;

    let irq_vec = res.gsi.and_then(|gsi| try_route_irq(gsi, res.irq_flags));

    let mut driver = LpssI2c::new(
        path.to_string(),
        PhysAddr::new(res.mmio_base),
        res.mmio_len,
        irq_vec,
    );
    // #772: record the grounded input clock for this HID and the
    // composed _CRS bus speed (slowest declared wins, Linux
    // i2c_acpi_find_bus_speed semantics). enable() derives the
    // SCL counts only when both are known.
    let ic_clk_khz = ic_clk_khz_for_hid(hid);
    driver.set_ic_clk_khz(ic_clk_khz);
    driver.set_bus_speed_hz(crate::dw_speed::bus_speed_hz(path));
    let bus_speed = driver.bus_speed_hz();
    let driver = Arc::new(driver);

    if let Err(e) = driver.probe_component_type() {
        let _ = writeln!(
            narf_console::Writer,
            "  lpss-i2c: {} probe failed ({:?}) at {:#x}",
            path,
            e,
            res.mmio_base
        );
        return None;
    }
    if let Err(e) = driver.enable() {
        let _ = writeln!(
            narf_console::Writer,
            "  lpss-i2c: {} enable failed ({:?})",
            path,
            e
        );
        return None;
    }

    let registered = crate::registry::register_unique(driver.clone());
    let _ = writeln!(
        narf_console::Writer,
        "  lpss-i2c: detected at MMIO={:#x}+{:#x} {} irq=GSI{}->v{} bus-speed={}",
        res.mmio_base,
        res.mmio_len,
        path,
        res.gsi
            .map(|g| format!("{}", g))
            .unwrap_or_else(|| "?".into()),
        irq_vec
            .map(|v| format!("{}", v))
            .unwrap_or_else(|| "polled".into()),
        match (bus_speed, ic_clk_khz) {
            (Some(hz), Some(_)) => format!("{}Hz (_CRS)", hz),
            // Declared but not programmable: this HID's input
            // clock is ungrounded, so enable() kept the defaults.
            (Some(hz), None) => format!("{}Hz declared, clock ungrounded", hz),
            (None, _) => "default".to_string(),
        },
    );
    let _ = registered;
    Some(())
}

#[cfg(target_arch = "x86_64")]
fn try_route_irq(gsi: u32, acpi_flags: u8) -> Option<u8> {
    let v = narf_interrupts::vector::alloc().ok()?;
    let pol = if acpi_flags & (1 << 1) != 0 {
        narf_acpi::ioapic::POLARITY_LOW
    } else {
        narf_acpi::ioapic::POLARITY_HIGH
    };
    let trig = if acpi_flags & (1 << 2) != 0 {
        narf_acpi::ioapic::TRIGGER_LEVEL
    } else {
        narf_acpi::ioapic::TRIGGER_EDGE
    };
    narf_interrupts::install_handler(v, noop_irq);
    // SAFETY: `v` was freshly allocated via `vector::alloc` above and its
    // handler (`noop_irq`) was installed on the line immediately above, so
    // the dispatch slot is configured before the GSI is routed to it — the
    // contract `route_gsi_to_vector` requires.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    if unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, pol | trig) } {
        Some(v)
    } else {
        let _ = narf_interrupts::vector::free(v);
        None
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn try_route_irq(_gsi: u32, _acpi_flags: u8) -> Option<u8> {
    None
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn noop_irq() {}

#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    LPSS_I2C_HIDS
}

#[doc(hidden)]
pub fn __new_for_test(name: String, mmio_base: PhysAddr, mmio_len: u64) -> LpssI2c {
    LpssI2c::new(name, mmio_base, mmio_len, None)
}
