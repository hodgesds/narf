//! Intel PCH LPSS I2C controller — Synopsys DesignWare core, INT3xxx /
//! 80860Fxx / 808622xx ACPI HIDs.
//!
//! Stage-1 implementation — discovery + MMIO mapping + LPSS ungate +
//! DW I2C programming + PIO transactions.
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
pub struct LpssI2c {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    irq_vector: Option<u8>,
    bus: AsyncMutex<()>,
    enabled: AtomicBool,
    last_target: AtomicU8,
}

impl core::fmt::Debug for LpssI2c {
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

impl LpssI2c {
    pub fn new(name: String, mmio_base: PhysAddr, mmio_len: u64, irq_vector: Option<u8>) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            irq_vector,
            bus: AsyncMutex::new(()),
            enabled: AtomicBool::new(false),
            last_target: AtomicU8::new(0xff),
        }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
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

        let ct = unsafe { self.read32(IC_COMP_TYPE) };
        if ct == DW_COMP_TYPE_MAGIC {
            Ok(())
        } else {
            Err(I2cError::BadHardware)
        }
    }

    /// Program the controller to a known-good 400 kHz master config.
    pub fn enable(&self) -> Result<(), I2cError> {
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
                IC_CON_MASTER_MODE
                    | IC_CON_SPEED_FAST
                    | IC_CON_IC_SLAVE_DISABLE
                    | IC_CON_RESTART_EN,
            );
            self.write32(IC_SS_SCL_HCNT, SS_HCNT);
            self.write32(IC_SS_SCL_LCNT, SS_LCNT);
            self.write32(IC_FS_SCL_HCNT, FS_HCNT);
            self.write32(IC_FS_SCL_LCNT, FS_LCNT);
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
        unsafe {
            self.write32(IC_ENABLE, 0);
        }
        self.enabled.store(false, Ordering::Release);
    }

    fn program_target(&self, addr: u8) {
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
        let raw = unsafe { self.read32(IC_RAW_INTR_STAT) };
        if raw & INTR_TX_ABRT != 0 {
            let src = unsafe { self.read32(IC_TX_ABRT_SOURCE) };
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
impl I2cBus for LpssI2c {
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
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
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
                            let tfnf = unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0;
                            if !tfnf {
                                break;
                            }
                            let last_byte = issued + 1 == len;
                            let mut cmd = DATA_CMD_READ;
                            if is_last && last_byte {
                                cmd |= DATA_CMD_STOP;
                            }
                            unsafe {
                                self.write32(IC_DATA_CMD, cmd);
                            }
                            issued += 1;
                        }
                        wait_until(
                            || {
                                self.check_abort()?;
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_RFNE != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
                        let avail = unsafe { self.read32(IC_RXFLR) } as usize;
                        let take = avail.min(len - received);
                        for _ in 0..take {
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
                kind, min, length, ..
            } if kind == 0 => {
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace64 {
                kind, min, length, ..
            } if kind == 0 => {
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
            if probe_one(&node.path).is_some() {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    use core::fmt::Write;

    let res = decode_ctrl_crs(path)?;

    let irq_vec = res.gsi.and_then(|gsi| try_route_irq(gsi, res.irq_flags));

    let driver = Arc::new(LpssI2c::new(
        path.to_string(),
        PhysAddr::new(res.mmio_base),
        res.mmio_len,
        irq_vec,
    ));

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
        "  lpss-i2c: detected at MMIO={:#x}+{:#x} {} irq=GSI{}->v{}",
        res.mmio_base,
        res.mmio_len,
        path,
        res.gsi
            .map(|g| format!("{}", g))
            .unwrap_or_else(|| "?".into()),
        irq_vec
            .map(|v| format!("{}", v))
            .unwrap_or_else(|| "polled".into()),
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

fn noop_irq() {}

#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    LPSS_I2C_HIDS
}

#[doc(hidden)]
pub fn __new_for_test(name: String, mmio_base: PhysAddr, mmio_len: u64) -> LpssI2c {
    LpssI2c::new(name, mmio_base, mmio_len, None)
}
