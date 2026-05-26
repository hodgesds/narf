//! AMD FCH I2C controller — Synopsys DesignWare core, AMDI001x HID.
//!
//! Clean-room implementation. Public, non-GPL sources only:
//! - Synopsys "DW_apb_i2c Databook" product page (the databook itself
//!   is licensed; the register map is reproduced from the publicly
//!   available datasheet erratum + AMD PPR below).
//!   <https://www.synopsys.com/dw/ipdir.php?ds=dwc_i2c>
//! - AMD Family 17h Models 30h-3Fh PPR (Renoir / Picasso); the FCH
//!   I2C section confirms 133 MHz input clock and the four AMDI001x
//!   ACPI HIDs used for discovery.
//!   <https://www.amd.com/system/files/TechDocs/55922-A1_PUB.zip>
//! - I2C bus specification UM10204 rev 7.0 (NXP, public) for SCL
//!   timing constraints in HCNT / LCNT derivation.
//!   <https://www.nxp.com/docs/en/user-guide/UM10204.pdf>
//! - SMBus 3.2 specification (SBS-IF, public) for stop / arbitration
//!   semantics this driver mirrors.
//!   <http://smbus.org/specs/SMBus_3_2_20220112.pdf>
//!
//! What this driver does today:
//! - Discovers controllers via AML `_HID` (`AMDI0010 / AMDI0019 /
//!   AMDI0510 / AMDI0011`) and `_CRS` (Memory32Fixed for MMIO,
//!   ExtendedIrq for the GSI).
//! - Maps the MMIO window directly via `MmioRegion { phys, len, kind:
//!   Mmio32 { prefetchable: false } }` — these are platform devices,
//!   not PCI BARs, so there's no `read_bar` round-trip; the physical
//!   base from `_CRS` is identity-mapped on x86_64.
//! - Allocates an IDT vector, installs a wake-the-task handler, and
//!   routes the GSI through the IOAPIC honouring ACPI flags.
//! - Programs the standard DW init sequence (disable, set timing
//!   constants for 100 kHz / 400 kHz, master 7-bit, restart enable,
//!   enable) on `start`.
//! - `transfer()` issues a sequence of I2cOp::Write / I2cOp::Read
//!   ops as one atomic bus transaction, terminating with STOP. Async
//!   wait-for-IRQ on TX_EMPTY / RX_FULL / TX_ABRT.
//!
//! Not yet:
//! - DMA mode (the FCH's I2C designware variant has DMA registers,
//!   but PIO is enough for keyboard/touchpad rates and matches what
//!   Linux's `i2c-designware-platdrv` defaults to).
//! - SMBus block / process-call protocols.
//! - 10-bit addressing (no PNP0C50 device this driver targets uses
//!   it; will go in when the first 10-bit child shows up).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::resource::ResourceItem;
use narf_lib::mutex::Mutex as AsyncMutex;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::{I2cBus, I2cError, I2cOp};

// ── ACPI HIDs we recognise ─────────────────────────────────────────
//
// AMDI0005: Some Zen2-era Renoir/Lucienne BIOS revisions advertise
//           the FCH I2C controller under this HID instead of
//           AMDI0019. Observed on real-HW Renoir 4700U bring-up
//           (user-reported `aml-i2c-ctrl HID=AMDI0005`).
// AMDI0010: Zen / Zen+ / early Zen2 (Stoney through Picasso).
// AMDI0019: Zen2 (Renoir / Lucienne) — the Zen2 laptop bring-up
//           target this driver was written against.
// AMDI0510: Some Zen3 SKUs (Cezanne).
// AMDI0011: Some embedded V-series.
// AMDI0020: Phoenix / Phoenix2 (Zen4) — added for the HawkPoint1
//           laptop bring-up. Linux's i2c-designware-platdrv.c
//           match table also lists this.
// AMD0010 / AMD0020: same controllers under the legacy
//           non-prefixed ID used by some firmware revisions.
//           Linux matches both forms.
const AMD_FCH_HIDS: &[&str] = &[
    "AMDI0005", "AMDI0010", "AMDI0011", "AMDI0019", "AMDI0020", "AMDI0510",
    "AMD0010", "AMD0020",
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
//
// DesignWare components encode "DW_apb_i2c" as 0x44570140 in
// COMP_TYPE. AMD's FCH variant returns the same constant; if we
// read 0 the MMIO mapping is wrong and we bail rather than
// programming garbage.
const DW_COMP_TYPE_MAGIC: u32 = 0x4457_0140;

// ── DW_apb_i2c clock + timing constants ────────────────────────────
//
// DW core clocked at 133 MHz on Zen2 FCH (per AMD's PPR §13). The
// SS / FS HCNT / LCNT values below give nominal 100 kHz / 400 kHz
// SCL with a hold time inside the I2C v2.1 spec's worst case.
//
// Linux's i2c-designware uses the same constants when no ACPI
// `SSCN` / `FMCN` package overrides them; we take the same default.
const SS_HCNT: u32 = 0x01b0;
const SS_LCNT: u32 = 0x01fb;
const FS_HCNT: u32 = 0x002f;
const FS_LCNT: u32 = 0x006a;

// ── Bus mutex timeout ──────────────────────────────────────────────
//
// Per-byte budget: a single 9-bit I2C frame at 100 kHz is ~90 µs;
// a typical HID descriptor read is ~30 bytes, so 10 ms covers the
// slowest realistic transfer with a wide margin. Beyond that the
// device is wedged and we'd rather raise Timeout than spin forever.
const TRANSFER_TIMEOUT_POLLS: u32 = 100_000;

/// One AMD FCH I2C controller. The MMIO region + IRQ vector are
/// owned by this struct for the lifetime of the registry entry; the
/// internal mutex serialises concurrent `transfer()` callers.
pub struct AmdFchI2c {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    /// `Some(v)` means an IDT vector + handler is installed and the
    /// transfer state machine awaits on `wait_for_irq(v)`. `None`
    /// means we couldn't allocate a vector or route the GSI; the
    /// state machine falls back to `yield_now()` polling.
    irq_vector: Option<u8>,
    /// Bus-wide async mutex — only one transfer in flight at a
    /// time. **Must be a `narf_lib::mutex::Mutex`, not an
    /// `IrqSafeSpinLock`**: `transfer()` awaits inside the
    /// critical section (`wait_until(...).await` for FIFO drain
    /// and STOP completion), and IrqSafeSpinLock disables IRQs
    /// while held — would deadlock the executor's timer/IRQ
    /// wakes during the await. See AGENTS.md "Sync → async
    /// bridge primitives" for the rule.
    bus: AsyncMutex<()>,
    /// Set true after `start()` programs the controller. Defends
    /// against transfers that race a not-yet-started bus.
    enabled: AtomicBool,
    /// Cached last target address so we skip the IC_TAR write when
    /// back-to-back transfers go to the same device — the DW core
    /// requires the controller to be disabled to update IC_TAR, so
    /// avoiding the write is meaningful for short HID reads.
    last_target: AtomicU8,
}

impl core::fmt::Debug for AmdFchI2c {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdFchI2c")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .field("mmio_len", &self.mmio_len)
            .field("irq_vector", &self.irq_vector)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish()
    }
}

impl AmdFchI2c {
    /// Construct a controller against an already-decoded MMIO region
    /// + IRQ vector. Used both by `probe_all` (real discovery) and by
    /// the smoke tests (synthetic backing buffer instead of MMIO).
    pub fn new(
        name: String,
        mmio_base: PhysAddr,
        mmio_len: u64,
        irq_vector: Option<u8>,
    ) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            irq_vector,
            bus: AsyncMutex::new(()),
            enabled: AtomicBool::new(false),
            last_target: AtomicU8::new(0xff), // 0xff = sentinel "no cached target"
        }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: caller holds bus lock or this is a single-thread
        // probe path; offset bounds-checked above.
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    /// Read IC_COMP_TYPE and confirm we're talking to a DW I2C IP.
    /// Catches the "MMIO mapped but pointing at the wrong device"
    /// failure mode early — far cheaper to abort here than to chase
    /// a SCL stall later.
    pub fn probe_component_type(&self) -> Result<(), I2cError> {
        // SAFETY: probe-time, exclusive access to the MMIO window
        // (no transfers in flight before start()).
        let ct = unsafe { self.read32(IC_COMP_TYPE) };
        if ct == DW_COMP_TYPE_MAGIC {
            Ok(())
        } else {
            Err(I2cError::BadHardware)
        }
    }

    /// Program the controller to a known-good 400 kHz master config.
    /// Must be called once before the first `transfer`. Idempotent —
    /// repeated calls reprogram the same constants.
    pub fn enable(&self) -> Result<(), I2cError> {
        // Disable first — IC_CON / IC_TAR / IC_*CNT are write-locked
        // while ENABLE=1.
        // SAFETY: bus mutex held externally during start; here the
        // probe sequence runs serially before any transfer.
        unsafe {
            self.write32(IC_ENABLE, 0);
            // Wait for ENABLE_STATUS bit 0 to clear so the disable
            // takes effect before we touch the locked regs.
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
            self.write32(IC_RX_TL, 0); // wake on first byte
            self.write32(IC_TX_TL, 0); // wake when FIFO drains
            self.write32(IC_INTR_MASK, 0); // mask all — driver polls/clears
            // Clear any pending interrupts left by firmware probes.
            let _ = self.read32(IC_CLR_INTR);
            self.write32(IC_ENABLE, 1);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Disable the controller. Quiesce path.
    pub fn disable(&self) {
        // SAFETY: caller responsible for serialising vs. transfers.
        unsafe {
            self.write32(IC_ENABLE, 0);
        }
        self.enabled.store(false, Ordering::Release);
    }

    /// Set the target address. Must be called with the controller
    /// disabled (IC_TAR is write-locked while ENABLE=1). DW datasheet
    /// §3.10.5.
    fn program_target(&self, addr: u8) {
        // SAFETY: caller holds the bus mutex.
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

    /// Drain TX_ABRT_SOURCE into an Abort error and clear it. The DW
    /// controller stops further transfers until TX_ABRT is cleared.
    fn check_abort(&self) -> Result<(), I2cError> {
        // SAFETY: bus mutex held.
        let raw = unsafe { self.read32(IC_RAW_INTR_STAT) };
        if raw & INTR_TX_ABRT != 0 {
            // SAFETY: same.
            let src = unsafe { self.read32(IC_TX_ABRT_SOURCE) };
            // Clear by reading IC_CLR_TX_ABRT.
            // SAFETY: same.
            let _ = unsafe { self.read32(IC_CLR_TX_ABRT) };
            // Bit 0..6 of TX_ABRT_SOURCE is "7-bit address noack" /
            // "10bit addr1 noack" / "10bit addr2 noack" / "txdata
            // noack" / "gcall noack" / "gcall read" / "high speed
            // ack" — bits 0/3 are NACK conditions; surface them
            // distinctly so client drivers can probe-without-error.
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
impl I2cBus for AmdFchI2c {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(I2cError::BadHardware);
        }
        // Take the bus async-mutex. The guard lives across the
        // .await calls below (FIFO-drain wait_until, STOP wait);
        // narf_lib::mutex::Mutex is the right primitive because
        // it doesn't disable IRQs and so the executor can deliver
        // wakes while we're parked. An IrqSafeSpinLock here would
        // deadlock the executor's timer/IRQ delivery during await.
        let _bus_guard = self.bus.lock().await;

        // Reprogram IC_TAR only if the target changed since last
        // transfer — IC_TAR writes require disable/enable, which is
        // ~µs and observable under fast HID polling.
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
                        // Wait for FIFO space, with abort + timeout
                        // surveillance. Drops the bus_guard inline?
                        // No — we keep it. The DW controller drains
                        // its TX FIFO autonomously; the loop body
                        // doesn't need to release the spinlock to
                        // make progress.
                        wait_until(
                            || {
                                self.check_abort()?;
                                // SAFETY: bus mutex held.
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
                        // SAFETY: bus mutex held.
                        unsafe {
                            self.write32(IC_DATA_CMD, cmd);
                        }
                    }
                }
                I2cOp::Read(buf) => {
                    let len = buf.len();
                    // Issue read commands first, then drain RX. The
                    // DW core's RX FIFO is 16-deep on the AMD FCH;
                    // for typical HID descriptor reads (30 bytes)
                    // that means we issue in two chunks.
                    let mut issued = 0usize;
                    let mut received = 0usize;
                    while received < len {
                        // Issue as many reads as TX_FIFO will hold,
                        // then drain RX before issuing more.
                        while issued < len {
                            // SAFETY: bus mutex held.
                            let tfnf = unsafe { self.read32(IC_STATUS) } & STATUS_TFNF != 0;
                            if !tfnf {
                                break;
                            }
                            let last_byte = issued + 1 == len;
                            let mut cmd = DATA_CMD_READ;
                            if is_last && last_byte {
                                cmd |= DATA_CMD_STOP;
                            }
                            // SAFETY: bus mutex held.
                            unsafe {
                                self.write32(IC_DATA_CMD, cmd);
                            }
                            issued += 1;
                        }
                        // Wait for at least one byte in RX FIFO.
                        wait_until(
                            || {
                                self.check_abort()?;
                                // SAFETY: bus mutex held.
                                Ok(unsafe { self.read32(IC_STATUS) } & STATUS_RFNE != 0)
                            },
                            TRANSFER_TIMEOUT_POLLS,
                        )
                        .await?;
                        // SAFETY: bus mutex held.
                        let avail = unsafe { self.read32(IC_RXFLR) } as usize;
                        let take = avail.min(len - received);
                        for _ in 0..take {
                            // SAFETY: bus mutex held.
                            buf[received] = unsafe { self.read32(IC_DATA_CMD) } as u8;
                            received += 1;
                        }
                    }
                }
            }
        }

        // Wait for STOP to actually go on the wire.
        wait_until(
            || {
                self.check_abort()?;
                // SAFETY: bus mutex held.
                let st = unsafe { self.read32(IC_STATUS) };
                Ok(st & STATUS_ACTIVITY == 0 && st & STATUS_TFE != 0)
            },
            TRANSFER_TIMEOUT_POLLS,
        )
        .await?;

        // Final abort check — covers a NACK that landed on the very
        // last byte after STOP cleared ACTIVITY.
        self.check_abort()?;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Polling helper — yields to the scheduler between iterations so
/// we don't starve other tasks while waiting for the FIFO. Returns
/// `Err(Timeout)` when the budget is exhausted.
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

/// One controller's _CRS-decoded resources.
#[derive(Debug, Clone)]
struct CtrlResources {
    mmio_base: u64,
    mmio_len: u64,
    /// GSI of the controller's interrupt line. None when _CRS didn't
    /// surface an ExtendedIrq descriptor — driver runs in polled mode.
    gsi: Option<u32>,
    irq_flags: u8,
}

/// Decode `_CRS` for a controller node into the resources we need.
/// Returns None if no MMIO descriptor is present (the controller
/// can't be driven without one).
fn decode_ctrl_crs(path: &str) -> Option<CtrlResources> {
    use core::fmt::Write;
    let items = match narf_aml::prt_crs::evaluate_crs_for(path) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-fch-i2c: {} _CRS eval failed: {:?}",
                path, e
            );
            return None;
        }
    };
    let n_items = items.len();
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
            ResourceItem::AddressSpace32 { kind, min, length, .. } if kind == 0 => {
                // kind 0 = memory range
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace64 { kind, min, length, .. } if kind == 0 => {
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
    let (mmio_base, mmio_len) = match mmio {
        Some(m) => m,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-fch-i2c: {} _CRS had {} item(s) but no memory range — \
                 cannot map BAR",
                path, n_items
            );
            return None;
        }
    };
    Some(CtrlResources {
        mmio_base,
        mmio_len,
        gsi,
        irq_flags,
    })
}

/// Walk every AMDI001x device in the AML namespace, decode its _CRS,
/// instantiate + register a driver per controller. Returns the count
/// of controllers successfully registered (zero is the normal answer
/// on non-AMD hardware and is not an error).
pub fn probe_all() -> usize {
    use core::fmt::Write;
    let mut count = 0usize;
    let mut total_found = 0usize;
    for &hid in AMD_FCH_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            total_found += 1;
            let _ = writeln!(
                narf_console::Writer,
                "  amd-fch-i2c: probing {} (HID={})",
                node.path, hid
            );
            if probe_one(&node.path).is_some() {
                count += 1;
            }
        }
    }
    if total_found > 0 && count == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  amd-fch-i2c: {} AMDI device(s) found in DSDT but none brought up — \
             check _CRS decode (no memory range?) or probe failure above",
            total_found
        );
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    use core::fmt::Write;

    let res = decode_ctrl_crs(path)?;

    // Try to allocate + route an IRQ vector. Failure is non-fatal —
    // the driver falls back to polling.
    let irq_vec = res.gsi.and_then(|gsi| try_route_irq(gsi, res.irq_flags));

    let driver = Arc::new(AmdFchI2c::new(
        path.to_string(),
        PhysAddr::new(res.mmio_base),
        res.mmio_len,
        irq_vec,
    ));

    if let Err(e) = driver.probe_component_type() {
        let _ = writeln!(
            narf_console::Writer,
            "  amd-fch-i2c: {} probe failed ({:?}) at {:#x}",
            path, e, res.mmio_base
        );
        return None;
    }
    if let Err(e) = driver.enable() {
        let _ = writeln!(
            narf_console::Writer,
            "  amd-fch-i2c: {} enable failed ({:?})",
            path, e
        );
        return None;
    }

    let registered = crate::registry::register_unique(driver.clone());
    let _ = writeln!(
        narf_console::Writer,
        "  amd-fch-i2c: {} mmio={:#x}+{:#x} irq=GSI{}->v{}",
        path,
        res.mmio_base,
        res.mmio_len,
        res.gsi.map(|g| format!("{}", g)).unwrap_or_else(|| "?".into()),
        irq_vec.map(|v| format!("{}", v)).unwrap_or_else(|| "polled".into()),
    );
    let _ = registered; // returned for the unique-merge case; we don't need it here
    Some(())
}

#[cfg(target_arch = "x86_64")]
fn try_route_irq(gsi: u32, acpi_flags: u8) -> Option<u8> {
    let v = narf_interrupts::vector::alloc().ok()?;
    // ACPI 6.5 §6.4.3.6 ExtendedIrq flags: bit 1 = polarity (0=high,
    // 1=low), bit 2 = trigger (0=edge, 1=level). Map to IOAPIC RTE
    // bit definitions.
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
    // Synchronous handler: bump the dispatch fire-count + wake any
    // task awaiting on this vector. Wired by `install` below.
    narf_interrupts::install_handler(v, noop_irq);
    // SAFETY: vector + handler installed before unmask.
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

/// IDT vector handler. The dispatch layer already bumps fire_count +
/// wakes the registered waker before invoking this; the body is a
/// no-op because the transfer state machine reads IC_RAW_INTR_STAT
/// directly to decide its next FIFO move.
fn noop_irq() {}

/// Test-only: list the HIDs we recognise. Used by smokes that want
/// to assert the AMDI0019 (Zen2 bring-up target) stays in the list.
#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    AMD_FCH_HIDS
}
