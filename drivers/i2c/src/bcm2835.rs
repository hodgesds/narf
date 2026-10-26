//! BCM2835 BSC I2C master (Broadcom 2835 ARM Peripherals §9) —
//! the DT binding (DT programme step 5).
//!
//! The audit found no non-DesignWare ARM I2C master in the tree;
//! the BSC is the canonical real-board-class ARM I2C controller
//! (every Raspberry Pi generation routes its I2C buses through
//! BSC masters at `brcm,bcm2835-i2c`), so this lane folds it in
//! as the DT I2C binding rather than a virt-only reference part —
//! QEMU virt exposes no I2C controller at all. The driver
//! registers into the crate's existing bus registry, the same
//! one the DesignWare drivers publish into, so consumers
//! (I2C-HID etc.) see one registry story.
//!
//! Register access goes through the [`BscIo`] seam: production
//! is a thin MMIO form over the ioremap'd window; the smokes
//! drive a model of the BSC (FIFO + register-file slave) behind
//! the same seam, so the transfer state machine below is what
//! executes against the model, unchanged.
//!
//! Transfers are polled (no IRQ path): single write, single
//! read, and the combined write→read repeated-start form. The
//! combined form uses the Linux i2c-bcm2835 method — DLEN covers
//! both phases, and the READ bit is flipped while the transfer
//! is still active (after the write FIFO drains), which is what
//! makes the BSC issue a repeated START instead of a STOP.
//! Longer op chains are refused with `Abort` rather than
//! silently splitting them into separate transactions (a split
//! would break register-pointer semantics of real slaves).
//!
//! Clocking: DIV = core / bus. The bus rate comes from the
//! node's own `clock-frequency` property (default 100 kHz). The
//! core clock resolves from the node's `clocks` phandle when it
//! names a fixed-clock; the BCM2835 clock provider is not one,
//! so on Pi device trees the binding lands on
//! [`CORE_CLK_FALLBACK_HZ`] — the 250 MHz default core clock —
//! flagged here as the §3.1 constant the #1052 clock framework
//! will replace.

use alloc::boxed::Box;
use alloc::string::String;

use async_trait::async_trait;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::IoMapping;

use crate::{I2cBus, I2cError, I2cOp};

// Register offsets (BCM2835 ARM Peripherals §9.2).
const REG_C: u32 = 0x00;
const REG_S: u32 = 0x04;
const REG_DLEN: u32 = 0x08;
const REG_A: u32 = 0x0C;
const REG_FIFO: u32 = 0x10;
const REG_DIV: u32 = 0x14;

// C register bits.
const C_I2CEN: u32 = 1 << 15;
const C_ST: u32 = 1 << 7;
const C_CLEAR: u32 = 1 << 4;
const C_READ: u32 = 1 << 0;

// S register bits.
const S_CLKT: u32 = 1 << 9;
const S_ERR: u32 = 1 << 8;
const S_RXF: u32 = 1 << 7;
const S_TXE: u32 = 1 << 6;
const S_RXD: u32 = 1 << 5;
const S_TXD: u32 = 1 << 4;
const S_DONE: u32 = 1 << 1;
const S_TA: u32 = 1 << 0;

/// Status bits the driver clears by writing them back before a
/// transfer (the Linux i2c-bcm2835 discipline).
const S_CLEARABLE: u32 = S_CLKT | S_ERR | S_DONE;

/// Poll budget per transfer phase. The BSC at 100 kHz clocks a
/// byte in ~90 µs; this budget is several orders past any real
/// transfer the FIFO model can describe and exists only to keep
/// a dead bus from spinning forever.
const POLL_BUDGET: u32 = 2_000_000;

/// BCM2835 core clock fallback (250 MHz, the Pi default core
/// rate). See the module docs for why this is a named constant.
pub const CORE_CLK_FALLBACK_HZ: u32 = 250_000_000;

/// Register-access seam for the BSC (see the module docs).
pub trait BscIo: Send + Sync + core::fmt::Debug {
    /// Read one BSC register.
    fn read(&self, reg: u32) -> u32;
    /// Write one BSC register.
    fn write(&self, reg: u32, val: u32);
}

/// Production [`BscIo`]: volatile MMIO over the ioremap'd window.
#[derive(Debug)]
pub struct MmioBsc {
    base_va: u64,
    /// Kept so the ioremap lives as long as the controller.
    _mapping: Option<IoMapping>,
}

impl MmioBsc {
    /// Wrap an ioremap'd BSC window.
    ///
    /// # Safety
    /// `mapping` must cover the BSC register block (4 KiB).
    pub unsafe fn new(mapping: IoMapping) -> Self {
        Self {
            base_va: mapping.va(),
            _mapping: Some(mapping),
        }
    }
}

impl BscIo for MmioBsc {
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: base_va covers the BSC register block by the
        // constructor contract; reg is one of the fixed offsets.
        unsafe { core::ptr::read_volatile((self.base_va + reg as u64) as *const u32) }
    }

    fn write(&self, reg: u32, val: u32) {
        // SAFETY: same contract as read.
        unsafe { core::ptr::write_volatile((self.base_va + reg as u64) as *mut u32, val) }
    }
}

/// One bound BCM2835 BSC master.
pub struct Bcm2835I2c<I: BscIo> {
    name: String,
    io: I,
    /// Serialises transfers (the trait's bus-mutex contract).
    lock: IrqSafeSpinLock<()>,
}

impl<I: BscIo> core::fmt::Debug for Bcm2835I2c<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bcm2835I2c")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<I: BscIo> Bcm2835I2c<I> {
    /// Construct and program the clock divider for
    /// `bus_hz` from `core_hz`.
    pub fn new(name: String, io: I, core_hz: u32, bus_hz: u32) -> Self {
        let ctrl = Self {
            name,
            io,
            lock: IrqSafeSpinLock::new(()),
        };
        let divider = divider_for(core_hz, bus_hz);
        ctrl.io.write(REG_DIV, divider as u32);
        ctrl
    }

    /// Run one transfer: an optional write phase followed by an
    /// optional read phase, joined by a repeated START when both
    /// are present.
    fn run_transfer(
        &self,
        addr: u8,
        write: Option<&[u8]>,
        mut read: Option<&mut [u8]>,
    ) -> Result<(), I2cError> {
        let wbuf: &[u8] = write.unwrap_or(&[]);
        let wlen = wbuf.len();
        let rlen = read.as_ref().map_or(0, |r| r.len());
        if wlen + rlen > u16::MAX as usize {
            return Err(I2cError::Abort(0xB5C0_0001));
        }
        let io = &self.io;
        // Clear stale status, program address + total length.
        io.write(REG_S, S_CLEARABLE);
        io.write(REG_A, addr as u32 & 0x7F);
        io.write(REG_DLEN, (wlen + rlen) as u32);
        let mut c = C_I2CEN | C_CLEAR | C_ST;
        if wlen == 0 && rlen > 0 {
            c |= C_READ;
        }
        io.write(REG_C, c);

        let mut wpos = 0usize;
        let mut rpos = 0usize;
        let mut flipped = wlen == 0;
        let mut budget = POLL_BUDGET;
        loop {
            let s = io.read(REG_S);
            if s & S_ERR != 0 {
                io.write(REG_C, C_I2CEN | C_CLEAR);
                return Err(I2cError::Nack);
            }
            if s & S_CLKT != 0 {
                io.write(REG_C, C_I2CEN | C_CLEAR);
                return Err(I2cError::Abort(s));
            }
            // Feed the write phase.
            while wpos < wlen && io.read(REG_S) & S_TXD != 0 {
                io.write(REG_FIFO, wbuf[wpos] as u32);
                wpos += 1;
            }
            // Flip to the read phase once the write FIFO has
            // drained into the slave: with TA still up, setting
            // READ now is the repeated START. The status is
            // re-read after feeding — a snapshot from before the
            // feed would flip while the last write byte is still
            // in the FIFO, before it has been clocked.
            if !flipped && wpos == wlen {
                let s2 = io.read(REG_S);
                if s2 & S_TXE != 0 && s2 & S_TA != 0 {
                    io.write(REG_C, C_I2CEN | C_READ);
                    flipped = true;
                }
            }
            // Drain the read phase.
            if let Some(rbuf) = read.as_deref_mut() {
                while rpos < rlen && io.read(REG_S) & S_RXD != 0 {
                    rbuf[rpos] = io.read(REG_FIFO) as u8;
                    rpos += 1;
                }
            }
            if s & S_DONE != 0 {
                break;
            }
            budget -= 1;
            if budget == 0 {
                io.write(REG_C, C_I2CEN | C_CLEAR);
                return Err(I2cError::Timeout);
            }
            core::hint::spin_loop();
        }
        // DONE: the final read bytes may still sit in the FIFO.
        if let Some(rbuf) = read.as_deref_mut() {
            while rpos < rlen && io.read(REG_S) & S_RXD != 0 {
                rbuf[rpos] = io.read(REG_FIFO) as u8;
                rpos += 1;
            }
            if rpos != rlen {
                return Err(I2cError::Abort(0xB5C0_0002));
            }
        }
        io.write(REG_C, C_I2CEN);
        Ok(())
    }
}

/// Clock divider for `bus_hz` from `core_hz`: DIV = ceil(core /
/// bus), at least 1 (the BSC divides the core clock by DIV).
/// Pure — host-assertable.
pub fn divider_for(core_hz: u32, bus_hz: u32) -> u16 {
    if bus_hz == 0 {
        return 0xFFFF;
    }
    let div = core_hz.div_ceil(bus_hz).max(1);
    div.min(0xFFFF) as u16
}

#[async_trait]
impl<I: BscIo> I2cBus for Bcm2835I2c<I> {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        let _guard = self.lock.lock();
        match ops {
            [] => Ok(()),
            [I2cOp::Write(w)] => self.run_transfer(addr, Some(w), None),
            [I2cOp::Read(r)] => self.run_transfer(addr, None, Some(r)),
            [I2cOp::Write(w), I2cOp::Read(r)] => self.run_transfer(addr, Some(w), Some(r)),
            // Longer chains / repeated writes: refused, not split
            // (see the module docs).
            _ => Err(I2cError::Abort(0xB5C0_0003)),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── DT binding ──────────────────────────────────────────────────

/// Register this crate's DT match entries with the bus match
/// table. Called from `register_initcalls` — composition-time
/// registration, census-neutral (bus registry state, not an
/// initcall).
pub fn register_dt_drivers() {
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: "bcm2835-i2c",
        compatible: "brcm,bcm2835-i2c",
        probe: probe_dt,
    });
}

fn probe_dt(
    dev: narf_bus::BusDevice,
    _cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    use narf_memory::ioremap::{ioremap, MmioAttrs};
    let narf_bus::BusKind::Platform(rec) = dev.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    let win = rec.reg_windows().first().ok_or(ProbeError::BadDevice)?;
    // Bus rate: the node's own clock-frequency (default 100 kHz).
    // Core clock: the fixed-clock resolution of the SPI helper's
    // shape, else the named fallback (module docs).
    let bus_hz = narf_bus::dt::dtb_blob()
        .and_then(|blob| {
            narf_bus::dt::node_prop(
                blob,
                rec.first_compatible(),
                win.base.raw(),
                "clock-frequency",
            )
        })
        .and_then(|v| {
            if v.len() >= 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
        .unwrap_or(100_000);
    let core_hz = bcm2835_clock_hz(&rec).unwrap_or(CORE_CLK_FALLBACK_HZ);
    // SAFETY: the window is the device's DT reg window; ioremap
    // maps it device-nongathering for the binding's lifetime (the
    // mapping rides inside the registered controller's MmioBsc).
    let mapping = unsafe { ioremap(win.base.raw(), win.len.max(0x1000), MmioAttrs::Device) }
        .map_err(|_| ProbeError::Other("bcm2835-i2c: ioremap of the DT reg window failed"))?;
    let name = alloc::format!("bcm2835-i2c@{:#x}", win.base.raw());
    // SAFETY: the ioremap covers the BSC register block.
    let io = unsafe { MmioBsc::new(mapping) };
    let bus = Bcm2835I2c::new(name, io, core_hz, bus_hz);
    crate::registry::register_unique(alloc::sync::Arc::new(bus));
    Ok(())
}

/// Resolve the controller core clock from the node's `clocks`
/// phandle when it names a fixed-clock provider (bus spec §3.1).
fn bcm2835_clock_hz(rec: &narf_bus::PlatformDevice) -> Option<u32> {
    let blob = narf_bus::dt::dtb_blob()?;
    let win = rec.reg_windows().first()?;
    let clocks = narf_bus::dt::node_prop(blob, rec.first_compatible(), win.base.raw(), "clocks")?;
    if clocks.len() < 4 {
        return None;
    }
    let phandle = u32::from_be_bytes([clocks[0], clocks[1], clocks[2], clocks[3]]);
    narf_bus::dt::clock_frequency_of_phandle(blob, phandle)
}
