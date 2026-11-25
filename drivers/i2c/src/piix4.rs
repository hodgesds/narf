//! AMD PIIX4 / FCH SMBus host driver (KERNCZ, `1022:790b`).
//!
//! Ref: Linux `drivers/i2c/busses/i2c-piix4.c` and `i2c-piix4.h`,
//! `include/linux/platform_data/x86/amd-fch.h`.
//!
//! ## Topology
//!
//! An SB800-class FCH has a **main** SMBus host whose base the FCH PM
//! DecodeEn register advertises, multiplexed across several ports, and
//! an **auxiliary** host at `base | 0x20`. Linux registers, for KERNCZ:
//!
//! | Adapter name                          | Host | Port select |
//! |---------------------------------------|------|-------------|
//! | `SMBus PIIX4 adapter port 0 at <smba>` | main | 0           |
//! | `SMBus PIIX4 adapter port 2 at <smba>` | main | 1           |
//! | `SMBus PIIX4 adapter port 1 at <aux>`  | aux  | —           |
//!
//! (KERNCZ reserves main ports 3 and 4; the aux adapter is skipped when
//! firmware claims it for ASF, `\_SB.ASFC`.) The two main-host adapters
//! share one host and one lock. Each of their transactions takes the
//! host's SMBus semaphore (shared with the FCH's integrated
//! microcontroller), selects its port in PM register `0x02` bits 4:3,
//! runs, restores the previous port selection and drops the semaphore —
//! `piix4_access_sb800`. The aux host is a plain PIIX4 host.
//!
//! ## PM register access
//!
//! FCH SMBus revision ≥ `0x51` may have the `0xCD6`/`0xCD7` index/data
//! ports disabled; Linux uses the MMIO window at `FCH_PM_BASE`
//! (`0xFED80300`) there, and the index pair below that revision. The
//! base discovery itself changed at revision `0x49` (DecodeEn at PM
//! `0x00` instead of `SmBus0En` at `0x2c`). This driver is the only
//! code that touches either window; the module-private host lock
//! serialises every access.
//!
//! The driver is SMBus-only: [`I2cBus::transfer`] (raw I2C) is
//! unsupported, as Linux's piix4 has no `master_xfer`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BusDevice, BusDeviceCap, MatchKind, PciMatch};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex as AsyncMutex;

use crate::smbus::{I2cFunc, SmbusOp, SMBUS_BLOCK_MAX};
use crate::{I2cBus, I2cError, I2cOp};

pub const AMD_VENDOR_ID: u16 = 0x1022;
pub const AMD_KERNCZ_SMBUS: u16 = 0x790b; // Found on Zen/Zen2/Zen3/Zen4 FCH

// Host registers, offsets from the host base (i2c-piix4.h).
const SMBHSTSTS: u16 = 0x00;
const SMBHSTCNT: u16 = 0x02;
const SMBHSTCMD: u16 = 0x03;
const SMBHSTADD: u16 = 0x04;
const SMBHSTDAT0: u16 = 0x05;
const SMBHSTDAT1: u16 = 0x06;
const SMBBLKDAT: u16 = 0x07;
const SMBSLVCNT: u16 = 0x08;
/// Main host's I2C-config register: bit 0 IRQ vs SMI#, bits 7:4 revision.
const SMB_I2CCFG: u16 = 0x10;

// Transaction sizes, SMBHSTCNT bits 4:2.
const PIIX4_QUICK: u8 = 0x00;
const PIIX4_BYTE: u8 = 0x04;
const PIIX4_BYTE_DATA: u8 = 0x08;
const PIIX4_WORD_DATA: u8 = 0x0C;
const PIIX4_BLOCK_DATA: u8 = 0x14;

const SMBHSTCNT_START: u8 = 0x40;
const SMBHSTSTS_HOST_BUSY: u8 = 0x01;
const SMBHSTSTS_DEV_ERR: u8 = 0x04;
const SMBHSTSTS_BUS_ERR: u8 = 0x08;
const SMBHSTSTS_FAILED: u8 = 0x10;
/// SMBSLVCNT bit 4: request (write) / owned (read) the host semaphore.
const SMBSLVCNT_SEMAPHORE: u8 = 0x10;
/// SMBSLVCNT bit 5: release the semaphore.
const SMBSLVCNT_RELEASE: u8 = 0x20;

/// `MAX_TIMEOUT`: busy-bit polls per transaction, and semaphore and
/// IMC attempts.
const MAX_TIMEOUT: u32 = 500;

const SB800_PIIX4_SMB_IDX: u16 = 0xcd6;
/// `FCH_PM_BASE`: MMIO view of PMx00..PMx07.
const FCH_PM_BASE: u64 = 0xFED8_0300;
const SB800_PIIX4_FCH_PM_SIZE: u64 = 8;
/// `SB800_PIIX4_PORT_IDX_KERNCZ` (`FCH_PM_DECODEEN + 2`).
const SB800_PIIX4_PORT_IDX_KERNCZ: u8 = 0x02;
/// `SB800_PIIX4_PORT_IDX_MASK_KERNCZ` (`FCH_PM_DECODEEN_SMBUS0SEL >> 16`).
const SB800_PIIX4_PORT_IDX_MASK_KERNCZ: u8 = 0x18;
const SB800_PIIX4_PORT_IDX_SHIFT_KERNCZ: u8 = 3;
const KERNCZ_IMC_IDX: u16 = 0x3e;
const KERNCZ_IMC_DATA: u16 = 0x3f;
const SB800_ASF_ACPI_PATH: &str = "\\_SB.ASFC";

/// First KERNCZ revision whose base comes from DecodeEn (`smb_en = 0`).
const REV_DECODEEN: u8 = 0x49;
/// First KERNCZ revision that wants PM access through MMIO.
const REV_PM_MMIO: u8 = 0x51;

/// Main-host port names, indexed by port-select value
/// (`piix4_main_port_names_sb800`; KERNCZ uses the first two).
const MAIN_PORT_NAMES: [&str; 2] = [" port 0", " port 2"];
const AUX_PORT_NAME: &str = " port 1";

fn log(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "piix4_smbus: {args}");
}

// ── Register seams ───────────────────────────────────────────────────

/// Port I/O the SMBus hosts, the PM index pair and the IMC mailbox are
/// reached through. A seam so tests can drive the driver against a
/// register model.
pub trait PortIo: Send + Sync + core::fmt::Debug {
    fn inb(&self, port: u16) -> u8;
    fn outb(&self, port: u16, value: u8);
}

/// Real x86 port I/O.
#[derive(Debug)]
pub struct HwPortIo;

impl PortIo for HwPortIo {
    #[cfg(target_arch = "x86_64")]
    fn inb(&self, port: u16) -> u8 {
        // SAFETY: every port this driver touches — its SMBus host
        // windows, the PM index pair and the IMC mailbox — belongs to
        // the FCH it was probed on.
        unsafe { narf_arch::x86_64::io_port::inb(port) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn inb(&self, _port: u16) -> u8 {
        0xff
    }

    #[cfg(target_arch = "x86_64")]
    fn outb(&self, port: u16, value: u8) {
        // SAFETY: as for `inb`.
        unsafe { narf_arch::x86_64::io_port::outb(port, value) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn outb(&self, _port: u16, _value: u8) {}
}

/// FCH power-management registers PMx00.. (DecodeEn, SMBus0 port
/// select), through MMIO or the index/data pair.
pub trait FchPm: Send + Sync + core::fmt::Debug {
    fn read8(&self, reg: u8) -> u8;
    fn write8(&self, reg: u8, value: u8);
}

/// PM registers through the `FCH_PM_BASE` MMIO window.
#[derive(Debug)]
struct PmMmio {
    va: u64,
}

impl FchPm for PmMmio {
    fn read8(&self, reg: u8) -> u8 {
        debug_assert!(u64::from(reg) < SB800_PIIX4_FCH_PM_SIZE);
        // SAFETY: `va` is a Device ioremap of the 8-byte PM window and
        // the only registers addressed are PMx00..PMx02.
        unsafe { narf_arch::mmio::read8(self.va + u64::from(reg)) }
    }

    fn write8(&self, reg: u8, value: u8) {
        debug_assert!(u64::from(reg) < SB800_PIIX4_FCH_PM_SIZE);
        // SAFETY: as for `read8`.
        unsafe { narf_arch::mmio::write8(self.va + u64::from(reg), value) }
    }
}

/// PM registers through the `0xCD6`/`0xCD7` index/data pair.
#[derive(Debug)]
struct PmIndexed {
    io: Arc<dyn PortIo>,
}

impl FchPm for PmIndexed {
    fn read8(&self, reg: u8) -> u8 {
        self.io.outb(SB800_PIIX4_SMB_IDX, reg);
        self.io.inb(SB800_PIIX4_SMB_IDX + 1)
    }

    fn write8(&self, reg: u8, value: u8) {
        self.io.outb(SB800_PIIX4_SMB_IDX, reg);
        self.io.outb(SB800_PIIX4_SMB_IDX + 1, value);
    }
}

// ── Host transactions ────────────────────────────────────────────────

/// One PIIX4 SMBus host register block.
#[derive(Debug)]
struct Host {
    io: Arc<dyn PortIo>,
    smba: u16,
}

impl Host {
    fn inb(&self, off: u16) -> u8 {
        self.io.inb(self.smba + off)
    }

    fn outb(&self, off: u16, value: u8) {
        self.io.outb(self.smba + off, value)
    }

    /// `piix4_transaction`: start the programmed transaction and wait
    /// for it. Error precedence follows Linux: a timeout is reported
    /// unless a status error bit overrides it, and "no response"
    /// (`DEV_ERR`) wins over the other two.
    async fn transaction(&self) -> Result<(), I2cError> {
        // Make sure the host is ready to start transmitting.
        let temp = self.inb(SMBHSTSTS);
        if temp != 0x00 {
            self.outb(SMBHSTSTS, temp);
            let again = self.inb(SMBHSTSTS);
            if again != 0x00 {
                log(format_args!("SMBus busy ({again:02x}), reset failed"));
                return Err(I2cError::Busy);
            }
        }

        let cnt = self.inb(SMBHSTCNT);
        self.outb(SMBHSTCNT, cnt | SMBHSTCNT_START);

        // Always wait a fraction of a second (PIIX4 errata).
        narf_time::usleep_range(250, 500).await;

        // `while ((++timeout < MAX_TIMEOUT) && ((temp = inb(STS)) & 1))`:
        // when the count runs out `temp` keeps the previous read.
        let mut temp = 0u8;
        let mut timeout = 0u32;
        loop {
            timeout += 1;
            if timeout >= MAX_TIMEOUT {
                break;
            }
            temp = self.inb(SMBHSTSTS);
            if temp & SMBHSTSTS_HOST_BUSY == 0 {
                break;
            }
            narf_time::usleep_range(250, 500).await;
        }

        let mut result = Ok(());
        if timeout == MAX_TIMEOUT {
            log(format_args!("SMBus Timeout!"));
            result = Err(I2cError::Timeout);
        }
        if temp & SMBHSTSTS_FAILED != 0 {
            log(format_args!("Error: Failed bus transaction"));
            result = Err(I2cError::Abort(u32::from(SMBHSTSTS_FAILED)));
        }
        if temp & SMBHSTSTS_BUS_ERR != 0 {
            // Bus collision; Linux reports -EIO.
            result = Err(I2cError::Abort(u32::from(SMBHSTSTS_BUS_ERR)));
        }
        if temp & SMBHSTSTS_DEV_ERR != 0 {
            // No response (Linux -ENXIO): the normal answer while
            // probing an empty address, so not logged.
            result = Err(I2cError::Nack);
        }

        if self.inb(SMBHSTSTS) != 0x00 {
            let sts = self.inb(SMBHSTSTS);
            self.outb(SMBHSTSTS, sts);
        }
        let after = self.inb(SMBHSTSTS);
        if after != 0x00 {
            log(format_args!(
                "Failed reset at end of transaction ({after:02x})"
            ));
        }
        result
    }

    /// `piix4_access`: program and run one SMBus transaction.
    async fn access(&self, addr: u8, op: SmbusOp<'_>) -> Result<(), I2cError> {
        let write = addr << 1;
        let read = write | 1;
        let size = match &op {
            SmbusOp::Quick { read: r } => {
                self.outb(SMBHSTADD, write | u8::from(*r));
                PIIX4_QUICK
            }
            SmbusOp::ReceiveByte { .. } => {
                self.outb(SMBHSTADD, read);
                PIIX4_BYTE
            }
            SmbusOp::SendByte { value } => {
                self.outb(SMBHSTADD, write);
                self.outb(SMBHSTCMD, *value);
                PIIX4_BYTE
            }
            SmbusOp::ReadByteData { cmd, .. } => {
                self.outb(SMBHSTADD, read);
                self.outb(SMBHSTCMD, *cmd);
                PIIX4_BYTE_DATA
            }
            SmbusOp::WriteByteData { cmd, value } => {
                self.outb(SMBHSTADD, write);
                self.outb(SMBHSTCMD, *cmd);
                self.outb(SMBHSTDAT0, *value);
                PIIX4_BYTE_DATA
            }
            SmbusOp::ReadWordData { cmd, .. } => {
                self.outb(SMBHSTADD, read);
                self.outb(SMBHSTCMD, *cmd);
                PIIX4_WORD_DATA
            }
            SmbusOp::WriteWordData { cmd, value } => {
                let [lo, hi] = value.to_le_bytes();
                self.outb(SMBHSTADD, write);
                self.outb(SMBHSTCMD, *cmd);
                self.outb(SMBHSTDAT0, lo);
                self.outb(SMBHSTDAT1, hi);
                PIIX4_WORD_DATA
            }
            SmbusOp::ReadBlockData { cmd, .. } => {
                self.outb(SMBHSTADD, read);
                self.outb(SMBHSTCMD, *cmd);
                PIIX4_BLOCK_DATA
            }
            SmbusOp::WriteBlockData { cmd, data } => {
                self.outb(SMBHSTADD, write);
                self.outb(SMBHSTCMD, *cmd);
                if data.is_empty() || data.len() > SMBUS_BLOCK_MAX {
                    return Err(I2cError::InvalidArgs);
                }
                self.outb(SMBHSTDAT0, data.len() as u8);
                self.inb(SMBHSTCNT); // Reset SMBBLKDAT
                for &b in data.iter() {
                    self.outb(SMBBLKDAT, b);
                }
                PIIX4_BLOCK_DATA
            }
        };

        // ENABLE_INT9 is 0: completion is polled.
        self.outb(SMBHSTCNT, size & 0x1C);
        self.transaction().await?;

        match op {
            SmbusOp::Quick { .. }
            | SmbusOp::SendByte { .. }
            | SmbusOp::WriteByteData { .. }
            | SmbusOp::WriteWordData { .. }
            | SmbusOp::WriteBlockData { .. } => Ok(()),
            SmbusOp::ReceiveByte { out } | SmbusOp::ReadByteData { out, .. } => {
                *out = self.inb(SMBHSTDAT0);
                Ok(())
            }
            SmbusOp::ReadWordData { out, .. } => {
                *out = u16::from(self.inb(SMBHSTDAT0)) | (u16::from(self.inb(SMBHSTDAT1)) << 8);
                Ok(())
            }
            SmbusOp::ReadBlockData { out, len, .. } => {
                let n = usize::from(self.inb(SMBHSTDAT0));
                if n == 0 || n > SMBUS_BLOCK_MAX {
                    return Err(I2cError::Protocol);
                }
                self.inb(SMBHSTCNT); // Reset SMBBLKDAT
                for b in out.iter_mut().take(n) {
                    *b = self.inb(SMBBLKDAT);
                }
                *len = n;
                Ok(())
            }
        }
    }
}

// ── SB800 port multiplexing ──────────────────────────────────────────

/// The main host's port multiplexer and its IMC handshake.
#[derive(Debug)]
struct Sb800Mux {
    io: Arc<dyn PortIo>,
    pm: Box<dyn FchPm>,
    /// Notify the IMC around block transfers (`notify_imc`); cleared
    /// for good after one failed handshake.
    notify_imc: AtomicBool,
}

impl Sb800Mux {
    /// `piix4_sb800_port_sel`: select `port` (already shifted) and
    /// return the previous selection.
    fn port_sel(&self, port: u8) -> u8 {
        let lo = self.pm.read8(SB800_PIIX4_PORT_IDX_KERNCZ);
        let val = (lo & !SB800_PIIX4_PORT_IDX_MASK_KERNCZ) | port;
        if lo != val {
            self.pm.write8(SB800_PIIX4_PORT_IDX_KERNCZ, val);
        }
        lo & SB800_PIIX4_PORT_IDX_MASK_KERNCZ
    }

    fn imc_read(&self, idx: u8) -> u8 {
        self.io.outb(KERNCZ_IMC_IDX, idx);
        self.io.inb(KERNCZ_IMC_DATA)
    }

    fn imc_write(&self, idx: u8, value: u8) {
        self.io.outb(KERNCZ_IMC_IDX, idx);
        self.io.outb(KERNCZ_IMC_DATA, value);
    }

    /// `piix4_imc_sleep` / `piix4_imc_wakeup`: IMC mailbox command 0x96
    /// with the ownership request (`0xB4`) or release (`0xB5`).
    async fn imc_handshake(&self, flag: u8) -> Result<(), I2cError> {
        self.imc_write(0x82, 0x00); // clear response register
        self.imc_write(0x83, flag);
        self.imc_write(0x80, 0x96);
        for _ in 0..MAX_TIMEOUT {
            if self.imc_read(0x82) == 0xfa {
                return Ok(());
            }
            narf_time::usleep_range(1000, 2000).await;
        }
        Err(I2cError::Timeout)
    }

    /// `piix4_access_sb800`.
    async fn access(
        &self,
        host: &Host,
        port: u8,
        addr: u8,
        op: SmbusOp<'_>,
    ) -> Result<(), I2cError> {
        // Request the SMBus semaphore, avoiding conflicts with the IMC.
        let mut smbslvcnt = host.inb(SMBSLVCNT);
        let mut retries = MAX_TIMEOUT;
        loop {
            host.outb(SMBSLVCNT, smbslvcnt | SMBSLVCNT_SEMAPHORE);
            smbslvcnt = host.inb(SMBSLVCNT);
            if smbslvcnt & SMBSLVCNT_SEMAPHORE != 0 {
                break;
            }
            narf_time::usleep_range(1000, 2000).await;
            retries -= 1;
            if retries == 0 {
                // Still owned by the IMC.
                return Err(I2cError::Busy);
            }
        }

        // Long (block) transactions collide with the IMC's own sensor
        // polling unless it is asked to stand off.
        let block = matches!(
            op,
            SmbusOp::ReadBlockData { .. } | SmbusOp::WriteBlockData { .. }
        );
        if block
            && self.notify_imc.load(Ordering::Acquire)
            && self.imc_handshake(0xB4).await.is_err()
        {
            log(format_args!("Failed to communicate with the IMC."));
            log(format_args!("Continuing without IMC notification."));
            self.notify_imc.store(false, Ordering::Release);
        }

        let prev = self.port_sel(port);
        let result = host.access(addr, op).await;
        self.port_sel(prev);

        // Release the semaphore.
        host.outb(SMBSLVCNT, smbslvcnt | SMBSLVCNT_RELEASE);

        if block && self.notify_imc.load(Ordering::Acquire) {
            let _ = self.imc_handshake(0xB5).await;
        }
        result
    }
}

// ── Adapters ─────────────────────────────────────────────────────────

/// One registered SMBus adapter: a host, plus the port it selects when
/// the host is the multiplexed main one.
#[derive(Debug)]
pub struct Piix4Adapter {
    name: String,
    host: Arc<Host>,
    /// Serialises every adapter on `host` — Linux's adapter lock plus
    /// the muxed PM region the main-host adapters share.
    lock: Arc<AsyncMutex<()>>,
    /// `(multiplexer, shifted port)` for main-host adapters.
    mux: Option<(Arc<Sb800Mux>, u8)>,
}

#[async_trait]
impl I2cBus for Piix4Adapter {
    async fn transfer(&self, _addr: u8, _ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        Err(I2cError::Unsupported)
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn smbus_xfer(&self, addr: u8, op: SmbusOp<'_>) -> Result<(), I2cError> {
        let _guard = self.lock.lock().await;
        match &self.mux {
            Some((mux, port)) => mux.access(&self.host, *port, addr, op).await,
            None => self.host.access(addr, op).await,
        }
    }

    /// `piix4_func`.
    fn functionality(&self) -> I2cFunc {
        I2cFunc::SMBUS_QUICK
            | I2cFunc::SMBUS_BYTE
            | I2cFunc::SMBUS_BYTE_DATA
            | I2cFunc::SMBUS_WORD_DATA
            | I2cFunc::SMBUS_BLOCK_DATA
    }
}

/// An adapter set up by [`setup_kerncz`], and whether Linux registers
/// SPD EEPROMs on it (`i2c_register_spd_write_enable` runs for the
/// adapters whose port argument is 0: main port 0 and the aux host).
#[derive(Debug)]
pub struct SetupAdapter {
    pub adapter: Arc<Piix4Adapter>,
    pub register_spd: bool,
}

/// `piix4_setup_sb800_smba`: read the host base out of the PM
/// registers. Returns `None` when the host is disabled.
fn sb800_smba(pm: &dyn FchPm, revision: u8, aux: bool) -> Option<u16> {
    let smb_en: u8 = if revision >= REV_DECODEEN {
        0x00
    } else if aux {
        0x28
    } else {
        0x2c
    };
    let lo = pm.read8(smb_en);
    let hi = pm.read8(smb_en + 1);
    let (enabled, smba) = if smb_en == 0 {
        let base = (u16::from(hi) << 8) | if aux { 0x20 } else { 0 };
        (lo & 0x10 != 0, base)
    } else {
        (
            lo & 0x01 != 0,
            ((u16::from(hi) << 8) | u16::from(lo)) & 0xffe0,
        )
    };
    if !enabled {
        log(format_args!("SMBus Host Controller not enabled!"));
        return None;
    }
    Some(smba)
}

/// `piix4_probe` for a KERNCZ function, minus the hardware lookups:
/// set up the main host's two port adapters and, unless `asf`, the
/// aux host's adapter. `None` when the main host is disabled.
pub fn setup_kerncz(
    io: Arc<dyn PortIo>,
    pm: Box<dyn FchPm>,
    revision: u8,
    notify_imc: bool,
    asf: bool,
) -> Option<Vec<SetupAdapter>> {
    let smba = sb800_smba(pm.as_ref(), revision, false)?;
    let i2ccfg = io.inb(smba + SMB_I2CCFG);
    log(format_args!(
        "SMBus Host Controller at {:#x}, revision {}",
        smba,
        i2ccfg >> 4
    ));
    log(format_args!(
        "Using register {:#04x} for SMBus port selection",
        SB800_PIIX4_PORT_IDX_KERNCZ
    ));
    let aux_smba = if asf {
        None
    } else {
        sb800_smba(pm.as_ref(), revision, true)
    };

    let mux = Arc::new(Sb800Mux {
        io: io.clone(),
        pm,
        notify_imc: AtomicBool::new(notify_imc),
    });
    let main = Arc::new(Host {
        io: io.clone(),
        smba,
    });
    let main_lock = Arc::new(AsyncMutex::new(()));
    let mut out = Vec::new();
    for (port, port_name) in MAIN_PORT_NAMES.iter().enumerate() {
        out.push(SetupAdapter {
            adapter: Arc::new(Piix4Adapter {
                name: format!("SMBus PIIX4 adapter{port_name} at {smba:04x}"),
                host: main.clone(),
                lock: main_lock.clone(),
                mux: Some((
                    mux.clone(),
                    (port as u8) << SB800_PIIX4_PORT_IDX_SHIFT_KERNCZ,
                )),
            }),
            register_spd: port == 0,
        });
    }
    if let Some(aux) = aux_smba {
        log(format_args!("Auxiliary SMBus Host Controller at {aux:#x}"));
        out.push(SetupAdapter {
            adapter: Arc::new(Piix4Adapter {
                name: format!("SMBus PIIX4 adapter{AUX_PORT_NAME} at {aux:04x}"),
                host: Arc::new(Host { io, smba: aux }),
                lock: Arc::new(AsyncMutex::new(())),
                mux: None,
            }),
            register_spd: true,
        });
    }
    Some(out)
}

/// Whether the FCH's integrated microcontroller is active and must be
/// told about block transfers: LPC bridge `00:14.3` config `0x40`
/// bit 7 (coreboot's AMD IMC notes, `piix4_probe`).
fn imc_active() -> bool {
    let Some(lpc) = narf_bus::devices().into_iter().find(|d| {
        matches!(d.kind, narf_bus::BusKind::Pcie { addr, .. }
            if addr.segment == 0 && addr.bus == 0 && addr.device == 0x14 && addr.function == 3)
    }) else {
        return false;
    };
    let narf_bus::BusKind::Pcie { cfg_phys, .. } = lpc.kind else {
        return false;
    };
    let Some(ptr) = narf_bus::ecam::ptr_for(cfg_phys, 0x40) else {
        return false;
    };
    // SAFETY: `ptr` lies inside 00:14.3's live ECAM mapping; a config
    // byte read has no side effects.
    let imc = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    imc & 0x80 != 0
}

fn pm_window(revision: u8, io: &Arc<dyn PortIo>) -> Option<Box<dyn FchPm>> {
    if revision < REV_PM_MMIO {
        return Some(Box::new(PmIndexed { io: io.clone() }));
    }
    // SAFETY: FCH_PM_BASE is the FCH's PM register window (fixed by the
    // platform); only PMx00..PMx02 are addressed through the mapping.
    let mapping = unsafe {
        narf_memory::ioremap::ioremap(
            FCH_PM_BASE,
            SB800_PIIX4_FCH_PM_SIZE,
            narf_memory::ioremap::MmioAttrs::Device,
        )
    };
    match mapping {
        Ok(m) => Some(Box::new(PmMmio { va: m.va() })),
        Err(_) => {
            log(format_args!("SMBus base address mapping failed."));
            None
        }
    }
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let revision = narf_bus::pci::read_config32(&cap, &device, 0x08)
        .map_err(|_| narf_bus::ProbeError::BadDevice)? as u8;
    let io: Arc<dyn PortIo> = Arc::new(HwPortIo);
    let pm = pm_window(revision, &io).ok_or(narf_bus::ProbeError::BadDevice)?;
    let asf = narf_aml::find_node(SB800_ASF_ACPI_PATH).is_some();
    let adapters =
        setup_kerncz(io, pm, revision, imc_active(), asf).ok_or(narf_bus::ProbeError::BadDevice)?;
    for a in adapters {
        let bus: Arc<dyn I2cBus> = a.adapter;
        let bus = crate::registry::register_unique(bus);
        if a.register_spd {
            crate::spd::register_spd_write_enable(&bus);
        }
    }
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(PciMatch {
        name: "piix4_smbus",
        kind: MatchKind::VendorDevice {
            vendor: AMD_VENDOR_ID,
            device: AMD_KERNCZ_SMBUS,
        },
        probe,
    });
}
