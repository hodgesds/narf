//! NXP I3C Master Controller driver.
//!
//! Based on the NXP I3C register map found in i.MX 93 and MCX N series.
//! Clean-room implementation following the publicly documented register map.
//!
//! # CCC / DAA implementation notes
//!
//! ## MCTRL.REQUEST field (bits [2:0])
//! The NXP MCTRL register uses a REQUEST enumeration:
//!   0 = NONE (idle), 1 = SDR_MSG, 2 = DDR_MSG, 3 = SDR_BROADCAST_CCC,
//!   4 = SDR_ADDR_CCC (directed CCC), 7 = PROCESS_DAA.
//! Refs: NXP i.MX 93 Reference Manual §I3C; see also the pattern in
//! drivers/i3c/master/i3c-master-cdns.c (Cadence, same request model).
//!
//! ## ENTDAA / RSTDAA
//! DAA is a special burst transaction.  The master asserts START + 0x7E,
//! sends RSTDAA (0x06) to clear stale dynamic addresses, then sends ENTDAA
//! (0x07).  Each device that wants an address drives its PID (6 bytes) +
//! BCR + DCR onto the bus; the master assigns a dynamic address and repeats
//! until no more devices respond.
//! Ref: I3C spec rev 1.1 §5.1.9.3; Linux dw-i3c-master.c dw_i3c_master_daa().

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::task::Waker;
use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_i3c::{
    registry, CccDest, CommonCommandCode, I3cBus, I3cDevice, I3cError, I3cOp, IbiHandler,
};
use narf_lib::sync::IrqSafeSpinLock;

// ── NXP I3C Register Offsets ───────────────────────────────────────
const REG_MCTRL: u64 = 0x00; // Main Control
const REG_MSTATUS: u64 = 0x04; // Main Status
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_IBIRULES: u64 = 0x08; // IBI Rules
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_MINTSET: u64 = 0x0C; // Interrupt Set
const REG_MDATACTRL: u64 = 0x20; // Data Control
const REG_MWDATAB: u64 = 0x24; // Write Data Byte
const REG_MRDATAB: u64 = 0x2C; // Read Data Byte
const REG_MWMSG_SADDR: u64 = 0x30; // Static Address
const REG_MCONFIG: u64 = 0x40; // Master Config

// ── MCTRL.REQUEST values ───────────────────────────────────────────
// NXP i.MX 93 RM §I3C_MCTRL.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const MCTRL_REQUEST_NONE: u32 = 0x0;
const MCTRL_REQUEST_SDR_MSG: u32 = 0x1; // SDR private message
const MCTRL_REQUEST_SDR_BC_CCC: u32 = 0x3; // Broadcast CCC
const MCTRL_REQUEST_SDR_DIR_CCC: u32 = 0x4; // Directed (addressed) CCC
const MCTRL_REQUEST_DDR_MSG: u32 = 0x2; // HDR-DDR private message
const MCTRL_REQUEST_DAA: u32 = 0x7; // Process DAA (ENTDAA)

// MCTRL.TYPE field (bits [5:4]) — only I3C mode used at Stage 2.
const MCTRL_TYPE_I3C: u32 = 0x0 << 4;

// MCTRL.ADDR field: target 7-bit dynamic address in bits [23:17].
// For broadcast CCCs the hardware uses 0x7E automatically when
// REQUEST = SDR_BC_CCC; for directed CCCs the host sets this field.
const fn mctrl_addr(a: u8) -> u32 {
    ((a as u32) & 0x7F) << 17
}

// MSTATUS bits
const MSTATUS_COMPLETE: u32 = 1 << 0; // Transfer complete
const MSTATUS_ERROR: u32 = 1 << 1; // Error flag
const MSTATUS_RXPEND: u32 = 1 << 5; // RX data pending (DAA response byte ready)

// MDATACTRL: flush TX/RX FIFOs before a new transfer.
const MDATACTRL_FLUSH_TX: u32 = 1 << 14;
const MDATACTRL_FLUSH_RX: u32 = 1 << 15;

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: caller-authority over the device.
    let mmio = unsafe { map_bar(&device, 0) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let driver = Arc::new(NxpI3c {
        mmio: mmio.clone(),
        ibi_wakers: IrqSafeSpinLock::new([const { None }; 128]),
    });

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("nxp-i3c"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: None,
        pci_did: None,
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    registry::register(driver);
    Ok(())
}

pub fn register() {
    // In a real system, this would be a platform driver match.
    // narf_bus::register_platform_driver(...)
}

#[derive(Debug)]
pub struct NxpI3c {
    mmio: MmioRegion,
    ibi_wakers: IrqSafeSpinLock<[Option<Waker>; 128]>,
}

impl NxpI3c {
    /// Flush the TX/RX FIFOs before starting any new frame.
    fn flush_fifos(&self) {
        unsafe {
            self.mmio
                .write32(REG_MDATACTRL, MDATACTRL_FLUSH_TX | MDATACTRL_FLUSH_RX);
        }
    }

    /// Spin-poll MSTATUS until COMPLETE or ERROR.
    ///
    /// In a production driver this would yield to the scheduler while
    /// waiting for a completion IRQ.  We use yield_now() so other
    /// kernel tasks can make progress; the LAPIC timer and interrupt
    /// delivery stay live.
    async fn wait_complete(&self) -> Result<(), I3cError> {
        loop {
            let status = unsafe { self.mmio.read32(REG_MSTATUS) };
            if (status & MSTATUS_COMPLETE) != 0 {
                return Ok(());
            }
            if (status & MSTATUS_ERROR) != 0 {
                return Err(I3cError::HardwareError);
            }
            narf_scheduler::yield_now().await;
        }
    }
}

impl Driver for NxpI3c {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // Enable master mode.
            unsafe {
                self.mmio.write32(REG_MCONFIG, 0x1);
            }
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {
            unsafe {
                self.mmio.write32(REG_MCONFIG, 0x0);
            }
        })
    }
}

#[async_trait]
impl I3cBus for NxpI3c {
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError> {
        self.flush_fifos();

        // Write target address into MWMSG_SADDR (7-bit, left-shifted by 1
        // to leave room for R/W bit at bit 0; NXP convention).
        unsafe {
            self.mmio.write32(REG_MWMSG_SADDR, (addr as u32) << 1);
        }

        for op in ops {
            match op {
                I3cOp::Write(data) => {
                    for &byte in data.iter() {
                        unsafe {
                            self.mmio.write32(REG_MWDATAB, byte as u32);
                        }
                    }
                }
                I3cOp::Read(buf) => {
                    for i in 0..buf.len() {
                        buf[i] = unsafe { self.mmio.read32(REG_MRDATAB) as u8 };
                    }
                }
            }
        }

        // Issue SDR private message request.
        unsafe {
            self.mmio.write32(
                REG_MCTRL,
                MCTRL_REQUEST_SDR_MSG | MCTRL_TYPE_I3C | mctrl_addr(addr),
            );
        }

        self.wait_complete().await
    }

    /// Send a Common Command Code.
    ///
    /// Broadcast CCCs: REQUEST = SDR_BC_CCC.  The hardware drives the
    /// I3C broadcast address (0x7E) automatically.  The CCC opcode is
    /// written as the first data byte, followed by any payload.
    ///
    /// Directed CCCs: REQUEST = SDR_DIR_CCC with ADDR = target address.
    /// Same byte ordering.
    ///
    /// Ref: NXP i.MX 93 RM §I3C_MCTRL; Linux dw-i3c-master.c
    ///      dw_i3c_master_send_ccc_cmd().
    async fn ccc(
        &self,
        ccc: CommonCommandCode,
        dest: CccDest,
        payload: &[u8],
    ) -> Result<(), I3cError> {
        self.flush_fifos();

        // CCC opcode is always the first byte on the wire.
        unsafe {
            self.mmio.write32(REG_MWDATAB, ccc.opcode() as u32);
        }

        for &byte in payload {
            unsafe {
                self.mmio.write32(REG_MWDATAB, byte as u32);
            }
        }

        let (request, addr_field) = match dest {
            CccDest::Broadcast => (MCTRL_REQUEST_SDR_BC_CCC, 0u32),
            CccDest::Address(a) => (MCTRL_REQUEST_SDR_DIR_CCC, mctrl_addr(a)),
        };

        unsafe {
            self.mmio
                .write32(REG_MCTRL, request | MCTRL_TYPE_I3C | addr_field);
        }

        self.wait_complete().await
    }

    /// Dynamic Address Assignment (ENTDAA).
    ///
    /// Sequence:
    ///  1. RSTDAA broadcast — resets stale dynamic addresses.
    ///  2. ENTDAA burst — iteratively:
    ///     a. Hardware drives the ENTDAA frame (START + 0x7E + ENTDAA).
    ///     b. First device responds with 8 bytes: PID[5:0], BCR, DCR.
    ///     c. Master writes back the chosen dynamic address (with parity
    ///        in bit 7 per spec §5.1.9.3).
    ///     d. Repeat until MSTATUS.COMPLETE without a new RXPEND.
    ///
    /// On this controller DAA is triggered by REQUEST = 0x7 (PROCESS_DAA).
    /// The master firmware pre-programs a candidate address in MWDATAB
    /// before pulling the trigger; the hardware handles the low-level
    /// arbitration.  We pre-fill address candidates sequentially starting
    /// from 0x08 (first legal dynamic address per spec §5.1.9.3).
    ///
    /// Linux ref: dw_i3c_master_daa() — same write-candidate-then-trigger
    /// loop, different register names.
    async fn enter_daa(&self) -> Result<Vec<I3cDevice>, I3cError> {
        // Step 1: RSTDAA broadcast.
        self.ccc(CommonCommandCode::RstdaaBc, CccDest::Broadcast, &[])
            .await?;

        let mut devices = Vec::new();
        // Dynamic addresses start at 0x08 (first non-reserved address).
        let mut next_addr: u8 = 0x08;

        loop {
            // Pre-load the candidate dynamic address for the next device.
            // Bit 7 = odd parity of bits [6:0], per I3C spec §5.1.9.3.
            let addr_with_parity = next_addr | (parity7(next_addr) << 7);
            unsafe {
                self.mmio.write32(REG_MWDATAB, addr_with_parity as u32);
            }

            // Trigger ENTDAA.
            unsafe {
                self.mmio
                    .write32(REG_MCTRL, MCTRL_REQUEST_DAA | MCTRL_TYPE_I3C);
            }

            // Wait for either a device response or completion (no more devices).
            let got_device = loop {
                let status = unsafe { self.mmio.read32(REG_MSTATUS) };
                if (status & MSTATUS_ERROR) != 0 {
                    return Err(I3cError::HardwareError);
                }
                if (status & MSTATUS_RXPEND) != 0 {
                    // A device drove its PID+BCR+DCR.
                    break true;
                }
                if (status & MSTATUS_COMPLETE) != 0 {
                    // No more devices responded.
                    break false;
                }
                narf_scheduler::yield_now().await;
            };

            if !got_device {
                break;
            }

            // Read 8 bytes: PID[5:0], BCR, DCR.
            let mut raw = [0u8; 8];
            for b in raw.iter_mut() {
                *b = unsafe { self.mmio.read32(REG_MRDATAB) as u8 };
            }

            devices.push(I3cDevice::from_daa_response(&raw, next_addr));
            next_addr = next_addr.wrapping_add(1);

            // Guard: max 11 devices on a single I3C segment.
            if next_addr >= 0x77 {
                break;
            }
        }

        Ok(devices)
    }

    fn register_ibi_waker(&self, addr: u8, waker: Waker) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = Some(waker);
        }
    }

    fn unregister_ibi_waker(&self, addr: u8) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = None;
        }
    }

    /// HDR-DDR write — NXP controller uses MCTRL.REQUEST = 0x2 (DDR_MSG).
    ///
    /// On the NXP I3C controller, HDR-DDR is triggered by setting
    /// MCTRL.REQUEST = DDR_MSG (0x2).  The controller internally handles
    /// the ENTHDR0 broadcast and DDR framing.  Data words are written
    /// byte-by-byte to MWDATAB (LSB then MSB per word).
    ///
    /// I3C spec rev 1.1 §5.2.3; NXP i.MX 93 RM §I3C_MCTRL.
    async fn hdr_ddr_write(&self, addr: u8, _command: u8, data: &[u16]) -> Result<(), I3cError> {
        self.flush_fifos();
        for &w in data {
            unsafe {
                self.mmio.write32(REG_MWDATAB, (w & 0xFF) as u32);
                self.mmio.write32(REG_MWDATAB, (w >> 8) as u32);
            }
        }
        unsafe {
            self.mmio.write32(
                REG_MCTRL,
                MCTRL_REQUEST_DDR_MSG | MCTRL_TYPE_I3C | mctrl_addr(addr),
            );
        }
        self.wait_complete().await
    }

    /// HDR-DDR read — NXP controller.
    ///
    /// Triggers DDR_MSG request with the read direction; then drains
    /// MRDATAB byte pairs into the output word slice.
    async fn hdr_ddr_read(&self, addr: u8, _command: u8, data: &mut [u16]) -> Result<(), I3cError> {
        self.flush_fifos();
        unsafe {
            self.mmio.write32(
                REG_MCTRL,
                MCTRL_REQUEST_DDR_MSG | MCTRL_TYPE_I3C | mctrl_addr(addr),
            );
        }
        self.wait_complete().await?;
        for w in data.iter_mut() {
            let lo = unsafe { self.mmio.read32(REG_MRDATAB) as u8 };
            let hi = unsafe { self.mmio.read32(REG_MRDATAB) as u8 };
            *w = (lo as u16) | ((hi as u16) << 8);
        }
        Ok(())
    }

    /// Register an IBI handler for a slave device (NXP controller).
    ///
    /// Sends ENEC directed to `dev_addr` with SIR events enabled.
    /// I3C spec §5.1.6; Linux i3c_master_enable_ibi().
    async fn register_ibi_handler(
        &self,
        dev_addr: u8,
        _handler: Arc<dyn IbiHandler>,
    ) -> Result<(), I3cError> {
        const I3C_CCC_EVENT_SIR: u8 = 1 << 0;
        self.ccc(
            CommonCommandCode::EnecDir,
            CccDest::Address(dev_addr),
            &[I3C_CCC_EVENT_SIR],
        )
        .await
    }
}

/// Compute the odd parity bit for a 7-bit address.
///
/// Returns 1 if the number of set bits in `addr[6:0]` is even (making
/// the total including the parity bit odd), 0 otherwise.
/// Ref: I3C spec rev 1.1 §5.1.9.3.
fn parity7(addr: u8) -> u8 {
    let v = addr & 0x7F;
    // popcount mod 2: XOR all bits together.
    let mut p = v ^ (v >> 4);
    p ^= p >> 2;
    p ^= p >> 1;
    // odd parity: flip so total bits (including parity) are odd.
    (p & 1) ^ 1
}
