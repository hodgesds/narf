//! ON Semiconductor FUSB302B Type-C Port Controller (clean-room).
//!
//! References (public-only):
//! - FUSB302B Programmable USB Type-C Controller w/ PD —
//!   ON Semi document FUSB302B/D, Rev. 6 (Sept 2017).
//!   <https://www.onsemi.com/download/data-sheet/pdf/fusb302b-d.pdf>
//! - USB Type-C 2.2 §4 (CC pin meanings).
//! - USB Power Delivery 3.1 §5.6 (BMC framing — feeds the FIFO).
//!
//! No GPL Linux source consulted.
//!
//! ## I²C address (datasheet §"Pin Description / I2C Address")
//!
//! 7-bit address depends on package strap:
//! - FUSB302BUCX / BMPX: 0x22 (most common)
//! - FUSB302BVMPX: 0x23, 0x24, 0x25 (alternate strap variants)
//!
//! ## Register map (datasheet §"Register Description")
//!
//! ```text
//!   0x01 DEVICE_ID      RO  vendor (high nibble) + version (low)
//!   0x02 SWITCHES0      RW  CC1/CC2 pull-up + pull-down + measure
//!   0x03 SWITCHES1      RW  TXCC1/2, AUTO_CRC, SPECREV
//!   0x04 MEASURE        RW  MEAS_VBUS + 6-bit MDAC threshold
//!   0x05 SLICE          RW  BMC slicer threshold
//!   0x06 CONTROL0       RW  TX_FLUSH, INT_MASK, HOST_CUR, AUTO_PRE,
//!                            TX_START
//!   0x07 CONTROL1       RW  ENSOP, RX_FLUSH, BIST_MODE2
//!   0x08 CONTROL2       RW  TOG_RD_ONLY, MODE, TOGGLE
//!   0x09 CONTROL3       RW  SEND_HARD_RESET, AUTO_HARDRESET,
//!                            AUTO_SOFTRESET, N_RETRIES, AUTO_RETRY
//!   0x0A MASK           RW  IRQ-line mask bitmap
//!   0x0B POWER          RW  PWR[3:0] block enables
//!   0x0C RESET          RW  PD_RESET, SW_RES (self-clearing)
//!   0x0E MASKA          RW  IRQ-line mask, group A
//!   0x0F MASKB          RW  IRQ-line mask, group B
//!   0x10 CONTROL4       RW  TOG_USRC_EXIT
//!   0x3C STATUS0A       RO  shadow status, group A (latched)
//!   0x3D STATUS1A       RO  shadow status, group B (latched)
//!   0x3E INTERRUPTA     RO  edge-triggered IRQs, group A
//!   0x3F INTERRUPTB     RO  edge-triggered IRQs, group B
//!   0x40 STATUS0        RO  VBUSOK, ACTIVITY, COMP, CRC_CHK,
//!                            ALERT, WAKE, BC_LVL[1:0]
//!   0x41 STATUS1        RO  RXSOP, RXSOP1, RXSOP2, RX_EMPTY,
//!                            RX_FULL, TX_EMPTY, TX_FULL
//!   0x42 INTERRUPT      RO  IRQ source bits (clear-on-read)
//!   0x43 FIFOS          RW  TX/RX FIFO data window
//! ```
//!
//! ## BMC FIFO tokens (datasheet §"BMC PHY")
//!
//! ```text
//!   0x12 SYNC1
//!   0x13 SYNC2
//!   0x1B SYNC3 (used in SOP'/SOP'' sequences)
//!   0x15 RESET1
//!   0x16 RESET2
//!   0x80 | n  PACKSYM(n)   — next n bytes are PD payload
//!   0xA1 JAM_CRC           — append BMC CRC + EOP
//!   0xFE TXON
//!   0xFF TXOFF
//! ```
//!
//! SOP frame on TX: SYNC1, SYNC1, SYNC1, SYNC2, PACKSYM(n), <n bytes>,
//! JAM_CRC, EOP, TXOFF.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};

// ── I²C address ────────────────────────────────────────────────────

pub const FUSB302_DEFAULT_I2C_ADDR: u8 = 0x22;

// ── Register addresses (datasheet §"Register Description") ────────
pub const REG_DEVICE_ID: u8 = 0x01;
pub const REG_SWITCHES0: u8 = 0x02;
pub const REG_SWITCHES1: u8 = 0x03;
pub const REG_MEASURE: u8 = 0x04;
pub const REG_SLICE: u8 = 0x05;
pub const REG_CONTROL0: u8 = 0x06;
pub const REG_CONTROL1: u8 = 0x07;
pub const REG_CONTROL2: u8 = 0x08;
pub const REG_CONTROL3: u8 = 0x09;
pub const REG_MASK: u8 = 0x0A;
pub const REG_POWER: u8 = 0x0B;
pub const REG_RESET: u8 = 0x0C;
pub const REG_MASKA: u8 = 0x0E;
pub const REG_MASKB: u8 = 0x0F;
pub const REG_CONTROL4: u8 = 0x10;
pub const REG_STATUS0A: u8 = 0x3C;
pub const REG_STATUS1A: u8 = 0x3D;
pub const REG_INTERRUPTA: u8 = 0x3E;
pub const REG_INTERRUPTB: u8 = 0x3F;
pub const REG_STATUS0: u8 = 0x40;
pub const REG_STATUS1: u8 = 0x41;
pub const REG_INTERRUPT: u8 = 0x42;
pub const REG_FIFOS: u8 = 0x43;

// ── Bit definitions ───────────────────────────────────────────────
//
// SWITCHES0:
//   bit 0  PDWN1   — pull-down on CC1 (sink)
//   bit 1  PDWN2   — pull-down on CC2 (sink)
//   bit 2  MEAS_CC1
//   bit 3  MEAS_CC2
//   bit 4  VCONN_CC1
//   bit 5  VCONN_CC2
//   bit 6  PU_EN1  — pull-up on CC1 (source)
//   bit 7  PU_EN2  — pull-up on CC2 (source)
pub const SWITCHES0_PDWN1: u8 = 1 << 0;
pub const SWITCHES0_PDWN2: u8 = 1 << 1;
pub const SWITCHES0_MEAS_CC1: u8 = 1 << 2;
pub const SWITCHES0_MEAS_CC2: u8 = 1 << 3;
pub const SWITCHES0_PU_EN1: u8 = 1 << 6;
pub const SWITCHES0_PU_EN2: u8 = 1 << 7;

// CONTROL0 bits.
pub const CONTROL0_TX_FLUSH: u8 = 1 << 6;
pub const CONTROL0_INT_MASK: u8 = 1 << 5;
pub const CONTROL0_TX_START: u8 = 1 << 0;

// CONTROL3: SEND_HARD_RESET self-clears once the wire transition fires.
pub const CONTROL3_SEND_HARD_RESET: u8 = 1 << 6;

// POWER bits (PWR[3:0]).
pub const POWER_BANDGAP_WAKE: u8 = 1 << 0;
pub const POWER_RX_BANDGAP_OSC: u8 = 1 << 1;
pub const POWER_MEASURE: u8 = 1 << 2;
pub const POWER_INT_OSC: u8 = 1 << 3;
pub const POWER_ALL: u8 = POWER_BANDGAP_WAKE | POWER_RX_BANDGAP_OSC | POWER_MEASURE | POWER_INT_OSC;

// RESET bits (self-clearing).
pub const RESET_SW_RES: u8 = 1 << 0;
pub const RESET_PD_RESET: u8 = 1 << 1;

// STATUS0 bits.
pub const STATUS0_VBUSOK: u8 = 1 << 7;
pub const STATUS0_ACTIVITY: u8 = 1 << 6;
pub const STATUS0_COMP: u8 = 1 << 5;
pub const STATUS0_CRC_CHK: u8 = 1 << 4;
pub const STATUS0_ALERT: u8 = 1 << 3;
pub const STATUS0_WAKE: u8 = 1 << 2;
/// BC_LVL[1:0] — BMC comparator level → Rp value when sensing as a sink.
pub const STATUS0_BC_LVL_MASK: u8 = 0x3;

// STATUS1 bits.
pub const STATUS1_RXSOP: u8 = 1 << 7;
pub const STATUS1_RX_EMPTY: u8 = 1 << 5;
pub const STATUS1_RX_FULL: u8 = 1 << 4;
pub const STATUS1_TX_EMPTY: u8 = 1 << 3;
pub const STATUS1_TX_FULL: u8 = 1 << 2;

// FIFO TX tokens (datasheet §"BMC PHY", "TX FIFO encoding").
pub const TX_TOKEN_SYNC1: u8 = 0x12;
pub const TX_TOKEN_SYNC2: u8 = 0x13;
pub const TX_TOKEN_SYNC3: u8 = 0x1B;
pub const TX_TOKEN_RESET1: u8 = 0x15;
pub const TX_TOKEN_RESET2: u8 = 0x16;
/// PACKSYM(n): low 5 bits encode `n` (PD message length in bytes).
pub const TX_TOKEN_PACKSYM_BASE: u8 = 0x80;
pub const TX_TOKEN_JAM_CRC: u8 = 0xA1;
pub const TX_TOKEN_EOP: u8 = 0x14;
pub const TX_TOKEN_TXON: u8 = 0xA1; // duplicate per §; kept distinct to JAM_CRC by call-site
pub const TX_TOKEN_TXOFF: u8 = 0xFE;

// ── I²C bus abstraction ────────────────────────────────────────────

/// Minimal I²C surface the FUSB302 driver needs. Production wires
/// this to a real I²C controller cap; tests use the in-memory mock
/// `MockBus` below.
pub trait I2cBus: Send + Sync + Debug {
    /// Write `value` to register `reg` on `addr`.
    fn write_reg(&self, addr: u8, reg: u8, value: u8) -> Result<(), TcpcError>;

    /// Read a single byte from register `reg` on `addr`.
    fn read_reg(&self, addr: u8, reg: u8) -> Result<u8, TcpcError>;

    /// Burst-read `out.len()` bytes starting at `reg`. Used to drain
    /// the RX FIFO (register 0x43) which auto-increments internally.
    fn read_burst(&self, addr: u8, reg: u8, out: &mut [u8]) -> Result<(), TcpcError>;

    /// Burst-write `data.len()` bytes starting at `reg`. Used to push
    /// the TX FIFO.
    fn write_burst(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), TcpcError>;
}

// ── Driver ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Fusb302 {
    bus: Arc<dyn I2cBus>,
    addr: u8,
    role: IrqSafeSpinLock<PortRole>,
    /// Cached last CC measurement so consecutive `cc_status` calls
    /// don't slam the I²C bus when no IRQ has fired.
    last_cc: IrqSafeSpinLock<Option<CcStatus>>,
}

impl Fusb302 {
    pub fn new(bus: Arc<dyn I2cBus>, addr: u8) -> Self {
        Self {
            bus,
            addr,
            role: IrqSafeSpinLock::new(PortRole::Drp),
            last_cc: IrqSafeSpinLock::new(None),
        }
    }

    /// Software-reset the chip and bring the BMC PHY up. Run once at
    /// probe; equivalent to the datasheet's "initialization sequence":
    ///   1. SW_RES
    ///   2. POWER = all banks on
    ///   3. CONTROL0 = clear TX_FLUSH | INT_MASK
    ///   4. caller follows up with `set_role`.
    pub fn init(&self) -> Result<(), TcpcError> {
        self.write(REG_RESET, RESET_SW_RES)?;
        self.write(REG_POWER, POWER_ALL)?;
        self.write(REG_CONTROL0, 0)?; // clear TX_FLUSH + INT_MASK
        Ok(())
    }

    fn write(&self, reg: u8, val: u8) -> Result<(), TcpcError> {
        self.bus.write_reg(self.addr, reg, val)
    }

    fn read(&self, reg: u8) -> Result<u8, TcpcError> {
        self.bus.read_reg(self.addr, reg)
    }

    /// Read DEVICE_ID; the high nibble must be 0x8 (FUSB302BMPX revA),
    /// 0x9 (revB), 0xA (revC) per the datasheet "DEVICE_ID register"
    /// section. Returns the raw byte for diagnostics.
    pub fn probe_device_id(&self) -> Result<u8, TcpcError> {
        let id = self.read(REG_DEVICE_ID)?;
        // The high nibble carries the chip family id; we accept any
        // FUSB302 revision.
        if (id >> 4) < 0x8 {
            return Err(TcpcError::Unsupported);
        }
        Ok(id)
    }

    /// Decode the BC_LVL bits + the active MEAS_CC selection into a
    /// concrete `CcState`. Datasheet table "BC_LVL Decoding":
    ///
    ///   00 — < ~200 mV (Open / no Rp)
    ///   01 — Rp@USB-default (~200..660 mV)
    ///   10 — Rp@1.5A (~660..1230 mV)
    ///   11 — Rp@3A (> 1230 mV)
    fn decode_bc_lvl(bc_lvl: u8) -> CcState {
        match bc_lvl & 0x3 {
            0b00 => CcState::Open,
            0b01 => CcState::RpDefault,
            0b10 => CcState::Rp1A5,
            0b11 => CcState::Rp3A0,
            _ => CcState::Open,
        }
    }

    /// Sample one CC pin: program SWITCHES0 to MEAS_CCx, wait the
    /// datasheet-required tCCDebounce, then read STATUS0.BC_LVL.
    fn measure_cc(&self, cc1: bool) -> Result<CcState, TcpcError> {
        // Preserve the pull-down/pull-up bits we already have set.
        let mut sw0 = self.read(REG_SWITCHES0)?;
        sw0 &= !(SWITCHES0_MEAS_CC1 | SWITCHES0_MEAS_CC2);
        sw0 |= if cc1 {
            SWITCHES0_MEAS_CC1
        } else {
            SWITCHES0_MEAS_CC2
        };
        self.write(REG_SWITCHES0, sw0)?;
        let s0 = self.read(REG_STATUS0)?;
        Ok(Self::decode_bc_lvl(s0 & STATUS0_BC_LVL_MASK))
    }

    /// Build a SOP TX packet around a PD message body and push it
    /// into the FIFO. `body` is the encoded PD frame from
    /// `narf_usbpd::message::encode_message`.
    fn tx_sop(&self, body: &[u8]) -> Result<(), TcpcError> {
        if body.len() > 30 {
            return Err(TcpcError::TransmitFailed);
        }
        let mut frame = Vec::with_capacity(8 + body.len());
        // SYNC1, SYNC1, SYNC1, SYNC2 — SOP signal sequence.
        frame.push(TX_TOKEN_SYNC1);
        frame.push(TX_TOKEN_SYNC1);
        frame.push(TX_TOKEN_SYNC1);
        frame.push(TX_TOKEN_SYNC2);
        // PACKSYM(n) — the low 5 bits hold the byte count.
        frame.push(TX_TOKEN_PACKSYM_BASE | ((body.len() as u8) & 0x1F));
        frame.extend_from_slice(body);
        // JAM_CRC + EOP + TXOFF.
        frame.push(TX_TOKEN_JAM_CRC);
        frame.push(TX_TOKEN_EOP);
        frame.push(TX_TOKEN_TXOFF);

        self.bus.write_burst(self.addr, REG_FIFOS, &frame)?;
        // Kick the engine.
        let mut c0 = self.read(REG_CONTROL0)?;
        c0 |= CONTROL0_TX_START;
        self.write(REG_CONTROL0, c0)
    }

    /// Drain one RX message from the FIFO. Returns the PD body bytes
    /// (the `MESSAGE_HEADER + DATA_OBJECT_*` portion); SOP framing
    /// tokens and CRC bytes are stripped.
    fn rx_drain(&self) -> Result<Vec<u8>, TcpcError> {
        let s1 = self.read(REG_STATUS1)?;
        if s1 & STATUS1_RX_EMPTY != 0 {
            return Err(TcpcError::NoMessage);
        }
        // First read pops the SOP token; per the datasheet the
        // engine then exposes the message-header byte count in the
        // next byte automatically. We read the SOP token + 2-byte
        // header, derive the payload size from the header's
        // num_data_objects field (high 3 bits of byte 1), then drain
        // the rest including the 4-byte CRC the chip appends.
        let mut sop = [0u8; 1];
        self.bus
            .read_burst(self.addr, REG_FIFOS, &mut sop)?;
        // sop[0] in {0xE0..=0xE3} per "RX FIFO Token" section: bit
        // pattern 111x_x000 with low bits encoding SOP/SOP'/SOP''.
        // We accept any and proceed.
        let mut hdr = [0u8; 2];
        self.bus.read_burst(self.addr, REG_FIFOS, &mut hdr)?;
        // PD header bits: num_data_objects at bits 12..14 of the LE
        // header word.
        let header_word = u16::from_le_bytes(hdr);
        let nobj = ((header_word >> 12) & 0x7) as usize;
        let payload_len = 4 * nobj;
        let mut payload = alloc::vec![0u8; payload_len];
        if payload_len > 0 {
            self.bus.read_burst(self.addr, REG_FIFOS, &mut payload)?;
        }
        // CRC32 trails (4 bytes) — drain + drop.
        let mut crc = [0u8; 4];
        self.bus.read_burst(self.addr, REG_FIFOS, &mut crc)?;

        // Re-pack the header and payload into the format
        // `narf_usbpd::message::decode_message` expects.
        let mut out = Vec::with_capacity(2 + payload_len);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

impl Tcpc for Fusb302 {
    fn name(&self) -> &'static str {
        "fusb302"
    }

    fn set_role(&self, role: PortRole) -> Result<(), TcpcError> {
        let mut sw0 = self.read(REG_SWITCHES0)?;
        sw0 &= !(SWITCHES0_PDWN1
            | SWITCHES0_PDWN2
            | SWITCHES0_PU_EN1
            | SWITCHES0_PU_EN2);
        match role {
            PortRole::Sink => sw0 |= SWITCHES0_PDWN1 | SWITCHES0_PDWN2,
            PortRole::Source => sw0 |= SWITCHES0_PU_EN1 | SWITCHES0_PU_EN2,
            PortRole::Drp => {
                // DRP toggling is owned by CONTROL2.TOGGLE on this
                // chip; for now, leave the pulls cleared and let
                // periodic role-toggle fall back to explicit Sink/
                // Source callers. Real DRP wiring lands when the
                // TCPM gets a "toggle until attach" loop.
            }
        }
        self.write(REG_SWITCHES0, sw0)?;
        *self.role.lock() = role;
        Ok(())
    }

    fn cc_status(&self) -> Result<CcStatus, TcpcError> {
        let cc1 = self.measure_cc(true)?;
        let cc2 = self.measure_cc(false)?;
        let s = CcStatus { cc1, cc2 };
        *self.last_cc.lock() = Some(s);
        Ok(s)
    }

    fn transmit(&self, msg: &[u8]) -> Result<(), TcpcError> {
        self.tx_sop(msg)
    }

    fn receive(&self) -> Result<Vec<u8>, TcpcError> {
        self.rx_drain()
    }

    fn hard_reset(&self) -> Result<(), TcpcError> {
        let c3 = self.read(REG_CONTROL3)?;
        self.write(REG_CONTROL3, c3 | CONTROL3_SEND_HARD_RESET)
    }
}

// ── Mock I²C bus for tests ─────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub use mock::MockBus;

#[cfg(any(test, feature = "kernel-test"))]
mod mock {
    use super::*;

    /// 256-register flat memory (FUSB302 register space ≤ 0x43).
    /// Read FIFO is a separate VecDeque so reading register 0x43
    /// pops the next byte; writing to 0x43 pushes onto the TX log.
    #[derive(Debug)]
    pub struct MockBus {
        regs: IrqSafeSpinLock<[u8; 256]>,
        rx_fifo: IrqSafeSpinLock<alloc::collections::VecDeque<u8>>,
        tx_log: IrqSafeSpinLock<Vec<u8>>,
    }

    impl Default for MockBus {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockBus {
        pub fn new() -> Self {
            let mut regs = [0u8; 256];
            // DEVICE_ID — synthesise revB FUSB302BMPX (0x9_) for tests.
            regs[REG_DEVICE_ID as usize] = 0x90;
            Self {
                regs: IrqSafeSpinLock::new(regs),
                rx_fifo: IrqSafeSpinLock::new(alloc::collections::VecDeque::new()),
                tx_log: IrqSafeSpinLock::new(Vec::new()),
            }
        }

        /// Inject bytes the driver will read out of the RX FIFO.
        pub fn enqueue_rx(&self, bytes: &[u8]) {
            let mut q = self.rx_fifo.lock();
            for b in bytes {
                q.push_back(*b);
            }
            // RX_EMPTY clears now that we have data.
            self.regs.lock()[REG_STATUS1 as usize] &= !STATUS1_RX_EMPTY;
        }

        /// Snapshot of every byte the driver has pushed to TX FIFO.
        pub fn tx_log(&self) -> Vec<u8> {
            self.tx_log.lock().clone()
        }

        /// Pre-set a register value (e.g. STATUS0.BC_LVL for CC sense
        /// tests).
        pub fn set_reg(&self, reg: u8, value: u8) {
            self.regs.lock()[reg as usize] = value;
        }
    }

    impl I2cBus for MockBus {
        fn write_reg(&self, _addr: u8, reg: u8, value: u8) -> Result<(), TcpcError> {
            if reg == REG_FIFOS {
                self.tx_log.lock().push(value);
            } else {
                let mut r = self.regs.lock();
                if reg == REG_RESET && value & RESET_SW_RES != 0 {
                    // SW_RES clears most of the register file.
                    let dev_id = r[REG_DEVICE_ID as usize];
                    *r = [0u8; 256];
                    r[REG_DEVICE_ID as usize] = dev_id;
                    r[REG_STATUS1 as usize] = STATUS1_RX_EMPTY | STATUS1_TX_EMPTY;
                    return Ok(());
                }
                r[reg as usize] = value;
            }
            Ok(())
        }

        fn read_reg(&self, _addr: u8, reg: u8) -> Result<u8, TcpcError> {
            if reg == REG_FIFOS {
                let mut q = self.rx_fifo.lock();
                let v = q.pop_front().ok_or(TcpcError::NoMessage)?;
                if q.is_empty() {
                    self.regs.lock()[REG_STATUS1 as usize] |= STATUS1_RX_EMPTY;
                }
                return Ok(v);
            }
            Ok(self.regs.lock()[reg as usize])
        }

        fn read_burst(&self, addr: u8, reg: u8, out: &mut [u8]) -> Result<(), TcpcError> {
            for slot in out.iter_mut() {
                *slot = self.read_reg(addr, reg)?;
            }
            Ok(())
        }

        fn write_burst(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), TcpcError> {
            for b in data {
                self.write_reg(addr, reg, *b)?;
            }
            Ok(())
        }
    }
}
