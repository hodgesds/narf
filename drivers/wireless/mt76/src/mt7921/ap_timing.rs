//! AP MAC timing, Linux mt792x_mac.c::mt792x_mac_set_timeing.
//! The Session owns the actual RF/request and the1us asynchronous pause.
use super::{Error, Hardware};
const ARB: u32 = 0x820e3080;
const STOP: u32 = 3 << 8;
impl Hardware {
    fn verify_ap_timing(&self, reg: u32, expected: u32, mask: u32) -> Result<(), Error> {
        let observed = self.read(reg)?;
        if observed & mask != expected & mask {
            // Only failed association/retiming paths print: preserve the
            // exact read that failed instead of perturbing normal MMIO.
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "mt76: MAC timing readback {reg:#010x}: observed={observed:#010x} expected={expected:#010x} mask={mask:#010x}"
            );
            return Err(Error::Register);
        }
        Ok(())
    }

    pub(super) fn pause_ap_timing(&mut self) -> Result<(), Error> {
        let value = self.read(ARB)?;
        self.write(ARB, value | STOP)?;
        self.verify_ap_timing(ARB, STOP, STOP)
    }
    /// Called only after the native pause and a bounded at-least1us wait.
    /// This fresh-reset AP owns MAC TX/RX; unrelated ARB bits are preserved.
    pub(super) fn finish_ap_timing(&mut self, five: bool, short_slot: bool) -> Result<(), Error> {
        self.verify_ap_timing(ARB, STOP, STOP)?;
        let short = five || short_slot;
        let values = [
            (0x820e4090, 231 | 48 << 16),
            (0x820e4094, 60 | 28 << 16),
            (
                0x820e40a4,
                360 | 2 << 10
                    | if five { 16 << 16 } else { 10 << 16 }
                    | if short { 9 << 24 } else { 20 << 24 },
            ),
        ];
        for (reg, value) in values {
            self.write(reg, value)?;
            self.verify_ap_timing(reg, value, u32::MAX)?;
        }
        let cfend = self.read(0x820e2084)?;
        let rate = if short { 0x49 } else { 3 };
        self.write(0x820e2084, cfend & !0x3fff | rate)?;
        self.verify_ap_timing(0x820e2084, rate, 0x3fff)?;
        let current = self.read(ARB)?;
        if current & STOP != STOP {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "mt76: MAC timing resume {ARB:#010x}: observed={current:#010x} expected={STOP:#010x} mask={STOP:#010x}"
            );
            return Err(Error::Register);
        }
        self.write(ARB, current & !STOP)?;
        self.verify_ap_timing(ARB, 0, STOP)
    }
}
