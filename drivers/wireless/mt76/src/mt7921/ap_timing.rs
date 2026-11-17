//! AP MAC timing, Linux mt792x_mac.c::mt792x_mac_set_timeing.
//! The Session owns the actual RF/request and the 1us asynchronous pause.
use super::{Error, Hardware};
const ARB: u32 = 0x820e3080;
const STOP: u32 = 3 << 8;
impl Hardware {
    pub(super) fn pause_ap_timing(&mut self) -> Result<(), Error> {
        let value = self.read(ARB)?;
        // Linux uses these as control writes, not a stop-status handshake.
        // On MT7922 the immediate readback can be zero; requiring STOP to
        // latch aborted association before authentication on real hardware.
        // The caller supplies the same >=1us pause as mt792x_mac_set_timeing.
        self.write(ARB, value | STOP)
    }
    /// Called only after the native pause and a bounded at-least1us wait.
    /// This fresh-reset AP owns MAC TX/RX; unrelated ARB bits are preserved.
    pub(super) fn finish_ap_timing(&mut self, five: bool, short_slot: bool) -> Result<(), Error> {
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
        }
        let cfend = self.read(0x820e2084)?;
        let rate = if short { 0x49 } else { 3 };
        self.write(0x820e2084, cfend & !0x3fff | rate)?;
        let current = self.read(ARB)?;
        self.write(ARB, current & !STOP)
    }
}
