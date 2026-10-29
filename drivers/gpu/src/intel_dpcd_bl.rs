//! Intel eDP DPCD backlight device (issue #957).
//!
//! Drives panel brightness through the eDP DPCD backlight block over
//! the AUX channel, for panels whose brightness is AUX-controlled
//! (increasingly common, and the only path when the PWM pin is not
//! routed). The device implements
//! [`narf_drivers_backlight::BacklightDevice`] and registers into the
//! arbitrated backlight stack via [`install`], alongside the existing
//! PWM device (`narf_drivers_backlight::intel_bl`).
//!
//! ## Registers used (all pinned — see Sources)
//!
//! * `0x722` — `BACKLIGHT_BRIGHTNESS_MSB`
//! * `0x723` — `BACKLIGHT_BRIGHTNESS_LSB`
//!
//! The brightness field width is a per-panel fact, carried as
//! `lsb_used`: when the panel uses the LSB register the level is a
//! 16-bit MSB-first value (`(msb << 8) | lsb`, max `0xFFFF`); otherwise
//! it is the MSB byte alone (max `0xFF`). Reads request exactly the
//! field width, and writes carry exactly the field width — never a
//! blanket 2-byte access, which would touch `0x723` on an 8-bit panel.
//!
//! AUX framing is the crate's [`crate::dp_aux`] layer (VESA DP 1.4a
//! §2.7): `dpcd_read`/`dpcd_write` build NATIVE_READ/NATIVE_WRITE
//! requests; the transport (real `IntelAux` MMIO, or the fixture's
//! panel model) owns retries and reply decoding. This device is
//! generic over [`crate::dp_aux::AuxChannel`], so the production
//! channel and the fixture channel are the same conversation at the
//! same layer.
//!
//! ## Arbitration
//!
//! Kind is [`narf_drivers_backlight::BacklightKind::Raw`] (direct
//! hardware control, like the PWM device). The registry keeps the
//! earliest registration on a priority tie, so install ordering
//! against `intel_bl::install` decides which native device owns a
//! panel that offers both paths — see the remainder note below.
//!
//! ## Deliberately NOT in this lane (remainder, follow-up issue)
//!
//! * Mode selection at `0x721` (`BACKLIGHT_MODE`): switching a panel
//!   into DPCD control mode. The control-mode field encoding could
//!   not be pinned to a citable source in this lane (the VESA eDP
//!   spec text is paywalled; every public Linux source consulted
//!   uses symbolic names, never the numeric field values), and a
//!   guessed selector could switch a real panel to the wrong control
//!   source. Panels already in DPCD control mode — the firmware
//!   state for AUX-only panels — are driven correctly by this lane.
//! * Capability probe of the `0x700` block (TCON / AUX-enable /
//!   AUX-set / byte-count caps) and the `0x720` display-control
//!   enable bit: same grounding gap, same reason.
//! * Probe-time wiring: no call site installs this device yet. An
//!   unconditional install would register a DPCD candidate on every
//!   Intel panel, including PWM panels where it must never promote.
//!   The follow-up probes the `0x700` caps, installs only on
//!   full-AUX panels, and installs BEFORE `intel_bl::install` so the
//!   DPCD device wins the Raw tie on AUX-only panels.
//!
//! ## Sources
//!
//! * Issue #957 (VESA eDP backlight block: `0x721` mode, `0x722/0x723`
//!   brightness).
//! * VESA DisplayPort 1.4a §2.7 (AUX transactions), via the
//!   spec-shaped [`crate::dp_aux`] framing layer.
//! * Linux `drivers/gpu/drm/i915/display/intel_dp_aux_backlight.c`
//!   and the extracted `drm_edp_backlight` helpers, as the public
//!   reference implementation of the VESA backlight protocol, for the
//!   field-width semantics: max is `0xFFFF` iff the LSB register is
//!   used, else `0xFF`; get reads MSB-first; set writes
//!   `1 + lsb_reg_used` bytes. The VESA eDP spec text itself was not
//!   directly consulted (paywalled); a reviewer holding it should
//!   eyeball the mode/cap remainder, not this lane's registers.
//! * The generic PWM panel backlight half of #957 (`pwm_bl`-style
//!   device on a `narf-pwm` channel) is likewise remainder: it was
//!   optional scope and is not in this lane.

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write as FmtWrite;

use narf_drivers_backlight::{register_backlight, BacklightDevice, BacklightKind, Ownership};
use narf_lib::sync::IrqSafeSpinLock;

use crate::dp_aux::AuxChannel;

/// DPCD address of `BACKLIGHT_BRIGHTNESS_MSB` (issue #957).
pub const DPCD_BACKLIGHT_BRIGHTNESS_MSB: u32 = 0x722;
/// DPCD address of `BACKLIGHT_BRIGHTNESS_LSB` (issue #957).
pub const DPCD_BACKLIGHT_BRIGHTNESS_LSB: u32 = 0x723;

/// eDP panel backlight driven over DPCD through an AUX channel.
///
/// Generic over the channel so production (`IntelAux`-backed) and
/// fixture (panel-model) channels run the same device code. The
/// channel is held behind an [`IrqSafeSpinLock`] because
/// [`BacklightDevice`] methods take `&self` while
/// [`AuxChannel::transact`] takes `&mut self`.
pub struct DpcdBacklightDevice<C: AuxChannel> {
    name: String,
    channel: IrqSafeSpinLock<C>,
    /// True when the panel uses the LSB register (16-bit levels).
    lsb_used: bool,
}

impl<C: AuxChannel> core::fmt::Debug for DpcdBacklightDevice<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DpcdBacklightDevice")
            .field("name", &self.name)
            .field("lsb_used", &self.lsb_used)
            .field("max", &self.max_level())
            .finish()
    }
}

impl<C: AuxChannel> DpcdBacklightDevice<C> {
    /// Build a device. `lsb_used` is the panel's field-width fact:
    /// true for 16-bit levels (`0x722` + `0x723`), false for 8-bit
    /// levels (`0x722` alone). It comes from the panel's `0x700`
    /// capability block once the follow-up probe lands; until then
    /// the install caller supplies it.
    pub fn new(name: &str, channel: C, lsb_used: bool) -> Self {
        Self {
            name: String::from(name),
            channel: IrqSafeSpinLock::new(channel),
            lsb_used,
        }
    }

    /// Maximum level for this panel's field width (reference-implementation
    /// rule: `0xFFFF` iff the LSB register is used, else `0xFF`).
    fn max_level(&self) -> u32 {
        if self.lsb_used {
            0xFFFF
        } else {
            0xFF
        }
    }

    /// Read the current level, or `None` on any AUX failure.
    fn read_level(&self) -> Option<u32> {
        let mut buf = [0u8; 2];
        let n = 1 + self.lsb_used as usize;
        self.channel
            .lock()
            .dpcd_read(DPCD_BACKLIGHT_BRIGHTNESS_MSB, &mut buf[..n])
            .ok()?;
        Some(if self.lsb_used {
            ((buf[0] as u32) << 8) | buf[1] as u32
        } else {
            buf[0] as u32
        })
    }

    /// Write `level` (already clamped) at exactly the field width.
    fn write_level(&self, level: u32) {
        let bytes = [(level >> 8) as u8, level as u8];
        let payload = if self.lsb_used {
            &bytes[..2]
        } else {
            &bytes[..1]
        };
        // The trait returns `()` and sysfs stores cannot surface an
        // AUX error; a failed write is a silent no-op, like the PWM
        // device's unconditional MMIO write.
        let _ = self
            .channel
            .lock()
            .dpcd_write(DPCD_BACKLIGHT_BRIGHTNESS_MSB, payload);
    }
}

impl<C: AuxChannel + Send> BacklightDevice for DpcdBacklightDevice<C> {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max_level()
    }

    fn current_brightness(&self) -> u32 {
        // Trait contract: 0 on any read failure.
        self.read_level().unwrap_or(0)
    }

    fn set_brightness(&self, level: u32) {
        // The caller clamps before dispatch (trait contract); clamp
        // again defensively so an unclamped direct caller cannot
        // push a 16-bit value into an 8-bit panel's MSB byte.
        self.write_level(level.min(self.max_level()));
    }

    fn kind(&self) -> BacklightKind {
        // Direct hardware control via AUX, like the PWM device.
        BacklightKind::Raw
    }
}

/// Register a DPCD backlight device into the arbitrated stack.
///
/// This is the seam the eDP bring-up follow-up calls once the `0x700`
/// capability probe lands: on full-AUX panels it must run BEFORE
/// `intel_bl::install`, so this device wins the Raw tie (ties keep
/// the earliest registration) and the PWM device defers. Returns the
/// device's standing after registration.
pub fn install<C: AuxChannel + Send + 'static>(channel: C, lsb_used: bool) -> Ownership {
    let dev = DpcdBacklightDevice::new("intel_dpcd_bl0", channel, lsb_used);
    let _ = writeln!(
        narf_console::Writer,
        "  intel-dpcd-backlight: registered, lsb_used={}",
        dev.lsb_used
    );
    register_backlight(Arc::new(dev))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    //! AUX-conversation fixture: a panel-side DPCD model.
    //!
    //! The fake is the panel, not the transport: it receives the
    //! already-framed [`AuxRequest`] (as the real `IntelAux` +
    //! `decode_response` path would deliver after wire transfer)
    //! and serves it from a DPCD register file. It honours the
    //! requested length exactly — a device that asks for the wrong
    //! field width is caught by the transcript, not masked by a
    //! fake that ignores lengths (the `dpcd_read(&[])` trap the
    //! `dp_aux` docs warn about).

    extern crate alloc;

    use super::*;
    use crate::dp_aux::{
        decode_response, encode_request, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus,
    };
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Panel-side DPCD model: a register file plus a transcript of
    /// every native transaction, split into reads (address +
    /// requested length) and writes (address + payload).
    #[derive(Debug)]
    struct FakeDpcdPanel {
        regs: [u8; 0x800],
        reads: Vec<(u32, usize)>,
        writes: Vec<(u32, Vec<u8>)>,
        /// When false the panel NACKs every transaction (link down).
        present: bool,
    }

    impl FakeDpcdPanel {
        fn new() -> Self {
            Self {
                regs: [0u8; 0x800],
                reads: Vec::new(),
                writes: Vec::new(),
                present: true,
            }
        }

        fn set_reg(&mut self, addr: u32, val: u8) {
            self.regs[addr as usize] = val;
        }

        fn reg(&self, addr: u32) -> u8 {
            self.regs[addr as usize]
        }
    }

    impl AuxChannel for FakeDpcdPanel {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            if !self.present {
                return Err(AuxError::Nacked);
            }
            match req.cmd {
                AuxCommand::NativeRead => {
                    let n = req.data.len();
                    let start = req.address as usize;
                    if start + n > self.regs.len() || reply_buf.len() < 1 + n {
                        return Err(AuxError::Nacked);
                    }
                    self.reads.push((req.address, n));
                    reply_buf[0] = (AuxStatus::Ack as u8) << 4;
                    reply_buf[1..1 + n].copy_from_slice(&self.regs[start..start + n]);
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1 + n],
                    })
                }
                AuxCommand::NativeWrite => {
                    let start = req.address as usize;
                    if start + req.data.len() > self.regs.len() || reply_buf.is_empty() {
                        return Err(AuxError::Nacked);
                    }
                    self.writes.push((req.address, req.data.to_vec()));
                    self.regs[start..start + req.data.len()].copy_from_slice(req.data);
                    reply_buf[0] = (AuxStatus::Ack as u8) << 4;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                _ => Err(AuxError::Nacked),
            }
        }
    }

    fn smoke_wire_frame_pin_byte_for_byte() -> TestResult {
        // DP 1.4a §2.7 frame, via the spec-shaped dp_aux layer:
        // byte 0 = (cmd << 4) | address-high-nibble, byte 1 =
        // address-mid, byte 2 = address-low, byte 3 = len - 1,
        // then the payload (writes only).
        let mut out = [0u8; 20];
        let req = AuxRequest {
            cmd: AuxCommand::NativeWrite,
            address: DPCD_BACKLIGHT_BRIGHTNESS_MSB,
            data: &[0xAB, 0xCD],
        };
        match encode_request(&req, &mut out) {
            Ok(6) => {}
            _ => return TestResult::Fail("write frame must be 6 bytes"),
        }
        if out[..6] != [0x80, 0x07, 0x22, 0x01, 0xAB, 0xCD] {
            return TestResult::Fail("NATIVE_WRITE 0x722 [AB CD] wire bytes wrong");
        }
        let req = AuxRequest {
            cmd: AuxCommand::NativeRead,
            address: DPCD_BACKLIGHT_BRIGHTNESS_MSB,
            data: &[0u8; 2],
        };
        match encode_request(&req, &mut out) {
            Ok(4) => {}
            _ => return TestResult::Fail("read frame must be 4 bytes"),
        }
        if out[..4] != [0x90, 0x07, 0x22, 0x01] {
            return TestResult::Fail("NATIVE_READ 0x722 len-2 wire bytes wrong");
        }
        // Reply side: ACK + payload passes through; a NACK status
        // nibble maps to Nacked, never to a payload.
        match decode_response(&[0x00, 0xAB, 0xCD], 2) {
            Ok(resp) if resp.status == AuxStatus::Ack && resp.data == [0xAB, 0xCD] => {}
            _ => return TestResult::Fail("ACK reply decode wrong"),
        }
        match decode_response(&[0x10, 0xAB, 0xCD], 2) {
            Err(AuxError::Nacked) => {}
            _ => return TestResult::Fail("NACK reply must map to Nacked"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_dpcd_bl",
        smoke_wire_frame_pin_byte_for_byte
    );

    fn smoke_brightness_16bit_round_trip() -> TestResult {
        let mut panel = FakeDpcdPanel::new();
        panel.set_reg(DPCD_BACKLIGHT_BRIGHTNESS_MSB, 0xAB);
        panel.set_reg(DPCD_BACKLIGHT_BRIGHTNESS_LSB, 0xCD);
        let dev = DpcdBacklightDevice::new("intel_dpcd_bl0", panel, true);
        if dev.max_brightness() != 0xFFFF {
            return TestResult::Fail("16-bit max must be 0xFFFF");
        }
        if dev.kind() != BacklightKind::Raw {
            return TestResult::Fail("DPCD device kind must be Raw");
        }
        if dev.current_brightness() != 0xABCD {
            return TestResult::Fail("16-bit read must be MSB-first 0xABCD");
        }
        dev.set_brightness(0x1234);
        let panel = &dev.channel.lock();
        if panel.reg(DPCD_BACKLIGHT_BRIGHTNESS_MSB) != 0x12
            || panel.reg(DPCD_BACKLIGHT_BRIGHTNESS_LSB) != 0x34
        {
            return TestResult::Fail("16-bit write must store MSB then LSB");
        }
        if panel.writes.len() != 1
            || panel.writes[0] != (DPCD_BACKLIGHT_BRIGHTNESS_MSB, alloc::vec![0x12, 0x34])
        {
            return TestResult::Fail("16-bit write transcript must be one 2-byte write at 0x722");
        }
        if panel.reads.len() != 1 || panel.reads[0] != (0x722, 2) {
            return TestResult::Fail("16-bit read transcript must be one 2-byte read at 0x722");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_dpcd_bl",
        smoke_brightness_16bit_round_trip
    );

    fn smoke_brightness_8bit_field_width() -> TestResult {
        let mut panel = FakeDpcdPanel::new();
        panel.set_reg(DPCD_BACKLIGHT_BRIGHTNESS_MSB, 0x5A);
        // Trap value in the LSB register: an 8-bit device must
        // never read it, and never write it.
        panel.set_reg(DPCD_BACKLIGHT_BRIGHTNESS_LSB, 0xEE);
        let dev = DpcdBacklightDevice::new("intel_dpcd_bl0", panel, false);
        if dev.max_brightness() != 0xFF {
            return TestResult::Fail("8-bit max must be 0xFF");
        }
        if dev.current_brightness() != 0x5A {
            return TestResult::Fail("8-bit read must be the MSB byte alone, not 0x5AEE");
        }
        dev.set_brightness(0x77);
        let panel = &dev.channel.lock();
        if panel.reg(DPCD_BACKLIGHT_BRIGHTNESS_MSB) != 0x77 {
            return TestResult::Fail("8-bit write must store the MSB byte");
        }
        if panel.reg(DPCD_BACKLIGHT_BRIGHTNESS_LSB) != 0xEE {
            return TestResult::Fail("8-bit write must leave 0x723 untouched");
        }
        if panel.writes.len() != 1
            || panel.writes[0] != (DPCD_BACKLIGHT_BRIGHTNESS_MSB, alloc::vec![0x77])
        {
            return TestResult::Fail("8-bit write transcript must be one 1-byte write at 0x722");
        }
        if panel.reads.len() != 1 || panel.reads[0] != (0x722, 1) {
            return TestResult::Fail("8-bit read transcript must be one 1-byte read at 0x722");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_dpcd_bl",
        smoke_brightness_8bit_field_width
    );

    fn smoke_read_failure_returns_zero_and_set_is_silent() -> TestResult {
        let mut panel = FakeDpcdPanel::new();
        panel.present = false;
        let dev = DpcdBacklightDevice::new("intel_dpcd_bl0", panel, true);
        if dev.current_brightness() != 0 {
            return TestResult::Fail("NACKed read must report 0");
        }
        // Must not panic: the trait returns () and has no error
        // channel, so a failed write is a silent no-op.
        dev.set_brightness(0x1234);
        let panel = &dev.channel.lock();
        if !panel.reads.is_empty() || !panel.writes.is_empty() {
            return TestResult::Fail("NACKed panel must record no completed transaction");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_dpcd_bl",
        smoke_read_failure_returns_zero_and_set_is_silent
    );

    fn smoke_step_defaults_and_clamp() -> TestResult {
        let panel = FakeDpcdPanel::new();
        let dev = DpcdBacklightDevice::new("intel_dpcd_bl0", panel, true);
        // Default step is a tenth of the range: 0 -> 6553 (0x1999).
        dev.step_up();
        if dev.current_brightness() != 6553 {
            return TestResult::Fail("step_up from 0 must reach 6553");
        }
        dev.step_down();
        if dev.current_brightness() != 0 {
            return TestResult::Fail("step_down must return to 0");
        }
        // Defensive clamp: a direct caller above max cannot push a
        // 17-bit value into the panel's registers.
        dev.set_brightness(0x1_FFFF);
        if dev.current_brightness() != 0xFFFF {
            return TestResult::Fail("set above max must clamp to 0xFFFF");
        }
        let dev8 = DpcdBacklightDevice::new("intel_dpcd_bl0", FakeDpcdPanel::new(), false);
        dev8.set_brightness(0x1FF);
        if dev8.current_brightness() != 0xFF {
            return TestResult::Fail("8-bit set above max must clamp to 0xFF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_dpcd_bl", smoke_step_defaults_and_clamp);
}
