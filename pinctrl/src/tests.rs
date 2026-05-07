//! Smoke tests for narf-pinctrl.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── pin-mux config word round-trip ────────────────────────────────

fn smoke_pinctrl_pinmux_config_round_trip() -> TestResult {
    use crate::pinmux::{
        PinConfig, PinDirection, PinDriveOpt, PinDriveStrength, PinPull, PinPullOpt,
    };
    let cfg = PinConfig {
        function: 3,
        pull: PinPullOpt(PinPull::Up),
        drive: PinDriveOpt(PinDriveStrength::Strength12mA),
        direction: PinDirection::Output,
        output_enabled: true,
        open_drain: false,
        schmitt: true,
    };
    let v = cfg.pack();
    let r = PinConfig::unpack(v);
    if r != cfg {
        return TestResult::Fail("PinConfig round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/pinmux", smoke_pinctrl_pinmux_config_round_trip);

fn smoke_pinctrl_pinmux_input_default() -> TestResult {
    use crate::pinmux::{PinConfig, PinDirection};
    let v = PinConfig::input().pack();
    let r = PinConfig::unpack(v);
    if r.direction != PinDirection::Input || r.output_enabled || r.function != 0 {
        return TestResult::Fail("default input config is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/pinmux", smoke_pinctrl_pinmux_input_default);

// ── SPMI ──────────────────────────────────────────────────────────

fn smoke_pinctrl_spmi_extended_write_round_trip() -> TestResult {
    use crate::spmi::{build_ext_write, decode_write, SpmiOp};
    let payload: [u8; 4] = [0x10, 0x20, 0x30, 0x40];
    let buf = build_ext_write(0x05, 0xC042, &payload);
    let (h, body) = match decode_write(&buf) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("decode_write failed"),
    };
    if h.sid != 0x05 || h.op != SpmiOp::ExtWrite || h.addr != 0xC042 || h.byte_count != 4 {
        return TestResult::Fail("header round-trip failed");
    }
    if body != payload {
        return TestResult::Fail("payload round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/spmi", smoke_pinctrl_spmi_extended_write_round_trip);

fn smoke_pinctrl_spmi_extended_read_header() -> TestResult {
    use crate::spmi::{build_ext_read, decode_header, SpmiOp};
    let buf = build_ext_read(0x0A, 0x1234, 8);
    if buf.len() != 4 {
        return TestResult::Fail("ext-read should be exactly 4 header bytes");
    }
    let h = decode_header(&buf).expect("hdr");
    if h.sid != 0x0A || h.op != SpmiOp::ExtRead || h.addr != 0x1234 || h.byte_count != 8 {
        return TestResult::Fail("header decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/spmi", smoke_pinctrl_spmi_extended_read_header);

// ── DesignWare APB GPIO ───────────────────────────────────────────

fn smoke_pinctrl_dwapb_make_set_output_drives_high() -> TestResult {
    use crate::dwapb::make_set_output;
    // Start with all-zero DDR and DR; set pin 5 of bank 0 to output high.
    let (ddr, dr) = make_set_output(0, 0, 5, true);
    if ddr != (1 << 5) || dr != (1 << 5) {
        return TestResult::Fail("set-output should mask in pin 5");
    }
    // Driving low afterwards: DR clears the bit, DDR keeps it.
    let (ddr2, dr2) = make_set_output(ddr, dr, 5, false);
    if ddr2 != (1 << 5) || dr2 != 0 {
        return TestResult::Fail("drive-low should clear DR bit only");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/dwapb", smoke_pinctrl_dwapb_make_set_output_drives_high);

fn smoke_pinctrl_dwapb_bank_offsets_sanity() -> TestResult {
    use crate::dwapb::bank_offset;
    let (a_dr, a_ddr, a_ctl) = bank_offset(0).expect("bank A");
    if a_dr != 0x00 || a_ddr != 0x04 || a_ctl != 0x08 {
        return TestResult::Fail("bank A offsets wrong");
    }
    let (b_dr, _, _) = bank_offset(1).expect("bank B");
    if b_dr != 0x0C {
        return TestResult::Fail("bank B starts +0x0C from bank A");
    }
    if bank_offset(4).is_some() {
        return TestResult::Fail("bank 4 should be out of range");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/dwapb", smoke_pinctrl_dwapb_bank_offsets_sanity);

// ── Qualcomm PMIC ─────────────────────────────────────────────────

fn smoke_pinctrl_qcom_pmic_mode_ctl_output_high() -> TestResult {
    use crate::qcom_pmic::{build_mode_ctl, GpioMode, GpioOutputType};
    let v = build_mode_ctl(GpioMode::Output, GpioOutputType::Cmos, true);
    // Expected: bit 7 (output value) set, bits[6:4]=001 (Output mode),
    // bits[3:2]=00 (CMOS).
    let expected = (1 << 7) | (0b001 << 4);
    if v != expected {
        return TestResult::Fail("mode_ctl output high wrong");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/qcom-pmic", smoke_pinctrl_qcom_pmic_mode_ctl_output_high);

fn smoke_pinctrl_qcom_pmic_pushpull_writes_sequence() -> TestResult {
    use crate::qcom_pmic::{make_gpio_pushpull_output_writes, regs};
    let writes = make_gpio_pushpull_output_writes(true);
    // Order matters: PULL → OUT_CTL → MODE_CTL → EN_CTL.
    let offsets: alloc::vec::Vec<usize> = writes.iter().map(|(o, _)| *o).collect();
    let want: alloc::vec::Vec<usize> = alloc::vec![
        regs::DIG_PULL_CTL,
        regs::DIG_OUT_CTL,
        regs::MODE_CTL,
        regs::EN_CTL,
    ];
    if offsets != want {
        return TestResult::Fail("write order wrong");
    }
    if writes[3].1 & (1 << 7) == 0 {
        return TestResult::Fail("EN_CTL must set enable bit");
    }
    TestResult::Pass
}
kernel_test_in!("pinctrl/qcom-pmic", smoke_pinctrl_qcom_pmic_pushpull_writes_sequence);
