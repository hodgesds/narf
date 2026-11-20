// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal source PCI quirks and their actual inactive board/PHY program.
use super::*;
use crate::ath9k::ar9003::board::Config;

const CUS: [(u16, u16); 6] = [
    (0x1a3b, 0x2086),
    (0x1a3b, 0x1237),
    (0x1a3b, 0x2126),
    (0x1a3b, 0x126a),
    (0x1a3b, 0x2152),
    (0x105b, 0xe075),
];
fn pci(vendor: u16, device: u16, subvendor: u16, subdevice: u16) -> narf_bus::DeviceId {
    narf_bus::DeviceId {
        vendor,
        device,
        class: 0x0002_8000,
        subsystem_vendor: subvendor,
        subsystem_id: subdevice,
    }
}
fn margin_writes(io: &Regs) -> usize {
    io.writes.iter().filter(|&&(r, _)| r == 0x9e18).count()
}
fn smoke_ath9k_ar9485_source_pcoem_inputs_and_gpio_fallback() -> TestResult {
    for (sv, si) in CUS {
        let config = Config::for_pci(&pci(0x168c, 0x0032, sv, si));
        if config.identity_bytes() != [9, 1, 1, 0, 0x88, 0xbb, 0x0b, 0] {
            return TestResult::Fail("CUS198/CUS230 canonical board inputs");
        }
        let mut image = board_image();
        image[map::TXRX_GAIN] = 0x40; // raw RX0, independent TX4.
        image[map::MODAL_2G + modal::XATTEN1_MARGIN] = 13;
        image[map::EXT1 + map::EXT1_ANT_DIV_CONTROL] = 0;
        let mut io = Regs::default();
        io.regs.insert(0x4050, 0xa5a5_5a5a);
        io.regs.insert(0x406c, 0x5aa5_a55a);
        if board::set_board_values_configured(&mut io, Chip::Ar9485, &image, 2412, 1, 1, config)
            .is_err()
            || io.regs.get(&0x4050) != Some(&0xa5ad_5a5a)
            || io.regs.get(&0x406c).copied().unwrap_or(0) & 0x000f_8000 != 0x0000_8000
            || io.regs.get(&0x406c).copied().unwrap_or(0) & !0x000f_8000
                != 0x5aa5_a55a & !0x000f_8000
            || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0x500a
            || margin_writes(&io) != 3
            // A configured switch mask does not imply manual BT sharing.
            || io.regs.get(&0xa28c).copied().unwrap_or(0) != 0x0012_3456
            || io.regs.get(&0x9e28).copied().unwrap_or(0) & 0x0100_0000 != 0
            || io.regs.get(&0x9fc0).copied().unwrap_or(0) & 0x2000 != 0
        {
            return TestResult::Fail("CUS board GPIO9/margin5/extra RMW or closed BT sharing");
        }
    }
    for id in [
        pci(0x168c, 0x0032, 0x1a3b, 0x2087),
        pci(0x168c, 0x0032, 0x105b, 0x2086),
        pci(0x168c, 0x0037, 0x1a3b, 0x2086), // AR1111 has no CUS match.
        pci(0x168c, 0x0036, 0x1a3b, 0x2086),
        pci(0x1234, 0x0032, 0x1a3b, 0x2086),
    ] {
        if Config::for_pci(&id) != Config::default() {
            return TestResult::Fail("board quirk crossed PCI/subsystem identity");
        }
    }
    // GPIO fallback is determined by raw EEPROM RX0. A gain-table fallback
    // for another raw index must not silently select the GPIO branch.
    for raw in 0..16 {
        let mut image = board_image();
        image[map::TXRX_GAIN] = 0x40 | raw;
        image[map::MODAL_2G + modal::XATTEN1_MARGIN] = 13;
        let mut io = Regs::default();
        if board::set_board_values(&mut io, Chip::Ar9485, &image, 2412, 1, 1).is_err()
            || io.regs.contains_key(&0x4050) != (raw == 0)
            || io.regs.contains_key(&0x406c) != (raw == 0)
            || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0xd00a
            || margin_writes(&io) != 2
        {
            return TestResult::Fail("AR9485 default GPIO raw-index gate or EEPROM margin");
        }
    }
    let config = Config::for_pci(&pci(0x168c, 0x0032, 0x105b, 0xe075));
    for raw in [1, 4, 15] {
        let mut image = board_image();
        image[map::TXRX_GAIN] = 0x40 | raw;
        image[map::MODAL_2G + modal::XATTEN1_MARGIN] = 13;
        let mut io = Regs::default();
        if board::set_board_values_configured(&mut io, Chip::Ar9485, &image, 2412, 1, 1, config)
            .is_err()
            || io.regs.contains_key(&0x4050)
            || io.regs.contains_key(&0x406c)
            || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0xd00a
            || margin_writes(&io) != 3
        {
            return TestResult::Fail("CUS nonzero raw RX index inherited margin5/GPIO0 branch");
        }
    }
    TestResult::Pass
}

struct LostMux {
    io: Regs,
    lost: bool,
}
impl RegisterIo for LostMux {
    fn authorized(&self) -> bool {
        !self.lost
    }
    fn read32(&mut self, offset: u64) -> u32 {
        if offset == 0x406c {
            self.lost = true;
            u32::MAX
        } else {
            self.io.read32(offset)
        }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.io.write32(offset, value);
    }
}
fn smoke_ath9k_ar9485_configured_prepare_and_gpio_refusal() -> TestResult {
    let config = Config::for_pci(&pci(0x168c, 0x0032, 0x105b, 0xe075));
    let mut image = board_image();
    image[map::TXRX_MASK] = 0x11;
    image[map::OP_FLAGS] = 2;
    image[map::TXRX_GAIN] = 0;
    image[map::MODAL_2G + modal::XATTEN1_MARGIN] = 13;
    let id = identity(&image);
    let revision = Revision {
        chip: Chip::Ar9485,
        mac_rev: 1,
        pcie: true,
    };
    let pll = super::super::super::serdes::PllPwrsave::resolve(Chip::Ar9485, 0x105b, 0xe075);
    let mut io = Regs::default();
    let prepared = prepare_with_board(&mut io, &revision, &id, pll, &image, 2412, 0xe0, 0, config);
    let expected = expected_with_board(&revision, &id, pll, &image, 2412, 0xe0, 0, config);
    if prepared.is_err()
        || prepared != expected
        || prepared.as_ref().is_ok_and(|p| p.board_config != config)
        || io.regs.get(&0x4050).copied().unwrap_or(0) & 0x000c_0000 != 0x000c_0000
        || io.regs.get(&0x406c).copied().unwrap_or(0) & 0x000f_8000 != 0x0000_8000
        || io.regs.get(&0x9e18).copied().unwrap_or(0) & 0x1f000 != 0x5000
        || io.regs.get(&0x24) != Some(&0)
        || io.regs.get(&0x8) != Some(&0x20)
        || io.regs.get(&0xa20c) != Some(&0)
    {
        return TestResult::Fail(
            "configured AR9485 preparation/expected identity or inactive gates",
        );
    }
    let mut io = Regs::default();
    if prepare_with_board(&mut io, &revision, &id, pll, &image, 5180, 0xe0, 0, config).is_ok()
        || !io.writes.is_empty()
    {
        return TestResult::Fail("configured AR9485 widened channel admission");
    }
    let wrong = Revision {
        chip: Chip::Ar9300,
        ..revision
    };
    if prepare_with_board(&mut io, &wrong, &id, pll, &image, 2412, 0xe0, 0, config).is_ok()
        || !io.writes.is_empty()
    {
        return TestResult::Fail("CUS board program crossed chip before refusal");
    }
    let mut io = LostMux {
        io: Regs::default(),
        lost: false,
    };
    if board::set_board_values_configured(&mut io, Chip::Ar9485, &image, 2412, 1, 1, config)
        != Err(BringUpError::DeviceGone)
        || io.io.regs.get(&0x4050) != Some(&0x000c_0000)
        || io.io.regs.contains_key(&0x406c)
        || io.io.regs.contains_key(&0xa288)
    {
        return TestResult::Fail("lost GPIO authority continued board programming");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9485_source_pcoem_inputs_and_gpio_fallback
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9485_configured_prepare_and_gpio_refusal
);

fn smoke_ath9k_ar9565_no_manual_bt_board_order_and_exact_capability_suppression() -> TestResult {
    for (sv, si, suppress) in [
        (0, 0, false),
        (0x105b, 0xe068, true),
        (0x105b, 0xe069, false),
    ] {
        let config = Config::for_pci(&pci(0x168c, 0x0036, sv, si));
        if config.suppress_9565_combining() != suppress
            || config.identity_bytes()[3] != u8::from(suppress)
            || config.check_chip(Chip::Ar9565).is_err()
            || suppress && config.check_chip(Chip::Ar9485).is_ok()
        {
            return TestResult::Fail("WB335 capability suppression crossed exact PCI/chip facts");
        }
        let mut image = board_image();
        image[map::EXT1 + map::EXT1_ANT_DIV_CONTROL] = 0;
        let mut io = Regs::default();
        io.regs.insert(0x9e28, 0x01800600);
        io.regs.insert(0x1a64, 0xabcdffff);
        if board::set_board_values_configured(&mut io, Chip::Ar9565, &image, 2412, 1, 1, config)
            .is_err()
            || io.regs.get(&0x9e28) != Some(&0x12000600)
            || io.regs.get(&0x1a64) != Some(&0xabcd7fff)
            || io.regs.get(&0x9fc0).copied().unwrap_or(0) & 0x2000 == 0
        {
            return TestResult::Fail(
                "AR9565 fixed0xc9 did not clear source no-BT LNADIV/protect/force",
            );
        }
        let writes: Vec<_> = io
            .writes
            .iter()
            .copied()
            .filter(|&(r, _)| r == 0x9e28 || r == 0x1a64)
            .collect();
        let expected = if suppress {
            &[
                (0x9e28, 0x01000600),
                (0x1a64, 0xabcd7fff),
                (0x9e28, 0x12000600),
            ][..]
        } else {
            &[
                (0x9e28, 0x01000600),
                (0x1a64, 0xabcd7fff),
                (0x9e28, 0x12000600),
                (0x9e28, 0x12000600),
            ][..]
        };
        if writes.as_slice() != expected {
            return TestResult::Fail(
                "AR9565 no-request board sequence invented/dropped a capability write",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_no_manual_bt_board_order_and_exact_capability_suppression
);
