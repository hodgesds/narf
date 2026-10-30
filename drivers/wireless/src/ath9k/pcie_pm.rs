// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 PCIe power-save workarounds. Linux ath9k pci.c::ath_pci_aspm_init,
//! ar9002_hw.c::ar9002_hw_configpcipowersave and ar9002_initvals.h.
use super::identity::{BringUpError, RegisterIo};

pub(super) fn enabled(
    device: &narf_bus::BusDevice,
    cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<bool, BringUpError> {
    let read = cap.derive().map_err(|_| BringUpError::DeviceGone)?;
    narf_bus::pci_express::parent_link_control(&read, device)
        .map(|control| control.is_some_and(|control| control & 3 != 0))
        .map_err(|_| BringUpError::DeviceGone)
}

pub(super) fn restore(
    device: &narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    mmio: narf_bus::MmioRegion,
    xe2: bool,
) -> Result<bool, BringUpError> {
    let aspm = enabled(device, &cap)?;
    configure(
        &mut super::identity::Registers::new(mmio, cap),
        aspm,
        xe2,
        false,
    )?;
    Ok(aspm)
}

// ar9280PciePhy_clkreq_always_on_L1_9280, also selected for AR9285.
const SERDES: [u32; 9] = [
    0x9248_fd00,
    0x2492_4924,
    0xa800_0019,
    0x1316_0820,
    0xe598_0560,
    0xc01d_cffd,
    0x1aaa_be41,
    0xbe10_5554,
    0x0004_3007,
];
const WA: u64 = 0x4004;
const PM: u64 = 0x4014;
const L1_ENABLE: u32 = 1 << 19;
const D3_L1_DISABLE: u32 = 1 << 14;
const D0_WORKAROUND: u32 = (1 << 6) | (1 << 7);

/// Apply only after the upstream link's current ASPM setting was read.
/// This changes device-local SerDes/workaround registers, never PCIe link
/// policy on the endpoint or bridge. `xe2` is the actual SYNTH9 fact.
pub(super) fn configure(
    io: &mut impl RegisterIo,
    enabled: bool,
    xe2: bool,
    power_off: bool,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    if !enabled {
        return Ok(());
    }
    if !power_off {
        for value in SERDES {
            io.write32(0x4040, value);
        }
        io.write32(0x4044, 0);
        io.delay_us(1000);
    }
    let pm = io.read32(PM);
    if pm == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    if power_off {
        io.write32(PM, pm & !L1_ENABLE);
        let wa = io.read32(WA);
        if wa == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        // AR9285_WA_DEFAULT lacks D3_L1_DISABLE, so preserve its prior
        // value. Clear bits6/7 before D3 to avoid the documented hang.
        io.write32(WA, (wa & !D0_WORKAROUND) | if xe2 { 1 << 23 } else { 0 });
    } else {
        let wa = (0x004a_050b & !D3_L1_DISABLE) | D0_WORKAROUND | if xe2 { 1 << 23 } else { 0 };
        io.write32(WA, wa);
        io.write32(PM, pm | L1_ENABLE);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        Read(u64),
        Write(u64, u32),
        Delay(u64),
    }
    #[derive(Default)]
    struct Model {
        registers: BTreeMap<u64, u32>,
        ops: Vec<Op>,
        revoked: bool,
    }
    impl RegisterIo for Model {
        fn authorized(&self) -> bool {
            !self.revoked
        }
        fn read32(&mut self, offset: u64) -> u32 {
            self.ops.push(Op::Read(offset));
            *self.registers.get(&offset).unwrap_or(&0)
        }
        fn write32(&mut self, offset: u64, value: u32) {
            self.ops.push(Op::Write(offset, value));
            self.registers.insert(offset, value);
        }
        fn delay_us(&mut self, us: u64) {
            self.ops.push(Op::Delay(us));
        }
    }

    fn smoke_ath9k_pcie_power_preserves_platform_policy_and_d3_workarounds() -> TestResult {
        let mut disabled = Model::default();
        if configure(&mut disabled, false, false, false).is_err() || !disabled.ops.is_empty() {
            return TestResult::Fail("disabled ASPM still touched PCIe SerDes");
        }
        for xe2 in [false, true] {
            let mut model = Model::default();
            model.registers.insert(PM, 0x1234);
            if configure(&mut model, true, xe2, false).is_err() {
                return TestResult::Fail("AR9285 D0 PCIe workarounds refused");
            }
            // Literal table entries and workarounds from Linux
            // ar9280PciePhy_clkreq_always_on_L1_9280 / AR9285_WA_DEFAULT.
            let expected = vec![
                Op::Write(0x4040, 0x9248fd00),
                Op::Write(0x4040, 0x24924924),
                Op::Write(0x4040, 0xa8000019),
                Op::Write(0x4040, 0x13160820),
                Op::Write(0x4040, 0xe5980560),
                Op::Write(0x4040, 0xc01dcffd),
                Op::Write(0x4040, 0x1aaabe41),
                Op::Write(0x4040, 0xbe105554),
                Op::Write(0x4040, 0x00043007),
                Op::Write(0x4044, 0),
                Op::Delay(1000),
                Op::Read(0x4014),
                Op::Write(0x4004, if xe2 { 0x00ca05cb } else { 0x004a05cb }),
                Op::Write(0x4014, 0x81234),
            ];
            if model.ops != expected {
                return TestResult::Fail("AR9285 SerDes/D0 sequence differs from source");
            }
            model.ops.clear();
            model.registers.insert(WA, 0x504a45cb);
            if configure(&mut model, true, xe2, true).is_err()
                || model.ops
                    != vec![
                        Op::Read(0x4014),
                        Op::Write(0x4014, 0x1234),
                        Op::Read(0x4004),
                        Op::Write(0x4004, if xe2 { 0x50ca450b } else { 0x504a450b }),
                    ]
            {
                return TestResult::Fail("AR9285 D3 bits6/7 or reserved WA preservation");
            }
        }
        let mut revoked = Model {
            revoked: true,
            ..Model::default()
        };
        if configure(&mut revoked, true, false, false) != Err(BringUpError::DeviceGone)
            || !revoked.ops.is_empty()
        {
            return TestResult::Fail("revoked PCIe workaround authority touched registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath9k/pcie_pm",
        smoke_ath9k_pcie_power_preserves_platform_policy_and_d3_workarounds
    );
}
