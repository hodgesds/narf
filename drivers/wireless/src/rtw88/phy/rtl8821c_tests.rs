use super::mac_tests::{ready_8821c, Model};
use super::*;
use crate::rtw88::{
    efuse::Factory8821c,
    firmware_lifecycle,
    phy8821c::{self, Info},
};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("rtl8821c_golden.rs");
fn hash(trace: &[(u8, u8, u16, u32)]) -> u64 {
    let mut hash = 14695981039346656037u64;
    for &(op, width, reg, data) in trace {
        let kind = match (op, width) {
            (0, 32) => 0,
            (1, 32) => 1,
            (8, 0) => 2,
            (1, 8) => 3,
            (0, 8) => 4,
            _ => panic!("non-C21 PHY reference operation"),
        };
        for byte in core::iter::once(kind)
            .chain(u32::from(reg).to_le_bytes())
            .chain(data.to_le_bytes())
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
    }
    hash
}
fn info(cut: u8, package: u8, rfe: u8) -> Info {
    Info {
        cut,
        package,
        rfe,
        crystal: 0x33,
        channel_filters: [0; 3],
    }
}
pub(super) fn factory() -> Factory8821c {
    let mut raw = [255; 512];
    raw[0xd0..0xd6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    raw[0xb9] = 0x73;
    raw[0xca] = 2 | 1 << 5;
    Factory8821c::for_test(raw).unwrap()
}
fn seeded() -> Model {
    let mut io = Model::new(0, 0);
    for (i, byte) in io.regs.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(7);
    }
    io
}
fn mac_ready() -> Owner<Model> {
    let mut owner = ready_8821c();
    narf_scheduler::block_on(owner.prepare_mac()).unwrap();
    owner.io.trace.clear();
    owner
}
fn smoke_rtw8821ce_phy_reference_cut_package_rfe_callbacks_and_prefix() -> TestResult {
    for (cut, packages) in LINUX_C21_HASHES.iter().enumerate() {
        for (package, rfes) in packages.iter().enumerate() {
            for (rfe_index, kinds) in rfes.iter().enumerate() {
                let info = info(cut as u8, package as u8, (rfe_index * 2) as u8);
                for (kind, expected) in kinds.iter().enumerate() {
                    let mut io = seeded();
                    if narf_scheduler::block_on(phy8821c::apply_table(&mut io, info, kind)).is_err()
                        || hash(&io.trace) != *expected
                    {
                        return TestResult::Fail(
                            "C21 table callbacks diverged from the frozen table/callback references",
                        );
                    }
                }
                let mut io = seeded();
                let actual = narf_scheduler::block_on(phy8821c::prepare(&mut io, info)).unwrap();
                let expected = LINUX_C21_PREFIX[cut][package][rfe_index];
                if hash(&io.trace) != expected.0 || actual.channel_filters != expected.1 {
                    return TestResult::Fail("C21 pre/post table sequence or retained channel filters differ from the frozen reference");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_phy_reference_cut_package_rfe_callbacks_and_prefix
);
fn smoke_rtw8821ce_same_owner_phy_preserves_closed_mac_and_chip_type() -> TestResult {
    let mut owner = mac_ready();
    let actual = match narf_scheduler::block_on(owner.prepare_phy8821c(&factory())) {
        Ok(actual) => actual,
        Err(_) => return TestResult::Fail("C21 retained MAC owner failed PHY preparation"),
    };
    if actual.cut != 3
        || actual.package != 1
        || actual.rfe != 2
        || actual.crystal != 0x33
        || owner.phase() != Phase::PhyTablesPrepared
        || owner.phy8821c != Some(actual)
    {
        return TestResult::Fail("C21 PHY completion lost exact factory or lifecycle identity");
    }
    if owner.phy_info().is_some() || owner.radio.is_some() || owner.power.is_some() {
        return TestResult::Fail("C21 PHY preparation populated C22 PHY/radio/power state");
    }
    if owner.io.regs[0x100] & 0xcf != 0
        || owner.io.regs[0x522] != 255
        || owner.io.trace.last() != Some(&(10, 0, 0, 0))
    {
        return TestResult::Fail("C21 PHY completion opened MAC or missed parked receipt");
    }
    // The genuine C21 BB table writes1cd0=0x400. That shared register is
    // not itself a C22 RFK trigger; C22's separate RFK-init sequence instead
    // sets bits28/29/30 there. Require the exact C21 source write and reject
    // every C22-only RF aperture used by the other PHY continuation.
    if !owner
        .io
        .trace
        .iter()
        .copied()
        .filter(|op| op.0 == 1 && op.2 == 0x1cd0)
        .eq(core::iter::once((1, 32, 0x1cd0, 0x400)))
        || owner
            .io
            .trace
            .iter()
            .any(|op| op.0 == 1 && matches!(op.2, 0x1808 | 0x4108 | 0x3c00 | 0x4c00))
    {
        return TestResult::Fail("C21 table trace diverged into C22 RF/RFK programming");
    }
    let calls = owner.io.trace.len();
    if narf_scheduler::block_on(owner.prepare_phy8821c(&factory())) != Err(Error::State)
        || owner.io.trace.len() != calls
    {
        return TestResult::Fail("completed C21 table owner replayed registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_same_owner_phy_preserves_closed_mac_and_chip_type
);
fn smoke_rtw8821ce_phy_faults_and_factory_path_cut_restrictions_are_terminal() -> TestResult {
    let mut reference = mac_ready();
    narf_scheduler::block_on(reference.prepare_phy8821c(&factory())).unwrap();
    let mut cuts = alloc::vec![0, 1, reference.io.trace.len() - 1];
    for reg in [2, 0xef, 0x808, 0x800, 0x81c, 0xc90, 0x24, 0x28, 0xaac] {
        if let Some(at) = reference
            .io
            .trace
            .iter()
            .position(|op| op.2 == reg && op.0 != 8)
        {
            cuts.push(at);
        } else {
            return TestResult::Fail("C21 fault fixture missing actual source stage");
        }
    }
    for fail in cuts {
        let mut owner = mac_ready();
        owner.io.fail = Some(fail);
        if narf_scheduler::block_on(owner.prepare_phy8821c(&factory())) != Err(Error::Access)
            || owner.phase() != Phase::Failed
            || owner.phy8821c.is_some()
            || owner.io.trace.len() != fail + 1
        {
            return TestResult::Fail("partial C21 PHY failure continued or claimed readiness");
        }
        let before = owner.io.trace.len();
        if narf_scheduler::block_on(owner.prepare_phy8821c(&factory())) != Err(Error::State)
            || owner.io.trace.len() != before
        {
            return TestResult::Fail("failed C21 table owner was replayed");
        }
    }
    for mutation in 0..9 {
        let mut owner = mac_ready();
        let mut raw = *factory().logical();
        match mutation {
            0 => raw[0xca] = 1,
            1 => raw[0xb9] = 255,
            2 => owner.hardware.as_mut().unwrap().antennas = 2,
            3 => owner.hardware.as_mut().unwrap().streams = 2,
            4 => owner.mac.as_mut().unwrap().cut = 7,
            5 => owner.io.regs[0xf3] |= 8,
            6 => owner.io.regs[0xf1] = 0,
            7 => owner.io.regs[0xf0..0xf4].fill(255),
            _ => owner.did = 0xc822,
        }
        let expected = if mutation == 7 {
            Error::Gone
        } else {
            Error::Unsupported
        };
        if narf_scheduler::block_on(owner.prepare_phy8821c(&Factory8821c::for_test(raw).unwrap()))
            != Err(expected)
            || owner.phy8821c.is_some()
            || (mutation < 5 && !owner.io.trace.is_empty())
            || owner.io.trace.iter().any(|op| op.0 == 1)
        {
            return TestResult::Fail(
                "invalid C21 factory/physical path/current cut reached table publication",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_phy_faults_and_factory_path_cut_restrictions_are_terminal
);
fn smoke_rtw8821ce_phy_cancel_retains_outer_inner_owner_and_blocks_reconstruction() -> TestResult {
    let mut reference = mac_ready();
    narf_scheduler::block_on(reference.prepare_phy8821c(&factory())).unwrap();
    let rf_delay = reference
        .io
        .trace
        .iter()
        .position(|op| *op == (8, 0, 0, 13))
        .unwrap();
    for cancel_at in [None, Some(rf_delay)] {
        let lifecycle = firmware_lifecycle::Lifecycle::new(0xc821);
        let mut bytes = super::mac_tests::firmware();
        bytes[0] = 0x21;
        let mut io = Model::new(0, 3);
        io.regs[0x80..0x84].fill(0);
        io.regs[0x1208..0x120c].fill(0);
        narf_scheduler::block_on(lifecycle.initialize_bytes(|| Ok(io), bytes)).unwrap();
        {
            let mut retained = lifecycle.retained.try_lock().unwrap();
            retained.as_mut().unwrap().io.regs[0x1a6..0x1aa]
                .copy_from_slice(&((7u32 << 16) | (1 << 19) | (1 << 21) | (3 << 26)).to_le_bytes());
        }
        narf_scheduler::block_on(lifecycle.prepare_mac()).unwrap();
        let address = {
            let mut retained = lifecycle.retained.try_lock().unwrap();
            let io = &mut retained.as_mut().unwrap().io;
            io.trace.clear();
            io.suspend = cancel_at.is_none();
            io.suspend_at = cancel_at;
            io.regs.as_ptr()
        };
        let factory = factory();
        {
            let mut future = core::pin::pin!(lifecycle.prepare_phy8821c(&factory));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                != Poll::Pending
            {
                return TestResult::Fail("C21 PHY cancellation did not reach source delay");
            }
        }
        if lifecycle.status().stage != firmware_lifecycle::Stage::Failed
            || lifecycle.status().error != Some(Error::Cancelled)
        {
            return TestResult::Fail("C21 PHY cancellation did not poison outer lifecycle");
        }
        let before = {
            let retained = lifecycle.retained.try_lock().unwrap();
            let owner = retained.as_ref().unwrap();
            if owner.phase() != Phase::Failed
                || owner.io.regs.as_ptr() != address
                || owner.phy8821c.is_some()
                || owner.io.trace.iter().any(|op| op.0 == 10)
            {
                return TestResult::Fail(
                    "C21 cancellation lost exact native storage or claimed completion",
                );
            }
            owner.io.trace.len()
        };
        if narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory)) != Err(Error::State)
            || narf_scheduler::block_on(
                lifecycle.initialize_bytes(|| Err(Error::Memory), alloc::vec![]),
            ) != Err(Error::State)
            || lifecycle
                .retained
                .try_lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .io
                .trace
                .len()
                != before
        {
            return TestResult::Fail("cancelled C21 lifecycle reconstructed or replayed owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_phy_cancel_retains_outer_inner_owner_and_blocks_reconstruction
);
