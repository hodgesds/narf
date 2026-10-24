use super::mac_tests::{ready, Model};
use super::*;
use crate::rtw88::{
    efuse::Factory,
    phy::{self, Info},
};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn hash(trace: &[(u8, u8, u16, u32)]) -> u64 {
    let mut value = 14695981039346656037u64;
    for &(op, width, reg, data) in trace {
        let kind = match (op, width) {
            (0, 32) => 0,
            (1, 32) => 1,
            (8, 0) => 2,
            _ => panic!("non-PHY callback in table oracle"),
        };
        for byte in core::iter::once(kind)
            .chain(u32::from(reg).to_le_bytes())
            .chain(data.to_le_bytes())
        {
            value = (value ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
    }
    value
}
fn factory() -> Factory {
    let mut bytes = [255; 768];
    bytes[0x120..0x126].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    bytes[0xb9] = 0x33;
    bytes[0xc1] = 0;
    bytes[0xca] = 0;
    bytes[0xd0..0xd2].copy_from_slice(&[25, 26]);
    Factory::for_test(bytes).unwrap()
}
fn mac_ready() -> Owner<Model> {
    let mut owner = ready();
    narf_scheduler::block_on(owner.prepare_mac()).unwrap();
    owner.io.trace.clear();
    owner
}
fn smoke_rtw8822ce_phy_callbacks_match_original_linux_all_cut_rfe_profiles() -> TestResult {
    for (cut, rfes) in LINUX_PHY_HASHES.iter().enumerate() {
        for (rfe, kinds) in rfes.iter().enumerate() {
            for (kind, expected) in kinds.iter().enumerate() {
                let mut io = Model::new(0, 0);
                for (i, byte) in io.regs.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(17).wrapping_add(7);
                }
                let info = Info {
                    cut: cut as u8,
                    rfe: rfe as u8,
                    paths: 2,
                    crystal: 0x33,
                };
                if narf_scheduler::block_on(phy::apply_table(&mut io, info, kind)).is_err()
                    || hash(&io.trace) != *expected
                {
                    return TestResult::Fail(
                        "native BB/AGC/RFK/RF callbacks diverged from original C accessors",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_phy_callbacks_match_original_linux_all_cut_rfe_profiles
);
fn smoke_rtw8822ce_same_owner_phy_tables_hold_mac_dma_closed_and_reject_replay() -> TestResult {
    let mut owner = mac_ready();
    let info = match narf_scheduler::block_on(owner.prepare_phy_tables(&factory())) {
        Ok(info) => info,
        Err(_) => {
            return TestResult::Fail("same retained firmware/MAC owner did not load PHY tables")
        }
    };
    if info
        != (Info {
            cut: 3,
            rfe: 0,
            paths: 2,
            crystal: 0x33,
        })
        || owner.phase() != Phase::PhyTablesPrepared
        || owner.phy_info() != Some(info)
        || owner.mac_info().is_none()
        || owner.hardware_info().is_none()
        || owner.io.regs[0x100] & 0xcf != 0
        || owner.io.regs[0x522] != 255
        || owner.io.regs[0x1040..0x1044] == [0; 4]
        || owner.io.trace.last() != Some(&(10, 0, 0, 0))
    {
        return TestResult::Fail("PHY table completion lost owner/clock identity or opened MAC TX");
    }
    let calls = owner.io.trace.len();
    if narf_scheduler::block_on(owner.prepare_phy_tables(&factory())) != Err(Error::State)
        || narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::State)
        || owner.io.trace.len() != calls
    {
        return TestResult::Fail("prepared PHY owner replayed/reset live native state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_same_owner_phy_tables_hold_mac_dma_closed_and_reject_replay
);
fn smoke_rtw8822ce_phy_stage_faults_cancel_and_unqualified_factory_stay_terminal() -> TestResult {
    let mut reference = mac_ready();
    narf_scheduler::block_on(reference.prepare_phy_tables(&factory())).unwrap();
    let mut cuts = alloc::vec![0, 1, reference.io.trace.len() - 1];
    for reg in [0x1d0c, 0x1d90, 0x1b80, 0x4108, 0x1808, 0x1040] {
        if let Some(at) = reference
            .io
            .trace
            .iter()
            .position(|op| op.0 == 1 && op.2 == reg)
        {
            cuts.push(at);
        } else {
            return TestResult::Fail("PHY fault fixture missed actual source stage");
        }
    }
    for fail in cuts {
        let mut owner = mac_ready();
        owner.io.fail = Some(fail);
        if narf_scheduler::block_on(owner.prepare_phy_tables(&factory())) != Err(Error::Access)
            || owner.phase() != Phase::Failed
            || owner.phy_info().is_some()
            || owner.io.trace.len() != fail + 1
        {
            return TestResult::Fail(
                "partial PHY stage error claimed readiness or continued accesses",
            );
        }
        let calls = owner.io.trace.len();
        if narf_scheduler::block_on(owner.prepare_phy_tables(&factory())) != Err(Error::State)
            || owner.io.trace.len() != calls
        {
            return TestResult::Fail("failed PHY owner reused native state");
        }
    }
    let mut owner = mac_ready();
    owner.io.suspend = true;
    {
        let factory = factory();
        let mut future = core::pin::pin!(owner.prepare_phy_tables(&factory));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            != Poll::Pending
        {
            return TestResult::Fail("PHY fixture did not yield after actual publication");
        }
    }
    let calls = owner.io.trace.len();
    if owner.phase() != Phase::Failed
        || owner.phy_info().is_some()
        || !owner.io.phy_started
        || owner.io.trace.iter().any(|op| op.0 == 10)
        || narf_scheduler::block_on(owner.prepare_phy_tables(&factory())) != Err(Error::State)
        || owner.io.trace.len() != calls
    {
        return TestResult::Fail("cancelled PHY owner reopened or claimed calibration complete");
    }
    for mutation in 0..6 {
        let mut owner = mac_ready();
        let mut raw = *factory().logical();
        match mutation {
            0 => raw[0xca] = 7,
            1 => raw[0xb9] = 255,
            2 => raw[0xc1] = 255,
            3 => raw[0xd0] = 255,
            4 => owner.hardware.as_mut().unwrap().antennas = 1,
            _ => owner.mac.as_mut().unwrap().cut = 7,
        }
        let factory = Factory::for_test(raw).unwrap();
        if narf_scheduler::block_on(owner.prepare_phy_tables(&factory)) != Err(Error::Unsupported)
            || !owner.io.trace.is_empty()
            || owner.phase() != Phase::Failed
        {
            return TestResult::Fail("unqualified PHY geometry/calibration reached native MMIO");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_phy_stage_faults_cancel_and_unqualified_factory_stay_terminal
);
