use super::super::phy_access::Generation;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{object_table, CapKind, CapSlot, Rights};
use narf_kernel_test::{kernel_test_in, TestResult};
fn cap() -> Cap<BusDeviceCap, Write> {
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: fresh private model object and matching kind/generation/rights.
    unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    }
}
fn region(words: &mut Vec<u32>) -> MmioRegion {
    MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 65536,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    }
}
fn once<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_native_phy_current_authority_and_retained_failure() -> TestResult {
    let mut words = vec![0u32; 16384];
    let authority = cap();
    // SAFETY: exclusive private aligned RAM window, no device or producers.
    let mut native =
        unsafe { NativeIo::new(region(&mut words), authority, ChipId::Rtl8852C, 0) }.unwrap();
    for generation in [Generation::One, Generation::Two] {
        let base = if generation == Generation::One {
            0x3800
        } else {
            0x3880
        };
        if once(native.write_phy(generation, 63, 0x1234)) != Some(Ok(()))
            || once(native.read_phy(generation, 63)) != Some(Ok(0x1234))
            || once(native.modify_phy(generation, 63, 0xf0, 0xb)) != Some(Ok(()))
            || words[(base + 124) / 4] >> 16 != 0x12b4
        {
            return TestResult::Fail("actual native scoped RAC offsets/width/field writes");
        }
    }
    let before = words.clone();
    authority.revoke();
    if once(native.write_phy(Generation::Two, 63, 0x5678)) != Some(Err(Error::Access))
        || words != before
        || once(native.read_phy(Generation::Two, 63)) != Some(Err(Error::Terminal))
    {
        return TestResult::Fail("revoked PHY access touched BAR or reopened uncertain owner");
    }
    let authority = cap();
    authority.revoke();
    let invalid = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 65536,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: no hardware owns this deliberately unmapped model window.
    // Revocation must reject before the first actual register dereference.
    let mut native = unsafe { NativeIo::new(invalid, authority, ChipId::Rtl8852B, 0) }.unwrap();
    if once(native.read_phy(Generation::One, 0)) != Some(Err(Error::Access))
        || once(native.read_dbi(1)) != Some(Err(Error::Terminal))
    {
        return TestResult::Fail(
            "revoked PHY/DBI owner dereferenced unmapped BAR or lost exclusion",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_phy_current_authority_and_retained_failure
);
