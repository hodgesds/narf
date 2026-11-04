// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB reset/rejoin/IPS/system-sleep admission. Inert: no USB
//! device is bound, so every entry must refuse before any EP0 transfer.
use super::{operating_reset::Error, usb_recovery};
use alloc::boxed::Box;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power::device_pm::DevicePmError;

fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    for _ in 0..1_000_000 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("rtw88 USB recovery fixture stalled");
}

fn smoke_rtw88_usb_recovery_unbound_slot_refuses() -> TestResult {
    const SLOT: u8 = 0xfe;
    if !matches!(complete(usb_recovery::reset_usb(SLOT)), Err(Error::State)) {
        return TestResult::Fail("reset of an unbound USB slot was admitted");
    }
    if !matches!(
        complete(usb_recovery::park(SLOT, usb_recovery::Mode::Idle)),
        Err(Error::State)
    ) {
        return TestResult::Fail("IPS park of an unbound USB slot was admitted");
    }
    if !matches!(
        complete(usb_recovery::idle_usb(SLOT)),
        Err(DevicePmError::Busy)
    ) {
        return TestResult::Fail("idle of an unbound USB slot started a worker");
    }
    if super::usb_driver::slots().contains(&SLOT) {
        return TestResult::Fail("unbound USB slot joined the system PM fan-out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_recovery_unbound_slot_refuses
);
