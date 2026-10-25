use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Debug)]
struct Model {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    published: Arc<AtomicBool>,
}
impl Drop for Model {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
#[async_trait::async_trait]
// SAFETY: no hardware. The model records the actual submitted-packet boundary
// before pending; shared Lifecycle must retain this exact owner on cancellation.
unsafe impl Io for Model {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn read8(&mut self, _: u16) -> Result<u8, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    fn read16(&mut self, _: u16) -> Result<u16, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    fn read32(&mut self, _: u16) -> Result<u32, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn write16(&mut self, _: u16, _: u16) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.published.store(true, Ordering::SeqCst);
        core::future::pending().await
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        unreachable!()
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        unreachable!()
    }
}
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 64 + 9 + 8 + 9 + 8];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, 9),
        (0x30, 9),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
fn smoke_rtw88_retained_native_firmware_lifecycle_cancel_and_no_reconstruction() -> TestResult {
    retained_cancel(0xc822)
}
fn retained_cancel(did: u16) -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let published = Arc::new(AtomicBool::new(false));
    let lifecycle = Lifecycle::new(did);
    let allocations = AtomicUsize::new(0);
    let mut future = Box::pin(lifecycle.initialize(
        || {
            allocations.fetch_add(1, Ordering::SeqCst);
            Ok(Model {
                calls: calls.clone(),
                drops: drops.clone(),
                published: published.clone(),
            })
        },
        Source::Bytes({
            let mut bytes = image();
            bytes[0] = if did == 0xc821 { 0x21 } else { 0x22 };
            bytes
        }),
    ));
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
        || !published.load(Ordering::SeqCst)
    {
        return TestResult::Fail("lifecycle fixture did not publish actual firmware packet");
    }
    drop(future);
    let before = calls.load(Ordering::SeqCst);
    if lifecycle.status()
        != (Status {
            stage: Stage::Failed,
            info: None,
            error: Some(Error::Cancelled),
        })
        || drops.load(Ordering::SeqCst) != 0
    {
        return TestResult::Fail("cancel did not retain terminal native firmware owner");
    }
    let Some(retained) = lifecycle.retained.try_lock() else {
        return TestResult::Fail("cancel held async ownership guard");
    };
    if retained.as_ref().map(|owner| owner.phase())
        != Some(super::super::firmware_transport::Phase::Failed)
    {
        return TestResult::Fail("cancel lost exact inner native owner");
    }
    drop(retained);
    if narf_scheduler::block_on(lifecycle.initialize(
        || {
            allocations.fetch_add(1, Ordering::SeqCst);
            Err(Error::Memory)
        },
        Source::Bytes(image()),
    )) != Err(Error::State)
        || calls.load(Ordering::SeqCst) != before
        || allocations.load(Ordering::SeqCst) != 1
    {
        return TestResult::Fail("cancel reconstructed native owner or reused pending transfer");
    }
    drop(lifecycle);
    if drops.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("terminal model retained owner not owned exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_retained_native_firmware_lifecycle_cancel_and_no_reconstruction
);
fn smoke_rtw8821ce_cancel_retains_exact_outer_and_inner_firmware_owners() -> TestResult {
    retained_cancel(0xc821)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_cancel_retains_exact_outer_and_inner_firmware_owners
);
fn smoke_rtw88_failed_native_factory_is_terminal_without_io() -> TestResult {
    let lifecycle = Lifecycle::<Model>::new(0xc822);
    let allocations = AtomicUsize::new(0);
    for attempt in 0..2 {
        let wanted = if attempt == 0 {
            Error::Memory
        } else {
            Error::State
        };
        if narf_scheduler::block_on(lifecycle.initialize(
            || {
                allocations.fetch_add(1, Ordering::SeqCst);
                Err(Error::Memory)
            },
            Source::Bytes(image()),
        )) != Err(wanted)
        {
            return TestResult::Fail("failed native factory retried or claimed ready");
        }
    }
    if allocations.load(Ordering::SeqCst) != 1 || lifecycle.status().stage != Stage::Failed {
        return TestResult::Fail("native factory failure reopened lifecycle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_failed_native_factory_is_terminal_without_io
);

fn smoke_rtw88_registered_preflight_can_stage_later_without_allocating_or_replaying() -> TestResult
{
    let lifecycle = Lifecycle::<Model>::new(0xc822);
    let allocations = AtomicUsize::new(0);
    for error in [
        Error::Firmware(narf_firmware::FirmwareError::NotFound),
        Error::Firmware(narf_firmware::FirmwareError::AuthorityRevoked),
        Error::Image,
    ] {
        let result = narf_scheduler::block_on(lifecycle.initialize_registered_with(
            || {
                allocations.fetch_add(1, Ordering::SeqCst);
                Err(Error::Memory)
            },
            || Err(error),
        ));
        if result != Err(error)
            || allocations.load(Ordering::SeqCst) != 0
            || lifecycle.started.load(Ordering::Acquire)
            || lifecycle.status()
                != (Status {
                    stage: Stage::Detected,
                    info: None,
                    error: Some(error),
                })
            || lifecycle.retained.try_lock().is_none_or(|r| r.is_some())
        {
            return TestResult::Fail("registered preflight consumed/allocated pristine lifecycle");
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let published = Arc::new(AtomicBool::new(false));
    {
        let mut future = core::pin::pin!(lifecycle.initialize_registered_with(
            || {
                allocations.fetch_add(1, Ordering::SeqCst);
                Ok(Model {
                    calls: calls.clone(),
                    drops: drops.clone(),
                    published: published.clone(),
                })
            },
            || super::super::firmware_transport::preflight_image(0xc822, image())
        ));
        if !future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
            || !published.load(Ordering::Acquire)
        {
            return TestResult::Fail(
                "later staged image failed to reach real retained publication",
            );
        }
    }
    let loads = AtomicUsize::new(0);
    if lifecycle.status().stage != Stage::Failed
        || drops.load(Ordering::Acquire) != 0
        || allocations.load(Ordering::Acquire) != 1
        || narf_scheduler::block_on(lifecycle.initialize_registered_with(
            || Err(Error::Memory),
            || {
                loads.fetch_add(1, Ordering::SeqCst);
                super::super::firmware_transport::preflight_image(0xc822, image())
            },
        )) != Err(Error::State)
        || loads.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail(
            "started registered attempt reopened loader/allocation after cancel",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_registered_preflight_can_stage_later_without_allocating_or_replaying
);
