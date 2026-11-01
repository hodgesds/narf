//! Real primary/render node lifetime coverage for client-free reconfiguration.

use super::*;
use crate::drm_devfs_bridge::{BochsCard, DriCardFile, DriDir, IntelGpuCard};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{DirOps, FileOps};
use narf_kernel_test::{kernel_test_in, TestResult};

fn register(device: u16) -> u32 {
    crate::drm_registry::register_drm_card(Arc::new(IntelGpuCard::new(
        String::new(),
        0x8086,
        device,
        0,
        0,
    )))
}

fn primary(index: u32) -> Option<Arc<dyn FileOps>> {
    DriDir.lookup(&format!("card{index}"))
}

fn render(index: u32) -> Option<Arc<dyn FileOps>> {
    DriDir.lookup(&format!("renderD{}", index + 128))
}

fn smoke_ccs_devfs_pre_backend_opens_and_final_file_reference_exclude_reset() -> TestResult {
    let index = register(0x56a0);
    assert!(crate::drm_registry::mode_state(index).is_none());
    // Open both real nodes before the GT backend/controller exists. Discrete
    // cards have no mode-state Card, so that cannot be the client registry.
    let card = Arc::new(DriCardFile::new(index).unwrap());
    let render_file = render(index).unwrap();
    let control = Control::new(index).unwrap();
    assert!(Arc::ptr_eq(&control, &Control::new(index).unwrap()));
    control.publish(11, (0xf, 1)).unwrap();
    assert_eq!(control.gate.0.lock().count, 2);
    assert_eq!(control.enqueue(2), Err(FsError::Busy));
    drop(card);
    assert_eq!(control.gate.0.lock().count, 1);
    assert_eq!(control.enqueue(2), Err(FsError::Busy));
    // dup/fork references share one drm_file. Last descriptor release cannot
    // make a still-retained file (including a borrowed ioctl) disappear.
    let retained_file = render_file.clone();
    drop(render_file);
    assert_eq!(control.gate.0.lock().count, 1);
    assert_eq!(control.enqueue(2), Err(FsError::Busy));
    drop(retained_file);
    assert_eq!(control.gate.0.lock().count, 0);
    control.enqueue(2).unwrap();
    assert!(primary(index).is_none());
    assert!(render(index).is_none());
    assert_eq!(control.gate.0.lock().count, 0);
    // Cancellation alone does not reopen admission. Only the owner's next
    // verified publication may clear it; no reset is simulated by fd drop.
    control.close();
    assert!(primary(index).is_none());
    assert!(render(index).is_none());
    control.publish(12, (0xf, 1)).unwrap();
    let reopened_card = primary(index).unwrap();
    let reopened_render = render(index).unwrap();
    assert_eq!(control.gate.0.lock().count, 2);
    drop((reopened_card, reopened_render));
    assert_eq!(control.gate.0.lock().count, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_ccs_devfs_pre_backend_opens_and_final_file_reference_exclude_reset
);

fn smoke_ccs_devfs_gate_is_card_scoped_and_ignores_unregistered_or_other_vendors() -> TestResult {
    let first = register(0x56a0);
    let second = register(0xe202);
    let other = crate::drm_registry::register_drm_card(Arc::new(BochsCard::new(String::new())));
    let held_second = render(second).unwrap();
    let a = Control::new(first).unwrap();
    let b = Control::new(second).unwrap();
    a.publish(21, (0xf, 1)).unwrap();
    b.publish(22, (0xa, 1)).unwrap();
    assert_eq!(a.gate.0.lock().count, 0);
    assert_eq!(b.gate.0.lock().count, 1);
    a.enqueue(2).unwrap();
    assert!(primary(first).is_none());
    assert!(render(first).is_none());
    assert_eq!(b.enqueue(2), Err(FsError::Busy));
    let unaffected = primary(second).unwrap();
    let other_vendor = render(other).unwrap();
    assert_eq!(b.gate.0.lock().count, 2);
    assert!(Control::new(other).is_none());
    assert!(client_open(other).unwrap().is_none());
    assert!(client_open(u32::MAX).unwrap().is_none());
    assert!(CARDS
        .lock()
        .iter()
        .all(|entry| entry.index != other && entry.index != u32::MAX));
    drop((held_second, unaffected, other_vendor));
    assert_eq!(b.gate.0.lock().count, 0);
    a.close();
    a.publish(23, (0xf, 1)).unwrap();
    assert!(primary(first).is_some());
    assert!(render(first).is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_ccs_devfs_gate_is_card_scoped_and_ignores_unregistered_or_other_vendors
);

#[derive(Debug)]
struct Backend(Arc<Control>);

impl crate::intel_gpu_user::UserBackend for Backend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn ccs_control(&self) -> Option<Arc<Control>> {
        Some(self.0.clone())
    }
    fn submit<'a>(
        &'a self,
        _: Arc<crate::intel_gpu_user::UserContext>,
        _: crate::intel_gpu_user::UserBatch,
    ) -> narf_filesystem::FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        alloc::boxed::Box::pin(async { panic!("sysfs queued GPU work") })
    }
}

static ADMIN: AtomicBool = AtomicBool::new(false);
fn capable(capability: u32) -> bool {
    capability == 21 && ADMIN.load(Ordering::Acquire)
}
struct CapabilityHook(Option<fn(u32) -> bool>);
impl CapabilityHook {
    fn install() -> Self {
        ADMIN.store(false, Ordering::Release);
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            capable,
        )))
    }
}
impl Drop for CapabilityHook {
    fn drop(&mut self) {
        let _ = narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}

fn smoke_ccs_real_sysfs_requires_current_admin_and_queues_without_hardware() -> TestResult {
    let _capability = CapabilityHook::install();
    let card = Arc::new(IntelGpuCard::new(String::new(), 0x8086, 0x56a0, 0, 0));
    let index = crate::drm_registry::register_drm_card(card.clone());
    let node = Kobject::new_root("ccs-control-test");
    populate_card(index, &node);
    assert!(node.attr_is_writable("ccs_mode"));
    assert!(!node.attr_is_writable("num_cslices"));
    assert!(!node.attr_is_writable("ccs_mode_status"));
    assert_eq!(node.attr_show("ccs_mode").as_deref(), Some(""));
    assert_eq!(
        node.attr_store("ccs_mode", b"2"),
        Some(Err(FsError::NoDevice))
    );
    // The already-created callbacks resolve the backend when invoked, rather
    // than capturing its absence before asynchronous GT bring-up.
    let control = Control::new(index).unwrap();
    card.install_user_backend(Arc::new(Backend(control.clone())))
        .unwrap();
    control.publish(41, (0xf, 1)).unwrap();
    assert_eq!(node.attr_show("num_cslices").as_deref(), Some("4\n"));
    assert_eq!(node.attr_show("ccs_mode").as_deref(), Some("1\n"));
    assert_eq!(
        node.attr_store("ccs_mode", b"2"),
        Some(Err(FsError::OperationNotPermitted))
    );
    ADMIN.store(true, Ordering::Release);
    for bytes in [
        &b""[..],
        &b"0"[..],
        &b"5"[..],
        &b"02"[..],
        &b"3"[..], // four physical slices cannot be partitioned into three
        &b"2 4"[..],
        &b"1\n1"[..],
        &b"00000000000000001"[..],
        &[0xff][..],
    ] {
        assert_eq!(
            node.attr_store("ccs_mode", bytes),
            Some(Err(FsError::InvalidData))
        );
        assert!(!control.gate.0.lock().blocked);
    }
    assert_eq!(node.attr_store("ccs_mode", b"1\n"), Some(Ok(())));
    assert!(!control.gate.0.lock().blocked);
    assert!(node
        .attr_show("ccs_mode_status")
        .unwrap()
        .starts_with("applied "));
    let client = render(index).unwrap();
    assert_eq!(node.attr_store("ccs_mode", b"2"), Some(Err(FsError::Busy)));
    drop(client);
    // Administrative authority is checked again through the same callback.
    ADMIN.store(false, Ordering::Release);
    assert_eq!(
        node.attr_store("ccs_mode", b"2"),
        Some(Err(FsError::OperationNotPermitted))
    );
    ADMIN.store(true, Ordering::Release);
    assert_eq!(node.attr_store("ccs_mode", b"2"), Some(Ok(())));
    assert!(control.gate.0.lock().blocked);
    assert_eq!(node.attr_show("ccs_mode").as_deref(), Some("1\n"));
    assert!(node
        .attr_show("ccs_mode_status")
        .unwrap()
        .starts_with("queued "));
    assert_eq!(node.attr_store("ccs_mode", b"4"), Some(Err(FsError::Busy)));
    control.close();
    assert!(render(index).is_none());
    assert_eq!(
        node.attr_store("ccs_mode", b"4"),
        Some(Err(FsError::NoDevice))
    );
    control.publish(42, (0xf, 1)).unwrap();
    assert!(render(index).is_some());
    // Ordinary loss/S3, with no pending mode change, must also invalidate
    // its last epoch. A stale publication cannot run the ready callback.
    control.close();
    let mut called = false;
    assert_eq!(
        control.publish_with(42, (0xf, 1), || called = true),
        Err(FsError::NoDevice)
    );
    assert!(!called);
    assert_eq!(
        node.attr_store("ccs_mode", b"2"),
        Some(Err(FsError::NoDevice))
    );
    control.publish(43, (0xf, 1)).unwrap();
    assert_eq!(node.attr_store("ccs_mode", b"1"), Some(Ok(())));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_ccs_real_sysfs_requires_current_admin_and_queues_without_hardware
);
