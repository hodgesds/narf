//! Final-ACK receipts use actual revoked grants and exact removed entries.
use super::*;
fn withdrawn() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let original = child(&parent, None)?;
    let admin = delegate(&parent, &original)?;
    if admin.retire_control_child(&parent.iface, 0).is_ok()
        || admin.retire_control_child(&original.cap, 27).is_ok()
        || parent.admin.retire_control_child(&original.cap, 0).is_ok()
    {
        return Err("retirement accepted another cap/name/namespace or parent-only admin");
    }
    let receipt = admin
        .retire_control_child(&original.cap, 0)
        .map_err(|_| "actual invoked control withdrawal")?;
    if !receipt.current()
        || admin.check_live().is_ok()
        || admin.authorize_interface(&original.name, 0).is_ok()
        || admin.retire_control_child(&original.cap, 0).is_ok()
        || crate::registry()
            .with_interface_for_handle(&original.cap, |_| ())
            .is_some()
    {
        return Err("retirement restored live administration or failed exact removal");
    }
    let successor = child(&parent, Some(&original.name))?;
    let fresh = delegate(&parent, &successor)?;
    if fresh.authorize_interface(&successor.name, 0).is_err()
        || admin.authorize_interface(&successor.name, 0).is_ok()
        || admin.retire_control_child(&successor.cap, 0).is_ok()
        || !receipt.current()
    {
        return Err("old retirement/administrator retargeted a same-name successor");
    }
    Ok(())
}
fn control_retirement_is_exact_and_never_restores_admin_or_targets_a_successor() -> TestResult {
    withdrawn().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_retirement_is_exact_and_never_restores_admin_or_targets_a_successor
);

fn revoked() -> Result<(), &'static str> {
    for cause in 0..5 {
        let parent = Fixture::new(true)?;
        let child = child(&parent, None)?;
        let admin = delegate(&parent, &child)?;
        let receipt = admin
            .retire_control_child(&child.cap, 0)
            .map_err(|_| "control retirement before actual revoke")?;
        match cause {
            0 => admin.cap.revoke(),
            1 => parent.admin.cap.revoke(),
            2 => parent.daemon.revoke(),
            3 => parent.iface.revoke(),
            _ => child.cap.revoke(),
        }
        if receipt.current() {
            return Err("retired observation bypassed revoked admin/daemon/parent/child grant");
        }
    }
    Ok(())
}
fn control_retirement_rechecks_every_original_grant_after_native_withdrawal() -> TestResult {
    revoked().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_retirement_rechecks_every_original_grant_after_native_withdrawal
);

fn transfer() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let child = child(&parent, None)?;
    let admin = delegate(&parent, &child)?;
    let receipt = admin
        .retire_control_child(&child.cap, 0)
        .map_err(|_| "retirement before namespace handoff")?;
    parent
        .admin
        .move_to_net_ns(27)
        .map_err(|_| "actual parent namespace transfer")?;
    parent
        .admin
        .move_to_net_ns(0)
        .map_err(|_| "actual parent namespace ABA return")?;
    if receipt.current() {
        return Err("retirement restored old parent ownership epoch after namespace ABA");
    }
    Ok(())
}
fn control_retirement_parent_namespace_aba_cannot_revive_terminal_publication_scope() -> TestResult
{
    transfer().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_retirement_parent_namespace_aba_cannot_revive_terminal_publication_scope
);

fn kernel_scope() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let child = child(&parent, None)?;
    let admin = kernel_admin(&child.name).ok_or("actual namespace kernel child handle")?;
    let receipt = admin
        .retire_control_child(&child.cap, 0)
        .map_err(|_| "actual kernel-scope control retirement")?;
    if !receipt.current()
        || crate::registry()
            .with_interface_for_handle(&child.cap, |_| ())
            .is_some()
    {
        return Err("kernel namespace retirement omitted real parent/child or exact withdrawal");
    }
    crate::registry().unregister_for_handle(&parent.iface);
    if receipt.current() {
        return Err("retirement kernel handle reselected a missing physical parent");
    }
    Ok(())
}
fn control_retirement_preserves_namespace_kernel_scope_with_real_endpoint_invocations() -> TestResult
{
    kernel_scope().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_retirement_preserves_namespace_kernel_scope_with_real_endpoint_invocations
);
