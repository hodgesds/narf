//! Audit log topic. Every cap mint / revoke against a privileged-root
//! topic publishes one `AuditEvent` on `system.security.audit`.
//!
//! The audit topic is itself privileged: subscribing requires
//! `audit_subscribe_kernel` (which holds a kernel-minted
//! `Cap<TopicRegistry, Write>`); a plain `Cap<TopicRegistry, Read>`
//! can't reach it through `lookup_topic`. Publish is gated to the
//! internal `registry::audit_publisher` static so userspace can't
//! forge audit entries.

use narf_capabilities::CapKind;

use crate::topic::TopicName;

/// One audit-log entry. `Copy` so it can sit in a fixed-size slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AuditEvent {
    /// Cycle timestamp at the moment of audit emission.
    pub ts_cycles: u64,
    /// Operation: mint or revoke.
    pub op: AuditOp,
    /// `CapKind` of the cap being minted / revoked.
    pub cap_kind: u32,
    /// Topic name the event concerns (up to `MAX_NAME_BYTES`).
    pub topic: TopicName,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditOp {
    Mint = 1,
    Revoke = 2,
}

/// Publish a mint/revoke audit event. No-op if the audit topic has
/// not yet been initialised (which only happens during very early
/// boot before `event_bus::init`).
pub(crate) fn publish_audit_mint(op: AuditOp, cap_kind: CapKind, topic: TopicName) {
    let Some(pubr) = crate::registry::audit_publisher() else {
        return;
    };
    let ev = AuditEvent {
        ts_cycles: narf_time::now_cycles(),
        op,
        cap_kind: cap_kind as u32,
        topic,
    };
    // Discard the result — audit is best-effort. A failure here means
    // the audit publisher cap was revoked, which can't happen in
    // Phase 1 (no path to revoke it).
    let _ = pubr.publish(ev);
}
