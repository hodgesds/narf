//! PD policy — what a sink wants, what a source can offer.
//!
//! USB-PD 3.1 separates the *Policy Engine* (the state machine in
//! `tcpm.rs`) from *Policy* (the decisions a Policy Engine consults):
//! the Sink Policy decides which advertised PDO to request, the
//! Source Policy decides which PDOs to advertise + whether to Accept
//! an incoming Request. PD 3.1 §8.3.1 calls these "Local Policy
//! Manager" and "Device Policy Manager" but the split is the same.
//!
//! This module defines small, testable policy objects with no I/O so
//! the source- and sink-side state machines in `tcpm.rs` can ask one
//! question at a time: "given this list of incoming PDOs, what
//! position should I Request?" / "given this Request RDO, do I
//! Accept, Reject, or Wait?".
//!
//! References (public, non-GPL):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF), §8.3.1 (policy split),
//!   §6.4.1.3 (Fixed Source PDO), §6.4.2 (RDO encoding).
//!     <https://www.usb.org/document-library/usb-power-delivery>
//!
//! Linux's `drivers/usb/typec/tcpm/tcpm.c` keeps the same shape but
//! folds policy into the state machine; we keep it separate so the
//! tests can poke a `SinkPolicy` without standing up a chip.

extern crate alloc;

use alloc::vec::Vec;

use narf_usbpd::message::{FixedRdo, SourcePdo};

/// What a Sink Policy hands back from `evaluate_caps`. The Policy
/// Engine maps this to the actual outgoing Request RDO.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SinkSelection {
    /// 1-based PDO position from the most recently received
    /// Source_Capabilities (§6.4.2.1).
    pub object_position: u8,
    /// Voltage the sink is operating at, in millivolts. Equal to the
    /// PDO's voltage for Fixed PDOs; for PPS this is the requested
    /// programmable voltage.
    pub voltage_mv: u32,
    /// Operating current the sink is requesting, in milliamps.
    pub op_current_ma: u32,
    /// True when the sink is asking for *less* than its advertised
    /// requirement (Capability_Mismatch per §6.4.2.4 bit 26).
    pub cap_mismatch: bool,
}

impl SinkSelection {
    /// Cast a selection into an RDO. Defaults to sensible flags for a
    /// modern host (USB-Comms capable, no USB suspend).
    pub fn to_rdo(self) -> FixedRdo {
        FixedRdo {
            object_position: self.object_position,
            op_current_ma: self.op_current_ma,
            max_op_current_ma: self.op_current_ma,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: self.cap_mismatch,
        }
    }
}

/// Sink-side policy: "I want at least X V at Y mA; here is the list
/// of PDOs the source advertised — pick one."
///
/// The default policy is "lowest voltage that meets the minimum",
/// matching the laptop-as-sink case where the system prefers 5 V
/// unless it explicitly wants more. Tests can build alternate
/// policies (e.g. *max-power*) by passing different thresholds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SinkPolicy {
    /// Minimum acceptable voltage in mV. Sources that don't advertise
    /// at least this voltage cause `evaluate_caps` to fall back to
    /// PDO #1 with `cap_mismatch = true`.
    pub min_voltage_mv: u32,
    /// Operating current in mA. The sink will request this current
    /// from the chosen PDO, capped at the PDO's advertised maximum.
    pub op_current_ma: u32,
    /// `true` to pick the *highest* voltage that the source supports,
    /// false (default) to pick the *lowest* voltage that satisfies
    /// `min_voltage_mv`. Set to true for "give me as much power as I
    /// can get".
    pub prefer_high_voltage: bool,
    /// `true` to Accept inbound PR_Swap requests; `false` to Reject.
    /// Default off: most non-DRP sinks reject swap.
    pub accept_pr_swap: bool,
    /// `true` to Accept inbound DR_Swap requests. Default off — only
    /// dual-role data devices flip the flag on.
    pub accept_dr_swap: bool,
}

impl Default for SinkPolicy {
    fn default() -> Self {
        // Canonical laptop sink: 5 V, up to 3 A.
        Self {
            min_voltage_mv: 5000,
            op_current_ma: 3000,
            prefer_high_voltage: false,
            accept_pr_swap: false,
            accept_dr_swap: false,
        }
    }
}

impl SinkPolicy {
    /// Pick a PDO position from `caps`. Returns `None` only when the
    /// list is empty (which is itself a protocol violation per
    /// §6.4.1.1 — every source advertises Fixed 5 V at position 1).
    pub fn evaluate(&self, caps: &[SourcePdo]) -> Option<SinkSelection> {
        if caps.is_empty() {
            return None;
        }
        // Walk the Fixed PDOs collecting candidates. PPS / Battery /
        // Variable PDOs are skipped at this stage — Stage 2 layers
        // PPS support over the top.
        let mut best: Option<(u8, u32, u32)> = None; // (pos, voltage, current)
        for (i, pdo) in caps.iter().enumerate() {
            let SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
            } = *pdo
            else {
                continue;
            };
            if voltage_mv < self.min_voltage_mv {
                continue;
            }
            let pos = (i + 1) as u8;
            best = Some(match best {
                None => (pos, voltage_mv, max_current_ma),
                Some((p, v, c)) => {
                    if self.prefer_high_voltage {
                        if voltage_mv > v {
                            (pos, voltage_mv, max_current_ma)
                        } else {
                            (p, v, c)
                        }
                    } else if voltage_mv < v {
                        (pos, voltage_mv, max_current_ma)
                    } else {
                        (p, v, c)
                    }
                }
            });
        }
        // Capability mismatch path: every Fixed PDO was below our
        // minimum voltage. Spec (§7.1.5) tells the sink to fall back
        // to PDO #1 with the cap_mismatch bit set so the source knows
        // we're under-powered.
        if best.is_none() {
            if let SourcePdo::Fixed { voltage_mv, max_current_ma } = caps[0] {
                return Some(SinkSelection {
                    object_position: 1,
                    voltage_mv,
                    op_current_ma: self.op_current_ma.min(max_current_ma),
                    cap_mismatch: true,
                });
            }
            // Source advertised no Fixed PDOs at all — shouldn't be
            // legal, signal protocol violation upstream.
            return None;
        }
        let (pos, voltage_mv, max_current_ma) = best.unwrap();
        Some(SinkSelection {
            object_position: pos,
            voltage_mv,
            op_current_ma: self.op_current_ma.min(max_current_ma),
            cap_mismatch: false,
        })
    }
}

// ── Source-side policy ─────────────────────────────────────────────

/// Source-side decision on an incoming Request RDO.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    /// Source is willing — reply Accept then drive Vbus.
    Accept,
    /// Source cannot meet the request right now; sink should retry.
    Wait,
    /// Source refuses — sink keeps last contract / falls back.
    Reject,
}

/// Source-side policy: what PDOs to advertise + how to react to an
/// inbound Request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourcePolicy {
    /// PDOs to advertise in Source_Capabilities. PDO #1 must be the
    /// 5 V Fixed PDO per §6.4.1.1 — `default()` enforces that.
    pub pdos: Vec<SourcePdo>,
    /// `true` to Accept inbound PR_Swap requests; `false` to Reject.
    /// Sources typically reject swap unless they are explicitly
    /// dual-role (DRP).
    pub accept_pr_swap: bool,
    /// `true` to Accept inbound DR_Swap requests. Default off — the
    /// data role swap only makes sense when both sides can flip UFP/
    /// DFP.
    pub accept_dr_swap: bool,
}

impl Default for SourcePolicy {
    fn default() -> Self {
        // Canonical 5 V / 3 A advertisement, matching a USB-PD 3.0
        // Default Source (§6.4.1.3.1).
        Self {
            pdos: alloc::vec![SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            }],
            accept_pr_swap: false,
            accept_dr_swap: false,
        }
    }
}

impl SourcePolicy {
    /// Build a source policy from an explicit PDO list. Panics in
    /// debug builds if PDO #1 isn't a Fixed 5 V PDO — that's a spec
    /// requirement and "compile-time" reaching here means a caller
    /// bug, not a runtime issue.
    pub fn from_pdos(pdos: Vec<SourcePdo>) -> Self {
        debug_assert!(matches!(
            pdos.first(),
            Some(SourcePdo::Fixed { voltage_mv: 5000, .. })
        ));
        Self {
            pdos,
            accept_pr_swap: false,
            accept_dr_swap: false,
        }
    }

    /// Decide how to react to an incoming Request RDO. Default policy
    /// is "Accept if the requested position is in range and the
    /// requested current is ≤ the PDO's max_current".
    pub fn evaluate_request(&self, rdo: &FixedRdo) -> RequestDecision {
        let idx = rdo.object_position.checked_sub(1).map(|x| x as usize);
        let pdo = match idx.and_then(|i| self.pdos.get(i)) {
            Some(p) => *p,
            None => return RequestDecision::Reject,
        };
        let max_advertised = match pdo {
            SourcePdo::Fixed { max_current_ma, .. } => max_current_ma,
            SourcePdo::Variable { max_current_ma, .. } => max_current_ma,
            SourcePdo::Augmented { max_current_ma, .. } => max_current_ma,
            // Battery PDOs advertise power, not current; reject for
            // now — battery sourcing belongs to a later stage.
            SourcePdo::Battery { .. } => return RequestDecision::Reject,
        };
        if rdo.op_current_ma > max_advertised {
            // Capability mismatch path: the sink is asking for more
            // than we offered. Per §8.3.3.4 we reject unless the
            // sink set cap_mismatch — in which case the sink is
            // running under-powered intentionally and we Accept.
            if rdo.cap_mismatch {
                RequestDecision::Accept
            } else {
                RequestDecision::Reject
            }
        } else {
            RequestDecision::Accept
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_usbpd::message::{FixedRdo, SourcePdo};

    fn smoke_sink_policy_picks_5v_for_default() -> TestResult {
        let policy = SinkPolicy::default();
        let caps = [
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            },
            SourcePdo::Fixed {
                voltage_mv: 9000,
                max_current_ma: 3000,
            },
            SourcePdo::Fixed {
                voltage_mv: 15000,
                max_current_ma: 3000,
            },
        ];
        let sel = match policy.evaluate(&caps) {
            Some(s) => s,
            None => return TestResult::Fail("default policy returned None on valid caps"),
        };
        if sel.object_position != 1 || sel.voltage_mv != 5000 {
            return TestResult::Fail("default sink policy did not pick PDO #1 (5V)");
        }
        if sel.cap_mismatch {
            return TestResult::Fail("cap_mismatch set on a satisfied request");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/policy", smoke_sink_policy_picks_5v_for_default);

    fn smoke_sink_policy_high_voltage_picks_15v() -> TestResult {
        let policy = SinkPolicy {
            min_voltage_mv: 5000,
            op_current_ma: 3000,
            prefer_high_voltage: true,
            ..SinkPolicy::default()
        };
        let caps = [
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            },
            SourcePdo::Fixed {
                voltage_mv: 9000,
                max_current_ma: 3000,
            },
            SourcePdo::Fixed {
                voltage_mv: 15000,
                max_current_ma: 3000,
            },
        ];
        let sel = policy.evaluate(&caps).expect("policy returned None");
        if sel.voltage_mv != 15000 || sel.object_position != 3 {
            return TestResult::Fail("prefer_high_voltage didn't pick the 15V PDO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_high_voltage_picks_15v
    );

    fn smoke_sink_policy_min_voltage_caps_at_first() -> TestResult {
        // Sink wants 20 V minimum; source only offers 5 V. Expect a
        // fall-back to PDO #1 with cap_mismatch set.
        let policy = SinkPolicy {
            min_voltage_mv: 20000,
            op_current_ma: 5000,
            prefer_high_voltage: false,
            ..SinkPolicy::default()
        };
        let caps = [SourcePdo::Fixed {
            voltage_mv: 5000,
            max_current_ma: 3000,
        }];
        let sel = policy.evaluate(&caps).expect("evaluate");
        if !sel.cap_mismatch {
            return TestResult::Fail("expected cap_mismatch when no PDO meets minimum");
        }
        if sel.object_position != 1 {
            return TestResult::Fail("cap-mismatch fallback should target PDO #1");
        }
        if sel.op_current_ma != 3000 {
            return TestResult::Fail("current should clamp to PDO advertised max");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_min_voltage_caps_at_first
    );

    fn smoke_sink_policy_clamps_op_current_to_pdo_max() -> TestResult {
        let policy = SinkPolicy {
            min_voltage_mv: 5000,
            op_current_ma: 5000, // ask for 5 A
            prefer_high_voltage: false,
            ..SinkPolicy::default()
        };
        let caps = [SourcePdo::Fixed {
            voltage_mv: 5000,
            max_current_ma: 1500, // source only offers 1.5 A
        }];
        let sel = policy.evaluate(&caps).expect("evaluate");
        if sel.op_current_ma != 1500 {
            return TestResult::Fail("policy didn't clamp op_current to PDO max");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_clamps_op_current_to_pdo_max
    );

    fn smoke_sink_policy_empty_caps_returns_none() -> TestResult {
        let policy = SinkPolicy::default();
        if policy.evaluate(&[]).is_some() {
            return TestResult::Fail("empty caps should return None");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_empty_caps_returns_none
    );

    fn smoke_sink_selection_to_rdo_propagates_fields() -> TestResult {
        let sel = SinkSelection {
            object_position: 2,
            voltage_mv: 9000,
            op_current_ma: 2500,
            cap_mismatch: true,
        };
        let rdo = sel.to_rdo();
        if rdo.object_position != 2 {
            return TestResult::Fail("RDO position drift");
        }
        if rdo.op_current_ma != 2500 || rdo.max_op_current_ma != 2500 {
            return TestResult::Fail("RDO current drift");
        }
        if !rdo.cap_mismatch {
            return TestResult::Fail("cap_mismatch did not propagate to RDO");
        }
        if !rdo.usb_comms || !rdo.no_usb_suspend {
            return TestResult::Fail("modern-host flags should default on");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_selection_to_rdo_propagates_fields
    );

    fn smoke_source_policy_default_advertises_5v3a() -> TestResult {
        let p = SourcePolicy::default();
        if p.pdos.len() != 1 {
            return TestResult::Fail("default source policy should publish 1 PDO");
        }
        match p.pdos[0] {
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            } => TestResult::Pass,
            _ => TestResult::Fail("default PDO #1 should be Fixed 5V/3A"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_default_advertises_5v3a
    );

    fn smoke_source_policy_accepts_in_budget_request() -> TestResult {
        let p = SourcePolicy::default();
        let rdo = FixedRdo {
            object_position: 1,
            op_current_ma: 1500,
            max_op_current_ma: 1500,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        match p.evaluate_request(&rdo) {
            RequestDecision::Accept => TestResult::Pass,
            _ => TestResult::Fail("default source should accept 1.5A request on 3A PDO"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_accepts_in_budget_request
    );

    fn smoke_source_policy_rejects_over_budget_request() -> TestResult {
        let p = SourcePolicy::default();
        let rdo = FixedRdo {
            object_position: 1,
            op_current_ma: 5000, // ask for 5 A on a 3 A PDO
            max_op_current_ma: 5000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        match p.evaluate_request(&rdo) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("default source should reject over-budget request"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_rejects_over_budget_request
    );

    fn smoke_source_policy_accepts_cap_mismatch_overrun() -> TestResult {
        // Per §8.3.3.4, a sink that sets cap_mismatch=1 has told us
        // it's running under-powered intentionally. We Accept.
        let p = SourcePolicy::default();
        let rdo = FixedRdo {
            object_position: 1,
            op_current_ma: 5000,
            max_op_current_ma: 5000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: true,
        };
        match p.evaluate_request(&rdo) {
            RequestDecision::Accept => TestResult::Pass,
            _ => TestResult::Fail("cap_mismatch=1 request should be Accepted"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_accepts_cap_mismatch_overrun
    );

    fn smoke_source_policy_rejects_unknown_position() -> TestResult {
        let p = SourcePolicy::default();
        let rdo = FixedRdo {
            object_position: 7, // we only published 1 PDO
            op_current_ma: 1000,
            max_op_current_ma: 1000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        match p.evaluate_request(&rdo) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("unknown PDO position should be Rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_rejects_unknown_position
    );

    fn smoke_pr_swap_knobs_default_off() -> TestResult {
        let p = SinkPolicy::default();
        if p.accept_pr_swap {
            return TestResult::Fail("default sink should reject PR_Swap");
        }
        let q = SourcePolicy::default();
        if q.accept_pr_swap {
            return TestResult::Fail("default source should reject PR_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/policy", smoke_pr_swap_knobs_default_off);

    fn smoke_dr_swap_knobs_default_off() -> TestResult {
        let p = SinkPolicy::default();
        if p.accept_dr_swap {
            return TestResult::Fail("default sink should reject DR_Swap");
        }
        let q = SourcePolicy::default();
        if q.accept_dr_swap {
            return TestResult::Fail("default source should reject DR_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/policy", smoke_dr_swap_knobs_default_off);
}
