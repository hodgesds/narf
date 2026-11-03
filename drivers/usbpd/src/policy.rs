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
//!   <https://www.usb.org/document-library/usb-power-delivery>
//!
//! Linux's `drivers/usb/typec/tcpm/tcpm.c` keeps the same shape but
//! folds policy into the state machine; we keep it separate so the
//! tests can poke a `SinkPolicy` without standing up a chip.

extern crate alloc;

use alloc::vec::Vec;

use narf_usbpd::message::{
    AvsRdo, EprEnterFailedReason, EprModeAction, EprModeDataObject, FixedRdo, ProgrammableRdo,
    SourcePdo,
};

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
    /// True when the selected PDO is an Augmented (PPS) PDO — the
    /// Policy Engine must build a Programmable RDO instead of a
    /// Fixed RDO.
    pub is_pps: bool,
    /// True when the selected PDO is an EPR AVS APDO — the Policy
    /// Engine must build an AVS RDO (inside an EPR_Request) instead
    /// of a Fixed RDO.
    pub is_avs: bool,
    /// EPR Mode Capable (§6.4.2.7 bit 22) to set in the outgoing RDO.
    /// Mirrors the sink's `epr_capable` policy flag; EPR Mode entry
    /// (§6.4.10.1) requires it set in the sink's last Request RDO.
    pub epr_mode_capable: bool,
}

impl SinkSelection {
    /// Cast a Fixed selection into a Fixed RDO. Defaults to sensible
    /// flags for a modern host (USB-Comms capable, no USB suspend).
    /// Panics in debug builds if called on a PPS or AVS selection —
    /// use [`Self::to_programmable_rdo`] / [`Self::to_avs_rdo`] instead.
    pub fn to_rdo(self) -> FixedRdo {
        debug_assert!(
            !self.is_pps && !self.is_avs,
            "to_rdo on PPS/AVS selection — use to_programmable_rdo/to_avs_rdo"
        );
        FixedRdo {
            object_position: self.object_position,
            op_current_ma: self.op_current_ma,
            max_op_current_ma: self.op_current_ma,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: self.cap_mismatch,
            epr_mode_capable: self.epr_mode_capable,
        }
    }

    /// Cast a PPS selection into a Programmable RDO. Voltage and
    /// current are quantised by the encoder to the PPS step sizes
    /// (20 mV / 50 mA per §6.4.2.5).
    pub fn to_programmable_rdo(self) -> ProgrammableRdo {
        ProgrammableRdo {
            object_position: self.object_position,
            voltage_mv: self.voltage_mv,
            op_current_ma: self.op_current_ma,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: self.cap_mismatch,
            epr_mode_capable: self.epr_mode_capable,
        }
    }

    /// Cast an EPR AVS selection into an AVS RDO (table 6.27).
    /// Voltage is quantised by the encoder to the 100 mV AVS step;
    /// current to 50 mA. AVS sources do not current-limit, so there
    /// is no max-current field.
    pub fn to_avs_rdo(self) -> AvsRdo {
        AvsRdo {
            object_position: self.object_position,
            voltage_mv: self.voltage_mv,
            op_current_ma: self.op_current_ma,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: self.cap_mismatch,
            epr_mode_capable: self.epr_mode_capable,
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
    /// `true` to Accept inbound VConn_Swap requests. Default off —
    /// VConn ownership only changes when there is an active cable to
    /// power.
    pub accept_vconn_swap: bool,
    /// `true` to prefer an Augmented (PPS) PDO over a Fixed PDO when
    /// both can satisfy the request — the PPS branch picks the
    /// programmable voltage exactly. Default off because most laptop
    /// sinks just want 5 V.
    pub prefer_pps: bool,
    /// Voltage to ask for when picking a PPS PDO, in mV. Clamped at
    /// pick-time to the PDO's advertised [min..=max] range and
    /// quantised to the 20 mV PPS step.
    pub pps_voltage_mv: u32,
    /// `true` when this sink can operate in EPR Mode. Sets the
    /// EPR Mode Capable bit (§6.4.2.7 bit 22) in every outgoing RDO
    /// and gates `evaluate_epr`: a non-EPR sink never selects an EPR
    /// PDO. Default off — EPR is opt-in per port.
    pub epr_capable: bool,
    /// `true` to prefer an EPR AVS APDO over an EPR Fixed PDO when
    /// evaluating EPR-mode capabilities — the AVS branch picks the
    /// programmable voltage exactly. Default off.
    pub prefer_epr_avs: bool,
    /// Voltage to ask for when picking an EPR AVS APDO, in mV.
    /// Clamped at pick-time to the APDO's advertised [min..=max]
    /// range and quantised to the 100 mV AVS step.
    pub epr_avs_voltage_mv: u32,
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
            accept_vconn_swap: false,
            prefer_pps: false,
            pps_voltage_mv: 5000,
            epr_capable: false,
            prefer_epr_avs: false,
            epr_avs_voltage_mv: 28000,
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
        // PPS-preferred path: scan for an Augmented PDO that covers
        // our pps_voltage_mv. The first match wins because §6.4.1.2.6
        // says APDOs are listed in ascending voltage order.
        if self.prefer_pps {
            for (i, pdo) in caps.iter().enumerate() {
                if let SourcePdo::Augmented {
                    max_voltage_mv,
                    min_voltage_mv,
                    max_current_ma,
                } = *pdo
                {
                    if self.pps_voltage_mv >= min_voltage_mv
                        && self.pps_voltage_mv <= max_voltage_mv
                    {
                        // Quantise to the PPS 20 mV step.
                        let v = (self.pps_voltage_mv / 20) * 20;
                        return Some(SinkSelection {
                            object_position: (i + 1) as u8,
                            voltage_mv: v,
                            op_current_ma: self.op_current_ma.min(max_current_ma),
                            cap_mismatch: false,
                            is_pps: true,
                            is_avs: false,
                            epr_mode_capable: self.epr_capable,
                        });
                    }
                }
            }
            // Fall through to Fixed selection if no Augmented PDO can
            // serve us — the sink stays running rather than failing.
        }
        // Walk the Fixed PDOs collecting candidates.
        let mut best: Option<(u8, u32, u32)> = None; // (pos, voltage, current)
        for (i, pdo) in caps.iter().enumerate() {
            let SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
                ..
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
            if let SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
                ..
            } = caps[0]
            {
                return Some(SinkSelection {
                    object_position: 1,
                    voltage_mv,
                    op_current_ma: self.op_current_ma.min(max_current_ma),
                    cap_mismatch: true,
                    is_pps: false,
                    is_avs: false,
                    epr_mode_capable: self.epr_capable,
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
            is_pps: false,
            is_avs: false,
            epr_mode_capable: self.epr_capable,
        })
    }

    /// Pick a PDO position from an EPR-mode capability list — the
    /// contents of an EPR_Source_Capabilities Message, where SPR
    /// PDOs occupy positions 1..=7 and EPR PDOs positions 8..=11
    /// (§6.4.2.1). Returns `None` when the sink is not EPR capable,
    /// the list is empty, or no EPR PDO can serve us.
    ///
    /// Only EPR-mode PDO kinds are considered: Fixed and EPR AVS.
    /// EPR Mode uses only Fixed and AVS PDOs — Variable, Battery and
    /// SPR PPS entries are skipped even if a peer lists them. There
    /// is no cap-mismatch fallback here (unlike SPR `evaluate`): when
    /// no EPR PDO serves us, the caller keeps its SPR contract
    /// instead of requesting an under-powered EPR contract.
    pub fn evaluate_epr(&self, caps: &[SourcePdo]) -> Option<SinkSelection> {
        if !self.epr_capable || caps.is_empty() {
            return None;
        }
        // EPR positions are 8..=11, i.e. indices 7 and up.
        let epr_caps = caps.iter().enumerate().skip(7);
        // AVS-preferred path: first APDO whose range covers our
        // wanted voltage and whose PDP covers the requested power.
        // The PDP check is policy, not a spec reject rule: the PDP
        // is the port's design power, so requesting more than it
        // from an AVS APDO is asking for power the port cannot
        // sustain.
        if self.prefer_epr_avs {
            for (i, pdo) in epr_caps.clone() {
                if let SourcePdo::EprAvs {
                    max_voltage_mv,
                    min_voltage_mv,
                    pdp_w,
                    ..
                } = *pdo
                {
                    if self.epr_avs_voltage_mv >= min_voltage_mv
                        && self.epr_avs_voltage_mv <= max_voltage_mv
                    {
                        let want_mw = self.epr_avs_voltage_mv * self.op_current_ma / 1000;
                        if pdp_w * 1000 >= want_mw {
                            // Quantise to the AVS 100 mV step.
                            let v = (self.epr_avs_voltage_mv / 100) * 100;
                            return Some(SinkSelection {
                                object_position: (i + 1) as u8,
                                voltage_mv: v,
                                op_current_ma: self.op_current_ma,
                                cap_mismatch: false,
                                is_pps: false,
                                is_avs: true,
                                epr_mode_capable: self.epr_capable,
                            });
                        }
                    }
                }
            }
            // Fall through to Fixed selection if no AVS APDO serves
            // us — same stay-running shape as the SPR PPS path.
        }
        // Walk the EPR Fixed PDOs collecting candidates.
        let mut best: Option<(u8, u32, u32)> = None; // (pos, voltage, current)
        for (i, pdo) in epr_caps {
            let SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
                ..
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
        let (pos, voltage_mv, max_current_ma) = best?;
        Some(SinkSelection {
            object_position: pos,
            voltage_mv,
            op_current_ma: self.op_current_ma.min(max_current_ma),
            cap_mismatch: false,
            is_pps: false,
            is_avs: false,
            epr_mode_capable: self.epr_capable,
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
    /// `true` to Accept inbound VConn_Swap requests. Default off —
    /// only enabled for ports that can drive VConn (active cables).
    pub accept_vconn_swap: bool,
    /// `true` when this source can operate in EPR Mode. Sets the
    /// EPR Mode Capable bit (§6.4.1.2.2.7 bit 23) on the advertised
    /// Fixed 5 V PDO and gates EPR Mode entry. Default off — EPR is
    /// opt-in per port, and advertising it commits the port to the
    /// >100 W EPR behaviour.
    pub epr_capable: bool,
    /// EPR-mode PDOs, in EPR_Source_Capabilities order: positions
    /// 8..=11 of the EPR-mode list. Positions 1..=7 resolve against
    /// `pdos` (the SPR list); positions 8..=11 resolve here, so the
    /// SPR PDOs are not duplicated. Empty by default — an
    /// EPR-capable source fills this with its EPR Fixed and EPR AVS
    /// PDOs. EPR Mode uses only Fixed and AVS PDOs.
    pub epr_pdos: Vec<SourcePdo>,
}

impl Default for SourcePolicy {
    fn default() -> Self {
        // Canonical 5 V / 3 A advertisement, matching a USB-PD 3.0
        // Default Source (§6.4.1.3.1).
        Self {
            pdos: alloc::vec![SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            }],
            accept_pr_swap: false,
            accept_dr_swap: false,
            accept_vconn_swap: false,
            epr_capable: false,
            epr_pdos: Vec::new(),
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
            Some(SourcePdo::Fixed {
                voltage_mv: 5000,
                ..
            })
        ));
        Self {
            pdos,
            accept_pr_swap: false,
            accept_dr_swap: false,
            accept_vconn_swap: false,
            epr_capable: false,
            epr_pdos: Vec::new(),
        }
    }

    /// PDOs to actually put on the wire in Source_Capabilities: the
    /// SPR list with the EPR Mode Capable bit set on PDO #1 when
    /// this source is EPR capable. Table 6.9 restricts bits 29…23
    /// to the vSafe5V PDO, so only position 1 is touched — every
    /// other PDO is advertised exactly as listed.
    pub fn advertised_pdos(&self) -> Vec<SourcePdo> {
        let mut pdos = self.pdos.clone();
        if self.epr_capable {
            if let Some(SourcePdo::Fixed {
                epr_mode_capable, ..
            }) = pdos.first_mut()
            {
                *epr_mode_capable = true;
            }
        }
        pdos
    }

    /// Resolve an EPR-mode object position to its PDO: positions
    /// 1..=7 come from the SPR list, positions 8..=11 from
    /// `epr_pdos` (§6.4.2.1). Anything else is unresolvable.
    pub(crate) fn epr_position_pdo(&self, position: u8) -> Option<SourcePdo> {
        match position {
            1..=7 => self.pdos.get((position - 1) as usize).copied(),
            8..=11 => self.epr_pdos.get((position - 8) as usize).copied(),
            _ => None,
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
            // EPR AVS is negotiated via EPR_Request only, never via
            // a plain Request; an EprAvs at an SPR position is a
            // misplaced PDO — fail closed.
            SourcePdo::EprAvs { .. } => return RequestDecision::Reject,
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

    /// Evaluate a Programmable RDO targeting one of our Augmented
    /// (PPS) PDOs. Reject if the position isn't an APDO, the
    /// voltage falls outside the advertised [min..=max] range, or
    /// the current exceeds the APDO's max_current.
    pub fn evaluate_programmable_request(&self, rdo: &ProgrammableRdo) -> RequestDecision {
        let idx = rdo.object_position.checked_sub(1).map(|x| x as usize);
        let pdo = match idx.and_then(|i| self.pdos.get(i)) {
            Some(p) => *p,
            None => return RequestDecision::Reject,
        };
        match pdo {
            SourcePdo::Augmented {
                max_voltage_mv,
                min_voltage_mv,
                max_current_ma,
            } => {
                if rdo.voltage_mv < min_voltage_mv || rdo.voltage_mv > max_voltage_mv {
                    return RequestDecision::Reject;
                }
                if rdo.op_current_ma > max_current_ma {
                    return if rdo.cap_mismatch {
                        RequestDecision::Accept
                    } else {
                        RequestDecision::Reject
                    };
                }
                RequestDecision::Accept
            }
            // Programmable RDOs only target APDOs.
            _ => RequestDecision::Reject,
        }
    }
}

/// One EPR_Request Message's RDO, by kind. An EPR_Request (§6.4.9)
/// carries an RDO plus a copy of the PDO it targets; the source
/// verifies the copy exactly matches its latest advertised PDO at
/// that position before evaluating the request itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EprRequestKind {
    Fixed(FixedRdo),
    Programmable(ProgrammableRdo),
    Avs(AvsRdo),
}

impl EprRequestKind {
    fn object_position(&self) -> u8 {
        match *self {
            EprRequestKind::Fixed(r) => r.object_position,
            EprRequestKind::Programmable(r) => r.object_position,
            EprRequestKind::Avs(r) => r.object_position,
        }
    }
}

impl SourcePolicy {
    /// Decide how to react to an incoming EPR_Request (EPR Mode
    /// only). `pdo_copy` is the second data object of the message.
    /// Rules, all fail-closed to Reject:
    /// - the position must resolve (§6.4.2.1: 1..=7 SPR, 8..=11 EPR);
    /// - the PDO copy must encode byte-identically to the resolved
    ///   PDO (§6.4.9 — a mismatch is a Hard Reset offence on the
    ///   wire; policy reports Reject and the engine escalates);
    /// - Fixed: current ≤ PDO max, or cap_mismatch Accept (mirrors
    ///   `evaluate_request`);
    /// - Programmable: position must be an SPR PPS APDO (1..=7),
    ///   voltage in [min..=max], current rule as
    ///   `evaluate_programmable_request`;
    /// - AVS: position must be an EPR AVS APDO (8..=11), voltage in
    ///   [min..=max] with the table 6.27 low-bits-zero rule
    ///   (voltage must be 100 mV aligned, else Reject). Current is
    ///   NOT checked: an AVS source does not current-limit, the sink
    ///   is responsible for not exceeding what it requested.
    ///
    /// This never returns Wait: a sink receiving Wait to an
    /// EPR_Request initiates a Hard Reset (§6.4.9), so the source
    /// answers Accept or Reject only.
    pub fn evaluate_epr_request(&self, kind: &EprRequestKind, pdo_copy: u32) -> RequestDecision {
        let position = kind.object_position();
        let pdo = match self.epr_position_pdo(position) {
            Some(p) => p,
            None => return RequestDecision::Reject,
        };
        if pdo_copy != pdo.encode() {
            return RequestDecision::Reject;
        }
        match *kind {
            EprRequestKind::Fixed(rdo) => match pdo {
                SourcePdo::Fixed { max_current_ma, .. } => {
                    if rdo.op_current_ma > max_current_ma {
                        if rdo.cap_mismatch {
                            RequestDecision::Accept
                        } else {
                            RequestDecision::Reject
                        }
                    } else {
                        RequestDecision::Accept
                    }
                }
                _ => RequestDecision::Reject,
            },
            EprRequestKind::Programmable(rdo) => {
                // SPR PPS lives at positions 1..=7; an Augmented PDO
                // at an EPR position is a policy construction bug —
                // fail closed rather than accepting it.
                if position > 7 {
                    return RequestDecision::Reject;
                }
                match pdo {
                    SourcePdo::Augmented {
                        max_voltage_mv,
                        min_voltage_mv,
                        max_current_ma,
                    } => {
                        if rdo.voltage_mv < min_voltage_mv || rdo.voltage_mv > max_voltage_mv {
                            return RequestDecision::Reject;
                        }
                        if rdo.op_current_ma > max_current_ma {
                            if rdo.cap_mismatch {
                                RequestDecision::Accept
                            } else {
                                RequestDecision::Reject
                            }
                        } else {
                            RequestDecision::Accept
                        }
                    }
                    _ => RequestDecision::Reject,
                }
            }
            EprRequestKind::Avs(rdo) => {
                // EPR AVS APDOs live at positions 8..=11.
                if position < 8 {
                    return RequestDecision::Reject;
                }
                match pdo {
                    SourcePdo::EprAvs {
                        max_voltage_mv,
                        min_voltage_mv,
                        ..
                    } => {
                        if rdo.voltage_mv % 100 != 0 {
                            return RequestDecision::Reject;
                        }
                        if rdo.voltage_mv < min_voltage_mv || rdo.voltage_mv > max_voltage_mv {
                            return RequestDecision::Reject;
                        }
                        RequestDecision::Accept
                    }
                    _ => RequestDecision::Reject,
                }
            }
        }
    }
}

// ── EPR Mode entry (§6.4.10.1) ────────────────────────────────────
//
// Pure, I/O-free state machines for the EPR Mode entry sequence.
// The source engine drives `SourceEprEntry`; the sink engine (once
// it is policy-driven) drives `SinkEprEntry`. Cable capability and
// VCONN-supplier state arrive as inputs — this module never probes
// hardware — so SOP' cable discovery (#1215) can feed them later
// without changing the sequence logic.
//
// Entry preconditions (§6.4.10.1): sink requests entry; source
// verifies the cable is EPR capable; no CT-VPD in the path; an SPR
// Explicit Contract is in place; the EPR Mode Capable bit is set in
// the Fixed 5 V PDO and in the sink's last RDO. Timers (tEnterEPR,
// keepalives) are NOT modelled here: the engines are step-driven
// with no clock, and the timer values are follow-up work.

/// Source side of EPR Mode entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SourceEprEntry {
    /// True once Enter Succeeded has been sent.
    epr_mode: bool,
    /// True between Enter Acknowledged and the Succeeded/Failed
    /// verdict, while cable capability resolves.
    awaiting_cable: bool,
}

impl Default for SourceEprEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceEprEntry {
    pub fn new() -> Self {
        Self {
            epr_mode: false,
            awaiting_cable: false,
        }
    }

    pub fn is_epr_mode(&self) -> bool {
        self.epr_mode
    }

    /// Handle an inbound EPR_Mode Enter (step 2 of §6.4.10.1).
    /// Checks run in spec order: RDO bit, then PDO bit, then
    /// still-able. On the first failure the machine answers Enter
    /// Failed with the matching reason and stays out of EPR Mode;
    /// on success it answers Enter Acknowledged and waits for cable
    /// resolution. Calling this while already in EPR Mode or
    /// awaiting cable is a caller bug — it answers Unable rather
    /// than corrupting state.
    pub fn on_enter(
        &mut self,
        rdo_epr_bit: bool,
        pdo_epr_bit: bool,
        still_able: bool,
    ) -> EprModeDataObject {
        if self.epr_mode || self.awaiting_cable {
            return EprModeDataObject::enter_failed(EprEnterFailedReason::UnableAtThisTime);
        }
        if !rdo_epr_bit {
            return EprModeDataObject::enter_failed(EprEnterFailedReason::RdoBitNotSet);
        }
        if !pdo_epr_bit {
            return EprModeDataObject::enter_failed(EprEnterFailedReason::PdoBitNotSet);
        }
        if !still_able {
            return EprModeDataObject::enter_failed(EprEnterFailedReason::UnableAtThisTime);
        }
        self.awaiting_cable = true;
        EprModeDataObject::enter_acknowledged()
    }

    /// Resolve the pending entry once cable capability is known
    /// (steps 4–7). `known = false` means discovery is still in
    /// flight — returns `None` and stays pending. When the source
    /// is not the VCONN supplier, entry fails with NotVconnSource:
    /// this machine does not perform a VCONN Swap mid-entry (that
    /// wiring is follow-up work); a source that is not the supplier
    /// must not claim success.
    pub fn on_cable_resolved(
        &mut self,
        known: bool,
        capable: bool,
        vconn_supplier: bool,
    ) -> Option<EprModeDataObject> {
        if !self.awaiting_cable {
            return None;
        }
        if !known {
            return None;
        }
        self.awaiting_cable = false;
        if !vconn_supplier {
            return Some(EprModeDataObject::enter_failed(
                EprEnterFailedReason::NotVconnSource,
            ));
        }
        if !capable {
            return Some(EprModeDataObject::enter_failed(
                EprEnterFailedReason::CableNotEprCapable,
            ));
        }
        self.epr_mode = true;
        Some(EprModeDataObject::enter_succeeded())
    }

    /// An EPR_Mode Exit was received while in EPR Mode: leave it.
    /// The engine decides the follow-up (re-advertise SPR caps when
    /// the live contract is SPR, Hard Reset when it is EPR).
    pub fn on_exit(&mut self) {
        self.epr_mode = false;
        self.awaiting_cable = false;
    }
}

/// Outcome of feeding an EPR_Mode message to the sink entry machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SinkEprEntryOutcome {
    /// Enter Acknowledged received; still waiting for Succeeded.
    AwaitingSucceeded,
    /// Enter Succeeded received — now in EPR Mode.
    Entered,
    /// Enter Failed received, with the source's reason. The engine
    /// maps this to a Soft Reset, as with any entry abort.
    Failed(EprEnterFailedReason),
    /// Anything other than the expected message (step 3 / step 8):
    /// the sink initiates a Soft Reset.
    AbortSoftReset,
}

/// Sink side of EPR Mode entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SinkEprEntry {
    /// True once Enter has been sent and Acknowledged is awaited.
    enter_sent: bool,
    /// True once Acknowledged has arrived and Succeeded is awaited.
    ack_received: bool,
    /// True once Succeeded has arrived.
    epr_mode: bool,
}

impl Default for SinkEprEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl SinkEprEntry {
    pub fn new() -> Self {
        Self {
            enter_sent: false,
            ack_received: false,
            epr_mode: false,
        }
    }

    pub fn is_epr_mode(&self) -> bool {
        self.epr_mode
    }

    /// Build the Enter message (step 1) and arm the machine. Data
    /// is the sink's Operational PDP in watts.
    pub fn send_enter(&mut self, operational_pdp_w: u8) -> EprModeDataObject {
        self.enter_sent = true;
        self.ack_received = false;
        self.epr_mode = false;
        EprModeDataObject::enter(operational_pdp_w)
    }

    /// Feed an inbound EPR_Mode message into the machine.
    pub fn on_message(&mut self, mdo: &EprModeDataObject) -> SinkEprEntryOutcome {
        if self.ack_received {
            // Step 8: only Succeeded enters EPR Mode.
            if mdo.action == EprModeAction::EnterSucceeded {
                self.ack_received = false;
                self.enter_sent = false;
                self.epr_mode = true;
                return SinkEprEntryOutcome::Entered;
            }
            if mdo.action == EprModeAction::EnterFailed {
                let reason = mdo.failed_reason().unwrap_or(EprEnterFailedReason::Unknown);
                self.ack_received = false;
                self.enter_sent = false;
                return SinkEprEntryOutcome::Failed(reason);
            }
            // Abort: reset so a later Succeeded cannot resurrect a
            // dead entry sequence.
            self.ack_received = false;
            self.enter_sent = false;
            return SinkEprEntryOutcome::AbortSoftReset;
        }
        if self.enter_sent {
            // Step 3: only Acknowledged continues the sequence.
            if mdo.action == EprModeAction::EnterAcknowledged {
                self.ack_received = true;
                return SinkEprEntryOutcome::AwaitingSucceeded;
            }
            if mdo.action == EprModeAction::EnterFailed {
                let reason = mdo.failed_reason().unwrap_or(EprEnterFailedReason::Unknown);
                self.enter_sent = false;
                return SinkEprEntryOutcome::Failed(reason);
            }
            self.enter_sent = false;
            return SinkEprEntryOutcome::AbortSoftReset;
        }
        SinkEprEntryOutcome::AbortSoftReset
    }

    /// An EPR_Mode Exit was sent or received while in EPR Mode:
    /// leave it.
    pub fn on_exit(&mut self) {
        self.epr_mode = false;
        self.enter_sent = false;
        self.ack_received = false;
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
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 9000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 15000,
                max_current_ma: 3000,
                epr_mode_capable: false,
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
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_picks_5v_for_default
    );

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
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 9000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 15000,
                max_current_ma: 3000,
                epr_mode_capable: false,
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
            epr_mode_capable: false,
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
            epr_mode_capable: false,
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
            is_pps: false,
            is_avs: false,
            epr_mode_capable: true,
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
        if !rdo.epr_mode_capable {
            return TestResult::Fail("epr_mode_capable did not propagate to RDO");
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
                ..
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
            epr_mode_capable: false,
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
            epr_mode_capable: false,
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
            epr_mode_capable: false,
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
            epr_mode_capable: false,
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

    fn smoke_vconn_swap_knobs_default_off() -> TestResult {
        let p = SinkPolicy::default();
        if p.accept_vconn_swap {
            return TestResult::Fail("default sink should reject VConn_Swap");
        }
        let q = SourcePolicy::default();
        if q.accept_vconn_swap {
            return TestResult::Fail("default source should reject VConn_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/policy", smoke_vconn_swap_knobs_default_off);

    // ── PPS ────────────────────────────────────────────────────────

    fn smoke_sink_policy_pps_picks_apdo_when_preferred() -> TestResult {
        let policy = SinkPolicy {
            prefer_pps: true,
            pps_voltage_mv: 9000,
            ..SinkPolicy::default()
        };
        let caps = [
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ];
        let sel = policy.evaluate(&caps).expect("evaluate");
        if !sel.is_pps {
            return TestResult::Fail("prefer_pps did not select an APDO");
        }
        if sel.object_position != 2 {
            return TestResult::Fail("APDO should be at position 2");
        }
        if sel.voltage_mv != 9000 {
            return TestResult::Fail("PPS voltage drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_pps_picks_apdo_when_preferred
    );

    fn smoke_sink_policy_pps_quantises_voltage_to_20mv() -> TestResult {
        let policy = SinkPolicy {
            prefer_pps: true,
            pps_voltage_mv: 9013, // not 20 mV aligned
            ..SinkPolicy::default()
        };
        let caps = [SourcePdo::Augmented {
            max_voltage_mv: 11000,
            min_voltage_mv: 3300,
            max_current_ma: 3000,
        }];
        let sel = policy.evaluate(&caps).expect("evaluate");
        if sel.voltage_mv != 9000 {
            return TestResult::Fail("PPS voltage should be quantised to 20 mV step");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_pps_quantises_voltage_to_20mv
    );

    fn smoke_sink_policy_pps_falls_back_to_fixed_when_out_of_range() -> TestResult {
        let policy = SinkPolicy {
            prefer_pps: true,
            pps_voltage_mv: 20000, // out of any APDO range here
            ..SinkPolicy::default()
        };
        let caps = [
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ];
        let sel = policy.evaluate(&caps).expect("evaluate");
        if sel.is_pps {
            return TestResult::Fail("out-of-range PPS should fall through to Fixed");
        }
        if sel.object_position != 1 || sel.voltage_mv != 5000 {
            return TestResult::Fail("fall-through should pick Fixed 5V PDO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_pps_falls_back_to_fixed_when_out_of_range
    );

    fn smoke_pps_selection_emits_programmable_rdo() -> TestResult {
        let sel = SinkSelection {
            object_position: 2,
            voltage_mv: 9000,
            op_current_ma: 2000,
            cap_mismatch: false,
            is_pps: true,
            is_avs: false,
            epr_mode_capable: false,
        };
        let rdo = sel.to_programmable_rdo();
        if rdo.object_position != 2 {
            return TestResult::Fail("position drift");
        }
        if rdo.voltage_mv != 9000 || rdo.op_current_ma != 2000 {
            return TestResult::Fail("programmable RDO voltage/current drift");
        }
        let raw = rdo.encode();
        let back = ProgrammableRdo::decode(raw);
        if back.voltage_mv != 9000 || back.op_current_ma != 2000 || back.object_position != 2 {
            return TestResult::Fail("ProgrammableRdo round-trip drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_pps_selection_emits_programmable_rdo
    );

    fn smoke_source_policy_accepts_programmable_request_in_range() -> TestResult {
        let p = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ]);
        let rdo = ProgrammableRdo {
            object_position: 2,
            voltage_mv: 9000,
            op_current_ma: 2000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: false,
        };
        match p.evaluate_programmable_request(&rdo) {
            RequestDecision::Accept => TestResult::Pass,
            _ => TestResult::Fail("in-range PPS request should be Accepted"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_accepts_programmable_request_in_range
    );

    fn smoke_source_policy_rejects_programmable_out_of_voltage_range() -> TestResult {
        let p = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ]);
        let rdo = ProgrammableRdo {
            object_position: 2,
            voltage_mv: 20000,
            op_current_ma: 1000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: false,
        };
        match p.evaluate_programmable_request(&rdo) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("out-of-range PPS voltage should be Rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_rejects_programmable_out_of_voltage_range
    );

    fn smoke_source_policy_rejects_programmable_against_fixed_position() -> TestResult {
        let p = SourcePolicy::default();
        let rdo = ProgrammableRdo {
            object_position: 1,
            voltage_mv: 5000,
            op_current_ma: 1000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: false,
        };
        match p.evaluate_programmable_request(&rdo) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("ProgrammableRdo on Fixed PDO should be Rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_rejects_programmable_against_fixed_position
    );

    // ── EPR ────────────────────────────────────────────────────────

    /// EPR-mode capability list: SPR PDOs at 1..=7, EPR PDOs at 8..=11.
    fn epr_caps_fixture() -> [SourcePdo; 11] {
        [
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: true,
            },
            SourcePdo::Fixed {
                voltage_mv: 9000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 15000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 20000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 21000,
                min_voltage_mv: 3300,
                max_current_ma: 5000,
            },
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 1500,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 1500,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 28000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 36000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 48000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
            SourcePdo::EprAvs {
                max_voltage_mv: 48000,
                min_voltage_mv: 15000,
                pdp_w: 240,
                peak_current: 0,
            },
        ]
    }

    fn smoke_sink_policy_epr_disabled_returns_none() -> TestResult {
        // Default sink is not EPR capable: no EPR selection, even
        // with EPR PDOs on offer.
        let policy = SinkPolicy::default();
        if policy.evaluate_epr(&epr_caps_fixture()).is_some() {
            return TestResult::Fail("non-EPR sink should not select EPR PDOs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_disabled_returns_none
    );

    fn smoke_sink_policy_epr_picks_lowest_epr_fixed() -> TestResult {
        let policy = SinkPolicy {
            epr_capable: true,
            min_voltage_mv: 5000,
            ..SinkPolicy::default()
        };
        let sel = match policy.evaluate_epr(&epr_caps_fixture()) {
            Some(s) => s,
            None => return TestResult::Fail("EPR sink returned None on valid caps"),
        };
        // Lowest EPR Fixed is 28 V at position 8; SPR entries at
        // 1..=7 must not win, and the AVS APDO at 11 must not win
        // without prefer_epr_avs.
        if sel.object_position != 8 || sel.voltage_mv != 28000 || sel.is_avs {
            return TestResult::Fail("EPR evaluation did not pick 28V Fixed at position 8");
        }
        if !sel.epr_mode_capable {
            return TestResult::Fail("EPR selection should carry the EPR bit");
        }
        let rdo = sel.to_rdo();
        if rdo.object_position != 8 || !rdo.epr_mode_capable {
            return TestResult::Fail("EPR Fixed selection RDO drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_picks_lowest_epr_fixed
    );

    fn smoke_sink_policy_epr_high_voltage_picks_48v() -> TestResult {
        let policy = SinkPolicy {
            epr_capable: true,
            prefer_high_voltage: true,
            ..SinkPolicy::default()
        };
        let sel = policy.evaluate_epr(&epr_caps_fixture()).expect("evaluate");
        if sel.object_position != 10 || sel.voltage_mv != 48000 {
            return TestResult::Fail("prefer_high_voltage should pick 48V Fixed at position 10");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_high_voltage_picks_48v
    );

    fn smoke_sink_policy_epr_avs_preferred_when_in_range() -> TestResult {
        let policy = SinkPolicy {
            epr_capable: true,
            prefer_epr_avs: true,
            epr_avs_voltage_mv: 28000,
            op_current_ma: 3000, // 28 V × 3 A = 84 W ≤ 240 W PDP
            ..SinkPolicy::default()
        };
        let sel = policy.evaluate_epr(&epr_caps_fixture()).expect("evaluate");
        if !sel.is_avs || sel.object_position != 11 || sel.voltage_mv != 28000 {
            return TestResult::Fail("AVS-preferred EPR evaluation did not pick the APDO");
        }
        let rdo = sel.to_avs_rdo();
        if rdo.object_position != 11 || rdo.voltage_mv != 28000 || rdo.op_current_ma != 3000 {
            return TestResult::Fail("AVS selection RDO drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_avs_preferred_when_in_range
    );

    fn smoke_sink_policy_epr_avs_skipped_when_pdp_too_small() -> TestResult {
        // 48 V × 5 A = 240 W wanted; the APDO's PDP is 240 W, so it
        // passes — but ask for 48 V at 5 A with a 140 W PDP fixture
        // instead: the AVS branch must skip to Fixed.
        let mut caps = epr_caps_fixture();
        caps[10] = SourcePdo::EprAvs {
            max_voltage_mv: 48000,
            min_voltage_mv: 15000,
            pdp_w: 140,
            peak_current: 0,
        };
        let policy = SinkPolicy {
            epr_capable: true,
            prefer_epr_avs: true,
            prefer_high_voltage: true,
            epr_avs_voltage_mv: 48000,
            op_current_ma: 5000, // 48 V × 5 A = 240 W > 140 W PDP
            ..SinkPolicy::default()
        };
        let sel = policy.evaluate_epr(&caps).expect("evaluate");
        if sel.is_avs {
            return TestResult::Fail("AVS APDO with too-small PDP should be skipped");
        }
        if sel.object_position != 10 || sel.voltage_mv != 48000 {
            return TestResult::Fail("PDP-skip should fall through to 48V Fixed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_avs_skipped_when_pdp_too_small
    );

    fn smoke_sink_policy_epr_ignores_spr_pps_and_variable() -> TestResult {
        // EPR evaluation must not select SPR kinds even at EPR
        // positions: replace the 28 V Fixed with an SPR PPS APDO and
        // expect the next EPR Fixed (36 V) to win.
        let mut caps = epr_caps_fixture();
        caps[7] = SourcePdo::Augmented {
            max_voltage_mv: 48000,
            min_voltage_mv: 15000,
            max_current_ma: 5000,
        };
        let policy = SinkPolicy {
            epr_capable: true,
            ..SinkPolicy::default()
        };
        let sel = policy.evaluate_epr(&caps).expect("evaluate");
        if sel.object_position != 9 || sel.voltage_mv != 36000 {
            return TestResult::Fail("EPR evaluation selected a non-Fixed/AVS PDO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_sink_policy_epr_ignores_spr_pps_and_variable
    );

    fn smoke_source_policy_advertised_pdos_sets_epr_bit_on_5v_only() -> TestResult {
        let mut p = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 20000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
        ]);
        p.epr_capable = true;
        let adv = p.advertised_pdos();
        match adv[0] {
            SourcePdo::Fixed {
                epr_mode_capable: true,
                ..
            } => {}
            _ => return TestResult::Fail("advertised PDO #1 should carry the EPR bit"),
        }
        match adv[1] {
            SourcePdo::Fixed {
                epr_mode_capable: false,
                ..
            } => {}
            _ => return TestResult::Fail("table 6.9 restricts bits 29..23 to the 5V PDO"),
        }
        // Disabled: advertisement is exactly the listed PDOs.
        p.epr_capable = false;
        let adv = p.advertised_pdos();
        match adv[0] {
            SourcePdo::Fixed {
                epr_mode_capable: false,
                ..
            } => TestResult::Pass,
            _ => TestResult::Fail("EPR-disabled advertisement should not set the bit"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_advertised_pdos_sets_epr_bit_on_5v_only
    );

    fn epr_source_policy_fixture() -> SourcePolicy {
        let mut p = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 20000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
        ]);
        p.epr_capable = true;
        p.epr_pdos = alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 28000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
            SourcePdo::Fixed {
                voltage_mv: 48000,
                max_current_ma: 5000,
                epr_mode_capable: false,
            },
            SourcePdo::EprAvs {
                max_voltage_mv: 48000,
                min_voltage_mv: 15000,
                pdp_w: 240,
                peak_current: 0,
            },
        ];
        p
    }

    fn smoke_source_policy_accepts_epr_fixed_request_with_matching_copy() -> TestResult {
        let p = epr_source_policy_fixture();
        // Position 8 = 28 V Fixed; copy must match exactly.
        let target = p.epr_pdos[0].encode();
        let rdo = FixedRdo {
            object_position: 8,
            op_current_ma: 5000,
            max_op_current_ma: 5000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Fixed(rdo), target) {
            RequestDecision::Accept => TestResult::Pass,
            _ => TestResult::Fail("matching EPR Fixed request should be Accepted"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_accepts_epr_fixed_request_with_matching_copy
    );

    fn smoke_source_policy_rejects_epr_request_on_copy_mismatch() -> TestResult {
        let p = epr_source_policy_fixture();
        // Copy claims 36 V while position 8 advertises 28 V.
        let wrong = SourcePdo::Fixed {
            voltage_mv: 36000,
            max_current_ma: 5000,
            epr_mode_capable: false,
        }
        .encode();
        let rdo = FixedRdo {
            object_position: 8,
            op_current_ma: 5000,
            max_op_current_ma: 5000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Fixed(rdo), wrong) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("PDO-copy mismatch must be Rejected (§6.4.9)"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_rejects_epr_request_on_copy_mismatch
    );

    fn smoke_source_policy_epr_avs_request_rules() -> TestResult {
        let p = epr_source_policy_fixture();
        // Position 10 = EPR AVS APDO (15–48 V, 240 W).
        let target = p.epr_pdos[2].encode();
        let good = AvsRdo {
            object_position: 10,
            voltage_mv: 28000,
            op_current_ma: 5000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Avs(good), target) {
            RequestDecision::Accept => {}
            _ => return TestResult::Fail("in-range AVS request should be Accepted"),
        }
        // Out-of-range voltage.
        let high = AvsRdo {
            voltage_mv: 49000,
            ..good
        };
        match p.evaluate_epr_request(&EprRequestKind::Avs(high), target) {
            RequestDecision::Reject => {}
            _ => return TestResult::Fail("out-of-range AVS voltage should be Rejected"),
        }
        // Non-100 mV-aligned voltage violates the table 6.27 note.
        let unaligned = AvsRdo {
            voltage_mv: 28025,
            ..good
        };
        match p.evaluate_epr_request(&EprRequestKind::Avs(unaligned), target) {
            RequestDecision::Reject => {}
            _ => return TestResult::Fail("unaligned AVS voltage should be Rejected"),
        }
        // AVS against a Fixed position.
        let against_fixed = AvsRdo {
            object_position: 8,
            ..good
        };
        let fixed_copy = p.epr_pdos[0].encode();
        match p.evaluate_epr_request(&EprRequestKind::Avs(against_fixed), fixed_copy) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("AVS RDO on a Fixed PDO should be Rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_epr_avs_request_rules
    );

    fn smoke_source_policy_epr_request_for_spr_position() -> TestResult {
        // EPR_Request may target an SPR PDO (§6.4.10.2): position 2
        // = 20 V Fixed, copy matching.
        let p = epr_source_policy_fixture();
        let target = p.pdos[1].encode();
        let rdo = FixedRdo {
            object_position: 2,
            op_current_ma: 3000,
            max_op_current_ma: 3000,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Fixed(rdo), target) {
            RequestDecision::Accept => TestResult::Pass,
            _ => TestResult::Fail("EPR_Request for an SPR PDO should be Accepted"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_epr_request_for_spr_position
    );

    fn smoke_source_policy_epr_request_position_kind_binding() -> TestResult {
        // Position-kind binding (§6.4.2.1 + EPR uses only Fixed and
        // AVS): a Programmable RDO at an EPR position and an AVS
        // RDO at an SPR position are both Rejected even when the
        // PDO copy matches — the variant must live at its own
        // positions. Both fixtures use deliberately misplaced PDOs
        // (a policy construction bug) to isolate the binding check
        // from the variant check.
        let mut p = epr_source_policy_fixture();
        p.epr_pdos[0] = SourcePdo::Augmented {
            max_voltage_mv: 21000,
            min_voltage_mv: 3300,
            max_current_ma: 5000,
        };
        let prdo = ProgrammableRdo {
            object_position: 8,
            voltage_mv: 9000,
            op_current_ma: 2000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Programmable(prdo), p.epr_pdos[0].encode()) {
            RequestDecision::Reject => {}
            _ => return TestResult::Fail("Programmable RDO at position 8 should be Rejected"),
        }
        let mut p = epr_source_policy_fixture();
        p.pdos[1] = SourcePdo::EprAvs {
            max_voltage_mv: 48000,
            min_voltage_mv: 15000,
            pdp_w: 240,
            peak_current: 0,
        };
        let ardo = AvsRdo {
            object_position: 2,
            voltage_mv: 28000,
            op_current_ma: 5000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
            epr_mode_capable: true,
        };
        match p.evaluate_epr_request(&EprRequestKind::Avs(ardo), p.pdos[1].encode()) {
            RequestDecision::Reject => TestResult::Pass,
            _ => TestResult::Fail("AVS RDO at position 2 should be Rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_source_policy_epr_request_position_kind_binding
    );

    fn smoke_epr_entry_source_happy_path() -> TestResult {
        let mut m = SourceEprEntry::new();
        let ack = m.on_enter(true, true, true);
        if ack.action != EprModeAction::EnterAcknowledged {
            return TestResult::Fail("happy-path Enter should be Acknowledged");
        }
        // Cable still unknown: stays pending, no verdict.
        if m.on_cable_resolved(false, false, true).is_some() {
            return TestResult::Fail("unknown cable should stay pending");
        }
        let done = m.on_cable_resolved(true, true, true).expect("verdict");
        if done.action != EprModeAction::EnterSucceeded || !m.is_epr_mode() {
            return TestResult::Fail("capable cable should yield Enter Succeeded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/policy", smoke_epr_entry_source_happy_path);

    fn smoke_epr_entry_source_reject_reasons_in_spec_order() -> TestResult {
        // RDO bit checked before PDO bit before still-able (§6.4.10.1
        // step 2 order a, b, c).
        let mut m = SourceEprEntry::new();
        let r = m.on_enter(false, false, false);
        if r.failed_reason() != Some(EprEnterFailedReason::RdoBitNotSet) {
            return TestResult::Fail("RDO-bit failure should come first");
        }
        let mut m = SourceEprEntry::new();
        let r = m.on_enter(true, false, false);
        if r.failed_reason() != Some(EprEnterFailedReason::PdoBitNotSet) {
            return TestResult::Fail("PDO-bit failure should come second");
        }
        let mut m = SourceEprEntry::new();
        let r = m.on_enter(true, true, false);
        if r.failed_reason() != Some(EprEnterFailedReason::UnableAtThisTime) {
            return TestResult::Fail("still-able failure should come third");
        }
        // Cable failures after Ack.
        let mut m = SourceEprEntry::new();
        let _ = m.on_enter(true, true, true);
        let r = m.on_cable_resolved(true, false, true).expect("verdict");
        if r.failed_reason() != Some(EprEnterFailedReason::CableNotEprCapable) {
            return TestResult::Fail("incapable cable should fail with reason 0x01");
        }
        let mut m = SourceEprEntry::new();
        let _ = m.on_enter(true, true, true);
        let r = m.on_cable_resolved(true, true, false).expect("verdict");
        if r.failed_reason() != Some(EprEnterFailedReason::NotVconnSource) {
            return TestResult::Fail("non-VCONN source should fail with reason 0x02");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_epr_entry_source_reject_reasons_in_spec_order
    );

    fn smoke_epr_entry_sink_sequence_and_aborts() -> TestResult {
        let mut m = SinkEprEntry::new();
        let enter = m.send_enter(240);
        if enter.action != EprModeAction::Enter || enter.operational_pdp_w() != Some(240) {
            return TestResult::Fail("send_enter should emit Enter with the PDP");
        }
        // Anything but Ack after Enter → Soft Reset (step 3).
        match m.on_message(&EprModeDataObject::enter_succeeded()) {
            SinkEprEntryOutcome::AbortSoftReset => {}
            _ => return TestResult::Fail("Succeeded before Ack should abort"),
        }
        let mut m = SinkEprEntry::new();
        let _ = m.send_enter(240);
        match m.on_message(&EprModeDataObject::enter_acknowledged()) {
            SinkEprEntryOutcome::AwaitingSucceeded => {}
            _ => return TestResult::Fail("Ack should advance to awaiting-Succeeded"),
        }
        match m.on_message(&EprModeDataObject::enter_succeeded()) {
            SinkEprEntryOutcome::Entered => {}
            _ => return TestResult::Fail("Succeeded after Ack should enter EPR Mode"),
        }
        if !m.is_epr_mode() {
            return TestResult::Fail("machine should report EPR mode after Succeeded");
        }
        // Failed carries the source's reason through.
        let mut m = SinkEprEntry::new();
        let _ = m.send_enter(240);
        match m.on_message(&EprModeDataObject::enter_failed(
            EprEnterFailedReason::CableNotEprCapable,
        )) {
            SinkEprEntryOutcome::Failed(EprEnterFailedReason::CableNotEprCapable) => {}
            _ => return TestResult::Fail("Enter Failed reason should propagate"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/policy",
        smoke_epr_entry_sink_sequence_and_aborts
    );
}
