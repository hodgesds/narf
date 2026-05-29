//! Multicast Listener Discovery — RFC 3810 (MLDv2).
//!
//! Skeleton scope: builder for the MLDv2 Report message + the
//! constant set the Stage-1 stack needs. The MLDv2 query receiver and
//! group-join API are deferred until a multicast consumer (mDNS,
//! SSDP, MLDv1 router) actually exists in the kernel.
//!
//! References (public-only):
//! - RFC 3810 — Multicast Listener Discovery Version 2 (MLDv2) for
//!   IPv6 (R. Vida, L. Costa, Jun 2004). §5.2 (Report layout),
//!   §5.1 (Query layout — receiver not implemented), §5.2.12 (Multicast
//!   Address Record).
//!   <https://datatracker.ietf.org/doc/html/rfc3810>

extern crate alloc;

use alloc::vec::Vec;

/// ICMPv6 type 143 — Multicast Listener Report (MLDv2).
pub const ICMPV6_MLD2_REPORT: u8 = 143;
/// ICMPv6 type 130 — Multicast Listener Query (MLDv1/v2).
pub const ICMPV6_MLD_QUERY: u8 = 130;

/// Record type values (RFC 3810 §5.2.12).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MlRecordType {
    ModeIsInclude = 1,
    ModeIsExclude = 2,
    ChangeToInclude = 3,
    ChangeToExclude = 4,
    AllowNew = 5,
    BlockOld = 6,
}

/// One Multicast Address Record.
#[derive(Clone, Debug)]
pub struct MlRecord {
    pub record_type: MlRecordType,
    pub multicast_addr: [u8; 16],
    pub sources: Vec<[u8; 16]>,
}

/// Build an MLDv2 Report body (no ICMPv6 outer header — the caller
/// wraps it with the standard type / code / checksum).
///
/// Body layout (RFC 3810 §5.2): 2 bytes reserved, 2 bytes Nr of
/// Multicast Address Records, then each record.
pub fn build_mldv2_report(records: &[MlRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + records.len() * 24);
    out.push(ICMPV6_MLD2_REPORT);
    out.push(0); // code
    out.extend_from_slice(&[0u8; 2]); // checksum (caller fills)
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for r in records {
        // Record: type (1) + aux-data-len (1) + #sources (2) +
        // multicast-addr (16) + each source (16).
        out.push(r.record_type as u8);
        out.push(0);
        out.extend_from_slice(&(r.sources.len() as u16).to_be_bytes());
        out.extend_from_slice(&r.multicast_addr);
        for s in &r.sources {
            out.extend_from_slice(s);
        }
    }
    out
}

/// Build the "Join this multicast group" MLDv2 report (single
/// CHANGE_TO_EXCLUDE record, no source filter).
pub fn build_join_report(group: [u8; 16]) -> Vec<u8> {
    let recs = [MlRecord {
        record_type: MlRecordType::ChangeToExclude,
        multicast_addr: group,
        sources: Vec::new(),
    }];
    build_mldv2_report(&recs)
}

/// Build the "Leave this multicast group" report.
pub fn build_leave_report(group: [u8; 16]) -> Vec<u8> {
    let recs = [MlRecord {
        record_type: MlRecordType::ChangeToInclude,
        multicast_addr: group,
        sources: Vec::new(),
    }];
    build_mldv2_report(&recs)
}
