//! DisplayPort bandwidth-allocation fixtures.
//!
//! The register values below are pinned from the USB4
//! specification's DisplayPort adapter configuration space
//! (ADP_DP_CS_2, DP_LOCAL_CAP / DP_REMOTE_CAP in the
//! DP_COMMON_CAP layout, DP_STATUS, ADP_DP_CS_8) and the DP
//! tunnelling bandwidth-allocation handshake (ESTIMATED_BW /
//! ALLOCATED_BW / REQUESTED_BW denominated in the adapter's
//! granularity — 250 / 500 / 1000 Mb/s per the GR field — and the
//! CM Acknowledge CA pulse that latches a grant), cross-checked
//! against the GPU sink side's DPIA DPCD extension encodings
//! (BW_GRANULARITY steps of 250/500/1000 Mb/s) and the shared
//! link-training core's payload table (Intel #1092:
//! payload = rate * lanes * 8/10). Nothing here reads an
//! expectation back from the production codecs in `super`.
use super::*;
use crate::cm::CfgSpace;
use crate::control::Config;
use crate::ring::Error;
use crate::topology::{Domain, Port, Router};
use crate::tunnel::tests::Model;
use crate::tunnel::{displays, forget_domain, reconcile, Endpoint, Protocol, Tunnel, TunnelInfo};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The configuration model plus the two pieces of adapter
/// behaviour the allocation protocol needs and the base model
/// does not implement: a write log (so a fixture can pin the
/// exact allocation exchange byte-for-byte) and the adapter
/// latching a grant on the CM Acknowledge pulse — a CA 1->0
/// transition on the DP IN adapter's ADP_DP_CS_2 clears DR in
/// ADP_DP_CS_8, as the spec's handshake prescribes.
pub(crate) struct DpModel {
    inner: Model,
    log: Vec<(u64, u8, u8, u16, u32)>,
    ca_high: bool,
    in_ep: (u64, u8),
    in_cap: u16,
}

impl DpModel {
    fn new(inner: Model, in_route: u64, in_port: u8, in_cap: u16) -> Self {
        Self {
            inner,
            log: Vec::new(),
            ca_high: false,
            in_ep: (in_route, in_port),
            in_cap,
        }
    }
    fn get(&self, route: u64, port: u8, space: CfgSpace, offset: u16) -> u32 {
        self.inner.get(route, port, space, offset)
    }
    fn put(&mut self, route: u64, port: u8, space: CfgSpace, offset: u16, value: u32) {
        self.inner.put(route, port, space, offset, value);
    }
    /// Writes to one port's listed Port-space DWORDs since `mark`
    /// (a `log.len()` snapshot), as (offset, value) pairs.
    fn writes_since(&self, mark: usize, route: u64, port: u8, offsets: &[u16]) -> Vec<(u16, u32)> {
        self.log[mark..]
            .iter()
            .filter(|(r, p, s, o, _)| {
                *r == route && *p == port && *s == CfgSpace::Port as u8 && offsets.contains(o)
            })
            .map(|(_, _, _, o, v)| (*o, *v))
            .collect()
    }
}

impl Config for DpModel {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error> {
        self.inner.read(route, port, space, offset, len).await
    }
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        self.inner.write(route, port, space, offset, data).await?;
        for (i, value) in data.iter().copied().enumerate() {
            let off = offset + i as u16;
            self.log.push((route, port, space as u8, off, value));
            if (route, port) == self.in_ep && space == CfgSpace::Port && off == self.in_cap + 2 {
                if value & (1 << 10) != 0 {
                    self.ca_high = true;
                } else if self.ca_high {
                    self.ca_high = false;
                    let cs8 = self.inner.get(route, port, CfgSpace::Port, self.in_cap + 8);
                    self.inner.put(
                        route,
                        port,
                        CfgSpace::Port,
                        self.in_cap + 8,
                        cs8 & !(1 << 31),
                    );
                }
            }
        }
        Ok(())
    }
}

fn port(number: u8, kind: u32, cap: u16, secondary: bool) -> Port {
    Port {
        number,
        kind,
        adapter_cap: cap,
        phy_cap: 8,
        usb4_cap: 64,
        max_in_hop: 15,
        max_out_hop: 15,
        total_credits: 64,
        secondary,
    }
}

fn router(route: u64, upstream: u8, ports: Vec<Port>) -> Router {
    Router {
        route,
        upstream,
        vendor: 0x8086,
        device: 2,
        ports,
    }
}

/// One host DP IN (adapter cap 32) feeding one device DP OUT
/// over a single first link whose lane adapter (cap 48) reports
/// `lane_cs1` as LANE_ADP_CS_1; `bonded` adds the second bonded
/// lane, doubling the link width.
fn single_link_domain(
    id: u32,
    in_cap: u32,
    out_cap: u32,
    in_cs2: u32,
    lane_cs1: u32,
    bonded: bool,
) -> (Domain, DpModel) {
    let host = router(
        0,
        0,
        alloc::vec![port(1, 1, 0, false), port(5, 0x0e0101, 32, false)],
    );
    let mut child_ports = alloc::vec![port(1, 1, 48, false)];
    if bonded {
        child_ports.push(port(8, 1, 0, true));
    }
    child_ports.push(port(5, 0x0e0102, 32, false));
    let child = router(1, 1, child_ports);
    let mut m = Model::default();
    m.put(0, 5, CfgSpace::Port, 36, in_cap);
    m.put(0, 5, CfgSpace::Port, 34, in_cs2);
    m.put(1, 5, CfgSpace::Port, 36, out_cap);
    m.put(1, 5, CfgSpace::Port, 34, 1 << 6);
    m.put(1, 1, CfgSpace::Port, 49, lane_cs1);
    for r in [0u64, 1] {
        m.put(r, 1, CfgSpace::Port, 4, 64 << 20);
    }
    (
        Domain {
            id,
            routers: alloc::vec![host, child],
        },
        DpModel::new(m, 0, 5, 32),
    )
}

// ── (a) The allocation exchange, byte-for-byte ─────────────────
//
// IN advertises HBR2 x4 + BW_MODE at 250 Mb/s granularity, the
// link is bonded Gen 3 (20 Gb/s x2, 36_000 Mb/s after the guard
// band). Activation must program REMOTE_CAP = 0x1000_2200 on both
// adapters, publish CS_2 = 0x9013_2000 (ESTIMATED_BW 144 units |
// CMMS | CM_ID 3 | GROUP_ID 1), grant 69 units in DP_STATUS, and
// answer a later 40-unit request with the exact grant + CA-pulse
// sequence.
fn usb4_dp_bw_allocation_exchange_byte_for_byte() -> TestResult {
    forget_domain(3);
    let (d, mut m) = single_link_domain(3, 0x1000_2200, 0x2200, 0, 0x4 << 16, true);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("DP tunnel activation in allocation mode");
    }
    if m.get(0, 5, CfgSpace::Port, 37) != 0x1000_2200
        || m.get(1, 5, CfgSpace::Port, 37) != 0x1000_2200
    {
        return TestResult::Fail("REMOTE_CAP must carry the HBR2 x4 envelope on both adapters");
    }
    if m.get(0, 5, CfgSpace::Port, 34) != 0x9013_2000 {
        return TestResult::Fail("CS_2 estimate/group/CM publication");
    }
    // 69 units = 17_250 Mb/s of the 17_280 Mb/s HBR2 x4 payload
    // (grants floor to whole granularity units).
    if m.get(0, 5, CfgSpace::Port, 38) != 69 << 24 {
        return TestResult::Fail("initial ALLOCATED_BW grant");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 3).collect();
    if live.len() != 1
        || live[0].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr2,
                lanes: 4,
                allocated_mbps: 17_250,
                bw_mode: true,
                group: 1,
                budget_mbps: 36_000,
            })
        || live[0].consumed_mbps != 17_250
    {
        return TestResult::Fail("published tunnel state after activation");
    }
    // The source raises a request: DR | DPME | REQUESTED_BW 40
    // units (10_000 Mb/s) in ADP_DP_CS_8.
    m.put(0, 5, CfgSpace::Port, 40, (1 << 31) | (1 << 30) | 40);
    let mark = m.log.len();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err() {
        return TestResult::Fail("allocation servicing pass");
    }
    // The exact CM answer, in order: the grant in DP_STATUS, CA
    // set, CA clear — and nothing else to CS_2 / DP_STATUS.
    let exchange = m.writes_since(mark, 0, 5, &[34, 38]);
    if exchange != alloc::vec![(38, 0x2800_0000), (34, 0x9013_2400), (34, 0x9013_2000)] {
        return TestResult::Fail("allocation exchange differs from the spec-shaped sequence");
    }
    if m.get(0, 5, CfgSpace::Port, 40) & (1 << 31) != 0 {
        return TestResult::Fail("adapter must clear DR once the grant is latched");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 3).collect();
    if live.len() != 1
        || live[0].dp.map(|dp| dp.allocated_mbps) != Some(10_000)
        || live[0].consumed_mbps != 10_000
    {
        return TestResult::Fail("grant must be republished to the ledger");
    }
    forget_domain(3);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_allocation_exchange_byte_for_byte
);

// ── (b) Masking-defeating contention ───────────────────────────
//
// Two DP tunnels on independent links plus a USB3 tunnel sharing
// DP1's link. A per-tunnel-only ledger would grant DP1's
// 40_000 Mb/s request 144 units; charging the USB3 tunnel's
// 225 Mb/s against the same 36_000 Mb/s group caps it at 143 —
// and DP2's group is decided by its own thin Gen 2 link alone.
fn contention_domain() -> (Domain, DpModel) {
    let host = router(
        0,
        0,
        alloc::vec![
            port(1, 1, 0, false),
            port(2, 1, 0, false),
            port(3, 0x200101, 32, false),
            port(5, 0x0e0101, 32, false),
            port(6, 0x0e0101, 32, false),
        ],
    );
    let child1 = router(
        1,
        1,
        alloc::vec![
            port(1, 1, 48, false),
            port(8, 1, 0, true),
            port(3, 0x200102, 32, false),
            port(5, 0x0e0102, 32, false),
        ],
    );
    let child2 = router(
        2,
        2,
        alloc::vec![
            port(2, 1, 48, false),
            port(5, 0x0e0102, 32, false),
            port(6, 0x0e0102, 32, false),
        ],
    );
    let mut m = Model::default();
    // DP IN adapters: IN1 HBR2 x4, IN2 HBR3 x4, both allocation
    // mode at 250 Mb/s granularity (CS_2 = 0).
    m.put(0, 5, CfgSpace::Port, 36, 0x1000_2200);
    m.put(0, 6, CfgSpace::Port, 36, 0x1000_2300);
    // DP OUT adapters (all hot-plugged).
    m.put(1, 5, CfgSpace::Port, 36, 0x2200);
    m.put(1, 5, CfgSpace::Port, 34, 1 << 6);
    m.put(2, 5, CfgSpace::Port, 36, 0x1000_2300);
    m.put(2, 5, CfgSpace::Port, 34, 1 << 6);
    m.put(2, 6, CfgSpace::Port, 36, 0x1000_2300);
    m.put(2, 6, CfgSpace::Port, 34, 1 << 6);
    // Links: child1 bonded Gen 3 (36_000 Mb/s), child2 Gen 2 x1
    // (9_000 Mb/s).
    m.put(1, 1, CfgSpace::Port, 49, 0x4 << 16);
    m.put(2, 2, CfgSpace::Port, 49, 0x8 << 16);
    // USB3 scale 7: the handshake's minimum allocation is
    // 1717 units up + 1717 down at 512 * 2^7 b/s = 225 Mb/s,
    // charged to child1's link group.
    m.put(0, 3, CfgSpace::Port, 35, 7);
    for r in [0u64, 1, 2] {
        m.put(r, 1, CfgSpace::Port, 4, 64 << 20);
    }
    (
        Domain {
            id: 4,
            routers: alloc::vec![host, child1, child2],
        },
        DpModel::new(m, 0, 5, 32),
    )
}

fn usb4_dp_bw_multi_tunnel_shared_and_independent_groups() -> TestResult {
    forget_domain(4);
    let (d, mut m) = contention_domain();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 7)).is_err() {
        return TestResult::Fail("contention reconcile");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 4).collect();
    let usb3: Vec<&TunnelInfo> = live
        .iter()
        .filter(|t| t.protocol == Protocol::Usb3)
        .collect();
    if usb3.len() != 1 || usb3[0].consumed_mbps != 225 {
        return TestResult::Fail("USB3 consumption must be charged in Mb/s");
    }
    let dp: Vec<&TunnelInfo> = live
        .iter()
        .filter(|t| t.protocol == Protocol::DisplayPort)
        .collect();
    // Two DP tunnels form; child2's second sink finds no free
    // DP IN adapter and is left for a later pass.
    if dp.len() != 2 {
        return TestResult::Fail("exactly two DP tunnels must form");
    }
    if dp[0].output.route != 1
        || dp[0].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr2,
                lanes: 4,
                allocated_mbps: 17_250,
                bw_mode: true,
                group: 1,
                budget_mbps: 36_000,
            })
    {
        return TestResult::Fail("DP1 envelope/grant on the Gen 3 group");
    }
    // DP2's HBR3 x4 demand is fitted down to HBR x4 by its own
    // group's 9_000 Mb/s budget: 34 units granted (8_500 Mb/s).
    if dp[1].output.route != 2
        || dp[1].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr,
                lanes: 4,
                allocated_mbps: 8_500,
                bw_mode: true,
                group: 2,
                budget_mbps: 9_000,
            })
        || m.get(0, 6, CfgSpace::Port, 37) != 0x1000_1200
        || m.get(0, 6, CfgSpace::Port, 38) != 34 << 24
    {
        return TestResult::Fail("DP2 must fall back to HBR x4 on its own budget");
    }
    // DP1 asks for 30_000 Mb/s (120 units): fits alongside the
    // USB3 tunnel's 225 Mb/s — granted in full.
    m.put(0, 5, CfgSpace::Port, 40, (1 << 31) | (1 << 30) | 120);
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || m.get(0, 5, CfgSpace::Port, 38) != 120 << 24
    {
        return TestResult::Fail("fitting request must be granted in full");
    }
    // DP1 asks for 40_000 Mb/s (160 units): the group holds
    // 36_000 - 225 = 35_775 Mb/s, so the grant is 143 units
    // (35_750 Mb/s) — a ledger that ignored the USB3 tunnel
    // would grant 144 and overcommit the link.
    m.put(0, 5, CfgSpace::Port, 40, (1 << 31) | (1 << 30) | 160);
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || m.get(0, 5, CfgSpace::Port, 38) != 143 << 24
    {
        return TestResult::Fail("over-budget request must be capped by the shared group");
    }
    let dp: Vec<TunnelInfo> = displays()
        .into_iter()
        .filter(|t| t.domain == 4 && t.protocol == Protocol::DisplayPort)
        .collect();
    if dp.len() != 2 || dp[0].dp.map(|x| x.allocated_mbps) != Some(35_750) {
        return TestResult::Fail("partial grant must be republished");
    }
    // DP2's independent group is untouched by DP1's servicing.
    if m.get(0, 6, CfgSpace::Port, 38) != 34 << 24
        || dp[1].dp.map(|x| x.allocated_mbps) != Some(8_500)
    {
        return TestResult::Fail("groups must be independent");
    }
    forget_domain(4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_multi_tunnel_shared_and_independent_groups
);

// ── (c) HBR3 demand on a thin link degrades, never fails ──────
fn usb4_dp_bw_hbr3_falls_back_on_thin_link() -> TestResult {
    forget_domain(5);
    // Both adapters HBR3 x4, allocation mode at 1 Gb/s
    // granularity (GR = 2), behind a single Gen 2 lane:
    // 9_000 Mb/s of budget.
    let (d, mut m) = single_link_domain(5, 0x1000_2300, 0x2300, 2 << 11, 0x8 << 16, false);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("fallback tunnel activation");
    }
    // HBR3 x4 (25_920 Mb/s) and HBR2 x4 (17_280) exceed the
    // budget; the ladder lands on HBR x4 (8_640): REMOTE_CAP
    // rate code 1, 8 whole 1-Gb/s units granted, estimate 9.
    if m.get(0, 5, CfgSpace::Port, 37) != 0x1000_1200
        || m.get(0, 5, CfgSpace::Port, 38) != 8 << 24
        || (m.get(0, 5, CfgSpace::Port, 34) >> 24) & 0xff != 9
    {
        return TestResult::Fail("HBR3 demand must degrade to HBR x4 with 1 Gb/s units");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 5).collect();
    if live.len() != 1
        || live[0].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr,
                lanes: 4,
                allocated_mbps: 8_000,
                bw_mode: true,
                group: 1,
                budget_mbps: 9_000,
            })
    {
        return TestResult::Fail("fallback state must be recorded");
    }
    forget_domain(5);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_hbr3_falls_back_on_thin_link
);

// ── (d1) No pending request: the adapter is left alone ────────
fn usb4_dp_bw_idle_adapter_is_not_disturbed() -> TestResult {
    forget_domain(7);
    let (d, mut m) = single_link_domain(7, 0x1000_2200, 0x2200, 0, 0x4 << 16, true);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err() {
        return TestResult::Fail("activation");
    }
    let mark = m.log.len();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err() {
        return TestResult::Fail("idle servicing pass");
    }
    // DR is clear and the estimate is current: servicing and the
    // estimate refresh write nothing to either adapter's
    // allocation registers.
    if !m.writes_since(mark, 0, 5, &[34, 38, 40]).is_empty()
        || !m.writes_since(mark, 1, 5, &[34, 40]).is_empty()
        || m.get(0, 5, CfgSpace::Port, 40) != 0
    {
        return TestResult::Fail("idle adapter must not be disturbed");
    }
    forget_domain(7);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_idle_adapter_is_not_disturbed
);

// ── (d2) Reserved capability encodings are refused ────────────
fn usb4_dp_bw_reserved_capability_refused() -> TestResult {
    forget_domain(8);
    // IN LOCAL_CAP carries the reserved lane-count encoding 3.
    let (d, mut m) = single_link_domain(8, 0x3200, 0x2200, 0, 0x4 << 16, true);
    let mut tunnels: Vec<Tunnel> = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)) != Err(Error::Invalid)
        || !tunnels.is_empty()
        || m.get(0, 5, CfgSpace::Port, 37) != 0
        || m.get(1, 5, CfgSpace::Port, 37) != 0
        || displays().iter().any(|t| t.domain == 8)
    {
        return TestResult::Fail("reserved capability must refuse the tunnel unprogrammed");
    }
    forget_domain(8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_reserved_capability_refused
);

// ── (d3) Reserved granularity: legacy mode, no allocation ─────
fn usb4_dp_bw_reserved_granularity_falls_back_to_legacy() -> TestResult {
    forget_domain(9);
    // BW_MODE advertised but the GR field is the reserved
    // encoding 3: the unit of every allocation value is
    // unknowable, so the tunnel is programmed in legacy mode.
    let (d, mut m) = single_link_domain(9, 0x1000_2200, 0x2200, 3 << 11, 0x4 << 16, true);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("legacy fallback activation");
    }
    if !m.writes_since(0, 0, 5, &[34, 38, 40]).is_empty()
        || !m.writes_since(0, 1, 5, &[34]).is_empty()
        || m.get(0, 5, CfgSpace::Port, 37) != 0x2200
    {
        return TestResult::Fail("legacy fallback must not touch allocation registers");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 9).collect();
    if live.len() != 1
        || live[0].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr2,
                lanes: 4,
                allocated_mbps: 17_280,
                bw_mode: false,
                group: 1,
                budget_mbps: 36_000,
            })
    {
        return TestResult::Fail("legacy fallback state");
    }
    forget_domain(9);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_reserved_granularity_falls_back_to_legacy
);

// ── (e) Legacy mode programs the full negotiated rate ─────────
fn usb4_dp_bw_legacy_mode_programs_full_rate() -> TestResult {
    forget_domain(10);
    // Neither adapter advertises BW_MODE. The pre-lane CM floored
    // REMOTE_CAP at "Advertise RBR" (word 0x2000); the negotiated
    // envelope now programs HBR2 x4 (0x2200) with no allocation
    // writes at all.
    let (d, mut m) = single_link_domain(10, 0x2200, 0x2200, 0, 0x4 << 16, true);
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(reconcile(&mut m, &d, &mut tunnels, 2)).is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("legacy activation");
    }
    if m.get(0, 5, CfgSpace::Port, 37) != 0x2200
        || m.get(1, 5, CfgSpace::Port, 37) != 0x2200
        || !m.writes_since(0, 0, 5, &[34, 38, 40]).is_empty()
    {
        return TestResult::Fail("legacy mode must program the full rate without allocation");
    }
    let live: Vec<TunnelInfo> = displays().into_iter().filter(|t| t.domain == 10).collect();
    if live.len() != 1
        || live[0].dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr2,
                lanes: 4,
                allocated_mbps: 17_280,
                bw_mode: false,
                group: 1,
                budget_mbps: 36_000,
            })
        || live[0].consumed_mbps != 17_280
    {
        return TestResult::Fail("legacy state must still be accounted");
    }
    forget_domain(10);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_legacy_mode_programs_full_rate
);

// ── (f) Replay replays the recorded rate ──────────────────────
fn usb4_dp_bw_replay_uses_recorded_rate() -> TestResult {
    forget_domain(6);
    let (d, mut m) = single_link_domain(6, 0x1000_2300, 0x2300, 0, 0x4 << 16, true);
    // A tunnel rebuilt from its suspend record: HBR x2 holding
    // 4_320 Mb/s in allocation mode, against HBR3-capable
    // adapters on a 36_000 Mb/s group.
    let mut t = Tunnel {
        display: TunnelInfo {
            domain: 6,
            input: Endpoint { route: 0, port: 5 },
            output: Endpoint { route: 1, port: 5 },
            protocol: Protocol::DisplayPort,
            dprx_done: false,
            dp: Some(DpTunnelInfo {
                rate: DpRate::Hbr,
                lanes: 2,
                allocated_mbps: 4_320,
                bw_mode: true,
                group: 1,
                budget_mbps: 36_000,
            }),
            consumed_mbps: 4_320,
        },
        writes: Vec::new(),
        resource: false,
        hpd_owned: false,
        bandwidth: None,
    };
    if narf_scheduler::block_on_spin(t.activate(&mut m, &d)).is_err() {
        return TestResult::Fail("replay activation");
    }
    // Programmed at the recorded envelope (HBR rate code 1,
    // 2-lane encoding 1), not renegotiated up to the HBR3
    // ceiling; the grant is the recorded payload in whole
    // 250 Mb/s units: 17 units = 4_250 Mb/s.
    if m.get(0, 5, CfgSpace::Port, 37) != 0x1000_1100
        || m.get(1, 5, CfgSpace::Port, 37) != 0x1000_1100
        || m.get(0, 5, CfgSpace::Port, 38) != 17 << 24
        || t.display.dp
            != Some(DpTunnelInfo {
                rate: DpRate::Hbr,
                lanes: 2,
                allocated_mbps: 4_250,
                bw_mode: true,
                group: 1,
                budget_mbps: 36_000,
            })
    {
        return TestResult::Fail("replay must reprogram the recorded rate and grant");
    }
    forget_domain(6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/dp_bw",
    usb4_dp_bw_replay_uses_recorded_rate
);

// ── (g) Codec and accounting pure functions ───────────────────
fn usb4_dp_bw_codecs() -> TestResult {
    // Payload table: rate * lanes * 8/10 — the shared
    // link-training core's payload_kbps / 1000 (Intel #1092).
    if DpRate::Rbr.payload_mbps(1) != 1_296
        || DpRate::Hbr.payload_mbps(2) != 4_320
        || DpRate::Hbr2.payload_mbps(4) != 17_280
        || DpRate::Hbr3.payload_mbps(4) != 25_920
        || DpRate::from_cap_code(0) != Some(DpRate::Rbr)
        || DpRate::from_cap_code(3) != Some(DpRate::Hbr3)
        || DpRate::from_cap_code(4) != None
    {
        return TestResult::Fail("payload table / rate codes");
    }
    if decode_lane_count(0) != Some(1)
        || decode_lane_count(1) != Some(2)
        || decode_lane_count(2) != Some(4)
        || decode_lane_count(3) != None
        || encode_lane_count(1) != Some(0)
        || encode_lane_count(4) != Some(2)
        || encode_lane_count(3) != None
    {
        return TestResult::Fail("lane encodings");
    }
    // The fallback ladder: rate steps down first; at the bottom
    // rate the lanes halve and the ladder restarts.
    if fit_link(DpRate::Hbr3, 4, 36_000) != Some((DpRate::Hbr3, 4))
        || fit_link(DpRate::Hbr3, 4, 9_000) != Some((DpRate::Hbr, 4))
        || fit_link(DpRate::Hbr3, 4, 5_000) != Some((DpRate::Hbr, 2))
        || fit_link(DpRate::Hbr2, 4, 17_279) != Some((DpRate::Hbr, 4))
        || fit_link(DpRate::Rbr, 1, 1_000) != None
    {
        return TestResult::Fail("fit_link ladder");
    }
    let g250 = Granularity::decode(0);
    let g1000 = Granularity::decode(2 << 11);
    if g250.map(|g| g.units_floor(17_280)) != Some(69)
        || g250.map(|g| g.to_mbps(69)) != Some(17_250)
        || g1000.map(|g| g.units_floor(8_640)) != Some(8)
        || g250.map(|g| g.units_floor(1_000_000)) != Some(255)
        || Granularity::decode(3 << 11) != None
    {
        return TestResult::Fail("granularity denominations");
    }
    if lane_speed_mbps(0x8) != Some(10_000)
        || lane_speed_mbps(0x4) != Some(20_000)
        || lane_speed_mbps(0x2) != Some(40_000)
        || lane_speed_mbps(0xc) != None
        || link_budget_mbps(20_000, 2) != 36_000
        || link_budget_mbps(10_000, 1) != 9_000
    {
        return TestResult::Fail("link budgets");
    }
    // Capability decode is strict; REMOTE_CAP composition
    // preserves peer-owned bits outside the shared fields
    // (DPRX_DONE and the LTTPR field survive).
    if DpAdapterCaps::decode(0x1000_2200).map(|c| (c.max_rate, c.max_lanes, c.bw_mode))
        != Ok((DpRate::Hbr2, 4, true))
        || DpAdapterCaps::decode(4 << 8) != Err(Error::Invalid)
        || DpAdapterCaps::decode(3 << 12) != Err(Error::Invalid)
        || remote_cap_word((1 << 31) | (5 << 20) | 0x2300, DpRate::Hbr, 2, false) != 0x8050_1100
    {
        return TestResult::Fail("capability decode / remote cap composition");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/dp_bw", usb4_dp_bw_codecs);
