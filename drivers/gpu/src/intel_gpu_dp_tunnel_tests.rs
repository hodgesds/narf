//! Native fixtures for the DP tunnel BW allocation against a scripted USB4
//! DP IN adapter whose connection manager grants or refuses requests. Every
//! expected access and number is derived from Linux 7.4 `drm_dp_tunnel.c`
//! (`read_tunnel_regs`, `tunnel_regs_are_valid`, `set_bw_alloc_mode`,
//! `allocate_tunnel_bw`, `bw_req_complete`), not recorded from this code.
extern crate alloc;

use super::*;
use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Read(u32, usize),
    Write(u32, Vec<u8>),
}

/// A DP IN adapter: its tunnel DPCD image, the connection manager's answer
/// to `DP_REQUEST_BW` (granted after `grant_after` status reads, refused,
/// or never) and the log of every native access.
struct Adapter {
    regs: [u8; 0x32],
    status: u8,
    log: Vec<Ev>,
    /// `Some(n)`: the CM grants on the n-th status read after a request;
    /// `None`: it never answers.
    grant_after: Option<u32>,
    refuse: bool,
    reads_since_request: u32,
}

/// The USB4 DP IN adapter of the fixtures: tunneling and BW allocation
/// support, USB4 driver 1 with BW allocation support, group 1, 0.25 Gbps
/// granularity, an estimated 72 units (2250000 kBps), nothing allocated, a
/// DPRX of HBR3 x2 with UHBR10 and the 128b/132b lane 0 mapping.
fn adapter() -> Adapter {
    let mut regs = [0u8; 0x32];
    regs[0x0d] = DP_TUNNELING_SUPPORT | DP_IN_BW_ALLOCATION_MODE_SUPPORT;
    regs[0x0f] = 1;
    regs[0x20] = DP_USB4_DRIVER_BW_ALLOCATION_MODE_SUPPORT;
    regs[0x21] = 1;
    regs[0x22] = 0;
    regs[0x23] = 72;
    regs[0x28] = 0x1e;
    regs[0x29] = 2;
    regs[0x2b] = DP_128B132B_DP_SUPPORTED;
    regs[0x2c] = 0x01 | DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT;
    Adapter {
        regs,
        status: 0,
        log: Vec::new(),
        grant_after: Some(1),
        refuse: false,
        reads_since_request: 0,
    }
}

impl AuxChannel for Adapter {
    fn transact<'b>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'b mut [u8],
    ) -> Result<AuxResponse<'b>, AuxError> {
        let at = |a: u32| (a - DP_TUNNELING_BASE) as usize;
        match req.cmd {
            AuxCommand::NativeWrite => {
                self.log.push(Ev::Write(req.address, req.data.to_vec()));
                match req.address {
                    DP_TUNNELING_STATUS => self.status &= !req.data[0],
                    DP_REQUEST_BW => {
                        self.reads_since_request = 0;
                        if !self.refuse && self.grant_after.is_some() {
                            self.regs[at(DP_ALLOCATED_BW)] = req.data[0];
                        }
                    }
                    a => {
                        for (i, b) in req.data.iter().enumerate() {
                            self.regs[at(a) + i] = *b;
                        }
                    }
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
            AuxCommand::NativeRead => {
                let n = req.data.len();
                self.log.push(Ev::Read(req.address, n));
                if req.address == DP_TUNNELING_STATUS {
                    self.reads_since_request += 1;
                    if self.grant_after == Some(self.reads_since_request) {
                        self.status |= if self.refuse {
                            DP_BW_REQUEST_FAILED
                        } else {
                            DP_BW_REQUEST_SUCCEEDED
                        };
                    }
                    reply[1] = self.status;
                } else {
                    for i in 0..n {
                        reply[1 + i] = self.regs[at(req.address) + i];
                    }
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[1..1 + n],
                })
            }
            _ => Err(AuxError::UnknownStatus),
        }
    }
}

struct VClock(Cell<u64>, u32);

impl Clock for VClock {
    fn now_us(&mut self) -> u64 {
        self.0.get()
    }
    fn sleep_us(&mut self, us: u64) {
        self.0.set(self.0.get() + us);
        self.1 += 1;
    }
}

fn area_reads() -> Vec<Ev> {
    REG_AREAS.iter().map(|&(a, n)| Ev::Read(a, n)).collect()
}

/// `drm_dp_tunnel_detect`: the six `DPTUN_INFO_REG_MASK` ranges (never
/// `DP_TUNNELING_STATUS`), `DP_TUNNELING_SUPPORT`, the validity rules
/// without the DPRX check, and `create_tunnel`'s undetermined allocation;
/// `drm_dp_tunnel_enable_bw_alloc` refuses a tunnel without BW allocation
/// support before any write.
fn smoke_uhbr_tunnel_detect_reads_linux_ranges() -> TestResult {
    let mut a = adapter();
    let t = match detect(&mut a) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("the USB4 adapter must detect as a tunnel"),
    };
    if a.log != area_reads()
        || REG_AREAS
            != [
                (0xe_0000, 12),
                (0xe_000d, 3),
                (0xe_0020, 5),
                (0xe_0028, 2),
                (0xe_002b, 2),
                (0xe_0030, 1),
            ]
    {
        return TestResult::Fail("read_tunnel_regs reads the DPTUN_INFO_REG_MASK ranges");
    }
    if t.granularity != 31_250
        || t.allocated_bw.is_some()
        || t.available_bw.is_some()
        || !t.bw_alloc_supported
        || t.bw_alloc_enabled
        || t.drv_group_id != (1 << 3) | 1
    {
        return TestResult::Fail("create_tunnel state differs from Linux");
    }
    // No DP_TUNNELING_SUPPORT: -ENODEV.
    let mut none = adapter();
    none.regs[0x0d] = 0;
    if detect(&mut none) != Err(TunnelError::NoTunnel) {
        return TestResult::Fail("a link without DP_TUNNELING_SUPPORT has no tunnel");
    }
    // BWA unsupported (no USB4 driver support) but a group ID: -EINVAL.
    let mut bad = adapter();
    bad.regs[0x20] = 0;
    if detect(&mut bad) != Err(TunnelError::Invalid) {
        return TestResult::Fail("a group ID without BWA support is invalid");
    }
    // BWA unsupported, no group, nothing allocated: a legacy tunnel.
    let mut legacy = adapter();
    legacy.regs[0x20] = 0;
    legacy.regs[0x21] = 0;
    let mut t = match detect(&mut legacy) {
        Ok(t) if !t.bw_alloc_supported => t,
        _ => return TestResult::Fail("a legacy tunnel must detect without BWA"),
    };
    legacy.log.clear();
    if enable_bw_alloc(&mut legacy, &mut t) != Err(TunnelError::Unsupported)
        || !legacy.log.is_empty()
    {
        return TestResult::Fail("enabling BWA without support must refuse before any access");
    }
    // Allocated above estimated, or the reserved granularity, are invalid.
    let mut over = adapter();
    over.regs[0x24] = 73;
    let mut gran = adapter();
    gran.regs[0x22] = 3;
    if detect(&mut over) != Err(TunnelError::Invalid) || detect(&mut gran) != Err(TunnelError::Invalid)
    {
        return TestResult::Fail("allocated > estimated and granularity 3 are invalid");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_tunnel_detect_reads_linux_ranges
);

/// `drm_dp_tunnel_enable_bw_alloc`: `set_bw_alloc_mode` (read, then write
/// `DP_DISPLAY_DRIVER_BW_ALLOCATION_MODE_ENABLE | DP_UNMASK_BW_ALLOCATION_IRQ`
/// over the old value), the registers re-read with the DPRX check, the
/// DPRX caps from the tunnel (UHBR10, so `max_dprx_rate` 1000000; two
/// lanes) and the group's available bandwidth (72 x 31250 = 2250000 kBps),
/// which `intel_dp_max_link_data_rate` caps at: UHBR10 x2 (2417750) reads
/// 2250000, HBR3 x2 (1296000) stays. A DPRX lane count that is not a power
/// of two fails verification and clears the mode again.
fn smoke_uhbr_tunnel_bw_alloc_enable_and_caps() -> TestResult {
    let mut a = adapter();
    a.regs[0x30] = 0x01;
    let Ok(mut t) = detect(&mut a) else {
        return TestResult::Fail("the adapter must detect");
    };
    a.log.clear();
    if enable_bw_alloc(&mut a, &mut t).is_err() {
        return TestResult::Fail("BWA must enable on a supporting adapter");
    }
    let mut want = vec![
        Ev::Read(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, 1),
        Ev::Write(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, vec![0xc1]),
    ];
    want.extend(area_reads());
    if a.log != want {
        return TestResult::Fail("BWA enable sequence differs from set_bw_alloc_mode");
    }
    if !t.bw_alloc_enabled
        || t.dprx_128b132b_rates != 0x01
        || !t.lane0_mapping
        || t.max_dprx_rate != 1_000_000
        || t.max_dprx_lanes != 2
        || t.estimated_bw != 2_250_000
        || t.available_bw != Some(2_250_000)
    {
        return TestResult::Fail("the tunnel's DPRX caps and available BW differ");
    }
    if t.max_link_data_rate(1_000_000, 2) != 2_250_000
        || t.max_link_data_rate(810_000, 2) != 1_296_000
        || t.uhbr_lane_mask() != 0
    {
        return TestResult::Fail("intel_dp_max_link_data_rate must cap at the tunnel BW");
    }
    // Without the lane 0 mapping the one- and two-lane UHBR configs go.
    let mut no_map = adapter();
    no_map.regs[0x2c] = 0x01;
    let Ok(mut t) = detect(&mut no_map) else {
        return TestResult::Fail("the adapter must detect");
    };
    if enable_bw_alloc(&mut no_map, &mut t).is_err() || t.uhbr_lane_mask() != 0b11 {
        return TestResult::Fail("no lane 0 mapping disables 1- and 2-lane UHBR");
    }
    // Without 128b/132b the DPRX rate is DP_TUNNELING_MAX_LINK_RATE.
    let mut eight = adapter();
    eight.regs[0x2b] = 0;
    let Ok(mut t) = detect(&mut eight) else {
        return TestResult::Fail("the adapter must detect");
    };
    if enable_bw_alloc(&mut eight, &mut t).is_err()
        || t.dprx_128b132b_rates != 0
        || t.max_dprx_rate != 810_000
    {
        return TestResult::Fail("an 8b/10b DPRX reads its rate from the max link rate code");
    }
    // Three DPRX lanes: the re-read is invalid, the mode is cleared.
    let mut three = adapter();
    three.regs[0x29] = 3;
    let Ok(mut t) = detect(&mut three) else {
        return TestResult::Fail("detect skips the DPRX check");
    };
    three.log.clear();
    if enable_bw_alloc(&mut three, &mut t) != Err(TunnelError::Invalid)
        || t.bw_alloc_enabled
        || three.log.last() != Some(&Ev::Write(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, vec![0x00]))
    {
        return TestResult::Fail("a failed verification must clear the BWA mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_tunnel_bw_alloc_enable_and_caps
);

/// `allocate_tunnel_bw` for the 4K60 UHBR10 x2 stream
/// (`intel_dp_config_required_rate` = 1782000 kBps): `DIV_ROUND_UP(1782000,
/// 31250)` = 58 units, the request status cleared, `DP_REQUEST_BW` 58, the
/// status polled until the CM grants (cleared again), 58 x 31250 = 1812500
/// kBps allocated; the same request again is a no-op; a refusal is
/// -ENOSPC; an unanswered request ends after 3000 ms (the read after the
/// deadline decides); 256 units exceeds `MAX_DP_REQUEST_BW` before any
/// write; freeing requests 0 units.
fn smoke_uhbr_tunnel_alloc_bw_request_and_completion() -> TestResult {
    let enabled = |a: &mut Adapter| {
        let mut t = detect(a).ok()?;
        enable_bw_alloc(a, &mut t).ok()?;
        a.log.clear();
        Some(t)
    };
    let mut a = adapter();
    a.grant_after = Some(3);
    let Some(mut t) = enabled(&mut a) else {
        return TestResult::Fail("BWA must enable");
    };
    let mut clock = VClock(Cell::new(0), 0);
    if alloc_bw(&mut a, &mut clock, &mut t, 1_782_000).is_err() {
        return TestResult::Fail("the CM must grant 58 units");
    }
    let mask = DP_BW_REQUEST_SUCCEEDED | DP_BW_REQUEST_FAILED;
    let want = vec![
        Ev::Write(DP_TUNNELING_STATUS, vec![mask]),
        Ev::Write(DP_REQUEST_BW, vec![58]),
        Ev::Read(DP_TUNNELING_STATUS, 1),
        Ev::Read(DP_TUNNELING_STATUS, 1),
        Ev::Read(DP_TUNNELING_STATUS, 1),
        Ev::Write(DP_TUNNELING_STATUS, vec![mask]),
    ];
    if a.log != want || clock.1 != 2 || t.allocated_bw != Some(1_812_500) {
        return TestResult::Fail("BW request sequence differs from allocate_tunnel_bw");
    }
    a.log.clear();
    if alloc_bw(&mut a, &mut clock, &mut t, 1_800_000).is_err() || !a.log.is_empty() {
        return TestResult::Fail("re-requesting the allocated units must not touch AUX");
    }
    // Refused.
    let mut r = adapter();
    r.refuse = true;
    let Some(mut t) = enabled(&mut r) else {
        return TestResult::Fail("BWA must enable");
    };
    if alloc_bw(&mut r, &mut clock, &mut t, 1_782_000) != Err(TunnelError::Refused)
        || t.allocated_bw.is_some()
    {
        return TestResult::Fail("DP_BW_REQUEST_FAILED is -ENOSPC");
    }
    // Never answered: 3000 ms of 1 ms polls, then one more read.
    let mut n = adapter();
    n.grant_after = None;
    let Some(mut t) = enabled(&mut n) else {
        return TestResult::Fail("BWA must enable");
    };
    let mut clock = VClock(Cell::new(0), 0);
    let reads = |a: &Adapter| {
        a.log
            .iter()
            .filter(|e| **e == Ev::Read(DP_TUNNELING_STATUS, 1))
            .count()
    };
    if alloc_bw(&mut n, &mut clock, &mut t, 1_782_000) != Err(TunnelError::Timeout)
        || reads(&n) != 3_002
        || clock.0.get() != 3_001_000
    {
        return TestResult::Fail("an unanswered request must time out after 3000 ms");
    }
    // 256 units at 31250 kBps exceeds MAX_DP_REQUEST_BW.
    let mut big = adapter();
    let Some(mut t) = enabled(&mut big) else {
        return TestResult::Fail("BWA must enable");
    };
    if alloc_bw(&mut big, &mut clock, &mut t, 256 * 31_250) != Err(TunnelError::TooLarge)
        || !big.log.is_empty()
    {
        return TestResult::Fail("a request above 255 units must refuse before any write");
    }
    // Free, then disable: request 0, then the mode bits cleared.
    let mut f = adapter();
    let Some(mut t) = enabled(&mut f) else {
        return TestResult::Fail("BWA must enable");
    };
    if alloc_bw(&mut f, &mut clock, &mut t, 1_782_000).is_err()
        || alloc_bw(&mut f, &mut clock, &mut t, 0).is_err()
        || t.allocated_bw != Some(0)
        || !f.log.contains(&Ev::Write(DP_REQUEST_BW, vec![0]))
    {
        return TestResult::Fail("freeing the tunnel BW requests 0 units");
    }
    f.log.clear();
    if disable_bw_alloc(&mut f, &mut t).is_err()
        || t.bw_alloc_enabled
        || t.allocated_bw.is_some()
        || f.log
            != vec![
                Ev::Read(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, 1),
                Ev::Write(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, vec![0x00]),
            ]
    {
        return TestResult::Fail("disabling BWA clears the mode and the allocation");
    }
    if bw_code_to_link_rate(0x1e) != 810_000
        || bw_code_to_link_rate(0x02) != 2_000_000
        || bw_code_to_link_rate(0x04) != 1_350_000
    {
        return TestResult::Fail("drm_dp_bw_code_to_link_rate differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_tunnel_alloc_bw_request_and_completion
);
