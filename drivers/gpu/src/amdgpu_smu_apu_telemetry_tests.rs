//! Kernel tests for the APU SMU telemetry owner (#1698).
//!
//! Spec-fixture discipline: the fake DMA buffer stands in for the
//! memory the SMU DMAs into, and `MockSmu` scripts the mailbox. The
//! table bytes under test are hand-built from the Linux driver-IF
//! headers (`smu12_driver_if.h`, `smu13_driver_if_v13_0_4.h`) — the
//! same source the decoders were written from — so the fake and the
//! code cannot agree on a wrong constant. The expected mailbox
//! message ids are written out literally (0x0D/0x0E/0x0F for v13,
//! 0x1A/0x1B/0x1C for v12, per `amdgpu_smu_v13` / `amdgpu_smu_v12`)
//! instead of reusing the production constants, so the test checks
//! the ids rather than echoing them.

use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::amdgpu_smu::{
    parse_metrics, parse_metrics_v12, MockSmu, SmuError, SmuVersion, MP1_C2PMSG_ARG_REL,
    MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL, SMU_METRICS_V12_BYTES, SMU_METRICS_V13_0_4_BYTES,
    SMU_RESP_FAIL, SMU_RESP_OK,
};

const MP1_BASE: u32 = 0x16000;
const DMA_ADDR: u64 = 0x0000_1234_5678_9000;

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Phoenix (SMU 13.0.4) metrics table, hand-built from `SmuMetrics_t`
/// in `smu13_driver_if_v13_0_4.h`: GFX 2400 MHz, edge 52.35 C,
/// hotspot 61.00 C, APU power 45 W.
fn v13_table() -> [u8; SMU_METRICS_V13_0_4_BYTES] {
    let mut b = [0u8; SMU_METRICS_V13_0_4_BYTES];
    put16(&mut b, 0x00, 2400); // GfxclkFrequency
    put16(&mut b, 0x02, 1000); // SocclkFrequency
    put16(&mut b, 0x08, 2000); // MemclkFrequency
    put16(&mut b, 0x0c, 4250); // GfxActivity 42.5%
    put16(&mut b, 0x10, 1100); // Voltage[0] VDDGFX
    put16(&mut b, 0x12, 950); // Voltage[1] VDD SOC
    put16(&mut b, 0x4e, 4100); // L3Temperature 41.00 C
    put16(&mut b, 0x50, 5235); // GfxTemperature 52.35 C
    put16(&mut b, 0x52, 6100); // SocTemperature 61.00 C
    put16(&mut b, 0x54, 0x0020); // ThrottlerStatus
    put16(&mut b, 0x56, 12000); // CurrentSocketPower mW
    put32(&mut b, 0x5c, 45000); // ApuPower mW
    put16(&mut b, 0x88, 11000); // AverageSocketPower mW
    b
}

/// Renoir (SMU 12.0) metrics table, hand-built from `SmuMetrics_t`
/// in `smu12_driver_if.h`: GFX 1800 MHz, edge 48.75 C, hotspot
/// 55.00 C, APU power 22 W (watts on this generation, not milliwatts).
fn v12_table() -> [u8; SMU_METRICS_V12_BYTES] {
    let mut b = [0u8; SMU_METRICS_V12_BYTES];
    put16(&mut b, 0x22, 1800); // ClockFrequency[CLOCK_GFXCLK]
    put16(&mut b, 0x24, 1750); // AverageGfxclkFrequency
    put16(&mut b, 0x2c, 3800); // AverageGfxActivity 38%
    put16(&mut b, 0x30, 1050); // Voltage[0]
    put16(&mut b, 0x3c, 45000); // FanPwm milli
    put16(&mut b, 0x3e, 25); // CurrentSocketPower [W]
    put16(&mut b, 0x78, 4875); // GfxTemperature 48.75 C
    put16(&mut b, 0x7a, 5500); // SocTemperature 55.00 C
    put16(&mut b, 0x7c, 0x0004); // ThrottlerStatus
    put16(&mut b, 0x84, 22); // ApuPower [W]
    put16(&mut b, 0x86, 0); // dGpuPower [W]
    b
}

/// Fake DMA buffer: plain bytes plus a staged table the fake SMU
/// "DMAs" in when the owner syncs after the transfer. The staged
/// bytes live apart from the buffer bytes, so the zero-fill in
/// `refresh` cannot erase them — exactly like a real DMA landing
/// after the transfer message.
struct FakeBuffer {
    bytes: [u8; APU_METRICS_BUFFER_BYTES],
    addr: u64,
    size: usize,
    staged: [u8; SMU_METRICS_V13_0_4_BYTES],
    staged_len: usize,
}

impl FakeBuffer {
    fn new(addr: u64) -> Self {
        Self {
            bytes: [0; APU_METRICS_BUFFER_BYTES],
            addr,
            size: APU_METRICS_BUFFER_BYTES,
            staged: [0; SMU_METRICS_V13_0_4_BYTES],
            staged_len: 0,
        }
    }

    /// A buffer too small for either generation's metrics struct.
    fn small(addr: u64) -> Self {
        let mut b = Self::new(addr);
        b.size = 64;
        b
    }

    /// Stage the table the fake SMU will DMA in on the next transfer.
    fn stage_dma_table(&mut self, table: &[u8]) {
        self.staged[..table.len()].copy_from_slice(table);
        self.staged_len = table.len();
    }
}

impl MetricsBuffer for FakeBuffer {
    fn dma_addr(&self) -> u64 {
        self.addr
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.size]
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.size]
    }
    fn sync_after_transfer(&mut self) {
        // The DMA landing point: the SMU wrote the staged table into
        // the buffer between the transfer message and the CPU read.
        let n = self.staged_len;
        self.bytes[..n].copy_from_slice(&self.staged[..n]);
        self.staged_len = 0;
    }
    fn len(&self) -> usize {
        self.size
    }
}

/// Stage one successful mailbox message: handshake idle, OK response,
/// zero ARG read-back.
fn stage_ok(smu: &mut MockSmu, mp1_base: u32) {
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;
    smu.stage_read(resp, 1);
    smu.stage_read(resp, SMU_RESP_OK);
    smu.stage_read(arg, 0);
}

/// Stage one rejected mailbox message: handshake idle, FAIL response
/// (the ARG read-back is never reached after a rejection).
fn stage_reject(smu: &mut MockSmu, mp1_base: u32) {
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    smu.stage_read(resp, 1);
    smu.stage_read(resp, SMU_RESP_FAIL);
}

fn apu_metrics_table_id_is_seven() -> TestResult {
    // TABLE_SMU_METRICS is 7 in smu12_driver_if.h and 7 in
    // smu13_driver_if_v13_0_4.h — unlike the discrete 5. The
    // struct sizes are the header layouts, not guesses.
    if APU_METRICS_TABLE != 7 {
        return TestResult::Fail("APU_METRICS_TABLE must be 7 on both APU generations");
    }
    if SMU_METRICS_V12_BYTES != 148 {
        return TestResult::Fail("SMU_METRICS_V12_BYTES must be 148");
    }
    if SMU_METRICS_V13_0_4_BYTES != 160 {
        return TestResult::Fail("SMU_METRICS_V13_0_4_BYTES must be 160");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_metrics_table_id_is_seven
);

fn apu_v13_decode_units() -> TestResult {
    let m = match parse_metrics(&v13_table()) {
        Some(m) => m,
        None => return TestResult::Fail("v13 table did not decode"),
    };
    if m.edge_temperature_milli_c() != 52350 {
        return TestResult::Fail("v13 edge must be 52350 mC (52.35 C centi-C x10)");
    }
    if m.hotspot_temperature_milli_c() != 61000 {
        return TestResult::Fail("v13 hotspot must be 61000 mC (SocTemperature)");
    }
    if m.gfxclk_mhz != 2400 {
        return TestResult::Fail("v13 gfxclk must be 2400 MHz");
    }
    if m.apu_power_mw != 45000 {
        return TestResult::Fail("v13 ApuPower must be 45000 mW");
    }
    if m.gfx_activity_percent() != 42 {
        return TestResult::Fail("v13 activity must be 42%");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/smu_apu_telemetry", apu_v13_decode_units);

fn apu_v12_decode_units() -> TestResult {
    let m = match parse_metrics_v12(&v12_table()) {
        Some(m) => m,
        None => return TestResult::Fail("v12 table did not decode"),
    };
    if m.edge_temperature_milli_c() != 48750 {
        return TestResult::Fail("v12 edge must be 48750 mC (48.75 C centi-C x10)");
    }
    if m.hotspot_temperature_milli_c() != 55000 {
        return TestResult::Fail("v12 hotspot must be 55000 mC (SocTemperature)");
    }
    if m.gfxclk_mhz != 1800 {
        return TestResult::Fail("v12 gfxclk must be 1800 MHz (ClockFrequency[GFXCLK])");
    }
    // The v12 power fields are watts, not milliwatts: 22 W, not 22000.
    if m.apu_power_w != 22 {
        return TestResult::Fail("v12 ApuPower must be 22 W");
    }
    if m.current_socket_power_w != 25 {
        return TestResult::Fail("v12 CurrentSocketPower must be 25 W");
    }
    if m.dgpu_power_w != 0 {
        return TestResult::Fail("v12 dGpuPower must be 0 W");
    }
    if m.gfx_activity_percent() != 38 {
        return TestResult::Fail("v12 activity must be 38%");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/smu_apu_telemetry", apu_v12_decode_units);

fn apu_decode_rejects_short_tables() -> TestResult {
    if parse_metrics_v12(&[0u8; SMU_METRICS_V12_BYTES - 1]).is_some() {
        return TestResult::Fail("v12 decode must reject a 147-byte table");
    }
    if parse_metrics(&[0u8; SMU_METRICS_V13_0_4_BYTES - 1]).is_some() {
        return TestResult::Fail("v13 decode must reject a 159-byte table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_decode_rejects_short_tables
);

fn apu_publish_programs_dram_addr_high_then_low_v13() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut owner =
        match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, FakeBuffer::new(DMA_ADDR)) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("owner construction failed"),
        };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    if !owner.is_published() {
        return TestResult::Fail("owner must report published after publish_dram_addr");
    }
    if owner.dma_addr() != DMA_ADDR {
        return TestResult::Fail("owner dma_addr must be the buffer address");
    }
    // High then Low, with the address split (Linux
    // smu_v13_0_set_driver_table_location order, as in the discrete
    // owner's upload): (addr >> 32) then (addr & 0xffffffff).
    let resp = MP1_BASE + MP1_C2PMSG_RESP_REL;
    let arg = MP1_BASE + MP1_C2PMSG_ARG_REL;
    let msg = MP1_BASE + MP1_C2PMSG_MSG_REL;
    let expected: [(u32, u32); 6] = [
        (resp, 0),
        (arg, 0x1234_5678),
        (msg, 0x0D), // V13 SetDriverDramAddrHigh
        (resp, 0),
        (arg, 0x5678_9000),
        (msg, 0x0E), // V13 SetDriverDramAddrLow
    ];
    if smu.writes.as_slice() != expected.as_slice() {
        return TestResult::Fail("publish must write High then Low with the split address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_publish_programs_dram_addr_high_then_low_v13
);

fn apu_publish_programs_dram_addr_high_then_low_v12() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut owner =
        match ApuTelemetryOwner::new(SmuVersion::V12, MP1_BASE, FakeBuffer::new(DMA_ADDR)) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("owner construction failed"),
        };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    let resp = MP1_BASE + MP1_C2PMSG_RESP_REL;
    let arg = MP1_BASE + MP1_C2PMSG_ARG_REL;
    let msg = MP1_BASE + MP1_C2PMSG_MSG_REL;
    let expected: [(u32, u32); 6] = [
        (resp, 0),
        (arg, 0x1234_5678),
        (msg, 0x1A), // V12 SetDriverDramAddrHigh
        (resp, 0),
        (arg, 0x5678_9000),
        (msg, 0x1B), // V12 SetDriverDramAddrLow
    ];
    if smu.writes.as_slice() != expected.as_slice() {
        return TestResult::Fail("v12 publish must write High (0x1A) then Low (0x1B)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_publish_programs_dram_addr_high_then_low_v12
);

fn apu_refresh_v13_end_to_end() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut buf = FakeBuffer::new(DMA_ADDR);
    buf.stage_dma_table(&v13_table());
    let mut owner = match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, buf) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner construction failed"),
    };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    stage_ok(&mut smu, MP1_BASE);
    let metrics = match owner.refresh(&mut smu) {
        Ok(m) => m,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("refresh failed");
        }
    };
    if metrics.edge_temperature_milli_c() != 52350 {
        return TestResult::Fail("refresh must decode edge 52350 mC from the DMA table");
    }
    if metrics.hotspot_temperature_milli_c() != 61000 {
        return TestResult::Fail("refresh must decode hotspot 61000 mC from the DMA table");
    }
    // The transfer itself: ARG = TABLE_SMU_METRICS (7), MSG = v13
    // TransferTableSmu2Dram (0x0F), after the six publish writes.
    let arg = MP1_BASE + MP1_C2PMSG_ARG_REL;
    let msg = MP1_BASE + MP1_C2PMSG_MSG_REL;
    if smu.writes.len() != 9 {
        return TestResult::Fail("expected 6 publish + 3 transfer writes");
    }
    if smu.writes[7] != (arg, APU_METRICS_TABLE) {
        return TestResult::Fail("transfer ARG must be TABLE_SMU_METRICS (7)");
    }
    if smu.writes[8] != (msg, 0x0F) {
        return TestResult::Fail("transfer MSG must be v13 TransferTableSmu2Dram (0x0F)");
    }
    if owner.samples() != 1 {
        return TestResult::Fail("one successful refresh must record one sample");
    }
    if owner.error().is_some() {
        return TestResult::Fail("a successful refresh must clear the error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_refresh_v13_end_to_end
);

fn apu_refresh_v12_end_to_end() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut buf = FakeBuffer::new(DMA_ADDR);
    buf.stage_dma_table(&v12_table());
    let mut owner = match ApuTelemetryOwner::new(SmuVersion::V12, MP1_BASE, buf) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner construction failed"),
    };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    stage_ok(&mut smu, MP1_BASE);
    let metrics = match owner.refresh(&mut smu) {
        Ok(m) => m,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("refresh failed");
        }
    };
    if metrics.edge_temperature_milli_c() != 48750 {
        return TestResult::Fail("v12 refresh must decode edge 48750 mC from the DMA table");
    }
    if metrics.version() != SmuVersion::V12 {
        return TestResult::Fail("v12 refresh must report the v12 generation");
    }
    let arg = MP1_BASE + MP1_C2PMSG_ARG_REL;
    let msg = MP1_BASE + MP1_C2PMSG_MSG_REL;
    if smu.writes[7] != (arg, APU_METRICS_TABLE) {
        return TestResult::Fail("v12 transfer ARG must be TABLE_SMU_METRICS (7)");
    }
    if smu.writes[8] != (msg, 0x1C) {
        return TestResult::Fail("transfer MSG must be v12 TransferTableSmu2Dram (0x1C)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_refresh_v12_end_to_end
);

fn apu_refresh_before_publish_fails_without_mailbox_traffic() -> TestResult {
    let mut smu = MockSmu::new();
    let mut owner =
        match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, FakeBuffer::new(DMA_ADDR)) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("owner construction failed"),
        };
    match owner.refresh(&mut smu) {
        Err(ApuError::NotPublished) => {}
        _ => return TestResult::Fail("refresh before publish must fail NotPublished"),
    }
    if !smu.writes.is_empty() {
        return TestResult::Fail("an unpublished refresh must not touch the mailbox");
    }
    if owner.last().is_some() {
        return TestResult::Fail("an unpublished refresh must not produce a sample");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_refresh_before_publish_fails_without_mailbox_traffic
);

fn apu_unwritten_table_reads_as_zeros() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    // Poison the staging area: if refresh did not zero it first, the
    // stale bytes would decode as a bogus sample.
    let mut buf = FakeBuffer::new(DMA_ADDR);
    buf.as_mut_slice().fill(0xAA);
    let mut owner = match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, buf) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner construction failed"),
    };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    stage_ok(&mut smu, MP1_BASE);
    let metrics = match owner.refresh(&mut smu) {
        Ok(m) => m,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("refresh failed");
        }
    };
    if metrics.edge_temperature_milli_c() != 0 || metrics.hotspot_temperature_milli_c() != 0 {
        return TestResult::Fail("an unwritten table must decode as zeros, not stale bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_unwritten_table_reads_as_zeros
);

fn apu_rejected_refresh_retains_last_sample() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut buf = FakeBuffer::new(DMA_ADDR);
    buf.stage_dma_table(&v13_table());
    let mut owner = match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, buf) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner construction failed"),
    };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    stage_ok(&mut smu, MP1_BASE);
    if owner.refresh(&mut smu).is_err() {
        return TestResult::Fail("first refresh must succeed");
    }
    // The SMU now rejects the transfer.
    stage_reject(&mut smu, MP1_BASE);
    match owner.refresh(&mut smu) {
        Err(ApuError::Smu(SmuError::Rejected(0xFF))) => {}
        _ => return TestResult::Fail("rejected refresh must surface SmuError::Rejected"),
    }
    let last = match owner.last() {
        Some(m) => m,
        None => return TestResult::Fail("rejection must retain the last sample"),
    };
    if last.edge_temperature_milli_c() != 52350 {
        return TestResult::Fail("retained sample must still be 52350 mC");
    }
    if owner.samples() != 1 {
        return TestResult::Fail("a rejected refresh must not bump the sample count");
    }
    if owner.error().is_none() {
        return TestResult::Fail("a rejected refresh must record its error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_rejected_refresh_retains_last_sample
);

fn apu_owner_rejects_undersized_buffer() -> TestResult {
    match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, FakeBuffer::small(DMA_ADDR)) {
        Err(ApuError::BufferTooSmall) => TestResult::Pass,
        _ => TestResult::Fail("a 64-byte buffer must fail BufferTooSmall"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_owner_rejects_undersized_buffer
);

fn apu_update_fold_retains_across_rejection() -> TestResult {
    let sample = match parse_metrics(&v13_table()) {
        Some(m) => ApuMetrics::V13(m),
        None => return TestResult::Fail("fixture table did not decode"),
    };
    let rejected = ApuError::Smu(SmuError::Rejected(0xFF));
    // A failure before any success: no sample, error recorded, no count.
    let s0 = update(None, Err(ApuError::NotPublished));
    if s0.metrics.is_some() || s0.error.is_none() || s0.samples != 0 {
        return TestResult::Fail("failed first refresh must publish no sample");
    }
    // Success: sample recorded, error cleared, count bumped.
    let s1 = update(Some(s0), Ok(sample));
    if s1.metrics != Some(sample) || s1.error.is_some() || s1.samples != 1 {
        return TestResult::Fail("successful refresh must publish the sample");
    }
    // Rejection: sample retained, error recorded, count unchanged.
    let s2 = update(Some(s1), Err(rejected));
    if s2.metrics != Some(sample) || s2.error != Some(rejected) || s2.samples != 1 {
        return TestResult::Fail("rejection must retain the sample and the count");
    }
    // Next success: error cleared, count bumped.
    let s3 = update(Some(s2), Ok(sample));
    if s3.metrics != Some(sample) || s3.error.is_some() || s3.samples != 2 {
        return TestResult::Fail("a later success must clear the error and bump the count");
    }
    // The snapshot's edge accessor reads the retained sample; an empty
    // snapshot reports nothing rather than a fabricated zero.
    if s3.edge_temperature_milli_c() != Some(52350) {
        return TestResult::Fail("snapshot edge must be 52350 mC");
    }
    if s0.edge_temperature_milli_c().is_some() {
        return TestResult::Fail("an empty snapshot must report no edge temperature");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_update_fold_retains_across_rejection
);

fn apu_monitor_publishes_first_refresh_then_exits_on_epoch_change() -> TestResult {
    let mut smu = MockSmu::new();
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    stage_ok(&mut smu, MP1_BASE);
    let mut buf = FakeBuffer::new(DMA_ADDR);
    buf.stage_dma_table(&v13_table());
    let mut owner = match ApuTelemetryOwner::new(SmuVersion::V13, MP1_BASE, buf) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("owner construction failed"),
    };
    if owner.publish_dram_addr(&mut smu).is_err() {
        return TestResult::Fail("publish_dram_addr failed");
    }
    let epoch = begin_epoch();
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = alloc::boxed::Box::pin(monitor(&mut owner, &mut smu, epoch));
    // First poll: refresh + publish, then Pending on the 1 s sleep.
    if !matches!(fut.as_mut().poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("monitor must pend on its first sleep after publishing");
    }
    let snap = match snapshot() {
        Some(s) => s,
        None => return TestResult::Fail("monitor must publish its first refresh"),
    };
    if snap.edge_temperature_milli_c() != Some(52350) {
        return TestResult::Fail("monitor must publish edge 52350 mC");
    }
    drop(fut); // dropping cancels the timer-wheel slot

    // A monitor whose epoch was superseded exits immediately.
    let stale_epoch = begin_epoch();
    stop();
    let mut fut2 = alloc::boxed::Box::pin(monitor(&mut owner, &mut smu, stale_epoch));
    if !matches!(fut2.as_mut().poll(&mut cx), Poll::Ready(())) {
        return TestResult::Fail("monitor must exit when its epoch is superseded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu_apu_telemetry",
    apu_monitor_publishes_first_refresh_then_exits_on_epoch_change
);
