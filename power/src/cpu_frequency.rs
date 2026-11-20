//! Read-only CPU frequency telemetry for `/proc/cpuinfo`.
//!
//! Like Linux `arch/x86/kernel/cpu/aperfmperf.c`, report the CPU reference
//! clock times delta APERF / delta MPERF: busy frequency, excluding
//! idle time. Governor requests and the invariant TSC alone are not current
//! CPU frequency. Pinned workers sample MSRs; proc readers only copy a cache.

use core::sync::atomic::{AtomicBool, Ordering};
use narf_arch::x86_64::{cpuid::cpuid, msr::rdmsr_or_gp, tsc};
use narf_lib::sync::{without_interrupts, IrqSafeSpinLock};

const MSR_MPERF: u32 = 0xe7;
const MSR_APERF: u32 = 0xe8;
const SAMPLE_MS: u64 = 100;
const MAX_SAMPLE_AGE_MS: u64 = 500;
static STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
struct Counters {
    aperf: u64,
    mperf: u64,
    at: u64,
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    khz: u64,
    at: u64,
}

static SAMPLES: [IrqSafeSpinLock<Option<Sample>>; narf_lib::percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; narf_lib::percpu::MAX_CPUS];

/// Latest measured busy frequency in kHz; unavailable before two samples,
/// after a counter reset/read failure, or after 500 ms without an update.
/// No MSR, remote call, allocation or wait occurs in the reader.
pub fn current_khz(cpu: u32) -> Option<u64> {
    if !narf_lib::smp::is_online(cpu) {
        return None;
    }
    let sample = *SAMPLES.get(cpu as usize)?.lock();
    fresh_khz(sample, narf_time::now_cycles(), tsc::frequency_hz())
}

fn fresh_khz(sample: Option<Sample>, now: u64, clock_hz: u64) -> Option<u64> {
    let sample = sample?;
    let age = now.checked_sub(sample.at)?;
    let max_age = clock_hz.checked_mul(MAX_SAMPLE_AGE_MS)? / 1000;
    (clock_hz != 0 && age <= max_age).then_some(sample.khz)
}

fn measured_khz(previous: Counters, current: Counters, reference_hz: u64) -> Option<Sample> {
    // A wrap/reset must reseed instead of looking like a huge boost. A real
    // 64-bit counter wrap takes many decades at normal CPU clock rates.
    let aperf = current.aperf.checked_sub(previous.aperf)?;
    let mperf = current.mperf.checked_sub(previous.mperf)?;
    if reference_hz == 0 || aperf == 0 || mperf == 0 || current.at <= previous.at {
        return None;
    }
    let khz = u64::try_from((reference_hz as u128 * aperf as u128) / mperf as u128 / 1000).ok()?;
    (khz != 0).then_some(Sample {
        khz,
        at: current.at,
    })
}

fn supported() -> bool {
    // SAFETY: CPUID leaf 0 is architectural; leaf 6 is guarded by its maximum.
    unsafe { cpuid(0, 0).0 >= 6 && cpuid(6, 0).2 & 1 != 0 }
}

fn reference_hz() -> Option<u64> {
    // Linux uses cpu_khz, not necessarily tsc_khz. Prefer the CPU's base
    // rate (CPUID 16h or AMD P0) independently of timer calibration.
    without_interrupts(|| {
        if let Some(hz) = tsc::__from_cpuid_16h() {
            return Some(hz);
        }
        let amd_p0 = tsc::calibrate_via_amd_pstate0();
        if amd_p0 != 0 {
            return Some(amd_p0);
        }
        // A calibrated invariant TSC is the fallback reference when no
        // separate base rate is exposed. A variable TSC is not a base rate.
        // SAFETY: extended maximum is architectural; leaf 7 is guarded.
        let invariant = unsafe {
            cpuid(0x8000_0000, 0).0 >= 0x8000_0007 && cpuid(0x8000_0007, 0).3 & (1 << 8) != 0
        };
        let hz = tsc::frequency_hz();
        (invariant && hz != 0).then_some(hz)
    })
}

fn read_counters(cpu: usize) -> Option<Counters> {
    // Keep the GP-recovery probe and both CPU-local counter reads together.
    // This region is bounded and does not hold a cache lock or await.
    without_interrupts(|| {
        if narf_lib::percpu::current_cpu() != cpu {
            return None;
        }
        Some(Counters {
            aperf: rdmsr_or_gp(MSR_APERF).ok()?,
            mperf: rdmsr_or_gp(MSR_MPERF).ok()?,
            at: narf_time::now_cycles(),
        })
    })
}

async fn worker(cpu: usize) {
    if !supported() {
        return;
    }
    let Some(reference_hz) = reference_hz() else {
        return;
    };
    let Some(mut previous) = read_counters(cpu) else {
        return;
    };
    loop {
        // Deferrable: Linux samples APERF/MPERF from the tick of a CPU that
        // runs (`arch_scale_freq_tick`), never waking an idle one for it.
        let expires = narf_time::timer::jiffies() + narf_time::timer::msecs_to_jiffies(SAMPLE_MS);
        narf_time::sleep_until_jiffies(expires, narf_time::timer::TIMER_DEFERRABLE).await;
        if !narf_lib::smp::is_online(cpu as u32) {
            *SAMPLES[cpu].lock() = None;
            return;
        }
        let Some(current) = read_counters(cpu) else {
            *SAMPLES[cpu].lock() = None;
            return;
        };
        let sample = measured_khz(previous, current, reference_hz);
        previous = current;
        *SAMPLES[cpu].lock() = sample;
    }
}

/// Install the proc reader and start read-only telemetry independently of
/// whether a writable HWP/CPPC governor backend was admitted.
pub fn start() {
    narf_filesystem::procfs::install_cpu_frequency_hook(current_khz);
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    for cpu in 0..narf_lib::percpu::MAX_CPUS {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let mut spec = narf_scheduler::TaskSpec::unthrottled();
        spec.affinity =
            narf_scheduler::Affinity::pinned(narf_scheduler::affinity::CpuId(cpu as u32));
        narf_scheduler::spawn_with_spec(worker(cpu), spec);
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_frequency_uses_busy_counter_deltas() -> TestResult {
        let previous = Counters {
            aperf: 100,
            mperf: 200,
            at: 1,
        };
        // A 4.7 GHz reference with boost at 120%, then a slower 50% sample.
        // Elapsed wall time differs; idle time must not dilute busy MHz.
        for (aperf, mperf, at, expected) in [
            (1200, 1000, 10, 5_640_000),
            (500, 1000, 1_000_000, 2_350_000),
            (1000, 1000, 20, 4_700_000),
        ] {
            let current = Counters {
                aperf: 100 + aperf,
                mperf: 200 + mperf,
                at,
            };
            if measured_khz(previous, current, 4_700_000_000).map(|s| s.khz) != Some(expected) {
                return TestResult::Fail(
                    "frequency used totals, wall time or requested performance",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("power/frequency", smoke_frequency_uses_busy_counter_deltas);

    fn smoke_frequency_rejects_invalid_and_stale_samples() -> TestResult {
        let previous = Counters {
            aperf: 100,
            mperf: 200,
            at: 10,
        };
        for current in [
            Counters {
                aperf: 100,
                mperf: 300,
                at: 20,
            },
            Counters {
                aperf: 200,
                mperf: 200,
                at: 20,
            },
            Counters {
                aperf: 99,
                mperf: 300,
                at: 20,
            },
            Counters {
                aperf: 200,
                mperf: 199,
                at: 20,
            },
            Counters {
                aperf: 200,
                mperf: 300,
                at: 10,
            },
        ] {
            if measured_khz(previous, current, 4_700_000_000).is_some() {
                return TestResult::Fail("invalid frequency sample accepted");
            }
        }
        let current = Counters {
            aperf: 200,
            mperf: 300,
            at: 20,
        };
        if measured_khz(previous, current, 0).is_some() {
            return TestResult::Fail("uncalibrated reference reported a frequency");
        }
        let sample = Some(Sample {
            khz: 5_640_000,
            at: 100,
        });
        if fresh_khz(sample, 600, 1000) != Some(5_640_000)
            || fresh_khz(sample, 601, 1000).is_some()
            || fresh_khz(sample, 99, 1000).is_some()
            || fresh_khz(sample, 100, 0).is_some()
            || fresh_khz(None, 100, 1000).is_some()
        {
            return TestResult::Fail("stale or absent frequency exposed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/frequency",
        smoke_frequency_rejects_invalid_and_stale_samples
    );
}
