//! Read-only dGPU telemetry sampled by the retained GT reset/power owner.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_hwmon.c::{xe_hwmon_get_reg,xe_hwmon_temp_read,xe_hwmon_get_voltage,
//! xe_hwmon_energy_get}, regs/{xe_mchbar_regs,xe_pcode_regs,xe_gt_regs}.h.
//! Sysfs reads use cached observations, never wake the GPU or touch MMIO.
//! Thermal limits, fan/power controls and BMG PMT energy remain separate.

use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform};

const INTERVAL_NS: u64 = 1_000_000_000;
const MAX_AGE_NS: u64 = 2_000_000_000;
const DG2_TEMP: u64 = 0x145978;
const BMG_TEMP: u64 = 0x138434;
const VRAM_TEMP: u64 = 0x1382c0;
const VRAM_CHANNEL: u64 = 0x138260;
const VOLTAGE: u64 = 0x1381b4;
const ENERGY_UNIT: u64 = 0x145938;
const ENERGY_STATUS: u64 = 0x14593c;
const TEMPERATURE_NAMES: [(&str, &str); 18] = [
    ("temp2_input", "temp2_label"),
    ("temp3_input", "temp3_label"),
    ("temp6_input", "temp6_label"),
    ("temp7_input", "temp7_label"),
    ("temp8_input", "temp8_label"),
    ("temp9_input", "temp9_label"),
    ("temp10_input", "temp10_label"),
    ("temp11_input", "temp11_label"),
    ("temp12_input", "temp12_label"),
    ("temp13_input", "temp13_label"),
    ("temp14_input", "temp14_label"),
    ("temp15_input", "temp15_label"),
    ("temp16_input", "temp16_label"),
    ("temp17_input", "temp17_label"),
    ("temp18_input", "temp18_label"),
    ("temp19_input", "temp19_label"),
    ("temp20_input", "temp20_label"),
    ("temp21_input", "temp21_label"),
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Reading {
    // pkg, aggregate VRAM, then the sixteen BMG memory channels.
    temperature: [Option<i64>; 18],
    voltage_mv: Option<u32>,
    energy_uj: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct Energy {
    raw: u32,
    accumulated: u64,
    shift: u8,
}
impl Energy {
    fn microjoules(&self) -> Option<u64> {
        u64::try_from((u128::from(self.accumulated) * 1_000_000) >> self.shift).ok()
    }
}

#[derive(Debug)]
struct State {
    epoch: u64,
    sampled: Option<u64>,
    reading: Option<Reading>,
    energy: Option<Energy>,
    energy_lost: bool,
}

/// One card's telemetry. An explicit ready epoch admits sampling; stale
/// observations cannot reopen admission after park, suspend or reset.
#[derive(Debug)]
pub(crate) struct Monitor {
    platform: GtPlatform,
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
}
impl Monitor {
    fn new(platform: GtPlatform) -> Option<Self> {
        if !matches!(platform, GtPlatform::Alchemist | GtPlatform::Battlemage) {
            return None;
        }
        Some(Self {
            platform,
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                sampled: None,
                reading: None,
                energy: None,
                energy_lost: false,
            }),
        })
    }

    pub(crate) fn register(index: u32, platform: GtPlatform) -> Option<Arc<Self>> {
        let monitor = Arc::new(Self::new(platform)?);
        monitor.publish(index);
        Some(monitor)
    }

    pub(crate) fn activate(&self, epoch: u64) {
        let mut state = self.state.lock();
        state.epoch = epoch;
        state.sampled = None;
        state.reading = None;
        state.energy = None;
        state.energy_lost = false;
        self.admission.store(epoch, Ordering::Release);
    }

    pub(crate) fn close(&self) {
        self.admission.store(0, Ordering::Release);
        let mut state = self.state.lock();
        state.epoch = 0;
        state.reading = None;
        state.sampled = None;
        state.energy = None;
        state.energy_lost = false;
    }

    /// The caller holds the GT reset/power mutex and checks current PCI D0
    /// and capability authority before *each* read. None stops this sample
    /// immediately. All-ones optional registers yield unavailable fields.
    /// At most 1 Hz and 18 (BMG) / 5 (DG2) reads; no write, wait or wake.
    pub(crate) fn sample_mmio(
        &self,
        epoch: u64,
        now: u64,
        mmio: &impl MmioWindow,
        mut current_access_ok: impl FnMut() -> bool,
    ) {
        self.sample(epoch, now, |offset| {
            // An unavailable optional sensor must not discard valid siblings.
            current_access_ok().then(|| mmio.read32(offset))
        });
    }

    fn sample(&self, epoch: u64, now: u64, mut read: impl FnMut(u64) -> Option<u32>) {
        let (previous, energy, energy_lost) = {
            let state = self.state.lock();
            if epoch == 0
                || state.epoch != epoch
                || self.admission.load(Ordering::Acquire) != epoch
                || state
                    .sampled
                    .is_some_and(|last| now >= last && now - last < INTERVAL_NS)
            {
                return;
            }
            (state.sampled, state.energy, state.energy_lost)
        };
        let mut authorized = |offset| {
            (self.admission.load(Ordering::Acquire) == epoch)
                .then(|| read(offset))
                .flatten()
        };
        let result = (|| {
            let mut reading = Reading::default();
            let package = if self.platform == GtPlatform::Alchemist {
                DG2_TEMP
            } else {
                BMG_TEMP
            };
            reading.temperature[0] = degrees(authorized(package)?);
            reading.temperature[1] = degrees(authorized(VRAM_TEMP)?);
            let mut next_energy = energy;
            let mut lost = energy_lost;
            if self.platform == GtPlatform::Battlemage {
                for (index, output) in reading.temperature[2..].iter_mut().enumerate() {
                    let value = authorized(VRAM_CHANNEL + index as u64 * 4)?;
                    if value != 0 && value != u32::MAX {
                        let magnitude = i64::from((value & 0x7fff_ff00) >> 8);
                        *output =
                            Some(magnitude * if value & (1 << 31) != 0 { -1000 } else { 1000 });
                    }
                }
            } else {
                let voltage = authorized(VOLTAGE)?;
                reading.voltage_mv =
                    (voltage != u32::MAX).then(|| ((voltage & 0x7ff) * 2500 + 500) / 1000);
                let units = authorized(ENERGY_UNIT)?;
                let raw = authorized(ENERGY_STATUS)?;
                let shift = ((units >> 8) & 0x1f) as u8;
                // Do not invent continuity over missed/unavailable samples,
                // changed units, or an unobserved reset. A new explicit GT
                // activation is required before energy accumulation resumes.
                lost |= units == u32::MAX
                    || raw == u32::MAX
                    || previous.is_some_and(|last| now < last || now - last > MAX_AGE_NS)
                    || energy.is_some_and(|old| old.shift != shift);
                if !lost {
                    let accumulated = match energy {
                        Some(old) => old
                            .accumulated
                            .checked_add(u64::from(raw.wrapping_sub(old.raw))),
                        None => Some(u64::from(raw)),
                    };
                    next_energy = accumulated.map(|accumulated| Energy {
                        raw,
                        accumulated,
                        shift,
                    });
                    reading.energy_uj = next_energy.and_then(|value| value.microjoules());
                    lost = reading.energy_uj.is_none();
                }
            }
            Some((reading, next_energy, lost))
        })();
        let mut state = self.state.lock();
        if state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        state.sampled = Some(now);
        match result {
            Some((reading, energy, lost)) => {
                state.reading = Some(reading);
                state.energy = energy;
                state.energy_lost = lost;
            }
            None => {
                state.reading = None;
                state.energy_lost = true;
            }
        }
    }

    fn reading(&self, now: u64) -> Option<Reading> {
        let state = self.state.lock();
        if state.epoch == 0
            || self.admission.load(Ordering::Acquire) != state.epoch
            || state
                .sampled
                .is_none_or(|at| now < at || now - at > MAX_AGE_NS)
        {
            return None;
        }
        state.reading
    }

    fn show(&self, attribute: &str, now: u64) -> String {
        if let Some((index, label)) = temperature_attribute(attribute) {
            if label {
                return match index {
                    0 => "pkg\n".into(),
                    1 => "vram\n".into(),
                    i if self.platform == GtPlatform::Battlemage => format!("vram_ch_{}\n", i - 2),
                    _ => String::new(),
                };
            }
            return self
                .reading(now)
                .and_then(|r| r.temperature[index])
                .map_or_else(String::new, |value| format!("{value}\n"));
        }
        match attribute {
            "in1_label" | "energy2_label" if self.platform == GtPlatform::Alchemist => {
                "pkg\n".into()
            }
            "in1_input" => self
                .reading(now)
                .and_then(|r| r.voltage_mv)
                .map_or_else(String::new, |value| format!("{value}\n")),
            "energy2_input" => self
                .reading(now)
                .and_then(|r| r.energy_uj)
                .map_or_else(String::new, |value| format!("{value}\n")),
            _ => String::new(),
        }
    }

    fn publish(self: &Arc<Self>, card: u32) {
        let class = class_register("hwmon");
        let existing = class.child_names();
        let index = (0u32..).find(|n| !existing.iter().any(|name| *name == format!("hwmon{n}")));
        let Some(index) = index else { return };
        let node = class_device_register(class, &format!("hwmon{index}"));
        kobject_add_attr(&node, "name", || "xe\n".into());
        node.add_symlink("device", format!("/sys/class/drm/card{card}/device"));
        narf_filesystem::sysfs::kobject_add_uevent_attr(&node, String::new());
        let count = if self.platform == GtPlatform::Battlemage {
            18
        } else {
            2
        };
        for &(input, label) in &TEMPERATURE_NAMES[..count] {
            for attribute in [input, label] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
        }
        if self.platform == GtPlatform::Alchemist {
            for attribute in ["in1_input", "in1_label", "energy2_input", "energy2_label"] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
        }
    }
}

fn degrees(value: u32) -> Option<i64> {
    (value != u32::MAX).then(|| i64::from(value & 0xff) * 1000)
}
fn temperature_attribute(name: &str) -> Option<(usize, bool)> {
    let (number, suffix) = name.strip_prefix("temp")?.split_once('_')?;
    let number: usize = number.parse().ok()?;
    let index = match number {
        2 => 0,
        3 => 1,
        6..=21 => number - 4,
        _ => return None,
    };
    Some((
        index,
        match suffix {
            "input" => false,
            "label" => true,
            _ => return None,
        },
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_hwmon_tests.rs"]
mod tests;
