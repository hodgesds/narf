//! Cached dGPU telemetry and bounded DG2/BMG power requests, serviced by the
//! retained GT reset/power owner.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_hwmon.c::{xe_hwmon_get_reg,xe_hwmon_temp_read,xe_hwmon_get_voltage,
//! xe_hwmon_energy_get}, regs/{xe_mchbar_regs,xe_pcode_regs,xe_gt_regs}.h.
//! Sysfs reads use cached observations, never wake the GPU or touch MMIO.
//! BMG PMT energy uses this same owner's bounded BAR0/remapper transaction.

use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform};

#[path = "intel_gpu_hwmon_bmg_power.rs"]
mod bmg_power;
#[path = "intel_gpu_hwmon_i1.rs"]
mod i1;
#[path = "intel_gpu_hwmon_interval.rs"]
mod interval;
#[path = "intel_gpu_hwmon_pcode.rs"]
mod pcode;
#[path = "intel_gpu_hwmon_pmt.rs"]
mod pmt;
#[path = "intel_gpu_hwmon_power.rs"]
mod power;

trait Io {
    fn read(&mut self, offset: u64) -> Option<u32>;
    fn write(&mut self, offset: u64, value: u32) -> bool;
}

struct LiveIo<'a, M, F> {
    monitor: &'a Monitor,
    epoch: u64,
    mmio: &'a M,
    current: F,
    lost: bool,
}
impl<M, F: FnMut() -> bool> LiveIo<'_, M, F> {
    fn allowed(&mut self) -> bool {
        if !self.lost {
            self.lost =
                self.monitor.admission.load(Ordering::Acquire) != self.epoch || !(self.current)();
        }
        !self.lost
    }
}
impl<M: MmioWindow, F: FnMut() -> bool> Io for LiveIo<'_, M, F> {
    fn read(&mut self, offset: u64) -> Option<u32> {
        self.allowed().then(|| self.mmio.read32(offset))
    }
    fn write(&mut self, offset: u64, value: u32) -> bool {
        if !self.allowed() {
            return false;
        }
        self.mmio.write32(offset, value);
        true
    }
}

const INTERVAL_NS: u64 = 1_000_000_000;
const MAX_AGE_NS: u64 = 2_000_000_000;
const DG2_TEMP: u64 = 0x145978;
const BMG_TEMP: u64 = 0x138434;
const VRAM_TEMP: u64 = 0x1382c0;
const VRAM_CHANNEL: u64 = 0x138260;
const VOLTAGE: u64 = 0x1381b4;
const ENERGY_UNIT: u64 = 0x145938;
const ENERGY_STATUS: u64 = 0x14593c;
const FAN: [u64; 3] = [0x138140, 0x138170, 0x1381a0];
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

#[derive(Clone, Copy, Debug)]
struct Fan {
    raw: u32,
    at: u64,
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
    pmt: pmt::Energy,
    pmt_sampled: Option<u64>,
    pmt_reading: Option<[u64; 2]>,
    discovery: pcode::Discovery,
    mailbox: pcode::Mailbox,
    control_owner: Option<pcode::Client>,
    control_next: pcode::Client,
    fan_sampled: Option<u64>,
    fans: [Option<Fan>; 3],
    fan_rpm: [Option<u64>; 3],
}

/// One card's telemetry. An explicit ready epoch admits sampling; stale
/// observations cannot reopen admission after park, suspend or reset.
#[derive(Debug)]
pub(crate) struct Monitor {
    platform: GtPlatform,
    bar_len: u64,
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
    power: power::Power,
    bmg_power: bmg_power::Power,
    card_power: bmg_power::Power,
    i1: i1::I1,
}
impl Monitor {
    fn new(platform: GtPlatform, bar_len: u64) -> Option<Self> {
        if !matches!(platform, GtPlatform::Alchemist | GtPlatform::Battlemage) {
            return None;
        }
        Some(Self {
            platform,
            bar_len,
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                sampled: None,
                reading: None,
                energy: None,
                energy_lost: false,
                pmt: pmt::Energy::default(),
                pmt_sampled: None,
                pmt_reading: None,
                discovery: pcode::Discovery::default(),
                mailbox: pcode::Mailbox::default(),
                control_owner: None,
                control_next: pcode::Client::Power,
                fan_sampled: None,
                fans: [None; 3],
                fan_rpm: [None; 3],
            }),
            power: power::Power::new(),
            bmg_power: bmg_power::Power::new(),
            card_power: bmg_power::Power::card(),
            i1: i1::I1::new(),
        })
    }

    pub(crate) fn register(index: u32, platform: GtPlatform, bar_len: u64) -> Option<Arc<Self>> {
        let monitor = Arc::new(Self::new(platform, bar_len)?);
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
        state.pmt = pmt::Energy::default();
        state.pmt_sampled = None;
        state.pmt_reading = None;
        state.discovery = pcode::Discovery::default();
        state.mailbox = pcode::Mailbox::default();
        state.control_owner = None;
        state.control_next = pcode::Client::Power;
        state.fan_sampled = None;
        state.fans = [None; 3];
        state.fan_rpm = [None; 3];
        self.power.activate(epoch);
        self.bmg_power.activate(epoch);
        self.card_power.activate(epoch);
        self.i1.activate(epoch);
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
        state.pmt = pmt::Energy::default();
        state.pmt_sampled = None;
        state.pmt_reading = None;
        state.discovery = pcode::Discovery::default();
        state.mailbox = pcode::Mailbox::default();
        state.control_owner = None;
        state.control_next = pcode::Client::Power;
        state.fan_sampled = None;
        state.fans = [None; 3];
        state.fan_rpm = [None; 3];
        self.power.close();
        self.bmg_power.close();
        self.card_power.close();
        self.i1.close();
    }

    /// The caller holds the GT reset/power mutex and checks current PCI D0
    /// and capability authority before *each* operation. All-ones optional
    /// sensors remain unavailable. Sensors and power observations run at most
    /// 1 Hz; a queued DG2 control uses one bounded read/RMW/readback sequence.
    /// BMG discovery advances at most one mailbox step per service poll.
    /// No wait, PM wake, IRQ or sysfs-triggered MMIO is performed here.
    pub(crate) fn service_mmio(
        &self,
        epoch: u64,
        now: u64,
        mmio: &impl MmioWindow,
        current_access_ok: impl FnMut() -> bool,
    ) {
        if epoch == 0 || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        let mut io = LiveIo {
            monitor: self,
            epoch,
            mmio,
            current: current_access_ok,
            lost: false,
        };
        self.service(epoch, now, &mut io);
        if io.lost {
            // A different sub-sampler can observe authority/D0 loss between
            // the 1 Hz sensor ticks. Revoke all current observations even
            // when those samplers correctly skipped their rate-limited reads.
            // Optional all-ones registers do not set this denial latch.
            self.invalidate_observations(epoch);
        }
    }

    fn invalidate_observations(&self, epoch: u64) {
        let mut state = self.state.lock();
        if state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        state.reading = None;
        state.energy = None;
        state.energy_lost = true;
        state.pmt.invalidate();
        state.pmt_reading = None;
        state.fans = [None; 3];
        state.fan_rpm = [None; 3];
        // Preserve timestamps and discovery diagnostics, including a pending
        // mailbox's failed Access result. Lost fan/energy continuity must not
        // be reconstructed from cached samples when authority later returns.
        self.power.access_lost(epoch);
        if self.platform == GtPlatform::Battlemage {
            state.mailbox.access_lost();
            self.bmg_power.access_lost(epoch);
            self.card_power.access_lost(epoch);
            self.i1.access_lost(epoch);
        }
    }

    fn service(&self, epoch: u64, now: u64, io: &mut impl Io) {
        if epoch == 0 || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        if self.platform == GtPlatform::Alchemist {
            self.power.service(epoch, now, io);
        } else {
            let (mut discovery, mut mailbox, mut control_owner, mut control_next) = {
                let state = self.state.lock();
                (
                    state.discovery,
                    state.mailbox,
                    state.control_owner,
                    state.control_next,
                )
            };
            let next = if mailbox.available() {
                discovery.command().or_else(|| {
                    self.control_command(epoch, now, &mut control_owner, &mut control_next)
                })
            } else {
                None
            };
            if let Some((client, result)) = mailbox.step(next, now, io) {
                match client {
                    pcode::Client::Power => self.bmg_power.complete(epoch, now, result),
                    pcode::Client::CardPower => self.card_power.complete(epoch, now, result),
                    pcode::Client::I1 => self.i1.complete(epoch, now, result),
                    _ => discovery.complete(client, result),
                }
            }
            if let Some(fault) = mailbox.fault() {
                // A shared hardware port with ambiguous ownership cannot
                // accept requests or retain measurements for either actor.
                self.bmg_power.port_lost(epoch, fault);
                self.card_power.port_lost(epoch, fault);
                self.i1.port_lost(epoch, fault);
            }
            let mut state = self.state.lock();
            if state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch {
                return;
            }
            state.discovery = discovery;
            state.mailbox = mailbox;
            state.control_owner = control_owner;
            state.control_next = control_next;
        }
        self.sample(epoch, now, |offset| io.read(offset));
        self.sample_fans(epoch, now, io);
        if self.platform == GtPlatform::Battlemage {
            self.sample_pmt(epoch, now, io)
        }
    }

    fn control_command(
        &self,
        epoch: u64,
        now: u64,
        owner: &mut Option<pcode::Client>,
        next: &mut pcode::Client,
    ) -> Option<pcode::Command> {
        use pcode::Client;
        let successor = |client| match client {
            Client::Power => Client::I1,
            Client::I1 => Client::CardPower,
            _ => Client::Power,
        };
        let active = |client| match client {
            Client::Power => self.bmg_power.in_transaction(epoch),
            Client::I1 => self.i1.in_transaction(epoch),
            Client::CardPower => self.card_power.in_transaction(epoch),
            _ => false,
        };
        let command = |client| match client {
            Client::Power => self.bmg_power.command(epoch, now),
            Client::I1 => self.i1.command(epoch, now),
            Client::CardPower => self.card_power.command(epoch, now),
            _ => None,
        };
        // A read/write/verify sequence retains ownership. Once terminal, a
        // newly queued request from that same client cannot bypass the peer.
        if let Some(client) = *owner {
            if active(client) {
                return command(client);
            }
            *owner = None;
            *next = successor(client);
        }
        for client in [*next, successor(*next), successor(successor(*next))] {
            if let Some(command) = command(client) {
                if active(client) {
                    *owner = Some(client);
                } else {
                    // Passive reads consist of one transfer only.
                    *next = successor(client);
                }
                return Some(command);
            }
        }
        None
    }

    fn sample_pmt(&self, epoch: u64, now: u64, io: &mut impl Io) {
        let mut pmt = {
            let state = self.state.lock();
            if epoch == 0
                || state.epoch != epoch
                || self.admission.load(Ordering::Acquire) != epoch
                || state
                    .pmt_sampled
                    .is_some_and(|at| now >= at && now - at < INTERVAL_NS)
            {
                return;
            }
            state.pmt
        };
        let reading = pmt.sample(self.bar_len, now, io);
        let mut state = self.state.lock();
        if state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        state.pmt = pmt;
        state.pmt_reading = reading;
        state.pmt_sampled = Some(now);
    }

    fn sample_fans(&self, epoch: u64, now: u64, io: &mut impl Io) {
        let (mut fans, count) = {
            let state = self.state.lock();
            if state.epoch != epoch
                || self.admission.load(Ordering::Acquire) != epoch
                || state
                    .fan_sampled
                    .is_some_and(|at| now >= at && now - at < INTERVAL_NS)
            {
                return;
            }
            let count = if self.platform == GtPlatform::Alchemist {
                // xe_hwmon_pcode_read_fan_control explicitly uses two for DG2;
                // that firmware's reported count is known to be incorrect.
                2
            } else {
                usize::from(state.discovery.fans.unwrap_or(0))
            };
            (state.fans, count)
        };
        let mut rpm = [None; 3];
        let mut valid = true;
        for index in 0..count {
            let Some(raw) = io.read(FAN[index]) else {
                valid = false;
                break;
            };
            let previous = fans[index];
            fans[index] = (raw != u32::MAX).then_some(Fan { raw, at: now });
            if raw == u32::MAX {
                continue;
            }
            if let Some(previous) = previous {
                if now > previous.at && now - previous.at <= MAX_AGE_NS {
                    // Xe source: two cumulative PWM pulses per rotation,
                    // integer milliseconds and ceil(rotations*60000 / ms).
                    let elapsed_ms = (now - previous.at) / 1_000_000;
                    if elapsed_ms != 0 {
                        let rotations = u64::from(raw.wrapping_sub(previous.raw) / 2);
                        rpm[index] = Some((rotations * 60_000).div_ceil(elapsed_ms));
                    }
                }
            }
        }
        let mut state = self.state.lock();
        if state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch {
            return;
        }
        state.fan_sampled = Some(now);
        state.fans = if valid { fans } else { [None; 3] };
        state.fan_rpm = if valid { rpm } else { [None; 3] };
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
        if self.platform == GtPlatform::Battlemage && attribute == "power1_label" {
            return "card\n".into();
        }
        if self.platform == GtPlatform::Battlemage
            && (attribute.starts_with("power1_crit")
                || attribute.starts_with("curr2_")
                || attribute == "i1_status")
        {
            return self.i1.show(attribute, now);
        }
        if self.platform == GtPlatform::Battlemage && attribute.starts_with("power1_") {
            return self.card_power.show(attribute, now);
        }
        if self.platform == GtPlatform::Battlemage {
            let index = match attribute {
                "energy1_label" => return "card\n".into(),
                "energy2_label" => return "pkg\n".into(),
                "energy1_input" => Some(1),
                "energy2_input" => Some(0),
                _ => None,
            };
            if let Some(index) = index {
                let state = self.state.lock();
                if state.epoch == 0
                    || self.admission.load(Ordering::Acquire) != state.epoch
                    || state
                        .pmt_sampled
                        .is_none_or(|at| now < at || now - at > MAX_AGE_NS)
                {
                    return String::new();
                }
                return state
                    .pmt_reading
                    .map_or_else(String::new, |v| format!("{}\n", v[index]));
            }
        }
        if attribute.starts_with("power2_") {
            return if attribute == "power2_label" {
                "pkg\n".into()
            } else if self.platform == GtPlatform::Alchemist {
                self.power.show(attribute, now)
            } else {
                self.bmg_power.show(attribute, now)
            };
        }
        if let Some(index) = attribute
            .strip_prefix("fan")
            .and_then(|s| s.strip_suffix("_input"))
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&i| (1..=3).contains(&i))
        {
            let state = self.state.lock();
            if state.epoch == 0
                || self.admission.load(Ordering::Acquire) != state.epoch
                || state
                    .fan_sampled
                    .is_none_or(|at| now < at || now - at > MAX_AGE_NS)
            {
                return String::new();
            }
            return state.fan_rpm[index - 1].map_or_else(String::new, |rpm| format!("{rpm}\n"));
        }
        if self.platform == GtPlatform::Battlemage {
            let state = self.state.lock();
            let current = state.epoch != 0 && self.admission.load(Ordering::Acquire) == state.epoch;
            if attribute == "telemetry_status" {
                return if current {
                    state.discovery.status(&state.mailbox)
                } else {
                    "unavailable\n".into()
                };
            }
            if current
                && state.reading.is_some()
                && state
                    .sampled
                    .is_some_and(|at| now >= at && now - at <= MAX_AGE_NS)
            {
                if let Some(value) = state.discovery.limit(attribute) {
                    return format!("{value}\n");
                }
            }
        }
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
        } else {
            for attribute in [
                "energy1_input",
                "energy1_label",
                "energy2_input",
                "energy2_label",
            ] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
            for attribute in [
                "temp2_emergency",
                "temp2_crit",
                "temp2_max",
                "temp3_emergency",
                "temp3_crit",
                "telemetry_status",
            ] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
        }
        for attribute in [
            "power2_label",
            "power2_rated_max",
            "power2_max_default",
            "power2_max_min",
            "power2_max_max",
            "power2_max_status",
        ] {
            let monitor = self.clone();
            kobject_add_attr(&node, attribute, move || {
                monitor.show(attribute, narf_time::monotonic_ns())
            });
        }
        let show = self.clone();
        let store = self.clone();
        kobject_add_writable_attr(
            &node,
            "power2_max",
            move || show.show("power2_max", narf_time::monotonic_ns()),
            move |bytes| {
                if store.platform == GtPlatform::Alchemist {
                    store.power.store(bytes, narf_time::monotonic_ns())
                } else {
                    store.bmg_power.store(bytes, narf_time::monotonic_ns())
                }
            },
        );
        if self.platform == GtPlatform::Alchemist {
            for attribute in ["power2_max_interval_min", "power2_max_interval_max"] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
            let show = self.clone();
            let store = self.clone();
            kobject_add_writable_attr(
                &node,
                "power2_max_interval",
                move || show.show("power2_max_interval", narf_time::monotonic_ns()),
                move |bytes| store.power.store_interval(bytes, narf_time::monotonic_ns()),
            );
        } else {
            for attribute in [
                "power1_max_default",
                "power1_max_min",
                "power1_max_max",
                "power1_max_status",
                "power1_cap_default",
                "power1_cap_min",
                "power1_cap_max",
                "power1_cap_status",
                "power1_max_interval_min",
                "power1_max_interval_max",
                "power1_cap_interval_min",
                "power1_cap_interval_max",
            ] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
            for attribute in [
                "power1_max",
                "power1_cap",
                "power1_max_interval",
                "power1_cap_interval",
            ] {
                let show = self.clone();
                let store = self.clone();
                kobject_add_writable_attr(
                    &node,
                    attribute,
                    move || show.show(attribute, narf_time::monotonic_ns()),
                    move |bytes| {
                        store.card_power.store_attribute(
                            attribute,
                            bytes,
                            narf_time::monotonic_ns(),
                        )
                    },
                );
            }
            for attribute in [
                "power2_cap_default",
                "power2_cap_min",
                "power2_cap_max",
                "power2_cap_status",
                "power2_max_interval_min",
                "power2_max_interval_max",
                "power2_cap_interval_min",
                "power2_cap_interval_max",
            ] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
            for attribute in ["power2_cap", "power2_max_interval", "power2_cap_interval"] {
                let show = self.clone();
                let store = self.clone();
                kobject_add_writable_attr(
                    &node,
                    attribute,
                    move || show.show(attribute, narf_time::monotonic_ns()),
                    move |bytes| {
                        store
                            .bmg_power
                            .store_attribute(attribute, bytes, narf_time::monotonic_ns())
                    },
                );
            }
            for attribute in [
                "i1_status",
                "power1_label",
                "power1_crit_default",
                "power1_crit_min",
                "power1_crit_max",
                "curr2_label",
                "curr2_crit_default",
                "curr2_crit_min",
                "curr2_crit_max",
            ] {
                let monitor = self.clone();
                kobject_add_attr(&node, attribute, move || {
                    monitor.show(attribute, narf_time::monotonic_ns())
                });
            }
            for attribute in ["power1_crit", "curr2_crit"] {
                let show = self.clone();
                let store = self.clone();
                kobject_add_writable_attr(
                    &node,
                    attribute,
                    move || show.show(attribute, narf_time::monotonic_ns()),
                    move |bytes| store.i1.store(attribute, bytes, narf_time::monotonic_ns()),
                );
            }
        }
        for attribute in if self.platform == GtPlatform::Alchemist {
            &["fan1_input", "fan2_input"][..]
        } else {
            &["fan1_input", "fan2_input", "fan3_input"][..]
        } {
            let monitor = self.clone();
            kobject_add_attr(&node, attribute, move || {
                monitor.show(attribute, narf_time::monotonic_ns())
            });
        }
    }
}

fn decimal(bytes: &[u8]) -> Result<u64, narf_filesystem::FsError> {
    use narf_filesystem::FsError;
    if bytes.len() > 32 {
        return Err(FsError::InvalidData);
    }
    let text = core::str::from_utf8(bytes)
        .map_err(|_| FsError::InvalidData)?
        .trim();
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return Err(FsError::InvalidData);
    }
    text.parse().map_err(|_| FsError::InvalidData)
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_hwmon_control_tests.rs"]
mod control_tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_hwmon_pmt_tests.rs"]
mod pmt_tests;
