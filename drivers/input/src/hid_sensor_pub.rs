//! HID sensor publication — the consumption surface for decoded HID
//! sensor readings (issue #773).
//!
//! ## The gap this closes
//!
//! The decode half of HID sensors is complete: `hid_sensor` decodes
//! reports from every live transport (Intel ISH, AMD SFH, and — with
//! this lane — HID-over-I2C hubs), but the decoded `SensorEvent`s
//! dead-ended in the crate-private event ring, whose only consumers
//! were tests. Nothing a user could read — no sysfs node, no in-kernel
//! API — exposed a single accelerometer, gyroscope, or ambient-light
//! reading.
//!
//! This module is the ONE publication path all producers feed:
//!
//! - **Producers** (`intel_ish`, `amd_sfh`, the I2C-HID pump in
//!   `i2c_hid_bind`) call [`register_sensor`] when a sensor collection
//!   is probed and [`publish`] for every decoded, unit-rescaled
//!   reading.
//! - **Userspace** reads `/sys/class/iio/iio:device<N>/` — an
//!   IIO-compatible layout (below).
//! - **In-kernel consumers** use [`sensors`] / [`latest`] /
//!   [`latest_of_kind`].
//! - The legacy `hid_sensor` event ring keeps being fed from
//!   [`publish`], so existing ring consumers are unaffected.
//!
//! ## Userspace layout (IIO-compatible)
//!
//! Linux exposes HID sensors through IIO (`drivers/iio/*/hid-sensor-*`):
//! one `iio:device<N>` per sensor with a `name` attribute and
//! per-channel `<channel>_raw` / `<channel>_scale` attributes, where
//! `SI value = raw × scale`. NARF's sysfs exposes classes under
//! `/sys/class/<class>/` (see the hwmon and backlight bridges), so the
//! devices live at `/sys/class/iio/iio:device<N>/` rather than Linux's
//! `/sys/bus/iio/devices/`; the device names, attribute names, and
//! scale semantics are the IIO ABI's
//! (`Documentation/ABI/testing/sysfs-bus-iio`). The class directory is
//! created lazily at the first registration: a machine with no sensor
//! hub has no `/sys/class/iio`, and no initcall is spent on it.
//!
//! Per-kind mapping (names and channel types from the Linux
//! `hid-sensor-*` IIO drivers; scales derived from the `SensorEvent`
//! unit contract in `hid_sensor`):
//!
//! | Kind            | `name`      | Channels (prefix)     | raw unit   | scale → SI unit        |
//! |-----------------|-------------|-----------------------|------------|------------------------|
//! | Accelerometer3D | `accel_3d`  | `in_accel_{x,y,z}`    | milli-g    | 0.00980665 → m/s²      |
//! | Gyrometer3D     | `gyro_3d`   | `in_anglvel_{x,y,z}`  | milli-dps  | π/180000 → rad/s       |
//! | Magnetometer3D  | `magn_3d`   | `in_magn_{x,y,z}`     | µT         | 0.01 → gauss           |
//! | AmbientLight    | `als`       | `in_illuminance`      | lux        | 1 → lux                |
//! | Proximity       | `prox`      | `in_proximity`        | mm         | 0.001 → m              |
//! | Inclinometer    | `incli_3d`  | `in_incli_{x,y,z}`    | milli-deg  | 0.001 → deg            |
//!
//! Gyro scale: 1 milli-dps = (π/180)/1000 rad/s =
//! 0.000017453292519943295 rad/s. Accel scale: 1 milli-g =
//! 9.80665/1000 m/s². Magnetometer: 1 µT = 0.01 gauss.
//!
//! A registered sensor that has not published yet shows its `name`
//! and `*_scale` attributes immediately (they exist from probe, as in
//! IIO), while its `*_raw` attributes read as the empty string until
//! the first reading lands — there is no fabricated zero sample.
//!
//! Deliberately not exposed: `sampling_frequency` (the report
//! interval stays on the transports' existing feature-report path in
//! `hid_sensor`), IIO buffered capture / triggers (no consumer yet),
//! and the proximity `present` flag (IIO proximity channels carry
//! distance only).
//!
//! ## Consumption split
//!
//! Policy consumers — screen rotation, adaptive brightness — are
//! userspace policy on Linux too (iio-sensor-proxy → compositor), and
//! they are here: they read this sysfs surface. What the kernel owes
//! them is exactly this publication layer plus the typed in-kernel
//! read API above for future kernel-side consumers; no in-kernel
//! rotation/brightness policy is implemented, by the same split.
//!
//! ## Sources
//!
//! - **HID Sensor Usages**, USB-IF, 2017 — sensor kinds and units.
//! - **HID Usage Tables 1.4**, USB-IF, §17 (Sensors page 0x20).
//! - Linux **IIO ABI**, `Documentation/ABI/testing/sysfs-bus-iio`;
//!   `drivers/iio/accel/hid-sensor-accel-3d.c`,
//!   `drivers/iio/gyro/hid-sensor-gyro-3d.c`,
//!   `drivers/iio/magnetometer/hid-sensor-magn-3d.c`,
//!   `drivers/iio/light/hid-sensor-als.c`,
//!   `drivers/iio/proximity/hid-sensor-prox.c`,
//!   `drivers/iio/orientation/hid-sensor-incl-3d.c` — device names,
//!   channel types, and scale conventions.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid_sensor::{self, HidSensorKind, SensorEvent};

/// Which transport produced a published sensor.
///
/// Part of a sensor's registry identity: the same kind arriving over
/// two transports (a convertible's ISH accelerometer vs. an SFH one)
/// is two published devices, never an alias.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SensorSource {
    /// HID-over-I2C sensor hub (the `i2c_hid_bind` pump).
    I2cHid,
    /// Intel Integrated Sensor Hub (`intel_ish`).
    IntelIsh,
    /// AMD Sensor Fusion Hub / MP2 (`amd_sfh`).
    AmdSfh,
}

impl SensorSource {
    /// Short stable tag for the source transport.
    pub fn as_str(&self) -> &'static str {
        match self {
            SensorSource::I2cHid => "i2c-hid",
            SensorSource::IntelIsh => "intel-ish",
            SensorSource::AmdSfh => "amd-sfh",
        }
    }
}

/// Registry index of a published sensor.
///
/// Assigned in registration (probe) order and never reused within a
/// boot; the sysfs node is `iio:device<id>`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SensorId(pub u32);

/// Static identity of one published sensor, for in-kernel consumers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SensorInfo {
    /// Registry id (and `iio:device<N>` index).
    pub id: SensorId,
    /// Producing transport.
    pub source: SensorSource,
    /// Producer-local device key (ISH HID device id, SFH sensor id,
    /// or the I2C-HID pump's per-device index).
    pub device_key: u32,
    /// Sensor kind.
    pub kind: HidSensorKind,
}

/// One registered sensor: identity plus its latest reading.
pub struct PublishedSensor {
    id: SensorId,
    source: SensorSource,
    device_key: u32,
    kind: HidSensorKind,
    latest: IrqSafeSpinLock<Option<SensorEvent>>,
}

impl fmt::Debug for PublishedSensor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedSensor")
            .field("id", &self.id)
            .field("source", &self.source)
            .field("device_key", &self.device_key)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl PublishedSensor {
    /// The sensor's registry identity.
    pub fn info(&self) -> SensorInfo {
        SensorInfo {
            id: self.id,
            source: self.source,
            device_key: self.device_key,
            kind: self.kind,
        }
    }

    /// The most recent published reading, if any.
    pub fn latest(&self) -> Option<SensorEvent> {
        *self.latest.lock()
    }

    fn store(&self, ev: SensorEvent) {
        *self.latest.lock() = Some(ev);
    }
}

/// All published sensors, in registration order.
static REGISTRY: IrqSafeSpinLock<Vec<Arc<PublishedSensor>>> = IrqSafeSpinLock::new(Vec::new());

/// The IIO `name` for a sensor kind (Linux `hid-sensor-*` `indio_dev->name`).
fn iio_name(kind: HidSensorKind) -> &'static str {
    match kind {
        HidSensorKind::Accelerometer3D => "accel_3d",
        HidSensorKind::Gyrometer3D => "gyro_3d",
        HidSensorKind::Magnetometer3D => "magn_3d",
        HidSensorKind::AmbientLight => "als",
        HidSensorKind::Proximity => "prox",
        HidSensorKind::Inclinometer => "incli_3d",
    }
}

/// The `*_scale` attribute name for a kind (one scale shared by all
/// of the kind's channels, per the IIO ABI).
fn iio_scale_attr(kind: HidSensorKind) -> &'static str {
    match kind {
        HidSensorKind::Accelerometer3D => "in_accel_scale",
        HidSensorKind::Gyrometer3D => "in_anglvel_scale",
        HidSensorKind::Magnetometer3D => "in_magn_scale",
        HidSensorKind::AmbientLight => "in_illuminance_scale",
        HidSensorKind::Proximity => "in_proximity_scale",
        HidSensorKind::Inclinometer => "in_incli_scale",
    }
}

/// The scale string for a kind: `SI value = raw × scale`, with the
/// raw unit fixed by the `SensorEvent` contract (see module docs).
fn iio_scale(kind: HidSensorKind) -> &'static str {
    match kind {
        // milli-g → m/s²: 9.80665 / 1000.
        HidSensorKind::Accelerometer3D => "0.00980665",
        // milli-dps → rad/s: (π/180) / 1000.
        HidSensorKind::Gyrometer3D => "0.000017453292519943295",
        // µT → gauss: 1 µT = 0.01 G.
        HidSensorKind::Magnetometer3D => "0.01",
        // lux → lux.
        HidSensorKind::AmbientLight => "1",
        // mm → m.
        HidSensorKind::Proximity => "0.001",
        // milli-deg → deg.
        HidSensorKind::Inclinometer => "0.001",
    }
}

/// The `*_raw` attribute names for a kind, in channel order
/// ([x, y, z] for 3-axis kinds, [value] for scalar kinds).
fn iio_channel_attrs(kind: HidSensorKind) -> &'static [&'static str] {
    match kind {
        HidSensorKind::Accelerometer3D => &["in_accel_x_raw", "in_accel_y_raw", "in_accel_z_raw"],
        HidSensorKind::Gyrometer3D => &["in_anglvel_x_raw", "in_anglvel_y_raw", "in_anglvel_z_raw"],
        HidSensorKind::Magnetometer3D => &["in_magn_x_raw", "in_magn_y_raw", "in_magn_z_raw"],
        HidSensorKind::AmbientLight => &["in_illuminance_raw"],
        HidSensorKind::Proximity => &["in_proximity_raw"],
        HidSensorKind::Inclinometer => &["in_incli_x_raw", "in_incli_y_raw", "in_incli_z_raw"],
    }
}

/// Extract the channel values of an event as `[x, y, z]` (scalar
/// kinds use slot 0). `None` slots are channels the kind lacks.
fn event_channels(ev: &SensorEvent) -> [Option<i32>; 3] {
    match *ev {
        SensorEvent::Accel3d {
            x_milli_g,
            y_milli_g,
            z_milli_g,
            ..
        } => [Some(x_milli_g), Some(y_milli_g), Some(z_milli_g)],
        SensorEvent::Gyro3d {
            x_milli_dps,
            y_milli_dps,
            z_milli_dps,
            ..
        } => [Some(x_milli_dps), Some(y_milli_dps), Some(z_milli_dps)],
        SensorEvent::Magneto3d {
            x_micro_t,
            y_micro_t,
            z_micro_t,
            ..
        } => [Some(x_micro_t), Some(y_micro_t), Some(z_micro_t)],
        SensorEvent::Lux { lux, .. } => [Some(lux as i32), None, None],
        SensorEvent::Proximity { distance_mm, .. } => [Some(distance_mm as i32), None, None],
        SensorEvent::Inclination {
            x_milli_deg,
            y_milli_deg,
            z_milli_deg,
            ..
        } => [Some(x_milli_deg), Some(y_milli_deg), Some(z_milli_deg)],
        SensorEvent::FusedOrientation {
            yaw_milli_deg,
            pitch_milli_deg,
            roll_milli_deg,
            ..
        } => [
            Some(yaw_milli_deg),
            Some(pitch_milli_deg),
            Some(roll_milli_deg),
        ],
    }
}

/// The sensor kind an event belongs to, for the kind-match check in
/// [`publish`]. `FusedOrientation` is a computed product, not a
/// probed kind, and maps to `None`.
fn kind_of(ev: &SensorEvent) -> Option<HidSensorKind> {
    match ev {
        SensorEvent::Accel3d { .. } => Some(HidSensorKind::Accelerometer3D),
        SensorEvent::Gyro3d { .. } => Some(HidSensorKind::Gyrometer3D),
        SensorEvent::Magneto3d { .. } => Some(HidSensorKind::Magnetometer3D),
        SensorEvent::Lux { .. } => Some(HidSensorKind::AmbientLight),
        SensorEvent::Proximity { .. } => Some(HidSensorKind::Proximity),
        SensorEvent::Inclination { .. } => Some(HidSensorKind::Inclinometer),
        SensorEvent::FusedOrientation { .. } => None,
    }
}

/// Create the sysfs device for a freshly registered sensor:
/// `/sys/class/iio/iio:device<N>/` with its `name`, `*_scale`, and
/// `*_raw` attributes. The raw attributes read the sensor's live
/// latest-reading cell, so no republication step exists.
fn populate_sysfs(sensor: &Arc<PublishedSensor>) {
    let class = class_register("iio");
    let node_name = format!("iio:device{}", sensor.id.0);
    let kobj = class_device_register(class, &node_name);

    let name = iio_name(sensor.kind);
    kobject_add_attr(&kobj, "name", move || format!("{name}\n"));

    let scale = iio_scale(sensor.kind);
    kobject_add_attr(&kobj, iio_scale_attr(sensor.kind), move || {
        format!("{scale}\n")
    });

    for (axis, attr) in iio_channel_attrs(sensor.kind).iter().enumerate() {
        let s = sensor.clone();
        kobject_add_attr(&kobj, attr, move || match s.latest() {
            Some(ev) => match event_channels(&ev)[axis] {
                Some(v) => format!("{v}\n"),
                None => String::new(),
            },
            None => String::new(),
        });
    }
}

/// Find a registered sensor by identity, if any.
fn lookup(
    source: SensorSource,
    device_key: u32,
    kind: HidSensorKind,
) -> Option<Arc<PublishedSensor>> {
    REGISTRY
        .lock()
        .iter()
        .find(|s| s.source == source && s.device_key == device_key && s.kind == kind)
        .cloned()
}

/// Find the sensor for `(source, device_key, kind)`, registering it
/// (and creating its sysfs device) if this is its first appearance.
fn lookup_or_register(
    source: SensorSource,
    device_key: u32,
    kind: HidSensorKind,
) -> Arc<PublishedSensor> {
    if let Some(existing) = lookup(source, device_key, kind) {
        return existing;
    }
    let mut reg = REGISTRY.lock();
    // Re-check under the lock: a concurrent probe of the same sensor
    // must not mint a second device.
    if let Some(existing) = reg
        .iter()
        .find(|s| s.source == source && s.device_key == device_key && s.kind == kind)
    {
        return existing.clone();
    }
    let sensor = Arc::new(PublishedSensor {
        id: SensorId(reg.len() as u32),
        source,
        device_key,
        kind,
        latest: IrqSafeSpinLock::new(None),
    });
    populate_sysfs(&sensor);
    reg.push(sensor.clone());
    sensor
}

/// Register a probed sensor collection for publication and create
/// its sysfs device. Called by each transport at probe/enumeration
/// time. Idempotent on `(source, device_key, kind)`: re-probing a
/// transport (hub session rebuild, rediscovery) returns the existing
/// id and keeps the existing sysfs device and latest reading.
pub fn register_sensor(source: SensorSource, device_key: u32, kind: HidSensorKind) -> SensorId {
    lookup_or_register(source, device_key, kind).id
}

/// Publish one decoded, unit-rescaled reading.
///
/// Updates the sensor's latest-reading cell (and therefore its sysfs
/// `*_raw` attributes) and feeds the legacy `hid_sensor` event ring,
/// returning the ring's result (`false` when the ring is full or
/// uninitialised), exactly as a direct `push_sensor_event` would.
///
/// The sensor is registered lazily if the producer publishes without
/// having registered at probe time, so no reading is ever dropped for
/// want of a registration call. A reading whose event variant does
/// not match the registered kind still reaches the ring but does not
/// touch the published cell — a producer bug must not smear one
/// kind's values across another kind's channels.
pub fn publish(
    source: SensorSource,
    device_key: u32,
    kind: HidSensorKind,
    ev: SensorEvent,
) -> bool {
    let sensor = lookup_or_register(source, device_key, kind);
    if kind_of(&ev) == Some(kind) {
        sensor.store(ev);
    }
    hid_sensor::push_sensor_event(ev)
}

/// All published sensors' identities, in registration order.
/// Empty on a machine with no sensor hub — the no-producer case.
pub fn sensors() -> Vec<SensorInfo> {
    REGISTRY.lock().iter().map(|s| s.info()).collect()
}

/// The latest reading published for `id`, if it has published yet.
pub fn latest(id: SensorId) -> Option<SensorEvent> {
    REGISTRY
        .lock()
        .iter()
        .find(|s| s.id == id)
        .and_then(|s| s.latest())
}

/// The latest reading of a kind across all producers, with the
/// sensor it came from. `None` when no sensor of that kind is
/// registered or none has published yet.
pub fn latest_of_kind(kind: HidSensorKind) -> Option<(SensorId, SensorEvent)> {
    REGISTRY
        .lock()
        .iter()
        .filter(|s| s.kind == kind)
        .find_map(|s| s.latest().map(|ev| (s.id, ev)))
}

/// Test-only: drop every registration. Pair with
/// `narf_filesystem::sysfs::__reset_for_test` — the sysfs devices
/// created for the dropped sensors belong to the old tree.
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}

// ── Tests ────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn reset_all() {
        __reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        hid_sensor::init_sensor_ring();
        hid_sensor::__reset_sensor_ring_for_test();
    }

    fn device_kobj(id: SensorId) -> Option<Arc<narf_filesystem::sysfs::Kobject>> {
        let class = class_register("iio");
        class.get_child(&alloc::format!("iio:device{}", id.0))
    }

    fn show(id: SensorId, attr: &str) -> Option<String> {
        device_kobj(id).and_then(|k| k.attr_show(attr))
    }

    // Round trip for every kind: register → publish → the kernel API
    // and the sysfs device both report the reading, with the IIO
    // name/scale pinned per kind.
    /// (kind, event, IIO name, scale, expected sysfs attrs).
    type RoundTripCase = (
        HidSensorKind,
        SensorEvent,
        &'static str,
        &'static str,
        &'static [(&'static str, &'static str)],
    );

    fn smoke_sensor_pub_round_trip_all_kinds() -> TestResult {
        reset_all();
        let cases: [RoundTripCase; 6] = [
            (
                HidSensorKind::Accelerometer3D,
                SensorEvent::Accel3d {
                    x_milli_g: 123,
                    y_milli_g: -456,
                    z_milli_g: 1000,
                    timestamp_ns: 10,
                },
                "accel_3d",
                "0.00980665",
                &[
                    ("in_accel_x_raw", "123\n"),
                    ("in_accel_y_raw", "-456\n"),
                    ("in_accel_z_raw", "1000\n"),
                ],
            ),
            (
                HidSensorKind::Gyrometer3D,
                SensorEvent::Gyro3d {
                    x_milli_dps: 1000,
                    y_milli_dps: -2000,
                    z_milli_dps: 45000,
                    timestamp_ns: 11,
                },
                "gyro_3d",
                "0.000017453292519943295",
                &[
                    ("in_anglvel_x_raw", "1000\n"),
                    ("in_anglvel_y_raw", "-2000\n"),
                    ("in_anglvel_z_raw", "45000\n"),
                ],
            ),
            (
                HidSensorKind::Magnetometer3D,
                SensorEvent::Magneto3d {
                    x_micro_t: 100,
                    y_micro_t: -200,
                    z_micro_t: 300,
                    timestamp_ns: 12,
                },
                "magn_3d",
                "0.01",
                &[
                    ("in_magn_x_raw", "100\n"),
                    ("in_magn_y_raw", "-200\n"),
                    ("in_magn_z_raw", "300\n"),
                ],
            ),
            (
                HidSensorKind::AmbientLight,
                SensorEvent::Lux {
                    lux: 250,
                    timestamp_ns: 13,
                },
                "als",
                "1",
                &[("in_illuminance_raw", "250\n")],
            ),
            (
                HidSensorKind::Proximity,
                SensorEvent::Proximity {
                    distance_mm: 42,
                    present: true,
                    timestamp_ns: 14,
                },
                "prox",
                "0.001",
                &[("in_proximity_raw", "42\n")],
            ),
            (
                HidSensorKind::Inclinometer,
                SensorEvent::Inclination {
                    x_milli_deg: 1000,
                    y_milli_deg: -2000,
                    z_milli_deg: 3000,
                    timestamp_ns: 15,
                },
                "incli_3d",
                "0.001",
                &[
                    ("in_incli_x_raw", "1000\n"),
                    ("in_incli_y_raw", "-2000\n"),
                    ("in_incli_z_raw", "3000\n"),
                ],
            ),
        ];
        for (i, (kind, ev, name, scale, raws)) in cases.iter().enumerate() {
            let id = register_sensor(SensorSource::I2cHid, 100 + i as u32, *kind);
            if show(id, "name").as_deref() != Some(alloc::format!("{name}\n").as_str()) {
                return TestResult::Fail("IIO name attr wrong");
            }
            if show(id, iio_scale_attr(*kind)).as_deref()
                != Some(alloc::format!("{scale}\n").as_str())
            {
                return TestResult::Fail("IIO scale attr wrong");
            }
            if !publish(SensorSource::I2cHid, 100 + i as u32, *kind, *ev) {
                return TestResult::Fail("publish did not reach the ring");
            }
            if latest(id) != Some(*ev) {
                return TestResult::Fail("latest() lost the published reading");
            }
            if latest_of_kind(*kind) != Some((id, *ev)) {
                return TestResult::Fail("latest_of_kind lost the published reading");
            }
            for (attr, want) in *raws {
                if show(id, attr).as_deref() != Some(*want) {
                    return TestResult::Fail("raw attr does not round-trip the reading");
                }
            }
            // The legacy ring still receives every published event.
            if hid_sensor::pop_sensor_event() != Some(*ev) {
                return TestResult::Fail("legacy ring lost the published event");
            }
        }
        if sensors().len() != 6 {
            return TestResult::Fail("registry should hold all six kinds");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_pub_round_trip_all_kinds);

    // Masking-defeating: two kinds on one hub device and the same
    // kind on two transports, published interleaved, must never
    // alias — each device keeps exactly its own channels and values.
    fn smoke_sensor_pub_no_aliasing() -> TestResult {
        reset_all();
        let ish_accel = register_sensor(SensorSource::IntelIsh, 1, HidSensorKind::Accelerometer3D);
        let ish_gyro = register_sensor(SensorSource::IntelIsh, 1, HidSensorKind::Gyrometer3D);
        let sfh_accel = register_sensor(SensorSource::AmdSfh, 3, HidSensorKind::Accelerometer3D);
        if ish_accel == ish_gyro || ish_accel == sfh_accel || ish_gyro == sfh_accel {
            return TestResult::Fail("distinct sensors minted the same id");
        }
        let a1 = SensorEvent::Accel3d {
            x_milli_g: 0,
            y_milli_g: 0,
            z_milli_g: 1000,
            timestamp_ns: 1,
        };
        let g1 = SensorEvent::Gyro3d {
            x_milli_dps: 0,
            y_milli_dps: 0,
            z_milli_dps: 45000,
            timestamp_ns: 2,
        };
        let a2 = SensorEvent::Accel3d {
            x_milli_g: -1000,
            y_milli_g: 0,
            z_milli_g: 0,
            timestamp_ns: 3,
        };
        publish(
            SensorSource::IntelIsh,
            1,
            HidSensorKind::Accelerometer3D,
            a1,
        );
        publish(SensorSource::IntelIsh, 1, HidSensorKind::Gyrometer3D, g1);
        publish(SensorSource::AmdSfh, 3, HidSensorKind::Accelerometer3D, a2);
        if latest(ish_accel) != Some(a1)
            || latest(ish_gyro) != Some(g1)
            || latest(sfh_accel) != Some(a2)
        {
            return TestResult::Fail("readings aliased across sensors");
        }
        if show(ish_accel, "in_accel_z_raw").as_deref() != Some("1000\n")
            || show(sfh_accel, "in_accel_x_raw").as_deref() != Some("-1000\n")
            || show(ish_gyro, "in_anglvel_z_raw").as_deref() != Some("45000\n")
        {
            return TestResult::Fail("sysfs readings aliased across sensors");
        }
        // Channel sets are per-kind: the gyro device has no accel
        // channels and the accel device has no gyro channels.
        if show(ish_gyro, "in_accel_x_raw").is_some()
            || show(ish_accel, "in_anglvel_x_raw").is_some()
        {
            return TestResult::Fail("channel sets leaked across kinds");
        }
        // Republishing one sensor leaves the others untouched.
        let a1b = SensorEvent::Accel3d {
            x_milli_g: 500,
            y_milli_g: 0,
            z_milli_g: 0,
            timestamp_ns: 4,
        };
        publish(
            SensorSource::IntelIsh,
            1,
            HidSensorKind::Accelerometer3D,
            a1b,
        );
        if latest(ish_accel) != Some(a1b)
            || latest(ish_gyro) != Some(g1)
            || latest(sfh_accel) != Some(a2)
        {
            return TestResult::Fail("republish disturbed a sibling sensor");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_pub_no_aliasing);

    // Absence cases: no producer at all, a producer that has not
    // published yet, and publishing with no consumer anywhere.
    fn smoke_sensor_pub_absence_cases() -> TestResult {
        reset_all();
        // No producer: registry empty, lookups miss cleanly.
        if !sensors().is_empty() {
            return TestResult::Fail("registry not empty after reset");
        }
        if latest_of_kind(HidSensorKind::Accelerometer3D).is_some() {
            return TestResult::Fail("phantom reading with no producer");
        }
        if latest(SensorId(0)).is_some() {
            return TestResult::Fail("phantom reading for unknown id");
        }
        // Registered but never published: identity + scale are live,
        // raw reads as empty (no fabricated zero sample).
        let id = register_sensor(SensorSource::AmdSfh, 9, HidSensorKind::AmbientLight);
        if show(id, "name").as_deref() != Some("als\n") {
            return TestResult::Fail("unpublished sensor lost its name attr");
        }
        if show(id, "in_illuminance_scale").as_deref() != Some("1\n") {
            return TestResult::Fail("unpublished sensor lost its scale attr");
        }
        if show(id, "in_illuminance_raw").as_deref() != Some("") {
            return TestResult::Fail("unpublished sensor fabricated a sample");
        }
        if latest(id).is_some() {
            return TestResult::Fail("unpublished sensor has a latest reading");
        }
        // No consumer: nobody pops the ring or reads an attribute;
        // publishing still records the reading for a later consumer.
        let ev = SensorEvent::Lux {
            lux: 77,
            timestamp_ns: 5,
        };
        publish(SensorSource::AmdSfh, 9, HidSensorKind::AmbientLight, ev);
        publish(SensorSource::AmdSfh, 9, HidSensorKind::AmbientLight, ev);
        if latest(id) != Some(ev) {
            return TestResult::Fail("consumer-less publish lost the reading");
        }
        // A kind-mismatched publish reaches the ring but must not
        // overwrite the published cell.
        let wrong = SensorEvent::Accel3d {
            x_milli_g: 1,
            y_milli_g: 2,
            z_milli_g: 3,
            timestamp_ns: 6,
        };
        publish(SensorSource::AmdSfh, 9, HidSensorKind::AmbientLight, wrong);
        if latest(id) != Some(ev) {
            return TestResult::Fail("kind-mismatched publish smeared the cell");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_sensor_pub_absence_cases);
}
