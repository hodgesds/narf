//! Devicetree bindings for SPI controllers (DT programme step 5).
//!
//! The PL022 and Cadence cores each register a `DtMatch`; on a
//! match the controller is constructed over an ioremap'd window
//! and registered into the crate's existing bus registry — the
//! same registry the AMD FCH / Intel LPSS drivers publish into,
//! so consumers see one registry story regardless of how the
//! controller was discovered.
//!
//! A bound controller's DT child devices (flash chips, sensors,
//! …) are published into the child registry below at probe time,
//! decoded from the retained DTB via `narf_bus::dt::children_of`
//! — the Linux spi-core shape, where child nodes on the
//! controller's bus node become devices on that bus. SPI-NOR
//! binding consumes the published children from step 6.
//!
//! Clock resolution (bus spec §3.1): the controller's input clock
//! is resolved at probe time by re-locating the node — its
//! `clocks` phandle chased to a fixed-clock node's
//! `clock-frequency`. When the node carries no usable `clocks`,
//! each driver falls back to a named constant, flagged at the
//! definition; the clock framework (#1052) replaces both paths.

use alloc::string::String;
use alloc::vec::Vec;

use narf_bus::PlatformDevice;
use narf_lib::sync::IrqSafeSpinLock;

/// One DT child device of a bound SPI controller.
#[derive(Clone, Debug)]
pub struct SpiChild {
    /// Registry name of the owning controller (`SpiBus::name()`).
    pub controller: String,
    /// Node name (`flash@0`).
    pub name: String,
    /// The child's raw `compatible` value (NUL-separated strings),
    /// exactly as decoded by `narf_bus::dt::DtChild`.
    pub compatible: Vec<u8>,
    /// Chip-select: the child's `reg` address in the controller's
    /// local space.
    pub cs: u32,
    /// `spi-max-frequency`, 0 when the node does not declare one.
    pub max_hz: u32,
}

static CHILDREN: IrqSafeSpinLock<Vec<SpiChild>> = IrqSafeSpinLock::new(Vec::new());

/// Publish one child (deduplicated on controller + chip-select).
pub fn publish_child(child: SpiChild) {
    let mut g = CHILDREN.lock();
    if !g
        .iter()
        .any(|c| c.controller == child.controller && c.cs == child.cs)
    {
        g.push(child);
    }
}

/// Snapshot of every published SPI child device.
pub fn published_children() -> Vec<SpiChild> {
    CHILDREN.lock().clone()
}

/// Test-only: drain the child registry.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_children_for_test() {
    CHILDREN.lock().clear();
}

/// Publish the DT children of the controller that owns `rec`
/// (registered under `bus_name`) into the child registry.
/// Returns how many children carried a chip-select `reg`.
/// No-ops when no DTB was retained (x86_64 / ACPI boots).
pub fn publish_children(rec: &PlatformDevice, bus_name: &str) -> usize {
    let Some(blob) = narf_bus::dt::dtb_blob() else {
        return 0;
    };
    let Some(win) = rec.reg_windows().first() else {
        return 0;
    };
    publish_children_from(blob, rec.first_compatible(), win.base.raw(), bus_name)
}

/// The blob-explicit core of [`publish_children`] (test seam).
pub fn publish_children_from(
    blob: &[u8],
    parent_first_compatible: &str,
    parent_base: u64,
    bus_name: &str,
) -> usize {
    let mut n = 0;
    for child in narf_bus::dt::children_of(blob, parent_first_compatible, parent_base) {
        let Some((cs, _)) = child.reg else {
            continue;
        };
        publish_child(SpiChild {
            controller: String::from(bus_name),
            name: child.name.clone(),
            compatible: child.compatible.clone(),
            cs: cs as u32,
            max_hz: child.prop_u32("spi-max-frequency").unwrap_or(0),
        });
        n += 1;
    }
    n
}

/// Resolve the controller's input clock from its DT node:
/// `clocks` phandle → fixed-clock `clock-frequency` (bus spec
/// §3.1 probe-time resolution). `None` when the node carries no
/// usable `clocks` — callers fall back to their named constant.
pub fn controller_clock_hz(rec: &PlatformDevice) -> Option<u32> {
    let blob = narf_bus::dt::dtb_blob()?;
    let win = rec.reg_windows().first()?;
    let clocks = narf_bus::dt::node_prop(blob, rec.first_compatible(), win.base.raw(), "clocks")?;
    if clocks.len() < 4 {
        return None;
    }
    let phandle = u32::from_be_bytes([clocks[0], clocks[1], clocks[2], clocks[3]]);
    narf_bus::dt::clock_frequency_of_phandle(blob, phandle)
}

/// Register the SPI crate's DT match entries with the bus match
/// table. Called from `register_initcalls` — composition-time
/// registration, census-neutral (bus registry state, not an
/// initcall).
pub fn register_dt_drivers() {
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: "pl022-dt",
        compatible: "arm,pl022",
        probe: crate::pl022::probe_dt,
    });
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: "cadence-spi-dt",
        compatible: "cdns,spi-r1p6",
        probe: crate::cadence::probe_dt,
    });
}
