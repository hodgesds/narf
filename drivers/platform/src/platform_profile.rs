// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform-profile userspace surface.
//!
//! Before this module, HP's `set_thermal_profile` and the IdeaPad
//! VPC performance-mode store were in-kernel functions with no
//! userspace reachability: nothing exposed a profile choice and
//! nothing read the active profile back. This module is the
//! vendor-neutral surface those drivers register into.
//!
//! ## Userspace surface (Linux platform-profile ABI)
//!
//! - `/sys/firmware/acpi/platform_profile` (rw): the active
//!   profile name; storing a name from the choices list selects it.
//! - `/sys/firmware/acpi/platform_profile_choices` (ro):
//!   space-separated list of profiles the active backend offers.
//!
//! Reference: `Documentation/ABI/testing/sysfs-platform_profile`,
//! `drivers/platform/x86/platform_profile.c` (GPL-2.0-or-later).
//! Profile names are the canonical strings of
//! `include/linux/platform_profile.h` (`enum platform_profile_option`).
//!
//! ## Backends
//!
//! Exactly one backend is active at a time (Linux registers one
//! `platform_profile_handler` per machine in practice): the first
//! vendor driver to register wins. A backend supplies its choice
//! list plus get/set callbacks. `get` must read the firmware state
//! where the vendor interface offers a read (IdeaPad VPC read, HP
//! BIOS query); backends whose interface is write-only (ASUS
//! DEVID_THERMAL_CTRL) return their last-set value, and say so at
//! their registration site.
//!
//! The HP Fn-P hotkey cycles the profile ([`cycle`]), which is
//! what `hp-wmi.c::HPWMI_FN_P_HOTKEY` drives through the same ABI.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Profile values ────────────────────────────────────────────────────

/// A platform profile, in the canonical Linux ordering.
/// Reference: `include/linux/platform_profile.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlatformProfile {
    LowPower,
    Cool,
    Quiet,
    Balanced,
    BalancedPerformance,
    Performance,
}

impl PlatformProfile {
    /// All profiles, in canonical order.
    pub const ALL: [PlatformProfile; 6] = [
        PlatformProfile::LowPower,
        PlatformProfile::Cool,
        PlatformProfile::Quiet,
        PlatformProfile::Balanced,
        PlatformProfile::BalancedPerformance,
        PlatformProfile::Performance,
    ];

    /// The canonical sysfs name.
    pub fn name(&self) -> &'static str {
        match self {
            PlatformProfile::LowPower => "low-power",
            PlatformProfile::Cool => "cool",
            PlatformProfile::Quiet => "quiet",
            PlatformProfile::Balanced => "balanced",
            PlatformProfile::BalancedPerformance => "balanced-performance",
            PlatformProfile::Performance => "performance",
        }
    }

    /// Parse a canonical sysfs name.
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.name() == s)
    }
}

// ── Backend registry ──────────────────────────────────────────────────

/// A vendor platform-profile backend.
#[derive(Debug)]
pub struct ProfileBackend {
    /// Backend name (the Linux handler name, e.g. `"hp-wmi"`).
    pub name: &'static str,
    /// Profiles this backend offers, in canonical order.
    pub choices: &'static [PlatformProfile],
    /// Read the active profile back. Backends with a firmware read
    /// path must use it; write-only backends return last-set.
    pub get: fn() -> Option<PlatformProfile>,
    /// Select a profile. Returns true when the firmware call was
    /// issued without error.
    pub set: fn(PlatformProfile) -> bool,
}

static BACKEND: IrqSafeSpinLock<Option<ProfileBackend>> = IrqSafeSpinLock::new(None);
static SYSFS_PUBLISHED: AtomicBool = AtomicBool::new(false);

/// Register the active platform-profile backend. The first
/// registration wins (one profile device per machine); later
/// registrations return false and change nothing.
pub fn register_backend(backend: ProfileBackend) -> bool {
    let mut slot = BACKEND.lock();
    if slot.is_some() {
        return false;
    }
    *slot = Some(backend);
    drop(slot);
    if SYSFS_PUBLISHED.load(Ordering::Acquire) {
        publish_sysfs();
    }
    true
}

/// Name of the active backend, if any.
pub fn active_backend_name() -> Option<&'static str> {
    BACKEND.lock().as_ref().map(|b| b.name)
}

/// The active backend's choice list (empty when no backend).
pub fn choices() -> Vec<PlatformProfile> {
    BACKEND
        .lock()
        .as_ref()
        .map(|b| b.choices.to_vec())
        .unwrap_or_default()
}

/// Read the active profile through the backend's get path.
pub fn current() -> Option<PlatformProfile> {
    let get = BACKEND.lock().as_ref().map(|b| b.get)?;
    get()
}

/// Select a profile. Fails (returns false) when no backend is
/// registered, the profile is not in the backend's choice list, or
/// the backend's firmware call fails.
pub fn set(profile: PlatformProfile) -> bool {
    let set_fn = {
        let slot = BACKEND.lock();
        match slot.as_ref() {
            Some(b) if b.choices.contains(&profile) => b.set,
            _ => return false,
        }
    };
    set_fn(profile)
}

/// Advance to the next profile in the backend's choice list,
/// wrapping at the end. Drives the HP Fn-P hotkey. Returns the
/// newly selected profile, or `None` when no backend is active or
/// the current profile cannot be determined.
pub fn cycle() -> Option<PlatformProfile> {
    let choices = choices();
    if choices.is_empty() {
        return None;
    }
    let cur = current()?;
    let idx = choices.iter().position(|c| *c == cur).unwrap_or(0);
    let next = choices[(idx + 1) % choices.len()];
    if set(next) {
        Some(next)
    } else {
        None
    }
}

// ── Sysfs publication ─────────────────────────────────────────────────

/// Publish `/sys/firmware/acpi/platform_profile{,_choices}` for
/// the active backend. Called from a Stage::Late initcall, after
/// vendor drivers (Stage::Subsys) have registered. No-op when no
/// backend is registered; a backend registering after this call
/// re-invokes publication itself.
pub fn publish_sysfs() {
    use narf_filesystem::sysfs::{
        get_or_create_child, get_root, kobject_add_attr, kobject_add_writable_attr,
    };
    use narf_filesystem::FsError;

    if BACKEND.lock().is_none() {
        return;
    }
    SYSFS_PUBLISHED.store(true, Ordering::Release);

    let root = get_root();
    let firmware = get_or_create_child(&root, "firmware");
    let acpi = get_or_create_child(&firmware, "acpi");

    kobject_add_attr(&acpi, "platform_profile_choices", || {
        let names: Vec<&str> = choices().iter().map(|p| p.name()).collect();
        alloc::format!("{}\n", names.join(" "))
    });
    kobject_add_writable_attr(
        &acpi,
        "platform_profile",
        || match current() {
            Some(p) => alloc::format!("{}\n", p.name()),
            None => String::from("\n"),
        },
        |buf| {
            let s = core::str::from_utf8(buf)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            let profile = PlatformProfile::from_name(s).ok_or(FsError::InvalidData)?;
            if set(profile) {
                Ok(())
            } else {
                Err(FsError::InvalidData)
            }
        },
    );
}

// ── Test helpers ────────────────────────────────────────────────────────

/// Reset the profile registry for tests.
#[doc(hidden)]
pub fn __test_reset() {
    *BACKEND.lock() = None;
    SYSFS_PUBLISHED.store(false, Ordering::Relaxed);
}
