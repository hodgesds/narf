//! Standalone Media GT (GT1) telemetry and sysfs attributes.
//!
//! Exposes GT1 telemetry for Meteor Lake and Arrow Lake under:
//! - `/sys/class/drm/card<N>/gt1/` (i915-style telemetry attributes):
//!   - `rps_cur_freq_mhz`: current operating / target frequency in MHz
//!   - `rps_act_freq_mhz`: actual measured operating frequency in MHz
//!   - `rc6_residency_ms`: media C6 (MC6) residency in milliseconds
//!   - `rc6p_residency_ms`: legacy RC6p residency (always 0)
//!   - `rc6pp_residency_ms`: legacy RC6pp residency (always 0)
//!   - `freq_factor_scale`: scaling multiplier ("1.00\n")
//!   - `throttle_reasons`: bitmask / string representation ("0\n")
//!   - `gt_min_freq_mhz`: minimum allowed frequency (RPn or range minimum)
//!   - `gt_max_freq_mhz`: maximum allowed frequency (RP0 or range maximum)
//!   - `gt_RP0_freq_mhz`: maximum dynamic frequency (RP0)
//!   - `gt_RP1_freq_mhz`: efficient / base frequency (RPe)
//!   - `gt_RPn_freq_mhz`: minimum hardware frequency (RPn)
//!   - `slpc_status`: "running", "disabled", or "unavailable"
//!   - `slpc_power_profile`: "base" or "power_saving"
//! - `/sys/class/drm/card<N>/device/tile0/gt1/` (Xe-style attributes):
//!   - `freq0/cur_freq`, `freq0/act_freq`, `freq0/min_freq`, `freq0/max_freq`
//!   - `freq0/rp0_freq`, `freq0/rpe_freq`, `freq0/rpn_freq`, `freq0/power_profile`
//!   - `gtidle/name`: "gt1-mc\n"
//!   - `gtidle/idle_residency_ms`: MC6 residency in ms
//!   - `gtidle/idle_status`: "gt-c6\n" or "gt-c0\n"
//!   - `gtidle/gt1-mc`: MC6 residency in ms
//!
//! When `narf.intel.media_gt=1` is absent or the media GT is unpublished,
//! queries return empty strings or "unavailable\n", matching Linux behavior.

use alloc::{format, string::String, sync::Arc};
use narf_filesystem::sysfs::{get_or_create_child, kobject_add_attr, Kobject};

use crate::intel_gpu_user::UserBackend;

/// Telemetry metrics snapshot for the standalone Media GT (GT1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaGtTelemetry {
    pub cur_freq_mhz: u32,
    pub act_freq_mhz: u32,
    pub rc6_residency_ms: u64,
    pub min_freq_mhz: u32,
    pub max_freq_mhz: u32,
    pub rp0_freq_mhz: u32,
    pub rpe_freq_mhz: u32,
    pub rpn_freq_mhz: u32,
    pub is_running: bool,
    pub power_profile: &'static str,
    pub idle_status: &'static str,
}

impl MediaGtTelemetry {
    /// Sample telemetry from a card's active `UserBackend`.
    pub fn from_backend(backend: &dyn UserBackend) -> Option<Self> {
        let media_gt = backend.media_gt()?;
        let slpc = backend.media_gt_slpc_status();
        let rc6_ms = backend.media_gt_rc6_residency_ms().unwrap_or(0);
        let hw_act = backend.media_gt_act_freq_mhz();
        let idle_status = if hw_act == Some(0) && rc6_ms > 0 {
            "gt-c6"
        } else {
            "gt-c0"
        };

        if let Some(status) = slpc {
            let power_profile = match status.profile {
                crate::intel_gpu_slpc::PowerProfile::Base => "base",
                crate::intel_gpu_slpc::PowerProfile::PowerSaving => "power_saving",
            };
            Some(Self {
                cur_freq_mhz: status.range.min_mhz,
                act_freq_mhz: hw_act.filter(|&f| f > 0).unwrap_or(status.range.min_mhz),
                rc6_residency_ms: rc6_ms,
                min_freq_mhz: status.range.min_mhz,
                max_freq_mhz: status.range.max_mhz,
                rp0_freq_mhz: status.limits.rp0_mhz,
                rpe_freq_mhz: status.limits.rpe_mhz,
                rpn_freq_mhz: status.limits.rpn_mhz,
                is_running: true,
                power_profile,
                idle_status,
            })
        } else {
            // Media GT is published but SLPC status not yet active
            let ref_mhz = (media_gt.reference_clock / 1_000_000).max(100);
            Some(Self {
                cur_freq_mhz: ref_mhz,
                act_freq_mhz: hw_act.filter(|&f| f > 0).unwrap_or(ref_mhz),
                rc6_residency_ms: rc6_ms,
                min_freq_mhz: 100,
                max_freq_mhz: 1150,
                rp0_freq_mhz: 1150,
                rpe_freq_mhz: 500,
                rpn_freq_mhz: 100,
                is_running: false,
                power_profile: "base",
                idle_status,
            })
        }
    }
}

/// Populate GT1 telemetry attributes on the card's sysfs nodes.
pub(crate) fn populate_card(
    card_index: u32,
    card_node: &Arc<Kobject>,
    dev_node: Option<&Arc<Kobject>>,
) {
    // 1) /sys/class/drm/card<N>/gt1/ directory
    let gt1_kobj = get_or_create_child(card_node, "gt1");

    let resolve = move || {
        let card = crate::drm_registry::card(card_index)?;
        let backend = card.intel_user_backend()?;
        MediaGtTelemetry::from_backend(backend.as_ref())
    };

    // Card-level gt1 attributes
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "rps_cur_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.cur_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "rps_act_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.act_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "rc6_residency_ms", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rc6_residency_ms))
        });
    }
    {
        kobject_add_attr(&gt1_kobj, "rc6p_residency_ms", move || "0\n".into());
    }
    {
        kobject_add_attr(&gt1_kobj, "rc6pp_residency_ms", move || "0\n".into());
    }
    {
        kobject_add_attr(&gt1_kobj, "freq_factor_scale", move || "1.00\n".into());
    }
    {
        kobject_add_attr(&gt1_kobj, "throttle_reasons", move || "0\n".into());
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "gt_min_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.min_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "gt_max_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.max_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "gt_RP0_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rp0_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "gt_RP1_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rpe_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "gt_RPn_freq_mhz", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rpn_freq_mhz))
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "slpc_status", move || {
            r().map_or_else(
                || "unavailable\n".into(),
                |t| {
                    if t.is_running {
                        "running\n".into()
                    } else {
                        "disabled\n".into()
                    }
                },
            )
        });
    }
    {
        let r = resolve;
        kobject_add_attr(&gt1_kobj, "slpc_power_profile", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.power_profile))
        });
    }

    // 2) If dev_node is present: /sys/class/drm/card<N>/device/tile0/gt1/
    if let Some(dev) = dev_node {
        let tile0 = get_or_create_child(dev, "tile0");
        let gt1_dev = get_or_create_child(&tile0, "gt1");
        let freq0 = get_or_create_child(&gt1_dev, "freq0");
        let gtidle = get_or_create_child(&gt1_dev, "gtidle");

        let r = resolve;
        kobject_add_attr(&freq0, "cur_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.cur_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "act_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.act_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "min_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.min_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "max_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.max_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "rp0_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rp0_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "rpe_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rpe_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "rpn_freq", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rpn_freq_mhz))
        });
        let r = resolve;
        kobject_add_attr(&freq0, "power_profile", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.power_profile))
        });

        kobject_add_attr(&gtidle, "name", move || "gt1-mc\n".into());
        let r = resolve;
        kobject_add_attr(&gtidle, "idle_residency_ms", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rc6_residency_ms))
        });
        let r = resolve;
        kobject_add_attr(&gtidle, "idle_status", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.idle_status))
        });
        let r = resolve;
        kobject_add_attr(&gtidle, "gt1-mc", move || {
            r().map_or_else(String::new, |t| format!("{}\n", t.rc6_residency_ms))
        });
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_media_gt_sysfs_tests.rs"]
mod tests;
