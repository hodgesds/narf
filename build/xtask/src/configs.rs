//! `cargo xtask --config <name>` — named kernel build configurations.
//!
//! Policy lives in this one file (the `affected.rs` precedent): a
//! closed registry mapping a config name to (a) whether the build
//! drops `narf-frame`'s default features first and (b) the frame
//! features the config selects. A config is a selection of
//! *driver-group* forwarding features on `narf-frame` (design of
//! record: `narf-configurable-drivers-design.md` §5.1/§5.2):
//! frame's `default` includes every group, so `all` is literally
//! today's build, and subset configs are `--no-default-features`
//! selections of the same group features plus the always-on core
//! set. Free-form `--features` remains available for one-off local
//! use and composes with `--config` by union; CI passes names only.
//!
//! The registry is closed on purpose (design §6, risk 3): unknown
//! names are an error, group granularity is the finest selection
//! offered, and new configs land here in the same change that wires
//! their groups — never as ad-hoc feature vectors at call sites.
//!
//! Lane 1 registers `all` and `minimal` and wires the net/storage
//! groups. Later lanes add the `test-<group>` instances and
//! `laptop` here as their groups gain frame forwarding features.
//!
//! Per-vendor GPU selection (Daniel, 2026-10-26) lands with lane 2
//! as frame forwarding features over `narf-drivers-gpu`'s own
//! `intel` / `amdgpu` features (both default-on there, so `all`
//! stays baseline-identical): this table is where that selection
//! is expressed — a config lists the intel forwarding feature and
//! omits the amdgpu one, or vice versa; `minimal` lists neither.
//! No second mechanism: the registry's feature list *is* the
//! selection surface, at group granularity.

/// Frame features that are not driver-group selections but members
/// of frame's `default` — the always-on core a subset config must
/// re-add explicitly when it drops defaults. Mirrors the non-group
/// members of `default` in `frame/Cargo.toml`; if the two drift
/// apart, subset builds lose core behaviour and the composition
/// census fixture (frame/src/census.rs) shows the drift in stages
/// no group owns.
pub const CORE_FEATURES: &[&str] = &["user-task-smp"];

/// One named build configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Registry name, as passed to `--config`.
    pub name: &'static str,
    /// Drop `narf-frame`'s default features (`--no-default-features`)
    /// before applying `features`. `false` for `all`: the default
    /// build is preserved bit-for-bit.
    pub no_default_features: bool,
    /// Frame features the config selects, unioned with whatever the
    /// invoking command adds itself (`kernel-test`, `boot-smoke`, …)
    /// and with the caller's own `--features`.
    pub features: &'static [&'static str],
}

/// Every named config, in display order.
pub const CONFIGS: &[Config] = &[
    Config {
        name: "all",
        no_default_features: false,
        features: &[],
    },
    Config {
        name: "minimal",
        no_default_features: true,
        features: CORE_FEATURES,
    },
];

/// Resolve a config name against the closed registry.
pub fn lookup(name: &str) -> Option<&'static Config> {
    CONFIGS.iter().find(|c| c.name == name)
}

/// All registered config names, for error messages.
pub fn names() -> impl Iterator<Item = &'static str> {
    CONFIGS.iter().map(|c| c.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_preserves_the_default_build() {
        let all = lookup("all").expect("the `all` config is registered");
        assert!(
            !all.no_default_features,
            "`all` must keep frame's defaults on — it is today's build"
        );
        assert!(
            all.features.is_empty(),
            "`all` adds nothing on top of the defaults"
        );
    }

    #[test]
    fn minimal_is_core_only() {
        let minimal = lookup("minimal").expect("the `minimal` config is registered");
        assert!(
            minimal.no_default_features,
            "a subset config must drop frame's defaults or the groups stay on"
        );
        assert_eq!(minimal.features, CORE_FEATURES);
        assert!(
            !minimal.features.iter().any(|f| f.starts_with("drivers-")),
            "the core set must not smuggle a driver group back in"
        );
    }

    #[test]
    fn unknown_names_are_rejected() {
        assert!(lookup("bogus").is_none());
        assert!(lookup("").is_none());
        assert!(lookup("ALL").is_none(), "names are case-sensitive");
        assert!(lookup("test-net").is_none(), "not wired yet (lane 5)");
    }

    #[test]
    fn registry_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for c in CONFIGS {
            assert!(seen.insert(c.name), "duplicate config name {}", c.name);
        }
    }
}
