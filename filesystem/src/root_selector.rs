//! Kernel-cmdline `root=` selector parsing + matching.
//!
//! The boot path can pin which block device gets mounted on / via
//! `root=<spec>` in the kernel cmdline. Forms supported:
//!
//! - `root=/dev/<name>` — match by registered block-device name
//!   (e.g. `nvme0p1`, `usb-msc0p2`). No `/dev/` prefix on NARF —
//!   the block registry uses bare names like `nvme0p1` — so the
//!   parser strips `/dev/` if present and matches the suffix.
//! - `root=PARTLABEL=<utf8>` — match a GPT partition's UTF-16LE
//!   name field decoded into UTF-8.
//! - `root=PARTUUID=<guid>` — match a GPT partition's per-partition
//!   GUID rendered in canonical 8-4-4-4-12 hex.
//! - `root=UUID=<guid>` — match the filesystem's volume UUID
//!   (carried by ext / xfs / btrfs superblocks).
//!
//! Match semantics:
//!
//! - If `RootSelector::from_cmdline` returns `Some(spec)`, the
//!   walker honours it: any device that matches is the chosen root;
//!   no match → boot refuses (no silent fallback to a wrong volume).
//! - If `None`, the walker falls back to "first detected FS in
//!   registration order" — the existing behaviour.
//!
//! PARTUUID / UUID matching needs partition / FS-instance metadata
//! beyond the block registry's name. The `root_mount` walker
//! threads what it has; matchers that need data the walker doesn't
//! carry yet return `MatchOutcome::NeedsMoreData` so the caller
//! can decide whether to fall through or fail.

extern crate alloc;

use alloc::string::String;

/// A parsed `root=` selector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootSelector {
    /// Match a registered block device by its registry name.
    /// Example: `root=/dev/nvme0p1` → `ByName("nvme0p1")`.
    ByName(String),
    /// Match a GPT partition by its UTF-16LE name field.
    /// Example: `root=PARTLABEL=NARF_ROOT`.
    ByPartLabel(String),
    /// Match a GPT partition by per-partition GUID (canonical 8-4-4-4-12).
    /// Example: `root=PARTUUID=12345678-1234-1234-1234-123456789ABC`.
    ByPartUuid(String),
    /// Match a filesystem's volume UUID (ext2/3/4 s_uuid field, etc.).
    ByFsUuid(String),
}

impl RootSelector {
    /// Parse the first `root=...` token from a kernel cmdline.
    /// Returns `None` if no `root=` is present. Token discovery goes
    /// through the single structured parser ([`narf_boot::KernelCmdline`]);
    /// this function only maps the `root=` value onto a selector variant.
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        narf_boot::KernelCmdline::new(cmdline)
            .value("root")
            .and_then(Self::parse)
    }

    /// Parse a single `root=` value (the part after the `=`).
    pub fn parse(value: &str) -> Option<Self> {
        if let Some(label) = value.strip_prefix("PARTLABEL=") {
            return Some(Self::ByPartLabel(String::from(label)));
        }
        if let Some(uuid) = value.strip_prefix("PARTUUID=") {
            return Some(Self::ByPartUuid(String::from(uuid)));
        }
        if let Some(uuid) = value.strip_prefix("UUID=") {
            return Some(Self::ByFsUuid(String::from(uuid)));
        }
        // Plain path. Strip /dev/ if present — NARF's registry uses
        // bare names.
        let name = value.strip_prefix("/dev/").unwrap_or(value);
        if name.is_empty() {
            return None;
        }
        Some(Self::ByName(String::from(name)))
    }

    /// True iff the selector targets metadata the walker has (just
    /// device name). False for PARTLABEL / PARTUUID / FS UUID
    /// selectors which need extra resolution.
    pub fn is_name_only(&self) -> bool {
        matches!(self, RootSelector::ByName(_))
    }

    /// Match against a registered block-device name. Returns true
    /// for `ByName(...)` matches; the other variants always return
    /// false here — the walker checks them against partition /
    /// FS-side metadata.
    pub fn matches_name(&self, name: &str) -> bool {
        match self {
            RootSelector::ByName(target) => target == name,
            _ => false,
        }
    }
}
