//! Module manifest.
//!
//! Parsed from the `.modinfo` section's NUL-separated key=value list.
//! Linux ref: `linux/kernel/module/main.c::get_modinfo` (`main.c:1714`)
//! and the MODULE_INFO macro family (`include/linux/module.h:184`).
//!
//! NARF extends modinfo with:
//!   * `kernel_abi=0xHEX` — a 32-bit hash of the running kernel build
//!     that the kernel was compiled with. A module whose kernel_abi
//!     doesn't match is rejected at load time.
//!   * `required_caps=NetIface:Write,DmaRegion:Invoke` — cap requirements
//!     enforced by the relocator when the module imports a cap-typed
//!     export.
//!   * `target_domain=net` — the PKS-isolated domain in which the
//!     module's text and data are placed.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_capabilities::{parse_kind, CapKind};

/// Errors from manifest parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// `.modinfo` was missing or empty.
    Missing,
    /// `name=` key was absent.
    NameMissing,
    /// `kernel_abi=` didn't match the running kernel.
    AbiMismatch { expected: u32, got: u32 },
    /// `required_caps` mentioned an unknown CapKind.
    UnknownCap(String),
    /// `required_caps` had an entry without the `Kind:Right` shape.
    BadCapSpec(String),
    /// `target_domain` mentioned a domain the kernel doesn't expose.
    UnknownDomain(String),
}

/// Capability requirement: a kind + a right.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RequiredCap {
    pub kind: CapKind,
    /// One of `Read | Write | Grant | Spend | Invoke`. Stored as the
    /// runtime BITS value matching `narf_capabilities::Rights::BITS`.
    pub right: u32,
}

/// Parsed module manifest.
#[derive(Debug, Default, Clone)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub license: String,
    pub author: String,
    pub description: String,
    pub depends: Vec<String>,
    pub required_caps: Vec<RequiredCap>,
    pub target_domain: String,
    pub kernel_abi: u32,
    /// All raw key=value pairs preserved for `/sys/module/<name>/.modinfo`.
    pub raw: Vec<(String, String)>,
}

impl Manifest {
    /// Parse a `.modinfo`-shaped byte slice. Lines are split on
    /// either NUL or LF; ASCII `key=value` pairs are captured.
    ///
    /// Linux's `get_modinfo` walks NUL-separated strings written by
    /// the MODULE_INFO macros at compile time.
    pub fn parse(bytes: &[u8], expected_abi: u32) -> Result<Self, ManifestError> {
        if bytes.is_empty() {
            return Err(ManifestError::Missing);
        }
        let mut out = Manifest::default();
        let mut start = 0usize;
        for i in 0..=bytes.len() {
            let at_end = i == bytes.len();
            let is_sep = !at_end && (bytes[i] == 0 || bytes[i] == b'\n');
            if at_end || is_sep {
                if i > start {
                    let raw = &bytes[start..i];
                    if let Ok(s) = core::str::from_utf8(raw) {
                        if let Some(eq) = s.find('=') {
                            let key = s[..eq].trim();
                            let mut val = s[eq + 1..].trim();
                            // Allow `"quoted"` values.
                            if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                                val = &val[1..val.len() - 1];
                            }
                            out.absorb(key, val)?;
                        }
                    }
                }
                start = i + 1;
            }
        }
        if out.name.is_empty() {
            return Err(ManifestError::NameMissing);
        }
        if out.kernel_abi != expected_abi {
            return Err(ManifestError::AbiMismatch {
                expected: expected_abi,
                got: out.kernel_abi,
            });
        }
        Ok(out)
    }

    fn absorb(&mut self, key: &str, val: &str) -> Result<(), ManifestError> {
        self.raw.push((key.to_string(), val.to_string()));
        match key {
            "name" => self.name = val.to_string(),
            "version" => self.version = val.to_string(),
            "license" => self.license = val.to_string(),
            "author" => self.author = val.to_string(),
            "description" => self.description = val.to_string(),
            "depends" => {
                self.depends = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "required_caps" => {
                for spec in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let mut parts = spec.splitn(2, ':');
                    let kind_s = parts.next().ok_or_else(|| {
                        ManifestError::BadCapSpec(spec.to_string())
                    })?;
                    let right_s = parts.next().ok_or_else(|| {
                        ManifestError::BadCapSpec(spec.to_string())
                    })?;
                    let kind = parse_kind(kind_s).map_err(|_| {
                        ManifestError::UnknownCap(kind_s.to_string())
                    })?;
                    let right = match right_s {
                        "Read" => 0b0_0001u32,
                        "Write" => 0b0_0010u32,
                        "Grant" => 0b0_0100u32,
                        "Spend" => 0b0_1000u32,
                        "Invoke" => 0b1_0000u32,
                        other => {
                            return Err(ManifestError::BadCapSpec(other.to_string()));
                        }
                    };
                    self.required_caps.push(RequiredCap { kind, right });
                }
            }
            "target_domain" => self.target_domain = val.to_string(),
            "kernel_abi" => {
                let v = val.strip_prefix("0x").unwrap_or(val);
                self.kernel_abi = u32::from_str_radix(v, 16).unwrap_or(0);
            }
            _ => {}
        }
        Ok(())
    }

    /// True iff the manifest declares the given required cap.
    pub fn has_required_cap(&self, kind: CapKind, right: u32) -> bool {
        self.required_caps
            .iter()
            .any(|c| c.kind == kind && (c.right & right) == right)
    }
}
