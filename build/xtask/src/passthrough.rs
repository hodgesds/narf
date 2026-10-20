//! PCIe passthrough preflight for testing a discrete AMD GPU under QEMU.
//!
//! Booting NARF with a real card attached needs the host set up in four
//! independent ways, and three of the four fail silently — QEMU starts, the
//! guest boots, and the card is either absent or wedged. This checks them
//! before launching, and reports what is wrong rather than what is missing.
//!
//! The fourth is specific to this kernel and is the reason this lives here
//! rather than in a shell script: **NARF does not map all of physical
//! address space.** A BAR the firmware parks outside the mapped windows
//! #PFs on first register access, which looks like a driver bug and is not
//! one. See [`BAR_WINDOWS`].

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// A physical-address range NARF's page tables cover, as
/// `memory/src/x86_64/mmu.rs` builds them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysWindow {
    pub start: u64,
    /// Exclusive.
    pub end: u64,
    pub why: &'static str,
}

const GIB: u64 = 1 << 30;

/// Where a device BAR may land for NARF to be able to reach it.
///
/// Two windows, and the gap between them is the part that surprises people:
///
/// * The low identity map covers phys `[0, 512 GiB)`.
/// * The high-MMIO identity window (PML4[1]) covers phys
///   `[512 GiB, 1 TiB)` — **except its first gigabyte**. `mmu.rs` skips
///   PDPT[0] on purpose, because user binaries link at virt
///   `0x0000_0080_0000_1000`, which decodes into exactly that slot, and
///   mapping it as a 1-GiB page would collide with the user mapping's 4-KiB
///   descent. The comment there reasons that phys 512-513 GiB "is RAM
///   territory in any sane laptop, never MMIO" — which is true of laptops
///   and is not a guarantee about where QEMU parks a passed-through BAR.
/// * Nothing at or above 1 TiB is mapped at all.
pub const BAR_WINDOWS: &[PhysWindow] = &[
    PhysWindow {
        start: 0,
        end: 512 * GIB,
        why: "low identity map",
    },
    PhysWindow {
        start: 513 * GIB,
        end: 1024 * GIB,
        why: "high-MMIO identity window (PML4[1], PDPT[0] skipped)",
    },
];

/// Why a BAR placement is not reachable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BarVerdict {
    /// Fully inside one window.
    Ok(&'static str),
    /// Inside the 512-513 GiB hole that `mmu.rs` deliberately skips.
    InSkippedGigabyte,
    /// At or above 1 TiB — beyond PML4[1] entirely.
    AboveMappedSpace,
    /// Starts in one window and ends outside it. A BAR that straddles the
    /// 512-GiB boundary is the nastiest case: the first registers work and
    /// the ones past the boundary fault.
    Straddles,
}

/// Can NARF reach every byte of a BAR at `[base, base + size)`?
pub fn bar_verdict(base: u64, size: u64) -> BarVerdict {
    if size == 0 {
        // An unimplemented BAR. Nothing to reach.
        return BarVerdict::Ok("empty");
    }
    let end = base.saturating_add(size);
    for w in BAR_WINDOWS {
        if base >= w.start && end <= w.end {
            return BarVerdict::Ok(w.why);
        }
    }
    // Not contained. Say which way it failed, because the fixes differ.
    if base >= 1024 * GIB {
        return BarVerdict::AboveMappedSpace;
    }
    if (512 * GIB..513 * GIB).contains(&base) {
        return BarVerdict::InSkippedGigabyte;
    }
    if end > 1024 * GIB {
        return BarVerdict::AboveMappedSpace;
    }
    BarVerdict::Straddles
}

/// One BAR as the host kernel reports it in sysfs `resource`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostBar {
    pub index: usize,
    pub start: u64,
    pub end: u64,
    pub flags: u64,
}

/// `PCI_STD_NUM_BARS` — resource indices 0..5 are the standard BARs.
///
/// Index **6** is `PCI_ROM_RESOURCE`, the expansion ROM, and 7 and up are
/// SR-IOV and bridge windows (`include/linux/pci.h`'s region enum). They
/// appear in the same sysfs `resource` file and look exactly like 64-bit
/// memory BARs, so summing every line overcounts a card's footprint — on an
/// Intel iGPU, by 112 MiB of SR-IOV window.
pub const PCI_STD_NUM_BARS: usize = 6;

impl HostBar {
    /// Is this one of the six standard BARs, rather than the ROM or an
    /// SR-IOV / bridge window?
    pub fn is_standard_bar(&self) -> bool {
        self.index < PCI_STD_NUM_BARS
    }
    pub fn size(&self) -> u64 {
        if self.start == 0 && self.end == 0 {
            0
        } else {
            self.end.saturating_sub(self.start).saturating_add(1)
        }
    }
    /// Bit 0 of the flags word is set for I/O-port resources; everything
    /// else in a GPU's set is memory.
    pub fn is_io(&self) -> bool {
        self.flags & 0x1 != 0
    }
    /// Bit 2 of the type field marks a 64-bit memory BAR. Only these can be
    /// parked above 4 GiB, so only these can land outside NARF's windows.
    ///
    /// Restricted to the standard BARs: the ROM and the SR-IOV windows
    /// carry the same flag bits and are not placed in the guest's 64-bit
    /// hole by vfio-pci.
    pub fn is_64bit(&self) -> bool {
        self.is_standard_bar() && !self.is_io() && self.flags & 0x4 != 0
    }
}

/// Parse a sysfs `resource` file: one line per BAR, three hex fields.
///
/// The host's addresses are **not** where QEMU will put the guest's — they
/// are read to learn each BAR's *size*, which is what decides whether the
/// guest's 64-bit hole can hold them.
pub fn parse_resource(text: &str) -> Vec<HostBar> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let mut f = line.split_whitespace();
            let start = u64::from_str_radix(f.next()?.trim_start_matches("0x"), 16).ok()?;
            let end = u64::from_str_radix(f.next()?.trim_start_matches("0x"), 16).ok()?;
            let flags = u64::from_str_radix(f.next()?.trim_start_matches("0x"), 16).ok()?;
            Some(HostBar {
                index,
                start,
                end,
                flags,
            })
        })
        .collect()
}

/// Total 64-bit memory-BAR footprint, which is what has to fit in the
/// guest's 64-bit PCI hole.
pub fn total_64bit_bar_bytes(bars: &[HostBar]) -> u64 {
    bars.iter()
        .filter(|b| b.is_64bit())
        .map(HostBar::size)
        .sum()
}

/// The largest span a single contiguous 64-bit PCI hole could occupy,
/// derived from [`BAR_WINDOWS`] rather than restated.
///
/// Derived, because the number that matters is a consequence of what
/// `mmu.rs` maps: if the skipped gigabyte or the 1-TiB ceiling moves, this
/// follows, and the [`Blocker::BarsTooLarge`] threshold follows with it.
pub fn largest_window_bytes() -> u64 {
    BAR_WINDOWS
        .iter()
        .map(|w| w.end - w.start)
        .max()
        .unwrap_or(0)
}

/// Where QEMU would park the q35 64-bit PCI hole in the **worst case**,
/// given a total 64-bit BAR footprint and the `phys-bits=40` clamp.
///
/// QEMU places the hole above guest RAM and below the advertised physical
/// address limit, which the clamp pins at 1 TiB. The highest it can go is
/// therefore flush against that ceiling — so `[1 TiB - size, 1 TiB)` is the
/// worst case, and it is the one worth checking: a lower placement sits
/// either in the high window or down in the low identity map, both mapped.
///
/// The hole is 1-GiB aligned in practice; rounding the footprint up to a
/// gigabyte keeps the worst case pessimistic rather than optimistic.
pub fn worst_case_hole(total_64bit: u64) -> (u64, u64) {
    let size = total_64bit.div_ceil(GIB) * GIB;
    (1024 * GIB - size, size)
}

/// A device's BDF, as sysfs spells it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bdf(pub String);

impl Bdf {
    /// Accept `03:00.0` and `0000:03:00.0`, normalising to the long form
    /// sysfs uses. QEMU's `host=` accepts either, so a user will type both.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        let long = match parts.len() {
            2 => format!("0000:{s}"),
            3 => s.to_string(),
            _ => return None,
        };
        // domain:bus:dev.fn — 4, 2, 2 hex digits and a 1-digit function.
        let (head, func) = long.rsplit_once('.')?;
        if func.len() != 1 || !func.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let seg: Vec<&str> = head.split(':').collect();
        if seg.len() != 3 || seg[0].len() != 4 || seg[1].len() != 2 || seg[2].len() != 2 {
            return None;
        }
        if !seg.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit())) {
            return None;
        }
        Some(Bdf(long.to_ascii_lowercase()))
    }

    pub fn sysfs(&self) -> PathBuf {
        Path::new("/sys/bus/pci/devices").join(&self.0)
    }

    /// The other functions of the same physical device — for a GPU, its
    /// HD-audio function. Same domain:bus:device, different function.
    pub fn same_device_as(&self, other: &Bdf) -> bool {
        match (self.0.rsplit_once('.'), other.0.rsplit_once('.')) {
            (Some((a, _)), Some((b, _))) => a == b,
            _ => false,
        }
    }
}

impl FromStr for Bdf {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw).ok_or_else(|| {
            format!("{raw:?} is not a PCI address; expected 03:00.0 or 0000:03:00.0")
        })
    }
}

/// What the preflight found wrong. Every variant is a thing that makes the
/// launch fail or the guest see a broken card, not a style note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocker {
    NoKvm(String),
    NoIommu,
    DeviceMissing(String),
    /// A device shares an IOMMU group with the passthrough set but is not
    /// in it. VFIO claims whole groups, so this always fails at launch.
    GroupNotIsolated {
        group: String,
        stranger: String,
        stranger_driver: String,
    },
    /// Bound to something other than vfio-pci.
    WrongDriver {
        bdf: String,
        driver: String,
    },
    /// The requested device is a PCI bridge. Bridges are the structure of
    /// an IOMMU group, not members of it — VFIO never binds one.
    BridgeRequested(String),
    /// A BAR cannot be reached from NARF's page tables.
    BarUnreachable {
        bdf: String,
        index: usize,
        size: u64,
        verdict: BarVerdict,
    },
    /// The 64-bit BARs do not fit the window QEMU has to place them in.
    BarsTooLarge {
        total: u64,
        window: u64,
    },
    /// `/dev/vfio/<group>` cannot be opened by this user. QEMU opens the
    /// group node read-write; vfio-pci creates it root-only.
    GroupNodeUnusable {
        group: String,
        why: GroupNodeError,
    },
    /// `RLIMIT_MEMLOCK` is below what QEMU must pin. VFIO type1 pins every
    /// page of guest RAM for DMA, so a default 8 MiB limit fails the launch
    /// with `vfio_dma_map ... -12 (Cannot allocate memory)`.
    MemlockTooLow {
        limit: u64,
        need: u64,
    },
    /// The firmware's IOMMU table (AMD IVRS IVMD unity ranges, Intel DMAR
    /// RMRRs) gives the group `direct` reserved regions: ranges the device
    /// must see identity-mapped. Linux then refuses any domain but the
    /// identity one, so claiming the group for a guest fails with
    /// "Firmware has requested this device have a 1:1 IOMMU mapping" and
    /// QEMU's `failed to setup container for group N: ... Invalid argument`.
    /// `direct-relaxable` ranges do not do this.
    FirmwareDirectMapping {
        group: String,
        ranges: Vec<String>,
    },
}

/// Why `/dev/vfio/<group>` could not be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupNodeError {
    Missing,
    PermissionDenied,
    /// A VFIO group is single-open: another process (usually a QEMU that is
    /// still running) holds it.
    Busy,
    Other(String),
}

/// Things worth saying that do not stop the launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Advisory {
    /// A sibling function of a passed-through GPU is not in the set. Legal,
    /// but the guest then sees a GPU whose audio function is missing, and
    /// the host may still be driving it.
    SiblingFunctionNotPassed { bdf: String, sibling: String },
    /// Resizable BAR is likely in play: a memory BAR at or above 1 GiB.
    /// Worth saying because the host's current size is what was measured,
    /// and firmware can change it between boots.
    LargeBar {
        bdf: String,
        index: usize,
        size: u64,
    },
}

/// A device as the host describes it, for the isolation check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    pub bdf: Bdf,
    /// Driver currently bound, if any.
    pub driver: Option<String>,
    /// PCI class, high byte. 0x06 is a bridge.
    pub class_high: u8,
}

impl GroupMember {
    /// A PCI bridge in the group is not a problem: VFIO does not need a
    /// bridge bound to vfio-pci, and bridges have no driver worth claiming.
    pub fn is_bridge(&self) -> bool {
        self.class_high == 0x06
    }
}

/// Does the passthrough set own its IOMMU group outright?
///
/// VFIO grants access per **group**, not per device, so every endpoint in
/// the group has to be passed through together. A stranger in the group is
/// the single most common reason a passthrough launch fails, and it fails
/// at `VFIO_GROUP_GET_DEVICE_FD` with nothing useful in the message.
///
/// Bridges are exempt — they are the group's structure, not its members.
/// A stranger bound to no driver is still a stranger: the group is claimed
/// whole, so the guest would get a device the host never released.
pub fn isolation_blockers(group: &str, members: &[GroupMember], passing: &[Bdf]) -> Vec<Blocker> {
    members
        .iter()
        .filter(|m| !m.is_bridge())
        .filter(|m| !passing.contains(&m.bdf))
        .map(|m| Blocker::GroupNotIsolated {
            group: group.to_string(),
            stranger: m.bdf.0.clone(),
            stranger_driver: m.driver.clone().unwrap_or_else(|| "(none)".to_string()),
        })
        .collect()
}

/// Advisories about functions of a passed device that were left behind.
///
/// Passing `03:00.0` and not `03:00.1` is legal once the group check has
/// passed — but on an AMD GPU function 1 is the HD-audio device, and a
/// guest that sees the GPU without it has a card whose audio is missing,
/// while the host may still be driving that function.
pub fn sibling_advisories(members: &[GroupMember], passing: &[Bdf]) -> Vec<Advisory> {
    let mut out = Vec::new();
    for p in passing {
        for m in members {
            if m.bdf != *p && m.bdf.same_device_as(p) && !passing.contains(&m.bdf) {
                out.push(Advisory::SiblingFunctionNotPassed {
                    bdf: p.0.clone(),
                    sibling: m.bdf.0.clone(),
                });
            }
        }
    }
    out
}

/// BAR blockers and advisories for one device.
///
/// The host's BAR *addresses* are not the guest's, so they are not checked
/// against [`BAR_WINDOWS`] — their sizes are, against the window QEMU has
/// to fit them into. What IS checked against the windows is the total
/// footprint: if the 64-bit BARs cannot fit the high-MMIO window at all,
/// no placement QEMU chooses will work and that is knowable now.
pub fn bar_findings(bdf: &Bdf, bars: &[HostBar]) -> (Vec<Blocker>, Vec<Advisory>) {
    let mut blockers = Vec::new();
    let mut advisories = Vec::new();

    let total = total_64bit_bar_bytes(bars);
    let window = largest_window_bytes();
    if total > window {
        // Nothing QEMU can do with it: no single mapped window is big
        // enough to hold the hole, wherever it decides to put it.
        blockers.push(Blocker::BarsTooLarge { total, window });
    } else if total > 0 {
        // It fits *a* window; check the placement QEMU is most likely to
        // choose. This is what catches a footprint large enough to push the
        // top-anchored hole down across the skipped gigabyte.
        let (base, size) = worst_case_hole(total);
        let verdict = bar_verdict(base, size);
        if !matches!(verdict, BarVerdict::Ok(_)) {
            blockers.push(Blocker::BarUnreachable {
                bdf: bdf.0.clone(),
                index: usize::MAX,
                size,
                verdict,
            });
        }
    }
    for b in bars.iter().filter(|b| b.is_64bit() && b.size() >= GIB) {
        advisories.push(Advisory::LargeBar {
            bdf: bdf.0.clone(),
            index: b.index,
            size: b.size(),
        });
    }
    (blockers, advisories)
}

/// Render the QEMU fragment for a set of devices.
///
/// The first GPU gets no `x-vga`: NARF drives the card through its own
/// driver and never relies on VGA legacy decode, and `x-vga=on` requires
/// the host to have released the console framebuffer.
pub fn qemu_fragment(devices: &[Bdf]) -> String {
    let mut out = String::new();
    for d in devices {
        if !out.is_empty() {
            out.push(' ');
        }
        let _ = write!(out, "-device vfio-pci,host={}", d.0);
    }
    out
}

/// Render the typed QEMU argv entries for direct use with
/// [`std::process::Command`].
///
/// Keep this separate from [`qemu_fragment`]: the latter is display text,
/// while this form never relies on shell quoting or whitespace splitting.
pub fn qemu_args(devices: &[Bdf]) -> Vec<String> {
    devices
        .iter()
        .flat_map(|device| ["-device".to_string(), format!("vfio-pci,host={}", device.0)])
        .collect()
}

// ── Reading the host ───────────────────────────────────

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Basename of a symlink target, which is how sysfs reports a bound driver
/// and an IOMMU group.
fn link_basename(path: &Path) -> Option<String> {
    let target = std::fs::read_link(path).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

fn device_driver(bdf: &Bdf) -> Option<String> {
    link_basename(&bdf.sysfs().join("driver"))
}

fn device_iommu_group(bdf: &Bdf) -> Option<String> {
    link_basename(&bdf.sysfs().join("iommu_group"))
}

fn device_class_high(bdf: &Bdf) -> u8 {
    read_trim(&bdf.sysfs().join("class"))
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .map(|c| (c >> 16) as u8)
        .unwrap_or(0)
}

fn device_bars(bdf: &Bdf) -> Vec<HostBar> {
    read_trim(&bdf.sysfs().join("resource"))
        .map(|t| parse_resource(&t))
        .unwrap_or_default()
}

fn device_ids(bdf: &Bdf) -> Option<(u16, u16)> {
    let hex = |n: &str| {
        read_trim(&bdf.sysfs().join(n))
            .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    };
    Some((hex("vendor")?, hex("device")?))
}

/// Every endpoint and bridge sharing `group`.
fn group_members(group: &str) -> Vec<GroupMember> {
    let dir = Path::new("/sys/kernel/iommu_groups")
        .join(group)
        .join("devices");
    let mut out: Vec<GroupMember> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let bdf = Bdf::parse(&e.file_name().to_string_lossy())?;
            Some(GroupMember {
                driver: device_driver(&bdf),
                class_high: device_class_high(&bdf),
                bdf,
            })
        })
        .collect();
    out.sort_by(|a, b| a.bdf.cmp(&b.bdf));
    out
}

/// The `direct` lines of a group's `reserved_regions` (`<start> <end>
/// <type>`), as `start-end`. Only the exact type `direct` counts:
/// `direct-relaxable`, `msi` and `reserved` do not force an identity domain.
pub fn direct_ranges(reserved_regions: &str) -> Vec<String> {
    reserved_regions
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (start, end, kind) = (f.next()?, f.next()?, f.next()?);
            (kind == "direct").then(|| format!("{start}-{end}"))
        })
        .collect()
}

/// Guest RAM QEMU pins beyond `-m`: option ROMs, the firmware's own
/// buffers and VFIO's bookkeeping. Generous on purpose, because an
/// undersized limit fails late and obscurely.
pub const MEMLOCK_SLACK: u64 = 256 << 20;

/// The memlock verdict for a guest of `guest_ram` bytes, given the soft
/// `RLIMIT_MEMLOCK` (`None` = unlimited). Root holds `CAP_IPC_LOCK`, which
/// bypasses the limit.
pub fn memlock_blocker(limit: Option<u64>, guest_ram: u64, is_root: bool) -> Option<Blocker> {
    let need = guest_ram.saturating_add(MEMLOCK_SLACK);
    match limit {
        Some(limit) if !is_root && limit < need => Some(Blocker::MemlockTooLow { limit, need }),
        _ => None,
    }
}

/// The soft `Max locked memory` limit from `/proc/self/limits`, in bytes;
/// `None` for unlimited (or unreadable, which is then not a blocker).
pub fn parse_memlock_limit(limits: &str) -> Option<u64> {
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))?;
    let soft = line
        .trim_start_matches("Max locked memory")
        .split_whitespace()
        .next()?;
    soft.parse().ok()
}

fn is_root() -> bool {
    read_trim(Path::new("/proc/self/status"))
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|e| e == "0"))
        })
        .unwrap_or(false)
}

/// Open and immediately close `/dev/vfio/<group>` the way QEMU will.
fn check_group_node(group: &str) -> Result<(), GroupNodeError> {
    let path = Path::new("/dev/vfio").join(group);
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
    {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.kind() {
            std::io::ErrorKind::NotFound => GroupNodeError::Missing,
            std::io::ErrorKind::PermissionDenied => GroupNodeError::PermissionDenied,
            _ if e.raw_os_error() == Some(16) => GroupNodeError::Busy,
            _ => GroupNodeError::Other(e.to_string()),
        }),
    }
}

/// Is `bdf` a display controller (PCI class 0x03)? A passed-through GPU
/// should be the guest's only display adapter.
pub fn is_display(bdf: &Bdf) -> bool {
    device_class_high(bdf) == 0x03
}

/// Initramfs firmware globs a passed-through device needs before the root
/// mounts: the display engine comes up in a boot initcall, ahead of
/// `firmware-scan-rootfs`.
pub fn firmware_globs_for(vendor: u16, device: u16) -> &'static [&'static str] {
    match (vendor, device) {
        // Navi 22 (RX 6700 / 6700 XT / 6750 XT / 6800M / 6850M XT).
        (0x1002, 0x73c0..=0x73df) => &["amdgpu/navy_flounder*"],
        _ => &[],
    }
}

/// [`firmware_globs_for`] for every device in the set, read from sysfs.
pub fn firmware_globs(devices: &[Bdf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in devices {
        if let Some((v, id)) = device_ids(d) {
            for g in firmware_globs_for(v, id) {
                if !out.iter().any(|o| o == g) {
                    out.push((*g).to_string());
                }
            }
        }
    }
    out
}

/// The whole preflight.
pub struct Preflight {
    pub blockers: Vec<Blocker>,
    pub advisories: Vec<Advisory>,
    pub report: String,
}

/// Run every check for `passing`. `guest_ram` (bytes) adds the memlock
/// check for a guest of that size.
pub fn preflight(passing: &[Bdf], guest_ram: Option<u64>) -> Preflight {
    let mut blockers = Vec::new();
    let mut advisories = Vec::new();
    let mut report = String::new();

    // 1. KVM. Passthrough under TCG is not a degraded mode, it does not
    //    work at all: VFIO needs the hardware IOMMU mappings KVM sets up.
    let kvm = Path::new("/dev/kvm");
    if !kvm.exists() {
        blockers.push(Blocker::NoKvm("/dev/kvm does not exist".into()));
    } else if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm)
        .is_err()
    {
        blockers.push(Blocker::NoKvm(
            "/dev/kvm is not readable and writable by this user (add yourself to the kvm group)"
                .into(),
        ));
    }

    // 2. The IOMMU. An empty `iommu_groups` means the kernel booted
    //    without `amd_iommu=on` / `intel_iommu=on`, or the firmware has
    //    IOMMU disabled.
    let groups = Path::new("/sys/kernel/iommu_groups");
    let have_groups = std::fs::read_dir(groups)
        .map(|d| d.flatten().next().is_some())
        .unwrap_or(false);
    if !have_groups {
        blockers.push(Blocker::NoIommu);
    }

    for bdf in passing {
        if !bdf.sysfs().exists() {
            blockers.push(Blocker::DeviceMissing(bdf.0.clone()));
            continue;
        }
        let ids = device_ids(bdf);
        let driver = device_driver(bdf);
        let bars = device_bars(bdf);
        let group = device_iommu_group(bdf);

        let _ = writeln!(
            report,
            "{}  {}  driver={}  iommu_group={}",
            bdf.0,
            ids.map(|(v, d)| format!("{v:04x}:{d:04x}"))
                .unwrap_or_else(|| "????:????".into()),
            driver.clone().unwrap_or_else(|| "(none)".into()),
            group.clone().unwrap_or_else(|| "(none)".into()),
        );

        // 3. Bound to vfio-pci. Anything else means the host driver still
        //    owns it and the launch will fail to claim it.
        //
        //    A bridge is exempt: VFIO never binds one, and demanding
        //    vfio-pci on it would report a blocker with no fix. Passing a
        //    bridge is user error, so say that instead.
        if device_class_high(bdf) == 0x06 {
            blockers.push(Blocker::BridgeRequested(bdf.0.clone()));
        } else {
            match driver.as_deref() {
                Some("vfio-pci") => {}
                other => blockers.push(Blocker::WrongDriver {
                    bdf: bdf.0.clone(),
                    driver: other.unwrap_or("(none)").to_string(),
                }),
            }
        }

        // 4. The group is ours outright, and its node is ours to open.
        if let Some(g) = &group {
            if let Err(why) = check_group_node(g) {
                blockers.push(Blocker::GroupNodeUnusable {
                    group: g.clone(),
                    why,
                });
            }
            let members = group_members(g);
            for m in &members {
                let _ = writeln!(
                    report,
                    "    group {g} also holds {} driver={} class={:#04x}{}",
                    m.bdf.0,
                    m.driver.clone().unwrap_or_else(|| "(none)".into()),
                    m.class_high,
                    if m.is_bridge() { " (bridge)" } else { "" },
                );
            }
            let regions = Path::new("/sys/kernel/iommu_groups")
                .join(g)
                .join("reserved_regions");
            let ranges = direct_ranges(&std::fs::read_to_string(regions).unwrap_or_default());
            if !ranges.is_empty() {
                blockers.push(Blocker::FirmwareDirectMapping {
                    group: g.clone(),
                    ranges,
                });
            }
            blockers.extend(isolation_blockers(g, &members, passing));
            advisories.extend(sibling_advisories(&members, passing));
        }

        // 5. The BARs fit what NARF can map.
        for b in bars.iter().filter(|b| b.size() > 0) {
            let _ = writeln!(
                report,
                "    {}{} {:#x}..{:#x} {} KiB{}",
                if b.is_standard_bar() { "BAR" } else { "res" },
                b.index,
                b.start,
                b.end,
                b.size() / 1024,
                if !b.is_standard_bar() {
                    // Not a BAR: say which non-BAR resource it is, so the
                    // line is not read as part of the card's footprint.
                    if b.index == PCI_STD_NUM_BARS {
                        " expansion ROM"
                    } else {
                        " sr-iov / bridge window"
                    }
                } else if b.is_io() {
                    " io"
                } else if b.is_64bit() {
                    " mem64"
                } else {
                    " mem32"
                },
            );
        }
        let (bb, ba) = bar_findings(bdf, &bars);
        blockers.extend(bb);
        advisories.extend(ba);
    }

    // 6. Locked memory for the guest's RAM.
    if let Some(ram) = guest_ram.filter(|_| !passing.is_empty()) {
        let limit = read_trim(Path::new("/proc/self/limits"))
            .as_deref()
            .and_then(parse_memlock_limit);
        let _ = writeln!(
            report,
            "memlock: {} for a {} MiB guest",
            limit.map_or_else(|| "unlimited".into(), |l| format!("{} KiB", l / 1024)),
            ram >> 20
        );
        blockers.extend(memlock_blocker(limit, ram, is_root()));
    }

    // Deduplicate: two passed functions in one group would otherwise each
    // report the same stranger.
    blockers.dedup();
    advisories.dedup();

    Preflight {
        blockers,
        advisories,
        report,
    }
}

/// One line per blocker, saying what to do about it.
pub fn explain(b: &Blocker) -> String {
    match b {
        Blocker::NoKvm(why) => format!(
            "no KVM: {why}. Passthrough needs KVM — VFIO relies on the \
             hardware IOMMU mappings KVM installs, so there is no TCG fallback."
        ),
        Blocker::NoIommu => "/sys/kernel/iommu_groups is empty: boot the host with \
             amd_iommu=on (or intel_iommu=on) and IOMMU enabled in firmware."
            .to_string(),
        Blocker::DeviceMissing(bdf) => {
            format!("{bdf} is not in /sys/bus/pci/devices — check the BDF.")
        }
        Blocker::BridgeRequested(bdf) => format!(
            "{bdf} is a PCI bridge, not an endpoint. Pass the device behind \
             it — `lspci -nn` or the group listing above shows which."
        ),
        Blocker::WrongDriver { bdf, driver } => format!(
            "{bdf} is bound to {driver}, not vfio-pci. Unbind it and bind \
             vfio-pci (e.g. driverctl set-override {bdf} vfio-pci), or blacklist \
             the host driver."
        ),
        Blocker::GroupNotIsolated {
            group,
            stranger,
            stranger_driver,
        } => format!(
            "IOMMU group {group} also holds {stranger} (driver {stranger_driver}), \
             which is not in the passthrough set. VFIO claims whole groups, so \
             either pass that device too or move the card to a slot with its own \
             group."
        ),
        Blocker::BarUnreachable {
            bdf,
            index,
            size,
            verdict,
        } => format!(
            "{bdf} BAR{index} ({} KiB) would be unreachable: {verdict:?}. NARF maps \
             phys [0, 512 GiB) and [513 GiB, 1 TiB) only.",
            size / 1024
        ),
        Blocker::BarsTooLarge { total, window } => format!(
            "the 64-bit BARs total {} MiB but NARF's high-MMIO window is only \
             {} MiB. Disable Resizable BAR in host firmware, or extend the \
             window in memory/src/x86_64/mmu.rs.",
            total / (1 << 20),
            window / (1 << 20)
        ),
        Blocker::GroupNodeUnusable { group, why } => match why {
            GroupNodeError::Missing => {
                format!("/dev/vfio/{group} does not exist: is the device bound to vfio-pci?")
            }
            GroupNodeError::PermissionDenied => format!(
                "/dev/vfio/{group} is not readable and writable by this user. \
                 `sudo chown $USER /dev/vfio/{group}` (until the next rebind), or a \
                 udev rule: SUBSYSTEM==\"vfio\", OWNER=\"$USER\"."
            ),
            GroupNodeError::Busy => format!(
                "/dev/vfio/{group} is held by another process — usually a QEMU that \
                 is still running (`fuser -v /dev/vfio/{group}`)."
            ),
            GroupNodeError::Other(e) => format!("/dev/vfio/{group}: {e}"),
        },
        Blocker::MemlockTooLow { limit, need } => format!(
            "RLIMIT_MEMLOCK is {} KiB but VFIO pins all guest RAM: {} MiB needed. \
             Raise it for this shell (`sudo prlimit --pid $$ --memlock=unlimited`) \
             or persistently with `* - memlock unlimited` in \
             /etc/security/limits.d/ (new login).",
            limit / 1024,
            need >> 20
        ),
        Blocker::FirmwareDirectMapping { group, ranges } => format!(
            "IOMMU group {group} has firmware-mandated identity ranges ({}): the \
             platform's IOMMU table (AMD IVRS / Intel DMAR) requires this device \
             to stay 1:1 mapped, so Linux will not let VFIO give it to a guest. \
             Check firmware options (IOMMU, DMA protection) or a firmware update; \
             the kernel log says \"Firmware has requested this device have a 1:1 \
             IOMMU mapping\".",
            ranges.join(", ")
        ),
    }
}

/// One line per advisory.
pub fn note(a: &Advisory) -> String {
    match a {
        Advisory::SiblingFunctionNotPassed { bdf, sibling } => format!(
            "{bdf} is passed through but its sibling function {sibling} is not. \
             On an AMD GPU that is the HD-audio device; the guest will see a card \
             without it."
        ),
        Advisory::LargeBar { bdf, index, size } => format!(
            "{bdf} BAR{index} is {} MiB — Resizable BAR is probably enabled. The \
             size was read from the host now; firmware can change it between \
             boots, so re-run this check if the guest stops seeing the card.",
            size / (1 << 20)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_windows_describe_narf_page_tables() {
        // Two windows with a one-gigabyte hole between them, and nothing
        // above 1 TiB. If `mmu.rs` ever maps PDPT[0] or extends past
        // PML4[1], this table is what has to change with it.
        assert_eq!(BAR_WINDOWS.len(), 2);
        assert_eq!(BAR_WINDOWS[0].start, 0);
        assert_eq!(BAR_WINDOWS[0].end, 512 * GIB);
        assert_eq!(BAR_WINDOWS[1].start, 513 * GIB);
        assert_eq!(BAR_WINDOWS[1].end, 1024 * GIB);
        // The gap is exactly the skipped 1-GiB PDPT entry.
        assert_eq!(BAR_WINDOWS[1].start - BAR_WINDOWS[0].end, GIB);
    }

    #[test]
    fn a_bar_below_512_gib_is_reachable() {
        // Where a 32-bit BAR and QEMU's low MMIO hole live.
        assert_eq!(
            bar_verdict(0xF000_0000, 16 << 20),
            BarVerdict::Ok("low identity map")
        );
    }

    #[test]
    fn a_bar_in_the_high_window_is_reachable() {
        // Where OVMF parks 64-bit BARs on q35 with phys-bits=40: just
        // under 1 TiB.
        let base = 1000 * GIB;
        assert!(matches!(bar_verdict(base, 256 << 20), BarVerdict::Ok(_)));
    }

    #[test]
    fn the_skipped_gigabyte_is_reported_as_itself() {
        // This is the case nobody expects: inside PML4[1], but in the one
        // PDPT entry mmu.rs leaves unmapped for the user binary.
        assert_eq!(
            bar_verdict(512 * GIB, 256 << 20),
            BarVerdict::InSkippedGigabyte
        );
        // And the byte before and after behave differently, which is the
        // whole point of naming it.
        assert!(matches!(bar_verdict(511 * GIB, GIB), BarVerdict::Ok(_)));
        assert!(matches!(bar_verdict(513 * GIB, GIB), BarVerdict::Ok(_)));
    }

    #[test]
    fn above_a_terabyte_is_unmapped() {
        assert_eq!(
            bar_verdict(1024 * GIB, 256 << 20),
            BarVerdict::AboveMappedSpace
        );
        // `-cpu max` without the phys-bits clamp puts the hole here on a
        // host with a wide physical address width — the exact case the
        // clamp in `Arch::clamp_cpu_phys_bits` exists to prevent.
        assert_eq!(
            bar_verdict(14 * 1024 * GIB, 256 << 20),
            BarVerdict::AboveMappedSpace
        );
    }

    #[test]
    fn a_straddling_bar_is_worse_than_an_unreachable_one() {
        // Half-reachable: registers below the boundary answer and the ones
        // above fault, so the failure looks like a driver bug.
        assert_eq!(
            bar_verdict(512 * GIB - (128 << 20), 256 << 20),
            BarVerdict::Straddles
        );
        // And one that runs off the top of the high window.
        assert_eq!(
            bar_verdict(1024 * GIB - (128 << 20), 256 << 20),
            BarVerdict::AboveMappedSpace
        );
    }

    #[test]
    fn an_empty_bar_is_vacuously_fine() {
        assert_eq!(bar_verdict(0, 0), BarVerdict::Ok("empty"));
        // Even one nominally parked out of range.
        assert_eq!(bar_verdict(1 << 60, 0), BarVerdict::Ok("empty"));
    }

    #[test]
    fn resource_lines_parse_to_sizes() {
        // A 6750 XT's shape: 256 MiB BAR0, 2 MiB BAR2 (doorbell), an I/O
        // port BAR, and the 512 KiB register BAR5. Unimplemented BARs are
        // all-zero lines, which must read as size 0 rather than size 1.
        let text = "\
0x0000007000000000 0x000000700fffffff 0x0000000000140204
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000007010000000 0x00000070101fffff 0x0000000000140204
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000000000000e000 0x000000000000e0ff 0x0000000000040101
0x00000000fce00000 0x00000000fce7ffff 0x0000000000040200
";
        let bars = parse_resource(text);
        assert_eq!(bars.len(), 6);
        assert_eq!(bars[0].size(), 256 << 20);
        assert!(bars[0].is_64bit());
        assert_eq!(bars[1].size(), 0, "an all-zero line is an absent BAR");
        assert_eq!(bars[2].size(), 2 << 20);
        assert_eq!(bars[4].size(), 0x100);
        assert!(bars[4].is_io(), "bit 0 marks an I/O-port resource");
        assert!(
            !bars[4].is_64bit(),
            "an I/O BAR is never a 64-bit memory BAR"
        );
        assert_eq!(bars[5].size(), 512 << 10);
        assert!(!bars[5].is_64bit(), "the 32-bit register BAR");

        // Only the 64-bit memory BARs have to fit the guest's 64-bit hole.
        assert_eq!(total_64bit_bar_bytes(&bars), (256 << 20) + (2 << 20));
    }

    #[test]
    fn the_rom_and_sriov_windows_are_not_bars() {
        // Shape taken from a real `resource` file: index 6 is the expansion
        // ROM and index 7 an SR-IOV window. Both are 64-bit memory
        // resources by their flags, and counting them inflates the
        // footprint — which was this code's own bug until running it on a
        // host with an SR-IOV-capable iGPU showed a BAR7.
        let text = "\
0x0000013010000000 0x0000013010ffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000010000000000 0x000001000fffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x00000000000c0000 0x00000000000dffff 0x0000000000000212
0x0000013017000000 0x000001301dffffff 0x000000000014220c
";
        let bars = parse_resource(text);
        assert_eq!(bars.len(), 8);
        // BAR0 16 MiB + BAR2 256 MiB, and nothing else.
        assert_eq!(total_64bit_bar_bytes(&bars), (16 << 20) + (256 << 20));
        assert!(bars[6].size() > 0, "the ROM line is populated");
        assert!(!bars[6].is_64bit(), "index 6 is the expansion ROM");
        assert!(bars[7].size() > 0, "the SR-IOV line is populated");
        assert!(!bars[7].is_64bit(), "index 7 is an SR-IOV window");
        assert!(!bars[6].is_standard_bar() && !bars[7].is_standard_bar());
        assert!(bars[5].is_standard_bar(), "index 5 is the last real BAR");
    }

    #[test]
    fn the_window_limit_is_derived_from_the_page_tables() {
        // The low identity map is the larger of the two: 512 GiB against
        // the high window's 511. Derived, so moving either window in
        // `mmu.rs` moves the BarsTooLarge threshold with it.
        assert_eq!(largest_window_bytes(), 512 * GIB);
        assert_eq!(BAR_WINDOWS[1].end - BAR_WINDOWS[1].start, 511 * GIB);
    }

    #[test]
    fn a_rebar_sized_card_still_fits() {
        // 12 GiB of VRAM exposed through a resized BAR0, plus the doorbell
        // window. Fits with room to spare, so ReBAR is an advisory and not
        // a blocker.
        let bars = [
            HostBar {
                index: 0,
                start: 0,
                end: (16 << 30) - 1,
                flags: 0x140204,
            },
            HostBar {
                index: 2,
                start: 0,
                end: (2 << 20) - 1,
                flags: 0x140204,
            },
        ];
        let total = total_64bit_bar_bytes(&bars);
        assert!(total < largest_window_bytes());
        let (bdf, _) = (Bdf::parse("03:00.0").unwrap(), ());
        let (blockers, advisories) = bar_findings(&bdf, &bars);
        assert!(blockers.is_empty(), "{blockers:?}");
        assert_eq!(advisories.len(), 1, "only BAR0 is at or above a gigabyte");
    }

    #[test]
    fn the_worst_case_hole_is_anchored_at_the_ceiling() {
        // Top-anchored and rounded UP, so the check is pessimistic: a
        // 256 MiB footprint is treated as a full gigabyte.
        assert_eq!(worst_case_hole(256 << 20), (1024 * GIB - GIB, GIB));
        assert_eq!(worst_case_hole(16 * GIB), (1008 * GIB, 16 * GIB));
        // A real card's footprint lands comfortably inside the high window.
        let (base, size) = worst_case_hole(18 * GIB);
        assert!(matches!(bar_verdict(base, size), BarVerdict::Ok(_)));

        // The band where the placement check bites at all is exactly one
        // gigabyte wide: a footprint in (511, 512] GiB is small enough to
        // fit the largest window, yet top-anchored it starts inside the
        // gigabyte `mmu.rs` skips.
        let (base, size) = worst_case_hole(512 * GIB);
        assert_eq!((base, size), (512 * GIB, 512 * GIB));
        assert!(size <= largest_window_bytes(), "not BarsTooLarge");
        assert_eq!(bar_verdict(base, size), BarVerdict::InSkippedGigabyte);
        // One gigabyte smaller and it clears the hole entirely.
        let (base, size) = worst_case_hole(511 * GIB);
        assert!(matches!(bar_verdict(base, size), BarVerdict::Ok(_)));
    }

    #[test]
    fn a_card_too_big_for_any_window_is_a_blocker() {
        // 600 GiB exceeds the largest mapped window, so no placement QEMU
        // chooses can work and the size alone settles it.
        let bars = [HostBar {
            index: 0,
            start: 0,
            end: (600 * GIB) - 1,
            flags: 0x140204,
        }];
        let bdf = Bdf::parse("03:00.0").unwrap();
        let (blockers, _) = bar_findings(&bdf, &bars);
        assert!(
            matches!(blockers[0], Blocker::BarsTooLarge { .. }),
            "{blockers:?}"
        );
    }

    #[test]
    fn a_footprint_that_only_fails_on_placement_says_so() {
        // Exactly 512 GiB: it fits the largest window, so the size check
        // passes, and only the placement check sees that top-anchoring it
        // starts inside the skipped gigabyte.
        //
        // No real card is this size. The case is here because the gap in
        // NARF's page tables is structural — if `mmu.rs` ever maps PDPT[0],
        // this test is what records that the band closed.
        let bars = [HostBar {
            index: 0,
            start: 0,
            end: (512 * GIB) - 1,
            flags: 0x140204,
        }];
        let bdf = Bdf::parse("03:00.0").unwrap();
        let (blockers, _) = bar_findings(&bdf, &bars);
        assert!(
            matches!(
                blockers[0],
                Blocker::BarUnreachable {
                    verdict: BarVerdict::InSkippedGigabyte,
                    ..
                }
            ),
            "{blockers:?}"
        );
    }

    #[test]
    fn bdf_accepts_both_spellings_and_rejects_junk() {
        assert_eq!(Bdf::parse("03:00.0").unwrap().0, "0000:03:00.0");
        assert_eq!(Bdf::parse("0000:03:00.0").unwrap().0, "0000:03:00.0");
        assert_eq!(Bdf::parse(" 0a:1f.7 ").unwrap().0, "0000:0a:1f.7");
        // Shapes that would silently build a wrong sysfs path.
        assert!(Bdf::parse("3:0.0").is_none(), "fields are fixed-width");
        assert!(Bdf::parse("0000:03:00").is_none(), "no function");
        assert!(
            Bdf::parse("0000:03:00.00").is_none(),
            "function is one digit"
        );
        assert!(Bdf::parse("zzzz:03:00.0").is_none(), "hex only");
        assert!(Bdf::parse("").is_none());
    }

    #[test]
    fn a_bridge_in_the_group_is_not_a_stranger() {
        // The host's own root ports share groups with the devices behind
        // them. Treating a bridge as a stranger would make every real
        // passthrough look un-isolated.
        let gpu = Bdf::parse("03:00.0").unwrap();
        let members = vec![
            GroupMember {
                bdf: Bdf::parse("00:01.1").unwrap(),
                driver: Some("pcieport".into()),
                class_high: 0x06,
            },
            GroupMember {
                bdf: gpu.clone(),
                driver: Some("vfio-pci".into()),
                class_high: 0x03,
            },
        ];
        assert!(isolation_blockers("12", &members, &[gpu]).is_empty());
    }

    #[test]
    fn a_stranger_endpoint_blocks_even_with_no_driver() {
        // Unbound is still claimed: VFIO takes the whole group, so the
        // guest would get a device the host never released.
        let gpu = Bdf::parse("03:00.0").unwrap();
        let members = vec![
            GroupMember {
                bdf: gpu.clone(),
                driver: Some("vfio-pci".into()),
                class_high: 0x03,
            },
            GroupMember {
                bdf: Bdf::parse("03:00.1").unwrap(),
                driver: None,
                class_high: 0x04,
            },
        ];
        let out = isolation_blockers("12", &members, std::slice::from_ref(&gpu));
        assert_eq!(out.len(), 1);
        assert!(
            matches!(&out[0], Blocker::GroupNotIsolated { stranger, stranger_driver, .. }
                if stranger == "0000:03:00.1" && stranger_driver == "(none)"),
            "{out:?}"
        );
        // Passing both clears it, and then the sibling advisory is gone too.
        let both = vec![gpu, Bdf::parse("03:00.1").unwrap()];
        assert!(isolation_blockers("12", &members, &both).is_empty());
        assert!(sibling_advisories(&members, &both).is_empty());
    }

    #[test]
    fn a_left_behind_audio_function_is_advised() {
        let gpu = Bdf::parse("03:00.0").unwrap();
        let members = vec![
            GroupMember {
                bdf: gpu.clone(),
                driver: Some("vfio-pci".into()),
                class_high: 0x03,
            },
            GroupMember {
                bdf: Bdf::parse("03:00.1").unwrap(),
                driver: Some("vfio-pci".into()),
                class_high: 0x04,
            },
        ];
        let out = sibling_advisories(&members, &[gpu]);
        assert_eq!(out.len(), 1);
        assert!(matches!(
            &out[0],
            Advisory::SiblingFunctionNotPassed { sibling, .. } if sibling == "0000:03:00.1"
        ));
    }

    #[test]
    fn sibling_functions_are_recognised() {
        let gpu = Bdf::parse("03:00.0").unwrap();
        let audio = Bdf::parse("03:00.1").unwrap();
        let other = Bdf::parse("04:00.0").unwrap();
        assert!(gpu.same_device_as(&audio));
        assert!(audio.same_device_as(&gpu));
        assert!(!gpu.same_device_as(&other));
    }

    #[test]
    fn the_qemu_fragment_passes_every_function() {
        let devs = vec![
            Bdf::parse("03:00.0").unwrap(),
            Bdf::parse("03:00.1").unwrap(),
        ];
        let frag = qemu_fragment(&devs);
        assert_eq!(
            frag,
            "-device vfio-pci,host=0000:03:00.0 -device vfio-pci,host=0000:03:00.1"
        );
        // No x-vga: NARF drives the card itself and never needs legacy
        // VGA decode, which would additionally require the host to have
        // released the console.
        assert!(!frag.contains("x-vga"));
        assert_eq!(
            qemu_args(&devs),
            [
                "-device",
                "vfio-pci,host=0000:03:00.0",
                "-device",
                "vfio-pci,host=0000:03:00.1",
            ]
        );
    }

    #[test]
    fn bdf_from_str_normalises_case_and_domain() {
        assert_eq!(
            "AB:0C.D".parse::<Bdf>().unwrap(),
            Bdf("0000:ab:0c.d".into())
        );
        assert!("not-a-bdf".parse::<Bdf>().is_err());
    }

    #[test]
    fn memlock_must_cover_guest_ram_unless_root() {
        let ram = 4096u64 << 20;
        assert_eq!(
            memlock_blocker(Some(8 << 20), ram, false),
            Some(Blocker::MemlockTooLow {
                limit: 8 << 20,
                need: ram + MEMLOCK_SLACK,
            })
        );
        assert_eq!(memlock_blocker(None, ram, false), None);
        assert_eq!(memlock_blocker(Some(ram + MEMLOCK_SLACK), ram, false), None);
        // CAP_IPC_LOCK bypasses the limit.
        assert_eq!(memlock_blocker(Some(8 << 20), ram, true), None);
    }

    #[test]
    fn only_direct_reserved_regions_force_identity() {
        // The B650I's RX 6750 XT group: two IVMD unity ranges.
        let rx6750 = "0x000000008b06b000 0x000000008b06cfff direct\n\
                      0x0000000096035000 0x0000000096035fff direct\n\
                      0x00000000fee00000 0x00000000feefffff msi\n\
                      0x000000fd00000000 0x000000ffffffffff reserved\n";
        assert_eq!(
            direct_ranges(rx6750),
            vec![
                "0x000000008b06b000-0x000000008b06cfff".to_string(),
                "0x0000000096035000-0x0000000096035fff".to_string(),
            ]
        );
        let relaxable = "0x00000000000a0000 0x00000000000bffff direct-relaxable\n\
                         0x00000000fee00000 0x00000000feefffff msi\n";
        assert!(direct_ranges(relaxable).is_empty());
        assert!(direct_ranges("").is_empty());
    }

    #[test]
    fn memlock_limit_is_the_soft_column() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units     \n\
                      Max processes             127365               127365               processes \n\
                      Max locked memory         8388608              16777216             bytes     \n";
        assert_eq!(parse_memlock_limit(limits), Some(8 << 20));
        let unlimited =
            "Max locked memory         unlimited            unlimited            bytes\n";
        assert_eq!(parse_memlock_limit(unlimited), None);
    }

    #[test]
    fn navi22_needs_its_firmware_in_the_initramfs() {
        assert_eq!(
            firmware_globs_for(0x1002, 0x73df),
            &["amdgpu/navy_flounder*"]
        );
        // Its HD-audio function and unrelated cards need nothing.
        assert!(firmware_globs_for(0x1002, 0xab28).is_empty());
        assert!(firmware_globs_for(0x8086, 0x73df).is_empty());
    }
}
