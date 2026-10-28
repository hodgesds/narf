//! Composition census — the acceptance oracle for configurable
//! drivers (design of record: `narf-configurable-drivers-design.md`
//! §5.2 / §6, lane 1).
//!
//! Frame's boot flow composes the kernel by calling every linked
//! subsystem's `register_initcalls()`; the resulting registry
//! (`narf_init::registered_names`, per stage, in registration order)
//! is exactly the driver set a given build contains. [`capture`]
//! snapshots that set after the full boot init flow and before the
//! kernel-test harness runs any smoke, so a smoke's own registrations
//! (several suites register initcalls for their own purposes) can
//! never pollute the census or make it depend on test order.
//!
//! With `census_dump=1` on the kernel cmdline the snapshot is also
//! printed, one `census: <stage> <name>` line per initcall. That
//! dump is how the recorded baseline below was produced (pre-change
//! main, both arches), and how it is re-derived when a later lane
//! changes composition on purpose.
//!
//! The census fixture asserts the snapshot equals the recorded
//! baseline for this arch, minus the names owned by any driver group
//! the build's config left out (frame's `drivers-net` /
//! `drivers-storage` features gate those groups' registrations).
//! Habitat: the CI kernel-test invocation —
//! `cargo xtask test --features cgroup-all,container` (xtask itself
//! adds `kernel-test` + `module-allow-unsigned`), per
//! `.github/workflows/ci.yml`. The baseline is defined w.r.t. that
//! feature set: registrations gated on features it enables (e.g.
//! `narf-filesystem`'s `cgroup` / `cgroup-psi`, reached via frame's
//! `cgroup-all`) ARE part of the baseline, while optional one-off
//! features the test path never enables (e.g. the net facade's
//! `qemu-static-ipv4`, enabled only by QEMU run paths) are not.
//! A capture made without the CI feature set records a different,
//! smaller composition — see the correction note at the baseline
//! table below.

use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_lib::sync::IrqSafeSpinLock;

/// Boot-composition snapshot: registered initcall names per stage,
/// in registration (= execution) order.
static SNAPSHOT: IrqSafeSpinLock<Option<[Vec<&'static str>; 8]>> = IrqSafeSpinLock::new(None);

/// Snapshot the composed initcall registry. Called once, from the
/// kernel-test entry in `bare_main`, after boot init completes and
/// before the harness runs any smoke.
pub fn capture() {
    let snap: [Vec<&'static str>; 8] =
        core::array::from_fn(|i| narf_init::registered_names(narf_init::Stage::ALL[i]));
    if narf_boot::args().value("census_dump").is_some() {
        for (i, names) in snap.iter().enumerate() {
            let stage = narf_init::Stage::ALL[i].name();
            for name in names {
                let _ = writeln!(narf_console::Writer, "census: {stage} {name}");
            }
        }
    }
    *SNAPSHOT.lock() = Some(snap);
}

// ── recorded baseline ─────────────────────────────────────────────
//
// Recorded from the pre-change tree (origin/main 0712258a0 plus this
// file's capture code — the only change) via
// `cargo xtask test --arch <arch> --subsystem frame --kernel-tests-only`
// with `census_dump=1` on the kernel cmdline and
// `XTASK_QEMU_SERIAL_LOG` keeping the guest stream, 2026-10-26.
// x86_64: two independent boots produced byte-identical censuses.
//
// CORRECTION (2026-10-26, CI run 40372856800): the original capture
// omitted the CI kernel-test feature set (`--features
// cgroup-all,container`), so feature-gated registrations were
// missing from the table: the fs stage recorded 4 names where the
// CI-habitat build composes 6 — `narf-filesystem`'s `cgroupfs-mount`
// (`#[cfg(feature = "cgroup")]`) and `proc-pressure`
// (`#[cfg(feature = "cgroup-psi")]`) follow `procfs-mount`. Both
// registrations and their feature forwarding predate this lane and
// exist identically on pre-change main under the CI invocation;
// the composition did not drift, the capture habitat did. The fs
// entries below are corrected to the CI-habitat recording, and any
// future regeneration must pass the CI feature set (see the module
// header). Every other stage matched CI exactly as recorded.
//
// CORRECTION (2026-10-27, CI run 40423105253 on this branch's
// rebased head 7b89969d1): the baseline predates two merges that
// landed on main after the capture, so three registrations were
// missing from the table — Subsys recorded 151 where the snapshot
// composes 152, and Late recorded 63 where the snapshot composes
// 65. Each delta name is accounted for by a named, already-merged
// PR, verified against the registration sites on main: PR #1075
// (CCID devfs bridge) added `usb-ccid-devfs` at Subsys (between
// `usb-serial-devfs` and `usb-uac`, its registration order in
// `narf-drivers-usb`) and `usb-ccid-supervisor` at Late (directly
// after `usb-hid-supervisor`); PR #1040 (hwmon thresholds/pwm)
// added `hwmon-cooling` at Late (directly after
// `hwmon-sysfs-bridge`, its registration order in
// `narf-drivers-hwmon`). No other stage diverged, and no delta name
// is unaccounted for — the composition did not leak, the recorded
// baseline was stale by exactly those merges. The entries below
// are updated to the verified set; the fixture still asserts
// exact-set, exact-order equality.
//
// CORRECTION (2026-10-28, CI run 40671227858 on this branch's
// rebased head 262e83cf8): the baseline again predates merges
// that landed on main after the 2026-10-27 refresh — Subsys
// recorded 152 where the snapshot composes 154, and Late
// recorded 65 where the snapshot composes 68. Each delta name
// is accounted for by a named, already-merged PR, verified
// against the registration sites on main and the crate call
// order in frame's boot sequence: PR #1144 (WWAN CDC-MBIM)
// added `wwan-usb-mbim` at Subsys (snapshot index 81, directly
// before `ext-fs-factory`; `narf-drivers-wwan` registers it at
// drivers/wwan/src/lib.rs:182, and frame calls that crate after
// media, before the fs factories); PR #1105 (vendor laptop WMI
// surfaces) added `think-lmi` at Subsys (directly after
// `laptop-vendor-drivers` — the platform crate's last Subsys
// registration, drivers/platform/src/lib.rs:289) and
// `wmi-userspace-surfaces` at Late (directly after
// `power-service-wiring` — the platform crate's last Late
// registration, lib.rs:298); PR #1127 (SBS smart battery) added
// `acpi-sbs` at Late (directly before `power-service-wiring`,
// its registration order at lib.rs:204); PR #1137 (RTSX) added
// `rtsx-card-poll` at Late (snapshot index 5, directly before
// `usb-hid-supervisor`; the storage facade registers it at
// drivers/storage/src/lib.rs:111, and frame calls the facade
// after usbpd, before usb) — it is also added to
// STORAGE_GROUP_NAMES below, since the facade owns it. No
// other stage diverged, and no delta name is unaccounted for.
// The entries below are updated to the verified set; the
// fixture still asserts exact-set, exact-order equality.
// The recording is reality, not an ideal: on x86_64 the `arch` stage
// is empty and `ipmi`, `itco_wdt`, and `usb-r8152` each register
// twice at Subsys (pre-existing duplicate registrations; the census
// exists to surface exactly this kind of drift — fixing them is not
// this lane's scope).
//
// aarch64: NOT YET RECORDED. The capture run was interrupted twice
// by VM replacements; rather than ship an unverified table, the
// aarch64 baseline is `None` and the fixture Skips there with the
// reason. The recorded aarch64 table lands in a follow-up as soon as
// the capture completes — the regeneration procedure is the header
// comment at the top of this file.

#[cfg(target_arch = "x86_64")]
const BASELINE_X86_64: [&[&str]; 8] = [
    &["initramfs-stage", "luks-keyfile-provider"], // early: 2
    &["dmi-scan"],                                 // core: 1
    &["thermal-registry"],                         // postcore: 1
    &[],                                           // arch: 0
    &[
        "modules-abi",
        "modules-initramfs-autoload",
        "bpf-kfunc-registry",
        "bpf-percpu-stack",
        "input-event-ring",
        "nvme",
        "virtio-blk-pci",
        "virtio-net-pci",
        "virtio-rng-pci",
        "virtio-balloon-pci",
        "virtio-input-pci",
        "virtio-gpu-pci",
        "virtio-i2c-pci",
        "virtio-gpio-pci",
        "virtio-crypto-pci",
        "virtio-mem-pci",
        "virtio-pmem-pci",
        "virtio-video-pci",
        "virtio-snd-pci",
        "virtio-iommu-pci",
        "virtio-scsi-pci",
        "virtio-9p-pci",
        "virtio-fs-pci",
        "virtio-vsock-pci",
        "virtio-console-pci",
        "cxgb4",
        "e1000",
        "i40e",
        "realtek",
        "mlx5",
        "ixgbe",
        "igb",
        "igc",
        "rtl8139",
        "atheros",
        "tg3",
        "vmxnet3",
        "forcedeth",
        "bnxt",
        "enic",
        "iwlwifi",
        "mt76",
        "cyw43439",
        "rtl8xxxu",
        "rtlwifi",
        "rtw88",
        "rtw89",
        "brcmfmac",
        "ath11k",
        "ath10k",
        "ath9k",
        "i801-smbus",
        "piix4-smbus",
        "ahci",
        "megaraid",
        "smartpqi",
        "mpt3sas",
        "sdhci",
        "rtsx",
        "usb-serial-devfs",
        "usb-ccid-devfs",
        "usb-uac",
        "usb-uvc",
        "usb-r8152",
        "usb-cdc-ncm",
        "usb-msc",
        "usb-xpad",
        "xhci",
        "ehci",
        "ohci",
        "uhci",
        "usb-hid-vendor-quirks",
        "usb-r8152",
        "video-devfs",
        "intel-ipu3-pci",
        "intel-ipu6-pci",
        "amd-mp2-isp-pci",
        "video-imx219",
        "media-cec-gpio",
        "media-rtl2832",
        "media-tc358743",
        "wwan-usb-mbim",
        "ext-fs-factory",
        "ext4-fs-features",
        "fat-fs-factory",
        "squashfs-factory",
        "btrfs-factory",
        "alienware-wmi",
        "surface-acpi",
        "system76-acpi",
        "smbus",
        "tpm",
        "acpi-ec",
        "acpi-battery",
        "acpi-ac-adapter",
        "acpi-thermal",
        "acpi-fan",
        "acpi-lid",
        "acpi-buttons",
        "acpi-ec-hotkeys",
        "acpi-backlight",
        "intel-hid",
        "amd-asf",
        "ipmi",
        "itco_wdt",
        "mei-me",
        "intel_vsec",
        "proc_thermal",
        "amd-aoac",
        "wmi-vendors",
        "laptop-vendor-drivers",
        "think-lmi",
        "hwmon-k10temp",
        "hwmon-nct6775",
        "hwmon-it87",
        "hwmon-coretemp",
        "hwmon-applesmc",
        "hwmon-dell-smm",
        "hwmon-jc42",
        "serial-8250",
        "serial-lpss",
        "serial-pci",
        "serial-acpi",
        "serial-pl011",
        "intel-spi-flash",
        "bochs-display",
        "amdgpu-pci",
        "aspeed-pci",
        "intel-gpu-pci",
        "nvidia-gpu-pci",
        "qxl-gpu-pci",
        "vmware-svga-pci",
        "nvidia-pci",
        "fb-amdgpu-handoff-register",
        "fb-syscall-vtable",
        "fb-exit-observer",
        "hda-pci",
        "acp6-pci",
        "acp63-sdw-pci",
        "btintel-pcie",
        "s3-resume-hook",
        "cpu-pstate",
        "watchdog-bridge",
        "intel-npu",
        "shmem-syscall-vtable",
        "shmem-exit-observer",
        "firmware-init",
        "fw_cfg-probe",
        "csprng-seed",
        "rtl8xxxu-usb-ids",
        "ipmi",
        "itco_wdt",
        "pl011",
        "psmouse",
    ], // subsys: 154
    &[
        "modules-sysfs",
        "devfs-mount",
        "devshm-mount",
        "procfs-mount",
        "cgroupfs-mount",
        "proc-pressure",
    ], // fs: 6
    &[
        "amd-fch-gpio",
        "intel-pch-gpio",
        "amd-fch-i2c",
        "lpss-i2c",
        "intel-vmd",
        "usb4-nhi",
        "fingerprint",
        "amd-fch-spi",
        "intel-lpss-spi",
        "cadence-spi",
        "pl022-spi",
        "gpu-backlight",
        "i2c-hid-probe",
        "i2c-hid-bind",
        "hid-multitouch",
        "i8042-kbd",
        "i8042-mouse",
        "psmouse-extensions",
        "pci-probe-all",
        "jc42",
    ], // device: 20
    &[
        "bpf-leds/worker",
        "virtio-input-pump",
        "virtio-mem-config-pump",
        "usbpd-ucsi-acpi",
        "usbpd-tcpc-probe",
        "rtsx-card-poll",
        "usb-hid-supervisor",
        "usb-ccid-supervisor",
        "usb4-native-cm",
        "fat-bootlog",
        "btrfs-crash-check",
        "acpi-sbs",
        "power-service-wiring",
        "wmi-userspace-surfaces",
        "hwmon-sysfs-bridge",
        "hwmon-cooling",
        "intel-gpu-dp-bridge",
        "amdgpu-usbc",
        "virtio-gpu-drm-card",
        "bochs-drm-card",
        "drm-devfs-bridge",
        "drm-sysfs-bridge",
        "fb-scanout-picker",
        "fb-external-scanout",
        "drm-fb-hook",
        "fb-drain-task",
        "fb-status-refresh",
        "fb-cursor-pump",
        "fb-client-demo",
        "fb-devfs",
        "native-audio-devices",
        "audio-playback-picker",
        "bluetooth-stage0",
        "bluetooth-pump",
        "bluetooth-devfs",
        "bluetooth-sysfs",
        "bluetooth-mgmt",
        "power-monitor",
        "acpi-battery-enum",
        "acpi-thermal-enum",
        "power-button-orderly-poweroff",
        "power-service",
        "acpi-ac-enum",
        "power-sysfs-bridge",
        "cpufreq-init",
        "initramfs-mount-at-boot",
        "firmware-scan-initramfs",
        "firmware-scan-rootfs",
        "btintel-pcie-firmware",
        "rtl8127-phy-firmware",
        "bluetooth-bringup",
        "measured-boot",
        "fb-console-install",
        "fb-wc-remap",
        "root-mount-auto",
        "root-mount-settled",
        "btrfs-rootrw-interop",
        "efi-system-partition-mount",
        "mnt-mount-ext2",
        "btrfs-disk-smoke",
        "btrfs-write-smoke",
        "sysfs-input-class",
        "sysfs-tty-class",
        "sysfs-block-class",
        "mnt-dev-bind",
        "virtio-gpu-splash",
        "mt76-firmware",
        "amdgpu-discrete-firmware",
    ], // late: 68
];

/// The recorded baseline for the running arch, if one has been
/// recorded yet (see above).
#[cfg(target_arch = "x86_64")]
const BASELINE: Option<&[&[&str]; 8]> = Some(&BASELINE_X86_64);
#[cfg(target_arch = "aarch64")]
const BASELINE: Option<&[&[&str]; 8]> = None;

// ── group-owned names ─────────────────────────────────────────────

/// Names the net facade registers when frame's `drivers-net` group
/// is selected: the fifteen per-driver Subsys registrations from
/// `narf_drivers_net::register_initcalls` (in the facade's own
/// order) plus the Late RTL8127 PHY-firmware patch from
/// `register_late_firmware_initcalls`. Must follow the facade; if a
/// driver is added there, add its name here *and* regenerate the
/// baseline in the same change — the fixture failing is the
/// reminder. (`qemu-static-ipv4` is absent on purpose: only QEMU
/// run paths enable that facade feature, never the test path.)
const NET_GROUP_NAMES: &[&str] = &[
    "cxgb4",
    "e1000",
    "i40e",
    "realtek",
    "mlx5",
    "ixgbe",
    "igb",
    "igc",
    "rtl8139",
    "atheros",
    "tg3",
    "vmxnet3",
    "forcedeth",
    "bnxt",
    "enic",
    "rtl8127-phy-firmware",
];

/// Names the storage facade registers when frame's
/// `drivers-storage` group is selected: six Subsys registrations,
/// the Late RTSX card-detect poll, and the Device-stage VMD
/// registration, from `narf_drivers_storage::register_initcalls`.
/// Same maintenance rule as `NET_GROUP_NAMES`.
const STORAGE_GROUP_NAMES: &[&str] = &[
    "ahci",
    "megaraid",
    "smartpqi",
    "mpt3sas",
    "sdhci",
    "rtsx",
    "rtsx-card-poll",
    "intel-vmd",
];

// ── the fixture ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Composition census: the boot-composed initcall set must equal
/// the recorded baseline for this arch, minus the names owned by
/// any driver group this build's config left out. Exact, ordered,
/// per stage — registration order is execution order, so a
/// reordering is a composition change too. On mismatch the first
/// divergence per stage is printed (`census-mismatch:` lines)
/// before failing.
fn smoke_composition_census_matches_baseline() -> TestResult {
    let Some(baseline) = BASELINE else {
        return TestResult::Skip("no recorded composition baseline for this arch yet");
    };
    let Some(snap) = SNAPSHOT.lock().clone() else {
        return TestResult::Fail(
            "census snapshot missing — capture() did not run before the harness",
        );
    };
    let net_on = cfg!(feature = "drivers-net");
    let storage_on = cfg!(feature = "drivers-storage");
    let mut mismatch = false;
    for (i, stage) in narf_init::Stage::ALL.iter().enumerate() {
        let expected: Vec<&str> = baseline[i]
            .iter()
            .copied()
            .filter(|n| net_on || !NET_GROUP_NAMES.contains(n))
            .filter(|n| storage_on || !STORAGE_GROUP_NAMES.contains(n))
            .collect();
        if snap[i].iter().ne(expected.iter()) {
            mismatch = true;
            let _ = writeln!(
                narf_console::Writer,
                "census-mismatch: stage {} — baseline-derived expectation has {} initcalls, snapshot has {}",
                stage.name(),
                expected.len(),
                snap[i].len()
            );
            for (j, (want, got)) in expected.iter().zip(snap[i].iter()).enumerate() {
                if want != got {
                    let _ = writeln!(
                        narf_console::Writer,
                        "census-mismatch: {}[{j}]: expected {want}, snapshot has {got}",
                        stage.name()
                    );
                    break;
                }
            }
        }
    }
    if mismatch {
        return TestResult::Fail(
            "composition census differs from the recorded baseline (see census-mismatch lines)",
        );
    }
    TestResult::Pass
}
kernel_test_in!("frame/census", smoke_composition_census_matches_baseline);
