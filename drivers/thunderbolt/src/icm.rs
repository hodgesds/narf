//! Legacy ICM (firmware connection manager) coexistence: detection
//! and stand-down. **No ICM protocol lives here, by design.**
//!
//! On Thunderbolt 3-era hosts the host controller's firmware runs
//! its own connection manager (ICM) and owns the fabric: it
//! enumerates routers and programs tunnels itself, and the OS is
//! expected to talk to the firmware, not to the routers. This crate
//! implements only the software (native) CM. If the native CM
//! started ring 0 on such a host it would fight the firmware for
//! the same routers, so `runtime::start` asks each controller's
//! firmware status first and stands down for every controller the
//! firmware owns — before ring 0 starts, and before the platform
//! `_OSC` request when no controller is native at all.
//!
//! Standing down is a first-class outcome, not an error: the domain
//! is logged, its verdict is published through [`domain_statuses`],
//! and the rest of the system behaves exactly as if no native USB4
//! CM existed for that controller (no ring, no config traffic, no
//! device-PM registration earned by it).
//!
//! ## The detection signal
//!
//! One register, read-only for us: `REG_FW_STS` in the NHI MMIO
//! block (Linux `drivers/thunderbolt/nhi_regs.h`). Bit 0
//! (`REG_FW_STS_ICM_EN`) is the firmware's own statement that the
//! ICM is enabled; Linux's `icm_firmware_running()`
//! (`drivers/thunderbolt/icm.c`) discriminates on exactly this bit.
//! Bit 31 (`REG_FW_STS_NVM_AUTH_DONE`) records that the firmware
//! authenticated its NVM and finished booting; it is reported in
//! the verdict for operator context but never decides the mode —
//! it sets on software-CM hosts too while the link firmware boots.
//!
//! Two tempting non-signals are deliberately not used:
//!
//! - `REG_CAPS` version: Falcon Ridge onward — ICM and native
//!   controllers alike — report version 2 (`0x40`). It says which
//!   NHI register shape this is, not who manages the fabric.
//! - PCI identity: this crate binds NHIs by the USB4 class code,
//!   which firmware-managed controllers also present. Identity
//!   says what the silicon is, not which CM is running.
//!
//! ## Settle rule (ambiguity fails toward standing down)
//!
//! Firmware state is sampled, not read once: [`detect`] collects
//! up to [`MAX_SAMPLES`] samples spaced [`SAMPLE_GAP_MS`] apart and
//! stops as soon as two consecutive samples agree. [`classify`]
//! turns the samples into a verdict:
//!
//! - Settled with `ICM_EN` set → [`CmMode::FirmwareManaged`]
//!   (including firmware still authenticating: `ICM_EN` set with
//!   `NVM_AUTH_DONE` clear means the firmware owns the fabric and
//!   is still booting it).
//! - Settled with `ICM_EN` clear → [`CmMode::Native`] (including a
//!   hand-off that settles native: ICM released the fabric before
//!   the samples settled, which is the firmware's way of handing
//!   the domain to the OS).
//! - Samples never agree → [`CmMode::Unsettled`]: the fabric is
//!   mid-transition; stand down.
//! - Nothing readable (every sample a failed read or the all-ones
//!   pattern of a function that is not answering) →
//!   [`CmMode::Unreadable`]: stand down.
//!
//! ## What detection never does
//!
//! Detection is reads only. The remaining `REG_FW_STS` bits —
//! `ICM_EN_INVERT` (bit 1), `ICM_EN_CPU` (bit 2) and
//! `CIO_RESET_REQ` (bit 30) — are the host-writable controls Linux
//! uses to *start or reset* ICM firmware, and the ICM mailbox
//! registers (`REG_INMAIL_DATA` `0x39900`, `REG_INMAIL_CMD`
//! `0x39904`, `REG_OUTMAIL_CMD` `0x3990c` in `nhi_regs.h`) are how
//! an OS would *speak* to it. Starting, resetting or speaking to
//! ICM is the ICM protocol this lane does not implement, so none of
//! those are ever written or posted from here.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::nhi::Nhi;

/// `REG_FW_STS` — NHI firmware status register. Linux
/// `drivers/thunderbolt/nhi_regs.h`: `#define REG_FW_STS 0x39944`.
pub const REG_FW_STS: u64 = 0x39944;
/// `REG_FW_STS_ICM_EN` (bit 0): the ICM firmware is enabled and
/// owns the fabric. The discriminator Linux's
/// `icm_firmware_running()` (`icm.c`) tests.
pub const FW_STS_ICM_EN: u32 = 1 << 0;
/// `REG_FW_STS_ICM_EN_INVERT` (bit 1): host-writable ICM-start
/// control. Named so fixtures can pin the layout; never written.
pub const FW_STS_ICM_EN_INVERT: u32 = 1 << 1;
/// `REG_FW_STS_ICM_EN_CPU` (bit 2): host-writable ICM-start
/// control. Named so fixtures can pin the layout; never written.
pub const FW_STS_ICM_EN_CPU: u32 = 1 << 2;
/// `REG_FW_STS_CIO_RESET_REQ` (bit 30): host-writable reset
/// request toward the firmware. Never written.
pub const FW_STS_CIO_RESET_REQ: u32 = 1 << 30;
/// `REG_FW_STS_NVM_AUTH_DONE` (bit 31): the NHI firmware
/// authenticated its NVM and finished booting. Reported for
/// context; sets on native hosts too, so it never decides a mode.
pub const FW_STS_NVM_AUTH_DONE: u32 = 1 << 31;

/// Most firmware-status samples one detection pass collects.
pub const MAX_SAMPLES: usize = 8;
/// Spacing between detection samples. Detection runs in the
/// synchronous Late initcall; the whole pass is bounded by
/// `(MAX_SAMPLES - 1) * SAMPLE_GAP_MS` of responsive spinning, and
/// the common settled case costs a single gap.
pub const SAMPLE_GAP_MS: u64 = 5;

/// Who manages one controller's fabric, as decided by detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmMode {
    /// Software connection manager (this crate) owns the fabric:
    /// firmware status settled with `ICM_EN` clear.
    Native,
    /// The firmware connection manager (legacy ICM) owns the
    /// fabric: firmware status settled with `ICM_EN` set. The
    /// native CM stands down for this controller.
    FirmwareManaged,
    /// Firmware status never settled during the sampling window
    /// (the fabric is mid-transition). The native CM stands down:
    /// ambiguity fails toward not fighting firmware.
    Unsettled,
    /// Firmware status could not be read at all (aperture too
    /// small, capability revoked, or the function answers with the
    /// all-ones pattern of a device that is not there). The native
    /// CM stands down.
    Unreadable,
}

impl CmMode {
    /// Whether the native CM must keep away from this controller.
    pub fn stands_down(self) -> bool {
        !matches!(self, Self::Native)
    }
}

/// Detection outcome for one controller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The decided mode.
    pub mode: CmMode,
    /// The settled `REG_FW_STS` value for
    /// [`CmMode::Native`]/[`CmMode::FirmwareManaged`]; for the
    /// stand-down modes, the last non-all-ones value observed, if
    /// any.
    pub fw_sts: Option<u32>,
}

/// Classify a sequence of firmware-status samples into a verdict.
///
/// Each sample is `Some(value)` for a completed register read or
/// `None` for a read that could not be performed. The first pair
/// of consecutive equal, non-all-ones samples settles the verdict.
/// A run of only failed/all-ones samples is
/// [`CmMode::Unreadable`]; anything else that never settles is
/// [`CmMode::Unsettled`]. Pure: the sampler in [`detect`] and the
/// fixtures both drive this function.
pub fn classify(samples: &[Option<u32>]) -> Verdict {
    for pair in samples.windows(2) {
        if let (Some(a), Some(b)) = (pair[0], pair[1]) {
            if a == b && a != u32::MAX {
                return Verdict {
                    mode: if a & FW_STS_ICM_EN != 0 {
                        CmMode::FirmwareManaged
                    } else {
                        CmMode::Native
                    },
                    fw_sts: Some(a),
                };
            }
        }
    }
    let observed = samples.iter().rev().find_map(|s| match s {
        Some(v) if *v != u32::MAX => Some(*v),
        _ => None,
    });
    match observed {
        // Something real was read but it would not sit still.
        Some(v) => Verdict {
            mode: CmMode::Unsettled,
            fw_sts: Some(v),
        },
        // Nothing but failed reads and all-ones answers (or no
        // samples at all): there is no status to trust.
        None => Verdict {
            mode: CmMode::Unreadable,
            fw_sts: None,
        },
    }
}

/// One controller's recorded detection outcome, published by
/// `runtime::start` for every controller it was offered —
/// including the ones it stood down for, so "firmware-managed" is
/// queryable state rather than an absence to be inferred.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainStatus {
    /// Domain index (the controller's position in probe order).
    pub domain: u32,
    /// The decided mode.
    pub mode: CmMode,
    /// The verdict's firmware-status value, when one was observed.
    pub fw_sts: Option<u32>,
}

static STATUSES: IrqSafeSpinLock<Vec<DomainStatus>> = IrqSafeSpinLock::new(Vec::new());
/// Controllers detection classified [`CmMode::FirmwareManaged`]
/// since boot (or the last test reset).
static FIRMWARE_MANAGED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Record one controller's verdict. Called by `runtime::start`
/// for every retained controller, native or stood down.
pub(crate) fn record(domain: u32, verdict: Verdict) {
    if verdict.mode == CmMode::FirmwareManaged {
        FIRMWARE_MANAGED_COUNT.fetch_add(1, Ordering::AcqRel);
    }
    STATUSES.lock().push(DomainStatus {
        domain,
        mode: verdict.mode,
        fw_sts: verdict.fw_sts,
    });
}

/// Snapshot of every recorded controller outcome, in probe order.
pub fn domain_statuses() -> Vec<DomainStatus> {
    STATUSES.lock().clone()
}

/// How many controllers firmware manages (native CM stood down).
pub fn firmware_managed_count() -> u32 {
    FIRMWARE_MANAGED_COUNT.load(Ordering::Acquire)
}

#[doc(hidden)]
/// Test-only: clear the recorded outcomes between smokes. The boot
/// path never calls this.
pub fn __reset_for_test() {
    STATUSES.lock().clear();
    FIRMWARE_MANAGED_COUNT.store(0, Ordering::Release);
}

/// Sample `REG_FW_STS` on one controller and classify the result.
///
/// Reads go through the controller's bus capability (the same
/// `IoOp` epoch check every other Late-stage MMIO access in this
/// crate uses), so a revoked capability degrades to
/// [`CmMode::Unreadable`] instead of touching the device. Reads
/// only: nothing in the NHI aperture is written here.
///
/// # Safety posture
/// The caller owns the controller (probe retained it for the CM).
/// The register offset is bounds-checked against the BAR before
/// the first read.
pub(crate) fn detect(cap: &Cap<BusDeviceCap, Write>, nhi: &Nhi) -> Verdict {
    if nhi.bar0.len < REG_FW_STS + 4 {
        // The aperture does not even cover the status register:
        // there is no status to trust, so stand down.
        return Verdict {
            mode: CmMode::Unreadable,
            fw_sts: None,
        };
    }
    let bar: MmioRegion = nhi.bar0;
    let mut samples: Vec<Option<u32>> = Vec::new();
    loop {
        // SAFETY: `REG_FW_STS + 4` verified inside the BAR above;
        // REG_FW_STS is a read-only firmware status register whose
        // read has no side effects (Linux reads it the same way in
        // `icm_firmware_running`). Invoked under the bus
        // capability that owns this PCI function.
        let sample = cap
            .invoke(super::ring::IoOp(|| unsafe { bar.read32(REG_FW_STS) }))
            .ok();
        samples.push(sample);
        let n = samples.len();
        if n >= 2 && samples[n - 1] == samples[n - 2] {
            // Two consecutive identical answers (including two
            // failed reads): further samples cannot change the
            // classification, so stop early.
            break;
        }
        if n >= MAX_SAMPLES {
            break;
        }
        narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ms(SAMPLE_GAP_MS),
        );
    }
    classify(&samples)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const EN: u32 = FW_STS_ICM_EN;
    const AUTH: u32 = FW_STS_NVM_AUTH_DONE;

    fn usb4_icm_fw_sts_layout_matches_nhi_regs() -> TestResult {
        // Layout pinned against Linux `drivers/thunderbolt/
        // nhi_regs.h`: REG_FW_STS at 0x39944, ICM_EN bit 0,
        // ICM_EN_INVERT bit 1, ICM_EN_CPU bit 2, CIO_RESET_REQ
        // bit 30, NVM_AUTH_DONE bit 31. A future edit that shifts
        // any of these makes detection read the wrong bit and
        // either fight firmware or stand down on native hosts.
        if REG_FW_STS != 0x39944
            || FW_STS_ICM_EN != 1 << 0
            || FW_STS_ICM_EN_INVERT != 1 << 1
            || FW_STS_ICM_EN_CPU != 1 << 2
            || FW_STS_CIO_RESET_REQ != 1 << 30
            || FW_STS_NVM_AUTH_DONE != 1 << 31
        {
            return TestResult::Fail("thunderbolt: REG_FW_STS layout mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/icm",
        usb4_icm_fw_sts_layout_matches_nhi_regs
    );

    fn usb4_icm_classify_settled_worlds() -> TestResult {
        // The two host classes from the specifications, plus the
        // firmware-still-booting sub-state: ICM_EN set decides
        // firmware ownership whether or not NVM authentication has
        // completed yet.
        let cases: &[(&[Option<u32>], CmMode)] = &[
            (&[Some(EN | AUTH), Some(EN | AUTH)], CmMode::FirmwareManaged),
            (&[Some(EN), Some(EN)], CmMode::FirmwareManaged),
            (&[Some(AUTH), Some(AUTH)], CmMode::Native),
            (&[Some(0), Some(0)], CmMode::Native),
        ];
        for (samples, want) in cases {
            let v = classify(samples);
            if v.mode != *want || v.fw_sts != samples[0] {
                return TestResult::Fail("thunderbolt: settled-world classification wrong");
            }
            if v.mode.stands_down() != (*want != CmMode::Native) {
                return TestResult::Fail("thunderbolt: stands_down disagrees with mode");
            }
        }
        // A single sample settles nothing — the sampler always
        // takes at least two, and a lone value must not be trusted
        // into starting ring 0.
        if classify(&[Some(0)]).mode != CmMode::Unsettled
            || classify(&[Some(EN)]).mode != CmMode::Unsettled
        {
            return TestResult::Fail("thunderbolt: single sample settled a verdict");
        }
        if classify(&[]).mode != CmMode::Unreadable {
            return TestResult::Fail("thunderbolt: no samples must be unreadable");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/icm", usb4_icm_classify_settled_worlds);

    fn usb4_icm_classify_only_icm_en_decides() -> TestResult {
        // Masking-defeating: set every other documented FW_STS
        // bit, and a block of undocumented middle bits, and vary
        // only ICM_EN. The verdict must track bit 0 alone —
        // NVM_AUTH_DONE in particular sets on native hosts too.
        // One middle bit (16) stays clear in the sweep block:
        // with literally every other bit set, the ICM_EN case
        // would compose to `u32::MAX` — the all-ones pattern
        // `classify` reserves for a function that is not
        // answering (module docs, settle rule), so it can never
        // settle as a firmware status at all. Holding one bit
        // clear keeps this sweep about ICM_EN alone.
        let others = FW_STS_NVM_AUTH_DONE
            | FW_STS_CIO_RESET_REQ
            | FW_STS_ICM_EN_CPU
            | FW_STS_ICM_EN_INVERT
            | (0x3fff_fff8 & !(1 << 16));
        if classify(&[Some(others), Some(others)]).mode != CmMode::Native {
            return TestResult::Fail("thunderbolt: non-ICM_EN bits swayed the verdict");
        }
        let with_en = others | FW_STS_ICM_EN;
        if classify(&[Some(with_en), Some(with_en)]).mode != CmMode::FirmwareManaged {
            return TestResult::Fail("thunderbolt: ICM_EN lost among other bits");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/icm",
        usb4_icm_classify_only_icm_en_decides
    );

    fn usb4_icm_classify_transitions() -> TestResult {
        // Hand-off in both directions: what matters is the state
        // the samples settle into, not the state they started in.
        // Firmware takes over mid-window → firmware-managed.
        if classify(&[Some(0), Some(EN), Some(EN)]).mode != CmMode::FirmwareManaged {
            return TestResult::Fail("thunderbolt: hand-off to firmware missed");
        }
        // Firmware releases the fabric before the window closes
        // (the preboot-services hand-off) → native.
        if classify(&[Some(EN), Some(0), Some(0)]).mode != CmMode::Native {
            return TestResult::Fail("thunderbolt: hand-off to native missed");
        }
        // Authentication completing mid-window: ICM_EN stable, the
        // AUTH bit flips once, then the value settles.
        if classify(&[Some(EN), Some(EN | AUTH), Some(EN | AUTH)]).mode != CmMode::FirmwareManaged {
            return TestResult::Fail("thunderbolt: auth completion unsettled the verdict");
        }
        // A fabric that will not sit still never settles, and an
        // undecided fabric is stood down from.
        if classify(&[Some(0), Some(EN), Some(0), Some(EN), Some(0), Some(EN)]).mode
            != CmMode::Unsettled
        {
            return TestResult::Fail("thunderbolt: oscillating status settled");
        }
        // Dead-function shapes: failed reads, and the all-ones
        // pattern of a function that is not answering. Neither is
        // a firmware status anyone may act on natively.
        if classify(&[None, None]).mode != CmMode::Unreadable
            || classify(&[Some(u32::MAX), Some(u32::MAX)]).mode != CmMode::Unreadable
        {
            return TestResult::Fail("thunderbolt: dead-function status trusted");
        }
        // Real values interleaved with dead reads never form a
        // consecutive pair, so they cannot settle either.
        if classify(&[None, Some(EN), None, Some(EN)]).mode != CmMode::Unsettled {
            return TestResult::Fail("thunderbolt: interleaved dead reads settled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/icm", usb4_icm_classify_transitions);

    // ── Startup fixtures ────────────────────────────────────────
    //
    // These drive the production startup path end to end: a
    // fabricated NHI over a memory-backed BAR is retained exactly
    // as probe retains it, then `runtime::start` runs. The backing
    // array doubles as the write log — any write anywhere in the
    // NHI aperture during startup changes it, so comparing the
    // array afterwards asserts the brief's "zero config writes"
    // literally, across detection and everything that follows.

    use narf_bus::{BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use narf_capabilities::Cap;
    use narf_memory::PhysAddr;

    /// BAR aperture size used by the fixtures (matches `ring.rs`).
    const MODEL_LEN: usize = 0x3a000;

    fn model_bar(storage: &mut [u32], fw_sts: u32) -> MmioRegion {
        storage[(REG_CAPS_DWORD) as usize] = (0x40 << 16) | 16;
        storage[(REG_FW_STS / 4) as usize] = fw_sts;
        MmioRegion {
            phys: PhysAddr::new(0),
            virt: storage.as_mut_ptr() as u64,
            len: MODEL_LEN as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        }
    }

    /// Dword index of `REG_CAPS` within the model BAR.
    const REG_CAPS_DWORD: u64 = 0x39640 / 4;

    fn model_device(vendor: u16, device: u16) -> BusDevice {
        let addr = PcieAddr::new(0, 0, 0x0D, 0);
        BusDevice {
            addr: BusAddr::Pcie(addr),
            id: DeviceId {
                vendor,
                device,
                class: 0x0C0340,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr,
                cfg_phys: PhysAddr::new(0),
            },
        }
    }

    fn model_nhi(bar: MmioRegion, device_id: u16, sku: &'static str) -> Nhi {
        Nhi {
            device_id,
            sku,
            bar0: bar,
            nhi_version: 0x40,
            hop_count: 16,
        }
    }

    fn pm_names() -> Vec<alloc::string::String> {
        narf_power::device_pm::registered_devices()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    fn usb4_icm_startup_stands_down_firmware_managed() -> TestResult {
        __reset_for_test();
        let pm_before = pm_names();
        let mut storage = alloc::vec![0u32; MODEL_LEN / 4];
        let bar = model_bar(&mut storage, EN | AUTH);
        let before = storage.clone();
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        crate::runtime::retain(
            model_device(0x8086, 0x9A1B),
            cap,
            model_nhi(bar, 0x9A1B, "tgl-nhi0"),
        );
        // Firmware owns this fabric: startup must stop at the ICM
        // gate — no native CM, no `_OSC` bid for a fabric it will
        // not drive, no device-PM registration.
        if crate::runtime::start() != narf_init::InitResult::NotPresent {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: ICM host started a native CM");
        }
        let statuses = domain_statuses();
        let ok = statuses.len() == 1
            && statuses[0].domain == 0
            && statuses[0].mode == CmMode::FirmwareManaged
            && statuses[0].fw_sts == Some(EN | AUTH)
            && firmware_managed_count() == 1;
        if !ok {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: ICM stand-down not recorded");
        }
        if storage != before {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: startup wrote to a firmware-managed NHI");
        }
        if pm_names() != pm_before {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: stood-down CM joined the device-PM fan-out");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/icm",
        usb4_icm_startup_stands_down_firmware_managed
    );

    fn usb4_icm_startup_stands_down_unreadable() -> TestResult {
        __reset_for_test();
        // The whole aperture answers all-ones: the function is
        // not really there. Partial/absent state must fail toward
        // standing down, never toward starting ring 0 blind.
        let mut storage = alloc::vec![u32::MAX; MODEL_LEN / 4];
        let bar = model_bar(&mut storage, u32::MAX);
        let before = storage.clone();
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        crate::runtime::retain(
            model_device(0x8086, 0x9A1D),
            cap,
            model_nhi(bar, 0x9A1D, "tgl-nhi1"),
        );
        if crate::runtime::start() != narf_init::InitResult::NotPresent {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: unreadable NHI started a native CM");
        }
        let statuses = domain_statuses();
        let ok = statuses.len() == 1 && statuses[0].mode == CmMode::Unreadable;
        if !ok {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: unreadable stand-down not recorded");
        }
        if storage != before {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: startup wrote to an unreadable NHI");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/icm",
        usb4_icm_startup_stands_down_unreadable
    );

    fn usb4_icm_startup_native_passes_the_gate() -> TestResult {
        __reset_for_test();
        // A software-CM host: firmware authenticated, ICM not
        // enabled. The ICM gate must let the domain through to the
        // ordinary `_OSC` gate, which is what stops it on the QEMU
        // smoke target (no USB4 `_OSC` grant there) — the recorded
        // mode proves which gate decided.
        let mut storage = alloc::vec![0u32; MODEL_LEN / 4];
        let bar = model_bar(&mut storage, AUTH);
        let before = storage.clone();
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        crate::runtime::retain(
            model_device(0x8086, 0x463E),
            cap,
            model_nhi(bar, 0x463E, "adl-nhi0"),
        );
        if crate::runtime::start() != narf_init::InitResult::NotPresent {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: native domain unexpectedly started on QEMU");
        }
        let statuses = domain_statuses();
        let ok = statuses.len() == 1
            && statuses[0].mode == CmMode::Native
            && statuses[0].fw_sts == Some(AUTH)
            && firmware_managed_count() == 0;
        if !ok {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: native domain misclassified at startup");
        }
        if storage != before {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: detection wrote to a native NHI");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/icm",
        usb4_icm_startup_native_passes_the_gate
    );

    fn usb4_icm_startup_mixed_domains() -> TestResult {
        __reset_for_test();
        // Masking-defeating at the startup level: an ICM-owned
        // Intel controller and a native AMD controller in the same
        // boot. Each domain's verdict must be its own — the ICM
        // domain stands down, the native domain passes the gate,
        // and neither controller's aperture is written.
        let mut storage_a = alloc::vec![0u32; MODEL_LEN / 4];
        let bar_a = model_bar(&mut storage_a, EN | AUTH);
        let before_a = storage_a.clone();
        let mut storage_b = alloc::vec![0u32; MODEL_LEN / 4];
        // AMD binds by USB4 class, not by device ID; the ID field
        // is inert for this fixture.
        let bar_b = model_bar(&mut storage_b, AUTH);
        let before_b = storage_b.clone();
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        crate::runtime::retain(
            model_device(0x8086, 0x9A1B),
            cap,
            model_nhi(bar_a, 0x9A1B, "tgl-nhi0"),
        );
        crate::runtime::retain(
            model_device(0x1022, 0x0000),
            cap,
            model_nhi(bar_b, 0x0000, "amd-usb4"),
        );
        if crate::runtime::start() != narf_init::InitResult::NotPresent {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: mixed boot unexpectedly started on QEMU");
        }
        let statuses = domain_statuses();
        let ok = statuses.len() == 2
            && statuses[0].domain == 0
            && statuses[0].mode == CmMode::FirmwareManaged
            && statuses[1].domain == 1
            && statuses[1].mode == CmMode::Native
            && firmware_managed_count() == 1;
        if !ok {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: mixed-domain verdicts not independent");
        }
        if storage_a != before_a || storage_b != before_b {
            __reset_for_test();
            return TestResult::Fail("thunderbolt: startup wrote to a controller aperture");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/icm", usb4_icm_startup_mixed_domains);
}
