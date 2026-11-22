//! The LPS0 device (`PNP0D80`, the ACPI "System Power Management
//! Controller") and its `_DSM` notifications around suspend-to-idle,
//! after Linux's `drivers/acpi/x86/s2idle.c`. Also the handler list that
//! `acpi_register_lps0_dev` keeps; the AMD PMC driver registers there.
//!
//! A suspend-to-idle brackets the park with these calls (Linux's
//! `prepare_late` and `restore_early`, after the devices have suspended and
//! before they resume):
//! - **Prepare.** Screen off; then LPS0 entry; then each handler's
//!   `prepare`. On AMD the vendor entry runs before the Microsoft Modern
//!   Standby pair; on Intel, after it.
//! - **Each park iteration.** Each handler's `check`.
//! - **Restore.** Each handler's `restore`; then LPS0 exit; then the
//!   Microsoft exit, display-on intent and Modern Standby exit; then
//!   screen on.
//!
//! A function runs only if the firmware's function-0 mask for its UUID
//! lists it. Not done: the device constraint checks
//! (`lpi_check_constraints`), which only log.
use alloc::string::String;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// ACPI `ToUUID` byte order, as Linux's `guid_parse` produces it: the first
/// three groups little-endian, the rest as written.
pub const fn uuid(s: [u8; 36]) -> [u8; 16] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    const fn byte(s: &[u8; 36], at: usize) -> u8 {
        (nibble(s[at]) << 4) | nibble(s[at + 1])
    }
    // Text positions of each output byte.
    const AT: [usize; 16] = [6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = byte(&s, AT[i]);
        i += 1;
    }
    out
}

/// `ACPI_LPS0_DSM_UUID_MICROSOFT`.
pub const UUID_MICROSOFT: [u8; 16] = uuid(*b"11e00d56-ce64-47ce-837b-1f898f9aa461");
/// `ACPI_LPS0_DSM_UUID_AMD`.
pub const UUID_AMD: [u8; 16] = uuid(*b"e3f32452-febc-43ce-9039-932122d37721");
/// `ACPI_LPS0_DSM_UUID` (Intel).
pub const UUID_INTEL: [u8; 16] = uuid(*b"c4eb40a0-6cd2-11e2-bcfd-0800200c9a66");

// Intel and Microsoft function indices.
const SCREEN_OFF: u32 = 3; // linux: ACPI_LPS0_SCREEN_OFF
const SCREEN_ON: u32 = 4; // linux: ACPI_LPS0_SCREEN_ON
const ENTRY: u32 = 5; // linux: ACPI_LPS0_ENTRY
const EXIT: u32 = 6; // linux: ACPI_LPS0_EXIT
const MS_ENTRY: u32 = 7; // linux: ACPI_LPS0_MS_ENTRY
const MS_EXIT: u32 = 8; // linux: ACPI_LPS0_MS_EXIT
const MS_TURN_ON_DISPLAY: u32 = 9; // linux: ACPI_MS_TURN_ON_DISPLAY
                                   // AMD function indices.
const ENTRY_AMD: u32 = 2; // linux: ACPI_LPS0_ENTRY_AMD
const EXIT_AMD: u32 = 3; // linux: ACPI_LPS0_EXIT_AMD
const SCREEN_OFF_AMD: u32 = 4; // linux: ACPI_LPS0_SCREEN_OFF_AMD
const SCREEN_ON_AMD: u32 = 5; // linux: ACPI_LPS0_SCREEN_ON_AMD

/// The `amd_hid_ids` entries whose vendor mask is off by one
/// (`amd_picasso`'s `check_off_by_one`). Every other HID is `amd_cezanne`.
const PICASSO_HIDS: [&str; 3] = ["AMD0004", "AMD0005", "AMDI0005"];

/// The `_DSM` calls, as `acpi_evaluate_dsm` makes them on the LPS0 device.
pub trait Dsm {
    /// `_DSM(uuid, revision, function, Package())`; `None` if the
    /// evaluation failed.
    fn call(&mut self, uuid: [u8; 16], revision: u64, function: u32) -> Option<narf_aml::Value>;
}

/// An attached LPS0 device (`lps0_device_attach`): the function masks it
/// reported. `None` is a failed function-0 evaluation (Linux's negative
/// mask), and `Some(0)` lists no functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lps0 {
    /// An AMD CPU (`acpi_s2idle_vendor_amd`): the vendor UUID is AMD's.
    pub amd: bool,
    /// `lps0_dsm_func_mask`, for the vendor UUID.
    pub vendor: Option<u32>,
    /// `lps0_dsm_func_mask_microsoft`.
    pub microsoft: Option<u32>,
}
impl Lps0 {
    /// `lps0_device_attach`. `hid` is the device's `_HID`, which picks the
    /// AMD mask quirk. `None` when both function-0 evaluations failed.
    pub fn attach(dsm: &mut impl Dsm, amd: bool, hid: Option<&str>) -> Option<Self> {
        let microsoft = validate(dsm, UUID_MICROSOFT, 0);
        let vendor = if amd {
            validate(dsm, UUID_AMD, 0).map(|mask| {
                if mask > 0x3 && hid.is_some_and(|h| PICASSO_HIDS.contains(&h)) {
                    (mask << 1) | 0x1
                } else {
                    mask
                }
            })
        } else {
            validate(dsm, UUID_INTEL, 1)
        };
        (vendor.is_some() || microsoft.is_some()).then_some(Self {
            amd,
            vendor,
            microsoft,
        })
    }
    /// `rev_id`: 0 on AMD, 1 on Intel, for every call after function 0.
    fn revision(&self) -> u64 {
        if self.amd {
            0
        } else {
            1
        }
    }
    fn vendor_uuid(&self) -> [u8; 16] {
        if self.amd {
            UUID_AMD
        } else {
            UUID_INTEL
        }
    }
    /// `acpi_sleep_run_lps0_dsm`: `function` runs if `mask` lists it.
    fn run(&self, dsm: &mut impl Dsm, function: u32, mask: Option<u32>, uuid: [u8; 16]) {
        if mask.is_some_and(|m| m > 0 && m & (1 << function) != 0) {
            let _ = dsm.call(uuid, self.revision(), function);
        }
    }
    fn vendor_run(&self, dsm: &mut impl Dsm, function: u32) {
        self.run(dsm, function, self.vendor, self.vendor_uuid());
    }
    fn ms_run(&self, dsm: &mut impl Dsm, function: u32) {
        self.run(dsm, function, self.microsoft, UUID_MICROSOFT);
    }
    /// The `_DSM` half of `acpi_s2idle_prepare_late_lps0`: screen off, then
    /// LPS0 entry.
    pub fn prepare_late(&self, dsm: &mut impl Dsm) {
        self.vendor_run(dsm, if self.amd { SCREEN_OFF_AMD } else { SCREEN_OFF });
        self.ms_run(dsm, SCREEN_OFF);
        if self.amd {
            self.vendor_run(dsm, ENTRY_AMD);
        }
        self.ms_run(dsm, MS_ENTRY);
        self.ms_run(dsm, ENTRY);
        if !self.amd {
            self.vendor_run(dsm, ENTRY);
        }
    }
    /// The `_DSM` half of `acpi_s2idle_restore_early_lps0`: LPS0 exit, the
    /// Microsoft exit sequence, then screen on.
    pub fn restore_early(&self, dsm: &mut impl Dsm) {
        self.vendor_run(dsm, if self.amd { EXIT_AMD } else { EXIT });
        self.ms_run(dsm, EXIT);
        self.ms_run(dsm, MS_TURN_ON_DISPLAY);
        self.ms_run(dsm, MS_EXIT);
        self.ms_run(dsm, SCREEN_ON);
        self.vendor_run(dsm, if self.amd { SCREEN_ON_AMD } else { SCREEN_ON });
    }
}

/// `validate_dsm`: function 0 must return a buffer of one to four bytes,
/// read as the function mask.
fn validate(dsm: &mut impl Dsm, uuid: [u8; 16], revision: u64) -> Option<u32> {
    match dsm.call(uuid, revision, 0)? {
        narf_aml::Value::Buffer(bytes) if (1..=4).contains(&bytes.len()) => Some(
            bytes
                .iter()
                .enumerate()
                .fold(0, |mask, (i, &b)| mask | u32::from(b) << (8 * i)),
        ),
        _ => None,
    }
}

/// A driver hooked into the suspend-to-idle bracket (Linux's
/// `struct acpi_s2idle_dev_ops`). Each step runs on the suspending CPU.
pub trait Handler: Sync {
    /// A stable name, for `has_handler`.
    fn name(&self) -> &'static str;
    /// After the LPS0 entry.
    fn prepare(&self) {}
    /// Before each park iteration.
    fn check(&self) {}
    /// Before the LPS0 exit.
    fn restore(&self) {}
}

/// The `_DSM` calls through the AML evaluator, on the device at `path`.
struct AmlDsm<'a> {
    path: &'a str,
}
impl Dsm for AmlDsm<'_> {
    fn call(&mut self, uuid: [u8; 16], revision: u64, function: u32) -> Option<narf_aml::Value> {
        narf_aml::eval::evaluate_dsm(
            self.path,
            uuid,
            revision,
            u64::from(function),
            narf_aml::Value::Package(Vec::new()),
        )
        .ok()
    }
}

/// The attached device's namespace path and masks.
static DEVICE: IrqSafeSpinLock<Option<(String, Lps0)>> = IrqSafeSpinLock::new(None);
/// `lps0_s2idle_devops_head`.
static HANDLERS: IrqSafeSpinLock<Vec<&'static dyn Handler>> = IrqSafeSpinLock::new(Vec::new());

/// The first device whose `_HID` or `_CID` is `PNP0D80`, with its `_HID`.
fn find_device() -> Option<(String, Option<String>)> {
    narf_aml::list_all_device_paths()
        .into_iter()
        .find_map(|path| {
            let hid = narf_aml::device_hid(&path);
            let lps0 = hid.as_deref() == Some("PNP0D80")
                || narf_aml::device_cids(&path).iter().any(|c| c == "PNP0D80");
            lps0.then_some((path, hid))
        })
}

#[cfg(target_arch = "x86_64")]
fn amd_cpu() -> bool {
    use narf_arch::x86_64::microcode::{vendor, Vendor};
    vendor() == Vendor::Amd
}
#[cfg(not(target_arch = "x86_64"))]
fn amd_cpu() -> bool {
    false
}

/// `lps0_device_attach`, once the AML namespace is up. Returns whether an
/// LPS0 device attached.
pub fn setup() -> bool {
    let Some((path, hid)) = find_device() else {
        return false;
    };
    let Some(lps0) = Lps0::attach(&mut AmlDsm { path: &path }, amd_cpu(), hid.as_deref()) else {
        return false;
    };
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "lps0: {path} vendor mask {:?} microsoft mask {:?}",
            lps0.vendor,
            lps0.microsoft
        );
    }
    *DEVICE.lock() = Some((path, lps0));
    true
}
/// Whether an LPS0 device attached.
pub fn attached() -> bool {
    DEVICE.lock().is_some()
}

/// `acpi_register_lps0_dev`.
pub fn register(handler: &'static dyn Handler) {
    HANDLERS.lock().push(handler);
}
/// Whether a handler named `name` registered.
pub fn has_handler(name: &str) -> bool {
    HANDLERS.lock().iter().any(|h| h.name() == name)
}
fn handlers() -> Vec<&'static dyn Handler> {
    HANDLERS.lock().clone()
}
fn device() -> Option<(String, Lps0)> {
    DEVICE.lock().clone()
}

/// `acpi_s2idle_prepare_late_lps0`. Nothing without an attached device.
pub fn prepare_late() {
    let Some((path, lps0)) = device() else {
        return;
    };
    lps0.prepare_late(&mut AmlDsm { path: &path });
    for handler in handlers() {
        handler.prepare();
    }
}
/// `acpi_s2idle_check_lps0`.
pub fn check() {
    if !attached() {
        return;
    }
    for handler in handlers() {
        handler.check();
    }
}
/// `acpi_s2idle_restore_early_lps0`.
pub fn restore_early() {
    let Some((path, lps0)) = device() else {
        return;
    };
    for handler in handlers() {
        handler.restore();
    }
    lps0.restore_early(&mut AmlDsm { path: &path });
}

#[cfg(feature = "wake-test")]
#[path = "lps0_tests.rs"]
mod tests;
