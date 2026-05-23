//! ACPI Embedded Controller (EC) driver — clean-room.
//!
//! Spec: ACPI 6.5 §12.3 (Embedded Controller Interface).
//!   <https://uefi.org/specs/ACPI/>
//! The EC is the gatekeeper for laptop-specific hardware: battery, AC,
//! thermal zones, and FN keys.
//!
//! Beyond the bare register interface, this module also owns the
//! laptop platform's **SCI dispatcher**: an SCI fires on every
//! GPE-block status bit set + every PM1 fixed-event (power button,
//! sleep button, RTC alarm). On dispatch we:
//!
//! 1. Snapshot PM1 status — emit a `PlatformEvent` for any set
//!    PWRBTN_STS / SLPBTN_STS bit, then W1C-clear it.
//! 2. Walk every GPE-block status register. For each set bit:
//!    - If it's the EC's own GPE: issue `EC_QUERY` (0x84), read the
//!      query byte, and evaluate `<EC>._Qxx` on the AML namespace.
//!    - Otherwise: try `\_GPE._Lxx` then `\_GPE._Exx` per ACPI §5.6.4.
//!    - W1C-clear the GPE status bit.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
pub enum DriverError {
    Timeout,
}

// ── Standard EC Ports (ACPI §12.3) ──────────────────────────────────
pub const EC_DATA_PORT: u16 = 0x62;
pub const EC_COMMAND_PORT: u16 = 0x66;
pub const EC_STATUS_PORT: u16 = 0x66;

// ── EC Commands ─────────────────────────────────────────────────────
const EC_CMD_READ: u8 = 0x80;
const EC_CMD_WRITE: u8 = 0x81;
const EC_CMD_QUERY: u8 = 0x84; // Query SCI event

// ── Status Bits ─────────────────────────────────────────────────────
const EC_STS_OBF: u8 = 1 << 0; // Output buffer full
const EC_STS_IBF: u8 = 1 << 1; // Input buffer full
const EC_STS_SCI: u8 = 1 << 5; // SCI event pending

#[derive(Debug)]
pub struct AcpiEc {
    control_port: u16,
    data_port: u16,
}

impl AcpiEc {
    pub const fn new(control_port: u16, data_port: u16) -> Self {
        Self {
            control_port,
            data_port,
        }
    }

    /// Wait for the Input Buffer to be empty.
    fn wait_ibf_empty(&self) -> Result<(), DriverError> {
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive if the EC is wedged. ACPI 6.5 §5.2.15: an EC
        // command is bounded by T_EC (~10 ms typical); 100 ms wedge
        // threshold.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: validated EC status port from ECDT or standard base.
            || unsafe { narf_arch::x86_64::io_port::inb(self.control_port) } & EC_STS_IBF == 0,
            narf_time::Deadline::after_ms(100),
        );
        if done {
            Ok(())
        } else {
            Err(DriverError::Timeout)
        }
    }

    /// Wait for the Output Buffer to be full.
    fn wait_obf_full(&self) -> Result<(), DriverError> {
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive if the EC is slow to publish a response. 100 ms
        // wedge threshold (T_EC ~10 ms typical).
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: validated EC status port.
            || unsafe { narf_arch::x86_64::io_port::inb(self.control_port) } & EC_STS_OBF != 0,
            narf_time::Deadline::after_ms(100),
        );
        if done {
            Ok(())
        } else {
            Err(DriverError::Timeout)
        }
    }

    pub fn read_byte(&self, addr: u8) -> Result<u8, DriverError> {
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io_port::outb(self.control_port, EC_CMD_READ);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io_port::outb(self.data_port, addr);
        }
        self.wait_obf_full()?;
        Ok(unsafe { narf_arch::x86_64::io_port::inb(self.data_port) })
    }

    pub fn write_byte(&self, addr: u8, val: u8) -> Result<(), DriverError> {
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io_port::outb(self.control_port, EC_CMD_WRITE);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io_port::outb(self.data_port, addr);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io_port::outb(self.data_port, val);
        }
        Ok(())
    }
}

impl Driver for AcpiEc {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // In a real system, we'd check ECDT or AML here.
            // For now, we just expose the primitives.
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {})
    }
}

static GLOBAL_EC: IrqSafeSpinLock<Option<AcpiEc>> = IrqSafeSpinLock::new(None);

pub fn init() {
    // Preference order:
    //   1. ECDT (fastest, ACPI 6.5 §5.2.15 — guaranteed before namespace).
    //   2. PNP0C09 _CRS (decoded into oregion::EC_PORTS at parse_namespace
    //      time) plus the device's _GPE for the GPE bit.
    //   3. Standard 0x66/0x62 ports with no GPE (last-ditch, IBM PC AT
    //      convention; many laptops break this).
    let (ctrl, data, gpe) = if let Some(info) = narf_acpi::ecdt_info() {
        (info.control_addr as u16, info.data_addr as u16, Some(info.gpe_bit as u32))
    } else if let Some(device) = narf_aml::find_device_by_hid("PNP0C09") {
        let (data_port, cmd_port) = match narf_aml::oregion::ec_ports() {
            Some(p) => p,
            None => (EC_DATA_PORT, EC_COMMAND_PORT),
        };
        let gpe_bit = read_ec_gpe(&device.path);
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-ec: found {} via AML (data={:#x} cmd={:#x} gpe={:?})",
            device.path, data_port, cmd_port, gpe_bit,
        );
        (cmd_port, data_port, gpe_bit)
    } else {
        (EC_COMMAND_PORT, EC_DATA_PORT, None)
    };
    *GLOBAL_EC.lock() = Some(AcpiEc::new(ctrl, data));

    if let Some(g) = gpe {
        narf_acpi::enable_gpe(g);
        let _ = writeln!(narf_console::Writer, "  acpi-ec: enabled GPE {}", g);
    }
    init_sci(gpe.map(|g| g as u8));
}

/// ACPI 6.5 §12.11: every EC declares `_GPE` either as `Name(_GPE,
/// Integer)` or `Method(_GPE, 0)`. Return the integer GPE bit
/// number when present.
fn read_ec_gpe(ec_path: &str) -> Option<u32> {
    let path = alloc::format!("{}._GPE", ec_path);
    let node = narf_aml::find_node(&path)?;
    match node.kind {
        narf_aml::NodeKind::Method => narf_aml::eval::evaluate_method(&path, &[])
            .ok()
            .map(|v| v.as_integer() as u32),
        narf_aml::NodeKind::Name => match node.value {
            Some(narf_aml::NameValue::Integer(v)) => Some(v as u32),
            _ => None,
        },
        _ => None,
    }
}

pub fn with_ec<R>(f: impl FnOnce(&AcpiEc) -> R) -> Option<R> {
    GLOBAL_EC.lock().as_ref().map(f)
}

// ── Platform SCI events ─────────────────────────────────────────────

/// A PM1-class fixed-event the SCI dispatcher saw fire. Subscribers
/// (lid driver, button driver, idle governor) install callbacks via
/// `subscribe_platform_event`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PlatformEvent {
    PowerButton,
    SleepButton,
    RtcAlarm,
    /// A GPE bit fired with no matching `_Lxx`/`_Exx` method — useful
    /// for diagnostics on hardware whose AML names this kernel hasn't
    /// learned yet.
    UnclaimedGpe(u32),
    /// EC query response: `_Qxx` was invoked. Carries the query byte.
    EcQuery(u8),
}

type PlatformSubscriber = Box<dyn Fn(PlatformEvent) + Send + Sync + 'static>;

static SUBSCRIBERS: IrqSafeSpinLock<Vec<PlatformSubscriber>> = IrqSafeSpinLock::new(Vec::new());

/// SCI dispatch counters. Useful for tests + diagnostics.
static SCI_FIRES: AtomicU64 = AtomicU64::new(0);
static EC_QUERIES: AtomicU64 = AtomicU64::new(0);

/// Cached EC GPE bit (from ECDT or `_GPE` evaluation). `u32::MAX`
/// when no EC is registered — the dispatcher then skips the
/// EC-query path and treats every set bit as a non-EC GPE.
static EC_GPE_BIT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Install a platform-event subscriber. Callbacks fire from the SCI
/// dispatcher path — keep them short (post to a channel, set an
/// atomic, wake a task).
pub fn subscribe_platform_event<F>(cb: F)
where
    F: Fn(PlatformEvent) + Send + Sync + 'static,
{
    SUBSCRIBERS.lock().push(Box::new(cb));
}

fn notify(event: PlatformEvent) {
    let subs = SUBSCRIBERS.lock();
    for s in subs.iter() {
        s(event);
    }
}

/// Number of SCIs the dispatcher has serviced.
pub fn sci_fire_count() -> u64 {
    SCI_FIRES.load(Ordering::Acquire)
}

/// Number of EC `_Qxx` queries the dispatcher has issued.
pub fn ec_query_count() -> u64 {
    EC_QUERIES.load(Ordering::Acquire)
}

#[cfg(target_arch = "x86_64")]
fn dispatch_pm1() {
    let s = narf_acpi::pm1_status_read();
    if s & narf_acpi::PM1_STS_PWRBTN != 0 {
        narf_acpi::pm1_status_clear(narf_acpi::PM1_STS_PWRBTN);
        notify(PlatformEvent::PowerButton);
    }
    if s & narf_acpi::PM1_STS_SLPBTN != 0 {
        narf_acpi::pm1_status_clear(narf_acpi::PM1_STS_SLPBTN);
        notify(PlatformEvent::SleepButton);
    }
    if s & narf_acpi::PM1_STS_RTC != 0 {
        narf_acpi::pm1_status_clear(narf_acpi::PM1_STS_RTC);
        notify(PlatformEvent::RtcAlarm);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn dispatch_pm1() {}

#[cfg(target_arch = "x86_64")]
fn dispatch_gpe_block(block: narf_acpi::GpeBlockInfo) {
    let status = narf_acpi::gpe_block_status(block);
    for (byte_idx, byte) in status.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        for bit in 0..8 {
            if byte & (1 << bit) == 0 {
                continue;
            }
            let gpe_num = block.base_gsi + (byte_idx as u32 * 8) + bit;
            handle_gpe(gpe_num);
            narf_acpi::gpe_status_clear_bit(gpe_num);
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn dispatch_gpe_block(_block: narf_acpi::GpeBlockInfo) {}

fn handle_gpe(gpe_num: u32) {
    let ec_bit = EC_GPE_BIT.load(Ordering::Acquire);
    if ec_bit != u64::MAX && ec_bit as u32 == gpe_num {
        handle_ec_gpe();
        return;
    }

    let hex = format!("{:02X}", gpe_num);
    // ACPI §5.6.4: Lxx = level-triggered, Exx = edge-triggered. The
    // namespace path is `\_GPE._Lxx` / `\_GPE._Exx`. Try both — the
    // firmware author picks one.
    let l_path = format!("\\_GPE._L{}", hex);
    let e_path = format!("\\_GPE._E{}", hex);
    let l_ok = narf_aml::eval::evaluate_method(&l_path, &[]).is_ok();
    let e_ok = if l_ok {
        false
    } else {
        narf_aml::eval::evaluate_method(&e_path, &[]).is_ok()
    };
    if !l_ok && !e_ok {
        notify(PlatformEvent::UnclaimedGpe(gpe_num));
    }
}

fn handle_ec_gpe() {
    let query = with_ec(|ec| ec.query()).unwrap_or(None);
    let query = match query {
        Some(q) if q != 0 => q,
        _ => return,
    };
    EC_QUERIES.fetch_add(1, Ordering::Release);
    notify(PlatformEvent::EcQuery(query));

    // Walk for the EC node and evaluate <EC>._Qxx. The EC's namespace
    // path comes from the `PNP0C09` lookup. Most laptops put it at
    // `\_SB.PCI0.LPCB.EC0` or similar — we let `find_device_by_hid`
    // resolve it.
    let ec_node = narf_aml::find_device_by_hid("PNP0C09");
    if let Some(node) = ec_node {
        let path = format!("{}._Q{:02X}", node.path, query);
        let _ = narf_aml::eval::evaluate_method(&path, &[]);
    }
}

impl AcpiEc {
    /// Issue `EC_QUERY` and read the returned query byte. `Ok(None)`
    /// means SCI fired but the EC reported no event (query byte 0).
    pub fn query(&self) -> Option<u8> {
        if self.wait_ibf_empty().is_err() {
            return None;
        }
        // SAFETY: validated EC command port from ECDT or AML.
        unsafe {
            narf_arch::x86_64::io_port::outb(self.control_port, EC_CMD_QUERY);
        }
        if self.wait_obf_full().is_err() {
            return None;
        }
        // SAFETY: validated EC data port from ECDT or AML.
        Some(unsafe { narf_arch::x86_64::io_port::inb(self.data_port) })
    }
}

/// Run one pass of the SCI dispatcher. Wired as the synchronous
/// handler on the SCI vector by `init_sci()`; also exposed for the
/// kernel-test path that injects a synthetic SCI to verify dispatch.
pub fn dispatch_sci() {
    SCI_FIRES.fetch_add(1, Ordering::Release);
    dispatch_pm1();
    if let Some(b) = narf_acpi::gpe0_block() {
        dispatch_gpe_block(b);
    }
    if let Some(b) = narf_acpi::gpe1_block() {
        dispatch_gpe_block(b);
    }
}

/// Test helper: drain subscribers + reset counters so each smoke can
/// start from a clean slate.
#[doc(hidden)]
pub fn __test_reset_sci() {
    SUBSCRIBERS.lock().clear();
    SCI_FIRES.store(0, Ordering::Release);
    EC_QUERIES.store(0, Ordering::Release);
    EC_GPE_BIT.store(u64::MAX, Ordering::Release);
}

/// Test helper: invoke the per-GPE dispatcher without going through
/// the GPE block read (which needs live MMIO/PIO). Subscribers see
/// the same `PlatformEvent::UnclaimedGpe` / `EcQuery` notifications
/// the real path would generate; AML evaluation is genuine — when
/// the namespace is loaded with `\\_GPE._L42` the test sees that
/// method evaluated, otherwise the unclaimed-GPE notification fires.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub fn __test_handle_gpe(gpe_num: u32) {
    handle_gpe(gpe_num);
}

/// Test helper: walk a synthetic status-byte array as if the real
/// GPE block had latched these bits. Dispatches each set bit
/// through `handle_gpe`. Does NOT attempt to clear the status
/// (no real HW). Useful for verifying the bit-walk arithmetic +
/// fan-out to subscribers.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub fn __test_dispatch_synthetic_block(base_gsi: u32, status: &[u8]) {
    for (byte_idx, byte) in status.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        for bit in 0..8 {
            if byte & (1 << bit) == 0 {
                continue;
            }
            let gpe_num = base_gsi + (byte_idx as u32 * 8) + bit;
            handle_gpe(gpe_num);
        }
    }
}

/// Wire the SCI dispatcher to the FADT-supplied SCI_INT line.
///
/// Spec citations:
///   - **ACPI 6.5 §5.2.9** — `FADT.SCI_INT` is an *ISA IRQ
///     number*. Real chipsets route it through an IOAPIC at a
///     GSI determined by an MADT Interrupt Source Override
///     (§5.2.12.5) when present, or 1:1 against the ISA IRQ
///     when absent.
///   - **ACPI 6.5 §5.2.12.5** — ISO `flags` carry polarity
///     (bits 0-1) and trigger (bits 2-3) overrides. SCI's bus
///     default is level / active-low.
///   - **Intel 82093AA IOAPIC Datasheet §3.2.4** — IOREDTBL
///     entry layout (vector, dest mode, polarity, trigger,
///     mask, dest APIC).
///   - <https://uefi.org/specs/ACPI/6.5/>
///
/// Flow: allocate an IDT vector, resolve SCI_INT → GSI through
/// any matching ISO, locate the IOAPIC owning that GSI, program
/// the redirection-table entry (level / active-low, fixed
/// delivery, dest = BSP, unmasked), install `dispatch_sci` as
/// the synchronous handler, and switch the platform from legacy
/// (SMI-driven) to ACPI (SCI-driven) mode via FADT.SMI_CMD.
pub fn init_sci(ec_gpe_bit: Option<u8>) {
    if let Some(b) = ec_gpe_bit {
        EC_GPE_BIT.store(b as u64, Ordering::Release);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let pm = match narf_acpi::fadt_pm() {
            Some(p) => p,
            None => return,
        };
        if pm.sci_int == 0 {
            return;
        }
        let sci_int = pm.sci_int as u32;

        // Resolve SCI_INT → (gsi, polarity|trigger flags) by
        // walking MADT ISO entries. ACPI 6.5 §5.2.12.5: an
        // entry whose `bus = 0` (ISA) and `source` matches our
        // SCI_INT remaps the line; otherwise SCI_INT itself is
        // the GSI. SCI's bus default is level / active-low.
        let mut overrides = [narf_acpi::IsaOverride::default(); narf_acpi::MAX_ISA_OVERRIDES];
        let n_ov = narf_acpi::copy_isa_overrides(&mut overrides);
        let (gsi, ioapic_flags) = overrides[..n_ov]
            .iter()
            .find(|ov| ov.bus == 0 && ov.source as u32 == sci_int)
            .map(|ov| {
                let pol = match ov.flags & 0b11 {
                    0b01 => narf_acpi::ioapic::POLARITY_HIGH,
                    _ => narf_acpi::ioapic::POLARITY_LOW,
                };
                let trig = match (ov.flags >> 2) & 0b11 {
                    0b01 => narf_acpi::ioapic::TRIGGER_EDGE,
                    _ => narf_acpi::ioapic::TRIGGER_LEVEL,
                };
                (ov.gsi, pol | trig)
            })
            .unwrap_or((
                sci_int,
                narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
            ));

        let vector = match narf_interrupts::vector::alloc() {
            Ok(v) => v,
            Err(_) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  acpi-ec: vector::alloc failed for SCI"
                );
                return;
            }
        };
        narf_interrupts::install_handler(vector, dispatch_sci);

        // Route the GSI through the IOAPIC owning it. Dest = BSP
        // (APIC id 0). SAFETY: vector + handler installed above
        // before this routes the line.
        let ok = unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, vector, 0, ioapic_flags) };
        if !ok {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi-ec: IOAPIC route_gsi_to_vector rejected GSI {}",
                gsi
            );
            return;
        }

        narf_acpi::acpi_enable();
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-ec: SCI dispatcher installed (SCI_INT {} → GSI {} → vec {}, level/active-low, ec_gpe={:?})",
            pm.sci_int, gsi, vector, ec_gpe_bit
        );
    }
}
