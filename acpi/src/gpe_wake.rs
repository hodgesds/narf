//! Fixed-FADT-GPE wake leases for the platform power owner.
//!
//! A lease preserves an existing runtime enable and never replaces the AML
//! GPE handler. Its armed mask is suitable for the SCI's allocation-free
//! hard-IRQ observer. It does not turn a firmware _PRW into device authority.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::GpeBlockInfo;

const MAX_GPES: usize = 128;

#[derive(Copy, Clone, Debug)]
struct Slot {
    claimed: bool,
    runtime_enabled: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        claimed: false,
        runtime_enabled: false,
    };
}

static CONTROL: IrqSafeSpinLock<[Slot; MAX_GPES]> = IrqSafeSpinLock::new([Slot::EMPTY; MAX_GPES]);
static ARMED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
// FADT parsing is a boot-time operation. Tokens also retain the exact block
// identity so a reparse can never make cleanup target a different register.

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn read_port(port: u16) -> u8 {
    #[cfg(feature = "kernel-test")]
    if let Some((pointer, _)) = test_port(port) {
        // SAFETY: the scoped test registration retains this exact byte.
        return unsafe { pointer.read_volatile() };
    }
    // SAFETY: the caller validated the FADT byte-port GAS and geometry.
    unsafe { narf_arch::x86_64::io_port::inb(port) }
}

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn write_port(port: u16, value: u8) {
    #[cfg(feature = "kernel-test")]
    if let Some((pointer, write)) = test_port(port) {
        // SAFETY: the scoped registration owns this exact byte. Status
        // bytes emulate W1C; enable bytes can model lost enable writes.
        unsafe {
            let next = match write {
                TestWrite::Status => pointer.read_volatile() & !value,
                TestWrite::Enable(stuck, _) => value & !stuck,
            };
            let old = pointer.read_volatile();
            pointer.write_volatile(next);
            if let TestWrite::Enable(_, Some((mask, callback))) = write {
                if old & mask == 0 && next & mask != 0 {
                    callback();
                }
            }
        }
        return;
    }
    // SAFETY: caller validated the byte-port GAS and ownership contract.
    unsafe { narf_arch::x86_64::io_port::outb(port, value) };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeGpeError {
    Unsupported,
    Busy,
    Stale,
    Readback,
}

/// Opaque, retained register ownership. Dropping the token does not change
/// hardware. The power owner retains it across failures until `release`
/// succeeds under current platform authority.
#[derive(Debug)]
pub struct WakeGpe {
    number: u32,
    block: GpeBlockInfo,
    active: bool,
    enabled: bool,
}

impl WakeGpe {
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Enable-register readback from claim. A false result retains the
    /// lease for explicit cleanup; it must never authorize system sleep.
    pub fn enabled(&self) -> bool {
        self.active && self.enabled
    }
}

fn register_block(number: u32) -> Option<GpeBlockInfo> {
    if !cfg!(target_arch = "x86_64") {
        return None;
    }
    let mut found = None;
    for candidate in [super::gpe0_block(), super::gpe1_block()]
        .into_iter()
        .flatten()
    {
        if !super::gpe_byte_ports_valid(candidate) {
            continue;
        }
        let count = u32::from(candidate.byte_count) * 4;
        if number >= candidate.base_gsi && number - candidate.base_gsi < count {
            if found.is_some() {
                // Overlapping FADT blocks cannot establish a unique route.
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

fn block(number: u32) -> Option<GpeBlockInfo> {
    (number < MAX_GPES as u32)
        .then(|| register_block(number))
        .flatten()
}

pub fn supported(number: u32) -> bool {
    block(number).is_some()
}

fn same_block(a: GpeBlockInfo, b: GpeBlockInfo) -> bool {
    a.address == b.address
        && a.byte_count == b.byte_count
        && a.base_gsi == b.base_gsi
        && a.address_space == b.address_space
        && a.bit_offset == b.bit_offset
        && a.access_size == b.access_size
}

#[cfg(target_arch = "x86_64")]
fn ports(block: GpeBlockInfo, number: u32) -> (u16, u16, u8) {
    let bit = number - block.base_gsi;
    let status = block.address + u64::from(bit / 8);
    (
        status as u16,
        (status + u64::from(block.byte_count / 2)) as u16,
        1 << (bit % 8),
    )
}

/// Claim and enable one real fixed-FADT GPE. No handler is installed here.
///
/// # Safety
/// The platform power owner must invoke this only within its current Power
/// authority, after validating the device's actual _PRW. It must retain the
/// returned token through terminal cleanup; PCI endpoint authority alone
/// does not authorize this shared platform register.
pub unsafe fn claim(number: u32) -> Result<WakeGpe, WakeGpeError> {
    // SAFETY: unchanged caller contract; no observation preparation needed.
    unsafe { claim_with_prepare(number, || {}) }
}

/// Prepare generation observations under exclusive CONTROL, after Busy
/// refusal and before ARMED/enable. A second claimant cannot clear old hits.
///
/// # Safety
/// The claim contract applies. prepare must be atomic-only, nonblocking,
/// and must not access GPE controls or recursively invoke this module.
pub unsafe fn claim_with_prepare(
    number: u32,
    prepare: impl FnOnce(),
) -> Result<WakeGpe, WakeGpeError> {
    let descriptor = block(number).ok_or(WakeGpeError::Unsupported)?;
    let mut slots = CONTROL.lock();
    let slot = &mut slots[number as usize];
    if slot.claimed {
        return Err(WakeGpeError::Busy);
    }
    prepare();
    #[cfg(target_arch = "x86_64")]
    let enabled = {
        let (status_port, enable_port, bit) = ports(descriptor, number);
        // SAFETY: block() validated byte-port GAS geometry; CONTROL
        // serializes enable-byte read/modify/write with runtime enables.
        unsafe {
            let old = read_port(enable_port);
            slot.runtime_enabled = old & bit != 0;
            slot.claimed = true;
            ARMED[number as usize / 64].fetch_or(1 << (number % 64), Ordering::Release);
            if !slot.runtime_enabled {
                // Preserve a pending shared runtime GPE; clear stale status
                // only when this source was disabled before our claim.
                write_port(status_port, bit);
            }
            write_port(enable_port, old | bit);
            let enabled = read_port(enable_port) & bit != 0;
            if !enabled {
                ARMED[number as usize / 64].fetch_and(!(1 << (number % 64)), Ordering::Release);
            }
            enabled
        }
    };
    #[cfg(not(target_arch = "x86_64"))]
    let enabled = false;
    Ok(WakeGpe {
        number,
        block: descriptor,
        active: true,
        enabled,
    })
}

/// Restore the prior runtime enable. Failure retains the live token.
///
/// # Safety
/// The caller must invoke this within current platform Power authority and
/// must own `token`; concurrent FADT reparse is forbidden while leases live.
pub unsafe fn release(token: &mut WakeGpe) -> Result<(), WakeGpeError> {
    // SAFETY: unchanged exact-token/current-authority caller contract.
    unsafe { release_with_complete(token, || {}) }
}

/// Consume retiring observations under CONTROL before the slot is handed
/// to a successor. An inactive token never calls complete.
///
/// # Safety
/// The release contract applies. complete must be atomic-only, nonblocking
/// and must not re-enter GPE controls/register operations.
pub unsafe fn release_with_complete(
    token: &mut WakeGpe,
    complete: impl FnOnce(),
) -> Result<(), WakeGpeError> {
    if !token.active {
        return Ok(());
    }
    let descriptor = block(token.number).ok_or(WakeGpeError::Stale)?;
    if !same_block(descriptor, token.block) {
        return Err(WakeGpeError::Stale);
    }
    let mut slots = CONTROL.lock();
    let slot = &mut slots[token.number as usize];
    if !slot.claimed {
        return Err(WakeGpeError::Stale);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (_, enable_port, bit) = ports(descriptor, token.number);
        // SAFETY: same bounded GAS byte and CONTROL serialization as claim.
        unsafe {
            let old = read_port(enable_port);
            let new = if slot.runtime_enabled {
                old | bit
            } else {
                old & !bit
            };
            write_port(enable_port, new);
            if (read_port(enable_port) & bit != 0) != slot.runtime_enabled {
                return Err(WakeGpeError::Readback);
            }
        }
    }
    complete();
    slot.claimed = false;
    token.active = false;
    token.enabled = false;
    ARMED[token.number as usize / 64].fetch_and(!(1 << (token.number % 64)), Ordering::Release);
    Ok(())
}

/// Existing runtime GPE enable, serialized with wake leases. Called by
/// `acpi::enable_gpe`; an enable requested during a wake lease survives its
/// later release. Invalid or unsupported GAS geometry performs no I/O.
pub(super) fn enable_runtime(number: u32) {
    let Some(descriptor) = register_block(number) else {
        return;
    };
    let mut slots = CONTROL.lock();
    if number < MAX_GPES as u32 {
        slots[number as usize].runtime_enabled = true;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (_, enable_port, bit) = ports(descriptor, number);
        // SAFETY: bounded port and serialized byte read/modify/write.
        unsafe {
            let old = read_port(enable_port);
            write_port(enable_port, old | bit);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = descriptor;
}

/// Hard-IRQ read, atomics only. The platform SCI handler calls the power
/// wake observer for an armed bit before deferring ordinary AML processing.
pub fn armed(number: u32) -> bool {
    number < MAX_GPES as u32
        && ARMED[number as usize / 64].load(Ordering::Acquire) & (1 << (number % 64)) != 0
}

/// Allocation-free intersection of recorded GPE bits with currently held
/// wake leases. A released/replaced route cannot keep a later park awake.
pub fn any_armed(bits: [u64; 2]) -> bool {
    ARMED[0].load(Ordering::Acquire) & bits[0] != 0
        || ARMED[1].load(Ordering::Acquire) & bits[1] != 0
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
#[derive(Copy, Clone, Debug)]
struct TestPorts {
    base: u16,
    pointer: usize,
    length: usize,
    stuck_enable: u8,
    enable_hook: Option<(u8, fn())>,
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
static TEST_PORTS: IrqSafeSpinLock<Option<TestPorts>> = IrqSafeSpinLock::new(None);

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
#[derive(Copy, Clone)]
enum TestWrite {
    Status,
    Enable(u8, Option<(u8, fn())>),
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
fn test_port(port: u16) -> Option<(*mut u8, TestWrite)> {
    let registration = (*TEST_PORTS.lock())?;
    let offset = port.checked_sub(registration.base)? as usize;
    if offset >= registration.length {
        return None;
    }
    let write = if offset < registration.length / 2 {
        TestWrite::Status
    } else {
        TestWrite::Enable(registration.stuck_enable, registration.enable_hook)
    };
    Some(((registration.pointer + offset) as *mut u8, write))
}

/// Scoped byte-register fixture; absent from the production feature graph.
/// Does not install a SCI, Power grant, _PRW or firmware method.
#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
#[derive(Debug)]
pub struct TestGpeRegisters<'a> {
    bytes: &'a mut [u8],
    blocks: [Option<GpeBlockInfo>; 2],
    slots: [Slot; MAX_GPES],
    armed: [u64; 2],
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
impl TestGpeRegisters<'_> {
    pub fn byte(&self, offset: usize) -> u8 {
        assert!(offset < self.bytes.len());
        // SAFETY: this guard owns the borrowed byte array for its lifetime.
        unsafe { self.bytes.as_ptr().add(offset).read_volatile() }
    }

    pub fn set_byte(&mut self, offset: usize, value: u8) {
        assert!(offset < self.bytes.len());
        // SAFETY: checked byte within the guard's exclusive borrowed array.
        unsafe { self.bytes.as_mut_ptr().add(offset).write_volatile(value) };
    }

    pub fn set_stuck_enable(&mut self, mask: u8) {
        if let Some(registration) = TEST_PORTS.lock().as_mut() {
            registration.stuck_enable = mask;
        }
    }

    /// Model an IRQ at the exact enable transition. Callback must be an
    /// atomic-only observer; CONTROL is held and GPE re-entry is forbidden.
    pub fn set_enable_hook(&mut self, mask: u8, callback: Option<fn()>) {
        if let Some(registration) = TEST_PORTS.lock().as_mut() {
            registration.enable_hook = callback.map(|callback| (mask, callback));
        }
    }
}

/// Register a scoped FADT block and W1C byte-register model.
///
/// # Safety
/// Kernel tests must serialize this global fixture against real FADT
/// reparsing and other GPE fixtures. No production wake lease may be live.
#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
pub unsafe fn __test_registers(
    block: GpeBlockInfo,
    bytes: &mut [u8],
) -> Result<TestGpeRegisters<'_>, WakeGpeError> {
    if !super::gpe_byte_ports_valid(block) || bytes.len() != block.byte_count as usize {
        return Err(WakeGpeError::Unsupported);
    }
    let mut slots = CONTROL.lock();
    let mut registration = TEST_PORTS.lock();
    if registration.is_some() || slots.iter().any(|slot| slot.claimed) {
        return Err(WakeGpeError::Busy);
    }
    let old_blocks = [super::gpe0_block(), super::gpe1_block()];
    let old_slots = *slots;
    let old_armed = [
        ARMED[0].load(Ordering::Acquire),
        ARMED[1].load(Ordering::Acquire),
    ];
    *slots = [Slot::EMPTY; MAX_GPES];
    *registration = Some(TestPorts {
        base: block.address as u16,
        pointer: bytes.as_mut_ptr() as usize,
        length: bytes.len(),
        stuck_enable: 0,
        enable_hook: None,
    });
    *super::GPE0_BLOCK.lock() = Some(block);
    *super::GPE1_BLOCK.lock() = None;
    ARMED[0].store(0, Ordering::Release);
    ARMED[1].store(0, Ordering::Release);
    Ok(TestGpeRegisters {
        bytes,
        blocks: old_blocks,
        slots: old_slots,
        armed: old_armed,
    })
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
impl Drop for TestGpeRegisters<'_> {
    fn drop(&mut self) {
        *CONTROL.lock() = self.slots;
        *super::GPE0_BLOCK.lock() = self.blocks[0];
        *super::GPE1_BLOCK.lock() = self.blocks[1];
        ARMED[0].store(self.armed[0], Ordering::Release);
        ARMED[1].store(self.armed[1], Ordering::Release);
        *TEST_PORTS.lock() = None;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "gpe_wake_tests.rs"]
mod tests;
