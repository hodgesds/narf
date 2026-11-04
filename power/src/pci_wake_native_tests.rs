use super::*;
use alloc::vec;
use narf_bus::{
    addr::{BusAddr, PcieAddr},
    DeviceId,
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

#[derive(Debug)]
struct Restore {
    authority: Option<Cap<Power, Grant>>,
    devices: Vec<BusDevice>,
    sci: Option<u8>,
}

impl Drop for Restore {
    fn drop(&mut self) {
        *AUTHORITY.lock() = self.authority;
        narf_bus::registry::install(core::mem::take(&mut self.devices));
        narf_acpi::record_sci_vector(self.sci.unwrap_or(0));
    }
}

struct Config {
    _bytes: Vec<u8>,
    pointer: *mut u8,
    physical: PhysAddr,
}

impl Config {
    fn new() -> Self {
        let mut bytes = vec![0u8; 8192];
        let base = (bytes.as_mut_ptr() as usize + 4095) & !4095;
        let pointer = base as *mut u8;
        Self {
            _bytes: bytes,
            pointer,
            physical: PhysAddr::from_kernel_ptr(pointer),
        }
    }

    fn put(&self, offset: usize, value: u32) {
        assert!(offset % 4 == 0 && offset + 4 <= 4096);
        // SAFETY: aligned word in this owned page-sized fixture window.
        unsafe { self.pointer.add(offset).cast::<u32>().write_volatile(value) };
    }

    fn get(&self, offset: usize) -> u32 {
        assert!(offset % 4 == 0 && offset + 4 <= 4096);
        // SAFETY: same owned config word as put().
        unsafe { self.pointer.add(offset).cast::<u32>().read_volatile() }
    }
}

fn device(config: &Config, bus: u8, slot: u8) -> BusDevice {
    let address = PcieAddr::new(0x7f32, bus, slot, 0);
    BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: 0x14c3,
            device: 0x7922,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: config.physical,
        },
    }
}

fn package(opcode: &[u8], payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 2;
    assert!(length < 4096);
    let mut bytes = opcode.to_vec();
    bytes.extend_from_slice(&[0x40 | (length as u8 & 15), (length >> 4) as u8]);
    bytes.extend_from_slice(payload);
    bytes
}

fn firmware() -> Vec<u8> {
    let mut port = b"RP01\x08_ADR\x0c\x00\x00\x01\x00".to_vec();
    for name in [b"ENAB", b"SLPS", b"DSTA", b"FAIL", b"FALL"] {
        port.push(0x08);
        port.extend_from_slice(name);
        port.push(0);
    }
    port.extend_from_slice(b"\x08_PRW");
    port.extend_from_slice(&package(&[0x12], &[2, 0x0a, 70, 0x0a, 3]));
    let mut method = b"_DSW\x03\x70\x68ENAB\x70\x69SLPS\x70\x6aDSTA".to_vec();
    // If (Arg0 && FAIL) { BADH() }. BADH contains an unsupported extended
    // opcode, while the disable path remains executable for real rollback.
    method.extend_from_slice(&package(&[0xa0], b"\x90\x68FAILBADH"));
    port.extend_from_slice(&package(&[0x14], &method));
    port.extend_from_slice(&package(&[0x14], b"BADH\x00\x5b\x34"));
    port.extend_from_slice(&package(&[0x14], b"_PSW\x01\x70\x01FALL"));
    port.extend_from_slice(&package(&[0x14], b"SETF\x01\x70\x68FAIL"));
    let port = package(&[0x5b, 0x82], &port);
    let mut root = b"ZWK0\x08_HID\x0dPNP0A08\x00\x08_SEG\x0b\x32\x7f\x08_BBN\x00".to_vec();
    root.extend_from_slice(&port);
    package(&[0x5b, 0x82], &root)
}

fn value(name: &str) -> Result<u64, &'static str> {
    match narf_aml::eval::strict::evaluate_object(&format!("\\ZWK0.RP01.{name}"), &[]) {
        Ok(Value::Integer(value)) => Ok(value),
        _ => Err("actual strict AML recorder unavailable"),
    }
}

fn observe_gpe() {
    note_gpe_irq(70);
}

fn native_owner_uses_real_grants_routes_and_terminal_rollback() -> Result<(), &'static str> {
    let _restore = Restore {
        authority: *AUTHORITY.lock(),
        devices: narf_bus::registry::devices(),
        sci: narf_acpi::sci_vector(),
    };
    // SAFETY: serialized fixture owns namespace and OpRegion tables until
    // every native wake owner is explicitly retired or dropped idle.
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    narf_aml::__parse_body_for_test(&firmware(), "\\")
        .map_err(|_| "native wake AML fixture parse")?;
    let bridge = Config::new();
    let endpoint = Config::new();
    let endpoint2 = Config::new();
    // SAFETY: these two owned config windows outlive the scoped ECAM guard.
    let _ecam = unsafe {
        narf_bus::ecam::__test_windows(&[
            (bridge.physical, bridge.pointer, 4096),
            (endpoint.physical, endpoint.pointer, 4096),
            (endpoint2.physical, endpoint2.pointer, 4096),
        ])
    };
    bridge.put(0x0c, 1 << 16); // type1
    bridge.put(0x18, 0x0003_0300); // child bus3
    bridge.put(0x90, 0x1234_0042); // unrelated root-port policy sentinel
    endpoint.put(0x04, 0x0010_0000);
    endpoint.put(0x34, 0x80);
    endpoint.put(0x80, 0x4803_0001); // PMv3, native PME from D0/D3hot
    endpoint.put(0x84, 0xa55a_0000);
    endpoint2.put(0x04, 0x0010_0000);
    endpoint2.put(0x34, 0x80);
    endpoint2.put(0x80, 0x4803_0001);
    endpoint2.put(0x84, 0xa55a_0000);
    let child = device(&endpoint, 3, 0);
    let parent = device(&bridge, 0, 1);
    let child2 = device(&endpoint2, 3, 1);
    narf_bus::registry::install(vec![parent, child, child2]);
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let cap2 = Cap::<BusDeviceCap, Write>::bootstrap();
    let power = crate::bootstrap_power_authority();
    *AUTHORITY.lock() = None;
    if !matches!(PciWake::discover(&cap, child), Err(WakeError::Authority)) {
        return Err("endpoint authority manufactured a platform Power grant");
    }
    install_authority(&power).map_err(|_| "real platform grant refused")?;
    narf_acpi::record_sci_vector(0);
    if !matches!(PciWake::discover(&cap, child), Err(WakeError::Unsupported)) {
        return Err("a _PRW without installed SCI became a usable wake route");
    }
    // Explicit test model, not a production route installation: the tests
    // deliver an observed IRQ through note_gpe_irq without parking hardware.
    narf_acpi::record_sci_vector(0x67);
    let mut bytes = [0x20, 0, 0x20, 0]; // existing EC69 runtime enable/status
    let block = narf_acpi::GpeBlockInfo {
        address: 0x700,
        byte_count: 4,
        base_gsi: 64,
        address_space: 1,
        bit_offset: 0,
        access_size: 1,
    };
    // SAFETY: exact scoped byte-register model; no live production lease.
    let mut registers = unsafe { narf_acpi::gpe_wake::__test_registers(block, &mut bytes) }
        .map_err(|_| "native fixed-GPE fixture could not be installed")?;
    let latch = crate::s2idle::wake_test_latch::Snapshot::capture();
    let mut owner =
        PciWake::discover(&cap, child).map_err(|_| "actual endpoint/ancestor route rejected")?;
    let mut successor = PciWake::discover(&cap2, child2)
        .map_err(|_| "actual second endpoint's shared ancestor route rejected")?;
    owner
        .arm(SleepState::S3, WakeState::D3Hot)
        .map_err(|_| "native wake owner could not arm")?;
    if !owner.armed()
        || value("ENAB")? != 1
        || value("SLPS")? != 3
        || value("DSTA")? != 3
        || value("FALL")? != 0
        || registers.byte(2) != 0x60
        || bridge.get(0x90) != 0x1234_0042
    {
        return Err("actual _DSW args, shared GPE enable, fallback or bridge authority was lost");
    }
    // Model native W1C status retirement, then a genuinely observed PME/GPE.
    endpoint.put(0x84, 0xa55a_8100);
    note_gpe_irq(69);
    if wake_event_pending() {
        return Err("unleased shared GPE became this device's wake event");
    }
    note_gpe_irq(70);
    if successor.arm(SleepState::S0Idle, WakeState::D0) != Err(WakeError::Gpe(WakeGpeError::Busy))
        || !wake_event_pending()
        || !owner.armed()
        || registers.byte(2) != 0x60
    {
        return Err("second-owner Busy erased the first lease's observed wake or ownership");
    }
    latch.clear(); // exact generic clear performed just before s2idle park
    if !wake_event_pending() || !crate::s2idle::wake_event_pending() {
        return Err("pre-park generic clear erased a real leased-GPE event");
    }
    let evidence = owner
        .disarm()
        .map_err(|_| "native wake terminal cleanup failed")?;
    if !evidence.endpoint_pme_pending
        || !evidence.gpe_observed
        || owner.armed()
        || registers.byte(2) != 0x20
        || registers.byte(0) != 0x20
        || value("ENAB")? != 0
        || endpoint.get(0x84) & 0x100 != 0
        || wake_event_pending()
    {
        return Err("terminal wake evidence or shared runtime-GPE restoration was lost");
    }
    owner
        .arm(SleepState::S0Idle, WakeState::D0)
        .map_err(|_| "PME-only cause cycle could not arm")?;
    endpoint.put(0x84, 0xa55a_8100); // actual pending cause, no GPE delivery
    {
        let _fault = narf_bus::pci::pme::__test_disarm_readback_failure(endpoint.physical);
        if owner.disarm() != Err(WakeError::Pme(PmeError::Readback)) {
            return Err("lost disable receipt fabricated terminal PME retirement");
        }
    }
    // Native hardware has W1C-cleared the cause. A retry can observe zero,
    // so only the retained pre-W1C observation can preserve that fact.
    endpoint.put(0x84, 0xa55a_0000);
    if !owner.owned.as_ref().unwrap().evidence.endpoint_pme_pending
        || owner.owned.as_ref().unwrap().evidence.gpe_observed
    {
        return Err("failed disable readback lost the independent pre-W1C PME cause");
    }
    registers.set_enable_hook(0x40, Some(observe_gpe));
    let mut handoff = None;
    let evidence = cleanup_with_handoff(owner.owned.as_mut().unwrap(), || {
        // This successor claims/observes an IRQ after the old hardware
        // release but before the old owner's final host bookkeeping.
        handoff = Some(successor.arm(SleepState::S0Idle, WakeState::D0));
    })
    .map_err(|_| "PME-only retry could not complete terminal cleanup")?;
    registers.set_enable_hook(0x40, None);
    if !evidence.endpoint_pme_pending
        || evidence.gpe_observed
        || handoff != Some(Ok(()))
        || !successor.armed()
        || !wake_event_pending()
    {
        return Err("old cleanup erased successor's early-enable IRQ or lost retained PME cause");
    }
    if owner.disarm().is_err() || !wake_event_pending() {
        return Err("repeated old cleanup consumed a successor generation's event");
    }
    if !successor
        .disarm()
        .map_err(|_| "successor cleanup failed")?
        .gpe_observed
    {
        return Err("early-enable IRQ was cleared after the new lease's arm");
    }
    narf_aml::eval::strict::evaluate_method("\\ZWK0.RP01.SETF", &[Value::Integer(1)])
        .map_err(|_| "actual firmware refusal fixture could not be selected")?;
    if owner.arm(SleepState::S0Idle, WakeState::D0) != Err(WakeError::Firmware)
        || owner.armed()
        || registers.byte(2) != 0x20
        || value("ENAB")? != 0
        || endpoint.get(0x84) & 0x100 != 0
    {
        return Err("firmware helper refusal fabricated successful wake or skipped rollback");
    }
    narf_aml::eval::strict::evaluate_method("\\ZWK0.RP01.SETF", &[Value::Integer(0)])
        .map_err(|_| "actual firmware refusal fixture could not be cleared")?;
    {
        let _fault =
            narf_bus::pci::pme::__test_arm_readback_failure(endpoint.physical, Some(observe_gpe));
        if owner.arm(SleepState::S0Idle, WakeState::D0) != Err(WakeError::Pme(PmeError::Readback)) {
            return Err("missing native PME arm receipt did not abort preparation");
        }
    }
    let evidence = owner
        .disarm()
        .map_err(|_| "failed PME receipt could not retire")?;
    if owner.armed()
        || !evidence.gpe_observed
        || registers.byte(2) != 0x20
        || endpoint.get(0x84) & 0x100 != 0
        || value("ENAB")? != 0
        || value("SLPS")? != 0
    {
        return Err("PME receipt rollback lost observed wake or existing runtime enable");
    }
    // Both currently granted authorities are checked at operation time.
    let mut stale = PciWake::discover(&cap, child).map_err(|_| "idle route reprobe failed")?;
    power.revoke();
    if stale.arm(SleepState::S0Idle, WakeState::D0) != Err(WakeError::Authority)
        || registers.byte(2) != 0x20
        || endpoint.get(0x84) & 0x100 != 0
    {
        return Err("revoked platform authority still changed wake registers");
    }
    // Idle stale owners hold no hardware, so dropping them needs no grant.
    drop(stale);
    drop(owner);
    if bridge.get(0x90) != 0x1234_0042 {
        return Err("child cap changed root-port policy");
    }
    Ok(())
}

fn native_wake_owner() -> TestResult {
    native_owner_uses_real_grants_routes_and_terminal_rollback()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("power/pci_wake", native_wake_owner);
