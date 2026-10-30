use super::*;
use alloc::vec;
use alloc::vec::Vec;
use narf_bus::{BusAddr, BusKind, DeviceId, PcieAddr};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

struct Config {
    _bytes: Vec<u8>,
    pointer: *mut u8,
    physical: PhysAddr,
}

impl Config {
    fn new() -> Self {
        let mut bytes = vec![0u8; 8192];
        let pointer = ((bytes.as_mut_ptr() as usize + 4095) & !4095) as *mut u8;
        Self {
            _bytes: bytes,
            pointer,
            physical: PhysAddr::from_kernel_ptr(pointer),
        }
    }

    fn put(&self, offset: usize, value: u32) {
        assert!(offset % 4 == 0 && offset < 4096);
        // SAFETY: aligned word wholly inside the owned config window.
        unsafe { self.pointer.add(offset).cast::<u32>().write_volatile(value) };
    }

    fn device(&self, bus: u8, slot: u8) -> BusDevice {
        let addr = PcieAddr::new(0x7f33, bus, slot, 0);
        BusDevice {
            addr: BusAddr::Pcie(addr),
            id: DeviceId {
                vendor: 0x8086,
                device: 0x1234,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr,
                cfg_phys: self.physical,
            },
        }
    }
}

struct RestoreRegistry(Vec<BusDevice>);

impl Drop for RestoreRegistry {
    fn drop(&mut self) {
        narf_bus::registry::install(core::mem::take(&mut self.0));
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
    let mut endpoint = b"EP00\x08_ADR\x00\x08SEEN\x00".to_vec();
    let mut wrds = b"WRDS\x00\xa4".to_vec();
    wrds.extend_from_slice(&package(&[0x12], &[2, 0, 0x0a, 42]));
    endpoint.extend_from_slice(&package(&[0x14], &wrds));
    endpoint.extend_from_slice(&package(&[0x14], b"EWRD\x00\x70\x01SEEN\xa4\x0a\x4d"));
    endpoint.extend_from_slice(&package(&[0x14], b"WGDS\x00\x5b\x34"));
    let mut port = b"RP01\x08_ADR\x0c\x00\x00\x01\x00\x08WRDS\x0a\x63".to_vec();
    port.extend_from_slice(&package(&[0x5b, 0x82], &endpoint));
    let mut root = b"ZMD0\x08_HID\x0dPNP0A08\x00\x08_SEG\x0b\x33\x7f\x08_BBN\x00".to_vec();
    root.extend_from_slice(&package(&[0x5b, 0x82], &port));
    let mut body = package(&[0x5b, 0x82], &root);
    body.extend_from_slice(&package(
        &[0x5b, 0x82],
        b"NOPE\x08_HID\x0dPNP0A08\x00\x08_SEG\x01\x08_BBN\x00\x08WRDS\x0a\x63",
    ));
    body
}

fn native_metadata() -> Result<(), &'static str> {
    let _registry = RestoreRegistry(narf_bus::registry::devices());
    // SAFETY: serialized native fixture; no active metadata facade survives
    // the namespace or config scopes, and no wake lease is created.
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    narf_aml::__parse_body_for_test(&firmware(), "\\").map_err(|_| "typed metadata AML parse")?;
    let bridge = Config::new();
    let endpoint = Config::new();
    let missing = Config::new();
    // SAFETY: three uniquely owned ECAM windows outlive this registration.
    let _ecam = unsafe {
        narf_bus::ecam::__test_windows(&[
            (bridge.physical, bridge.pointer, 4096),
            (endpoint.physical, endpoint.pointer, 4096),
            (missing.physical, missing.pointer, 4096),
        ])
    };
    bridge.put(0x0c, 1 << 16);
    bridge.put(0x18, 0x0003_0300);
    // No PMC, _PRW or SCI is supplied: this is endpoint metadata lookup.
    let child = endpoint.device(3, 0);
    let absent_child = missing.device(3, 1);
    narf_bus::registry::install(vec![bridge.device(0, 1), child, absent_child]);
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let absent_cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let power = crate::bootstrap_power_authority();
    // SAFETY: serialized scope; all facades below are dropped first.
    let _authority = unsafe { __test_platform_authority_scope(&power) }
        .map_err(|_| "typed metadata actual platform grant")?;
    let metadata = PciMetadata::discover(&cap, child).map_err(|_| "exact metadata companion")?;
    let absent = PciMetadata::discover(&absent_cap, absent_child)
        .map_err(|_| "missing companion was an invalid topology")?;
    if metadata.endpoint_path() != Some("\\ZMD0.RP01.EP00")
        || metadata.object(PciMetadataKey::Wrds)
            != Ok(Some(Value::Package(vec![
                Value::Integer(0),
                Value::Integer(42),
            ])))
        || metadata.object(PciMetadataKey::Ppag) != Ok(None)
        || metadata.object(PciMetadataKey::Wgds) != Err(MetadataError::Firmware)
        || absent.endpoint_path().is_some()
        || absent.object(PciMetadataKey::Wrds) != Ok(None)
        || metadata.object(PciMetadataKey::Ewrd) != Ok(Some(Value::Integer(77)))
        || narf_aml::eval::strict::evaluate_object("\\ZMD0.RP01.EP00.SEEN", &[])
            != Ok(Value::Integer(1))
    {
        return Err("typed metadata lost exact identity, absence, real method effects or failure");
    }
    cap.revoke();
    if metadata.object(PciMetadataKey::Wrds) != Err(MetadataError::Authority) {
        return Err("revoked endpoint still executed metadata firmware");
    }
    power.revoke();
    if absent.object(PciMetadataKey::Wrds) != Err(MetadataError::Authority) {
        return Err("missing metadata hid revoked platform authority");
    }
    Ok(())
}

fn typed_pci_metadata_uses_exact_companion_and_real_granted_firmware_execution() -> TestResult {
    native_metadata().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "power/pci_firmware",
    typed_pci_metadata_uses_exact_companion_and_real_granted_firmware_execution
);
