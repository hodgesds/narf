//! Resolve PCI devices through the ACPI namespace without guessing a laptop model.
use alloc::{format, string::String, vec::Vec};
use narf_aml::{NameValue, Value};
use narf_bus::{BusDevice, BusKind};

pub(crate) fn value(path: &str) -> Option<Value> {
    fn convert(v: NameValue) -> Option<Value> {
        Some(match v {
            NameValue::Integer(v) => Value::Integer(v),
            NameValue::String(v) => Value::String(v),
            NameValue::Buffer(v) => Value::Buffer(v),
            NameValue::Package(v) => {
                Value::Package(v.into_iter().map(convert).collect::<Option<Vec<_>>>()?)
            }
            _ => return None,
        })
    }
    narf_aml::find_node(path)
        .and_then(|n| n.value)
        .and_then(convert)
        .or_else(|| narf_aml::eval::evaluate_method(path, &[]).ok())
}
fn integer(path: &str) -> Option<u64> {
    match value(path)? {
        Value::Integer(v) => Some(v),
        _ => None,
    }
}
/// Match root segment/bus and each bridge's secondary bus before the endpoint.
/// This disambiguates identical device/function numbers on different buses.
pub(crate) fn pci_path(device: &BusDevice) -> Option<String> {
    let BusKind::Pcie { addr: target, .. } = device.kind else {
        return None;
    };
    let paths = narf_aml::list_all_device_paths();
    let devices = narf_bus::devices();
    let mut pending = Vec::new();
    for path in &paths {
        let hid = narf_aml::device_hid(path);
        if matches!(hid.as_deref(), Some("PNP0A03" | "PNP0A08"))
            && integer(&format!("{path}._SEG")).unwrap_or(0) == target.segment as u64
        {
            pending.push((
                path.clone(),
                integer(&format!("{path}._BBN")).unwrap_or(0) as u8,
                0u8,
            ));
        }
    }
    while let Some((parent, bus, depth)) = pending.pop() {
        if depth >= 16 {
            continue;
        }
        for path in &paths {
            if path.rsplit_once('.').map(|x| x.0) != Some(parent.as_str()) {
                continue;
            }
            let Some(adr) = integer(&format!("{path}._ADR")) else {
                continue;
            };
            if adr & !0x1f_0007 != 0 {
                continue;
            }
            let slot = (adr >> 16) as u8;
            let function = adr as u8;
            if bus == target.bus && slot == target.device && function == target.function {
                return Some(path.clone());
            }
            for bridge in &devices {
                if let BusKind::Pcie { addr, cfg_phys } = bridge.kind {
                    if addr.segment == target.segment
                        && addr.bus == bus
                        && addr.device == slot
                        && addr.function == function
                        && bridge.id.class >> 8 == 0x0604
                    {
                        // SAFETY: read-only snapshot of enumerated PCI bridge config.
                        let Some(pointer) = narf_bus::ecam::ptr_for(cfg_phys, 0x18) else {
                            continue;
                        };
                        // SAFETY: Pointer addresses the bus-number dword of an enumerated bridge's mapped ECAM.
                        let buses = unsafe { pointer.cast::<u32>().read_volatile() };
                        let secondary = (buses >> 8) as u8;
                        let subordinate = (buses >> 16) as u8;
                        if secondary > bus && target.bus >= secondary && target.bus <= subordinate {
                            pending.push((path.clone(), secondary, depth + 1));
                        }
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn acp_dmic_present(device: &BusDevice) -> bool {
    let Some(parent) = pci_path(device) else {
        return false;
    };
    let wov = integer(&format!("{parent}._WOV"));
    if wov == Some(0) {
        return false;
    }
    narf_aml::list_all_device_paths().iter().any(|path| {
        if path.rsplit_once('.').map(|x| x.0) != Some(parent.as_str())
            || integer(&format!("{path}._ADR")) != Some(2)
        {
            return false;
        }
        let Some(Value::Package(dsd)) = value(&format!("{path}._DSD")) else {
            return false;
        };
        dsd_has_dmic(&dsd)
    })
}

fn dsd_has_dmic(dsd: &[Value]) -> bool {
    dsd.chunks_exact(2).any(|pair| match (&pair[0], &pair[1]) {
        // Standard ACPI device-properties UUID, in ACPI buffer byte order.
        (Value::Buffer(uuid), Value::Package(properties))
            if uuid.as_slice()
                == [
                    0x14, 0xd8, 0xff, 0xda, 0xba, 0x6e, 0x8c, 0x4d, 0x8a, 0x91, 0xbc, 0x9b, 0xbf,
                    0x4a, 0xa3, 0x01,
                ] =>
        {
            properties.iter().any(|entry| match entry {
                Value::Package(p) => matches!(p.as_slice(),
                    [Value::String(key), Value::Integer(2)] if key == "acp-audio-device-type"),
                _ => false,
            })
        }
        _ => false,
    })
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn native_acp_dmic_properties() -> TestResult {
        let mut properties = alloc::vec![
            Value::Buffer(alloc::vec![
                0x14, 0xd8, 0xff, 0xda, 0xba, 0x6e, 0x8c, 0x4d, 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a,
                0xa3, 0x01,
            ]),
            Value::Package(alloc::vec![Value::Package(alloc::vec![
                Value::String("acp-audio-device-type".into()),
                Value::Integer(2),
            ])]),
        ];
        if !dsd_has_dmic(&properties) {
            return TestResult::Fail("standard DMIC property");
        }
        properties[0] = Value::Buffer(alloc::vec![0; 16]);
        if dsd_has_dmic(&properties) || dsd_has_dmic(&properties[..1]) {
            return TestResult::Fail("foreign UUID/malformed _DSD must not enable capture");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp_dmic_properties);
}
