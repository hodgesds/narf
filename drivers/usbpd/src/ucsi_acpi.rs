//! ACPI PNP0CA0 UCSI transport, matching Linux ucsi_acpi.c's _DSM
//! revision 1 functions 1 (write) and 2 (refresh shared memory).
use super::ucsi::{Error, Ppm, Transport};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::{
    fmt::Write as _,
    sync::atomic::{fence, AtomicBool, AtomicU8, Ordering},
};
use narf_aml::{resource::ResourceItem, NameValue, Value};
use narf_memory::ioremap::{ioremap, iounmap, IoMapping, MmioAttrs};

const UUID: [u8; 16] = [
    0xc2, 0x98, 0x83, 0x6f, 0xa4, 0x7c, 0xe4, 0x11, 0xad, 0x36, 0x63, 0x10, 0x42, 0xb5, 0x00, 0x8f,
];
struct PowerState {
    // 0 idle, 1 command sequence, 2 suspended.
    phase: AtomicU8,
    reset: AtomicBool,
}
impl narf_power::device_pm::DevicePmOps for PowerState {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.phase
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| narf_power::device_pm::DevicePmError::Busy)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        if self.phase.load(Ordering::Acquire) == 2 {
            self.reset.store(true, Ordering::Release);
            self.phase.store(0, Ordering::Release);
        }
        Ok(())
    }
}
struct AcpiTransport {
    path: String,
    mapping: IoMapping,
    len: usize,
}
impl AcpiTransport {
    fn dsm(&self, function: u64) -> Result<(), Error> {
        narf_aml::eval::evaluate_dsm(&self.path, UUID, 1, function, Value::Package(Vec::new()))
            .map(|_| ())
            .map_err(|_| Error::Io)
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(Error::Protocol);
        }
        fence(Ordering::SeqCst);
        for (i, byte) in out.iter_mut().enumerate() {
            // SAFETY: _CRS describes the PPM-owned shared region, mapped WB;
            // bounds checked above. Volatile accesses prevent cached Rust loads.
            *byte =
                unsafe { ((self.mapping.va() as usize + offset + i) as *const u8).read_volatile() };
        }
        fence(Ordering::SeqCst);
        Ok(())
    }
}
impl Transport for AcpiTransport {
    fn version(&mut self) -> Result<u16, Error> {
        self.dsm(2)?;
        let mut bytes = [0; 2];
        self.read(0, &mut bytes)?;
        let version = u16::from_le_bytes(bytes);
        let required = if version <= 0x0120 { 48 } else { 528 };
        if self.len < required {
            return Err(Error::Protocol);
        }
        Ok(version)
    }
    fn cci(&mut self) -> Result<u32, Error> {
        self.dsm(2)?;
        let mut bytes = [0; 4];
        self.read(4, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn control(&mut self, command: u64) -> Result<(), Error> {
        if self.len < 16 {
            return Err(Error::Protocol);
        }
        for (i, byte) in command.to_le_bytes().iter().enumerate() {
            // SAFETY: control is bytes 8..16 of our exclusively owned mapping.
            unsafe { ((self.mapping.va() as usize + 8 + i) as *mut u8).write_volatile(*byte) };
        }
        fence(Ordering::SeqCst);
        self.dsm(1)
    }
    fn message(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.read(16, data)
    }
}
impl Drop for AcpiTransport {
    fn drop(&mut self) {
        // SAFETY: the owning task has stopped issuing commands; UCSI shared
        // memory belongs to firmware and is never returned to the allocator.
        unsafe { iounmap(self.mapping) };
    }
}

fn resource(path: &str) -> Option<(u64, u64)> {
    let crs = format!("{path}._CRS");
    let bytes = match narf_aml::find_node(&crs).and_then(|n| n.value) {
        Some(NameValue::Buffer(b)) => b,
        _ => match narf_aml::eval::evaluate_method(&crs, &[]).ok()? {
            Value::Buffer(b) => b,
            _ => return None,
        },
    };
    let resources = narf_aml::resource::decode_resource_template(&bytes).ok()?;
    resources
        .into_iter()
        .find_map(|r| match r {
            ResourceItem::Memory32Fixed { base, length, .. } => Some((base as u64, length as u64)),
            ResourceItem::Memory32 {
                min, max, length, ..
            } if min == max => Some((min as u64, length as u64)),
            ResourceItem::AddressSpace32 {
                kind: 0,
                min,
                translation,
                length,
                ..
            } => (min as u64)
                .checked_add(translation as u64)
                .map(|b| (b, length as u64)),
            ResourceItem::AddressSpace64 {
                kind: 0,
                min,
                translation,
                length,
                ..
            } => min.checked_add(translation).map(|b| (b, length)),
            _ => None,
        })
        .filter(|(base, len)| {
            *base != 0 && (48..=65536).contains(len) && base.checked_add(*len).is_some()
        })
}

pub(crate) fn probe() -> narf_init::InitResult {
    let mut found = 0;
    for node in narf_aml::find_all_devices_by_hid("PNP0CA0") {
        // Respect a disabled firmware device. Missing _STA means present.
        let sta_path = format!("{}._STA", node.path);
        let sta = match narf_aml::find_node(&sta_path).and_then(|n| n.value) {
            Some(NameValue::Integer(value)) => Some(value),
            _ => match narf_aml::eval::evaluate_method(&sta_path, &[]) {
                Ok(Value::Integer(value)) => Some(value),
                _ => None,
            },
        };
        if let Some(sta) = sta {
            if sta & 3 != 3 {
                continue;
            }
        }
        let Some((base, len)) = resource(&node.path) else {
            let _ = writeln!(
                narf_console::Writer,
                "ucsi: {} has no valid shared memory resource",
                node.path
            );
            continue;
        };
        // SAFETY: a present PNP0CA0's _CRS names firmware shared memory;
        // Linux maps this WB as well. Never remap it as uncached MMIO.
        let Ok(mapping) = (unsafe { ioremap(base, len, MmioAttrs::WriteBack) }) else {
            continue;
        };
        let path = node.path;
        let transport = AcpiTransport {
            path: path.clone(),
            mapping,
            len: len as usize,
        };
        let pm = Arc::new(PowerState {
            phase: AtomicU8::new(1),
            reset: AtomicBool::new(true),
        });
        narf_power::device_pm::register_device_pm_ops(&format!("ucsi:{path}"), pm.clone());
        // _DSM read is a polling fallback for platforms without ACPI Notify.
        // The PM gate excludes AML/CCI access while firmware is asleep.
        narf_scheduler::spawn(async move {
            let mut ppm = match Ppm::new(transport) {
                Ok(ppm) => ppm,
                Err(e) => {
                    pm.phase.store(0, Ordering::Release);
                    let _ = writeln!(narf_console::Writer, "ucsi: {path}: {e:?}");
                    return;
                }
            };
            let mut ports = Vec::new();
            let mut failures = 0;
            pm.phase.store(0, Ordering::Release);
            loop {
                if pm
                    .phase
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let result = if pm.reset.swap(false, Ordering::AcqRel) {
                        match ppm.initialize(&path).await {
                            Ok(current) => {
                                ports = current;
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "ucsi: {path} v{:04x}, {} connectors",
                                    ppm.version,
                                    ports.len()
                                );
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        ppm.poll(&mut ports).await
                    };
                    match result {
                        Ok(()) => failures = 0,
                        Err(e) => {
                            super::ucsi::invalidate(&path);
                            failures += 1;
                            pm.reset.store(true, Ordering::Release);
                            let _ = writeln!(
                                narf_console::Writer,
                                "ucsi: {path} command failed ({failures}/3): {e:?}"
                            );
                        }
                    }
                    pm.phase.store(0, Ordering::Release);
                    if failures == 3 {
                        break;
                    }
                }
                narf_time::SleepUntil::new(
                    narf_time::Deadline::after_ms(if failures == 0 { 100 } else { 1000 })
                        .as_instant(),
                )
                .await;
            }
        });
        found += 1;
    }
    if found == 0 {
        narf_init::InitResult::NotPresent
    } else {
        narf_init::InitResult::Ok
    }
}
