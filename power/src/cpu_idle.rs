//! ACPI CPU idle-state discovery.

use alloc::vec::Vec;
use narf_aml::{NodeKind, Value};
use narf_capabilities::{Cap, Grant};
use narf_power_core::{IdleEntry, IdleState, Power, PowerError};

struct Processor {
    path: alloc::string::String,
    apic_id: u32,
    authority: Cap<Power, Grant>,
    revision: u64,
}
static PROCESSORS: narf_lib::sync::IrqSafeSpinLock<Vec<Processor>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

fn read_states(path: &str) -> Option<Vec<IdleState>> {
    // Coupled domains require a coordinated entry protocol.
    if narf_aml::find_node(&alloc::format!("{path}._CSD")).is_some() {
        return None;
    }
    let value =
        narf_aml::eval::strict::evaluate_object(&alloc::format!("{path}._CST"), &[]).ok()?;
    decode_cst(&value)
}

fn notify(path: &str, value: u64) {
    if value != 0x81 {
        return;
    }
    let revision = {
        let mut processors = PROCESSORS.lock();
        let Some(cpu) = processors.iter_mut().find(|cpu| cpu.path == path) else {
            return;
        };
        cpu.revision = cpu.revision.wrapping_add(1);
        // Withdraw the old table before scheduling AML re-evaluation.
        let _ =
            narf_power_core::executor::register_firmware_states(&cpu.authority, cpu.apic_id, &[]);
        cpu.revision
    };
    let path = alloc::string::String::from(path);
    narf_scheduler::spawn(async move {
        let states = read_states(&path).unwrap_or_default();
        let processors = PROCESSORS.lock();
        if let Some(cpu) = processors
            .iter()
            .find(|cpu| cpu.path == path && cpu.revision == revision)
        {
            let _ = narf_power_core::executor::register_firmware_states(
                &cpu.authority,
                cpu.apic_id,
                &states,
            );
        }
    });
}

fn integer(value: &Value) -> Option<u64> {
    if let Value::Integer(value) = value {
        Some(*value)
    } else {
        None
    }
}

/// Decode an exact ACPI Generic Register resource. Unknown register spaces and
/// entry methods are skipped; no guessed port or C-state-to-MWAIT mapping.
fn entry(register: &[u8], acpi_type: u8) -> Option<IdleEntry> {
    if register.len() != 17 || register[..3] != [0x82, 12, 0] || register[15] != 0x79 {
        return None;
    }
    if register[16] != 0 && register.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
        return None;
    }
    let address = u64::from_le_bytes(register[7..15].try_into().ok()?);
    match register[3] {
        0x7f if register[4] == 1 && register[5] == 2 && register[6] & 2 == 0 => {
            // FFH bit_offset=2 identifies native MWAIT. A requested bus-master
            // status check needs additional platform handling and is rejected.
            Some(IdleEntry::Mwait {
                hint: u32::try_from(address).ok()?,
            })
        }
        0x7f if acpi_type == 1 && register[5] == 0 => Some(IdleEntry::Halt),
        1 if matches!(acpi_type, 2 | 3)
            && register[4] == 8
            && register[5] == 0
            && register[6] <= 1
            && address != 0 =>
        {
            Some(IdleEntry::SystemIo {
                port: u16::try_from(address).ok()?,
                acpi_type,
            })
        }
        _ => None,
    }
}

/// Validate `_CST` package shape, integer widths, resource descriptors and
/// state types before publishing anything to a CPU's idle driver.
pub(crate) fn decode_cst(value: &Value) -> Option<Vec<IdleState>> {
    let Value::Package(package) = value else {
        return None;
    };
    let count = usize::try_from(integer(package.first()?)?).ok()?;
    if count == 0
        || count >= narf_power_core::executor::MAX_IDLE_STATES
        || package.len() != count + 1
    {
        return None;
    }
    let mut states = Vec::with_capacity(count);
    for (index, value) in package[1..].iter().enumerate() {
        let Value::Package(fields) = value else {
            return None;
        };
        if fields.len() != 4 {
            return None;
        }
        let Value::Buffer(register) = &fields[0] else {
            return None;
        };
        let acpi_type = u8::try_from(integer(&fields[1])?).ok()?;
        let exit_latency_us = u32::from(u16::try_from(integer(&fields[2])?).ok()?);
        let _power_mw = u32::try_from(integer(&fields[3])?).ok()?;
        if !matches!(acpi_type, 1..=3) {
            continue;
        }
        let Some(entry) = entry(register, acpi_type) else {
            continue;
        };
        // _CST supplies exit latency, not target residency. Twice the exit
        // latency is the conservative ACPI-driver break-even estimate.
        states.push(IdleState {
            id: if acpi_type == 1 { 1 } else { (index + 2) as u8 },
            exit_latency_us,
            target_residency_us: exit_latency_us.saturating_mul(2),
            entry,
        });
    }
    Some(states)
}

/// Publish firmware tables for enabled MADT CPUs. Missing or unsupported AML
/// leaves that CPU on its built-in shallow-idle fallback.
pub fn discover(cap: &Cap<Power, Grant>) -> Result<usize, PowerError> {
    cap.check_live()?;
    if let Some(pm) = narf_acpi::fadt_pm() {
        if pm.cst_control != 0 {
            let port = u16::try_from(pm.smi_cmd)
                .ok()
                .filter(|port| *port != 0)
                .ok_or(PowerError::NoMatchingState)?;
            // SAFETY: checksummed FADT requests this byte write; live platform grant.
            unsafe { narf_arch::x86_64::io_port::outb(port, pm.cst_control) };
        }
    }
    let mut processors = Vec::new();
    narf_aml::for_each_node_of_kind(NodeKind::Processor, |node| processors.push(node.clone()));
    narf_aml::for_each_device(|node| {
        if narf_aml::device_hid(&node.path).as_deref() == Some("ACPI0007") {
            processors.push(node.clone());
        }
    });
    let mut registered = 0;
    for node in processors {
        let uid = if let Some(id) = node.processor_id {
            Some(u32::from(id))
        } else {
            narf_aml::eval::strict::evaluate_object(&alloc::format!("{}._UID", node.path), &[])
                .ok()
                .and_then(|value| integer(&value))
                .and_then(|uid| u32::try_from(uid).ok())
        };
        let Some(apic_id) = uid.and_then(narf_acpi::apic_id_for_processor_uid) else {
            continue;
        };
        let Some(states) = read_states(&node.path) else {
            continue;
        };
        if states.is_empty() {
            continue;
        }
        narf_power_core::executor::register_firmware_states(cap, apic_id, &states)?;
        let mut processors = PROCESSORS.lock();
        if !processors.iter().any(|cpu| cpu.path == node.path) {
            narf_aml::sync::register_notify_handler(&node.path, notify);
            processors.push(Processor {
                path: node.path,
                apic_id,
                authority: *cap,
                revision: 0,
            });
        }
        registered += 1;
    }
    Ok(registered)
}
