//! Bridge module: evaluate a device's _PRT / _CRS / _STA via the AML
//! method evaluator and decode the returned Value into structured
//! routing / resource entries.
//!
//! Limitation: firmware that declares _PRT/_CRS as Name(...)
//! rather than Method(...) is not handled — returns MethodNotFound.
//! (For _STA the Name form IS handled — see [`evaluate_sta_for`];
//! a plain integer literal is the form real firmware uses most.)

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::eval::evaluate_method;
use crate::resource::{
    decode_prt, decode_resource_template, PrtEntry, ResourceError, ResourceItem,
};
use crate::{find_node, AmlError, NodeKind, Value};

/// Errors from the _PRT / _CRS bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// No Method node found at the constructed path.
    MethodNotFound,
    /// The AML method evaluator returned an error.
    Eval(AmlError),
    /// The resource / PRT decoder returned an error.
    Decode(ResourceError),
    /// The method returned a Value type that doesn't match expectations
    /// (e.g. _CRS returned a Package instead of a Buffer).
    BadReturn,
}

impl From<AmlError> for BridgeError {
    fn from(e: AmlError) -> Self {
        BridgeError::Eval(e)
    }
}

impl From<ResourceError> for BridgeError {
    fn from(e: ResourceError) -> Self {
        BridgeError::Decode(e)
    }
}

/// Evaluate `<device_path>._PRT` and decode the result into a
/// `Vec<PrtEntry>`.
///
/// The method must be declared as `Method(_PRT, ...)` and must return
/// a `Package` of 4-element sub-packages. Name objects are not
/// evaluated; `MethodNotFound` is returned for those.
pub fn evaluate_prt_for(device_path: &str) -> Result<Vec<PrtEntry>, BridgeError> {
    let mut path = String::from(device_path);
    path.push_str("._PRT");
    let prt_path = path;

    let node = find_node(&prt_path).ok_or(BridgeError::MethodNotFound)?;
    let value = match node.kind {
        NodeKind::Method => evaluate_method(&prt_path, &[])?,
        NodeKind::Name => match node.value {
            // Most QEMU / EDK2 firmware writes `Name(_PRT, Package
            // {...})` rather than `Method(_PRT)`. Pull the recorded
            // body bytes from the global AML store and feed them
            // through the stateless decoder. The `Name` op + name
            // segment have already been consumed during namespace
            // build, so `(offset, length)` already points at the
            // package opcode.
            Some(crate::NameValue::Unparsed { offset, length }) => {
                // SEC-F4 (#1291): cap the allocation to the bytes
                // the AML store actually holds at this offset; the
                // `n < length` check below still rejects the
                // truncated body.
                let mut body = alloc::vec![0u8; length.min(crate::aml_remaining_len(offset))];
                let n = crate::copy_aml_bytes(offset, &mut body);
                if n < length {
                    return Err(AmlError::Truncated.into());
                }
                crate::eval::decode_value(&body)?
            }
            _ => return Err(BridgeError::BadReturn),
        },
        _ => return Err(BridgeError::MethodNotFound),
    };

    // _PRT must be a Package of sub-packages either way.
    match value {
        Value::Package(items) => Ok(decode_prt(&items)?),
        _ => Err(BridgeError::BadReturn),
    }
}

/// Evaluate `<device_path>._CRS` and decode the result into a
/// `Vec<ResourceItem>`.
///
/// Accepts both `Method(_CRS, ...)` returning a Buffer and
/// `Name(_CRS, ResourceTemplate { ... })`. The EC, button, and lid
/// devices almost universally use the Name form; PCIe host bridges
/// almost universally use the Method form.
pub fn evaluate_crs_for(device_path: &str) -> Result<Vec<ResourceItem>, BridgeError> {
    let mut path = String::from(device_path);
    path.push_str("._CRS");
    let crs_path = path;

    let node = find_node(&crs_path).ok_or(BridgeError::MethodNotFound)?;
    let value = match node.kind {
        NodeKind::Method => evaluate_method(&crs_path, &[])?,
        NodeKind::Name => match node.value {
            Some(crate::NameValue::Unparsed { offset, length }) => {
                // SEC-F4 (#1291): cap the allocation to the bytes
                // the AML store actually holds at this offset; the
                // `n < length` check below still rejects the
                // truncated body.
                let mut body = alloc::vec![0u8; length.min(crate::aml_remaining_len(offset))];
                let n = crate::copy_aml_bytes(offset, &mut body);
                if n < length {
                    return Err(AmlError::Truncated.into());
                }
                crate::eval::decode_value(&body)?
            }
            _ => return Err(BridgeError::BadReturn),
        },
        _ => return Err(BridgeError::MethodNotFound),
    };

    match value {
        Value::Buffer(buf) => Ok(decode_resource_template(&buf)?),
        _ => Err(BridgeError::BadReturn),
    }
}

/// ACPI 6.5 §6.1 `_STA` status bit 0: the device is present.
/// Only this bit gates enumeration — a device may report
/// enabled/UI/functioning bits without being present, and vice
/// versa; Linux's ACPI core (`acpi_bus_get_status` /
/// `acpi_bus_check_add`) likewise skips a device exactly when
/// the present bit is clear.
pub const STA_DEVICE_PRESENT: u64 = 0x01;

/// Evaluate `<device_path>._STA` and return the raw status bits.
///
/// Accepts both `Method(_STA, ...)` returning an Integer and
/// `Name(_STA, <integer>)` — the two forms real firmware uses
/// (QEMU/EDK2 emit the Method form; a constant `_STA` is
/// sometimes a Name). Unlike [`evaluate_crs_for`], the Name arm
/// handles a directly-decoded integer literal: the namespace
/// builder records `Name(_STA, 0x0F)` as
/// `NameValue::Integer`, not `Unparsed`, so mirroring the
/// `_CRS` Name arm verbatim would reject the common case.
///
/// Deliberately NOT built on `eval::evaluate_object`: that
/// helper silently folds an undecodable `Unparsed` body to
/// `Value::Integer(0)`, which for `_STA` would read as "absent"
/// and drop a device the evaluator simply could not decode.
/// Here every evaluation failure surfaces as `Err` so the
/// caller can apply the ACPI 6.5 §6.1 default — a device whose
/// `_STA` cannot be evaluated is treated as present, the same
/// assumption the spec mandates for a device with no `_STA`
/// at all — instead of silently enumerating it away.
///
/// `MethodNotFound` when the device declares no `_STA` object.
/// Any other error means `_STA` exists but could not be
/// evaluated (evaluator error, truncated body, non-Integer
/// return).
pub fn evaluate_sta_for(device_path: &str) -> Result<u64, BridgeError> {
    let mut path = String::from(device_path);
    path.push_str("._STA");
    let sta_path = path;

    let node = find_node(&sta_path).ok_or(BridgeError::MethodNotFound)?;
    let value = match node.kind {
        NodeKind::Method => evaluate_method(&sta_path, &[])?,
        NodeKind::Name => match node.value {
            Some(crate::NameValue::Integer(v)) => Value::Integer(v),
            Some(crate::NameValue::Unparsed { offset, length }) => {
                // Same SEC-F4-capped store decode as
                // `evaluate_crs_for`.
                let mut body = alloc::vec![0u8; length.min(crate::aml_remaining_len(offset))];
                let n = crate::copy_aml_bytes(offset, &mut body);
                if n < length {
                    return Err(AmlError::Truncated.into());
                }
                crate::eval::decode_value(&body)?
            }
            _ => return Err(BridgeError::BadReturn),
        },
        _ => return Err(BridgeError::MethodNotFound),
    };

    match value {
        Value::Integer(v) => Ok(v),
        _ => Err(BridgeError::BadReturn),
    }
}
