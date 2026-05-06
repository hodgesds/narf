//! Bridge module: evaluate a device's _PRT / _CRS via the AML
//! method evaluator and decode the returned Value into structured
//! routing / resource entries.
//!
//! Limitation: firmware that declares _PRT/_CRS as Name(...)
//! rather than Method(...) is not handled — returns MethodNotFound.

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
    let method_path = path;

    // Confirm the node exists and is a Method.
    let node = find_node(&method_path).ok_or(BridgeError::MethodNotFound)?;
    if node.kind != NodeKind::Method {
        return Err(BridgeError::MethodNotFound);
    }

    // Evaluate with no arguments.
    let value = evaluate_method(&method_path, &[])?;

    // _PRT must return a Package of sub-packages.
    match value {
        Value::Package(items) => Ok(decode_prt(&items)?),
        _ => Err(BridgeError::BadReturn),
    }
}

/// Evaluate `<device_path>._CRS` and decode the result into a
/// `Vec<ResourceItem>`.
///
/// The method must be declared as `Method(_CRS, ...)` and must return
/// a `Buffer` containing a valid ACPI resource template. Name objects
/// are not evaluated; `MethodNotFound` is returned for those.
pub fn evaluate_crs_for(device_path: &str) -> Result<Vec<ResourceItem>, BridgeError> {
    let mut path = String::from(device_path);
    path.push_str("._CRS");
    let method_path = path;

    // Confirm the node exists and is a Method.
    let node = find_node(&method_path).ok_or(BridgeError::MethodNotFound)?;
    if node.kind != NodeKind::Method {
        return Err(BridgeError::MethodNotFound);
    }

    // Evaluate with no arguments.
    let value = evaluate_method(&method_path, &[])?;

    // _CRS must return a Buffer containing a resource template.
    match value {
        Value::Buffer(buf) => Ok(decode_resource_template(&buf)?),
        _ => Err(BridgeError::BadReturn),
    }
}
