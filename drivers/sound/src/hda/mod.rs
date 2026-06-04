//! HDA controller layer — PCI probe, register block, CORB/RIRB,
//! stream descriptors, widget graph walker.

pub mod controller;
pub mod corb;
pub mod rirb;
pub mod streams;
pub mod widget;

pub use controller::{
    HdaController, ProbeError as HdaProbeError, HDA_AMD_PHOENIX_DEVICE, HDA_AMD_PHOENIX_VENDOR,
    HDA_AMD_RENOIR_DEVICE, HDA_AMD_RENOIR_VENDOR, HDA_CLASS_TRIPLE, HDA_INTEL_VENDOR, REGISTRY,
};
