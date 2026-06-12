//! Classic AC97 Audio driver (intel8x0).
//!
//! Provides support for Intel 82801AA/AB/BA/CA/DB/EB/FB/GB (ICH) and
//! equivalent AC97 controllers, standard in older hardware and VMs.
//!
//! References: `linux/sound/pci/intel8x0.c`

extern crate alloc;

pub fn register_initcalls() {
    // Placeholder for PCI vendor=0x8086 matches
}
