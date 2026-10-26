//! Smokes for the MTD core: partition parsing/bounds over a
//! RAM flash fake with honest NOR semantics (program ANDs,
//! erase resets a block to 0xFF), and the registry shape.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{attach_partitions, registry, MtdDevice, MtdError};

/// RAM flash with NOR semantics. 8 blocks x 4 KiB.
#[derive(Debug)]
struct RamFlash {
    name: String,
    data: IrqSafeSpinLock<Vec<u8>>,
}

impl RamFlash {
    fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            data: IrqSafeSpinLock::new(alloc::vec![0xFF; 8 * 4096]),
        }
    }
}

impl MtdDevice for RamFlash {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        8 * 4096
    }
    fn erase_size(&self) -> u32 {
        4096
    }
    fn write_size(&self) -> u32 {
        1
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError> {
        let data = self.data.lock();
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        buf.copy_from_slice(&data[off..off + buf.len()]);
        Ok(())
    }
    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError> {
        let mut data = self.data.lock();
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        for (i, b) in buf.iter().enumerate() {
            data[off + i] &= b; // NOR: program only clears bits
        }
        Ok(())
    }
    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError> {
        if off % 4096 != 0 || len % 4096 != 0 {
            return Err(MtdError::BadGeometry);
        }
        let mut data = self.data.lock();
        let (off, len) = (off as usize, len as usize);
        if off + len > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        data[off..off + len].fill(0xFF);
        Ok(())
    }
}

fn child(
    name: &str,
    reg: Option<(u64, u64)>,
    props: &[(&str, &[u8])],
    children: Vec<narf_bus::dt::DtChild>,
) -> narf_bus::dt::DtChild {
    narf_bus::dt::DtChild {
        name: String::from(name),
        compatible: Vec::new(),
        reg,
        props: props
            .iter()
            .map(|(n, v)| (String::from(*n), v.to_vec()))
            .collect(),
        children,
    }
}

fn partitions_node() -> narf_bus::dt::DtChild {
    let empty: &[u8] = &[];
    child(
        "partitions",
        None,
        &[],
        alloc::vec![
            child(
                "partition@0",
                Some((0, 8192)),
                &[("label", b"boot\0"), ("read-only", empty)],
                Vec::new(),
            ),
            child(
                "partition@2000",
                Some((8192, 16384)),
                &[("label", b"rootfs\0")],
                Vec::new(),
            ),
            // Not erase-aligned: attach must skip it.
            child(
                "partition@6000",
                Some((24576, 1000)),
                &[("label", b"odd\0")],
                Vec::new(),
            ),
        ],
    )
}

fn smoke_mtd_partition_bounds_and_readonly() -> TestResult {
    registry::__reset_for_test();
    let base: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("ramflash0"));
    registry::register_unique(base.clone());
    let attached = attach_partitions(&base, &partitions_node());
    if attached != 2 {
        return TestResult::Fail(
            "attach_partitions did not attach exactly the two aligned partitions",
        );
    }
    let Some(boot) = registry::find("ramflash0.boot") else {
        return TestResult::Fail("boot partition not registered");
    };
    if boot.size() != 8192 || boot.erase_size() != 4096 {
        return TestResult::Fail("boot partition geometry mismatch");
    }
    // Read-only partition refuses program + erase.
    if boot.write(0, &[0x00]) != Err(MtdError::ReadOnly)
        || boot.erase(0, 4096) != Err(MtdError::ReadOnly)
    {
        return TestResult::Fail("read-only partition accepted a write/erase");
    }
    let Some(rootfs) = registry::find("ramflash0.rootfs") else {
        return TestResult::Fail("rootfs partition not registered");
    };
    // Partition writes land at the base offset (0x2000).
    if rootfs.write(0, &[0x3C]).is_err() {
        return TestResult::Fail("rootfs write failed");
    }
    let mut byte = [0u8; 1];
    if base.read(8192, &mut byte).is_err() || byte[0] != 0x3C {
        return TestResult::Fail("partition write did not land at the base offset");
    }
    // AND semantics: programming 0x3C then 0xC3 without erase
    // yields 0x00 through the partition, like the base.
    if rootfs.write(0, &[0xC3]).is_err() {
        return TestResult::Fail("rootfs second write failed");
    }
    if rootfs.read(0, &mut byte).is_err() || byte[0] != 0x00 {
        return TestResult::Fail("partition write did not honour NOR AND semantics");
    }
    // Bounds: past the end refuses on read + write; erase
    // alignment is the base driver's contract, surfaced.
    if rootfs.read(16384, &mut byte) != Err(MtdError::OutOfBounds)
        || rootfs.write(16383, &[0x00, 0x00]) != Err(MtdError::OutOfBounds)
        || rootfs.erase(16, 4096) != Err(MtdError::BadGeometry)
    {
        return TestResult::Fail("partition bounds/geometry enforcement mismatch");
    }
    // Erase through the partition resets only its own range.
    if rootfs.erase(0, 4096).is_err() {
        return TestResult::Fail("rootfs erase failed");
    }
    if rootfs.read(0, &mut byte).is_err() || byte[0] != 0xFF {
        return TestResult::Fail("partition erase did not reset its first block");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("storage-mtd", smoke_mtd_partition_bounds_and_readonly);

fn smoke_mtd_registry_dedupes_by_name() -> TestResult {
    registry::__reset_for_test();
    let a: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("dup"));
    let b: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("dup"));
    registry::register_unique(a);
    let again = registry::register_unique(b);
    if registry::count() != 1 || registry::list().len() != 1 {
        return TestResult::Fail("MTD registry did not dedupe by name");
    }
    if again.name() != "dup" {
        return TestResult::Fail("MTD registry returned the wrong device");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("storage-mtd", smoke_mtd_registry_dedupes_by_name);
