use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

/// A whole-device store in memory.
struct MemDevice(IrqSafeSpinLock<Vec<u8>>);
impl ImageStore for MemDevice {
    fn len_bytes(&self) -> u64 {
        self.0.lock().len() as u64
    }
    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        let g = self.0.lock();
        let at = offset as usize;
        out.copy_from_slice(g.get(at..at + out.len()).ok_or(ServiceError::Store)?);
        Ok(())
    }
    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
        let mut g = self.0.lock();
        let at = offset as usize;
        g.get_mut(at..at + data.len())
            .ok_or(ServiceError::Store)?
            .copy_from_slice(data);
        Ok(())
    }
    fn flush(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}

/// A per-block map coalesces into extents and round-trips through the
/// locator block; a locator with a gap, a bad magic or too many extents is
/// refused.
fn locator_coalesces_and_round_trips() -> TestResult {
    let locator = Locator::from_map(&[10, 11, 12, 40, 41, 7]);
    let want = [
        Extent {
            file_block: 0,
            device_block: 10,
            blocks: 3,
        },
        Extent {
            file_block: 3,
            device_block: 40,
            blocks: 2,
        },
        Extent {
            file_block: 5,
            device_block: 7,
            blocks: 1,
        },
    ];
    if locator.extents != want || locator.file_blocks != 6 {
        return TestResult::Fail("the block map did not coalesce into its extents");
    }
    if locator.device_block(4) != Some(41) || locator.device_block(6).is_some() {
        return TestResult::Fail("a file block resolved to the wrong device block");
    }
    let Some(page) = locator.encode() else {
        return TestResult::Fail("three extents did not encode");
    };
    if Locator::decode(&page) != Ok(locator.clone()) {
        return TestResult::Fail("the locator did not round-trip");
    }
    let mut gap = page;
    gap[LOCATOR_HEADER + EXTENT_LEN..LOCATOR_HEADER + EXTENT_LEN + 8]
        .copy_from_slice(&4u64.to_le_bytes());
    let mut magic = page;
    magic[0] ^= 1;
    if Locator::decode(&gap) != Err(LocatorError::Malformed)
        || Locator::decode(&magic) != Err(LocatorError::Magic)
    {
        return TestResult::Fail("a gapped or unmarked locator decoded");
    }
    let scattered: Vec<u64> = (0..MAX_EXTENTS as u64 + 1).map(|i| 100 + 2 * i).collect();
    if Locator::from_map(&scattered).encode().is_some() {
        return TestResult::Fail("a locator with too many extents encoded");
    }
    TestResult::Pass
}
kernel_test_in!("power/hibernate", locator_coalesces_and_round_trips);

/// The extent store skips the locator block and lands every byte on the
/// device block its extent names, also for a write that crosses extents.
fn extent_store_maps_through_the_locator() -> TestResult {
    // File blocks 0..4: the locator at device 2, then 5, 6 and 1.
    let locator = Locator::from_map(&[2, 5, 6, 1]);
    let store = ExtentStore::new(
        MemDevice(IrqSafeSpinLock::new(vec![0; 8 * BLOCK as usize])),
        locator,
    );
    if store.len_bytes() != 3 * BLOCK {
        return TestResult::Fail("the image region is not the file minus its locator");
    }
    let data: Vec<u8> = (0..3 * BLOCK).map(|i| (i / BLOCK) as u8 + 1).collect();
    if store.write_all(0, &data).is_err() {
        return TestResult::Fail("a write across extents failed");
    }
    let dev = store.device.0.lock().clone();
    let block = |b: usize| &dev[b * BLOCK as usize..(b + 1) * BLOCK as usize];
    if block(5).iter().any(|&b| b != 1)
        || block(6).iter().any(|&b| b != 2)
        || block(1).iter().any(|&b| b != 3)
    {
        return TestResult::Fail("image bytes landed on the wrong device blocks");
    }
    if block(2).iter().any(|&b| b != 0) {
        return TestResult::Fail("the image write touched the locator block");
    }
    let mut back = vec![0u8; 100];
    if store.read_exact(2 * BLOCK - 50, &mut back).is_err()
        || back[..50].iter().any(|&b| b != 2)
        || back[50..].iter().any(|&b| b != 3)
    {
        return TestResult::Fail("a read across extents returned the wrong bytes");
    }
    if store.write_all(3 * BLOCK - 1, &[0, 0]).is_ok() {
        return TestResult::Fail("a write past the image region was accepted");
    }
    TestResult::Pass
}
kernel_test_in!("power/hibernate", extent_store_maps_through_the_locator);
