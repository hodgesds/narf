use super::*;
use crate::hibernate::payload::{Pages, PayloadSource, ARCH_RECORD_LEN};
use crate::suspend_service::{
    attempt_resume, KeyEntropy, PolicyLevel, RecordedPolicy, ResumePrompt, SuspendService,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

/// A whole image region in memory.
struct MemStore(IrqSafeSpinLock<Vec<u8>>);
impl ImageStore for MemStore {
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

/// Deterministic key material: fine for an OFF-policy round trip.
struct TestEntropy(core::cell::Cell<u64>);
impl KeyEntropy for TestEntropy {
    fn has_seed_grade(&self) -> bool {
        true
    }
    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
        for byte in out.iter_mut() {
            let n = self
                .0
                .get()
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0.set(n);
            *byte = (n >> 33) as u8;
        }
        Ok(())
    }
}

struct Quiet;
impl ResumePrompt for Quiet {
    fn say(&mut self, _line: &str) {}
}

/// Pages whose bytes name their index.
struct Fake {
    pfns: Vec<u64>,
}
impl Pages for Fake {
    fn count(&self) -> usize {
        self.pfns.len()
    }
    fn pfn(&self, i: usize) -> u64 {
        self.pfns[i]
    }
    fn page(&self, i: usize) -> &[u8; 4096] {
        static PAGES: [[u8; 4096]; 4] = [[0x11; 4096], [0x22; 4096], [0x33; 4096], [0x44; 4096]];
        &PAGES[i % 4]
    }
}

/// Walk a restore list: every (copy, original) pair, in order.
fn pairs(first_pb: u64) -> Vec<[u64; 2]> {
    let mut out = Vec::new();
    let mut pb = first_pb;
    while pb != 0 {
        // SAFETY: a restore-list page the loader owns, through the direct map.
        let page = unsafe { &*PhysAddr::new(pb).kernel_ptr::<PbPage>() };
        out.extend_from_slice(&page.pairs[..page.count as usize]);
        pb = page.next;
    }
    out
}

/// The boot side of a resume, short of the jump. A payload sealed with the
/// real writer verifies through `attempt_resume`. `load_payload` then
/// streams it into a loader whose restore list spans two pages: every page
/// staged with its contents, paired with its original frame, and no copy
/// or list page in a frame the image owns. The image's frames are ones the
/// allocator just gave back, so the loader meets them and has to hold them.
fn loader_stages_a_sealed_payload() -> TestResult {
    let mut recycled = Vec::new();
    for _ in 0..8 {
        let Ok(f) = frame::alloc_frame() else {
            return TestResult::Fail("no frame");
        };
        recycled.push(f);
    }
    let mut pfns: Vec<u64> = recycled
        .iter()
        .map(|f| f.start_address().raw() >> PAGE_SHIFT)
        .collect();
    frame::free_frame_batch(&recycled);
    // Past one restore-list page.
    pfns.extend((0..300u64).map(|i| 0x8000_0000 + i));
    let fake = Fake { pfns: pfns.clone() };
    let header = PayloadHeader {
        page_count: pfns.len() as u64,
        kernel_virt_base: 0,
        kernel_phys: (0, 0),
        ram_hash: [7; 32],
        arch: [0; ARCH_RECORD_LEN],
    };
    let source = PayloadSource::new(&header, &fake);
    let mut store = MemStore(IrqSafeSpinLock::new(vec![0; 4 << 20]));
    let mut svc = SuspendService::new(TestEntropy(core::cell::Cell::new(1)));
    let off = RecordedPolicy {
        level: PolicyLevel::Off,
        policy_epoch: 1,
    };
    if svc.seal_source(&mut store, off, &source).is_err() {
        return TestResult::Fail("sealing the payload failed");
    }
    let Ok(verified) = attempt_resume(&store, &[], &mut Quiet) else {
        return TestResult::Fail("the sealed payload did not verify");
    };
    let (decoded, loader) = match load_payload(&verified, &store) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("load_payload refused the payload"),
    };
    if decoded != header || loader.loaded() != pfns.len() as u64 {
        return TestResult::Fail("the loader staged the wrong header or page count");
    }
    let list = pairs(loader.first_pb());
    if list.len() != pfns.len() {
        return TestResult::Fail("the restore list lost pages");
    }
    let image: alloc::collections::BTreeSet<u64> = pfns.iter().copied().collect();
    let mut pb = loader.first_pb();
    let mut list_pages = 0;
    while pb != 0 {
        list_pages += 1;
        if image.contains(&(pb >> PAGE_SHIFT)) {
            return TestResult::Fail("a restore-list page is an image frame");
        }
        // SAFETY: as in `pairs`.
        pb = unsafe { (*PhysAddr::new(pb).kernel_ptr::<PbPage>()).next };
    }
    if list_pages != 2 {
        return TestResult::Fail("the restore list did not chain a second page");
    }
    for (i, &[copy, original]) in list.iter().enumerate() {
        if original != pfns[i] << PAGE_SHIFT || image.contains(&(copy >> PAGE_SHIFT)) {
            return TestResult::Fail(
                "a pair names the wrong original or an image frame as its copy",
            );
        }
        // SAFETY: a staged copy the loader owns.
        let staged = unsafe { &*PhysAddr::new(copy).kernel_ptr::<[u8; 4096]>() };
        if staged != fake.page(i) {
            return TestResult::Fail("a staged page differs from the image's");
        }
    }
    loader.abandon();
    TestResult::Pass
}
kernel_test_in!("power/hibernate", loader_stages_a_sealed_payload);
