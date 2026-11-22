use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Three pages, each filled with its index.
struct Fake {
    pfns: Vec<u64>,
    pages: Vec<[u8; 4096]>,
}
impl Pages for Fake {
    fn count(&self) -> usize {
        self.pfns.len()
    }
    fn pfn(&self, i: usize) -> u64 {
        self.pfns[i]
    }
    fn page(&self, i: usize) -> &[u8; 4096] {
        &self.pages[i]
    }
}

/// The header round-trips; the layout's offsets hold; reads that cross
/// region boundaries return the header, the frame table and the pages.
fn payload_streams_header_table_and_pages() -> TestResult {
    let fake = Fake {
        pfns: vec![0x10, 0x11, 0x2000],
        pages: vec![[1; 4096], [2; 4096], [3; 4096]],
    };
    let mut header = PayloadHeader {
        page_count: 3,
        kernel_virt_base: 0xffff_ffff_8100_0000,
        kernel_phys: (0x100_0000, 0x200_0000),
        ram_hash: ram_layout_hash(&[(0, 0x100), (0x200, 0x8000)]),
        arch: [0; ARCH_RECORD_LEN],
    };
    header.arch[0] = 0x5a;
    if PayloadHeader::decode(&header.encode()) != Ok(header.clone()) {
        return TestResult::Fail("the payload header did not round-trip");
    }
    let mut bad = header.encode();
    bad[0] ^= 1;
    if PayloadHeader::decode(&bad) != Err(PayloadError::Magic) {
        return TestResult::Fail("a bad magic decoded");
    }
    let source = PayloadSource::new(&header, &fake);
    if source.len() != 4096 * 5 || pages_offset(3) != 8192 {
        return TestResult::Fail("the payload layout is wrong");
    }
    // Read everything in uneven pieces, crossing each boundary.
    let mut all = vec![0u8; source.len() as usize];
    let mut at = 0;
    for piece in [100usize, 4000, 1000, 3000, 9000, 3380].iter().cycle() {
        if at == all.len() {
            break;
        }
        let n = (*piece).min(all.len() - at);
        source.read_at(at as u64, &mut all[at..at + n]);
        at += n;
    }
    if PayloadHeader::decode(&all[..4096]) != Ok(header) {
        return TestResult::Fail("the streamed header differs");
    }
    if decode_frame_table(&all[4096..8192], 3) != fake.pfns
        || all[4096 + 24..8192].iter().any(|&b| b != 0)
    {
        return TestResult::Fail("the streamed frame table differs");
    }
    for (i, page) in all[8192..].chunks(4096).enumerate() {
        if page.iter().any(|&b| b != i as u8 + 1) {
            return TestResult::Fail("a streamed page differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!("power/hibernate", payload_streams_header_table_and_pages);
