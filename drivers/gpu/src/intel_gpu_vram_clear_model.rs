//! Independent native device side of the documented Xe-HPG CCS transfer.
//! Decodes instructions fetched through real production PPGTT pages; metadata
//! lives in a model-only VRAM sideband so a CPU data clear cannot pass this test.
use alloc::vec::Vec;
use core::ops::Range;
use narf_lib::sync::IrqSafeSpinLock;

struct Model {
    range: Range<u64>,
    cpu: u64,
    metadata: Vec<u8>,
    clears: Vec<Range<u64>>,
}
static MODEL: IrqSafeSpinLock<Option<Model>> = IrqSafeSpinLock::new(None);
pub(crate) fn fixture_seed(base: u64, size: u64, cpu: u64) {
    assert_eq!((base | size) & 65535, 0);
    let old = MODEL.lock().replace(Model {
        range: base..base + size,
        cpu,
        metadata: alloc::vec![0xa5; (size / 256) as usize],
        clears: Vec::new(),
    });
    drop(old);
}
pub(crate) fn fixture_state() -> (Vec<u8>, Vec<Range<u64>>) {
    let model = MODEL.lock();
    let model = model.as_ref().expect("qualified fixture LMEM");
    (model.metadata.clone(), model.clears.clone())
}
pub(crate) fn fixture_finish() {
    let old = MODEL.lock().take();
    drop(old);
}

fn leaf(root: u64, va: u64) -> (u64, u64) {
    let mut table = root & 0x0000_3fff_ffff_f000;
    for shift in [39, 30, 21, 12] {
        let pointer = narf_memory::PhysAddr::new(table).kernel_ptr::<u64>();
        // SAFETY: called only while the native scheduler retains the real
        // immutable production page-table allocation for this request.
        let entry =
            unsafe { core::ptr::read_volatile(pointer.add(((va >> shift) & 511) as usize)) };
        assert_ne!(entry & 1, 0);
        let physical = entry & 0x0000_3fff_ffff_f000;
        if shift == 12 {
            return (physical | (va & 4095), entry);
        }
        assert_ne!(physical, 0);
        assert_eq!(entry & !(0x0000_3fff_ffff_f000 | 0x18), 3, "ordinary table");
        table = physical;
    }
    unreachable!()
}
pub(crate) fn execute_fixture(root: u64, batch_va: u64) -> bool {
    let (code, flags) = leaf(root, batch_va);
    let pointer = narf_memory::PhysAddr::new(code).kernel_ptr::<u32>();
    // SAFETY: the production clear batch resides in one retained 4 KiB BO.
    let words = unsafe { core::slice::from_raw_parts(pointer, 128) };
    if words[0] != 0x5110_000e {
        return false;
    }
    assert_eq!(root & 0x18, 0, "DG2 private table PAT0");
    assert_eq!(flags & !0x0000_3fff_ffff_f000, 1, "read-only system batch");
    let mut offset = 0;
    let mut commands = 0;
    while words[offset] == 0x5110_000e {
        commands += 1;
        assert!(commands <= 4);
        let color = &words[offset..offset + 16];
        assert_eq!(&color[..3], &[0x5110000e, 0x00400fff, 0]);
        assert_eq!(color[3] & 65535, 1024);
        assert!(
            color[6..].iter().all(|v| *v == 0),
            "local memory, zero color, uncompressed"
        );
        let color_bytes = u64::from(color[3] >> 16) * 4096;
        let color_target = u64::from(color[4]) | u64::from(color[5]) << 32;
        offset += 16;
        let cmd = &words[offset..offset + 5];
        assert_eq!(cmd[0] & !0x0003_ff00, 0x52200003);
        let count = u64::from((cmd[0] >> 8) & 1023) + 1;
        let metadata_bytes = count * 256;
        let data_bytes = metadata_bytes * 256;
        assert_eq!(cmd[2] & 0xffff_0000, 1 << 26, "UC MOCS1 direct source");
        assert_eq!(cmd[4] & 0xffff_0000, 1 << 26, "UC MOCS1 indirect target");
        let source = u64::from(cmd[1]) | u64::from(cmd[2] & 65535) << 32;
        let target = u64::from(cmd[3]) | u64::from(cmd[4] & 65535) << 32;
        assert_eq!((color_target, color_bytes), (target, data_bytes));
        assert_eq!(target & 65535, 0);
        for byte in 0..metadata_bytes {
            let (physical, entry) = leaf(root, source + byte);
            assert_eq!(entry & !0x0000_3fff_ffff_f000, 1);
            // SAFETY: the checked leaf reaches the retained immutable zero BO.
            let value = unsafe {
                core::ptr::read_volatile(narf_memory::PhysAddr::new(physical).kernel_ptr::<u8>())
            };
            assert_eq!(value, 0);
        }
        let (dpa, _) = leaf(root, target);
        for chunk in (0..data_bytes).step_by(65536) {
            for page in 0..16 {
                let (physical, entry) = leaf(root, target + chunk + page * 4096);
                assert_eq!(physical, dpa + chunk + page * 4096);
                assert_eq!(entry & !0x0000_3fff_ffff_f000, 0x903, "DM|PS64|RW|PRESENT");
            }
        }
        let mut model = MODEL.lock();
        let model = model
            .as_mut()
            .expect("CCS transfer requires owned model LMEM");
        assert!(dpa >= model.range.start && dpa + data_bytes <= model.range.end);
        let start = ((dpa - model.range.start) / 256) as usize;
        // SAFETY: the fixture supplied this exclusively owned fake BAR and
        // keeps its frames live through terminal retirement/reset.
        unsafe {
            core::ptr::write_bytes(
                (model.cpu + dpa - model.range.start) as *mut u8,
                0,
                data_bytes as usize,
            )
        };
        model.metadata[start..start + metadata_bytes as usize].fill(0);
        model.clears.push(dpa..dpa + data_bytes);
        offset += 5;
    }
    assert_eq!(
        &words[offset..offset + 6],
        &[0x13010003, 0, 0, 0, 0, 0x05000000]
    );
    true
}
