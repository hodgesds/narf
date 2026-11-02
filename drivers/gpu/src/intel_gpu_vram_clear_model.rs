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
pub(crate) fn fixture_metadata(dpa: u64, bytes: &[u8]) {
    let mut model = MODEL.lock();
    let model = model.as_mut().expect("owned fixture LMEM");
    assert_eq!(dpa & 65535, 0);
    assert!(dpa >= model.range.start);
    let start = ((dpa - model.range.start) / 256) as usize;
    model.metadata[start..start + bytes.len()].copy_from_slice(bytes);
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
fn pointer(root: u64, va: u64, writable: bool) -> *mut u8 {
    let (physical, entry) = leaf(root, va);
    let pat = if root & 0x18 == 0x10 { 0x10 } else { 0 };
    let device = entry & 0x800 != 0;
    let page64 = device && pat == 0;
    assert_eq!(
        entry & !0x0000_3fff_ffff_f000,
        1 | (u64::from(writable) * 2)
            | pat
            | (u64::from(device) * 0x800)
            | (u64::from(page64) * 0x100),
        "copy leaf permission/cache policy"
    );
    if device {
        let model = MODEL.lock();
        let model = model.as_ref().expect("owned fixture LMEM");
        assert!(model.range.contains(&physical));
        (model.cpu + physical - model.range.start) as *mut u8
    } else {
        narf_memory::PhysAddr::new(physical).kernel_mut_ptr::<u8>()
    }
}

pub(crate) fn execute_fixture(root: u64, batch_va: u64) -> bool {
    let (code, flags) = leaf(root, batch_va);
    let pointer = narf_memory::PhysAddr::new(code).kernel_ptr::<u32>();
    // SAFETY: trusted copy/clear factories retain this complete 4 KiB BO.
    let words = unsafe { core::slice::from_raw_parts(pointer, 1024) };
    if !matches!(words[0], 0x50800008 | 0x56880008) {
        return false;
    }
    let xe2 = words[0] == 0x56880008;
    assert_eq!(root & 0x18, if xe2 { 0x10 } else { 0 });
    assert_eq!(
        flags & !0x0000_3fff_ffff_f000,
        if xe2 { 0x11 } else { 1 },
        "read-only system batch"
    );
    let mut offset = 0;
    let mut ccs = false;
    while offset < 1024 {
        if matches!(words[offset], 0x50800008 | 0x56880008) {
            let cmd = &words[offset..offset + 10];
            let (source, target, bytes) = if xe2 {
                assert_eq!(cmd[0], 0x56880008);
                assert_eq!((cmd[3], cmd[4], cmd[9]), (4095, 4095, 0x30000018));
                let bytes = (u64::from(cmd[1]) + 1) * 256;
                assert_eq!(u64::from(cmd[2]) + 1, bytes / 4096);
                (
                    u64::from(cmd[5]) | u64::from(cmd[6]) << 32,
                    u64::from(cmd[7]) | u64::from(cmd[8]) << 32,
                    bytes,
                )
            } else {
                assert_eq!(&cmd[..3], &[0x50800008, 0xc3001000, 0]);
                assert_eq!((cmd[3] & 65535, cmd[6], cmd[7]), (1024, 0, 4096));
                (
                    u64::from(cmd[8]) | u64::from(cmd[9]) << 32,
                    u64::from(cmd[4]) | u64::from(cmd[5]) << 32,
                    u64::from(cmd[3] >> 16) * 4096,
                )
            };
            assert!(bytes != 0 && bytes <= 8 * 1024 * 1024);
            for page in (0..bytes).step_by(4096) {
                let source = self::pointer(root, source + page, false);
                let target = self::pointer(root, target + page, true);
                // SAFETY: independent walks resolve retained RO source and
                // RW destination pages; admitted ranges cannot overlap.
                unsafe { core::ptr::copy_nonoverlapping(source, target, 4096) };
            }
            offset += 10;
            continue;
        }
        if words[offset] & !0x0033_ff00 != 0x5200_0003 {
            break;
        }
        assert!(!xe2, "Xe2 uncompressed copy has no auxiliary transfer");
        ccs = true;
        let cmd = &words[offset..offset + 5];
        let direct = cmd[0] & (1 << 21) != 0;
        assert_eq!(cmd[0] & !0x0023_ff00, 0x52000003);
        let count = u64::from((cmd[0] >> 8) & 1023) + 1;
        let metadata_bytes = count * 256;
        let data_bytes = metadata_bytes * 256;
        assert_eq!(cmd[2] & 0xffff_0000, 1 << 26, "UC MOCS1 source");
        assert_eq!(cmd[4] & 0xffff_0000, 1 << 26, "UC MOCS1 indirect target");
        let source = u64::from(cmd[1]) | u64::from(cmd[2] & 65535) << 32;
        let target = u64::from(cmd[3]) | u64::from(cmd[4] & 65535) << 32;
        assert_eq!(target & 65535, 0);
        let source_dpa = (!direct).then(|| leaf(root, source).0);
        if direct {
            for byte in 0..metadata_bytes {
                // SAFETY: independently verified retained RO zero source.
                let value =
                    unsafe { core::ptr::read_volatile(self::pointer(root, source + byte, false)) };
                assert_eq!(value, 0);
            }
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
        if let Some(source) = source_dpa {
            assert!(source >= model.range.start && source + data_bytes <= model.range.end);
            let source_start = ((source - model.range.start) / 256) as usize;
            model
                .metadata
                .copy_within(source_start..source_start + metadata_bytes as usize, start);
        } else {
            model.metadata[start..start + metadata_bytes as usize].fill(0);
        }
        model.clears.push(dpa..dpa + data_bytes);
        offset += 5;
    }
    if ccs {
        assert_eq!(&words[offset..offset + 5], &[0x13010003, 0, 0, 0, 0]);
        offset += 5;
    }
    assert_eq!(words[offset], 0x05000000);
    true
}
