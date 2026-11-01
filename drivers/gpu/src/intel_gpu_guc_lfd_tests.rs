//! Actual log descriptors, immutable firmware copies and literal LFD1.0 wire
//! vectors from Linux b90c984d xe_guc_log.c + guc_{lic,lfd,log}_abi.h.

use super::*;

fn configure(memory: &Memory) {
    for (offset, value) in [
        (108, 0x8086900d),
        (112, 0x00010000),
        (116, 10),
        (120, 0x00030001),
        (124, 19200),
        (128, 0x00010001),
        (132, 0x46003601),
        (136, 0x00050001),
        (140, 0x31),
        (144, 0x00020001),
        (148, 0x1234),
        (152, 0x00040001),
        (156, 0x140100),
    ] {
        memory.put(offset, value);
    }
    for offset in (0x11000..0x15000).step_by(4) {
        memory.put(offset, 0);
    }
}
fn lfd_node(backend: &Arc<Backend>, index: u32) -> Node {
    let mut node = backend.node(index);
    node.format = Format::Lfd;
    node
}
fn contents(file: &Arc<dyn FileOps>) -> Vec<u8> {
    let mut bytes = alloc::vec![0xcd; lfd::MAX_BYTES];
    let count = ready(file.read(0, &mut bytes)).unwrap();
    assert!(count <= bytes.len());
    assert!(bytes[count..].iter().all(|byte| *byte == 0xcd));
    bytes.truncate(count);
    bytes
}
fn blocks(bytes: &[u8]) -> Vec<(u16, &[u8])> {
    // Independently walk the public wire output, including DWORD padding.
    assert_eq!(
        &bytes[..12],
        &[0x46, 0x53, 0x4c, 0x47, 0xaa, 0xaa, 0x86, 0x80, 0, 0, 1, 0]
    );
    let mut offset = 12;
    let mut result = Vec::new();
    while offset < bytes.len() {
        assert_eq!(&bytes[offset..offset + 2], &[0x86, 0x80]);
        let kind = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
        let size = dword(bytes, offset + 4) as usize * 4;
        let end = offset + 8 + size;
        assert!(end <= bytes.len());
        result.push((kind, &bytes[offset + 8..end]));
        offset = end;
    }
    assert_eq!(offset, bytes.len());
    result
}

fn smoke_guc_lfd_file_wire_identity_linear_events_and_crash() -> TestResult {
    let _hook = Hook::install();
    let backend = Backend::new();
    configure(&backend.memory);
    backend.memory.put(0x11000, 0xdeadbeef);
    backend.memory.put(0x1000, 0x11223344);
    backend.memory.put(0x1004, 0xaabbccdd);
    let file = open(&lfd_node(&backend, slot()));
    assert_eq!(file.stat().size, 0);
    let bytes = contents(&file);
    let records = blocks(&bytes);
    assert_eq!(
        records.iter().map(|record| record.0).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 0x4000, 0x6001, 0x2000, 0x2001]
    );
    for (index, value) in [0x46003601u32, 0x1234, 19200, 0x140100, 0x31]
        .into_iter()
        .enumerate()
    {
        assert_eq!(records[index].1, value.to_le_bytes());
    }
    assert_eq!(dword(records[5].1, 0), 4); // Source's OTHER identifier.
    assert!(records[5].1[4..].starts_with(b"NARF/"));
    assert!(records[6]
        .1
        .starts_with(b"NARF passive GuC snapshot; sequential copy; no flush acknowledgement"));
    assert_eq!(
        &records[7].1[..12],
        &[2, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0xdd, 0xcc, 0xbb, 0xaa]
    );
    assert_eq!(records[7].1.len(), 4 + 16);
    assert_eq!(records[8].1.len(), 0x4000);
    assert_eq!(dword(records[8].1, 0), 0xdeadbeef);
    // 1MiB state capture is not part of the source's LFD snapshot stream.
    assert!(bytes.len() < 0x5000);
    assert_eq!(file.stat().size, bytes.len() as u64);
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    assert_eq!(ready(file.write(0, b"x")), Err(FsError::ReadOnly));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_lfd_file_wire_identity_linear_events_and_crash
);

fn smoke_guc_lfd_wrapped_empty_full_ranges_and_partial_reads() -> TestResult {
    let _hook = Hook::install();
    for (read, write, wrap, expected) in [
        (0xfff8, 8, 0x10000, alloc::vec![0x11u32, 0x22, 0x33, 0x44]),
        (4, 4, 0x10000, Vec::new()),
        (0, 0x10000, 0x10000, (0..0x4000u32).collect()),
    ] {
        let backend = Backend::new();
        configure(&backend.memory);
        backend.memory.put(8, read);
        backend.memory.put(12, write);
        backend.memory.put(24, wrap);
        for (index, value) in (0..0x4000u32).enumerate() {
            backend.memory.put(0x1000 + index * 4, value);
        }
        if read == 0xfff8 {
            for (offset, value) in [
                (0x10ff8, 0x11),
                (0x10ffc, 0x22),
                (0x1000, 0x33),
                (0x1004, 0x44),
            ] {
                backend.memory.put(offset, value);
            }
        }
        let file = open(&lfd_node(&backend, slot()));
        let bytes = contents(&file);
        let records = blocks(&bytes);
        assert!(records.iter().all(|record| record.0 != 0x2001));
        let event = records.iter().find(|record| record.0 == 0x2000);
        if expected.is_empty() {
            assert!(event.is_none());
        } else {
            let data = event.unwrap().1;
            assert_eq!(dword(data, 0), 2);
            assert_eq!(data.len(), 4 + expected.len() * 4);
            for (index, value) in expected.into_iter().enumerate() {
                assert_eq!(dword(data, 4 + index * 4), value);
            }
        }
        let mut reconstructed = Vec::new();
        for offset in (0..bytes.len()).step_by(7) {
            let mut chunk = [0xcc; 7];
            let count = ready(file.read(offset as u64, &mut chunk)).unwrap();
            reconstructed.extend_from_slice(&chunk[..count]);
            assert!(chunk[count..].iter().all(|byte| *byte == 0xcc));
        }
        assert_eq!(reconstructed, bytes);
        let mut untouched = [0x73; 4];
        assert_eq!(ready(file.read(bytes.len() as u64, &mut untouched)), Ok(0));
        assert_eq!(ready(file.read(u64::MAX, &mut untouched)), Ok(0));
        assert_eq!(untouched, [0x73; 4]);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_lfd_wrapped_empty_full_ranges_and_partial_reads
);

fn smoke_guc_lfd_corrupt_lic_and_ranges_refuse_without_losing_raw_diagnostics() -> TestResult {
    let _hook = Hook::install();
    for (at, value, error) in [
        (108, 0, FsError::Unsupported),
        (112, 0x00020000, FsError::Unsupported),
        (116, u32::MAX, FsError::InvalidData),
        (116, 8, FsError::InvalidData),
        (120, 0x00000001, FsError::InvalidData),
        (120, 0x00060001, FsError::InvalidData),
        (120, 0x00030002, FsError::InvalidData),
        (128, 0x00030001, FsError::InvalidData),
        (0, 0, FsError::InvalidData),
        (16, 0x10004, FsError::InvalidData),
        (8, 0x10004, FsError::InvalidData),
        (12, 0x10004, FsError::InvalidData),
        (24, 0x10004, FsError::InvalidData),
        (8, 1, FsError::InvalidData),
        (12, 1, FsError::InvalidData),
        (24, 1, FsError::InvalidData),
    ] {
        let backend = Backend::new();
        configure(&backend.memory);
        backend.memory.put(at, value);
        let index = slot();
        let file = open(&lfd_node(&backend, index));
        let mut output = [0x52; 16];
        assert_eq!(ready(file.read(0, &mut output)), Err(error));
        assert_eq!(output, [0x52; 16]);
        assert_eq!(file.stat().size, 0);
        assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
        let raw = open(&backend.node(index));
        assert_eq!(ready(raw.read(0, &mut output)), Ok(16));
        assert_eq!(&output[..8], b"NARFGLOG");
        assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    }
    // A valid-size wrap which points backwards is not a valid event extent.
    let backend = Backend::new();
    configure(&backend.memory);
    backend.memory.put(8, 32);
    backend.memory.put(12, 8);
    backend.memory.put(24, 16);
    let file = open(&lfd_node(&backend, slot()));
    assert_eq!(ready(file.read(0, &mut [0; 1])), Err(FsError::InvalidData));
    backend.memory.put(8, 0);
    backend.memory.put(12, 16);
    backend.memory.put(24, 0x10000);
    backend.memory.change_header.store(true, Ordering::Release);
    assert_eq!(ready(file.read(0, &mut [0; 1])), Err(FsError::InvalidData));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_lfd_corrupt_lic_and_ranges_refuse_without_losing_raw_diagnostics
);

fn smoke_guc_lfd_shared_permits_reset_and_capability_lifetime() -> TestResult {
    let _hook = Hook::install();
    let backend = Backend::new();
    configure(&backend.memory);
    let index = slot();
    let lfd = open(&lfd_node(&backend, index));
    let before = contents(&lfd);
    let duplicate = lfd.clone();
    let raw = open(&backend.node(index));
    assert_eq!(ready(raw.read(0, &mut [0; 4])), Ok(4));
    let third = open(&lfd_node(&backend, index));
    assert_eq!(ready(third.read(0, &mut [0; 4])), Err(FsError::Busy));
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    backend.available.store(false, Ordering::Release);
    backend.memory.put(0x1000, 0xdeadbeef);
    backend.epoch.store(43, Ordering::Release);
    backend.incarnation.store(100, Ordering::Release);
    let reads = backend.memory.reads.load(Ordering::Relaxed);
    assert_eq!(contents(&duplicate), before);
    assert_eq!(backend.memory.reads.load(Ordering::Relaxed), reads);
    AUTHORIZED.store(false, Ordering::Release);
    assert_eq!(lfd.stat().size, 0);
    assert_eq!(
        ready(lfd.read(u64::MAX, &mut [])),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(
        ready(lfd.read(0, &mut [0; 1])),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(
        lfd_node(&backend, index).open_instance_checked(false).err(),
        Some(FsError::OperationNotPermitted)
    );
    AUTHORIZED.store(true, Ordering::Release);
    assert_eq!(contents(&duplicate), before);
    drop(lfd);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    drop(duplicate);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    drop(raw);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    assert_eq!(ready(third.read(0, &mut [0; 1])), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_lfd_shared_permits_reset_and_capability_lifetime
);

fn smoke_guc_lfd_cancelled_capture_and_late_revocation_publish_nothing() -> TestResult {
    let _hook = Hook::install();
    let backend = Backend::new();
    configure(&backend.memory);
    backend.pending.store(true, Ordering::Release);
    let index = slot();
    let file = open(&lfd_node(&backend, index));
    let mut output = [0x19; 4];
    let mut read = file.read(0, &mut output);
    assert!(read
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    drop(read);
    assert_eq!(output, [0x19; 4]);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    assert_eq!(file.stat().size, 0);
    backend.pending.store(false, Ordering::Release);
    backend.revoke_on_capture.store(true, Ordering::Release);
    assert_eq!(
        ready(file.read(0, &mut output)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(output, [0x19; 4]);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    backend.revoke_on_capture.store(false, Ordering::Release);
    AUTHORIZED.store(true, Ordering::Release);
    assert_eq!(ready(file.read(0, &mut output)), Ok(4));
    assert_eq!(&output, b"FSLG");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_lfd_cancelled_capture_and_late_revocation_publish_nothing
);
