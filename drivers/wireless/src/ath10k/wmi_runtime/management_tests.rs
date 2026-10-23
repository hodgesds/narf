use super::*;
use alloc::{sync::Arc, vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("management_golden.rs");
fn auth() -> [u8; 30] {
    [
        0xb0, 0, 0, 0, 2, 8, 9, 10, 11, 12, 2, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 0, 0, 0, 0, 1,
        0, 0, 0,
    ]
}
fn smoke_ath10k_management_full_linux_generators_and_prefix_boundary() -> TestResult {
    let f = auth();
    for (id, expected) in [
        (0x7006, AUTH_MAIN),
        (0x9028, AUTH_10X),
        (0x9029, AUTH_102),
        (0x9031, AUTH_104),
    ] {
        if inline(id, &f).as_deref() != Ok(expected) {
            return TestResult::Fail("inline management differs from complete Linux C generator");
        }
    }
    if reference(0, 0x900000, &f).as_deref() != Ok(AUTH_TLV) {
        return TestResult::Fail("reference management padded32 prefix differs from Linux");
    }
    let mut assoc = vec![0; 101];
    assoc[..24].copy_from_slice(&f[..24]);
    assoc[0] = 0;
    assoc[24] = 1;
    assoc[26] = 10;
    assoc[29] = 4;
    assoc[30..34].copy_from_slice(b"narf");
    assoc[34..40].copy_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    assoc[40..42].copy_from_slice(&[221, 59]);
    for (i, b) in assoc.iter_mut().enumerate().skip(42) {
        *b = (i * 5) as u8;
    }
    if reference(0, 0x900000, &assoc).as_deref() != Ok(ASSOC_TLV) {
        return TestResult::Fail("reference management full frame versus64-byte prefix mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_management_full_linux_generators_and_prefix_boundary
);
#[derive(Debug)]
struct Buffer {
    bytes: Vec<u8>,
    address: u64,
    dropped: Arc<AtomicUsize>,
}
impl Memory for Buffer {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn dma_address(&self) -> u64 {
        self.address
    }
    fn read(&self, i: usize) -> u8 {
        self.bytes[i]
    }
    fn write(&mut self, i: usize, b: u8) {
        self.bytes[i] = b;
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
fn smoke_ath10k_wmi_management_pool_terminal_batch_is_atomic_and_ids_fresh() -> TestResult {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut pool = Pool::new().unwrap();
    let mut address = 0x900000;
    let mut allocate = |n| {
        let result = Buffer {
            bytes: vec![0xa5; n],
            address,
            dropped: dropped.clone(),
        };
        address += 4096;
        Ok(result)
    };
    if pool.prepare(&auth(), &mut allocate) != Ok((0, 0x900000))
        || pool.prepare(&auth(), &mut allocate) != Ok((1, 0x901000))
    {
        return TestResult::Fail("payload preparation ID/address");
    }
    let first = &pool.slots[0].as_ref().unwrap()._payload.bytes;
    if first[..30] != auth() || first[30..] != [0, 0] {
        return TestResult::Fail("management DMA copy contains uninitialized prefix padding");
    }
    for ids in [&[0, 99][..], &[0, 0][..]] {
        if pool.complete(ids) != Err(DmaError::Malformed)
            || dropped.load(Ordering::Relaxed) != 0
            || pool.pending() != 2
        {
            return TestResult::Fail("malformed bundle partially retired management DMA");
        }
    }
    if pool.complete(&[0, 1]).is_err()
        || dropped.load(Ordering::Relaxed) != 2
        || pool.pending() != 0
    {
        return TestResult::Fail("terminal bundle did not retire exact payloads");
    }
    if pool.prepare(&auth(), &mut allocate) != Ok((2, 0x902000))
        || pool.complete(&[0]) != Err(DmaError::Malformed)
        || pool.pending() != 1
        || dropped.load(Ordering::Relaxed) != 2
    {
        return TestResult::Fail("stale completion released reused management slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_management_pool_terminal_batch_is_atomic_and_ids_fresh
);
fn smoke_ath10k_wmi_management_completion_repeated_arrays_and_status_binding() -> TestResult {
    // Complete firmware wire literal: id7007, fixed tag552/n2, repeated tag16
    // descriptors [10,11], statuses [7,0], PPDU [20,21], optional RSSI [30,31].
    let b = [
        7, 0x70, 0, 0, 4, 0, 0x28, 2, 2, 0, 0, 0, 8, 0, 16, 0, 10, 0, 0, 0, 11, 0, 0, 0, 8, 0, 16,
        0, 7, 0, 0, 0, 0, 0, 0, 0, 8, 0, 16, 0, 20, 0, 0, 0, 21, 0, 0, 0, 8, 0, 16, 0, 30, 0, 0, 0,
        31, 0, 0, 0,
    ];
    if completions(&b)
        != Ok(Some(vec![
            Completion { id: 10, status: 7 },
            Completion { id: 11, status: 0 },
        ]))
    {
        return TestResult::Fail(
            "bundle used descriptor as status or lost repeated array ordering",
        );
    }
    for cut in 0..b.len() {
        let result = completions(&b[..cut]);
        // PPDU/RSSI arrays are optional; their complete absence is legal.
        if !matches!(cut, 36 | 48) && result.is_ok() {
            return TestResult::Fail("truncated completion array accepted");
        }
    }
    let mut duplicate = b;
    duplicate[20] = 10;
    if completions(&duplicate) != Err(Error::Malformed) {
        return TestResult::Fail("duplicate completion IDs accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_management_completion_repeated_arrays_and_status_binding
);

fn smoke_ath10k_wmi_management_epoch_revocation_retains_copied_payload() -> TestResult {
    use narf_bus::BusDeviceCap;
    use narf_capabilities::{Cap, NoopOp, Write};
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut pool = Pool::new().unwrap();
    let result = pool.prepare_authorized(
        &auth(),
        || cap.invoke(NoopOp).is_ok(),
        |n| {
            cap.revoke();
            Ok(Buffer {
                bytes: vec![0xa5; n],
                address: 0x900000,
                dropped: dropped.clone(),
            })
        },
    );
    if result != Err(DmaError::Memory)
        || pool.pending() != 1
        || dropped.load(Ordering::Relaxed) != 0
    {
        return TestResult::Fail(
            "revocation during management copy escaped DMA address or freed retained storage",
        );
    }
    let mut allocated = false;
    if pool.prepare_authorized(
        &auth(),
        || cap.invoke(NoopOp).is_ok(),
        |n| {
            allocated = true;
            Ok(Buffer {
                bytes: vec![0; n],
                address: 0x901000,
                dropped: dropped.clone(),
            })
        },
    ) != Err(DmaError::Memory)
        || allocated
        || pool.pending() != 1
    {
        return TestResult::Fail("revoked management provider allocated/published new payload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_management_epoch_revocation_retains_copied_payload
);
