use super::*;
fn slots(e: &Engine<Fake>) -> [bool; 13] {
    [
        e.ib_memory.is_some(),
        e.decode_memory.is_some(),
        e.hevc_memory.is_some(),
        e.hevc10_memory.is_some(),
        e.vp9_memory.is_some(),
        e.vp9_10_memory.is_some(),
        e.av1_memory.is_some(),
        e.av1_10_memory.is_some(),
        e.encode_memory.is_some(),
        e.hevc_encode_memory.is_some(),
        e.hevc_roundtrip_memory.is_some(),
        e.av1_encode_memory.is_some(),
        e.av1_roundtrip_memory.is_some(),
    ]
}
fn vcn5_proof_claim_is_atomic_unpublished_and_retries_without_trimming_profiles() -> TestResult {
    let bytes = reservation::proof_bytes(true, true, true);
    assert_eq!(bytes, 155734016);
    let (pool, mut e) = fixture_capacity(bytes);
    let pressure = pool.reserve(4096).unwrap();
    let free = pool.available();
    assert_eq!(e.reserve_proofs(true, true, true), Err(Error::Allocation));
    assert_eq!(slots(&e), [false; 13]);
    assert_eq!(pool.available(), free);
    assert_eq!(e.state, State::Prepared);
    assert!(e.io.writes.is_empty());
    drop(pressure);
    e.reserve_proofs(true, true, true).unwrap();
    assert_eq!(slots(&e), [true; 13]);
    assert_eq!(pool.available(), 0);
    assert!(e.io.writes.is_empty());
    assert_eq!(e.state, State::Prepared);
    // Idempotence retains the same exact claims, without transient extra space.
    e.reserve_proofs(true, true, true).unwrap();
    assert_eq!(pool.available(), 0);
    drop(e);
    assert_eq!(pool.available(), bytes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_proof_claim_is_atomic_unpublished_and_retries_without_trimming_profiles
);
fn vcn5_proof_claim_admits_only_requested_directions_and_refuses_active_owner() -> TestResult {
    for (decode, encode) in [(false, false), (false, true), (true, false)] {
        let bytes = reservation::proof_bytes(true, decode, encode);
        let (pool, mut e) = fixture_capacity(bytes);
        e.reserve_proofs(true, decode, encode).unwrap();
        assert_eq!(
            slots(&e),
            [
                true, decode, decode, decode, decode, decode, decode, decode, encode, encode,
                encode, encode, encode
            ]
        );
        assert_eq!(pool.available(), 0);
        e.state = State::Ready;
        assert_eq!(e.reserve_proofs(true, decode, encode), Err(Error::Busy));
        e.state = State::Prepared;
        drop(e);
        assert_eq!(pool.available(), bytes);
    }
    let (pool, mut e) = fixture_capacity(256 << 20);
    let before = pool.available();
    e.encode_interface = None;
    assert_eq!(e.reserve_proofs(true, true, true), Err(Error::Unsupported));
    assert_eq!(slots(&e), [false; 13]);
    assert_eq!(pool.available(), before);
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_proof_claim_admits_only_requested_directions_and_refuses_active_owner
);
fn vcn5_small_bar_preclaims_complete_media_before_client_heap_and_keeps_owner_floor() -> TestResult
{
    const MIB: u64 = 1 << 20;
    for (occupied, fits) in [(8 * MIB, true), (24 * MIB, false)] {
        let (pool, mut e) = fixture_capacity(256 * MIB);
        let firmware_display = pool.reserve(occupied).unwrap();
        e.reserve_proofs(true, true, true).unwrap();
        let jpeg = pool
            .reserve(crate::amdgpu_jpeg_navi48::proof_bytes(true, true))
            .unwrap();
        let free = pool.available();
        assert!(e.io.writes.is_empty());
        assert_eq!(slots(&e), [true; 13]);
        match crate::amdgpu_navi48_boot::reserve_client_chunk(&pool) {
            Ok(chunk) => {
                assert!(fits);
                assert!(chunk.size() >= 64 * MIB);
                assert!(pool.available() >= 32 * MIB);
                drop(chunk);
            }
            Err(crate::amdgpu_navi48_boot::Error::Allocation) => assert!(!fits),
            other => panic!("client carve {other:?}"),
        }
        assert_eq!(pool.available(), free);
        drop(jpeg);
        drop(firmware_display);
        drop(e);
        assert_eq!(pool.available(), 256 * MIB);
    }
    // Reproduces the previous startup order: carving before proof admission
    // leaves only the future-owner floor and cannot fit the complete request.
    let (pool, mut e) = fixture_capacity(256 * MIB);
    let firmware = pool.reserve(8 * MIB).unwrap();
    let client = crate::amdgpu_navi48_boot::reserve_client_chunk(&pool).unwrap();
    let free = pool.available();
    assert_eq!(e.reserve_proofs(true, true, true), Err(Error::Allocation));
    assert_eq!(slots(&e), [false; 13]);
    assert_eq!(pool.available(), free);
    assert!(e.io.writes.is_empty());
    drop(client);
    e.reserve_proofs(true, true, true).unwrap();
    assert_eq!(slots(&e), [true; 13]);
    drop(firmware);
    drop(e);
    assert_eq!(pool.available(), 256 * MIB);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_small_bar_preclaims_complete_media_before_client_heap_and_keeps_owner_floor
);

fn vcn5_reservation_failure_preserves_existing_published_pins() -> TestResult {
    let (pool, engine) = fixture_capacity(BYTES + 3 * 4096);
    let mut existing = Some(pool.reserve(4096).unwrap());
    existing.as_mut().unwrap().publish();
    let address = existing.as_ref().unwrap().address();
    let mut first = None;
    let mut last = None;
    let free = pool.available();
    assert_eq!(
        crate::amdgpu_media_reservation::reserve(
            &pool,
            [
                (&mut existing, 4096, true),
                (&mut first, 8192, true),
                (&mut last, 4096, true)
            ]
        ),
        Err(crate::amdgpu_vram::Error::Exhausted)
    );
    assert_eq!(existing.as_ref().unwrap().address(), address);
    assert!(!existing.as_ref().unwrap().reusable_for_test());
    assert!(first.is_none() && last.is_none());
    assert_eq!(pool.available(), free);
    drop(existing);
    assert_eq!(pool.available(), free);
    drop(engine);
    assert_eq!(pool.available(), BYTES + 8192);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_reservation_failure_preserves_existing_published_pins
);

fn vcn5_all_requested_profiles_encoders_restart_and_real_client_job_form_one_fresh_chain(
) -> TestResult {
    let capacity = reservation::proof_bytes(true, true, true);
    let (pool, mut e) = fixture_capacity(capacity);
    for restart in [false, true] {
        if restart {
            e.seq = u32::MAX;
        }
        e.reserve_proofs(true, true, true).unwrap();
        assert_eq!(pool.available(), 0);
        e.io.av1_roundtrip
            .bind(e.av1_roundtrip_memory.as_ref().unwrap());
        run(e.start(IMAGE, power())).unwrap();
        assert!(
            e.decode_result.is_none()
                && e.hevc_result.is_none()
                && e.hevc10_result.is_none()
                && e.vp9_result.is_none()
                && e.vp9_10_result.is_none()
                && e.av1_result.is_none()
                && e.av1_10_result.is_none()
                && e.encode_result.is_none()
                && e.hevc_encode_result.is_none()
                && e.av1_encode_result.is_none()
        );
        run(e.prove()).unwrap();
        let mut o = irqs(&e, Some(64));
        run(e.prove_interrupts(&mut o)).unwrap();
        let mut sequence = run(e.prove_ibs(&mut o)).unwrap().fence.sequence;
        macro_rules! decode {
            ($method:ident) => {{
                let p = run(e.$method(&mut o)).unwrap();
                assert_eq!(p.completion.fence.sequence, sequence.wrapping_add(1).max(1));
                sequence = p.completion.fence.sequence;
            }};
        }
        decode!(prove_decode);
        decode!(prove_hevc);
        decode!(prove_hevc10);
        decode!(prove_vp9);
        decode!(prove_vp9_10);
        decode!(prove_av1);
        decode!(prove_av1_10);
        let avc = run(e.prove_encode(&mut o)).unwrap();
        assert_eq!(avc.completion.fence.sequence, sequence + 1);
        sequence = avc.completion.fence.sequence;
        let hevc = run(e.prove_hevc_encode(&mut o)).unwrap();
        assert_eq!(hevc.encoded.completion.fence.sequence, sequence + 1);
        assert_eq!(hevc.decoded.completion.fence.sequence, sequence + 2);
        sequence = hevc.decoded.completion.fence.sequence;
        let av1 = run(e.prove_av1_encode(&mut o)).unwrap();
        assert_eq!(av1.encoded.completion.fence.sequence, sequence + 1);
        assert_eq!(av1.decoded.completion.fence.sequence, sequence + 2);
        assert_eq!(e.seq, av1.decoded.completion.fence.sequence);
        let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
        let submitted = e.submit(job).unwrap();
        assert_eq!(submitted, av1.decoded.completion.fence.sequence + 1);
        assert_eq!(e.completed_job(), Ok(submitted));
        assert_eq!(e.io.client_ibs.last(), Some(&(3, 0x2000, 4)));
        assert_eq!(pool.available(), 0);
        run(e.stop()).unwrap();
        assert_eq!(e.state, State::Stopped);
        assert!(
            e.av1_10_memory.as_ref().unwrap().reusable_for_test()
                && e.hevc_encode_memory.as_ref().unwrap().reusable_for_test()
                && e.hevc_roundtrip_memory
                    .as_ref()
                    .unwrap()
                    .reusable_for_test()
                && e.av1_encode_memory.as_ref().unwrap().reusable_for_test()
                && e.av1_roundtrip_memory.as_ref().unwrap().reusable_for_test()
        );
    }
    drop(e);
    assert_eq!(pool.available(), capacity);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_all_requested_profiles_encoders_restart_and_real_client_job_form_one_fresh_chain
);

fn vcn5_media_claim_accepts_last_48bit_page_and_rolls_back_exhaustion() -> TestResult {
    // SAFETY: metadata-only descriptor; no mapping access or hardware exists.
    let mapping = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000),
        virt: 0,
        len: 8192,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // The Pool itself rejects an aperture extending past the hardware limit.
    assert!(matches!(
        // SAFETY: metadata-only descriptor; the constructor must reject it.
        unsafe { Pool::from_owned_range(mapping, (1u64 << 48) - 4096) },
        Err(crate::amdgpu_vram::Error::Invalid)
    ));
    // SAFETY: the same metadata-only descriptor, now wholly below the limit.
    let pool = unsafe { Pool::from_owned_range(mapping, (1u64 << 48) - 8192) }.unwrap();
    let mut first = None;
    let mut second = None;
    let mut third = None;
    assert_eq!(
        crate::amdgpu_media_reservation::reserve(
            &pool,
            [
                (&mut first, 4096, true),
                (&mut second, 4096, true),
                (&mut third, 4096, true)
            ]
        ),
        Err(crate::amdgpu_vram::Error::Exhausted)
    );
    assert!(first.is_none() && second.is_none() && third.is_none());
    assert_eq!(pool.available(), 8192);
    crate::amdgpu_media_reservation::reserve(
        &pool,
        [(&mut first, 4096, true), (&mut second, 4096, true)],
    )
    .unwrap();
    assert_eq!(first.as_ref().unwrap().address(), (1u64 << 48) - 8192);
    assert_eq!(second.as_ref().unwrap().address(), (1u64 << 48) - 4096);
    assert_eq!(pool.available(), 0);
    drop((first, second));
    assert_eq!(pool.available(), 8192);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_media_claim_accepts_last_48bit_page_and_rolls_back_exhaustion
);
