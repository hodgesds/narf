// SPDX-License-Identifier: MIT
//! Additive integration coverage for the separately retained encoder chain.
use super::*;

fn vcn5_av1_10_encoder_successors_consume_latest_completion() -> TestResult {
    let capacity = BYTES
        + ib_words::IB_BYTES
        + av1_10_words::BYTES
        + hevc_encode_words::BYTES
        + hevc_roundtrip_words::BYTES
        + av1_encode_words::BYTES
        + av1_320_words::BYTES;
    for hevc in [false, true] {
        let (pool, mut e) = fixture_capacity(capacity);
        run(e.start(IMAGE, power())).unwrap();
        run(e.prove()).unwrap();
        let mut o = irqs(&e, Some(64));
        run(e.prove_interrupts(&mut o)).unwrap();
        run(e.prove_ibs(&mut o)).unwrap();
        e.av1_roundtrip_memory = Some(pool.reserve(av1_320_words::BYTES).unwrap());
        e.io.av1_roundtrip
            .bind(e.av1_roundtrip_memory.as_ref().unwrap());
        let prior = run(e.prove_av1_10(&mut o)).unwrap().completion;
        if hevc {
            let p = run(e.prove_hevc_encode(&mut o)).unwrap();
            assert_eq!(
                p.encoded.completion.fence.sequence,
                prior.fence.sequence + 1
            );
            assert_eq!(
                p.decoded.completion.fence.sequence,
                prior.fence.sequence + 2
            );
            let next = run(e.prove_av1_encode(&mut o)).unwrap();
            assert_eq!(
                next.encoded.completion.fence.sequence,
                p.decoded.completion.fence.sequence + 1
            );
            assert_eq!(pool.available(), 0);
        } else {
            let p = run(e.prove_av1_encode(&mut o)).unwrap();
            assert_eq!(
                p.encoded.completion.fence.sequence,
                prior.fence.sequence + 1
            );
            assert_eq!(
                p.decoded.completion.fence.sequence,
                prior.fence.sequence + 2
            );
            assert_eq!(
                pool.available(),
                hevc_encode_words::BYTES + hevc_roundtrip_words::BYTES
            );
        }
        run(e.stop()).unwrap();
        assert!(e.av1_10_memory.as_ref().unwrap().reusable_for_test());
        drop(e);
        assert_eq!(pool.available(), capacity);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_encoder_successors_consume_latest_completion
);
