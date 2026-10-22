use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn timing() -> Timing {
    Timing {
        pixel_clock_khz: 586_322,
        h_active: 2560,
        h_total: 2720,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 1440,
        v_total: 1497,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    }
}
fn freesync_lfc_replays_linux_btr_preflip_and_vupdate() -> TestResult {
    let mut current = None;
    let mut math = None;
    let mut adjust = None;
    let mut count = 0;
    for row in include_str!("../tests/dcn401_lfc/vectors.txt").lines() {
        let v: alloc::vec::Vec<u32> = row.split_whitespace().map(|s| s.parse().unwrap()).collect();
        assert_eq!(v.len(), 11);
        let key = (v[0], v[1], v[2]);
        if current != Some(key) {
            let c = LfcConfig::new(
                &timing(),
                VrrRange {
                    min_hz: v[1] as u16,
                    max_hz: v[2] as u16,
                },
            )
            .unwrap();
            math = Some(Lfc::new(c));
            adjust = Some(c.base());
            current = Some(key);
        }
        let m = math.as_mut().unwrap();
        if let Some(next) = if v[3] == 0 {
            m.preflip(v[4])
        } else {
            m.vupdate(v[0] != 0)
        } {
            adjust = Some(next);
        }
        assert_eq!(
            (
                u32::from(m.active),
                m.inserted_duration_us,
                m.frames_to_insert,
                m.frame_counter,
                adjust.unwrap().v_total_min,
                adjust.unwrap().v_total_max
            ),
            (v[5], v[6], v[7], v[8], v[9], v[10]),
            "{row}"
        );
        count += 1;
    }
    assert_eq!(count, 1286);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_lfc_replays_linux_btr_preflip_and_vupdate
);

fn freesync_lfc_requires_effective_two_to_one_and_bounds_duration() -> TestResult {
    let t = timing();
    assert!(LfcConfig::new(
        &t,
        VrrRange {
            min_hz: 73,
            max_hz: 144
        }
    )
    .is_none());
    assert!(LfcConfig::new(
        &t,
        VrrRange {
            min_hz: 72,
            max_hz: 144
        }
    )
    .is_some());
    assert!(LfcConfig::new(
        &t,
        VrrRange {
            min_hz: 24,
            max_hz: 120
        }
    )
    .is_none());
    let c = LfcConfig::new(
        &t,
        VrrRange {
            min_hz: 48,
            max_hz: 144,
        },
    )
    .unwrap();
    for hdmi in [false, true] {
        for duration in [0, 1, 6944, 12000, 20833, u32::MAX] {
            let total = c.total_from_duration(duration, hdmi).unwrap();
            assert!(total >= t.v_total && total <= c.base().v_total_max);
        }
        let mut m = Lfc::new(c);
        m.preflip(u32::MAX);
        assert!(m.frames_to_insert > 0);
        assert!(m.inserted_duration_us >= c.min_us);
        assert!(m.vupdate(hdmi).is_some());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_lfc_requires_effective_two_to_one_and_bounds_duration
);
