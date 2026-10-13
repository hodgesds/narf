use super::*;

const PAD: u64 = BASE + 0x28f4 * 4;
fn hpd(block: u64, reg: u64) -> u64 {
    BASE + (reg + block * 8) * 4
}

fn dcn401_hpd_routes_pin_enables_block_and_reads_debounced_sense() -> TestResult {
    // path(1) names GPIO_HPD_3: HPD block 2, pad mask bit 16.
    let (mut e, _) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    let regs = &mut e.io.inner.inner.regs;
    regs.insert(PAD, 0x1_0001);
    assert_eq!(e.hpd_sense(path(1)), Err(Error::Busy)); // GPIO-owned pin
    e.io.inner.inner.regs.insert(PAD, 0x1);
    assert_eq!(e.hpd_sense(path(1)), Err(Error::Busy)); // block disabled
    e.io.inner.inner.regs.insert(PAD, 0x1_0001);
    assert_eq!(e.enable_hpd(path(1)), Ok(()));
    let regs = &e.io.inner.inner.regs;
    assert_eq!(regs[&PAD], 0x1); // other pins keep their owner
    assert_eq!(regs[&hpd(2, 0x175c)] & 0x1000_0000, 0x1000_0000);
    assert_eq!(e.hpd_sense(path(1)), Ok(false));
    // The raw sense bit alone is not the debounced state Linux reads.
    e.io.inner.inner.regs.insert(hpd(2, 0x175a), 0x2);
    assert_eq!(e.hpd_sense(path(1)), Ok(false));
    e.io.inner.inner.regs.insert(hpd(2, 0x175a), 0x12);
    assert_eq!(e.hpd_sense(path(1)), Ok(true));
    // No selector, or one past the four blocks, is never addressed.
    for selector in [0, 5] {
        let p = inventory::Path {
            hpd: selector,
            ..path(1)
        };
        assert_eq!(e.enable_hpd(p), Err(Error::Unsupported));
        assert_eq!(e.hpd_sense(p), Err(Error::Unsupported));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hpd_routes_pin_enables_block_and_reads_debounced_sense
);

fn dcn401_dp_link_status_reads_sink_lock_without_touching_the_owner() -> TestResult {
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    // Only a trained (or later) link has a status to read.
    assert_eq!(run(e.dp_link_status(&mut io, path(1))), Err(Error::Busy));
    run(e.train_dp_link(&mut io, path(1), false)).unwrap();
    let writes = e.io.inner.inner.writes.len();
    let locked = run(e.dp_link_status(&mut io, path(1))).unwrap();
    if !locked.locked || locked.power.is_some() || locked.lost() {
        return TestResult::Fail("locked link");
    }
    // Lane 1 without symbol lock or EQ, then lost interlane alignment: all
    // are losses while the sink is in D0, and none while it sleeps.
    for status in [
        [0x37, 0x77, 1, 0, 0, 0],
        [0x17, 0, 1, 0, 0, 0],
        [0x77, 0, 0, 0, 0, 0],
    ] {
        io.status.push_back(status);
        let s = run(e.dp_link_status(&mut io, path(1))).unwrap();
        if s.locked || s.power != Some(1) || !s.lost() || s.lanes != status {
            return TestResult::Fail("lost link");
        }
    }
    io.bytes.insert(0x600, 2);
    io.status.push_back([0x11, 0x11, 0, 0, 0, 0]);
    let asleep = run(e.dp_link_status(&mut io, path(1))).unwrap();
    if asleep.locked || asleep.lost() {
        return TestResult::Fail("sleeping sink counted as loss");
    }
    // Lanes beyond the trained count are ignored.
    io.status.push_back([0x77, 0x00, 1, 0, 0, 0]);
    if !run(e.dp_link_status(&mut io, path(1))).unwrap().locked {
        return TestResult::Fail("untrained lanes checked");
    }
    // Wrong path, unready firmware and AUX failure: no state change, no write.
    assert_eq!(run(e.dp_link_status(&mut io, path(2))), Err(Error::Busy));
    io.fw.ready = false;
    assert_eq!(run(e.dp_link_status(&mut io, path(1))), Err(Error::Busy));
    io.fw.ready = true;
    io.fail = Some((io.step + 1, dmub::Error::Aux(3)));
    assert!(matches!(
        run(e.dp_link_status(&mut io, path(1))),
        Err(Error::Firmware(_))
    ));
    assert_eq!(e.status.state, State::DpLinkTrained(1));
    assert_eq!(e.io.inner.inner.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_link_status_reads_sink_lock_without_touching_the_owner
);

fn dcn401_unplugged_dp_link_stop_skips_sink_d3_only_with_hpd_low() -> TestResult {
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(1), false)).unwrap();
    // HPD not routed, then sensed high: the sink may still be there.
    assert_eq!(
        run(e.stop_unplugged_dp_link(&mut io, path(1))),
        Err(Error::Busy)
    );
    e.enable_hpd(path(1)).unwrap();
    e.io.inner.inner.regs.insert(hpd(2, 0x175a), 0x10);
    assert_eq!(
        run(e.stop_unplugged_dp_link(&mut io, path(1))),
        Err(Error::Busy)
    );
    assert_eq!(e.status.state, State::DpLinkTrained(1));
    e.io.inner.inner.regs.insert(hpd(2, 0x175a), 0);
    io.unplugged = true;
    let aux = io
        .events
        .iter()
        .filter(|e| matches!(e, Event::Aux(..)))
        .count();
    assert_eq!(run(e.stop_unplugged_dp_link(&mut io, path(1))), Ok(()));
    assert_eq!(e.status.state, State::DpPhyDisabled);
    // No AUX to the departed sink.
    assert_eq!(
        io.events
            .iter()
            .filter(|e| matches!(e, Event::Aux(..)))
            .count(),
        aux
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_unplugged_dp_link_stop_skips_sink_d3_only_with_hpd_low
);
