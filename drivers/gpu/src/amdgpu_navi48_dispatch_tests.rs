use super::*;
use crate::amdgpu_navi48_sources::{classify, CLIENT_DCN, CLIENT_GFX, CLIENT_VMC};
use core::{cell::Cell, task::Context};
use narf_kernel_test::{kernel_test_in, TestResult};

fn iv(client: u8, source: u8, ring: u8, vmid: u8, pasid: u16, data0: u32) -> ih::Event {
    ih::Event {
        ih_ring: 0,
        vector: ih::Vector::decode([
            u32::from(client)
                | (u32::from(source) << 8)
                | (u32::from(ring) << 16)
                | (u32::from(vmid) << 24),
            0,
            0,
            u32::from(pasid),
            data0,
            0,
            0,
            0,
        ]),
    }
}
fn route(t: &IrqSafeSpinLock<Table>, e: ih::Event) -> Delivery {
    t.lock().route(&e, classify(&e))
}
const GFX: src::Queue = src::Queue {
    me: 0,
    pipe: 0,
    queue: 0,
};
fn kernel(key: Key) -> Owner {
    Owner {
        key,
        vmid: 0,
        pasid: 0,
    }
}
fn user(doorbell: u32) -> Owner {
    Owner {
        key: Key::Doorbell(doorbell),
        vmid: 3,
        pasid: 5,
    }
}
fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}
fn far() -> Deadline {
    Deadline::after_ms(10_000)
}

fn navi48_vcn_dispatch_requires_registered_unified_source_and_owned_context() -> TestResult {
    let table = IrqSafeSpinLock::new(Table::new());
    let h = table
        .lock()
        .register(kernel(Key::Vcn { instance: 0 }))
        .unwrap();
    assert_eq!(
        table.lock().register(kernel(Key::Vcn { instance: 2 })),
        Err(RegisterError::Invalid)
    );
    let done = Cell::new(false);
    let mut wait = core::pin::pin!(wait_in(&table, h, far(), || done.get().then_some(1)));
    assert!(poll(wait.as_mut()).is_pending());
    for (client, source, vmid, pasid, expected) in [
        (0x0e, 119, 0, 0, Delivery::Unowned),
        (0x10, 119, 1, 0, Delivery::Unowned),
        (0x10, 119, 0, 1, Delivery::Unowned),
        (0x10, 114, 0, 0, Delivery::Ignored),
        (0x10, 120, 0, 0, Delivery::Ignored),
        (0x10, 153, 0, 0, Delivery::Ignored),
    ] {
        assert_eq!(
            route(&table, iv(client, source, 0, vmid, pasid, 0)),
            expected
        );
    }
    assert_eq!(table.lock().endpoint(h).unwrap().stats.signals, 0);
    // Linux identifies the unified ring by client/source, not ring payload.
    assert_eq!(
        route(&table, iv(0x10, 119, 0xff, 0, 0, 0)),
        Delivery::Signaled
    );
    assert!(poll(wait.as_mut()).is_pending()); // a trap never completes a fence
    done.set(true);
    assert_eq!(route(&table, iv(0x10, 119, 0, 0, 0, 0)), Delivery::Signaled);
    assert_eq!(poll(wait.as_mut()), Poll::Ready(Ok(1)));
    table.lock().retire(h).unwrap();
    assert_eq!(table.lock().endpoint(h), Err(WaitError::Stale));
    assert_eq!(route(&table, iv(0x10, 119, 0, 0, 0, 0)), Delivery::Unowned);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_vcn_dispatch_requires_registered_unified_source_and_owned_context
);

fn navi48_dispatch_coordinated_reset_invalidates_every_old_owner() -> TestResult {
    let mut table = Table::new();
    let keys = [
        Key::Cp(GFX),
        Key::Cp(src::Queue { me: 1, ..GFX }),
        Key::Sdma {
            instance: 0,
            queue: 0,
        },
    ];
    let handles = keys.map(|key| table.register(kernel(key)).unwrap());
    assert_eq!(table.recovery_owners(&handles), Ok(()));
    let extra = table.register(user(0x20)).unwrap();
    assert_eq!(table.reset_owners(handles), Err(WaitError::Stale));
    for h in handles {
        assert!(table.endpoint(h).is_ok());
    }
    table.retire(extra).unwrap();
    assert_eq!(table.reset_owners([handles[0]; 3]), Err(WaitError::Stale));
    let fault = iv(CLIENT_GFX, 183, 0, 3, 5, 0);
    assert_eq!(table.route(&fault, classify(&fault)), Delivery::Faulted(1));
    let next = table.reset_owners(handles).unwrap();
    for (i, old) in handles.into_iter().enumerate() {
        assert_eq!(table.endpoint(old), Err(WaitError::Stale));
        let endpoint = table.endpoint(next[i]).unwrap();
        assert_eq!(endpoint.owner, kernel(keys[i]));
        assert_eq!(endpoint.fault, None);
    }
    table.fail_all(Terminal::DeviceGone);
    assert_eq!(
        table.reset_owners(next),
        Err(WaitError::Terminal(Terminal::DeviceGone))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_coordinated_reset_invalidates_every_old_owner
);

fn navi48_dispatch_routes_completions_only_to_exact_live_owners() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let gfx = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    let sdma = t
        .lock()
        .register(kernel(Key::Sdma {
            instance: 0,
            queue: 0,
        }))
        .unwrap();
    let uq = t.lock().register(user(0x20)).unwrap();
    // Kernel EOP: exact slot, VMID/PASID zero; bit 7 of the ring is ignored.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 0x80, 0, 0, 0)),
        Delivery::Signaled
    );
    // Unowned slots, doorbells and SDMA instances are counted, not completed.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 4, 0, 0, 0)),
        Delivery::Unowned
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 4, 3, 5, 0x21)),
        Delivery::Unowned
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 49, 0x10, 0, 0, 0)),
        Delivery::Unowned
    );
    assert_eq!(route(&t, iv(CLIENT_GFX, 70, 0, 3, 5, 0)), Delivery::Unowned);
    // A user queue completes only from its own VMID/PASID.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 4, 3, 5, 0x20)),
        Delivery::Signaled
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 70, 0, 3, 5, 0x80)),
        Delivery::Signaled
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 4, 3, 6, 0x20)),
        Delivery::Unowned
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 181, 0, 1, 0, 0)),
        Delivery::Unowned
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 49, 0, 0, 0, 0)),
        Delivery::Signaled
    );
    // Diagnostics and unknown vectors are never completions.
    for e in [
        iv(CLIENT_GFX, 239, 0, 0, 0, 0),
        iv(CLIENT_GFX, 177, 0, 0, 0, 0),
        iv(0x0f, 0, 0, 0, 0, 0),
        iv(0x1b, 0, 0, 0, 0, 0),
    ] {
        assert_eq!(route(&t, e), Delivery::Ignored);
    }
    let s = t.lock().summary();
    assert_eq!(s.live, 3);
    assert_eq!(route(&t, iv(0x10, 119, 0, 0, 0, 0)), Delivery::Unowned);
    let s = t.lock().summary();
    assert_eq!(s.counters.unowned, 7);
    assert_eq!(
        (s.counters.unknown, s.counters.media, s.counters.power),
        (2, 1, 1)
    );
    assert_eq!(s.counters.shader_messages, 1);
    let l = t.lock();
    assert_eq!(l.endpoint(gfx).unwrap().stats.signals, 1);
    assert_eq!(l.endpoint(sdma).unwrap().stats.signals, 1);
    assert_eq!(l.endpoint(uq).unwrap().stats.signals, 2);
    assert_eq!(l.endpoint(gfx).unwrap().stats.completions, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_routes_completions_only_to_exact_live_owners
);

fn navi48_dispatch_wakes_waiters_but_only_the_owner_fence_completes() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let h = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    let fence = Cell::new(false);
    let checks = Cell::new(0);
    let mut w = core::pin::pin!(wait_in(&t, h, far(), || {
        checks.set(checks.get() + 1);
        fence.get().then_some(7)
    }));
    assert!(poll(w.as_mut()).is_pending());
    assert_eq!(checks.get(), 1);
    // A stale or early EOP wakes the waiter; its fence decides, so no completion.
    route(&t, iv(CLIENT_GFX, 181, 0, 0, 0, 0));
    assert!(poll(w.as_mut()).is_pending());
    assert_eq!(checks.get(), 2);
    // Arrival between the snapshot and the check is not lost.
    fence.set(true);
    route(&t, iv(CLIENT_GFX, 181, 0, 0, 0, 0));
    assert_eq!(poll(w.as_mut()), Poll::Ready(Ok(7)));
    let s = t.lock().endpoint(h).unwrap().stats;
    assert_eq!((s.signals, s.completions, s.signal_wakes), (2, 1, 2));
    assert_eq!((s.watchdog_wakes, s.watchdog_completions), (0, 0));
    // Woken waiters have unparked.
    assert!(t.lock().slots[0].waiters.iter().all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_wakes_waiters_but_only_the_owner_fence_completes
);

fn navi48_dispatch_watchdog_recovers_lost_interrupts_and_bounds_waits() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let h = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    // The fence lands but its interrupt never arrives.
    let lands = Deadline::after_ms(WATCHDOG_MS / 2);
    let result =
        narf_scheduler::block_on_spin(wait_in(&t, h, far(), || lands.expired().then_some(())));
    assert_eq!(result, Ok(()));
    let s = t.lock().endpoint(h).unwrap().stats;
    assert_eq!((s.completions, s.watchdog_completions), (1, 1));
    assert!(s.watchdog_wakes >= 1 && s.signal_wakes == 0);
    // A fence that never lands times out at the caller's deadline.
    let result =
        narf_scheduler::block_on_spin(wait_in(&t, h, Deadline::after_ms(WATCHDOG_MS + 20), || {
            None::<()>
        }));
    assert_eq!(result, Err(WaitError::Timeout));
    assert_eq!(t.lock().endpoint(h).unwrap().stats.timeouts, 1);
    assert!(t.lock().slots[0].waiters.iter().all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_watchdog_recovers_lost_interrupts_and_bounds_waits
);

fn navi48_dispatch_delivers_queue_faults_to_waiters_and_recovers_by_generation() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let gfx = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    let sdma_key = Key::Sdma {
        instance: 1,
        queue: 0,
    };
    let sdma = t.lock().register(kernel(sdma_key)).unwrap();
    let uq = t.lock().register(user(0x20)).unwrap();
    let mut a = core::pin::pin!(wait_in(&t, gfx, far(), || None::<()>));
    let mut b = core::pin::pin!(wait_in(&t, sdma, far(), || None::<()>));
    let mut c = core::pin::pin!(wait_in(&t, uq, far(), || None::<()>));
    assert!(poll(a.as_mut()).is_pending());
    assert!(poll(b.as_mut()).is_pending());
    assert!(poll(c.as_mut()).is_pending());
    // CP bad opcode on the graphics slot reaches only that owner.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 183, 0, 0, 0, 0)),
        Delivery::Faulted(1)
    );
    let fault = src::Fault::Command {
        fault: src::CommandFault::BadOpcode,
        queue: GFX,
    };
    assert_eq!(
        poll(a.as_mut()),
        Poll::Ready(Err(WaitError::Faulted(fault)))
    );
    assert!(poll(b.as_mut()).is_pending());
    // SDMA page fault: instance/queue attribution.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 60, 0x10, 0, 0, 0)),
        Delivery::Faulted(1)
    );
    assert!(matches!(
        poll(b.as_mut()),
        Poll::Ready(Err(WaitError::Faulted(src::Fault::Sdma {
            fault: src::SdmaFault::PageFault,
            ..
        })))
    ));
    // A VM fault names a context: the user queue, not the VMID0 owners.
    assert!(poll(c.as_mut()).is_pending());
    assert_eq!(
        route(&t, iv(CLIENT_VMC, 0, 0, 3, 5, 0)),
        Delivery::Faulted(1)
    );
    assert_eq!(
        poll(c.as_mut()),
        Poll::Ready(Err(WaitError::Faulted(src::Fault::Vm { mm_hub: true })))
    );
    // Privileged faults on a user slot fall back to the context-ID doorbell.
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 184, 0x14, 3, 5, 0x420)),
        Delivery::Faulted(1)
    );
    assert_eq!(
        route(&t, iv(CLIENT_GFX, 185, 0x14, 0, 0, 0)),
        Delivery::Unattributed
    );
    assert_eq!(t.lock().summary().counters.unattributed, 1);
    // The first fault is retained. Recovery needs a fault and bumps the
    // generation, so the faulted generation's handle is stale forever.
    assert_eq!(
        t.lock().endpoint(uq).unwrap().fault,
        Some(src::Fault::Vm { mm_hub: true })
    );
    let fresh = t.lock().recover(gfx).unwrap();
    assert_ne!(fresh, gfx);
    assert_eq!(t.lock().recover(fresh), Err(WaitError::Stale));
    assert_eq!(t.lock().endpoint(gfx), Err(WaitError::Stale));
    let stale = narf_scheduler::block_on_spin(wait_in(&t, gfx, far(), || Some(())));
    assert_eq!(stale, Err(WaitError::Stale));
    let ok = narf_scheduler::block_on_spin(wait_in(&t, fresh, far(), || Some(())));
    assert_eq!(ok, Ok(()));
    // A fence the owner already observed still completes despite a fault.
    let done = narf_scheduler::block_on_spin(wait_in(&t, sdma, far(), || Some(1)));
    assert_eq!(done, Ok(1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_delivers_queue_faults_to_waiters_and_recovers_by_generation
);

fn navi48_dispatch_terminal_errors_release_every_waiter_and_refuse_new_work() -> TestResult {
    for terminal in [
        Terminal::DeviceGone,
        Terminal::Interrupts(ih::Error::Overflow(0)),
        Terminal::Poison(src::Poison::Utcl2),
    ] {
        let t = IrqSafeSpinLock::new(Table::new());
        let a = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
        let b = t.lock().register(user(0x20)).unwrap();
        let mut wa = core::pin::pin!(wait_in(&t, a, far(), || None::<()>));
        let mut wb = core::pin::pin!(wait_in(&t, b, far(), || None::<()>));
        let mut wd = core::pin::pin!(wait_display_in(&t, HOTPLUG, None, far()));
        assert!(poll(wa.as_mut()).is_pending());
        assert!(poll(wb.as_mut()).is_pending());
        assert!(poll(wd.as_mut()).is_pending());
        if let Terminal::Poison(_) = terminal {
            assert_eq!(
                route(&t, iv(CLIENT_GFX, 1, 0, 0, 0, 0)),
                Delivery::Terminal(terminal)
            );
        } else {
            t.lock().fail_all(terminal);
        }
        let e = Err(WaitError::Terminal(terminal));
        assert_eq!(poll(wa.as_mut()), Poll::Ready(e));
        assert_eq!(poll(wb.as_mut()), Poll::Ready(e));
        assert_eq!(
            poll(wd.as_mut()),
            Poll::Ready(Err(WaitError::Terminal(terminal)))
        );
        // First cause wins; later vectors and registrations are refused.
        t.lock().fail_all(Terminal::DeviceGone);
        assert_eq!(t.lock().summary().terminal, Some(terminal));
        assert_eq!(
            t.lock().register(kernel(Key::Cp(src::Queue::from_ring(4)))),
            Err(RegisterError::Terminal(terminal))
        );
        assert_eq!(
            route(&t, iv(CLIENT_GFX, 181, 0, 0, 0, 0)),
            Delivery::Terminal(terminal)
        );
        assert_eq!(t.lock().recover(a), Err(WaitError::Terminal(terminal)));
        // New waits on a dead device return at once, without checking memory.
        let r = narf_scheduler::block_on_spin(wait_in(&t, a, far(), || -> Option<()> {
            panic!("read a dead device's fence")
        }));
        assert_eq!(r, e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_terminal_errors_release_every_waiter_and_refuse_new_work
);

fn navi48_dispatch_overflow_rechecks_all_waiters_and_display_consumers() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let h = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    let fence = Cell::new(false);
    let mut w = core::pin::pin!(wait_in(&t, h, far(), || fence.get().then_some(())));
    let mut d = core::pin::pin!(wait_display_in(&t, HOTPLUG, None, far()));
    assert!(poll(w.as_mut()).is_pending());
    assert!(poll(d.as_mut()).is_pending());
    // The EOP was among the overwritten vectors.
    fence.set(true);
    t.lock().lost();
    assert_eq!(poll(w.as_mut()), Poll::Ready(Ok(())));
    assert!(matches!(poll(d.as_mut()), Poll::Ready(Ok(_))));
    let s = t.lock().summary();
    assert_eq!((s.counters.lost, s.display.lost), (1, 1));
    assert_eq!(t.lock().endpoint(h).unwrap().stats.watchdog_completions, 0);
    // A latch found by the post-overflow sweep faults its VMID's owners.
    let uq = t.lock().register(user(0x20)).unwrap();
    assert_eq!(t.lock().latched(3, true), Delivery::Faulted(1));
    assert_eq!(t.lock().latched(9, false), Delivery::Unattributed);
    assert_eq!(
        t.lock().endpoint(uq).unwrap().fault,
        Some(src::Fault::Vm { mm_hub: true })
    );
    assert_eq!(t.lock().endpoint(h).unwrap().fault, None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_overflow_rechecks_all_waiters_and_display_consumers
);

fn navi48_dispatch_display_events_wake_only_matching_interest() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let mut d = core::pin::pin!(wait_display_in(&t, HOTPLUG, None, far()));
    assert!(poll(d.as_mut()).is_pending());
    for source in [0x4f, 0x57, 0x3c, 0x1e, 0x68] {
        assert_eq!(
            route(&t, iv(CLIENT_DCN, source, 0, 0, 0, 0)),
            Delivery::Display
        );
    }
    assert!(poll(d.as_mut()).is_pending());
    assert_eq!(route(&t, iv(CLIENT_DCN, 9, 0, 0, 0, 8)), Delivery::Display);
    let Poll::Ready(Ok(version)) = poll(d.as_mut()) else {
        panic!("HPD-RX did not wake the hot-plug consumer");
    };
    let e = t.lock().summary().display;
    assert_eq!((e.hpd_rx[2], e.flip[0], e.vupdate[0]), (1, 1, 1));
    assert_eq!((e.vblank[0], e.vline0[0], e.dmub), (1, 1, 1));
    // An event between waits is reported at once via the version.
    route(&t, iv(CLIENT_DCN, 9, 0, 0, 0, 1));
    let next = narf_scheduler::block_on_spin(wait_display_in(&t, HOTPLUG, Some(version), far()));
    assert_eq!(next, Ok(version + 1));
    let quiet = narf_scheduler::block_on_spin(wait_display_in(
        &t,
        HOTPLUG,
        Some(version + 1),
        Deadline::after_ms(5),
    ));
    assert_eq!(quiet, Err(WaitError::Timeout));
    assert!(t.lock().display_waiters.iter().all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_display_events_wake_only_matching_interest
);

fn navi48_dispatch_hotplug_wait_wakes_early_rate_limits_and_survives_terminal() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    let mut since = None;
    // Quiet: the plain period elapses.
    assert!(!narf_scheduler::block_on_spin(wait_hotplug_in(
        &t, &mut since, 5
    )));
    assert_eq!(since, None);
    // An HPD vector wakes the consumer early, but not before the floor.
    let floor = Deadline::after_ms(HOTPLUG_MIN_MS);
    {
        let mut w = core::pin::pin!(wait_hotplug_in(&t, &mut since, 10_000));
        assert!(poll(w.as_mut()).is_pending());
        route(&t, iv(CLIENT_DCN, 9, 0, 0, 0, 3));
        assert!(narf_scheduler::block_on_spin(w));
    }
    assert!(floor.expired());
    assert_eq!(since, Some(1));
    // One delivered between passes is reported by the next call.
    route(&t, iv(CLIENT_DCN, 9, 0, 0, 0, 3));
    assert!(narf_scheduler::block_on_spin(wait_hotplug_in(
        &t, &mut since, 10_000
    )));
    assert_eq!(since, Some(2));
    // A flip is not a hot-plug event.
    route(&t, iv(CLIENT_DCN, 0x4f, 0, 0, 0, 0));
    assert!(!narf_scheduler::block_on_spin(wait_hotplug_in(
        &t, &mut since, 5
    )));
    // After a terminal error the consumer still gets its period, not a spin.
    t.lock().fail_all(Terminal::DeviceGone);
    let period = Deadline::after_ms(20);
    assert!(!narf_scheduler::block_on_spin(wait_hotplug_in(
        &t, &mut since, 20
    )));
    assert!(period.expired());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_hotplug_wait_wakes_early_rate_limits_and_survives_terminal
);

fn navi48_dispatch_registration_is_unique_bounded_and_generation_checked() -> TestResult {
    let t = IrqSafeSpinLock::new(Table::new());
    assert_eq!(t.lock().register(user(0)), Err(RegisterError::Invalid));
    assert_eq!(
        t.lock().register(Owner {
            vmid: 16,
            ..user(1)
        }),
        Err(RegisterError::Invalid)
    );
    let h = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    assert_eq!(
        t.lock().register(kernel(Key::Cp(GFX))),
        Err(RegisterError::Busy)
    );
    let mut w = core::pin::pin!(wait_in(&t, h, far(), || None::<()>));
    assert!(poll(w.as_mut()).is_pending());
    t.lock().retire(h).unwrap();
    assert_eq!(poll(w.as_mut()), Poll::Ready(Err(WaitError::Stale)));
    assert_eq!(t.lock().retire(h), Err(WaitError::Stale));
    // The slot is reused under a new generation; the old handle stays stale.
    let again = t.lock().register(kernel(Key::Cp(GFX))).unwrap();
    assert_eq!(again.slot, h.slot);
    assert_ne!(again.generation, h.generation);
    assert_eq!(t.lock().endpoint(h), Err(WaitError::Stale));
    // A healthy owner has nothing to recover.
    assert_eq!(t.lock().recover(again), Err(WaitError::Stale));
    for doorbell in 1..SLOTS as u32 {
        t.lock().register(user(doorbell)).unwrap();
    }
    assert_eq!(t.lock().register(user(99)), Err(RegisterError::Full));
    // Waiters beyond the park bound still complete through the watchdog.
    let mut parked: [_; WAITERS + 1] =
        core::array::from_fn(|_| alloc::boxed::Box::pin(wait_in(&t, again, far(), || None::<()>)));
    for p in parked.iter_mut() {
        assert!(poll(p.as_mut()).is_pending());
    }
    assert_eq!(t.lock().summary().counters.unparked, 1);
    drop(parked);
    assert!(t.lock().slots[again.slot as usize]
        .waiters
        .iter()
        .all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_dispatch_registration_is_unique_bounded_and_generation_checked
);

fn navi48_dispatch_reset_invalidates_every_old_handle() -> TestResult {
    let mut table = Table::new();
    let old = table.register(kernel(Key::Cp(GFX))).unwrap();
    table.fail_all(Terminal::DeviceGone);
    table.restart();
    let new = table.register(kernel(Key::Cp(GFX))).unwrap();
    if old == new || table.slot(old).err() != Some(WaitError::Stale) || table.slot(new).is_err() {
        return TestResult::Fail("old IH handle names a new queue after reset");
    }
    table.fail_all(Terminal::DeviceGone);
    table.restart();
    if table.slot(new).err() != Some(WaitError::Stale) {
        return TestResult::Fail("second reset reused a generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48_dispatch",
    navi48_dispatch_reset_invalidates_every_old_handle
);
