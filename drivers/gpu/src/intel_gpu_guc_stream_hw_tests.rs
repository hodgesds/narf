// Real GuCGt/CT/owned firmware-BO log streaming conversations. Control wire
// vectors are from MIT Linux b90c984d intel_guc_log.c + guc_log_abi.h.
use super::*;
use crate::intel_gpu_guc_log::StreamSession;
use narf_filesystem::FsError;

fn logs(w: &Window) -> Words {
    w.0.borrow()
        .memory
        .values()
        .find(|b| b.borrow().len() == 0x115000 / 4)
        .unwrap()
        .clone()
}
fn response(memory: &Words, id: u16) {
    let mut words = memory.borrow_mut();
    let tail = words[513];
    words[2048 + tail as usize] = 1 | u32::from(id) << 16;
    words[2048 + ((tail + 1) & 4095) as usize] = 0xf0000000;
    words[513] = (tail + 2) & 4095;
}
pub(crate) fn service(w: &Window, memory: &Words, id: u16, request: &[u32]) {
    assert_eq!(request.len(), 2);
    let action = request[0] as u16;
    let value = request[1];
    let log = logs(w);
    w.0.borrow_mut().stream_controls.push((action, id, value));
    match action {
        0x40 | 0x302 => {
            assert!((0x7f00..=0x7ffc).contains(&id));
            assert!(
                w.0.borrow_mut().stream_fences.insert(id),
                "control fence reused"
            );
            if action == 0x40 {
                assert!(matches!(value, 0x101 | 0x100));
                w.0.borrow_mut().stream_enabled = value == 0x101;
            } else {
                assert_eq!(value, 0);
                assert!(w.0.borrow().stream_enabled);
                {
                    let mut words = log.borrow_mut();
                    for i in 0..2 {
                        words[i * 9 + 5] = words[i * 9 + 3];
                        words[i * 9 + 7] |= 1;
                    }
                }
                event(memory, 0x8003, &[]);
            }
            if w.0.borrow().stream_drop != Some((action, value)) {
                response(memory, id);
            }
        }
        0x30 => {
            assert_eq!((id, value), (0x7fff, 0));
            {
                let mut words = log.borrow_mut();
                for i in 0..2 {
                    assert_eq!(words[i * 9 + 2], words[i * 9 + 5]);
                    assert_eq!(words[i * 9 + 7], 0);
                }
                assert_eq!(words[72 / 4 + 7], 0x1f, "capture section was acknowledged");
                if w.0.borrow().stream_overwrite {
                    for word in &mut words[4096 / 4..0x15000 / 4] {
                        *word = 0xeeeeeeee;
                    }
                }
            }
            w.0.borrow_mut().stream_acks += 1;
        }
        _ => unreachable!(),
    }
}
fn put_bytes(words: &mut [u32], base: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        let at = base + index;
        let shift = (at & 3) * 8;
        words[at / 4] = (words[at / 4] & !(255 << shift)) | u32::from(*byte) << shift;
    }
}
fn initialize(w: &Window, wrapped: bool) -> [Vec<u8>; 2] {
    let log = logs(w);
    let mut words = log.borrow_mut();
    let positions = if wrapped {
        [(65532, 4, 65536), (16382, 3, 16384)]
    } else {
        [(0, 16, 65536), (0, 8, 16384)]
    };
    for (i, (read, write, size)) in positions.into_iter().enumerate() {
        let state = [
            0xcabba9e6,
            if i == 0 { 0xdeadfeed } else { 0x8086dead },
            read,
            write,
            size,
            0,
            size,
            0,
            2,
        ];
        words[i * 9..i * 9 + 9].copy_from_slice(&state);
    }
    words[18..27].copy_from_slice(&[
        0xcabba9f7, 0xbeeffeed, 24, 32, 0x100000, 32, 0x100000, 0x1f, 2,
    ]);
    if wrapped {
        put_bytes(&mut words, 4096 + 65532, &[0xa0, 0xa1, 0xa2, 0xa3]);
        put_bytes(&mut words, 4096, &[0xb0, 0xb1, 0xb2, 0xb3]);
        put_bytes(&mut words, 0x11000 + 16382, &[0xc0, 0xc1]);
        put_bytes(&mut words, 0x11000, &[0xd0, 0xd1, 0xd2]);
        [
            alloc::vec![0xa0, 0xa1, 0xa2, 0xa3, 0xb0, 0xb1, 0xb2, 0xb3],
            alloc::vec![0xc0, 0xc1, 0xd0, 0xd1, 0xd2],
        ]
    } else {
        let event: Vec<_> = (0x10..0x20).collect();
        let crash: Vec<_> = (0x30..0x38).collect();
        put_bytes(&mut words, 4096, &event);
        put_bytes(&mut words, 0x11000, &crash);
        [event, crash]
    }
}
fn session() -> Arc<StreamSession> {
    (0..64)
        .rev()
        .find_map(|index| StreamSession::reserve_for_test(index).ok())
        .unwrap()
}
fn poll(gt: &mut GuCGt<Window, Arena>, now: u64) {
    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
    gt.poll_log_stream(now, || true).unwrap();
}
fn service_now(w: &Window) {
    service_contexts(w, &mut BTreeMap::new(), true);
}
fn until_ack(gt: &mut GuCGt<Window, Arena>, w: &Window, count: usize, start: u64) {
    for now in start..start + 30 {
        poll(gt, now);
        service_now(w);
        if w.0.borrow().stream_acks == count {
            return;
        }
    }
    panic!("stream ACK{count} missing");
}
fn produce(w: &Window, pattern: u8) {
    let log = logs(w);
    let mut words = log.borrow_mut();
    for i in 0..2 {
        let old = words[i * 9 + 2];
        let next = old + 4;
        put_bytes(
            &mut words,
            (if i == 0 { 4096 } else { 0x11000 }) + old as usize,
            &[pattern, pattern + 1, pattern + 2, pattern + 3],
        );
        words[i * 9 + 3] = next;
        words[i * 9 + 5] = next;
        words[i * 9 + 7] = 1;
    }
    drop(words);
    event(&ct_memory(w), 0x8003, &[]);
}
fn dword(frame: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(frame[offset..offset + 4].try_into().unwrap())
}
fn qword(frame: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(frame[offset..offset + 8].try_into().unwrap())
}
fn frame(session: &StreamSession, mut prefix: Vec<u8>) -> Vec<u8> {
    while prefix.len() < 24 {
        let mut buffer = alloc::vec![0; 24-prefix.len()];
        let n = session.read_for_test(&mut buffer).unwrap();
        assert_ne!(n, 0);
        prefix.extend_from_slice(&buffer[..n]);
    }
    let length = dword(&prefix, 16) as usize;
    while prefix.len() < length {
        let mut buffer = alloc::vec![0; (length-prefix.len()).min(4096)];
        let n = session.read_for_test(&mut buffer).unwrap();
        assert_ne!(n, 0);
        prefix.extend_from_slice(&buffer[..n]);
    }
    prefix
}
fn sections(frame: &[u8]) -> [&[u8]; 2] {
    core::array::from_fn(|i| {
        let start = dword(frame, 72 + i * 8) as usize;
        let len = dword(frame, 76 + i * 8) as usize;
        &frame[start..start + len]
    })
}
fn close(gt: &mut GuCGt<Window, Arena>, w: &Window, session: &StreamSession, now: u64) {
    session.stop_for_test();
    poll(gt, now);
    assert!(!gt.idle());
    service_now(w);
    assert!(!w.0.borrow().stream_enabled);
    assert!(!gt.idle(), "detach before restore ACK");
    poll(gt, now + 1);
    assert!(gt.idle());
}
fn smoke_guc_stream_hardware_linear_wrapped_copy_precedes_ack_and_close() -> TestResult {
    for wrapped in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        prime_copy8(&mut gt, &w);
        let expected = initialize(&w, wrapped);
        let source_capture = logs(&w).borrow()[18..27].to_vec();
        let session = session();
        let epoch = gt.user_epoch().unwrap();
        let baseline = arena.live_allocations();
        assert!(gt.idle());
        assert_eq!(
            gt.attach_log_stream(session.clone(), epoch + 1, 500, [0xa5; 32]),
            Err(FsError::NoDevice)
        );
        assert_eq!(
            gt.attach_log_stream(session.clone(), epoch, 500, [0xa5; 32]),
            Ok(())
        );
        assert_eq!(
            gt.attach_log_stream(session.clone(), epoch, 500, [0xa5; 32]),
            Ok(())
        );
        assert!(!gt.idle());
        w.0.borrow_mut().stream_overwrite = true;
        let mut prefix = [0; 8];
        let mut copied = false;
        for now in 501..530 {
            poll(&mut gt, now);
            let n = session.read_for_test(&mut prefix).unwrap();
            if n != 0 {
                assert_eq!(n, 8);
                copied = true;
                break;
            }
            service_now(&w);
        }
        assert!(copied);
        assert_eq!(
            w.0.borrow().stream_acks,
            0,
            "host copy must precede firmware ACK"
        );
        assert_eq!(&prefix, b"NARFGSTR");
        service_now(&w);
        assert_eq!(w.0.borrow().stream_acks, 1);
        let bytes = frame(&session, prefix.to_vec());
        assert_eq!(
            sections(&bytes),
            [expected[0].as_slice(), expected[1].as_slice()]
        );
        assert_eq!(
            (
                dword(&bytes, 8),
                dword(&bytes, 12),
                dword(&bytes, 24),
                dword(&bytes, 28)
            ),
            (1, 192, 3, session.index())
        );
        assert_eq!(qword(&bytes, 32), 0);
        assert_eq!(qword(&bytes, 40), epoch);
        assert_ne!(qword(&bytes, 48), 0);
        assert_eq!(dword(&bytes, 64), 0x3646);
        assert_eq!(&bytes[160..192], &[0xa5; 32]);
        assert_eq!(logs(&w).borrow()[4096 / 4], 0xeeeeeeee);
        assert_eq!(&logs(&w).borrow()[18..27], source_capture.as_slice());
        close(&mut gt, &w, &session, 540);
        assert_eq!(session.read_for_test(&mut prefix), Err(FsError::NoDevice));
        assert_eq!(
            w.0.borrow().stream_controls,
            [
                (0x40, 0x7f00, 0x101),
                (0x302, 0x7f01, 0),
                (0x30, 0x7fff, 0),
                (0x40, 0x7f02, 0x100)
            ]
        );
        assert_eq!(arena.live_allocations(), baseline);
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_hardware_linear_wrapped_copy_precedes_ack_and_close
);

fn smoke_guc_stream_hardware_two_slots_backpressure_retries_without_early_ack() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy8(&mut gt, &w);
    let first = initialize(&w, false);
    let session = session();
    let epoch = gt.user_epoch().unwrap();
    gt.attach_log_stream(session.clone(), epoch, 500, [0; 32])
        .unwrap();
    w.0.borrow_mut().stream_overwrite = true;
    until_ack(&mut gt, &w, 1, 501);
    produce(&w, 0x40);
    until_ack(&mut gt, &w, 2, 540);
    produce(&w, 0x60);
    poll(&mut gt, 580);
    service_now(&w);
    assert_eq!(w.0.borrow().stream_acks, 2);
    assert_eq!(
        (
            logs(&w).borrow()[2],
            logs(&w).borrow()[5],
            logs(&w).borrow()[7]
        ),
        (20, 24, 1)
    );
    let bytes0 = frame(&session, Vec::new());
    assert_eq!(
        sections(&bytes0),
        [first[0].as_slice(), first[1].as_slice()]
    );
    poll(&mut gt, 581);
    assert_eq!(w.0.borrow().stream_acks, 2);
    service_now(&w);
    assert_eq!(w.0.borrow().stream_acks, 3);
    let bytes1 = frame(&session, Vec::new());
    let bytes2 = frame(&session, Vec::new());
    assert_eq!((qword(&bytes1, 32), qword(&bytes2, 32)), (1, 2));
    assert_eq!(sections(&bytes1), [&[0x40, 0x41, 0x42, 0x43][..]; 2]);
    assert_eq!(sections(&bytes2), [&[0x60, 0x61, 0x62, 0x63][..]; 2]);
    close(&mut gt, &w, &session, 590);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_hardware_two_slots_backpressure_retries_without_early_ack
);

fn smoke_guc_stream_hardware_bad_headers_overflow_cursor_and_access_loss() -> TestResult {
    for failure in 0..5 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        prime_copy8(&mut gt, &w);
        initialize(&w, false);
        let session = session();
        gt.attach_log_stream(session.clone(), gt.user_epoch().unwrap(), 500, [0; 32])
            .unwrap();
        until_ack(&mut gt, &w, 1, 501);
        let retained = frame(&session, Vec::new());
        let baseline = arena.live_allocations();
        if failure == 4 {
            let reads = w.0.borrow().mmio_reads.get();
            let commands = w.0.borrow().stream_controls.len();
            gt.poll_log_stream(540, || false).unwrap();
            assert_eq!(
                w.0.borrow().mmio_reads.get(),
                reads,
                "current authority must precede wake MMIO"
            );
            assert_eq!(w.0.borrow().stream_controls.len(), commands);
            assert!(!gt.idle());
            let mut buffer = [0; 8];
            assert_eq!(session.read_for_test(&mut buffer), Err(FsError::NoDevice));
            gt.poll_log_stream(541, || true).unwrap();
            assert_eq!(
                w.0.borrow().stream_controls.len(),
                commands,
                "lost owner cannot reopen"
            );
        } else if failure == 3 {
            event(&ct_memory(&w), 0x8003, &[1]);
            assert_eq!(
                gt.poll(540),
                Poll::Ready(Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Transport(
                        crate::intel_gpu_guc_transport::TransportError::Protocol(0x8003)
                    )
                )))
            );
            let mut buffer = [0; 8];
            assert_eq!(session.read_for_test(&mut buffer), Err(FsError::NoDevice));
            assert!(!gt.idle());
        } else {
            produce(&w, 0x40);
            let log = logs(&w);
            match failure {
                0 => log.borrow_mut()[0] = 0,
                1 => log.borrow_mut()[7] = 0x11,
                _ => log.borrow_mut()[2] = 0, // differs from our acknowledged read cursor16
            }
            poll(&mut gt, 540);
            let mut buffer = [0; 8];
            assert_eq!(
                session.read_for_test(&mut buffer),
                Err(FsError::InvalidData)
            );
            assert_eq!(w.0.borrow().stream_acks, 1);
            assert!(!gt.idle());
            poll(&mut gt, 541);
            service_now(&w);
            assert!(!gt.idle(), "restore still awaits its control response");
            poll(&mut gt, 542);
            assert!(gt.idle());
        }
        assert_eq!(
            sections(&retained)[0],
            &(0x10u8..0x20).collect::<Vec<_>>()[..]
        );
        assert_eq!(w.0.borrow().stream_acks, 1, "bad source was acknowledged");
        assert_eq!(
            arena.live_allocations(),
            baseline,
            "log source reclaimed before reset"
        );
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_hardware_bad_headers_overflow_cursor_and_access_loss
);

fn smoke_guc_stream_hardware_timeouts_full_fifo_and_malformed_restore_hold_owner() -> TestResult {
    for failure in 0..6 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        prime_copy8(&mut gt, &w);
        initialize(&w, false);
        let session = session();
        if failure == 0 {
            w.0.borrow_mut().stream_drop = Some((0x40, 0x101));
        }
        if failure == 1 {
            w.0.borrow_mut().stream_drop = Some((0x302, 0));
        }
        gt.attach_log_stream(session.clone(), gt.user_epoch().unwrap(), 500, [0; 32])
            .unwrap();
        let baseline = arena.live_allocations();
        if failure < 2 {
            for now in 501..520 {
                poll(&mut gt, now);
                service_now(&w);
            }
            assert_eq!(w.0.borrow().stream_acks, 0);
            poll(&mut gt, 500_001_000);
            service_now(&w);
            assert!(!gt.idle());
            poll(&mut gt, 500_001_001);
            assert!(gt.idle(), "known default-policy response permits detach");
            assert!(!w.0.borrow().stream_enabled);
            let mut buffer = [0; 8];
            assert_eq!(
                session.read_for_test(&mut buffer),
                Err(crate::intel_gpu_user::io_error())
            );
        } else if matches!(failure, 2 | 5) {
            until_ack(&mut gt, &w, 1, 501);
            frame(&session, Vec::new());
            w.0.borrow_mut().stream_drop = Some((0x40, 0x100));
            session.stop_for_test();
            poll(&mut gt, 540);
            service_now(&w);
            assert!(!gt.idle());
            let controls = w.0.borrow().stream_controls.len();
            if failure == 5 {
                response(&ct_memory(&w), 0x7fff);
                poll(&mut gt, 541);
            } else {
                poll(&mut gt, 500_001_000);
            }
            assert!(!gt.idle(), "uncertain restore stays owned");
            let mut buffer = [0; 8];
            assert_eq!(session.read_for_test(&mut buffer), Err(FsError::NoDevice));
            service_now(&w);
            poll(&mut gt, 500_001_001);
            service_now(&w);
            assert_eq!(
                w.0.borrow().stream_controls.len(),
                controls,
                "restore fence was reissued"
            );
            assert_eq!(w.0.borrow().stream_fences.len(), 3);
        } else {
            until_ack(&mut gt, &w, 1, 501);
            produce(&w, 0x40);
            until_ack(&mut gt, &w, 2, 540);
            produce(&w, 0x60);
            if failure == 4 {
                logs(&w).borrow_mut()[7] = 0x11;
            }
            poll(&mut gt, 580);
            service_now(&w);
            assert_eq!(w.0.borrow().stream_acks, 2);
            assert_eq!(
                logs(&w).borrow()[2],
                20,
                "full FIFO advanced the source cursor"
            );
            if failure == 3 {
                poll(&mut gt, 500_001_000);
            }
            let end = if failure == 3 { 500_001_001 } else { 581 };
            poll(&mut gt, end);
            service_now(&w);
            assert!(!gt.idle());
            poll(&mut gt, end + 1);
            assert!(gt.idle());
            let bytes0 = frame(&session, Vec::new());
            let bytes1 = frame(&session, Vec::new());
            assert_eq!((qword(&bytes0, 32), qword(&bytes1, 32)), (0, 1));
            assert_eq!(sections(&bytes1), [&[0x40, 0x41, 0x42, 0x43][..]; 2]);
            let mut buffer = [0; 8];
            assert_eq!(
                session.read_for_test(&mut buffer),
                Err(if failure == 3 {
                    FsError::NoSpace
                } else {
                    FsError::InvalidData
                })
            );
            assert_eq!(
                w.0.borrow().stream_acks,
                2,
                "terminal data loss fabricated a flush ACK"
            );
            assert_eq!(logs(&w).borrow()[2], 20);
        }
        assert_eq!(arena.live_allocations(), baseline);
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_stream_hardware_timeouts_full_fifo_and_malformed_restore_hold_owner
);
