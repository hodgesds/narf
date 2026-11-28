use crate::module_test_support as hw;
use core::sync::atomic::Ordering;
#[test]
fn module_large_firmware_packets_and_stalled_commands() {
    hw::MODEL.lock().unwrap().setup_mlx4();
    assert_eq!(crate::register(), 0);
    assert_eq!(hw::probe(1), 0);
    assert_eq!(hw::poll(1), 0);
    {
        let m = hw::MODEL.lock().unwrap();
        assert!(m.carrier);
        assert!(m.retain);
        assert_eq!(
            m.mapped_fw_pages, 8193,
            "32 MiB + one page crosses 32 VPM boundaries"
        );
        assert_eq!(m.commands.iter().filter(|c| c.0 == 0xfff).count(), 33);
        assert!(m.freed > 33, "completed command mailboxes must be freed");
        assert!(m.rx.is_empty(), "empty CQ must not fabricate packets");
        assert!(
            m.commands.contains(&(0xc, 0x101)),
            "RX steering is required"
        );
    }
    let frame = [0xadu8; 60];
    assert_eq!(hw::transmit(1, &frame), 0);
    {
        let m = hw::MODEL.lock().unwrap();
        // Linux SQ stride > RQ stride: SQ first, RQ at 16 * 64.
        // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
        let sq = unsafe { core::slice::from_raw_parts(m.wq_cpu as *const u8, 32) };
        assert_eq!(hw::be32(sq), 0xa);
        assert_eq!(
            hw::be32(&sq[8..]),
            12,
            "software checksummed frames request no offload"
        );
        let source = m.ptr(hw::be64(&sq[24..]));
        // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
        assert_eq!(unsafe { core::slice::from_raw_parts(source, 60) }, frame);
        // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
        let rq = unsafe { core::slice::from_raw_parts((m.wq_cpu + 1024) as *const u8, 16) };
        let rx = m.ptr(hw::be64(&rq[8..]));
        let db = m.ptr(hw::be64(&m.qp_context[0x80..]));
        assert_eq!(
            // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
            u32::from_be(unsafe { db.cast::<u32>().read() }),
            32,
            "RQ producer uses unshifted QPC address"
        );
        // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), rx, frame.len());
            let cqe = m.cq_cpu as *mut u8;
            core::ptr::copy_nonoverlapping(60u32.to_be_bytes().as_ptr(), cqe.add(0x14), 4);
            cqe.add(31).write(0); // received WQE 0, owner phase 0.
        }
    }
    assert_eq!(hw::poll(1), 0);
    assert_eq!(hw::MODEL.lock().unwrap().rx[0], frame);
    // Fresh model HCR after previous completed toggle: cold interface at zero.
    for (token, stuck, stale) in [(2, true, false), (3, false, true)] {
        {
            let mut m = hw::MODEL.lock().unwrap();
            m.regs.insert((1, 0x80698), 0);
            m.stuck_hcr = stuck;
            m.stale_toggle = stale;
        }
        hw::STEP.store(1_000_000, Ordering::Relaxed);
        let before = hw::CLOCK.load(Ordering::Relaxed);
        let freed = hw::MODEL.lock().unwrap().freed;
        assert_ne!(hw::probe(token), 0);
        assert!(
            hw::CLOCK.load(Ordering::Relaxed) - before < 11_000_000_000,
            "bounded HCR timeout"
        );
        assert_eq!(
            hw::MODEL.lock().unwrap().freed,
            freed,
            "timed out mailbox must remain pinned"
        );
    }
    // A required SET_PORT failure cannot be published as a working interface.
    {
        let mut m = hw::MODEL.lock().unwrap();
        m.regs.insert((1, 0x80698), 0);
        m.stuck_hcr = false;
        m.stale_toggle = false;
        m.fail_op = 0xc;
        m.fw_pages = 1;
    }
    hw::STEP.store(100, Ordering::Relaxed);
    assert_ne!(hw::probe(4), 0);
    // Sparse cMPT banks are indexed by type in bits 25:24, per Linux.
    let cap = crate::mlx4::fw::DevCap {
        cmpt_entry_sz: 32,
        ..Default::default()
    };
    let layout = crate::mlx4::icm::make_layout(&cap, &Default::default());
    let regions = layout.regions();
    assert_eq!(regions[1].0 - regions[0].0, 32 << 24);
    assert_eq!(regions[3].0 - regions[0].0, 3 * (32 << 24));
    assert!(regions.iter().map(|r| r.1).sum::<u64>() < 10 * 1024 * 1024);
}
