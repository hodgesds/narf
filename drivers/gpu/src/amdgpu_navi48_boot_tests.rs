use super::*;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn report() -> Report {
    Report {
        setup: setup::Report {
            revision: 0,
            clear_state_address: 0x800300000,
            clear_state_dwords: 75,
        },
        mes: mes::Report {
            versions: [0x308b; 2],
            completed: [3, 3],
        },
        rs64: rs64::Starts {
            pfp: 0x1000,
            me: 0x2000,
            mec: 0x3000,
        },
        topology: topology::Topology {
            active_cus: 64,
            active_arrays: 0xff,
            cu_bitmap: [[0xff, 0xff, 0, 0]; 4],
            enabled_rb_mask: 0xffff,
        },
        smu: smu::Versions {
            firmware: 0x684c00,
            interface: 0x2e,
        },
        graphics: psp::GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 1 << 31,
        },
        power: smu::PowerStatus {
            allowed: 1,
            enabled: 1,
            gfx_min_mhz: 500,
            gfx_max_mhz: 3100,
        },
        dmub: dmub::Status {
            firmware_version: 0x0a000c00,
            boot_status: 3,
            inbox: 0x800400000,
            outbox: 0x800402000,
            capabilities: None,
        },
        media: psp::MediaFirmware {
            vcn: Some(0x800100000),
            dmcub: Some(0x800200000),
        },
        aperture: gmc::Aperture {
            start: 0xc00000000,
            size: 2 << 20,
            source: 0xc00000000,
            destination: 0xc00001000,
        },
        dma: sdma::Proof {
            copied_bytes: 64,
            fence: 0x90700048,
            read_pointer: 128,
        },
    }
}
struct FakeBoot {
    log: Vec<Stage>,
    fail: Option<Stage>,
    stall: Option<Stage>,
}
impl Backend for FakeBoot {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        self.log.push(stage);
        if self.stall == Some(stage) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(stage) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(report())
    }
}
fn sequence(fail: Option<Stage>, stall: Option<Stage>) -> Sequence<FakeBoot> {
    Sequence {
        backend: FakeBoot {
            log: Vec::new(),
            fail,
            stall,
        },
        state: State::Prepared,
    }
}
fn navi48_boot_order_failure_and_cancellation() -> TestResult {
    let mut s = sequence(None, None);
    if run(s.run()) != Ok(report()) || s.backend.log != STAGES || s.state != State::MemoryReady {
        return TestResult::Fail("Navi48 firmware boot order/report");
    }
    if run(s.run()) != Err(Error::Busy) || s.backend.log.len() != STAGES.len() {
        return TestResult::Fail("completed cold boot replayed");
    }
    for (i, stage) in STAGES.into_iter().enumerate() {
        let mut s = sequence(Some(stage), None);
        if run(s.run()) != Err(Error::Invalid)
            || s.state != State::Failed(stage, Error::Invalid)
            || s.backend.log != STAGES[..=i]
            || run(s.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed stage continued or replayed");
        }
        let mut s = sequence(None, Some(stage));
        {
            let mut f = core::pin::pin!(s.run());
            if f.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("blocked stage completed");
            }
        }
        if s.state != State::Running(stage)
            || s.backend.log != STAGES[..=i]
            || run(s.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled cold boot continued or replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48_boot",
    navi48_boot_order_failure_and_cancellation
);
