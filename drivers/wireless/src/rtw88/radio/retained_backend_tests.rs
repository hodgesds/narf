//! Exercise the actual reserved-page owner around the complete C22 radio
//! continuation; RadioIo supplies only the device-side register receipts.
use super::*;
use crate::rtw88::reserved_page::{Backend, Memory, Registers};
use narf_lib::sync::IrqSafeSpinLock;

struct Storage {
    address: u64,
    bytes: Vec<u8>,
    syncs: usize,
    acquires: usize,
}
struct Buffer {
    storage: Arc<IrqSafeSpinLock<Storage>>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Buffer {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: isolated coherent byte storage, owned by this Backend only. The
// simulator reads it after sync and provides explicit device completion.
unsafe impl Memory for Buffer {
    fn address(&self) -> u64 {
        self.storage.lock().address
    }
    fn len(&self) -> usize {
        self.storage.lock().bytes.len()
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::Memory)?;
        self.storage
            .lock()
            .bytes
            .get_mut(offset..end)
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn sync(&self) {
        self.storage.lock().syncs += 1;
    }
    fn acquire(&self) {
        self.storage.lock().acquires += 1;
    }
}
#[derive(Default)]
struct Observed {
    pages: usize,
    parks: usize,
    cpu: usize,
    finished: usize,
    fail_park: bool,
    fail_cpu: bool,
}
struct Port {
    radio: RadioIo,
    ring: Arc<IrqSafeSpinLock<Storage>>,
    frame: Arc<IrqSafeSpinLock<Storage>>,
    seen: Arc<IrqSafeSpinLock<Observed>>,
    hold: Arc<AtomicBool>,
    parked: bool,
}
#[async_trait::async_trait]
// SAFETY: this is an inert register/firmware simulator, with the actual Backend
// controlling all reserved-page descriptor writes and terminal ownership.
unsafe impl Registers for Port {
    fn claim_firmware_dma(&mut self, base: u32) -> Result<(), Error> {
        let ring = self.ring.lock();
        if ring.address != u64::from(base) || ring.bytes != [0; 16] || ring.syncs == 0 {
            return Err(Error::Prerequisite);
        }
        drop(ring);
        Io::claim_pristine(&mut self.radio)
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        Io::read8(&mut self.radio, r)
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        Io::read16(&mut self.radio, r)
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        Io::read32(&mut self.radio, r)
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        Io::write8(&mut self.radio, r, v)?;
        if r == 0x383 && v & 16 != 0 {
            let ring = self.ring.lock();
            let frame = self.frame.lock();
            if ring.syncs == 0 || frame.syncs == 0 || ring.bytes[3] & 0x80 == 0 {
                return Err(Error::Prerequisite);
            }
            self.seen.lock().pages += 1;
            self.radio.base.regs[0x205] |= 0x80;
        }
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        Io::write16(
            &mut self.radio,
            r,
            if r == 0x204 { v & !(1 << 15) } else { v },
        )
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        Io::write32(&mut self.radio, r, v)
    }
    async fn delay_us(&mut self, us: u64) {
        Io::delay_us(&mut self.radio, us).await;
        if self.radio.pending && self.hold.load(Ordering::Acquire) {
            core::future::pending::<()>().await;
        }
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Io::lte_backup(&mut self.radio).await
    }
    async fn lte_restore(&mut self, v: u32) -> Result<(), Error> {
        Io::lte_restore(&mut self.radio, v).await
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Io::finish_dma(&mut self.radio).await?;
        self.parked = true;
        Ok(())
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        Io::begin_mac(&mut self.radio)
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        Io::finish_mac(&mut self.radio)
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        Io::begin_phy(&mut self.radio)
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        Io::finish_phy(&mut self.radio)?;
        self.radio.arm_calibration();
        Ok(())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        Io::begin_commands(&mut self.radio)?;
        self.parked = false;
        Ok(())
    }
    fn submit_h2c(&mut self, p: &[u8; 32]) -> Result<(), Error> {
        Io::submit_h2c(&mut self.radio, p)
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        Io::poll_h2c(&mut self.radio)
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        let mut seen = self.seen.lock();
        seen.parks += 1;
        if seen.fail_park {
            return Err(Error::Access);
        }
        if self.radio.pending || self.radio.commands.len() != 3 {
            return Err(Error::Prerequisite);
        }
        self.radio.base.regs[0x100] = 0x30;
        self.parked = true;
        Ok(())
    }
    fn parked_cpu<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let mut seen = self.seen.lock();
        seen.cpu += 1;
        if !self.parked || seen.fail_cpu {
            return Err(Error::Access);
        }
        drop(seen);
        operation()
    }
    fn finish_radio(&mut self, gate: crate::rtw88::power_policy::Gate) -> Result<(), Error> {
        if !self.parked
            || self.ring.lock().bytes != [0; 16]
            || self.frame.lock().bytes[..48] != [0; 48]
            || self.radio.base.regs[0x383] & 16 != 0
            || self.radio.base.regs[0x550] & 8 != 0
        {
            return Err(Error::Prerequisite);
        }
        Io::finish_radio(&mut self.radio, gate)?;
        self.seen.lock().finished += 1;
        Ok(())
    }
}
fn smoke_rtw8822ce_actual_reserved_backend_composes_radio_park_disarm_and_failures() -> TestResult {
    for outcome in 0..4 {
        let seen = Arc::new(IrqSafeSpinLock::new(Observed::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let hold = Arc::new(AtomicBool::new(false));
        let ring = Arc::new(IrqSafeSpinLock::new(Storage {
            address: 0x10000,
            bytes: alloc::vec![0xa5; 16],
            syncs: 0,
            acquires: 0,
        }));
        let frame = Arc::new(IrqSafeSpinLock::new(Storage {
            address: 0x20000,
            bytes: alloc::vec![0xa5; 48 + 4096],
            syncs: 0,
            acquires: 0,
        }));
        let port = Port {
            radio: RadioIo::new(),
            ring: ring.clone(),
            frame: frame.clone(),
            seen: seen.clone(),
            hold: hold.clone(),
            parked: false,
        };
        let backend = match Backend::new(
            port,
            Buffer {
                storage: ring.clone(),
                drops: drops.clone(),
            },
            Buffer {
                storage: frame.clone(),
                drops: drops.clone(),
            },
            0,
        ) {
            Ok(backend) => backend,
            Err(_) => {
                return TestResult::Fail("C22 real reserved backend fixture allocation failed")
            }
        };
        let mut owner = Owner::new(backend, 0xc822);
        if narf_scheduler::block_on(owner.download(&super::super::mac_tests::firmware())).is_err()
            || narf_scheduler::block_on(owner.prepare_mac()).is_err()
        {
            return TestResult::Fail("C22 real reserved backend firmware/MAC composition failed");
        }
        let factory = super::super::power_policy_tests::make_factory(0, 60);
        if narf_scheduler::block_on(owner.prepare_phy_tables(&factory)).is_err() {
            return TestResult::Fail("C22 real reserved backend PHY composition failed");
        }
        let board = match Board::new(
            &factory,
            owner.phy_info().unwrap(),
            owner.hardware_info().unwrap(),
            owner.image_digest().unwrap(),
        ) {
            Ok(board) => board,
            Err(_) => return TestResult::Fail("C22 composed board identity failed"),
        };
        let policy = super::super::power_policy_tests::domain();
        let source = super::super::power_policy_tests::source(
            super::super::power_policy_tests::image(board, &factory),
            narf_capabilities::Cap::bootstrap(),
        );
        let permission = match owner.qualify_with(&factory, &policy, source) {
            Ok(permission) => permission,
            Err(_) => return TestResult::Fail("C22 real backend measured qualification failed"),
        };
        let gate = crate::rtw88::power_policy::Gate::new(
            owner.power.as_ref().unwrap().clone(),
            permission,
            factory.mac(),
        );
        let pages = seen.lock().pages;
        let payload = frame.lock().bytes[48..].to_vec();
        seen.lock().fail_park = outcome == 1;
        seen.lock().fail_cpu = outcome == 2;
        hold.store(outcome == 3, Ordering::Release);
        if outcome == 3 {
            let mut future = alloc::boxed::Box::pin(owner.prepare_radio_with_policy(
                &factory,
                permission,
                || Ok(policy.clone()),
            ));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                != Poll::Pending
            {
                return TestResult::Fail("C22 actual backend missed pending command cancellation");
            }
            drop(future);
        } else {
            let result = narf_scheduler::block_on(owner.prepare_radio_with_policy(
                &factory,
                permission,
                || Ok(policy.clone()),
            ));
            if result.is_ok() != (outcome == 0) || (outcome != 0 && result != Err(Error::Access)) {
                return TestResult::Fail("C22 real reserved backend could not transfer successful firmware ownership into radio completion");
            }
        }
        {
            let seen = seen.lock();
            if pages == 0
                || seen.pages != pages
                || seen.finished != usize::from(outcome == 0)
                || seen.parks != usize::from(outcome != 3)
                || seen.cpu != usize::from(matches!(outcome, 0 | 2))
                || frame.lock().bytes[48..] != payload
                || drops.load(Ordering::SeqCst) != 0
                || owner.phase()
                    != if outcome == 0 {
                        Phase::Calibrated
                    } else {
                        Phase::Failed
                    }
            {
                return TestResult::Fail("C22 actual backend failed park/disarm order, terminal state or retained mappings");
            }
        }
        if outcome == 0 && (ring.lock().bytes != [0; 16] || frame.lock().bytes[..48] != [0; 48]) {
            return TestResult::Fail(
                "C22 successful radio did not disarm completed beacon descriptors",
            );
        }
        if outcome != 3 {
            let before = {
                let m = seen.lock();
                (m.parks, m.cpu)
            };
            let result = owner.io.finish_radio(gate);
            let after = {
                let m = seen.lock();
                (m.parks, m.cpu)
            };
            if result != Err(Error::State) || after != before {
                return TestResult::Fail(
                    "terminal C22 backend reopened one-shot radio/disarm transition",
                );
            }
        }
        if narf_scheduler::block_on(owner.io.reserved_page(&[1])) != Err(Error::State)
            || narf_scheduler::block_on(owner.prepare_radio_with_policy(
                &factory,
                permission,
                || Ok(policy.clone()),
            )) != Err(Error::State)
        {
            return TestResult::Fail(
                "C22 continued/terminal backend admitted firmware or radio replay",
            );
        }
        drop(owner);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail(
                "C22 completed/failed/cancelled actual backend freed published DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_actual_reserved_backend_composes_radio_park_disarm_and_failures
);
