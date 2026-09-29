//! AX210/Bz/Sc MSI-X routing and interrupt lifetime.
//! Linux iwl-csr.h and pcie/gen1_2/trans.c: RX IVAR is separate from
//! non-RX IVAR; bit 7 means NON_AUTO_CLEAR, not "valid". RX queue 0
//! and non-RX table entries use slots 0/1, delivered to one host vector.

use super::transport::IwlMmio;
use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use narf_lib::sync::IrqSafeSpinLock;

pub const CSR_MSIX_FH_INT_CAUSES_AD: u32 = 0x2800;
pub const CSR_MSIX_FH_INT_MASK_AD: u32 = 0x2804;
pub const CSR_MSIX_HW_INT_CAUSES_AD: u32 = 0x2808;
pub const CSR_MSIX_HW_INT_MASK_AD: u32 = 0x280c;
pub const CSR_MSIX_AUTOMASK_ST_AD: u32 = 0x2810;
pub const CSR_MSIX_RX_IVAR_AD_REG: u32 = 0x2880;
pub const CSR_MSIX_IVAR_AD_REG: u32 = 0x2890;
pub const VECTOR_RX_ALIVE: u8 = 0;
pub const VECTOR_TX: u8 = 1;
// Retained for the separate Gen2 probe's table reservation.
pub const VECTOR_ERR: u8 = 2;
const FH_ENABLED: u32 = 1 | (1 << 16) | (1 << 17) | (1 << 19) | (1 << 21);
const HW_COMMON: u32 =
    0xf | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 26) | (1 << 27) | (1 << 29) | (1 << 30);

pub fn set_ivar(mmio: &mut impl IwlMmio, base: u32, index: u8, vector: u8) {
    let offset = base + u32::from(index & !3);
    let shift = u32::from(index & 3) * 8;
    let old = mmio.read(offset);
    mmio.write(
        offset,
        (old & !(0xff << shift)) | (u32::from(vector | 0x80) << shift),
    );
}

pub fn program_default_causes(mmio: &mut impl IwlMmio) {
    configure(mmio, false);
}

fn configure(mmio: &mut impl IwlMmio, bz: bool) {
    mask(mmio);
    mmio.write(CSR_MSIX_FH_INT_CAUSES_AD, u32::MAX);
    mmio.write(CSR_MSIX_HW_INT_CAUSES_AD, u32::MAX);
    set_ivar(mmio, CSR_MSIX_RX_IVAR_AD_REG, 0, 0);
    for bit in [16, 17, 19, 21] {
        set_ivar(mmio, CSR_MSIX_IVAR_AD_REG, bit - 16, 1);
    }
    let hw = HW_COMMON | (1 << if bz { 5 } else { 25 });
    for bit in 0..32 {
        if hw & (1 << bit) != 0 {
            set_ivar(mmio, CSR_MSIX_IVAR_AD_REG, bit + 16, 1);
        }
    }
    mmio.write(CSR_MSIX_FH_INT_MASK_AD, !FH_ENABLED);
    mmio.write(CSR_MSIX_HW_INT_MASK_AD, !hw);
    mmio.write(CSR_MSIX_AUTOMASK_ST_AD, 3);
}

fn mask(mmio: &mut impl IwlMmio) {
    mmio.write(CSR_MSIX_FH_INT_MASK_AD, u32::MAX);
    mmio.write(CSR_MSIX_HW_INT_MASK_AD, u32::MAX);
    let _ = mmio.read(CSR_MSIX_HW_INT_MASK_AD);
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Causes {
    pub fh: u32,
    pub hw: u32,
}
impl Causes {
    pub fn fatal(self, bz: bool) -> bool {
        self.fh == u32::MAX
            || self.hw == u32::MAX
            || self.fh & (1 << 21) != 0
            || self.hw & ((1 << 3) | (1 << 6) | (1 << 29) | (1 << if bz { 5 } else { 25 })) != 0
    }
}

fn acknowledge(mmio: &mut impl IwlMmio) -> Causes {
    let causes = Causes {
        fh: mmio.read(CSR_MSIX_FH_INT_CAUSES_AD),
        hw: mmio.read(CSR_MSIX_HW_INT_CAUSES_AD),
    };
    if causes.fh != u32::MAX && causes.hw != u32::MAX {
        mmio.write(CSR_MSIX_FH_INT_CAUSES_AD, causes.fh);
        mmio.write(CSR_MSIX_HW_INT_CAUSES_AD, causes.hw);
        mmio.write(CSR_MSIX_AUTOMASK_ST_AD, 3);
    }
    causes
}

struct Shared {
    mmio: super::IwlMmioImpl,
    pending: Causes,
}

/// Owns the handler cookie until device delivery is disabled and handlers
/// are synchronized. The hard IRQ only acknowledges/latches causes; all
/// DMA processing stays in the driver task.
pub struct Interrupts {
    table: narf_bus::MsixTable,
    vector: u8,
    shared: Box<IrqSafeSpinLock<Shared>>,
}
impl core::fmt::Debug for Interrupts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlInterrupts")
            .field("vector", &self.vector)
            .finish_non_exhaustive()
    }
}
fn handler(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    // SAFETY: Interrupts owns this stable Box until disable + synchronize.
    let shared = unsafe { &*(cookie as *const IrqSafeSpinLock<Shared>) };
    let mut state = shared.lock();
    let causes = acknowledge(&mut state.mmio);
    state.pending.fh |= causes.fh;
    state.pending.hw |= causes.hw;
    if causes.fh | causes.hw != 0 {
        narf_interrupts::dispatch::IrqStatus::Handled
    } else {
        narf_interrupts::dispatch::IrqStatus::None
    }
}
impl Interrupts {
    pub fn new(
        cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: &narf_bus::BusDevice,
        region: narf_bus::MmioRegion,
    ) -> Result<Self, &'static str> {
        if region.len < 0x28c0 {
            return Err("Wi-Fi BAR is too short for MSI-X");
        }
        let mut table =
            narf_bus::enable_msix(cap, device).map_err(|_| "Wi-Fi has no MSI-X table")?;
        table
            .alloc_block(2)
            .map_err(|_| "Wi-Fi MSI-X table too small")?;
        // SAFETY: the claimed device is not running, and no handler is live.
        unsafe {
            table.disable();
        }
        let vector = narf_interrupts::vector::alloc().map_err(|_| "no Wi-Fi IRQ vector")?;
        narf_interrupts::dispatch::enable_irq(vector);
        let shared = Box::new(IrqSafeSpinLock::new(Shared {
            mmio: super::IwlMmioImpl(region),
            pending: Causes::default(),
        }));
        mask(&mut shared.lock().mmio);
        let cookie = (&*shared as *const IrqSafeSpinLock<Shared>) as u64;
        narf_interrupts::dispatch::install_handler_named(vector, "iwlwifi", cookie, handler);
        let mut this = Self {
            table,
            vector,
            shared,
        };
        // SAFETY: both entries were reserved; this object owns cfg/table.
        unsafe {
            for slot in 0..2 {
                this.table
                    .program_vector(slot, 0, vector)
                    .map_err(|_| "cannot route Wi-Fi MSI-X")?;
            }
        }
        Ok(this)
    }

    pub fn enable(&mut self, bz: bool) -> Result<(), &'static str> {
        {
            let mut state = self.shared.lock();
            state.pending = Causes::default();
            configure(&mut state.mmio, bz);
        }
        // SAFETY: both table entries and the handler exist before delivery.
        unsafe { self.table.enable().map_err(|_| "cannot enable Wi-Fi MSI-X") }
    }
    pub fn mask(&mut self) {
        mask(&mut self.shared.lock().mmio);
        // SAFETY: exclusive device ownership; cookie remains live.
        unsafe {
            self.table.disable();
        }
    }
    pub fn take_causes(&self) -> Causes {
        let mut state = self.shared.lock();
        let fresh = acknowledge(&mut state.mmio);
        let pending = core::mem::take(&mut state.pending);
        Causes {
            fh: fresh.fh | pending.fh,
            hw: fresh.hw | pending.hw,
        }
    }
    pub fn vector(&self) -> u8 {
        self.vector
    }
}
impl Drop for Interrupts {
    fn drop(&mut self) {
        self.mask();
        narf_interrupts::dispatch::disable_irq(self.vector);
        let cookie = (&*self.shared as *const IrqSafeSpinLock<Shared>) as u64;
        narf_interrupts::dispatch::remove_handler(self.vector, "iwlwifi", cookie);
        narf_interrupts::dispatch::synchronize_irq(self.vector);
        let _ = narf_interrupts::vector::free(self.vector);
    }
}

/// Construct BEFORE inspecting rings, so completion between drain and await
/// cannot be lost. The timer also bounds waits for lost interrupts/recovery.
#[derive(Debug)]
pub struct Activity {
    irq: Option<narf_interrupts::wait::WaitForIrq>,
    timer: narf_time::SleepUntil,
}
impl Activity {
    pub fn new(vector: Option<u8>, max_ms: u64) -> Self {
        Self {
            irq: vector.map(narf_interrupts::wait::wait_for_irq),
            timer: narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                if vector.is_some() { max_ms } else { 1 } * 1_000_000,
            )),
        }
    }
}
impl Future for Activity {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(irq) = self.irq.as_mut() {
            if Pin::new(irq).poll(cx).is_ready() {
                return Poll::Ready(());
            }
        }
        Pin::new(&mut self.timer).poll(cx)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    #[derive(Default)]
    struct Mmio(alloc::collections::BTreeMap<u32, u32>);
    impl IwlMmio for Mmio {
        fn read(&mut self, off: u32) -> u32 {
            *self.0.get(&off).unwrap_or(&0)
        }
        fn write(&mut self, off: u32, value: u32) {
            self.0.insert(off, value);
        }
    }
    fn smoke_msix_real_offsets_and_bz_causes() -> TestResult {
        let mut m = Mmio::default();
        configure(&mut m, true);
        if m.read(0x2880) & 0xff != 0x80
            || m.read(0x2890) & 0xffff != 0x8181
            || m.read(0x28a4) & 0xff00 != 0x8100
            || m.read(0x2804) != !0x002b0001
            || m.read(0x280c) & (1 << 5) != 0
            || m.read(0x280c) & (1 << 25) == 0
        {
            return TestResult::Fail("MSI-X routing differs from AX210/Bz register map");
        }
        if !(Causes { fh: 0, hw: 1 << 5 }).fatal(true)
            || (Causes { fh: 0, hw: 1 << 5 }).fatal(false)
        {
            return TestResult::Fail("firmware error cause generation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/msix",
        smoke_msix_real_offsets_and_bz_causes
    );
    fn smoke_msix_completion_before_wait_poll() -> TestResult {
        let vector = narf_interrupts::vector::alloc().expect("test IRQ vector");
        narf_interrupts::dispatch::enable_irq(vector);
        let mut activity = Activity::new(Some(vector), 10_000);
        // Device completion arrives after the ring was inspected, before
        // the driver first polls its wait. It must not sleep until timeout.
        narf_interrupts::dispatch::on_irq(vector);
        let mut cx = Context::from_waker(core::task::Waker::noop());
        let ready = Pin::new(&mut activity).poll(&mut cx).is_ready();
        drop(activity);
        let _ = narf_interrupts::vector::free(vector);
        if !ready {
            return TestResult::Fail("completion before wait poll was lost");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/msix",
        smoke_msix_completion_before_wait_poll
    );

    fn smoke_msix_w1c_and_rearm() -> TestResult {
        struct W1c {
            fh: u32,
            hw: u32,
            rearmed: u32,
        }
        impl IwlMmio for W1c {
            fn read(&mut self, off: u32) -> u32 {
                match off {
                    0x2800 => self.fh,
                    0x2808 => self.hw,
                    _ => 0,
                }
            }
            fn write(&mut self, off: u32, value: u32) {
                match off {
                    0x2800 => self.fh &= !value,
                    0x2808 => self.hw &= !value,
                    0x2810 => self.rearmed |= value,
                    _ => {}
                }
            }
        }
        let mut m = W1c {
            fh: 1,
            hw: 1 << 5,
            rearmed: 0,
        };
        let causes = acknowledge(&mut m);
        if causes.fh != 1 || !causes.fatal(true) || m.fh != 0 || m.hw != 0 || m.rearmed != 3 {
            return TestResult::Fail("RX/error acknowledgement failed to rearm both entries");
        }
        let empty = acknowledge(&mut m);
        if empty.fh != 0 || empty.hw != 0 {
            return TestResult::Fail("stale cause replayed");
        }
        m.fh = u32::MAX;
        m.rearmed = 0;
        if !acknowledge(&mut m).fatal(true) || m.rearmed != 0 {
            return TestResult::Fail("disappeared device rearmed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi/msix", smoke_msix_w1c_and_rearm);
}
