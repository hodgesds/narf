//! Actual Native/NativeIo publication and retained queue with explicit inert
//! authenticated-record/controller/RFK boundaries, as native RF tracking.
//! No real attach, hardware DMA, calibration or measurement is claimed.
use super::*;
use crate::rtw89::{
    lps::{Binding, Io as _},
    power, radio_policy,
    station_control::Admission,
};
use alloc::sync::Arc;
use narf_net::native_emission::ProviderLifetime;
struct LpsFixture(Fixture);
impl Drop for LpsFixture {
    fn drop(&mut self) {
        // SAFETY: same exclusively owned inert register/DMA RAM; no hardware
        // or prefetch, all actual Native calls/futures have ended.
        unsafe {
            self.0.native.receive.reclaim_fenced();
        }
    }
}
fn setup(
    effect: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (
    LpsFixture,
    Binding,
    ProviderLifetime,
    Admission,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
) {
    let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
    f.activate().unwrap();
    f.native.receive = crate::rtw89::rx_dma::tests::native_fixture();
    f.native.station_runtime.model_started();
    let (admission, peer) = crate::rtw89::lps::tests::peer();
    f.native.station_runtime.peer = Some(peer.clone());
    let (qualification, base, sleep) = radio_policy::tests::lps_model(effect);
    f.native.ordinary = Some(OrdinaryGrant {
        qualification: Arc::new(qualification),
    });
    let source = ProviderLifetime::new();
    let binding = Binding::new(peer, admission.clone(), source.observe(), 1).unwrap();
    (LpsFixture(f), binding, source, admission, base, sleep)
}
pub(in crate::rtw89) fn run() -> Result<(), &'static str> {
    for failure in 0..6 {
        let (mut f, binding, source, admission, base, sleep) = setup(None);
        let native = &mut f.0.native;
        match failure {
            1 => {
                sleep.revoke();
            }
            2 => {
                base.revoke();
            }
            3 => admission.close(),
            4 => source.retire().notify(),
            5 => native.station_runtime.peer = Some(crate::rtw89::lps::tests::peer().1),
            _ => {}
        }
        let result = native.sleep_port().write16(&binding, 0x10c0, 0x9005);
        if failure == 0 {
            if result.is_err() || f.0.words[0x10c0 / 4] & 0xffff != 0x9005 {
                return Err("actual Native original LPS source/RPWM publication");
            }
            native.sleep_block(true);
            if native.station_track_read(crate::rtw89::track::REGISTERS[0])
                != Err(power::Error::Terminal)
                || native.station_rf_tracking(&admission) != Err(power::Error::Terminal)
            {
                return Err("actual Native BB tracking bypassed closed wake/restore");
            }
        } else if result.is_ok()
            || f.0.words[0x10c0 / 4] & 0xffff != 0
            || native.queue.pending() != 0
        {
            return Err("actual Native borrowed lost original LPS program/peer/UP grant");
        }
    }
    let (mut f, binding, _source, _admission, _base, _sleep) = setup(None);
    let rx_idx = addr_set_for_chip(ChipId::Rtl8852B).rx[0].idx as usize;
    let doorbell = f.0.native.regs.idx as usize;
    let pointer = f.0.words.as_mut_ptr() as usize + rx_idx;
    let fired = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let record = fired.clone();
    let effect = Arc::new(move || {
        record.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        // SAFETY: private retained MMIO RAM, original real HCI producer
        // register, no aliased Rust reference or concurrent device. This
        // inert producer runs after all early prefixes and allocation.
        unsafe {
            (pointer as *mut u32).write_volatile(1 << 16);
        }
    });
    let (qualification, _, _) = radio_policy::tests::lps_model(Some(effect));
    f.0.native.ordinary = Some(OrdinaryGrant {
        qualification: Arc::new(qualification),
    });
    f.0.native.sleep_block(true);
    let ring = f.0.native.ring.as_ref().unwrap().as_slice().to_vec();
    let before = f.0.words[doorbell / 4];
    let result = narf_scheduler::block_on(f.0.native.runtime_command(
        1,
        2,
        0,
        &crate::rtw89::lps_wire::parameters(true),
        false,
        station::Permit::SleepEnter(&binding),
    ));
    if result != Err(power::Error::Busy)
        || fired.load(core::sync::atomic::Ordering::Acquire) == 0
        || f.0.native.state != State::Active
        || f.0.words[doorbell / 4] != before
        || f.0.native.ring.as_ref().unwrap().as_slice() != ring
        || f.0.native.queue.pending() != 0
        || f.0.native.queue.write_pointer() != 0
        || !f.0.native.queue.is_pristine()
    {
        return Err("actual final Native producer refusal lost Busy or changed issued/ring/doorbell ownership");
    }
    if f.0.native.sleep_port().pending(&binding) != Ok(true) {
        return Err("actual Native pending producer proof was metadata-only");
    }
    crate::rtw89::pci_reset::tests::lps_fence_boundary()?;
    Ok(())
}
