//! RTL8125 module: the built-in hardware/PHY code over the device KABI.
use crate::{
    platform::{self, ffi, network, BusDevice},
    rtl8125,
};
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU8, Ordering};
struct Nic {
    device: BusDevice,
    controller: Arc<rtl8125::RtlNic>,
    // 0: waiting for firmware registry; 1: configured; 2: failed.
    state: AtomicU8,
    firmware_deadline: platform::time::Deadline,
    next_attempt: platform::Lock<Option<platform::time::Deadline>>,
}
impl network::Nic for Nic {
    fn transmit(&self, frame: &[u8]) -> Result<(), i32> {
        self.controller
            .transmit(frame, &platform::net::TxMeta::plain())
            .map_err(|_| -5)
    }
    fn poll(&self) {
        if self.state.load(Ordering::Acquire) == 0 {
            {
                let mut next = self.next_attempt.lock();
                if next.is_some_and(|d| !d.expired()) {
                    return;
                }
                *next = Some(platform::time::Deadline::after_ms(1000));
            }
            match self.controller.configure_module_phy() {
                Ok(()) => self.state.store(1, Ordering::Release),
                Err(-2 | -11 | -19) if !self.firmware_deadline.expired() => return,
                Err(error) => {
                    narf_module_rt::printkln!(
                        "rtl8125: firmware/PHY setup failed ({error}); interface remains down"
                    );
                    self.state.store(2, Ordering::Release);
                    return;
                }
            }
        }
        if self.state.load(Ordering::Acquire) != 1 {
            return;
        }
        // A per-callback bound prevents a continuously busy link starving boot.
        for _ in 0..64 {
            let Some(mut frame) = self.controller.receive() else {
                break;
            };
            // RTL8125 reports the four-byte Ethernet FCS in descriptor length.
            if frame.len() >= 18 {
                frame.truncate(frame.len() - 4);
                network::deliver(self.device.token, &mut frame);
            }
        }
    }
    fn link_up(&self) -> bool {
        self.state.load(Ordering::Acquire) == 1 && self.controller.phy_status() & 2 != 0
    }
    fn failed(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2 || self.controller.module_access_failed()
    }
}

extern "C" fn probe(token: u64, _reserved: u64) -> i32 {
    match bring_up(token) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
fn bring_up(token: u64) -> Result<(), i32> {
    let device = BusDevice::from_token(token)?;
    if device.vendor != 0x10ec || ![0x8125, 0x3000].contains(&device.device) {
        return Err(-19);
    }
    device.prepare()?;
    // SAFETY: this probe owns the device context and both DMA and BAR grants.
    let controller = unsafe { rtl8125::RtlNic::bring_up(&device) }.map_err(|_| -5)?;
    let mac = controller.mac;
    network::publish(
        device,
        mac,
        Arc::new(Nic {
            device,
            controller,
            state: AtomicU8::new(0),
            firmware_deadline: platform::time::Deadline::after_ms(60_000),
            next_attempt: platform::Lock::new(None),
        }),
    )
}

pub fn register() -> i32 {
    for (id, name) in [
        (0x8125, b"rtl8125".as_slice()),
        (0x3000, b"rtl8125b".as_slice()),
    ] {
        // SAFETY: static match name and callback; kernel owns match lifetime.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                name.as_ptr(),
                name.len(),
                0x10ec,
                id,
                probe as *const () as usize,
            )
        };
        if rc != 0 {
            return rc;
        }
    }
    0
}
