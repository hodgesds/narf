//! ConnectX-3 module: the built-in firmware and queue engine over the KABI.
use crate::{
    mlx4,
    platform::{ffi, network, BusDevice},
};
use alloc::sync::Arc;

struct Nic(Arc<mlx4::Mlx4Eth>);
impl network::Nic for Nic {
    fn transmit(&self, frame: &[u8]) -> Result<(), i32> {
        self.0.transmit(frame).map_err(|_| -11)
    }
    fn poll(&self) {
        self.0.drain_datapath(64);
        self.0.poll_link();
    }
    fn link_up(&self) -> bool {
        self.0.nic_state().link_up
    }
    fn failed(&self) -> bool {
        self.0.module_access_failed()
    }
}
pub fn deliver(token: u64, frame: &mut [u8]) {
    network::deliver(token, frame);
}
extern "C" fn probe(token: u64, _reserved: u64) -> i32 {
    match bring_up(token) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
fn bring_up(token: u64) -> Result<(), i32> {
    let device = BusDevice::from_token(token)?;
    if device.vendor != 0x15b3 || ![0x1003, 0x1007].contains(&device.device) {
        return Err(-19);
    }
    device.prepare()?;
    // SAFETY: this probe owns the device context and all BAR/DMA grants.
    let controller = unsafe { mlx4::Mlx4Eth::bring_up(&device) }.map_err(|_| -5)?;
    let mac = controller.nic_state().mac;
    network::publish(device, mac, Arc::new(Nic(controller)))
}
pub fn register() -> i32 {
    for (id, name) in [
        (0x1003, b"mlx4-connectx3".as_slice()),
        (0x1007, b"mlx4-connectx3-pro".as_slice()),
    ] {
        // SAFETY: static match name and callback; kernel owns match lifetime.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                name.as_ptr(),
                name.len(),
                0x15b3,
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
