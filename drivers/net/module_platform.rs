//! Runtime used by the wired drivers' shared hardware code. Module DMA
//! carries separate CPU and bus addresses; neither may stand in for the other.

#[cfg(feature = "builtin")]
pub use narf_bus::{map_bar, BusDevice, MmioRegion};
#[cfg(feature = "builtin")]
pub use narf_io::DmaBuffer;

#[cfg(feature = "builtin")]
pub fn alloc_dma(_device: &BusDevice, len: usize) -> Result<DmaBuffer, ()> {
    narf_io::alloc_coherent(len, narf_lib::id::DomainId::DRIVER_0).map_err(|_| ())
}

#[cfg(feature = "module")]
pub use module::*;

#[cfg(feature = "module")]
#[allow(dead_code)] // Each chip uses a different subset of this shared platform.
mod module {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};

    pub use narf_module_rt::sync::SpinLock as Lock;

    pub mod ffi {
        unsafe extern "C" {
            pub fn narf_register_pci_driver(
                name: *const u8,
                len: usize,
                vendor: u16,
                device: u16,
                probe: usize,
            ) -> i32;
            pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
            pub fn narf_pci_prepare_probe(dev: u64) -> i32;
            pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out: *mut u16) -> i32;
            pub fn narf_bar_map_control(dev: u64, bar: u8) -> u64;
            pub fn narf_mmio_read8(dev: u64, bar: u64, off: u64, out: *mut u8) -> i32;
            pub fn narf_mmio_read16(dev: u64, bar: u64, off: u64, out: *mut u16) -> i32;
            pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
            pub fn narf_mmio_write8(dev: u64, bar: u64, off: u64, val: u8) -> i32;
            pub fn narf_mmio_write16(dev: u64, bar: u64, off: u64, val: u16) -> i32;
            pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
            pub fn narf_dma_alloc_mapped(
                dev: u64,
                len: usize,
                bits: u32,
                cpu: *mut usize,
                bus: *mut u64,
                reserved: *mut usize,
            ) -> u64;
            pub fn narf_dma_free(dev: u64, handle: u64) -> i32;
            pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
            pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
            pub fn narf_netif_register_with_context(
                dev: u64,
                mac: *const u8,
                tx: usize,
                ifindex: *mut u32,
            ) -> i32;
            pub fn narf_netif_set_link(dev: u64, ifindex: u32, carrier: u32) -> i32;
            pub fn narf_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32;
            pub fn narf_udelay(ns: u64) -> i32;
            pub fn narf_firmware_open(
                name: *const u8,
                len: usize,
                handle: *mut u64,
                size: *mut usize,
            ) -> i32;
            pub fn narf_firmware_read(
                handle: u64,
                off: u64,
                buf: *mut u8,
                len: usize,
                copied: *mut usize,
            ) -> i32;
            pub fn narf_firmware_close(handle: u64) -> i32;
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct BusDevice {
        pub token: u64,
        pub vendor: u16,
        pub device: u16,
    }

    impl BusDevice {
        pub fn from_token(token: u64) -> Result<Self, i32> {
            let mut id = [0u8; 16];
            // SAFETY: the KABI validates the token and writes this local record.
            result(unsafe { ffi::narf_pci_identity(token, id.as_mut_ptr(), id.len()) })?;
            Ok(Self {
                token,
                vendor: u16::from_le_bytes([id[0], id[1]]),
                device: u16::from_le_bytes([id[2], id[3]]),
            })
        }

        pub fn prepare(&self) -> Result<(), i32> {
            // SAFETY: token was supplied to this module's probe; KABI checks ownership.
            result(unsafe { ffi::narf_pci_prepare_probe(self.token) })?;
            // A timeout does not prove DMA quiescence. Keep mappings pinned on
            // failed probe/unload until a real reset-and-drain path exists.
            // SAFETY: device token belongs to this probe; KABI checks its live grant.
            result(unsafe { ffi::narf_dma_retain_on_teardown(self.token, 1) })
        }

        pub fn enable(&self) -> Result<(), i32> {
            let mut command = 0;
            // SAFETY: output is live and the KABI checks device authority.
            result(unsafe { ffi::narf_pci_command(self.token, 0, 0x406, &mut command) })?;
            if command & 0x406 == 0x406 {
                Ok(())
            } else {
                Err(-5)
            }
        }
    }

    pub fn result(rc: i32) -> Result<(), i32> {
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }

    #[derive(Debug)]
    pub struct MmioRegion {
        dev: u64,
        bar: u64,
        failed: AtomicBool,
    }

    macro_rules! access {
        ($read:ident, $write:ident, $ty:ty, $ffi_read:ident, $ffi_write:ident) => {
            /// # Safety
            /// The offset names a register of the documented width.
            pub unsafe fn $read(&self, off: u64) -> $ty {
                let mut value = <$ty>::MAX;
                // SAFETY: local output; kernel validates ownership, alignment and bounds.
                if unsafe { ffi::$ffi_read(self.dev, self.bar, off, &mut value) } != 0 {
                    self.failed.store(true, Ordering::Release);
                }
                value
            }
            /// # Safety
            /// The offset names a writable register of the documented width.
            pub unsafe fn $write(&self, off: u64, value: $ty) {
                // SAFETY: kernel validates ownership, alignment and bounds.
                if unsafe { ffi::$ffi_write(self.dev, self.bar, off, value) } != 0 {
                    self.failed.store(true, Ordering::Release);
                }
            }
        };
    }

    impl MmioRegion {
        access!(read8, write8, u8, narf_mmio_read8, narf_mmio_write8);
        access!(read16, write16, u16, narf_mmio_read16, narf_mmio_write16);
        access!(read32, write32, u32, narf_mmio_read32, narf_mmio_write32);
        pub fn failed(&self) -> bool {
            self.failed.load(Ordering::Acquire)
        }
    }

    /// # Safety
    /// The caller owns the device throughout hardware initialization.
    pub unsafe fn map_bar(device: &BusDevice, index: u8) -> Result<MmioRegion, ()> {
        // SAFETY: the KABI sizes/maps the BAR while decode is disabled.
        let bar = unsafe { ffi::narf_bar_map_control(device.token, index) };
        if bar == 0 {
            return Err(());
        }
        Ok(MmioRegion {
            dev: device.token,
            bar,
            failed: AtomicBool::new(false),
        })
    }

    #[derive(Clone, Copy, Debug)]
    pub struct DmaAddr(u64);
    impl DmaAddr {
        pub fn raw(self) -> u64 {
            self.0
        }
    }

    #[derive(Debug)]
    pub struct DmaBuffer {
        dev: u64,
        handle: u64,
        cpu: usize,
        bus: u64,
        len: usize,
    }

    pub fn alloc_dma(device: &BusDevice, len: usize) -> Result<DmaBuffer, ()> {
        let (mut cpu, mut bus, mut reserved) = (0, 0, 0);
        // SAFETY: writable outputs; KABI owns allocation and IOMMU mapping.
        let handle = unsafe {
            ffi::narf_dma_alloc_mapped(device.token, len, 64, &mut cpu, &mut bus, &mut reserved)
        };
        if handle == 0 || cpu == 0 || reserved < len {
            return Err(());
        }
        Ok(DmaBuffer {
            dev: device.token,
            handle,
            cpu,
            bus,
            len,
        })
    }

    impl DmaBuffer {
        pub fn dma_addr(&self) -> DmaAddr {
            DmaAddr(self.bus)
        }
        pub fn dma_addr_at(&self, off: u64) -> DmaAddr {
            assert!(off < self.len as u64);
            DmaAddr(self.bus + off)
        }
        pub fn cpu_ptr<T>(&self) -> *const T {
            self.cpu as *const T
        }
        pub fn cpu_ptr_at<T>(&self, off: u64) -> *const T {
            assert!(off <= self.len as u64 && core::mem::size_of::<T>() <= self.len - off as usize);
            (self.cpu + off as usize) as *const T
        }
        pub fn cpu_mut_ptr_at<T>(&self, off: u64) -> *mut T {
            self.cpu_ptr_at::<T>(off) as *mut T
        }
        pub fn free_completed(self) {
            // SAFETY: caller only uses this for a mailbox whose command completed.
            let _ = unsafe { ffi::narf_dma_free(self.dev, self.handle) };
        }
    }
    // No Drop: firmware may retain addresses even after failed probe. The
    // kernel context retains mappings on teardown. Completed mailboxes alone
    // may use free_completed; rings/ICM are not freed without a reset proof.

    pub mod time {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct Deadline(narf_module_rt::time::Deadline);
        impl Deadline {
            pub fn after_ms(ms: u64) -> Self {
                Self(narf_module_rt::time::Deadline::after_ms(ms))
            }
            pub fn after_us(us: u64) -> Self {
                Self(narf_module_rt::time::Deadline::after_ns(
                    us.saturating_mul(1000),
                ))
            }
            pub fn expired(self) -> bool {
                self.0.expired()
            }
        }
    }
    pub mod scheduler {
        use super::{ffi, time::Deadline};
        pub fn responsive_spin_until(mut done: impl FnMut() -> bool, deadline: Deadline) -> bool {
            loop {
                if done() {
                    return true;
                }
                if deadline.expired() {
                    return done();
                }
                // SAFETY: bounded 1 us delay also services the kernel's sleep pumps.
                let _ = unsafe { ffi::narf_udelay(1_000) };
            }
        }
    }
    pub mod console {
        pub use narf_module_rt::console::Console as Writer;
    }

    /// Read exactly the reported size; no fixed 4 KiB/64 KiB firmware buffer.
    pub fn firmware(name: &str) -> Result<Vec<u8>, i32> {
        let (mut handle, mut size) = (0, 0);
        // SAFETY: name and both outputs live through the call.
        result(unsafe {
            ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size)
        })?;
        let read = (|| {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(size).map_err(|_| -12)?;
            bytes.resize(size, 0);
            let mut offset = 0;
            while offset < size {
                let mut copied = 0;
                let chunk = (size - offset).min(64 * 1024);
                // SAFETY: selected chunk is within the allocated byte vector.
                result(unsafe {
                    ffi::narf_firmware_read(
                        handle,
                        offset as u64,
                        bytes.as_mut_ptr().add(offset),
                        chunk,
                        &mut copied,
                    )
                })?;
                if copied == 0 || copied > chunk {
                    return Err(-5);
                }
                offset += copied;
            }
            Ok(bytes)
        })();
        // SAFETY: close exactly the handle opened above, including on allocation/read failure.
        let _ = unsafe { ffi::narf_firmware_close(handle) };
        read
    }

    // Internal TX metadata for the shared Realtek descriptor builders. The
    // module ABI carries complete software-checksummed frames, so its entry
    // point always requests plain(). These types never cross the KABI.
    pub mod net {
        #[derive(Clone, Copy, Debug)]
        pub enum L4CsumKind {
            Tcp,
            Udp,
            Sctp,
        }
        #[derive(Clone, Copy, Debug, Default)]
        pub struct TxMeta {
            pub csum_l4: Option<L4CsumKind>,
            pub tso_mss: Option<u16>,
            pub vlan_tag: Option<u16>,
        }
        impl TxMeta {
            pub fn plain() -> Self {
                Self::default()
            }
        }
    }
}

#[cfg(feature = "module")]
pub mod network {
    use super::{ffi, result, BusDevice, Lock};
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicBool, Ordering};

    pub trait Nic: Send + Sync {
        fn transmit(&self, frame: &[u8]) -> Result<(), i32>;
        fn poll(&self);
        fn link_up(&self) -> bool;
        fn failed(&self) -> bool;
    }
    struct Bound {
        token: u64,
        ifindex: u32,
        nic: Arc<dyn Nic>,
        polling: AtomicBool,
        transmitting: AtomicBool,
    }
    static DEVICES: Lock<Vec<Arc<Bound>>> = Lock::new(Vec::new());
    fn lookup(token: u64) -> Option<Arc<Bound>> {
        DEVICES.lock().iter().find(|d| d.token == token).cloned()
    }
    struct Busy<'a>(&'a AtomicBool);
    impl Drop for Busy<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    fn enter(flag: &AtomicBool) -> Option<Busy<'_>> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Busy(flag))
    }
    pub fn publish(device: BusDevice, mac: [u8; 6], nic: Arc<dyn Nic>) -> Result<(), i32> {
        if mac == [0; 6] || mac[0] & 1 != 0 || nic.failed() {
            return Err(-5);
        }
        let mut ifindex = 0;
        // SAFETY: live MAC/output, static callbacks. Kernel removes callbacks
        // and drains their upcalls before unloading the module text.
        result(unsafe {
            ffi::narf_netif_register_with_context(
                device.token,
                mac.as_ptr(),
                tx as *const () as usize,
                &mut ifindex,
            )
        })?;
        // SAFETY: newly registered interface belongs to this device grant.
        result(unsafe {
            ffi::narf_netif_set_link(device.token, ifindex, u32::from(nic.link_up()))
        })?;
        DEVICES.lock().push(Arc::new(Bound {
            token: device.token,
            ifindex,
            nic,
            polling: AtomicBool::new(false),
            transmitting: AtomicBool::new(false),
        }));
        // SAFETY: static poll callback and device token remain valid until the kernel drains upcalls.
        result(unsafe {
            ffi::narf_spawn_poller(device.token, poll as *const () as usize, device.token)
        })
    }
    extern "C" fn tx(token: u64, frame: *const u8, len: usize) -> i32 {
        if frame.is_null() || !(14..=1514).contains(&len) {
            return -22;
        }
        let Some(device) = lookup(token) else {
            return -19;
        };
        let Some(_busy) = enter(&device.transmitting) else {
            return -11;
        };
        if device.nic.failed() {
            return -5;
        }
        if !device.nic.link_up() {
            return -100;
        }
        // SAFETY: KABI TX callback supplies exactly len readable bytes.
        match device
            .nic
            // SAFETY: the synchronous TX upcall supplies len readable bytes for this call.
            .transmit(unsafe { core::slice::from_raw_parts(frame, len) })
        {
            Ok(()) => 0,
            Err(error) => error,
        }
    }
    extern "C" fn poll(token: u64) -> i32 {
        let Some(device) = lookup(token) else {
            return -19;
        };
        let Some(_busy) = enter(&device.polling) else {
            return 0;
        };
        if device.nic.failed() {
            // SAFETY: owner/device/ifindex are validated by the KABI.
            let _ = unsafe { ffi::narf_netif_set_link(token, device.ifindex, 0) };
            return -5;
        }
        device.nic.poll();
        // SAFETY: KABI validates the interface against this device and owner.
        let _ = unsafe {
            ffi::narf_netif_set_link(token, device.ifindex, u32::from(device.nic.link_up()))
        };
        0
    }
    pub fn deliver(token: u64, frame: &mut [u8]) {
        let Some(device) = lookup(token) else {
            return;
        };
        // SAFETY: frame is live and writable throughout the synchronous copy.
        let _ =
            unsafe { ffi::narf_netif_rx(token, device.ifindex, frame.as_mut_ptr(), frame.len()) };
    }
}
