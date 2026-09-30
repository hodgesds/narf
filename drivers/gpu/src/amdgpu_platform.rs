//! Boot handoff for the DCN314 display owner. Firmware reservations come from
//! ATOM; live scanouts and cursors are inventoried before allocating VRAM.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dmub::Firmware,
    amdgpu_dmub_boot::{Error, Loader},
    amdgpu_vram::Pool,
};
use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;

static BOOT_FB: IrqSafeSpinLock<Option<narf_graphics_driver::generic::GenericFb>> =
    IrqSafeSpinLock::new(None);
/// Record the physical boot framebuffer before fbdev replaces its address with
/// a virtual mapping. Recording geometry performs no GPU access or allocation.
pub fn record_boot_framebuffer(fb: narf_graphics_driver::generic::GenericFb) {
    let mut saved = BOOT_FB.lock();
    if saved.is_none() {
        *saved = Some(fb);
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
struct CopyToc;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyToc {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| Error::Invalid)?;
            crate::amdgpu_psp_ring::toc_payload(view.bytes).map_err(Error::Psp)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
struct OpenToc;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenToc {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open("amdgpu/psp_13_0_4_toc.bin", cap) {
            Ok(blob) => blob,
            Err(_) => return Ok(Err(Error::Invalid)),
        };
        blob.invoke(CopyToc)
    }
}

/// Production boot has not initialized GFX/GART or other driver VRAM clients.
/// Reject live VM contexts rather than guessing the size of inherited tables.
fn inventory(gpu: &AmdGpu, cap: &Cap<BusDeviceCap, Write>) -> Result<Vec<Range<u64>>, Error> {
    use crate::amdgpu_discovery as ip;
    let dcn = crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_DCN, &[(3, 1, 4)], 2, 0x90f)
        .map_err(Error::Psp)?;
    let gc = crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_GC, &[(11, 0, 1), (11, 0, 4)], 0, 0x1697)
        .map_err(Error::Psp)?;
    let hub = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_MMHUB,
        &[(3, 0, 0), (3, 0, 1), (3, 0, 2)],
        0,
        0x74f,
    )
    .map_err(Error::Psp)?;
    if gpu.fw_loaded || gpu.mode.is_some() {
        return Err(Error::Busy);
    }
    cap.invoke(Op(|| {
        for (base, first) in [(gc, 0x1688), (hub, 0x740)] {
            for index in 0..16 {
                // SAFETY: exact IP bank and entire context array bounded above.
                let value = unsafe { gpu.regs.read32(base + (first + index) * 4) };
                if value == u32::MAX || value & 1 != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        // SAFETY: bank validation bounds all four HUBP/cursor instances.
        scan_surfaces(|reg| unsafe { gpu.regs.read32(dcn + reg as u64 * 4) })
    }))
    .map_err(|_| Error::Revoked)?
}
fn scan_surfaces(mut read: impl FnMut(u32) -> u32) -> Result<Vec<Range<u64>>, Error> {
    let mut ranges = Vec::new();
    let mut read = |reg| {
        let v = read(reg);
        if v == u32::MAX {
            Err(Error::Invalid)
        } else {
            Ok(v)
        }
    };
    for index in 0..4 {
        let delta = index * 0xdc;
        if read(0x5f3 + delta)? & 1 == 0 {
            // Only packed, linear RGB is a bounded inherited scanout here.
            // Reject DCC/YUV/stereo/VM surfaces instead of overlooking metadata.
            let format = read(0x5e5 + delta)? & 0x7f;
            let bpp = match format {
                1 | 3 => 2,
                8 | 10 => 4,
                24 | 26 => 8,
                _ => return Err(Error::Unsupported),
            };
            if read(0x5e7 + delta)? & 0x1f != 0
                || read(0x61a + delta)? & 0x303 != 0
                || read(0x609 + delta)? & 0xf != 0
            {
                return Err(Error::Unsupported);
            }
            let viewport = read(0x5ea + delta)?;
            let start = read(0x5e9 + delta)?;
            let pitch = (read(0x607 + delta)? & 0x3fff) + 1;
            let rows = ((start >> 16) & 0x3fff) + ((viewport >> 16) & 0x3fff);
            if rows == 0
                || (viewport & 0x3fff) == 0
                || (start & 0x3fff) + (viewport & 0x3fff) > pitch
            {
                return Err(Error::Invalid);
            }
            let size = pitch as u64 * rows as u64 * bpp;
            // Include programmed, latched and earliest-in-use surfaces: a
            // boot-time flip can still be draining its previous allocation.
            let before = ranges.len();
            for reg in [0x60a, 0x60e, 0x621, 0x625] {
                let low = read(reg + delta)?;
                let high = read(reg + 1 + delta)?;
                if high & !0xffff != 0 {
                    return Err(Error::Invalid);
                }
                let address = low as u64 | (high as u64) << 32;
                if address != 0 {
                    ranges.push(address..address.checked_add(size).ok_or(Error::Invalid)?);
                }
            }
            if ranges.len() == before {
                return Err(Error::Invalid);
            }
        }
        let control = read(0x678 + delta)?;
        if control & 1 != 0 {
            let mode = (control >> 8) & 7;
            if !matches!(mode, 1..=3) || control & 0x1000 != 0 {
                return Err(Error::Unsupported);
            }
            let size = read(0x67b + delta)?;
            let rows = size & 0x1ff;
            let width = (size >> 16) & 0x1ff;
            let pitch = 64u64 << ((control >> 16) & 3);
            if rows == 0 || width == 0 || width as u64 > pitch || pitch > 256 {
                return Err(Error::Invalid);
            }
            let address = read(0x679 + delta)? as u64 | (read(0x67a + delta)? as u64) << 32;
            ranges.push(
                address
                    ..address
                        .checked_add(pitch * rows as u64 * 4)
                        .ok_or(Error::Invalid)?,
            );
        }
    }
    Ok(ranges)
}

/// Build the one platform display owner without issuing hardware writes.
/// Failure here permits retaining the pre-existing firmware attachment.
pub(crate) fn prepare() -> Result<(Loader, Arc<Pool>), Error> {
    let boot = BOOT_FB.lock().ok_or(Error::Invalid)?;
    let size = (boot.pitch as u64)
        .checked_mul(boot.height as u64)
        .filter(|n| *n != 0)
        .ok_or(Error::Invalid)?;
    let boot_range = boot.addr..boot.addr.checked_add(size).ok_or(Error::Invalid)?;
    let cap = crate::amdgpu::pci_authority().ok_or(Error::Revoked)?;
    let fw_cap: Cap<narf_firmware::FirmwareRegistry, Read> =
        narf_firmware::trusted_loader_authority()
            .ok_or(Error::Revoked)?
            .derive()
            .map_err(|_| Error::Revoked)?;
    let toc = fw_cap.invoke(OpenToc).map_err(|_| Error::Revoked)??;
    crate::amdgpu::with_controller(|gpu| {
        let firmware = Firmware::open(gpu, &fw_cap).map_err(Error::Firmware)?;
        let clients = inventory(gpu, &cap)?;
        // SAFETY: sole boot owner, no NARF clients have initialized; VM clients
        // are rejected and all live supported scanouts/cursors inventoried.
        let plan = unsafe { crate::amdgpu_vram_boot::Plan::read(gpu, &cap, boot_range, &clients) }
            .map_err(Error::Memory)?;
        // SAFETY: boot handoff owns the free VRAM; all subsequent display
        // clients share this pool. Firmware and boot surfaces remain excluded.
        let pool = Arc::new(unsafe { plan.into_pool() }.map_err(Error::Memory)?);
        // SAFETY: exact GPU, authenticated containers, lifetime mappings and
        // exclusive PSP/DMUB ownership are retained by the loader and pool.
        let loader = unsafe { Loader::new_psp(gpu, cap, &pool, &firmware, &toc) }?;
        Ok((loader, pool))
    })
    .ok_or(Error::Unsupported)?
}

struct Display {
    loader: Loader,
    // Every future scanout allocation must share this pool.
    _pool: Arc<Pool>,
}
static DISPLAY: narf_lib::mutex::Mutex<Option<Display>> = narf_lib::mutex::Mutex::new(None);

pub(crate) fn start() -> bool {
    let (loader, pool) = match prepare() {
        Ok(prepared) => prepared,
        Err(_) => return false,
    };
    let Some(mut owner) = DISPLAY.try_lock() else {
        return false;
    };
    if owner.is_some() {
        return false;
    }
    *owner = Some(Display {
        loader,
        _pool: pool,
    });
    drop(owner);
    crate::amdgpu_usbc::observe_connectors();
    narf_scheduler::spawn(async {
        {
            let mut guard = DISPLAY.lock().await;
            let display = guard.as_mut().unwrap();
            let result = async {
                display.loader.boot(Default::default()).await?;
                display.loader.enable_notifications().await
            }
            .await;
            if let Err(error) = result {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu-usbc: PSP/DMUB boot failed: {error:?}"
                );
                // Retain both the owner and busy phase after a partial boot.
                // No attach fallback can race an outstanding PSP command.
                return;
            }
        }
        crate::amdgpu_usbc::finish_cycle();
        loop {
            if crate::amdgpu_usbc::begin_cycle() {
                let result = {
                    let mut guard = DISPLAY.lock().await;
                    guard.as_mut().unwrap().loader.discover_sinks().await
                };
                match result {
                    Ok(found) => crate::amdgpu_usbc::publish_sinks(found),
                    Err(error) => {
                        use core::fmt::Write as _;
                        crate::amdgpu_usbc::publish_sinks(Vec::new());
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu-usbc: owned DMUB discovery failed: {error:?}"
                        );
                        return;
                    }
                }
                crate::amdgpu_usbc::finish_cycle();
            }
            crate::amdgpu_usbc::wait_for_rescan().await;
        }
    });
    true
}

/// Synchronous PM bridge. No IRQ-safe lock is held and the polled hardware
/// futures depend only on device completion/time, never another executor task.
pub(crate) fn suspend() -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(display) = guard.as_mut() else {
        return true;
    };
    if narf_scheduler::current_task_id().raw() != 0 {
        return false;
    }
    narf_scheduler::block_on_spin(display.loader.stop()).is_ok()
}
pub(crate) fn resume() -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(display) = guard.as_mut() else {
        return true;
    };
    if narf_scheduler::current_task_id().raw() != 0 {
        return false;
    }
    narf_scheduler::block_on_spin(async {
        display.loader.boot(Default::default()).await?;
        display.loader.enable_notifications().await
    })
    .is_ok()
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn registers() -> Vec<u32> {
        let mut regs = vec![0; 0x910];
        for index in 0..4 {
            regs[0x5f3 + index * 0xdc] = 1;
        }
        regs
    }
    fn platform_inventory_retains_latched_surfaces_and_cursor() -> TestResult {
        let mut regs = registers();
        regs[0x5f3] = 0;
        regs[0x5e5] = 8;
        regs[0x5ea] = (768 << 16) | 1024;
        regs[0x607] = 1023;
        for (offset, address) in [
            (0x60a, 0x12000000),
            (0x621, 0x14000000),
            (0x625, 0x16000000),
        ] {
            regs[offset] = address;
            regs[offset + 1] = 2;
        }
        regs[0x678] = 1 | (2 << 8) | (1 << 16);
        regs[0x679] = 0x18000000;
        regs[0x67a] = 2;
        regs[0x67b] = (128 << 16) | 64;
        let ranges = scan_surfaces(|r| regs[r as usize]).unwrap();
        if ranges
            != [
                0x2_12000000..0x2_12300000,
                0x2_14000000..0x2_14300000,
                0x2_16000000..0x2_16300000,
                0x2_18000000..0x2_18008000,
            ]
        {
            return TestResult::Fail("in-use surfaces/cursor missing from inventory");
        }
        for (offset, value) in [
            (0x5e7, 1),
            (0x61a, 2),
            (0x609, 1),
            (0x5e5, 65),
            (0x5f3, u32::MAX),
        ] {
            let previous = regs[offset];
            regs[offset] = value;
            if scan_surfaces(|r| regs[r as usize]).is_ok() {
                return TestResult::Fail("unsupported surface ownership accepted");
            }
            regs[offset] = previous;
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        platform_inventory_retains_latched_surfaces_and_cursor
    );
}
