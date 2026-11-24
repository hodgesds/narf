//! Identity, plain MSI, ASPM and mapped-DMA bridges for module-owned PCI
//! functions, against a synthetic configuration space (`ecam::__test_windows`)
//! shaped like a WCN6855: vendor 17cb device 1103, subsystem 17aa:9309, an MSI
//! capability advertising 32 vectors, and a PCI Express capability with L1
//! enabled.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWNER: u64 = 0xffff_ffff_7411;
const TOKEN: u64 = 0xffff_ffff_7412;
const MSI_CAP: usize = 0x50;
const PCIE_CAP: usize = 0x80;
const LNKCTL: usize = PCIE_CAP + 0x10;

/// A synthetic function and its config-space address; the config words stay
/// owned by the caller.
fn function(words: &mut [u32]) -> (BusDevice, narf_memory::PhysAddr) {
    // Status bit 4: capability list present. Revision 0x01, class 0x028000.
    words[1] = 0x0010_0000;
    words[0x08 / 4] = 0x0280_0001;
    words[0x34 / 4] = MSI_CAP as u32;
    // MSI: id 0x05, next PCIE_CAP, Message Control = 64-bit, MMC = 5 (32).
    words[MSI_CAP / 4] = 0x05 | ((PCIE_CAP as u32) << 8) | (0x008a << 16);
    // PCI Express: id 0x10, end of list. Link Control: ASPM = L1, plus an
    // unrelated bit that must survive the field update.
    words[PCIE_CAP / 4] = 0x10;
    words[LNKCTL / 4] = 0x0000_0042;
    let cfg = narf_memory::PhysAddr::from_kernel_ptr(words.as_ptr());
    let addr = crate::PcieAddr::new(0x7f35, 0x02, 0x00, 0x0);
    let device = BusDevice {
        addr: crate::BusAddr::Pcie(addr),
        id: crate::DeviceId {
            vendor: 0x17cb,
            device: 0x1103,
            class: 0x028000,
            subsystem_vendor: 0x17aa,
            subsystem_id: 0x9309,
        },
        kind: crate::BusKind::Pcie {
            addr,
            cfg_phys: cfg,
        },
    };
    (device, cfg)
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        remove_device_ctx(TOKEN);
    }
}

fn module_pci_identity_reports_the_exact_function() -> TestResult {
    let mut words = alloc::vec![0u32; 1024];
    let (device, cfg) = function(&mut words);
    // SAFETY: the aligned owned window remains live through the scoped map.
    let _mapping = unsafe { crate::ecam::__test_windows(&[(cfg, words.as_mut_ptr().cast(), 4096)]) };
    install_device_ctx(OWNER, TOKEN, device, Cap::<BusDeviceCap, Write>::bootstrap());
    let _restore = Restore;

    if module_pci_identity(OWNER + 1, TOKEN) != Err(-19) {
        return TestResult::Fail("a foreign module read another context's identity");
    }
    let Ok(record) = module_pci_identity(OWNER, TOKEN) else {
        return TestResult::Fail("identity of an owned function was refused");
    };
    let want: [u8; MODULE_PCI_IDENTITY_LEN] = [
        0xcb, 0x17, 0x03, 0x11, 0xaa, 0x17, 0x09, 0x93, // ids
        0x01, 0x00, 0x80, 0x02, // revision, class (prog-if, sub, base)
        0x35, 0x7f, 0x02, 0x00, // segment, bus, devfn
    ];
    if record != want {
        return TestResult::Fail("identity record does not match the function's config space");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/module-pci",
    module_pci_identity_reports_the_exact_function
);

fn module_pcie_aspm_changes_only_the_aspm_field() -> TestResult {
    let mut words = alloc::vec![0u32; 1024];
    let (device, cfg) = function(&mut words);
    // SAFETY: as above.
    let _mapping = unsafe { crate::ecam::__test_windows(&[(cfg, words.as_mut_ptr().cast(), 4096)]) };
    install_device_ctx(OWNER, TOKEN, device, Cap::<BusDeviceCap, Write>::bootstrap());
    let _restore = Restore;

    if module_pcie_aspm(OWNER, TOKEN, 0x4) != Err(-22) || words[LNKCTL / 4] != 0x42 {
        return TestResult::Fail("a write outside the ASPM field was accepted");
    }
    if module_pcie_aspm(OWNER + 1, TOKEN, 0) != Err(-19) {
        return TestResult::Fail("a foreign module changed another function's link");
    }
    if module_pcie_aspm(OWNER, TOKEN, 0) != Ok(0x2) || words[LNKCTL / 4] & 0xffff != 0x40 {
        return TestResult::Fail("disabling ASPM did not clear L1 and keep the other bits");
    }
    if module_pcie_aspm(OWNER, TOKEN, 0x2) != Ok(0) || words[LNKCTL / 4] & 0xffff != 0x42 {
        return TestResult::Fail("restoring ASPM did not write back the saved field");
    }
    // No PCI Express capability: the field does not exist.
    words[MSI_CAP / 4] &= !0xff00;
    if module_pcie_aspm(OWNER, TOKEN, 0) != Err(-95) {
        return TestResult::Fail("ASPM write accepted on a function without PCIe capability");
    }
    TestResult::Pass
}
kernel_test_in!("bus/module-pci", module_pcie_aspm_changes_only_the_aspm_field);

fn module_msi_programs_an_aligned_block_and_tears_it_down() -> TestResult {
    let mut words = alloc::vec![0u32; 1024];
    let (device, cfg) = function(&mut words);
    // SAFETY: as above.
    let _mapping = unsafe { crate::ecam::__test_windows(&[(cfg, words.as_mut_ptr().cast(), 4096)]) };
    install_device_ctx(OWNER, TOKEN, device, Cap::<BusDeviceCap, Write>::bootstrap());
    let restore = Restore;

    for bad in [0u16, 3, 64] {
        if module_msi_enable(OWNER, TOKEN, bad) != Err(-22) {
            return TestResult::Fail("a non-power-of-two or oversized MSI block was accepted");
        }
    }
    if module_msi_enable(OWNER + 1, TOKEN, 1) != Err(-19) {
        return TestResult::Fail("a foreign module programmed another function's MSI");
    }
    let grant = match module_msi_enable(OWNER, TOKEN, 32) {
        Ok(grant) => grant,
        // No aligned 32-vector run free in this boot, or an interrupt
        // controller without a multi-message MSI target.
        Err(-28) | Err(-5) => return TestResult::Skip("no aligned 32-vector MSI block available"),
        Err(_) => return TestResult::Fail("multi-message MSI setup failed"),
    };
    let msg_ctrl = |w: &[u32]| (w[MSI_CAP / 4] >> 16) as u16;
    if grant.count != 32
        || grant.base_vector % 32 != 0
        || grant.data != u32::from(grant.base_vector)
        || grant.addr == 0
        || u64::from(words[MSI_CAP / 4 + 1]) != grant.addr & 0xffff_ffff
    {
        return TestResult::Fail("MSI grant is not the aligned block that was programmed");
    }
    if msg_ctrl(&words) & 1 != 0 {
        return TestResult::Fail("MSI delivery was enabled before the module asked for it");
    }
    if __module_irq_vector_count_for_test(OWNER) != 32 {
        return TestResult::Fail("MSI vectors were not recorded for handler attachment");
    }
    if module_msi_enable(OWNER, TOKEN, 1) != Err(-16) || module_msix_enable(OWNER, TOKEN) != -16 {
        return TestResult::Fail("a second interrupt setup was accepted over the MSI block");
    }
    if module_msi_set_enabled(OWNER, TOKEN, true) != 0
        || msg_ctrl(&words) & 1 != 1
        || (msg_ctrl(&words) >> 4) & 0x7 != 5
    {
        return TestResult::Fail("enable did not set MSI Enable with 32 messages granted");
    }
    if module_msi_set_enabled(OWNER, TOKEN, false) != 0 || msg_ctrl(&words) & 1 != 0 {
        return TestResult::Fail("disable did not clear MSI Enable");
    }
    if module_msi_set_enabled(OWNER, TOKEN, true) != 0 {
        return TestResult::Fail("re-enable failed");
    }
    drop(restore);
    if msg_ctrl(&words) & 1 != 0 || __module_irq_vector_count_for_test(OWNER) != 0 {
        return TestResult::Fail("teardown left MSI delivering or vectors recorded");
    }
    // The block went back to the allocator: it can be claimed again.
    match narf_interrupts::vector::alloc_block_aligned(32, 32) {
        Ok(base) => {
            for i in 0..32 {
                let _ = narf_interrupts::vector::free(base + i);
            }
        }
        Err(_) => return TestResult::Fail("teardown leaked the MSI vector block"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/module-pci",
    module_msi_programs_an_aligned_block_and_tears_it_down
);

fn module_mapped_dma_is_masked_shared_with_the_handle_and_freed() -> TestResult {
    let mut words = alloc::vec![0u32; 1024];
    let (device, cfg) = function(&mut words);
    // SAFETY: as above.
    let _mapping = unsafe { crate::ecam::__test_windows(&[(cfg, words.as_mut_ptr().cast(), 4096)]) };
    install_device_ctx(OWNER, TOKEN, device, Cap::<BusDeviceCap, Write>::bootstrap());
    let _restore = Restore;
    let domain = narf_lib::id::DomainId::SCRATCH;

    if module_dma_alloc_mapped(OWNER, TOKEN, 0, 32, domain) != Err(-22)
        || module_dma_alloc_mapped(OWNER, TOKEN, 4096, 31, domain) != Err(-22)
        || module_dma_alloc_mapped(OWNER, TOKEN, 4096, 65, domain) != Err(-22)
    {
        return TestResult::Fail("an empty buffer or an impossible address limit was accepted");
    }
    if module_dma_alloc_mapped(OWNER + 1, TOKEN, 4096, 32, domain) != Err(-19) {
        return TestResult::Fail("a foreign module allocated on another function");
    }
    let Ok(dma) = module_dma_alloc_mapped(OWNER, TOKEN, 5000, 32, domain) else {
        return TestResult::Fail("a 32-bit mapped DMA allocation failed");
    };
    if dma.len != 8192 || dma.cpu == 0 || dma.bus + dma.len as u64 - 1 > 0xffff_ffff {
        return TestResult::Fail("mapped DMA is not the masked power-of-two reservation");
    }
    if module_dma_addr(OWNER, TOKEN, dma.handle, 0) != Some(dma.bus) {
        return TestResult::Fail("mapped DMA handle does not name the same buffer");
    }
    // Writes through the CPU mapping are the bytes the handle reads.
    let cpu = dma.cpu as *mut u8;
    // SAFETY: the allocation spans `dma.len` bytes and is live until freed.
    unsafe {
        if core::slice::from_raw_parts(cpu, dma.len).iter().any(|&b| b != 0) {
            return TestResult::Fail("mapped DMA was not zeroed");
        }
        for i in 0..16 {
            cpu.add(4096 + i).write(0xa0 + i as u8);
        }
    }
    let mut back = [0u8; 16];
    if !__module_dma_read_for_test(OWNER, dma.handle, 4096, &mut back)
        || back.iter().enumerate().any(|(i, &b)| b != 0xa0 + i as u8)
    {
        return TestResult::Fail("CPU-mapped writes are not what the device buffer holds");
    }
    if module_dma_free(OWNER, TOKEN, dma.handle) != 0
        || module_dma_free(OWNER, TOKEN, dma.handle) == 0
    {
        return TestResult::Fail("mapped DMA did not free exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/module-pci",
    module_mapped_dma_is_masked_shared_with_the_handle_and_freed
);
