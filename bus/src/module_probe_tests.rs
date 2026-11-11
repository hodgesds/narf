use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn module_probe_preparation_uses_exact_fresh_context_authority() -> TestResult {
    let mut words = alloc::vec![0u32; 1024];
    let cfg = narf_memory::PhysAddr::from_kernel_ptr(words.as_ptr());
    // SAFETY: the aligned owned window remains live through the scoped map.
    let _mapping =
        unsafe { crate::ecam::__test_windows(&[(cfg, words.as_mut_ptr().cast(), 4096)]) };
    let addr = crate::PcieAddr::new(0x7f33, 0, 0, 0);
    let device = BusDevice {
        addr: crate::BusAddr::Pcie(addr),
        id: crate::DeviceId {
            vendor: 0x8086,
            device: 0x15f3,
            class: 0x020000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: crate::BusKind::Pcie {
            addr,
            cfg_phys: cfg,
        },
    };
    const OWNER: u64 = 0xffff_ffff_7311;
    const TOKEN: u64 = 0xffff_ffff_7312;
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    install_device_ctx(OWNER, TOKEN, device, cap);
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            remove_device_ctx(TOKEN);
        }
    }
    let _restore = Restore;
    words[1] = 7;
    if module_pci_prepare_probe(OWNER + 1, TOKEN) != -19 || words[1] != 7 {
        return TestResult::Fail("foreign module authority parked a function");
    }
    if module_pci_prepare_probe(OWNER, TOKEN) != 0 || words[1] != 0x401 {
        return TestResult::Fail("fresh module context did not park inherited mastering");
    }
    words[1] = 0x0010_0007;
    words[0x34 / 4] = 0x80;
    words[0x80 / 4] = 0x10;
    words[0x88 / 4] = 0x2810;
    if module_pci_prepare_probe(OWNER, TOKEN) != 0
        || words[0x88 / 4] != 0x2010
        || words[1] != 0x0010_0401
        || module_pci_enable(OWNER, TOKEN, crate::pci::cmd::MEM_SPACE) != 0
        || words[1] != 0x0010_0403
    {
        return TestResult::Fail("module coherent probe lost PCI policy or command readback");
    }
    words[0x34 / 4] = 0xfc;
    words[0xfc / 4] = 0x10;
    words[0x104 / 4] = 0xdead_beef;
    if module_pci_prepare_probe(OWNER, TOKEN) != -5 || words[0x104 / 4] != 0xdead_beef {
        return TestResult::Fail("malformed standard capability reached extended configuration");
    }
    words[0x34 / 4] = 0x80;
    {
        let mut contexts = DEVICE_CTXS.lock();
        let ctx = contexts.iter_mut().find(|ctx| ctx.token == TOKEN).unwrap();
        ctx.bars.push(crate::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: crate::BarKind::Mmio32 {
                prefetchable: false,
            },
        });
    }
    words[1] = 7;
    if module_pci_prepare_probe(OWNER, TOKEN) != -16 || words[1] != 7 {
        return TestResult::Fail("active module context was parked through initial preparation");
    }
    {
        let mut contexts = DEVICE_CTXS.lock();
        contexts
            .iter_mut()
            .find(|ctx| ctx.token == TOKEN)
            .unwrap()
            .bars
            .clear();
    }
    cap.revoke();
    if module_pci_prepare_probe(OWNER, TOKEN) != -5 || words[1] != 7 {
        return TestResult::Fail("revoked module probe changed configuration");
    }
    remove_device_ctx(TOKEN);
    if module_pci_prepare_probe(OWNER, TOKEN) != -19 {
        return TestResult::Fail("retired module probe token stayed valid");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pci-probe",
    module_probe_preparation_uses_exact_fresh_context_authority
);
