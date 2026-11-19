// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
fn aperture() -> (Vec<u32>, MmioRegion) {
    let mut words = vec![0u32; 0x40000 / 4];
    // Literal actual closed native common power/packet/CH12-only tuple.
    for (address, value) in [
        (0x24, 0x1f000000),
        (0x84, 0x02010003),
        (0x10000, 0xc00001ff),
        (0xb000, 0x30),
        (0xb010, 0x80006fff),
    ] {
        words[address / 4] = value;
    }
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x10000000),
        virt: words.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    (words, region)
}
fn smoke_rtw8922a_partial_native_has_current_signed_and_original_bus_authority() -> TestResult {
    for revoke_signed in [false, true] {
        let (mut words, region) = aperture();
        let (grant, signer) = be_qualification::tests::revocable();
        let bus = Cap::<BusDeviceCap, Write>::bootstrap();
        let cancelled = AtomicBool::new(false);
        // SAFETY: exclusive inert BAR RAM, actual current model N22P and bus
        // capabilities; no hardware, DMA producer, IRQ or reset exists.
        let mut io = unsafe { Registers::new(&region, &bus, &grant, &cancelled) };
        kt_assert_eq!(io.write32(0x20000, 4), Ok(()));
        kt_assert_eq!(words[0x20000 / 4], 4);
        if revoke_signed {
            signer.revoke();
        } else {
            bus.revoke();
        }
        kt_assert_eq!(io.write32(0x20000, 8), Err(power::Error::Access));
        kt_assert_eq!(words[0x20000 / 4], 4);
        // Repairing BAR state cannot revive a revoked/terminal port.
        words[0x20000 / 4] = 2;
        kt_assert_eq!(io.write32(0x20000, 9), Err(power::Error::Access));
        kt_assert_eq!(words[0x20000 / 4], 2);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_native_has_current_signed_and_original_bus_authority
);
fn smoke_rtw8922a_partial_native_refuses_every_packet_power_dma_uncertainty() -> TestResult {
    for (address, wrong) in [
        (0x24, 0x1e000000),
        (0x24, 0x1f000001),
        (0x84, 0x02030003),
        (0x84, 0x00010003),
        (0x84, 0x02010103),
        (0x10000, 0xf00001ff),
        (0xb010, 0x80007fff),
        (0xb010, 0x80006ffe),
        (0xb000, 0xb0),
        (0x24, u32::MAX),
        (0x84, u32::MAX),
        (0x10000, u32::MAX),
    ] {
        let (mut words, region) = aperture();
        let (grant, _) = be_qualification::tests::revocable();
        let bus = Cap::<BusDeviceCap, Write>::bootstrap();
        let cancelled = AtomicBool::new(false);
        let original = words[address / 4];
        words[address / 4] = wrong;
        // SAFETY: exclusive inert BAR RAM; intentionally invalid hardware
        // prerequisite must refuse before any requested register effect.
        let mut io = unsafe { Registers::new(&region, &bus, &grant, &cancelled) };
        kt_assert!(io.write32(0x20000, 0x1234).is_err());
        kt_assert_eq!(words[0x20000 / 4], 0);
        words[address / 4] = original;
        kt_assert!(io.write32(0x20000, 0x4321).is_err());
        kt_assert_eq!(words[0x20000 / 4], 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_native_refuses_every_packet_power_dma_uncertainty
);
fn smoke_rtw8922a_partial_native_never_exposes_packet_mac1_irq_or_power_open() -> TestResult {
    for base in [0xe500, 0xed00] {
        for word in 0..32 {
            kt_assert!(permitted(base + word * 4));
        }
        kt_assert!(!permitted(base - 4));
        kt_assert!(!permitted(base + 32 * 4));
    }
    for address in [
        0x10000, 0x14000, 0x15a78, 0x15a84, 0xb000, 0xb010, 0x24, 0x842c, 0x1a0, 0x30000, 0x20001,
    ] {
        kt_assert!(!permitted(address) || address & 3 != 0);
    }
    let (words, region) = aperture();
    let (grant, _) = be_qualification::tests::revocable();
    let bus = Cap::<BusDeviceCap, Write>::bootstrap();
    let cancelled = AtomicBool::new(false);
    // SAFETY: exclusive inert BAR RAM and current model authorities; no DMA.
    let mut io = unsafe { Registers::new(&region, &bus, &grant, &cancelled) };
    // Source PHY0 boot-ready/platform bits only; BB1 cannot be released.
    kt_assert_eq!(io.write32(0x84, 0x02010007), Ok(()));
    kt_assert_eq!(io.write32(0x84, 0x02010107), Err(power::Error::Access));
    kt_assert_eq!(words[0x84 / 4], 0x02010007);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_native_never_exposes_packet_mac1_irq_or_power_open
);
fn smoke_rtw8922a_partial_native_cancellation_and_gone_are_terminal() -> TestResult {
    for gone in [false, true] {
        let (mut words, region) = aperture();
        let (grant, _) = be_qualification::tests::revocable();
        let bus = Cap::<BusDeviceCap, Write>::bootstrap();
        let cancelled = AtomicBool::new(!gone);
        words[0x20000 / 4] = if gone { u32::MAX } else { 7 };
        // SAFETY: exclusive inert source BAR model; refusal has no hardware.
        let mut io = unsafe { Registers::new(&region, &bus, &grant, &cancelled) };
        kt_assert_eq!(
            io.read32(0x20000),
            Err(if gone {
                power::Error::Gone
            } else {
                power::Error::Access
            })
        );
        cancelled.store(false, Ordering::Release);
        words[0x20000 / 4] = 9;
        kt_assert!(io.write32(0x20000, 10).is_err());
        kt_assert_eq!(words[0x20000 / 4], 9);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_native_cancellation_and_gone_are_terminal
);

fn smoke_rtw8922a_wlan_native_mac1_power_window_is_separate_and_closes() -> TestResult {
    use super::super::{
        be_mac1::{State, Window},
        be_wlan_qualification,
    };
    let (words, region) = aperture();
    let (grant, _) = be_wlan_qualification::tests::revocable();
    let bus = Cap::<BusDeviceCap, Write>::bootstrap();
    let cancelled = AtomicBool::new(false);
    // SAFETY: exclusive inert native BAR plus actual current fixture caps.
    let mut io = unsafe { Registers::new_scope(&region, &bus, Grant::Wlan(&grant), &cancelled) };
    let mut window = Window::default();
    // SAFETY: concrete native retained window; RAM has the exact closed tuple.
    kt_assert_eq!(unsafe { window.program(&mut io) }, Ok(()));
    kt_assert_eq!(window.state(), State::CompleteOff);
    kt_assert_eq!(words[0x24 / 4] & 0x1f00001f, 0x1f000000);
    kt_assert_eq!(words[0x84 / 4] & 0x03030300, 0x02010000);
    kt_assert_eq!(words[0x14000 / 4] & 0x30000000, 0);
    kt_assert_eq!(words[0x15a84 / 4], 0x0201fe00);
    kt_assert_eq!(words[0x15a78 / 4], 0x00ffec7e);
    kt_assert_eq!(io.write16(0x1087c, 0x111), Ok(()));
    kt_assert_eq!(io.read16(0x1087c), Ok(0x111));
    // No permanent C1 aperture or ordinary packet/DMA API was acquired.
    kt_assert!(io.read32(0x15a84).is_err());
    for address in [0x10000, 0x14000, 0xb000, 0xb010, 0x24] {
        kt_assert!(!permitted(address) && !permitted_wlan(address));
    }
    let (words, region) = aperture();
    let (partial, _) = be_qualification::tests::revocable();
    // SAFETY: separate inert native N22P port must refuse the power window.
    let mut io = unsafe { Registers::new(&region, &bus, &partial, &cancelled) };
    let mut window = Window::default();
    // SAFETY: the full private RAM aperture and original port remain owned
    // without competing producers. This negative N22P adapter refuses the
    // first N22W-only transition before a MAC1 effect; no physical power or
    // packet authority is inferred from the synthetic closed tuple.
    kt_assert!(unsafe { window.program(&mut io) }.is_err());
    kt_assert_eq!(window.state(), State::FailedClosed);
    kt_assert_eq!(words[0x15a84 / 4], 0);
    kt_assert_eq!(words[0x15a78 / 4], 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_wlan_native_mac1_power_window_is_separate_and_closes
);

#[derive(Clone, Copy)]
enum WindowFault {
    Signed,
    Pci,
    Cancel,
}
struct WindowCut<'a, 'b> {
    io: &'a mut Registers<'b>,
    signer: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    after: usize,
    effects: usize,
    fault: WindowFault,
}
impl WindowCut<'_, '_> {
    fn effect(&mut self, result: Result<(), power::Error>) -> Result<(), power::Error> {
        result?;
        self.effects += 1;
        if self.effects == self.after {
            match self.fault {
                WindowFault::Signed => self.signer.revoke(),
                WindowFault::Pci => self.io.authority.revoke(),
                WindowFault::Cancel => self.io.cancelled.store(true, Ordering::Release),
            }
        }
        Ok(())
    }
}
impl super::super::be_mac1::Interface for WindowCut<'_, '_> {
    fn transition(
        &mut self,
        before: super::super::be_mac1::Power,
        after: super::super::be_mac1::Power,
        at: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), power::Error> {
        let result =
            super::super::be_mac1::Interface::transition(self.io, before, after, at, mask, value);
        self.effect(result)
    }
    fn powered_field(&mut self, at: u32, mask: u32, value: u32) -> Result<(), power::Error> {
        let result = super::super::be_mac1::Interface::powered_field(self.io, at, mask, value);
        self.effect(result)
    }
    fn restrict(&mut self) -> Result<(), power::Error> {
        super::super::be_mac1::Interface::restrict(self.io)
    }
}
fn smoke_rtw8922a_wlan_native_mac1_revocation_cancel_and_pci_closure_are_owned() -> TestResult {
    use super::super::{
        be_mac1::{State, Window},
        be_wlan_qualification,
    };
    for fault in [WindowFault::Signed, WindowFault::Pci, WindowFault::Cancel] {
        for after in 1..9 {
            let (words, region) = aperture();
            let (grant, signer) = be_wlan_qualification::tests::revocable();
            let bus = Cap::<BusDeviceCap, Write>::bootstrap();
            let cancelled = AtomicBool::new(false);
            // SAFETY: exact original RAM model; fault injection revokes real
            // fixture capability or cancels after an actual native effect.
            let mut io =
                unsafe { Registers::new_scope(&region, &bus, Grant::Wlan(&grant), &cancelled) };
            let mut cut = WindowCut {
                io: &mut io,
                signer,
                after,
                effects: 0,
                fault,
            };
            let mut window = Window::default();
            // SAFETY: the same exclusive RAM aperture/current N22W and PCI
            // adapter remain borrowed for this synchronous window. Cut only
            // forwards its checked effects before revoking their actual cap
            // or cancellation token; original state/storage remains retained
            // while the native restrictive closure records any uncertainty.
            kt_assert!(unsafe { window.program(&mut cut) }.is_err());
            kt_assert_eq!(cut.effects, after);
            if matches!(fault, WindowFault::Pci) {
                kt_assert_eq!(window.state(), State::FailedUnknown);
            } else {
                kt_assert_eq!(window.state(), State::FailedClosed);
                kt_assert_eq!(words[0x24 / 4] & 0x1f00001f, 0x1f000000);
                kt_assert_eq!(words[0x84 / 4] & 0x03030300, 0x02010000);
            }
            if after < 5 {
                kt_assert_eq!(words[0x15a84 / 4], 0);
            }
            let before = words.clone();
            // No completed/failed retained owner can replay its window.
            // SAFETY: the original inert adapter/aperture still outlive this
            // call, and the same terminal Window rejects before touching it.
            // This verifies refusal, not renewed source or MAC1 authority.
            kt_assert!(unsafe { window.program(&mut cut) }.is_err());
            kt_assert_eq!(words, before);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_wlan_native_mac1_revocation_cancel_and_pci_closure_are_owned
);
