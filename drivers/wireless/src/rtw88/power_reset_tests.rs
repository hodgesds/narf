//! Device-side power state receipts; independent of source command encoders.
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
pub(in crate::rtw88) struct Silicon<'a> {
    bytes: Vec<u8>,
    writes: Vec<(u64, u32)>,
    off: bool,
    on: bool,
    bad_off: bool,
    bad_on: bool,
    stall: bool,
    authority: Option<narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>>,
    claim: Option<&'a crate::rtw88::functions::ResetClaim>,
    revoke_after_off: bool,
    remove_after_off: Option<narf_bus::BusAddr>,
}
impl Silicon<'_> {
    fn new() -> Self {
        let mut bytes = vec![0; 0x1200];
        bytes[6] = 2; // actual supply-ready bit, independent of poll arguments
        Self {
            bytes,
            writes: Vec::new(),
            off: false,
            on: false,
            bad_off: false,
            bad_on: false,
            stall: false,
            authority: None,
            claim: None,
            revoke_after_off: false,
            remove_after_off: None,
        }
    }
}
impl Io for Silicon<'_> {
    fn permission(&mut self) -> bool {
        self.authority
            .is_none_or(|cap| cap.invoke(narf_capabilities::NoopOp).is_ok())
            && self.claim.is_none_or(|claim| claim.current().is_ok())
    }
    fn read8(&mut self, a: u64) -> u8 {
        self.bytes[a as usize]
    }
    fn read16(&mut self, a: u64) -> u16 {
        u16::from_le_bytes(self.bytes[a as usize..a as usize + 2].try_into().unwrap())
    }
    fn read32(&mut self, a: u64) -> u32 {
        u32::from_le_bytes(self.bytes[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.bytes[a as usize] = v;
        self.writes.push((a, u32::from(v)));
    }
    fn write32(&mut self, a: u64, v: u32) {
        self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        self.writes.push((a, v));
    }
    fn delay_us(&mut self, _: u64) {}
    fn poll8(&mut self, a: u64, mask: u8, target: u8) -> bool {
        if self.stall {
            return false;
        }
        if a == 5 && mask == 2 && target == 0 && self.bytes[5] & 2 != 0 {
            self.bytes[5] &= !2;
            self.off = true;
            if !self.bad_off {
                self.bytes[REG_CR as usize] = 0xea;
            }
            if self.revoke_after_off {
                self.authority.unwrap().revoke();
            }
            if let Some(addr) = self.remove_after_off {
                crate::rtw88::functions::begin_remove(addr);
            }
        }
        if a == 5 && mask == 1 && target == 0 && self.bytes[5] & 1 != 0 {
            self.bytes[5] &= !1;
            self.on = true;
            if !self.bad_on {
                self.bytes[REG_CR as usize] = 0;
            }
        }
        self.read8(a) & mask == target & mask
    }
}
pub(in crate::rtw88) fn remove_during_power(
    claim: &crate::rtw88::functions::ResetClaim,
    address: narf_bus::BusAddr,
) -> Result<(), PowerError> {
    let mut io = Silicon::new();
    io.claim = Some(claim);
    io.remove_after_off = Some(address);
    let result = reset_with(&mut io, RTL_DEV_8822CE);
    if io.on || io.writes.iter().any(|&(a, _)| a == 0x1080) {
        return Err(PowerError::StateReadback);
    }
    result
}
pub(in crate::rtw88) fn cycle(
    _retired: crate::rtw88::operating_reset::Retired,
) -> Result<(), PowerError> {
    reset_with(&mut Silicon::new(), RTL_DEV_8822CE)
}
fn smoke_rtw88_operating_reset_native_card_disable_enable_receipts() -> TestResult {
    for did in [RTL_DEV_8821CE, RTL_DEV_8822CE] {
        for cold_looking in [false, true] {
            let mut io = Silicon::new();
            if cold_looking {
                io.bytes[REG_CR as usize] = 0xea;
                if reset_with(&mut io, did) != Err(PowerError::StateReadback)
                    || !io.writes.is_empty()
                {
                    return TestResult::Fail("already-off card fabricated a reset transition");
                }
                continue;
            }
            if reset_with(&mut io, did) != Ok(())
                || !io.off
                || !io.on
                || io.bytes[REG_CR as usize] == 0xea
                || io.bytes[0x1103] & 15 != 12
                || !io.writes.iter().any(|&(a, _)| a == 0x93)
            {
                return TestResult::Fail(
                    "operating reset skipped real disable/enable or final state",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw88_operating_reset_native_card_disable_enable_receipts
);
fn smoke_rtw88_operating_reset_refuses_partial_power_and_false_cold_states() -> TestResult {
    for fault in 0..4 {
        let mut io = Silicon::new();
        match fault {
            0 => io.bad_off = true,
            1 => io.bad_on = true,
            2 => io.stall = true,
            _ => {
                io.authority = Some(narf_capabilities::Cap::bootstrap());
                io.revoke_after_off = true;
            }
        }
        let expected = if fault == 3 {
            PowerError::Access
        } else if fault == 2 {
            PowerError::Timeout
        } else {
            PowerError::StateReadback
        };
        if reset_with(&mut io, RTL_DEV_8822CE) != Err(expected)
            || io.writes.iter().any(|&(a, _)| a == 0x1080)
        {
            return TestResult::Fail("partial native reset continued system setup");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw88_operating_reset_refuses_partial_power_and_false_cold_states
);
