// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! The two API77 recipient BAID control ABIs. Linux mvm/sta.c selects
//! RX_BAID_ALLOCATION_CONFIG_CMD when BAID_ML_SUPPORT is present, even for
//! a single-link station; that capability is not an MLO association grant.
use super::super::super::boot_context::{put16, put32};
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Profile {
    Station,
    ConfigV1,
    ConfigV2,
}
pub(super) struct Command {
    pub group: u8,
    pub command: u8,
    pub bytes: Vec<u8>,
}
impl Profile {
    pub(super) fn add(self, tid: u8, ssn: u16, window: u16) -> Command {
        let mut command = match self {
            Self::Station => Command {
                group: 1,
                command: 0x18,
                bytes: vec![0; 48],
            },
            Self::ConfigV1 | Self::ConfigV2 => Command {
                group: 5,
                command: 0x16,
                bytes: vec![0; 16],
            },
        };
        let b = &mut command.bytes;
        match self {
            Self::Station => {
                b[0] = 1; // ADD_STA_MODE_MODIFY, AP station0.
                b[17] = 8; // STA_MODIFY_ADD_BA_TID.
                b[28] = tid;
                put16(b, 30, ssn);
                put16(b, 44, window);
            }
            Self::ConfigV1 | Self::ConfigV2 => {
                // ADD=0, exact retained AP station ID0 mask.
                put32(b, 4, 1);
                b[8] = tid;
                put16(b, 12, ssn);
                put16(b, 14, window);
            }
        }
        command
    }
    pub(super) fn remove(self, tid: u8, baid: u8) -> Command {
        let mut command = self.add(tid, 0, 0);
        command.bytes.fill(0);
        let b = &mut command.bytes;
        match self {
            Self::Station => {
                b[0] = 1;
                b[17] = 16; // STA_MODIFY_REMOVE_BA_TID.
                b[29] = tid;
            }
            Self::ConfigV1 => {
                put32(b, 0, 2); // REMOVE.
                put32(b, 4, u32::from(baid));
            }
            Self::ConfigV2 => {
                put32(b, 0, 2);
                put32(b, 4, 1); // Exact retained AP station ID0 mask.
                put32(b, 8, u32::from(tid));
            }
        }
        command
    }
    /// A correlated native ADD receipt names a free BAID, or explicitly
    /// declines allocation. Malformed/out-of-range identities remain fatal.
    pub(super) fn allocated(self, bytes: &[u8]) -> Result<Option<u8>, &'static str> {
        let value = u32::from_le_bytes(bytes.try_into().map_err(|_| "MVM BAID receipt extent")?);
        let id = match self {
            Self::Station => {
                if value & 255 == 4 {
                    return Ok(None);
                }
                if value & 255 != 1 || value & 0x8000 == 0 {
                    return Err("MVM station BAID allocation rejected or missing");
                }
                (value >> 8) & 127
            }
            Self::ConfigV1 | Self::ConfigV2 => {
                // Firmware returns a signed errno on allocation failure.
                if (value as i32) < 0 {
                    return Ok(None);
                }
                value
            }
        };
        if id >= 32 {
            return Err("MVM allocated BAID outside native map");
        }
        Ok(Some(id as u8))
    }
    pub(super) fn removed(self, bytes: &[u8]) -> Result<(), &'static str> {
        let value = u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| "MVM BAID removal receipt extent")?,
        );
        // Linux ignores the status/BAID value for CONFIG REMOVE, but still
        // requires the correlated complete response and later RX marker.
        if self == Self::Station && value & 255 != 1 {
            return Err("MVM station BAID removal rejected");
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_mvm_ml_baid_native_v1_v2_payloads_and_signed_reply() -> TestResult {
        for profile in [Profile::ConfigV1, Profile::ConfigV2] {
            let add = profile.add(5, 0xabc, 32);
            if add.group != 5
                || add.command != 0x16
                || add.bytes != [0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0xbc, 0xa, 32, 0]
            {
                return TestResult::Fail("ML BAID ADD station mask/TID/SSN/window ABI");
            }
            if profile.allocated(&[7, 0, 0, 0]) != Ok(Some(7))
                || profile.allocated(&[0xe4, 0xff, 0xff, 0xff]) != Ok(None)
                || profile.allocated(&[32, 0, 0, 0]).is_ok()
                || profile.allocated(&[7, 0, 0]).is_ok()
                || profile.removed(&[0, 0, 0]).is_ok()
            {
                return TestResult::Fail("ML BAID signed result/range/extent weakened");
            }
        }
        let v1 = Profile::ConfigV1.remove(5, 7);
        let v2 = Profile::ConfigV2.remove(5, 7);
        if v1.bytes != [2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            || v2.bytes != [2, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]
            || Profile::Station.allocated(&[1, 0x87, 0, 0]) != Ok(Some(7))
            || Profile::Station.allocated(&[7, 0, 0, 0]).is_ok()
            || Profile::ConfigV1.allocated(&[1, 0x87, 0, 0]).is_ok()
            || Profile::Station.removed(&[0, 0, 0, 0]).is_ok()
            || Profile::ConfigV1.removed(&[0, 0, 0, 0]).is_err()
        {
            return TestResult::Fail("BAID dialects crossed or REMOVE geometry changed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2/ba",
        smoke_mvm_ml_baid_native_v1_v2_payloads_and_signed_reply
    );
}
