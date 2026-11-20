// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware half of actual native monitor IOCTLs and flagged RX. Literal
//! expected values/records come from Linux7.3-rc4, not production encoders.
use alloc::{collections::VecDeque, vec, vec::Vec};
pub(crate) struct Profile {
    pub(super) handled: bool,
    pub(super) status: i16,
    pub(crate) capabilities: Vec<u8>,
    pub(crate) mode: u32,
    pub(crate) writes: Vec<u32>,
    chanspec: u32,
    mpc: u32,
    pub(crate) hold_readback: bool,
    pub(crate) hold_stop: bool,
    pub(crate) wrong_channel: bool,
    pub(crate) early: Option<Vec<u8>>,
    pub(crate) raw: VecDeque<(Vec<u8>, u16)>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            handled: false,
            status: 0,
            capabilities: b"monitor rtap\0".to_vec(),
            mode: 0,
            writes: Vec::new(),
            chanspec: 0x1006,
            mpc: 1,
            hold_readback: false,
            hold_stop: false,
            wrong_channel: false,
            early: None,
            raw: VecDeque::new(),
        }
    }
}
impl Profile {
    pub(super) fn command(&mut self, id: u32, input: &[u8], maximum: u16) -> Option<Vec<u8>> {
        self.status = 0;
        self.handled = true;
        let scalar = |value: u32| Some(value.to_le_bytes().to_vec());
        match id {
            107 => scalar(self.mode),
            108 => {
                let value = u32::from_le_bytes(input.try_into().unwrap());
                assert!(value == 0 || value == 3);
                self.writes.push(value);
                self.mode = value;
                if value == 3 {
                    if let Some(early) = self.early.take() {
                        self.raw.push_back((early, 2));
                    }
                }
                Some(Vec::new())
            }
            117 => scalar(0),
            159 => Some(0u32.to_le_bytes().to_vec()),
            262 if input.starts_with(b"cap\0") => {
                let mut out = vec![0; usize::from(maximum)];
                let len = out.len().min(self.capabilities.len());
                out[..len].copy_from_slice(&self.capabilities[..len]);
                Some(out)
            }
            262 if input == b"chanspec\0" => scalar(if self.wrong_channel && self.mode == 3 {
                0x1001
            } else {
                self.chanspec
            }),
            262 if input == b"mpc\0" => scalar(self.mpc),
            263 if input.starts_with(b"chanspec\0") => {
                assert_eq!(input.len(), 13);
                self.chanspec = u32::from_le_bytes(input[9..].try_into().unwrap());
                Some(Vec::new())
            }
            263 if input.starts_with(b"mpc\0") => {
                assert_eq!(input.len(), 8);
                self.mpc = u32::from_le_bytes(input[4..].try_into().unwrap());
                Some(Vec::new())
            }
            _ => {
                self.handled = false;
                None
            }
        }
    }
    pub(super) fn hold(&self, id: u32, input: &[u8]) -> bool {
        id == 107 && self.mode == 3 && self.hold_readback
            || id == 108 && input == 0u32.to_le_bytes() && self.hold_stop
    }
}
