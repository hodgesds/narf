// SPDX-License-Identifier: GPL-2.0-or-later
//! Inert F1/F2 device bytes behind the actual Card/SDHCI register model.
//! This supplies no source validator or production constructor. F0/CIS/R5,
//! command/PIO bounds and actual Controller/Card source lifetimes stay owned
//! by the parent native model.
use super::*;
use alloc::boxed::Box;

pub trait Endpoint: Send {
    fn pending(&self) -> bool {
        false
    }
    /// Fixture-only radio/source transition after argument setup, before
    /// the actual native COMMAND. Supplies no host completion or authority.
    fn prepare_write(&mut self, _function: u8) {}

    fn read52(&mut self, function: u8, address: u32) -> Result<u8, SdioError>;
    fn write52(&mut self, function: u8, address: u32, value: u8) -> Result<(), SdioError>;
    fn read53(
        &mut self,
        function: u8,
        address: u32,
        increment: bool,
        length: usize,
    ) -> Result<Vec<u8>, SdioError>;
    fn write53(
        &mut self,
        function: u8,
        address: u32,
        increment: bool,
        bytes: &[u8],
    ) -> Result<(), SdioError>;
}
pub(super) struct Write {
    function: u8,
    address: u32,
    increment: bool,
    length: usize,
    bytes: Vec<u8>,
}
impl Model {
    pub fn native_commands(&self) -> Vec<(u8, u32, u16)> {
        self.0.lock().commands.clone()
    }
    pub fn with_endpoint(
        endpoint: Box<dyn Endpoint>,
        identity: Option<crate::pio::HostIdentity>,
    ) -> Self {
        let mut model = Self::new();
        model.1 = identity;
        model.0.lock().endpoint = Some(endpoint);
        model
    }
}
pub(super) fn direct(state: &mut State, argument: u32) -> Option<u32> {
    let function = ((argument >> 28) & 7) as u8;
    if function == 0 {
        return None;
    }
    let endpoint = state.endpoint.as_mut()?;
    let address = (argument >> 9) & 0x1ffff;
    let result = if argument >> 31 != 0 {
        endpoint
            .write52(function, address, argument as u8)
            .map(|()| argument as u8)
    } else {
        endpoint.read52(function, address)
    };
    Some(result.map(u32::from).unwrap_or(0x0200))
}
pub(super) fn begin(state: &mut State, argument: u32, length: usize, read: bool) -> bool {
    let Some(endpoint) = state.endpoint.as_mut() else {
        return true;
    };
    let function = ((argument >> 28) & 7) as u8;
    let address = (argument >> 9) & 0x1ffff;
    let increment = argument & (1 << 26) != 0;
    if read {
        match endpoint.read53(function, address, increment, length) {
            Ok(bytes) if bytes.len() == length => {
                state.endpoint_read = bytes.into();
                true
            }
            _ => false,
        }
    } else {
        state.endpoint_write = Some(Write {
            function,
            address,
            increment,
            length,
            bytes: Vec::new(),
        });
        true
    }
}
pub(super) fn read(state: &mut State) -> u32 {
    if state.endpoint.is_none() {
        return 0x44332211;
    }
    let mut word = [0; 4];
    for byte in &mut word {
        *byte = state.endpoint_read.pop_front().unwrap_or(0);
    }
    u32::from_le_bytes(word)
}
pub(super) fn write(state: &mut State, value: u32) {
    if let Some(write) = state.endpoint_write.as_mut() {
        write.bytes.extend_from_slice(&value.to_le_bytes());
    }
}
pub(super) fn finish(state: &mut State) {
    let Some(write) = state.endpoint_write.take() else {
        return;
    };
    let Some(endpoint) = state.endpoint.as_mut() else {
        return;
    };
    let success = write.bytes.get(..write.length).is_some_and(|bytes| {
        endpoint
            .write53(write.function, write.address, write.increment, bytes)
            .is_ok()
    });
    if !success {
        state.set32(
            INT_STATUS,
            state.get32(INT_STATUS) | INT_ERROR | INT_DATA_CRC,
        );
    }
}
