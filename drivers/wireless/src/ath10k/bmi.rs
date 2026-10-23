// SPDX-License-Identifier: GPL-2.0-or-later
//! Bootloader messaging over the owned PCI Copy Engines.
//!
//! Linux `ath10k/bmi.{c,h}`: serialized CE0 request / CE1 response,
//! 256-byte commands, zero-padded writes and compressed stream download.
//! BMI_DONE is a one-way transition, including a failed DONE exchange.

use super::dma::DmaError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BmiError {
    Dma(DmaError),
    NoMemory,
    Pci,
    Timeout,
    DeviceGone,
    BadResponse,
    AddressOverflow,
    AfterDone,
    Unsupported,
}

impl From<DmaError> for BmiError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetInfo {
    pub version: u32,
    pub target_type: u32,
}

/// The exchange retains request/response DMA ownership until both terminal
/// completions. A timeout poisons the transport; a later request must fail.
pub(super) trait Transport {
    async fn exchange(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, BmiError>;
    /// Retain the coherent code segment until the complete device owner
    /// quiesces DMA. Replacing an already advertised allocation is forbidden.
    fn prepare_codeswap(&mut self, _bytes: &[u8]) -> Result<(u32, [u8; 208]), BmiError> {
        Err(BmiError::Unsupported)
    }
}

#[derive(Debug)]
pub(super) struct Bmi<T> {
    pub transport: T,
    done: bool,
}

impl<T: Transport> Bmi<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            done: false,
        }
    }

    pub async fn configure_codeswap(&mut self, bytes: &[u8]) -> Result<(), BmiError> {
        if self.done {
            return Err(BmiError::AfterDone);
        }
        let (address, info) = self.transport.prepare_codeswap(bytes)?;
        self.write_memory(address, &info).await
    }

    async fn exchange(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, BmiError> {
        if self.done {
            return Err(BmiError::AfterDone);
        }
        self.transport.exchange(request, response).await
    }

    pub async fn target_info(&mut self) -> Result<TargetInfo, BmiError> {
        let mut response = [0; 12];
        let count = self.exchange(&8u32.to_le_bytes(), &mut response).await?;
        if count != 12 {
            return Err(BmiError::BadResponse);
        }
        Ok(TargetInfo {
            version: word(&response[4..8]),
            target_type: word(&response[8..12]),
        })
    }

    pub async fn read_soc(&mut self, address: u32) -> Result<u32, BmiError> {
        if address & 3 != 0 {
            return Err(BmiError::AddressOverflow);
        }
        let mut request = [0; 8];
        request[..4].copy_from_slice(&6u32.to_le_bytes());
        request[4..].copy_from_slice(&address.to_le_bytes());
        let mut response = [0; 4];
        if self.exchange(&request, &mut response).await? != 4 {
            return Err(BmiError::BadResponse);
        }
        Ok(word(&response))
    }

    pub async fn write_soc(&mut self, address: u32, value: u32) -> Result<(), BmiError> {
        if address & 3 != 0 {
            return Err(BmiError::AddressOverflow);
        }
        let mut request = [0; 12];
        request[..4].copy_from_slice(&7u32.to_le_bytes());
        request[4..8].copy_from_slice(&address.to_le_bytes());
        request[8..].copy_from_slice(&value.to_le_bytes());
        if self.exchange(&request, &mut []).await? != 0 {
            return Err(BmiError::BadResponse);
        }
        Ok(())
    }

    pub async fn read_memory(&mut self, mut address: u32, out: &mut [u8]) -> Result<(), BmiError> {
        address
            .checked_add(u32::try_from(out.len()).map_err(|_| BmiError::AddressOverflow)?)
            .ok_or(BmiError::AddressOverflow)?;
        for chunk in out.chunks_mut(256) {
            let mut request = [0; 12];
            request[..4].copy_from_slice(&2u32.to_le_bytes());
            request[4..8].copy_from_slice(&address.to_le_bytes());
            request[8..].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            if self.exchange(&request, chunk).await? != chunk.len() {
                return Err(BmiError::BadResponse);
            }
            address += chunk.len() as u32;
        }
        Ok(())
    }

    pub async fn write_memory(&mut self, mut address: u32, data: &[u8]) -> Result<(), BmiError> {
        let padded = data.len().checked_add(3).ok_or(BmiError::AddressOverflow)? & !3;
        address
            .checked_add(u32::try_from(padded).map_err(|_| BmiError::AddressOverflow)?)
            .ok_or(BmiError::AddressOverflow)?;
        for chunk in data.chunks(244) {
            let length = (chunk.len() + 3) & !3;
            // Zero the complete request; never disclose stack tail bytes on
            // the last unaligned write (Linux's required 4-byte rounding).
            let mut request = [0; 256];
            request[..4].copy_from_slice(&3u32.to_le_bytes());
            request[4..8].copy_from_slice(&address.to_le_bytes());
            request[8..12].copy_from_slice(&(length as u32).to_le_bytes());
            request[12..12 + chunk.len()].copy_from_slice(chunk);
            self.exchange(&request[..12 + length], &mut []).await?;
            address += chunk.len() as u32;
        }
        Ok(())
    }

    pub async fn read_u32(&mut self, address: u32) -> Result<u32, BmiError> {
        let mut out = [0; 4];
        self.read_memory(address, &mut out).await?;
        Ok(word(&out))
    }

    pub async fn write_u32(&mut self, address: u32, value: u32) -> Result<(), BmiError> {
        self.write_memory(address, &value.to_le_bytes()).await
    }

    pub async fn execute(&mut self, address: u32, parameter: u32) -> Result<u32, BmiError> {
        let mut request = [0; 12];
        request[..4].copy_from_slice(&4u32.to_le_bytes());
        request[4..8].copy_from_slice(&address.to_le_bytes());
        request[8..].copy_from_slice(&parameter.to_le_bytes());
        let mut response = [0; 4];
        if self.exchange(&request, &mut response).await? != 4 {
            return Err(BmiError::BadResponse);
        }
        Ok(word(&response))
    }

    async fn start_lz(&mut self, address: u32) -> Result<(), BmiError> {
        let mut request = [0; 8];
        request[..4].copy_from_slice(&13u32.to_le_bytes());
        request[4..].copy_from_slice(&address.to_le_bytes());
        self.exchange(&request, &mut []).await?;
        Ok(())
    }

    pub async fn fast_download(&mut self, address: u32, data: &[u8]) -> Result<(), BmiError> {
        self.start_lz(address).await?;
        for chunk in data.chunks(248) {
            let length = (chunk.len() + 3) & !3;
            let mut request = [0; 256];
            request[..4].copy_from_slice(&14u32.to_le_bytes());
            request[4..8].copy_from_slice(&(length as u32).to_le_bytes());
            request[8..8 + chunk.len()].copy_from_slice(chunk);
            self.exchange(&request[..8 + length], &mut []).await?;
        }
        // Linux opens the dummy zero-address stream to flush target caches.
        self.start_lz(0).await
    }

    pub async fn done(&mut self) -> Result<(), BmiError> {
        if self.done {
            return Err(BmiError::AfterDone);
        }
        self.done = true;
        self.transport
            .exchange(&1u32.to_le_bytes(), &mut [])
            .await?;
        Ok(())
    }
}

pub(super) fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
