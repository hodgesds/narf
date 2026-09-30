//! Shared cyclic PCM storage and accounting for native HDA/ACP DMA.

use core::sync::atomic::{fence, Ordering};
use narf_drivers_sound::{format::HwParams, SoundError};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

#[derive(Debug)]
pub(crate) struct Ring {
    pub data: DmaBuffer,
    pub bdl: DmaBuffer,
    pub params: HwParams,
    pub bytes: usize,
    pub frame_bytes: usize,
    pub application: u64,
    pub hardware: u64,
    pub running: bool,
    pub prepared: bool,
    pub xrun: bool,
}

impl Ring {
    pub fn new(params: HwParams) -> Result<Self, SoundError> {
        let frame_bytes = params.channels.count() as usize * params.format.bytes_per_sample();
        let period = (params.period_size as usize)
            .checked_mul(frame_bytes)
            .ok_or(SoundError::InvalidParams)?;
        let bytes = period
            .checked_mul(params.periods as usize)
            .ok_or(SoundError::InvalidParams)?;
        if !(2..=256).contains(&params.periods)
            || period < 128
            || period % 128 != 0
            || !(4096..=256 * 1024).contains(&bytes)
        {
            return Err(SoundError::InvalidParams);
        }
        let data = alloc_coherent(bytes, DomainId::DRIVER_0).map_err(|_| SoundError::NoMemory)?;
        let bdl = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| SoundError::NoMemory)?;
        for i in 0..params.periods as usize {
            let addr = data.dma_addr_at((i * period) as u64).raw();
            // SAFETY: descriptor slot is in the owned, unpublished 4 KiB BDL.
            unsafe {
                let p = bdl.cpu_mut_ptr::<u32>().add(i * 4);
                p.write_volatile(addr as u32);
                p.add(1).write_volatile((addr >> 32) as u32);
                p.add(2).write_volatile(period as u32);
                p.add(3).write_volatile(1);
            }
        }
        Ok(Self {
            data,
            bdl,
            params,
            bytes,
            frame_bytes,
            application: 0,
            hardware: 0,
            running: false,
            prepared: false,
            xrun: false,
        })
    }

    /// Caller has stopped DMA before resetting software ownership.
    pub fn reset(&mut self) {
        // SAFETY: caller established quiescence, buffer is exclusively owned.
        unsafe {
            core::ptr::write_bytes(self.data.cpu_mut_ptr::<u8>(), 0, self.bytes);
        }
        self.application = 0;
        self.hardware = 0;
        self.running = false;
        self.prepared = true;
        self.xrun = false;
        fence(Ordering::Release);
    }

    pub fn write(&mut self, input: &[u8]) -> Result<usize, SoundError> {
        if !self.prepared || self.xrun {
            return Err(SoundError::BadState);
        }
        if input.len() % self.frame_bytes != 0 {
            return Err(SoundError::InvalidParams);
        }
        let queued = self
            .application
            .saturating_sub(self.hardware)
            .min(self.bytes as u64);
        let n = input.len().min(self.bytes - queued as usize);
        let offset = (self.application % self.bytes as u64) as usize;
        // SAFETY: only free playback slots are written; driver serializes CPU access.
        unsafe {
            for (i, byte) in input[..n].iter().enumerate() {
                self.data
                    .cpu_mut_ptr::<u8>()
                    .add((offset + i) % self.bytes)
                    .write_volatile(*byte);
            }
        }
        fence(Ordering::Release);
        self.application += n as u64;
        Ok(n)
    }

    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, SoundError> {
        if !self.prepared || self.xrun {
            return Err(SoundError::BadState);
        }
        if output.len() % self.frame_bytes != 0 {
            return Err(SoundError::InvalidParams);
        }
        let available = self.hardware.saturating_sub(self.application);
        if available > self.bytes as u64 {
            self.xrun = true;
            return Err(SoundError::BadState);
        }
        let n = output.len().min(available as usize);
        let offset = (self.application % self.bytes as u64) as usize;
        fence(Ordering::Acquire);
        // SAFETY: only completed capture slots are read, through volatile DMA pointers.
        unsafe {
            for (i, byte) in output[..n].iter_mut().enumerate() {
                *byte = self
                    .data
                    .cpu_ptr::<u8>()
                    .add((offset + i) % self.bytes)
                    .read_volatile();
            }
        }
        self.application += n as u64;
        Ok(n)
    }
}
