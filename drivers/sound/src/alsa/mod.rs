//! Linux 64-bit ALSA UAPI. Wire layouts follow include/uapi/sound/asound.h
//! (validated against /usr/src/linux, Linux 7.3-rc4); x86_64 and aarch64
//! share these sizes and offsets.
//! All process addresses are accessed through the syscall-owned IoctlContext.
mod control;
mod params;
mod pcm;
#[cfg(feature = "kernel-test")]
mod tests;
use alloc::vec::Vec;
pub(crate) use control::changed as control_changed;
pub(crate) use control::remove_card;
pub(crate) use control::Control;
use narf_filesystem::{FsError, IoctlContext};
pub(crate) use pcm::suspend_card;
pub(crate) use pcm::Pcm;

pub(crate) fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}
pub(crate) fn get64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}
pub(crate) fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}
pub(crate) fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}
pub(crate) fn string(b: &mut [u8], at: usize, len: usize, text: &str) {
    let n = text.len().min(len - 1);
    b[at..at + len].fill(0);
    b[at..at + n].copy_from_slice(&text.as_bytes()[..n]);
}
pub(crate) fn input(ctx: &dyn IoctlContext, arg: u64, len: usize) -> Result<Vec<u8>, FsError> {
    let mut b = alloc::vec![0; len];
    ctx.read(arg, &mut b)?;
    Ok(b)
}
pub(crate) const fn command(kind: u8, nr: u8, dir: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((kind as u32) << 8) | nr as u32
}
pub(crate) fn info(card: u32, device: u32, capture: bool) -> Result<Vec<u8>, FsError> {
    let card = crate::list_cards()
        .into_iter()
        .find(|c| c.index == card)
        .ok_or(FsError::NoDevice)?;
    if device
        >= if capture {
            card.capture_count
        } else {
            card.playback_count
        }
    {
        return Err(FsError::NotFound);
    }
    let mut b = alloc::vec![0; 288];
    put32(&mut b, 0, device);
    put32(&mut b, 8, u32::from(capture));
    put32(&mut b, 12, card.index);
    string(&mut b, 16, 64, card.id);
    string(&mut b, 80, 80, card.name);
    string(&mut b, 160, 32, "subdevice #0");
    put32(&mut b, 200, 1);
    put32(&mut b, 204, 1);
    Ok(b)
}
pub(crate) fn sound_error(e: crate::SoundError) -> FsError {
    use crate::SoundError::*;
    match e {
        NoSuchCard | NoSuchDevice => FsError::NoDevice,
        DeviceBusy => FsError::Busy,
        NoMemory => FsError::OutOfMemory,
        NoSuchControl => FsError::NotFound,
        BadState => FsError::StreamXrun,
        InvalidParams | OutOfRange => FsError::InvalidData,
    }
}

// include/uapi/asm-generic/{errno-base,errno}.h. PCM transfer ioctls store
// the negative errno in snd_xfer*.result as well as returning it.
fn errno(error: FsError) -> i64 {
    match error {
        FsError::OperationNotPermitted => 1,
        FsError::NotFound => 2,
        FsError::NoDeviceAddress => 6,
        FsError::BadFd => 9,
        FsError::WouldBlock => 11,
        FsError::OutOfMemory => 12,
        FsError::PermissionDenied => 13,
        FsError::BadAddress => 14,
        FsError::Busy => 16,
        FsError::NoDevice => 19,
        FsError::InvalidData | FsError::InvalidPath => 22,
        FsError::Unsupported => 25,
        FsError::StreamXrun => 32,
        FsError::NotImplemented => 38,
        FsError::BadFileState => 77,
        FsError::StreamSuspended => 86,
        _ => 5,
    }
}
