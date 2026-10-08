//! ALSA requests through the syscall boundary. Errno precedence comes from
//! /usr/src/linux/sound/core/{pcm_native,pcm_lib,control}.c; numeric values
//! come from /usr/src/linux/include/uapi/asm-generic/{errno-base,errno}.h.
use crate::abi_test_support::*;
use alloc::sync::Arc;
use narf_filesystem::{FileOps, FsInstance};

const BAD: u64 = 0x0000_8000_0000_0000;

/// ALSA syscall tests require an endpoint published by a successfully probed
/// sound card.  The aarch64 QEMU fixture may expose no usable sound device;
/// that is an unavailable-hardware condition, not an ABI failure.
fn sound_endpoint_available(playback: bool) -> bool {
    narf_filesystem::devfs::DevFs::new()
        .root()
        .lookup_dir("snd")
        .is_some_and(|dir| {
            dir.enumerate(0, 256).into_iter().any(|(name, _)| {
                if playback {
                    name.starts_with("pcm") && name.ends_with('p')
                } else {
                    name.starts_with("control")
                }
            })
        })
}

fn install_sound(playback: bool) -> Result<(u32, Arc<dyn FileOps>), &'static str> {
    let dir = narf_filesystem::devfs::DevFs::new()
        .root()
        .lookup_dir("snd")
        .ok_or("sound directory absent")?;
    let name = dir
        .enumerate(0, 256)
        .into_iter()
        .find(|(name, _)| {
            if playback {
                name.starts_with("pcm") && name.ends_with('p')
            } else {
                name.starts_with("control")
            }
        })
        .ok_or("sound endpoint absent")?
        .0;
    let node = dir.lookup(&name).ok_or("sound lookup failed")?;
    let ops = node
        .open_instance_checked(true)
        .map_err(|_| "sound open failed")?
        .unwrap_or(node);
    let fd = fd::install(
        FAKE_TASK,
        fd::FdEntry {
            ops: ops.clone(),
            offset: 0,
            flags: 0,
            status_flags: fd::O_RDWR | fd::O_NONBLOCK,
        },
    )
    .ok_or("sound fd install failed")?;
    Ok((fd, ops))
}
fn ioctl(fd: u32, cmd: u64, arg: u64) -> Option<i64> {
    call(Syscall::Ioctl.raw(), a2(fd as u64, cmd, arg))
}
fn set32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}
fn pcm_params() -> [u8; 608] {
    let mut b = [0; 608];
    set32(&mut b, 4, 1);
    b[36..100].fill(255);
    for i in 0..12 {
        set32(&mut b, 264 + i * 12, u32::MAX);
    }
    set32(&mut b, 512, u32::MAX);
    b
}
fn smoke_alsa_ioctl_errno_and_mmap_through_syscalls() -> TestResult {
    if !sound_endpoint_available(true) {
        return TestResult::Skip("requires a playback /dev/snd endpoint");
    }
    with_setup(|| {
        let (fd, ops) = install_sound(true)?;
        let mut version = 0u32;
        if ioctl(fd, 0x80044100, &mut version as *mut u32 as u64) != Some(0) || version != 0x20012 {
            return Err("ALSA PVERSION");
        }
        for (cmd, arg, errno) in [
            (0x80044100, BAD, -14),
            (0xc01041ff, BAD, -25),
            (0x40044102, BAD, 0),
            (0x4150, BAD, -25),
            (0x40184150, BAD, -77),
            (0x4140, 0, -77),
            (0x4112, 0, -77),
            (0x80084121, BAD, -77),
            (0x4147, 0, -77),
            (0x4161, 0, -114),
            (0x40044145, 1, -38),
        ] {
            if ioctl(fd, cmd, arg) != Some(errno) {
                return Err("ALSA ioctl errno or precedence differs from Linux");
            }
        }
        install_test_address_space()?;
        let mmap = |offset, prot, len| {
            call(
                Syscall::Mmap.raw(),
                SyscallArgs {
                    arg0: 0,
                    arg1: len,
                    arg2: prot,
                    arg3: 1,
                    arg4: fd as u64,
                    arg5: offset,
                },
            )
        };
        if mmap(0, 3, 4096) != Some(-77) {
            return Err("ALSA mmap before HW_PARAMS must be EBADFD");
        }
        let mut params = pcm_params();
        if ioctl(fd, 0xc2604111, params.as_mut_ptr() as u64) != Some(0) {
            return Err("ALSA HW_PARAMS through syscall");
        }
        if ioctl(fd, 0x4140, 0) != Some(0) {
            return Err("ALSA PREPARE through syscall");
        }
        let mut pollfd = [0u8; 8];
        pollfd[..4].copy_from_slice(&fd.to_ne_bytes());
        pollfd[4..6].copy_from_slice(&4u16.to_ne_bytes());
        // ppoll is available on both architectures (AArch64 has no poll syscall).
        let timeout = [0u64; 2];
        if call(
            Syscall::Ppoll.raw(),
            a4(pollfd.as_mut_ptr() as u64, 1, timeout.as_ptr() as u64, 0, 8),
        ) != Some(1)
        {
            return Err("ALSA PCM ppoll readiness");
        }
        if u16::from_ne_bytes(pollfd[6..8].try_into().unwrap()) & 4 == 0 {
            return Err("ALSA ppoll missing POLLOUT");
        }
        let mapped = mmap(0, 3, 4096)
            .filter(|v| *v > 0)
            .ok_or("ALSA data mmap failed")?;
        // VMA owns the exact data allocation, so HW_FREE rejects a live map.
        if ioctl(fd, 0x4112, 0) != Some(-77) {
            return Err("ALSA mapped HW_FREE must be EBADFD");
        }
        if call(Syscall::Munmap.raw(), a1(mapped as u64, 4096)) != Some(0) {
            return Err("ALSA data munmap");
        }
        if ops.mmap_frames(0xffff0000, 4096).is_ok() {
            return Err("ALSA mmap accepted invalid offset");
        }
        if mmap(0xffff0000, 3, 4096) != Some(-22) {
            return Err("invalid sound mmap fell back to copied file pages");
        }
        if ioctl(fd, 0x4112, 0) != Some(0) {
            return Err("ALSA HW_FREE after unmap");
        }
        let version = 0x20010u32;
        if ioctl(fd, 0x40044104, &version as *const u32 as u64) != Some(0) {
            return Err("ALSA USER_PVERSION");
        }
        if mmap(0x81000000, 3, 4096) != Some(-6) {
            return Err("SYNC_APPLPTR control mmap must be ENXIO");
        }
        let status = mmap(0x80000000, 3, 4096);
        if cfg!(target_arch = "aarch64") {
            if status != Some(-6) {
                return Err("aarch64 status mmap must be ENXIO");
            }
        } else {
            let status = status.filter(|v| *v > 0).ok_or("status mmap")? as u64;
            if call(Syscall::MProtect.raw(), a2(status, 4096, 3)) != Some(-13) {
                return Err("ALSA status must remain read-only after mprotect");
            }
            if call(Syscall::Munmap.raw(), a1(status, 4096)) != Some(0) {
                return Err("status munmap");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sound",
    smoke_alsa_ioctl_errno_and_mmap_through_syscalls
);

fn smoke_alsa_control_errno_through_syscalls() -> TestResult {
    if !sound_endpoint_available(false) {
        return TestResult::Skip("requires a control /dev/snd endpoint");
    }
    with_setup(|| {
        let (fd, _) = install_sound(false)?;
        for (cmd, arg, errno) in [
            (0x80045500, BAD, -14),
            (0xc00855ff, BAD, -25),
            (0xc00455d0, BAD, -92),
            (0xc0505510, BAD, -14),
            (0xc008551a, BAD, -14),
        ] {
            if ioctl(fd, cmd, arg) != Some(errno) {
                return Err("ALSA control errno precedence");
            }
        }
        let mut tlv = [0u32, 8];
        if ioctl(fd, 0xc008551a, tlv.as_mut_ptr() as u64) != Some(-22) {
            return Err("zero TLV numid must be EINVAL");
        }
        tlv[0] = u32::MAX;
        if ioctl(fd, 0xc008551a, tlv.as_mut_ptr() as u64) != Some(-2) {
            return Err("unknown TLV numid must be ENOENT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sound",
    smoke_alsa_control_errno_through_syscalls
);

fn smoke_alsa_xrun_epipe_does_not_raise_sigpipe() -> TestResult {
    if !sound_endpoint_available(true) {
        return TestResult::Skip("requires a playback /dev/snd endpoint");
    }
    with_setup(|| {
        let (fd, _) = install_sound(true)?;
        let mut params = pcm_params();
        set32(&mut params, 4, 1 << 3);
        if ioctl(fd, 0xc2604111, params.as_mut_ptr() as u64) != Some(0)
            || ioctl(fd, 0x4140, 0) != Some(0)
        {
            return Err("ALSA xrun configure");
        }
        let mut forward = 1u64;
        if ioctl(fd, 0x40084149, &mut forward as *mut u64 as u64) != Some(0)
            || ioctl(fd, 0x4142, 0) != Some(0)
            || ioctl(fd, 0x4148, 0) != Some(0)
        {
            return Err("ALSA force xrun");
        }
        crate::handlers::clear_signal_pending(FAKE_TASK, 13);
        let samples = [0u8; 32];
        if call(
            Syscall::Write.raw(),
            a2(fd as u64, samples.as_ptr() as u64, 32),
        ) != Some(-32)
        {
            return Err("ALSA write xrun must be EPIPE");
        }
        if crate::handlers::signal_pending_bits(FAKE_TASK) & crate::handlers::sig_bit(13) != 0 {
            return Err("ALSA xrun must not raise SIGPIPE");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sound",
    smoke_alsa_xrun_epipe_does_not_raise_sigpipe
);
