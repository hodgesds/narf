//! Exercise the registered filesystem nodes and backend leases together.
use crate::tests_support::poll_once;
use crate::{
    format::HwParams,
    hardware::{PcmDevice, PcmHardware},
    SoundError,
};
use alloc::{boxed::Box, format, string::String, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Default)]
struct Backend {
    claimed: [AtomicBool; 2],
    written: AtomicUsize,
    captured: AtomicUsize,
    starts: AtomicUsize,
    drains: AtomicUsize,
    configured: AtomicUsize,
}

#[derive(Debug)]
struct Card(Arc<Backend>);
#[derive(Debug)]
struct Stream {
    backend: Arc<Backend>,
    capture: bool,
}
impl PcmDevice for Card {
    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if device != 0 {
            return Err(SoundError::NoSuchDevice);
        }
        if self.0.claimed[usize::from(capture)].swap(true, Ordering::AcqRel) {
            return Err(SoundError::DeviceBusy);
        }
        Ok(Box::new(Stream {
            backend: self.0.clone(),
            capture,
        }))
    }
}
impl PcmHardware for Stream {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        self.backend
            .configured
            .store(params.rate.hz() as usize, Ordering::Release);
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        self.backend.starts.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        Ok(())
    }
    fn pointer(&self) -> u64 {
        self.backend.written.load(Ordering::Acquire) as u64 / 4
    }
    fn write(&mut self, data: &[u8]) -> Result<usize, SoundError> {
        self.backend.written.fetch_add(data.len(), Ordering::AcqRel);
        Ok(data.len())
    }
    fn read(&mut self, data: &mut [u8]) -> Result<usize, SoundError> {
        data.fill(0x5a);
        self.backend
            .captured
            .fetch_add(data.len(), Ordering::AcqRel);
        Ok(data.len())
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        self.backend.drains.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.backend.claimed[usize::from(self.capture)].store(false, Ordering::Release);
    }
}

struct Fixture {
    index: u32,
    backend: Arc<Backend>,
}
impl Fixture {
    fn new() -> Self {
        crate::sound_fs_initcall();
        let backend = Arc::new(Backend::default());
        let index = crate::register_hardware_card(
            crate::CardInfo {
                index: 0,
                driver: "namespace-test",
                id: "VFS",
                name: "VFS test card",
                playback_count: 1,
                capture_count: 1,
            },
            Arc::new(Card(backend.clone())),
        );
        Self { index, backend }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::unregister_hardware_card(self.index);
    }
}

fn sys(path: &str) -> Result<Arc<dyn FileOps>, &'static str> {
    poll_once(narf_filesystem::resolve_async(
        narf_filesystem::sysfs::SysFs::new().root(),
        path,
    ))
    .map_err(|_| "sysfs path does not resolve")
}
fn text(path: &str) -> Result<String, &'static str> {
    let file = sys(path)?;
    let mut buf = [0; 512];
    let n = poll_once(file.read(0, &mut buf)).map_err(|_| "sysfs read failed")?;
    String::from_utf8(buf[..n].into()).map_err(|_| "sysfs text is invalid")
}
fn dev(name: &str) -> Result<Arc<dyn FileOps>, &'static str> {
    narf_filesystem::devfs::DevFs::new()
        .root()
        .lookup_dir("snd")
        .and_then(|dir| dir.lookup(name))
        .ok_or("devfs sound node missing")
}
macro_rules! test {
    ($name:ident, $body:block) => {
        fn $name() -> TestResult {
            match (|| -> Result<(), &'static str> { $body })() {
                Ok(()) => TestResult::Pass,
                Err(why) => TestResult::Fail(why),
            }
        }
        kernel_test_in!("drivers/sound/namespace", $name);
    };
}

test!(sound_namespace_metadata_and_links, {
    let fixture = Fixture::new();
    let index = fixture.index;
    if text(&format!("class/sound/card{index}/id"))? != "VFS\n"
        || text(&format!("class/sound/card{index}/number"))? != format!("{index}\n")
        || text(&format!("class/sound/card{index}/longname"))? != "VFS test card\n"
    {
        return Err("sound card attributes are incorrect");
    }
    let class = sys("class/sound")?
        .as_dir()
        .ok_or("sound class is not a directory")?;
    let entries =
        poll_once(class.enumerate_async(0, usize::MAX)).map_err(|_| "class readdir failed")?;
    for (name, minor) in [
        (format!("controlC{index}"), index * 32),
        (format!("pcmC{index}D0p"), index * 32 + 16),
        (format!("pcmC{index}D0c"), index * 32 + 24),
    ] {
        if !entries
            .iter()
            .any(|(n, t)| n == &name && *t == FileType::Symlink)
        {
            return Err("class entry is not a discovery symlink");
        }
        let file = dev(&name)?;
        if file.rdev() != narf_filesystem::devfs::linux_makedev(116, minor)
            || file.stat().mode.file_type != FileType::Special
            || file.stat().mode.perms != 0o660
        {
            return Err("sound device stat is incorrect");
        }
        let path = format!("class/sound/{name}");
        if text(&format!("{path}/dev"))? != format!("116:{minor}\n")
            || sys(&format!("{path}/dev"))?.ino()
                != sys(&format!("dev/char/116:{minor}/dev"))?.ino()
        {
            return Err("devfs, class and dev/char disagree");
        }
        if sys(&format!("{path}/subsystem"))?.ino() != sys("class/sound")?.ino()
            || text(&format!("{path}/device/id"))? != "VFS\n"
        {
            return Err("sound subsystem or parent link is incorrect");
        }
        let event = text(&format!("{path}/uevent"))?;
        if !event.contains(&format!("MAJOR=116\nMINOR={minor}\nDEVNAME=snd/{name}\n")) {
            return Err("sound uevent lacks device identity");
        }
        if poll_once(sys(&format!("{path}/uevent"))?.write(0, b"change\n")).is_err() {
            return Err("sound uevent cannot be triggered");
        }
    }
    Ok(())
});

test!(sound_namespace_removal_preserves_open_lease, {
    let fixture = Fixture::new();
    let index = fixture.index;
    let file = dev(&format!("pcmC{index}D0p"))?;
    poll_once(file.write(0, &[0; 16])).map_err(|_| "initial PCM write failed")?;
    crate::unregister_hardware_card(index);
    for path in [
        format!("class/sound/card{index}"),
        format!("class/sound/controlC{index}"),
        format!("class/sound/pcmC{index}D0p"),
        format!("class/sound/pcmC{index}D0c"),
        format!("dev/char/116:{}", index * 32),
        format!("dev/char/116:{}", index * 32 + 16),
        format!("dev/char/116:{}", index * 32 + 24),
        format!("devices/virtual/sound/card{index}"),
    ] {
        if sys(&path).is_ok() {
            return Err("removed card left a sysfs entry");
        }
    }
    if dev(&format!("controlC{index}")).is_ok() || crate::open_playback(index, 0).is_ok() {
        return Err("removed card still accepts opens");
    }
    let proc_root = narf_filesystem::procfs::ProcFs.root();
    if poll_once(narf_filesystem::resolve_async(
        proc_root,
        &format!("asound/card{index}"),
    ))
    .is_ok()
    {
        return Err("removed card left a procfs entry");
    }
    poll_once(file.write(0, &[0; 16])).map_err(|_| "removal invalidated an open PCM lease")?;
    poll_once(file.flush()).map_err(|_| "PCM close flush did not drain")?;
    if fixture.backend.written.load(Ordering::Acquire) != 32
        || fixture.backend.drains.load(Ordering::Acquire) != 1
    {
        return Err("file I/O did not reach the backend");
    }
    drop(file);
    if fixture.backend.claimed[0].load(Ordering::Acquire) {
        return Err("PCM close leaked its lease");
    }
    Ok(())
});

test!(sound_capture_configuration_and_lazy_start, {
    let fixture = Fixture::new();
    let file = dev(&format!("pcmC{}D0c", fixture.index))?;
    let mut params = [0; 20];
    for (slot, value) in params.chunks_exact_mut(4).zip([0u32, 44100, 2, 1024, 4]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    poll_once(file.write(crate::devfs_bridge::HW_PARAMS_MAGIC_OFFSET, &params))
        .map_err(|_| "capture cannot configure its own PCM lease")?;
    if fixture.backend.configured.load(Ordering::Acquire) != 44100
        || fixture.backend.starts.load(Ordering::Acquire) != 0
    {
        return Err("capture configuration was ignored or started capture prematurely");
    }
    let mut samples = [0; 32];
    if poll_once(file.read(0, &mut samples)).map_err(|_| "capture read failed")? != 32
        || samples != [0x5a; 32]
        || fixture.backend.starts.load(Ordering::Acquire) != 1
    {
        return Err("capture file did not read the hardware backend");
    }
    drop(file);
    if fixture.backend.claimed[1].load(Ordering::Acquire) {
        return Err("capture close leaked its lease");
    }
    Ok(())
});

test!(sound_pcm_open_instances_own_exclusive_leases, {
    let fixture = Fixture::new();
    let node = dev(&format!("pcmC{}D0p", fixture.index))?;
    let first = node
        .open_instance_checked(true)
        .map_err(|_| "PCM open failed")?
        .ok_or("PCM open reused its lookup inode")?;
    if !matches!(
        node.open_instance_checked(true),
        Err(narf_filesystem::FsError::Busy)
    ) {
        return Err("second open shared the first PCM lease");
    }
    if fixture.backend.starts.load(Ordering::Acquire) != 0 {
        return Err("opening PCM started DMA");
    }
    drop(first);
    let reopened = node
        .open_instance_checked(true)
        .map_err(|_| "PCM close did not release lease")?
        .ok_or("PCM reopen reused its lookup inode")?;
    if reopened.ino() != node.ino() {
        return Err("PCM open changed device identity");
    }
    Ok(())
});

test!(sound_namespace_hotplug_events_and_idempotence, {
    use narf_filesystem::uevent::{UeventAction, UeventReader};
    let mut events = UeventReader::new();
    let fixture = Fixture::new();
    let path = format!("/devices/virtual/sound/card{}", fixture.index);
    let belongs = |event: &narf_filesystem::uevent::UeventEnv| {
        event.devpath == path || event.devpath.starts_with(&format!("{path}/"))
    };
    let added: alloc::vec::Vec<_> = events.drain(256).into_iter().filter(&belongs).collect();
    if added.len() != 5
        || !matches!(added[0].action, UeventAction::Add)
        || added[0].devpath != path
        || !matches!(added[4].action, UeventAction::Change)
        || added[4].devpath != path
        || added.iter().any(|event| event.subsystem != "sound")
    {
        return Err("sound ADD/initialization events are incomplete or unordered");
    }
    crate::sound_fs_initcall();
    if events.drain(256).iter().any(&belongs) {
        return Err("bridge init duplicated sound events");
    }
    crate::unregister_hardware_card(fixture.index);
    let removed: alloc::vec::Vec<_> = events.drain(256).into_iter().filter(belongs).collect();
    if removed.len() != 4
        || removed
            .iter()
            .any(|event| !matches!(event.action, UeventAction::Remove))
        || removed[3].devpath != path
    {
        return Err("sound REMOVE events are incomplete or unordered");
    }
    Ok(())
});

test!(sound_namespace_globals_and_invalid_names, {
    crate::sound_fs_initcall();
    for name in ["timer", "seq"] {
        if dev(name).is_ok() || sys(&format!("class/sound/{name}")).is_ok() {
            return Err("unimplemented global device is advertised");
        }
    }
    for name in ["pcmC0D0é", "pcmC0D0💿", "pcmC0D", "pcmC0D0x", "pcmCD0p"] {
        if dev(name).is_ok() {
            return Err("invalid PCM name resolved");
        }
    }
    Ok(())
});
