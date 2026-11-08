//! Preserve crash identity even when a large dump cannot be completed.
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_filesystem::{FsFuture, Mode, Stat};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Capture {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    calls: AtomicUsize,
    capacity: usize,
    chunk: usize,
}

impl Capture {
    fn new(capacity: usize, chunk: usize) -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(Vec::new()),
            calls: AtomicUsize::new(0),
            capacity,
            chunk,
        }
    }
}

impl FileOps for Capture {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let offset = offset as usize;
            if offset >= self.capacity {
                return Err(FsError::NoSpace);
            }
            let count = buf.len().min(self.chunk).min(self.capacity - offset);
            let mut bytes = self.bytes.lock();
            let size = bytes.len().max(offset + count);
            bytes.resize(size, 0);
            bytes[offset..offset + count].copy_from_slice(&buf[..count]);
            Ok(count)
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.bytes.lock().len() as u64,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

fn fixture(headers: usize) -> (Elf64_Ehdr, Vec<Elf64_Phdr>, Vec<u8>) {
    let notes = build_note_segment(
        &user_regs_struct::default(),
        &__test_prpsinfo(4242, b"greeter-crash"),
        &[],
    );
    let (phoff, note_offset, _) = metadata_offsets(headers, notes.len());
    let ehdr = Elf64_Ehdr {
        e_ident: [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: 4,
        e_phoff: phoff,
        e_ehsize: 64,
        e_phentsize: 56,
        e_phnum: headers as u16,
        ..Default::default()
    };
    let mut phdrs = alloc::vec![Elf64_Phdr::default(); headers];
    phdrs[0] = Elf64_Phdr {
        p_type: 4,
        p_offset: note_offset,
        p_filesz: notes.len() as u64,
        ..Default::default()
    };
    (ehdr, phdrs, notes)
}

fn smoke_coredump_interrupted_metadata_preserves_notes() -> TestResult {
    // The physical greeter's dump stopped after 822 of 853 headers, before
    // any registers or identity were saved. Simulate an even earlier stop.
    let (ehdr, phdrs, notes) = fixture(853);
    let file = Capture::new(4096, usize::MAX);
    if write_metadata(&file, u64::MAX, &ehdr, &phdrs, &notes).is_ok() {
        return TestResult::Fail("injected metadata write interruption was hidden");
    }
    let bytes = file.bytes.lock();
    let start = phdrs[0].p_offset as usize;
    if bytes.get(start..start + notes.len()) != Some(notes.as_slice()) {
        return TestResult::Fail("partial metadata lost crash registers and identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_interrupted_metadata_preserves_notes
);

fn smoke_coredump_metadata_batches_writes_and_retries_short_writes() -> TestResult {
    let (ehdr, phdrs, notes) = fixture(853);
    let full = Capture::new(usize::MAX, usize::MAX);
    if write_metadata(&full, u64::MAX, &ehdr, &phdrs, &notes).is_err()
        || full.calls.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("core metadata still needs a write per mapping");
    }
    let short = Capture::new(usize::MAX, 317);
    if write_metadata(&short, u64::MAX, &ehdr, &phdrs, &notes).is_err()
        || *full.bytes.lock() != *short.bytes.lock()
    {
        return TestResult::Fail("short metadata writes did not preserve every byte");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_metadata_batches_writes_and_retries_short_writes
);

fn smoke_coredump_zero_write_is_an_error() -> TestResult {
    let file = Capture::new(4096, 0);
    if write_at(&file, u64::MAX, 0, b"core").is_ok() {
        return TestResult::Fail("a zero-length write reported a completed core");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/coredump", smoke_coredump_zero_write_is_an_error);

/// Linux `vma_dump_size` dumps nothing for VM_IO/VM_PFNMAP mappings. A DRM
/// VRAM BAR mapping (WriteCombining device frames, here at 992 GiB, far above
/// the direct map) keeps its PT_LOAD size but no file bytes; reading it
/// through `kernel_ptr` faulted the kernel and froze the machine.
fn smoke_coredump_skips_device_mappings() -> TestResult {
    use narf_memory::address_space::{Region, RegionPerms};
    let bar = PhysAddr::new(0xf8_0000_0000);
    let Ok(backing) = narf_memory::region_backing::RegionBacking::try_from_slice(&[bar]) else {
        return TestResult::Fail("backing allocation");
    };
    let shared = RegionPerms(
        RegionPerms::READ.0
            | RegionPerms::WRITE.0
            | RegionPerms::SHARED.0
            | RegionPerms::LOCK_EXEMPT.0,
    );
    let device = Region {
        base: narf_memory::VirtAddr::new(0x7000_0000),
        len: 4096,
        perms: shared.with_memory_type(narf_memory::MemoryType::WriteCombining),
        phys: backing.clone(),
    };
    let write_back = Region {
        perms: shared,
        ..device.clone()
    };
    let anon = Region {
        perms: RegionPerms(RegionPerms::READ.0 | RegionPerms::WRITE.0),
        ..device.clone()
    };
    if dump_len(&device) != 0 {
        return TestResult::Fail("device (VRAM BAR) mapping would be read into the core");
    }
    if dump_len(&write_back) != 4096 || dump_len(&anon) != 4096 {
        return TestResult::Fail("write-back mappings must still be dumped");
    }
    // The per-page guard: a non-RAM frame is never dereferenced.
    if narf_memory::frame::is_system_ram(bar) {
        return TestResult::Fail("a 992 GiB BAR frame classified as System RAM");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/coredump", smoke_coredump_skips_device_mappings);

fn smoke_coredump_sparse_anonymous_trimmed() -> TestResult {
    use narf_memory::address_space::{Region, RegionPerms};
    let anon_perms = RegionPerms(RegionPerms::READ.0 | RegionPerms::WRITE.0);
    let empty_region = Region {
        base: narf_memory::VirtAddr::new(0x1000_0000),
        len: 64 * 1024 * 1024,
        perms: anon_perms,
        phys: narf_memory::region_backing::RegionBacking::new(),
    };
    if dump_len(&empty_region) != 0 {
        return TestResult::Fail("unbacked sparse region must dump 0 bytes");
    }

    let mut sparse_backing = narf_memory::region_backing::RegionBacking::new();
    if sparse_backing.reserve_slot(2).is_err() {
        return TestResult::Fail("backing reservation failed");
    }
    if let Some(slot) = sparse_backing.get_mut(2) {
        *slot = PhysAddr::new(0x2000);
    } else {
        return TestResult::Fail("backing slot 2 absent");
    }
    let sparse_region = Region {
        base: narf_memory::VirtAddr::new(0x1000_0000),
        len: 64 * 1024 * 1024,
        perms: anon_perms,
        phys: sparse_backing,
    };
    if dump_len(&sparse_region) != 3 * 4096 {
        return TestResult::Fail("sparse region must only dump up to highest resident page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_sparse_anonymous_trimmed
);
