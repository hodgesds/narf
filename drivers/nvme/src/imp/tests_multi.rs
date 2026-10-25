//! Multi-controller NVMe smokes: a model of two controllers registering
//! their namespaces (naming, identity, partition scan, `narf.disks` guard,
//! controller-node policy), the namespace-scan decoders, and — under
//! QEMU with two `-device nvme` — data integrity, distinct identities and
//! per-controller teardown on the real driver.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_block::disk_policy::{self, DiskPolicy};
use narf_block::{BlockDeviceSync, BlockIoError};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::ns::{self, ControllerIdentity, NamespaceInfo, NsIds, NsSkip};

// ── In-memory disk ─────────────────────────────────────────────────

/// Byte-addressed RAM disk that counts the writes reaching it.
struct MemDisk {
    data: IrqSafeSpinLock<Vec<u8>>,
    lba: u32,
    writes: AtomicU64,
}

impl MemDisk {
    fn new(image: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            data: IrqSafeSpinLock::new(image),
            lba: 512,
            writes: AtomicU64::new(0),
        })
    }
}

impl BlockDeviceSync for MemDisk {
    fn lba_size(&self) -> u32 {
        self.lba
    }
    fn capacity(&self) -> u64 {
        (self.data.lock().len() / self.lba as usize) as u64
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let g = self.data.lock();
        let at = lba as usize * self.lba as usize;
        let len = n as usize * self.lba as usize;
        let src = g.get(at..at + len).ok_or(BlockIoError::OutOfRange)?;
        out.get_mut(..len)
            .ok_or(BlockIoError::BufferTooSmall)?
            .copy_from_slice(src);
        Ok(())
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let mut g = self.data.lock();
        let at = lba as usize * self.lba as usize;
        let len = n as usize * self.lba as usize;
        g.get_mut(at..at + len)
            .ok_or(BlockIoError::OutOfRange)?
            .copy_from_slice(data.get(..len).ok_or(BlockIoError::BufferTooSmall)?);
        Ok(())
    }
}

/// One GPT partition for [`gpt_disk`]: start LBA, length, PARTUUID bytes.
struct Part {
    start: u64,
    len: u64,
    guid: [u8; 16],
}

/// 4 MiB disk with a protective MBR, a GPT header and `parts`.
fn gpt_disk(parts: &[Part]) -> Vec<u8> {
    let mut img = vec![0u8; 4 * 1024 * 1024];
    // Protective MBR.
    img[446 + 4] = 0xEE;
    img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    img[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    // GPT header at LBA 1, entries at LBA 2.
    let h = &mut img[512..1024];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    h[40..48].copy_from_slice(&34u64.to_le_bytes());
    h[48..56].copy_from_slice(&8158u64.to_le_bytes());
    h[72..80].copy_from_slice(&2u64.to_le_bytes());
    h[80..84].copy_from_slice(&128u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    for (i, p) in parts.iter().enumerate() {
        let e = &mut img[1024 + i * 128..1024 + (i + 1) * 128];
        // Linux filesystem data type GUID.
        e[0..16].copy_from_slice(&[
            0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47,
            0x7D, 0xE4,
        ]);
        e[16..32].copy_from_slice(&p.guid);
        e[32..40].copy_from_slice(&p.start.to_le_bytes());
        e[40..48].copy_from_slice(&(p.start + p.len - 1).to_le_bytes());
    }
    img
}

/// Put a btrfs superblock (magic + `fsid`) into the partition at `start`.
fn put_btrfs(img: &mut [u8], start: u64, fsid: [u8; 16]) {
    let sb = start as usize * 512 + 0x1_0000;
    img[sb + 0x20..sb + 0x30].copy_from_slice(&fsid);
    img[sb + 0x40..sb + 0x48].copy_from_slice(b"_BHRfS_M");
}

/// Put an ext superblock (magic + UUID) into the partition at `start`.
fn put_ext(img: &mut [u8], start: u64, uuid: [u8; 16]) {
    let sb = start as usize * 512 + 1024;
    img[sb + 0x38] = 0x53;
    img[sb + 0x39] = 0xEF;
    img[sb + 0x68..sb + 0x78].copy_from_slice(&uuid);
}

const ROOT_FSID: [u8; 16] = [
    0x65, 0x36, 0x02, 0xc3, 0xcd, 0x42, 0x42, 0x0e, 0x95, 0xef, 0x4c, 0x40, 0x33, 0xd1, 0x7b, 0x56,
];
const ROOT_FSID_STR: &str = "653602c3-cd42-420e-95ef-4c4033d17b56";
const DATA_UUID: [u8; 16] = [
    0x15, 0xd0, 0x44, 0xdb, 0x0c, 0x09, 0x4e, 0xc4, 0xa2, 0xd6, 0xcc, 0xd1, 0xf9, 0x2e, 0x4d, 0xd6,
];
const DATA_UUID_STR: &str = "15d044db-0c09-4ec4-a2d6-ccd1f92e4dd6";

fn ns_info(nsid: u32, ids: NsIds) -> NamespaceInfo {
    NamespaceInfo {
        nsid,
        lba_bytes: 512,
        nsze: 8192,
        usable: true,
        ids,
    }
}

/// The two host controllers of the CachyOS machine, as test data:
/// `(identity, namespaces, disks)` — the Sabrent data disk and the WD root
/// disk (with a second, unpartitioned namespace).
struct ModelCtrl {
    ident: ControllerIdentity,
    namespaces: Vec<NamespaceInfo>,
    disks: Vec<Arc<MemDisk>>,
}

fn model_controllers() -> (ModelCtrl, ModelCtrl) {
    let mut sabrent = gpt_disk(&[
        Part {
            start: 2048,
            len: 2048,
            guid: [0xA1; 16],
        },
        Part {
            start: 4096,
            len: 4062,
            guid: [0xA2; 16],
        },
    ]);
    put_ext(&mut sabrent, 4096, DATA_UUID);
    let mut wd = gpt_disk(&[
        Part {
            start: 2048,
            len: 2048,
            guid: [0xB1; 16],
        },
        Part {
            start: 4096,
            len: 4062,
            guid: [0xB2; 16],
        },
    ]);
    put_btrfs(&mut wd, 4096, ROOT_FSID);
    let a = ModelCtrl {
        ident: ControllerIdentity {
            instance: 0,
            bus_path: String::from("0000:04:00.0"),
            vendor_id: 0x1987,
            model: String::from("Sabrent Rocket 4.0 1TB"),
            serial: String::from("SAB0001"),
            firmware: String::from("RKT401.3"),
        },
        namespaces: vec![ns_info(
            1,
            NsIds {
                eui64: Some([0x64, 0x79, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x01]),
                ..NsIds::default()
            },
        )],
        disks: vec![MemDisk::new(sabrent)],
    };
    let b = ModelCtrl {
        ident: ControllerIdentity {
            instance: 1,
            bus_path: String::from("0000:07:00.0"),
            vendor_id: 0x15b7,
            model: String::from("WD_BLACK SN770 2TB"),
            serial: String::from("WD0002"),
            firmware: String::from("731100WD"),
        },
        namespaces: vec![
            ns_info(
                1,
                NsIds {
                    nguid: Some([0xE8; 16]),
                    uuid: Some([0x11; 16]),
                    ..NsIds::default()
                },
            ),
            // Sparse NSID: still the controller's second namespace, `n2`.
            ns_info(3, NsIds::default()),
        ],
        disks: vec![MemDisk::new(wd), MemDisk::new(vec![0u8; 1024 * 1024])],
    };
    (a, b)
}

/// Register `c` under probe-order `instance` (overriding its identity's).
fn register_model(c: &ModelCtrl, instance: u32) -> Vec<&'static str> {
    let mut ident = c.ident.clone();
    ident.instance = instance;
    let disks = c.disks.clone();
    let nsids: Vec<u32> = c.namespaces.iter().map(|n| n.nsid).collect();
    ns::register_namespaces(&ident, &c.namespaces, |nsid| {
        let i = nsids.iter().position(|&n| n == nsid).unwrap_or(0);
        disks[i].clone() as Arc<dyn BlockDeviceSync>
    })
}

fn bus_path_of(name: &str) -> Option<String> {
    narf_block::identity_of(name).map(|i| i.bus_path.clone())
}

/// Two controllers through the driver's registration path: Linux names in
/// probe order, a partition scan on every namespace, identity inherited by
/// partitions, and the root found by filesystem UUID whichever controller
/// enumerates first.
fn smoke_nvme_two_controller_model() -> TestResult {
    use narf_block::registry::{__restore_for_test, __snapshot_for_test};
    let snap = __snapshot_for_test();
    let r = two_controller_model();
    __restore_for_test(snap);
    r
}

fn two_controller_model() -> TestResult {
    // Instances 70/71 keep the model clear of the live nvme0/nvme1.
    let (sabrent, wd) = model_controllers();
    let a = register_model(&sabrent, 70);
    let b = register_model(&wd, 71);
    if a != ["nvme70n1"] || b != ["nvme71n1", "nvme71n2"] {
        return TestResult::Fail("namespace names are not nvme<C>n<N> in scan order");
    }
    for name in ["nvme70n1p1", "nvme70n1p2", "nvme71n1p1", "nvme71n1p2"] {
        if narf_block::find_block_device(name).is_none() {
            return TestResult::Fail("partition scan missed a namespace partition");
        }
    }
    if narf_block::find_block_device("nvme71n2p1").is_some() {
        return TestResult::Fail("unpartitioned namespace grew a partition");
    }
    // Identity, inherited by partitions.
    let Some(root_id) = narf_block::identity_of("nvme71n1p2") else {
        return TestResult::Fail("partition has no identity");
    };
    if root_id.bus_path != "0000:07:00.0" || root_id.nsid != 1 || root_id.serial != "WD0002" {
        return TestResult::Fail("partition identity is not its disk's");
    }
    if root_id.wwid() != "uuid.11111111-1111-1111-1111-111111111111" {
        return TestResult::Fail("wwid must prefer the namespace UUID");
    }
    match narf_block::identity_of("nvme70n1").map(|i| i.wwid()) {
        Some(w) if w == "eui.6479a70000000001" => {}
        _ => return TestResult::Fail("wwid must fall back to EUI64"),
    }
    match narf_block::identity_of("nvme71n2").map(|i| i.wwid()) {
        Some(w) if w == "nvme.15b7-WD0002-WD_BLACK_SN770_2TB-00000003" => {}
        _ => return TestResult::Fail("wwid fallback is not vid-serial-model-nsid"),
    }
    if narf_block::disk_of("nvme70n1") == narf_block::disk_of("nvme71n1")
        || narf_block::disk_of("nvme71n1") == narf_block::disk_of("nvme71n2")
        || narf_block::disk_of("nvme71n1") != narf_block::disk_of("nvme71n1p2")
    {
        return TestResult::Fail("disk identities must be per namespace, shared by partitions");
    }
    // Filesystem UUIDs found by content.
    match narf_block::find_by_fs_uuid(ROOT_FSID_STR) {
        Some(e) if e.name == "nvme71n1p2" => {}
        _ => return TestResult::Fail("btrfs fsid not discovered on the WD root partition"),
    }
    match narf_block::find_by_fs_uuid(DATA_UUID_STR) {
        Some(e) if e.name == "nvme70n1p2" => {}
        _ => return TestResult::Fail("ext UUID not discovered on the Sabrent data partition"),
    }
    match narf_block::find_disk_by_bus_path("0000:07:00.0", 3) {
        Some(e) if e.name == "nvme71n2" => {}
        _ => return TestResult::Fail("find_disk_by_bus_path missed the sparse namespace"),
    }
    // /dev/disk/by-id and by-path.
    match narf_filesystem::devfs_block::by_id_target("nvme-WD_BLACK_SN770_2TB_WD0002-part2") {
        Some("nvme71n1p2") => {}
        _ => return TestResult::Fail("by-id model_serial-partN link missing"),
    }
    match narf_filesystem::devfs_block::by_id_target("nvme-WD_BLACK_SN770_2TB_WD0002_3") {
        Some("nvme71n2") => {}
        _ => return TestResult::Fail("by-id model_serial_nsid link missing"),
    }
    match narf_filesystem::devfs_block::by_path_target("pci-0000:04:00.0-nvme-1-part2") {
        Some("nvme70n1p2") => {}
        _ => return TestResult::Fail("by-path link missing"),
    }

    // Enumeration order swapped: names move, identity and UUIDs do not.
    for e in narf_block::block_devices() {
        if e.name.starts_with("nvme70") || e.name.starts_with("nvme71") {
            narf_block::unregister_block_device(e.name);
        }
    }
    let (sabrent, wd) = model_controllers();
    register_model(&wd, 70);
    register_model(&sabrent, 71);
    match narf_block::find_by_fs_uuid(ROOT_FSID_STR) {
        Some(e) if e.name == "nvme70n1p2" => {}
        _ => return TestResult::Fail("root not found by UUID after reordering"),
    }
    if bus_path_of("nvme70n1p2").as_deref() != Some("0000:07:00.0")
        || bus_path_of("nvme71n1").as_deref() != Some("0000:04:00.0")
    {
        return TestResult::Fail("identity did not follow the disk across reordering");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/multi", smoke_nvme_two_controller_model);

/// `narf.disks=boot-only` over two controllers: every namespace and
/// partition is behind the guard and write-refused, nothing reaches the
/// media, and trusting one disk makes exactly that disk writable. The
/// `/dev/nvme<C>` passthrough follows the same rule per controller.
fn smoke_nvme_two_controller_policy_guard() -> TestResult {
    use narf_block::registry::{__restore_for_test, __snapshot_for_test};
    let snap = __snapshot_for_test();
    disk_policy::__set_policy_for_test(Some(DiskPolicy::BootOnly));
    disk_policy::__reset_trust_for_test();
    let r = two_controller_policy_guard();
    disk_policy::__reset_trust_for_test();
    disk_policy::__set_policy_for_test(None);
    narf_filesystem::devfs::unregister_nvme_controller(70);
    narf_filesystem::devfs::unregister_nvme_controller(71);
    __restore_for_test(snap);
    r
}

#[derive(Debug)]
struct NullNode;
impl narf_filesystem::FileOps for NullNode {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        let n = b.len();
        alloc::boxed::Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
}

fn two_controller_policy_guard() -> TestResult {
    const ADMIN_CMD: u32 = 0xC048_4E41;
    const IOCTL_ID: u32 = 0x4E40;
    let (sabrent, wd) = model_controllers();
    let a = register_model(&sabrent, 70);
    let b = register_model(&wd, 71);
    narf_filesystem::devfs::register_nvme_controller(70, Arc::new(NullNode), a.clone());
    narf_filesystem::devfs::register_nvme_controller(71, Arc::new(NullNode), b.clone());
    let block = vec![0x5Au8; 512];
    let ours = |name: &str| name.starts_with("nvme70") || name.starts_with("nvme71");
    let entries: Vec<_> = narf_block::block_devices()
        .into_iter()
        .filter(|e| ours(e.name))
        .collect();
    if entries.len() != 7 {
        return TestResult::Fail("expected 3 namespaces + 4 partitions registered");
    }
    for e in &entries {
        if !e.dev.is_read_only() || e.dev.write(0, 1, &block) != Err(BlockIoError::ReadOnly) {
            return TestResult::Fail("an untrusted namespace/partition accepted a write");
        }
    }
    let media_writes = |c: &ModelCtrl| {
        c.disks
            .iter()
            .map(|d| d.writes.load(Ordering::Relaxed))
            .sum::<u64>()
    };
    if media_writes(&sabrent) != 0 || media_writes(&wd) != 0 {
        return TestResult::Fail("a refused write reached the media");
    }
    if narf_filesystem::devfs::__nvme_passthrough_allowed_for_test(71, ADMIN_CMD) != Some(false)
        || narf_filesystem::devfs::__nvme_passthrough_allowed_for_test(71, IOCTL_ID) != Some(true)
    {
        return TestResult::Fail("untrusted controller passthrough not closed");
    }

    // Trust exactly the WD root namespace.
    let Some(disk) = narf_block::disk_of("nvme71n1") else {
        return TestResult::Fail("nvme71n1 vanished");
    };
    disk_policy::trust_boot_medium("nvme71n1", disk);
    for e in &entries {
        let should = e.name == "nvme71n1" || e.name.starts_with("nvme71n1p");
        if e.dev.is_read_only() == should {
            return TestResult::Fail("trust leaked beyond, or missed, the trusted disk");
        }
    }
    let Some(p2) = narf_block::find_block_device("nvme71n1p2") else {
        return TestResult::Fail("nvme71n1p2 vanished");
    };
    if p2.write(0, 1, &block).is_err() || wd.disks[0].writes.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("trusted partition write did not reach its disk");
    }
    if media_writes(&sabrent) != 0 || wd.disks[1].writes.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("trusting one namespace made another writable");
    }
    // nvme71 also has the untrusted n2: its passthrough stays closed;
    // a controller whose only namespace is trusted opens.
    if narf_filesystem::devfs::__nvme_passthrough_allowed_for_test(71, ADMIN_CMD) != Some(false) {
        return TestResult::Fail("passthrough opened with an untrusted namespace on it");
    }
    narf_filesystem::devfs::register_nvme_controller(71, Arc::new(NullNode), vec!["nvme71n1"]);
    if narf_filesystem::devfs::__nvme_passthrough_allowed_for_test(71, ADMIN_CMD) != Some(true)
        || narf_filesystem::devfs::__nvme_passthrough_allowed_for_test(70, ADMIN_CMD) != Some(false)
    {
        return TestResult::Fail("passthrough policy is not per controller");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/multi", smoke_nvme_two_controller_policy_guard);

/// Namespace-scan decoders: inactive / zero-capacity / metadata formats
/// are skipped, Identify Namespace NGUID/EUI64 and the descriptor list
/// decode, NSID lists terminate, and names count from 1.
fn smoke_nvme_namespace_scan_decode() -> TestResult {
    let mut page = vec![0u8; 4096];
    // NSZE = NCAP = 1000, FLBAS 0 → LBAF0 LBADS 9 (512 B), MS 0.
    page[0..8].copy_from_slice(&1000u64.to_le_bytes());
    page[8..16].copy_from_slice(&1000u64.to_le_bytes());
    page[128 + 2] = 9;
    page[104..120].copy_from_slice(&[0x42; 16]);
    page[120..128].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
    let info = match ns::classify_namespace(5, &page) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("usable namespace classified as skipped"),
    };
    if info.nsid != 5 || info.lba_bytes != 512 || info.nsze != 1000 {
        return TestResult::Fail("namespace geometry decode wrong");
    }
    if info.ids.nguid != Some([0x42; 16]) || info.ids.eui64 != Some([0, 0, 0, 0, 0, 0, 0, 7]) {
        return TestResult::Fail("Identify Namespace NGUID/EUI64 decode wrong");
    }
    let mut inactive = page.clone();
    inactive[8..16].fill(0);
    let mut zero = page.clone();
    zero[0..8].fill(0);
    let mut meta = page.clone();
    meta[128] = 8; // MS = 8 bytes per block
    if ns::classify_namespace(1, &inactive) != Err(NsSkip::Inactive)
        || ns::classify_namespace(1, &zero) != Err(NsSkip::ZeroCapacity)
        || ns::classify_namespace(1, &meta) != Err(NsSkip::UnusableFormat)
    {
        return TestResult::Fail("inactive / zero-capacity / metadata namespace not skipped");
    }
    // Descriptor list: EUI64, NGUID, UUID, CSI, then terminator.
    let mut list = vec![0u8; 4096];
    let mut at = 0;
    for (nidt, nid) in [
        (1u8, &[9u8; 8][..]),
        (2, &[8u8; 16][..]),
        (3, &[7u8; 16][..]),
        (4, &[0u8; 1][..]),
    ] {
        list[at] = nidt;
        list[at + 1] = nid.len() as u8;
        list[at + 4..at + 4 + nid.len()].copy_from_slice(nid);
        at += 4 + nid.len();
    }
    let mut ids = info.ids;
    ns::apply_ns_descriptors(&list, &mut ids);
    if ids.eui64 != Some([9; 8]) || ids.nguid != Some([8; 16]) || ids.uuid != Some([7; 16]) {
        return TestResult::Fail("descriptor list decode wrong");
    }
    // A wrong-length descriptor ends the walk, keeping earlier ids.
    let mut bad = vec![0u8; 64];
    bad[0] = 3;
    bad[1] = 8;
    let mut ids2 = NsIds::default();
    ns::apply_ns_descriptors(&bad, &mut ids2);
    if ids2 != NsIds::default() {
        return TestResult::Fail("malformed UUID descriptor accepted");
    }
    let mut nl = vec![0u8; 4096];
    nl[0..4].copy_from_slice(&1u32.to_le_bytes());
    nl[4..8].copy_from_slice(&4u32.to_le_bytes());
    if ns::decode_ns_list(&nl) != [1, 4] {
        return TestResult::Fail("active NSID list decode wrong");
    }
    if !ns::use_ns_list(0x0001_0100)
        || ns::use_ns_list(0x0001_0000)
        || !ns::use_ns_descriptors(0x0001_0300)
        || ns::use_ns_descriptors(0x0001_0200)
    {
        return TestResult::Fail("version gates differ from Linux nvme_scan_work");
    }
    if ns::namespace_name(1, 0) != "nvme1n1"
        || ns::controller_name(1) != "nvme1"
        || ns::trim_ascii(b"WD_BLACK SN770 2TB      ") != "WD_BLACK SN770 2TB"
    {
        return TestResult::Fail("naming / trimming wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/multi", smoke_nvme_namespace_scan_decode);

// ── QEMU: two real controllers ─────────────────────────────────────

/// LBA window the QEMU smokes scribble on (then restore): past both images'
/// partition tables (the GPT entries end at LBA 33) and inside the first
/// 64 KiB that btrfs leaves unused on nvme0's fixture.
const SCRATCH_LBA: u64 = 40;
/// 40 × 512 B = 20 KiB: a PRP-list transfer (more than two pages).
const SCRATCH_BLOCKS: u16 = 40;

fn pattern(seed: u8) -> Vec<u8> {
    (0..SCRATCH_BLOCKS as usize * 512)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// Re-bring-up controller `instance` on its own PCI function and reinstall
/// it in place. Other smokes in this crate reset the first QEMU controller
/// from stack-local `Controller`s (orphaning the probed queues); this gives
/// the multi-controller smokes a live controller regardless of order.
fn reinstall(instance: u32) -> Result<(), &'static str> {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    let Some(Some(dev)) = super::with_controller_at(instance, |c| c.bus_device()) else {
        return Err("installed controller has no bus device");
    };
    let authority = bootstrap_registry_authority();
    let (_h, cap) =
        claim_device_cap(&authority, dev.addr).map_err(|_| "claim_device_cap failed")?;
    let mut ctrl = super::Controller::from_device(dev);
    ctrl.bring_up(&cap).map_err(|_| "bring_up failed")?;
    if ctrl.create_io_queue().is_err() {
        ctrl.disable_after_failure(&cap);
        return Err("create_io_queue failed");
    }
    if super::install_controller(ctrl) != instance {
        return Err("reinstall moved the controller to another instance");
    }
    Ok(())
}

/// With two QEMU NVMe controllers: both probed as distinct instances with
/// distinct identities, both registered (`nvme0n1`, `nvme1n1`, the second
/// image's partition), and data written through each lands on that
/// controller only.
fn smoke_nvme_two_controllers_qemu() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs two NVMe controllers");
    }
    for i in 0..2 {
        if let Err(e) = reinstall(i) {
            return TestResult::Fail(e);
        }
    }
    let ids: Vec<_> = (0..2)
        .map(|i| {
            super::with_controller_at(i, |c| {
                (
                    c.bus_device().map(|d| d.addr),
                    c.identify().map(|id| ns::trim_ascii(&id.sn)),
                    c.namespaces().len(),
                )
            })
        })
        .collect();
    let (Some(a), Some(b)) = (&ids[0], &ids[1]) else {
        return TestResult::Fail("an installed controller is not reachable");
    };
    if a.0 == b.0 || a.1 == b.1 {
        return TestResult::Fail("the two controllers share a PCI address or serial");
    }
    if a.2 == 0 || b.2 == 0 {
        return TestResult::Fail("a controller registered no namespace");
    }
    let (Some(d0), Some(d1)) = (
        narf_block::find_block_device("nvme0n1"),
        narf_block::find_block_device("nvme1n1"),
    ) else {
        return TestResult::Fail("nvme0n1 / nvme1n1 not registered");
    };
    let (Some(i0), Some(i1)) = (
        narf_block::identity_of("nvme0n1"),
        narf_block::identity_of("nvme1n1"),
    ) else {
        return TestResult::Fail("namespace without identity");
    };
    if i0.bus_path == i1.bus_path || i0.serial == i1.serial || i0.wwid() == i1.wwid() {
        return TestResult::Fail("nvme0n1 and nvme1n1 identities are not distinct");
    }
    if i1.serial != "narf2" {
        return TestResult::Fail("nvme1 is not the second QEMU controller (serial narf2)");
    }
    if narf_block::find_block_device("nvme1n1p1").is_none() {
        return TestResult::Fail("second controller's GPT not partition-scanned");
    }
    if narf_block::disk_of("nvme0n1") == narf_block::disk_of("nvme1n1") {
        return TestResult::Fail("two namespaces share a policy disk id");
    }

    let n = SCRATCH_BLOCKS;
    let len = n as usize * 512;
    let mut saved0 = vec![0u8; len];
    let mut saved1 = vec![0u8; len];
    if d0.read(SCRATCH_LBA, n, &mut saved0).is_err()
        || d1.read(SCRATCH_LBA, n, &mut saved1).is_err()
    {
        return TestResult::Fail("initial read failed");
    }
    let (p0, p1) = (pattern(0x30), pattern(0xC1));
    let wrote = d0.write(SCRATCH_LBA, n, &p0).is_ok() && d1.write(SCRATCH_LBA, n, &p1).is_ok();
    let mut back0 = vec![0u8; len];
    let mut back1 = vec![0u8; len];
    let read =
        d0.read(SCRATCH_LBA, n, &mut back0).is_ok() && d1.read(SCRATCH_LBA, n, &mut back1).is_ok();
    let restored =
        d0.write(SCRATCH_LBA, n, &saved0).is_ok() && d1.write(SCRATCH_LBA, n, &saved1).is_ok();
    if !wrote || !read {
        return TestResult::Fail("pattern write / read-back failed");
    }
    if back0 != p0 || back1 != p1 {
        return TestResult::Fail("data crossed controllers or did not round-trip");
    }
    if !restored {
        return TestResult::Fail("restoring the scratch window failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/multi", smoke_nvme_two_controllers_qemu);

/// Per-controller teardown on real hardware: removing `nvme1` withdraws
/// its block devices and node, stops it (CC.EN=0 confirmed before DMA is
/// freed), refuses I/O to it, leaves `nvme0` untouched, and a re-probe
/// brings it back under the same instance with working I/O.
fn smoke_nvme_controller_teardown_and_reprobe_qemu() -> TestResult {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    if super::controller_count() < 2 {
        return TestResult::Skip("needs two NVMe controllers");
    }
    for i in 0..2 {
        if let Err(e) = reinstall(i) {
            return TestResult::Fail(e);
        }
    }
    let Some(Some(dev)) = super::with_controller_at(1, |c| c.bus_device()) else {
        return TestResult::Fail("nvme1 has no bus device");
    };
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return TestResult::Fail("claim_device_cap(nvme1) failed");
    };
    let slot0 = super::dbg_slot_addr_at(0);
    match super::remove_controller(1, &cap) {
        Some(true) => {}
        Some(false) => return TestResult::Fail("nvme1 did not confirm CC.EN=0 / RDY=0"),
        None => return TestResult::Fail("nvme1 not installed"),
    }
    if narf_block::find_block_device("nvme1n1").is_some()
        || narf_block::find_block_device("nvme1n1p1").is_some()
    {
        return TestResult::Fail("removed controller's block devices still registered");
    }
    let mut sector = [0u8; 512];
    if super::NvmeNamespaceBlock::new(1, 1).read(0, 1, &mut sector)
        != Err(BlockIoError::DeviceRemoved)
    {
        return TestResult::Fail("I/O to a removed controller was not refused");
    }
    if super::dbg_slot_addr_at(0) != slot0 {
        return TestResult::Fail("removing nvme1 replaced nvme0's slot");
    }
    let Some(d0) = narf_block::find_block_device("nvme0n1") else {
        return TestResult::Fail("removing nvme1 unregistered nvme0n1");
    };
    if let Err(e) = d0.read(0, 1, &mut sector) {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "nvme teardown: nvme0n1 read: {e:?}");
        return TestResult::Fail("nvme0n1 I/O failed after removing nvme1");
    }
    // Re-probe: same PCI function, same instance, working I/O.
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return TestResult::Fail("claim_device_cap(nvme1) failed after removal");
    };
    if super::probe(dev, cap).is_err() {
        return TestResult::Fail("re-probe of nvme1 failed");
    }
    if super::instance_of(match dev.addr {
        narf_bus::BusAddr::Pcie(a) => a,
        _ => return TestResult::Fail("nvme1 is not PCIe"),
    }) != Some(1)
    {
        return TestResult::Fail("re-probe changed nvme1's instance");
    }
    match narf_block::find_block_device("nvme1n1") {
        Some(d) if d.read(0, 1, &mut sector).is_ok() => TestResult::Pass,
        _ => TestResult::Fail("nvme1n1 not back after re-probe"),
    }
}
kernel_test_in!(
    "drivers/nvme/multi",
    smoke_nvme_controller_teardown_and_reprobe_qemu
);

// ── Reset / recovery (audit #929) ──────────────────────────────────
//
// `Controller::reset_recover` + the dead-controller triggers in the
// block entry points + the identity verdict, and the bus Detach
// path into `remove_controller`.

/// Build an IDENTIFY snapshot for verdict comparisons.
fn verdict_id(sn: u8, fr: u8) -> super::IdentifyController {
    super::IdentifyController {
        vid: 0x144d,
        ssvid: 0,
        sn: [sn; 20],
        mn: [b'M'; 40],
        fr: [fr; 8],
        mdts: 0,
        ver: 0x0001_0400,
        nn: 1,
        rtd3e: 0,
        vwc: 0,
    }
}

fn verdict_ns(nsid: u32, eui: u8) -> NamespaceInfo {
    NamespaceInfo {
        nsid,
        lba_bytes: 512,
        nsze: 1_000_000,
        usable: true,
        ids: NsIds {
            eui64: Some([eui; 8]),
            nguid: None,
            uuid: None,
        },
    }
}

/// The recovery identity verdict, as a pure model: firmware revision
/// is not identity; serial/model changes are a different controller;
/// any namespace-set change (membership, geometry, EUI64) is
/// reported, not silently adopted.
fn smoke_nvme_recovery_identity_verdicts() -> TestResult {
    use super::{recovery_verdict, RecoveryVerdict};
    let id = verdict_id(0x41, 0x31);
    let ns = [verdict_ns(1, 0xE1)];
    if recovery_verdict(&id, &ns, &id, &ns) != RecoveryVerdict::Unchanged {
        return TestResult::Fail("identical snapshots judged changed");
    }
    // Firmware revision differs: still the same controller + set.
    let newer_fw = verdict_id(0x41, 0x32);
    if recovery_verdict(&id, &ns, &newer_fw, &ns) != RecoveryVerdict::Unchanged {
        return TestResult::Fail("firmware revision treated as identity");
    }
    // Serial differs: a different controller answers at the function.
    let swapped = verdict_id(0x42, 0x31);
    if recovery_verdict(&id, &ns, &swapped, &ns) != RecoveryVerdict::ControllerChanged {
        return TestResult::Fail("serial change not judged a controller change");
    }
    // Namespace added / removed / re-identified / resized.
    let two = [verdict_ns(1, 0xE1), verdict_ns(2, 0xE2)];
    if recovery_verdict(&id, &ns, &id, &two) != RecoveryVerdict::NamespacesChanged {
        return TestResult::Fail("namespace addition not reported");
    }
    if recovery_verdict(&id, &two, &id, &ns) != RecoveryVerdict::NamespacesChanged {
        return TestResult::Fail("namespace removal not reported");
    }
    let reidentified = [verdict_ns(1, 0xE9)];
    if recovery_verdict(&id, &ns, &id, &reidentified) != RecoveryVerdict::NamespacesChanged {
        return TestResult::Fail("namespace EUI64 change not reported");
    }
    let mut resized = verdict_ns(1, 0xE1);
    resized.nsze += 1;
    if recovery_verdict(&id, &ns, &id, &[resized]) != RecoveryVerdict::NamespacesChanged {
        return TestResult::Fail("namespace geometry change not reported");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/multi", smoke_nvme_recovery_identity_verdicts);

/// QEMU, one controller: mark the installed controller dead — the
/// exact state a command timeout leaves — then prove the next block
/// read recovers it in place (reset, re-identify, I/O resumes, data
/// intact) instead of refusing with ControllerDead forever. The
/// flush entry point recovers the same way.
fn smoke_nvme_recovery_after_forced_dead_qemu() -> TestResult {
    if super::controller_count() < 1 {
        return TestResult::Skip("needs an NVMe controller");
    }
    if let Err(e) = reinstall(0) {
        return TestResult::Fail(e);
    }
    let Some(d) = narf_block::find_block_device("nvme0n1") else {
        return TestResult::Fail("nvme0n1 not registered");
    };
    let n = SCRATCH_BLOCKS;
    let len = n as usize * 512;
    let mut saved = vec![0u8; len];
    if d.read(SCRATCH_LBA, n, &mut saved).is_err() {
        return TestResult::Fail("initial scratch read failed");
    }
    let p = pattern(0x5A);
    if d.write(SCRATCH_LBA, n, &p).is_err() {
        return TestResult::Fail("pattern write failed");
    }
    // Force the timeout's mark on the installed controller.
    {
        let mut g = super::controller_at(0);
        let Some(g) = g.as_mut() else {
            return TestResult::Fail("controller 0 not installed");
        };
        g.dead = true;
    }
    if super::with_controller_at(0, |c| c.is_dead()) != Some(true) {
        return TestResult::Fail("dead mark did not land");
    }
    // This read must trigger recovery and return the pattern.
    let mut back = vec![0u8; len];
    if let Err(e) = d.read(SCRATCH_LBA, n, &mut back) {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "nvme recovery: read: {e:?}");
        return TestResult::Fail("read on a dead controller did not recover it");
    }
    if back != p {
        return TestResult::Fail("data did not survive the in-place reset");
    }
    if super::with_controller_at(0, |c| c.is_dead()) != Some(false) {
        return TestResult::Fail("controller still dead after recovery");
    }
    // The flush path recovers the same way.
    {
        let mut g = super::controller_at(0);
        let Some(g) = g.as_mut() else {
            return TestResult::Fail("controller 0 vanished");
        };
        g.dead = true;
    }
    if super::NvmeNamespaceBlock::new(0, 1).flush().is_err() {
        return TestResult::Fail("flush on a dead controller did not recover it");
    }
    if super::with_controller_at(0, |c| c.is_dead()) != Some(false) {
        return TestResult::Fail("controller still dead after flush recovery");
    }
    // Restore the scratch window.
    if d.write(SCRATCH_LBA, n, &saved).is_err() {
        return TestResult::Fail("restoring the scratch window failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/multi",
    smoke_nvme_recovery_after_forced_dead_qemu
);

/// QEMU, second controller: a stack-local controller whose identity
/// snapshot is poisoned (as if the function had been hot-swapped
/// while wedged) must fail `reset_recover` with `IdentityChanged`,
/// and the genuinely-present controller must be stopped again —
/// never adopted under the old identity.
fn smoke_nvme_recovery_identity_mismatch_qemu() -> TestResult {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    if super::controller_count() < 2 {
        return TestResult::Skip("needs two NVMe controllers");
    }
    if let Err(e) = reinstall(1) {
        return TestResult::Fail(e);
    }
    let Some(Some(dev)) = super::with_controller_at(1, |c| c.bus_device()) else {
        return TestResult::Fail("nvme1 has no bus device");
    };
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return TestResult::Fail("claim_device_cap(nvme1) failed");
    };
    // Stack-local bring-up crosses the installed controller's queues
    // (the harness pattern `reinstall` documents); it is reinstalled
    // at the end.
    let mut ctrl = super::Controller::from_device(dev);
    if ctrl.bring_up(&cap).is_err() {
        return TestResult::Fail("stack-local bring_up failed");
    }
    if ctrl.create_io_queue().is_err() {
        ctrl.disable_after_failure(&cap);
        return TestResult::Fail("stack-local create_io_queue failed");
    }
    // Poison the snapshot: reset_recover compares the re-identified
    // (real) serial against this — a stand-in for a hot-swap.
    match ctrl.identify.as_mut() {
        Some(id) => id.sn[0] ^= 0xFF,
        None => return TestResult::Fail("no identify snapshot to poison"),
    }
    ctrl.dead = true;
    let verdict = ctrl.reset_recover(&cap);
    // Restore shared state before judging the outcome.
    let restored = reinstall(1);
    match verdict {
        Err(super::NvmeError::IdentityChanged) => {}
        other => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "nvme recovery: expected IdentityChanged, got {other:?}"
            );
            return TestResult::Fail("identity mismatch not detected on recovery");
        }
    }
    if !ctrl.is_dead() {
        return TestResult::Fail("mismatched controller left live after recovery");
    }
    if let Err(e) = restored {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/multi",
    smoke_nvme_recovery_identity_mismatch_qemu
);

/// QEMU, second controller: a bus Detach event for nvme1's function,
/// dispatched through the production default dispatcher, runs the
/// registered remove hook and tears the controller down (block
/// devices withdrawn, I/O refused, nvme0 untouched) — and a re-probe
/// brings it back, mirroring the teardown smoke's restore.
fn smoke_nvme_detach_event_removes_controller_qemu() -> TestResult {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    if super::controller_count() < 2 {
        return TestResult::Skip("needs two NVMe controllers");
    }
    if let Err(e) = reinstall(1) {
        return TestResult::Fail(e);
    }
    let Some(Some(dev)) = super::with_controller_at(1, |c| c.bus_device()) else {
        return TestResult::Fail("nvme1 has no bus device");
    };
    let narf_bus::BusAddr::Pcie(bdf) = dev.addr else {
        return TestResult::Fail("nvme1 is not PCIe");
    };
    // The boot sequence installs the default dispatcher; installing
    // again only stacks a duplicate listener, and detach is
    // idempotent, so the outcome is the same either way.
    let _ = narf_bus::hotplug::install_default_dispatcher();
    narf_bus::dispatch_event(narf_bus::HotplugEvent::Detach { addr: dev.addr });
    if super::instance_of(bdf).is_some() {
        return TestResult::Fail("Detach event did not remove nvme1's slot");
    }
    if narf_block::find_block_device("nvme1n1").is_some() {
        return TestResult::Fail("Detach event left nvme1n1 registered");
    }
    let mut sector = [0u8; 512];
    let ns = super::NvmeNamespaceBlock::new(1, 1);
    if ns.read(0, 1, &mut sector) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("I/O to a detached controller was not refused");
    }
    let Some(d0) = narf_block::find_block_device("nvme0n1") else {
        return TestResult::Fail("detaching nvme1 unregistered nvme0n1");
    };
    if d0.read(0, 1, &mut sector).is_err() {
        return TestResult::Fail("nvme0n1 I/O failed after detaching nvme1");
    }
    // Restore: re-probe the same function under the same instance.
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return TestResult::Fail("claim_device_cap(nvme1) failed after detach");
    };
    if super::probe(dev, cap).is_err() {
        return TestResult::Fail("re-probe of nvme1 failed after detach");
    }
    if super::instance_of(bdf) != Some(1) {
        return TestResult::Fail("re-probe changed nvme1's instance");
    }
    match narf_block::find_block_device("nvme1n1") {
        Some(d) if d.read(0, 1, &mut sector).is_ok() => TestResult::Pass,
        _ => TestResult::Fail("nvme1n1 not back after re-probe"),
    }
}
kernel_test_in!(
    "drivers/nvme/multi",
    smoke_nvme_detach_event_removes_controller_qemu
);
