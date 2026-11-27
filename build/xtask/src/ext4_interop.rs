//! `cargo xtask ext4-rootrw-interop`: prove that `narf.disks=root-rw` with
//! `rd.luks.prompt=console` unlocks a LUKS1 root from the keyboard and
//! writes the ext4 inside it so that e2fsprogs finds nothing wrong.
//!
//! 1. Build, unprivileged, a GPT disk shaped like the 21ME's: an ESP and a
//!    LUKS1 (aes-xts-plain64, sha256) partition around a `mkfs.ext4 -d`
//!    filesystem with the host's default features, its directories indexed
//!    by `e2fsck -fyD`. `cryptsetup luksFormat` takes a volume key xtask
//!    chose, so the host can encrypt the payload itself (AES-XTS, plain64)
//!    with no device mapper. The keyslots are the 21ME's too: the
//!    passphrase in slot 0 and a keyfile in slot 1, with the iteration
//!    counts its installer's cryptsetup chose.
//! 2. Boot NARF on it under `narf.disks=root-rw root=UUID=<container>
//!    rd.luks.uuid=<container> rd.luks.prompt=console`. When the prompt
//!    appears, type the passphrase on the emulated PS/2 keyboard through the
//!    QEMU monitor (`sendkey`). The kernel's `narf.ext4_interop=root`
//!    workload (`drivers/fs/ext2/src/interop.rs`) writes pacman- and
//!    systemd-shaped changes, then remounts the root read-only.
//! 3. On the host: decrypt the payload, then `e2fsck -fn` must be clean,
//!    `dumpe2fs -h` must say clean with one more mount counted, `debugfs
//!    rdump` must hold exactly what the workload wrote, and every byte
//!    outside the payload (GPT, ESP, LUKS header) must be unchanged.
//!
//! Both UUIDs carry the harness prefix the kernel workload requires.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes::cipher::KeyInit;
use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use xts_mode::{get_tweak_default, Xts128};

/// UUID of the LUKS container (`root=` and `rd.luks.uuid=`).
pub const LUKS_UUID: &str = "c4c405ee-0000-4a11-9e57-00000000e4c5";
/// UUID of the ext4 inside it.
pub const FS_UUID: &str = "c4c405ee-0000-4a11-9e57-00000000e4f5";
/// Typed at the prompt: only keys `sendkey` names plainly.
const PASSPHRASE: &str = "narf-luks-test";
const ESP_MIB: u64 = 32;
const EXT4_MIB: u64 = 192;
/// LUKS1's payload offset for a 512-bit key (4096 sectors).
const PAYLOAD_SECTORS: u64 = 4096;
/// The 21ME's keyslot iterations (`cryptsetup luksDump`): its installer's
/// 2-second default on a Ryzen 7 PRO 8840HS. Slot 0 is over the 10M bound
/// NARF used to apply.
const SLOT0_ITERATIONS: &str = "10880166";
const SLOT1_ITERATIONS: &str = "9686614";
const ESP_START: u64 = 2048;

// Must match `narf_drivers_fs_ext2::interop`.
const HOSTNAME: &[u8] = b"narf-ext4-interop\n";
const ALPM_DB_VERSION: &[u8] = b"9\n";
const PKG_DESC: &[u8] = b"%NAME%\nnarf-interop\n\n%VERSION%\n1.0-1\n";
const BIG_PATCH: (usize, usize) = (300_000, 8192);
const LOG_CHUNKS: u32 = 64;
const MANY: u32 = 3000;
const SPARSE: u32 = 1500;
const TRUNC_TO: usize = 100_000;
/// Names `/usr/lib/narf-many` starts with: enough for e2fsck -D to index it.
const MANY_INITIAL: u32 = 400;

/// Options for `cargo xtask ext4-rootrw-interop`.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Seconds to wait for the boot's verdict.
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,

    /// Where to type the passphrase: the emulated PS/2 keyboard (the
    /// path a laptop without a serial port uses), or the serial line
    /// (which the console prompt also reads), to tell a keyboard problem
    /// from an unlock problem.
    #[arg(long, value_enum, default_value_t = TypeOn::Keyboard)]
    pub type_on: TypeOn,
}

/// See [`Args::type_on`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TypeOn {
    Keyboard,
    Serial,
}

/// `narf_drivers_fs_ext2::interop::pattern`.
fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn tool(name: &str) -> Result<()> {
    let found = Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !found {
        bail!("ext4-rootrw-interop: `{name}` not found");
    }
    Ok(())
}

fn run(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("spawn {what}"))?;
    if !out.status.success() {
        bail!(
            "ext4-rootrw-interop: {what} failed ({}):\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data).with_context(|| format!("write {}", path.display()))
}

fn many_name(i: u32) -> String {
    format!("library-module-with-a-long-name-{i:04}.so")
}

/// The tree `mkfs.ext4 -d` packs.
fn stage(dir: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dir);
    write(&dir.join("etc/hostname"), b"cachyos\n")?;
    write(&dir.join("var/lib/pacman/local/ALPM_DB_VERSION"), b"8\n")?;
    write(&dir.join("usr/share/narf/big.bin"), &pattern(5, 1 << 20))?;
    write(
        &dir.join("usr/share/narf/trunc.bin"),
        &pattern(6, 512 << 10),
    )?;
    write(&dir.join("usr/share/narf/remove-me"), b"bye\n")?;
    std::fs::create_dir_all(dir.join("usr/share/narf/empty-dir"))?;
    for i in 0..MANY_INITIAL {
        let name = many_name(i);
        write(&dir.join("usr/lib/narf-many").join(&name), name.as_bytes())?;
    }
    for d in ["var/log", "var/tmp", "srv"] {
        std::fs::create_dir_all(dir.join(d))?;
    }
    Ok(())
}

/// The ext4 filesystem, plain.
fn build_ext4(work: &Path, out: &Path) -> Result<()> {
    let stage_dir = work.join("stage");
    stage(&stage_dir)?;
    let _ = std::fs::remove_file(out);
    std::fs::File::create(out)?.set_len(EXT4_MIB << 20)?;
    run(
        Command::new("mkfs.ext4")
            .args([
                "-q", "-F", "-b", "4096", "-U", FS_UUID, "-L", "cachyos", "-d",
            ])
            .arg(&stage_dir)
            .arg(out),
        "mkfs.ext4",
    )?;
    // `mkfs -d` writes directories linearly; index them as Linux would.
    let code = Command::new("e2fsck")
        .arg("-fyD")
        .arg(out)
        .stdout(Stdio::null())
        .status()
        .context("spawn e2fsck -D")?
        .code();
    if !matches!(code, Some(0 | 1)) {
        bail!("ext4-rootrw-interop: e2fsck -fyD exited {code:?}");
    }
    let htree = run(
        Command::new("debugfs")
            .args(["-R", "htree /usr/lib/narf-many"])
            .arg(out),
        "debugfs htree",
    )?;
    if !htree.contains("Root node dump") {
        bail!("ext4-rootrw-interop: /usr/lib/narf-many was not indexed");
    }
    Ok(())
}

fn xts(key: &[u8; 64]) -> Xts128<Aes256> {
    Xts128::new(
        Aes256::new_from_slice(&key[..32]).expect("key"),
        Aes256::new_from_slice(&key[32..]).expect("key"),
    )
}

/// The LUKS1 partition: a header from `cryptsetup luksFormat` with our
/// volume key, then the ext4 encrypted with aes-xts-plain64 (the plain64
/// tweak is the sector number from the start of the payload).
fn build_luks(work: &Path, ext4: &Path, key: &[u8; 64], out: &Path) -> Result<()> {
    let key_file = work.join("volume.key");
    let pass_file = work.join("passphrase");
    std::fs::write(&key_file, key)?;
    std::fs::write(&pass_file, PASSPHRASE)?;
    let _ = std::fs::remove_file(out);
    std::fs::File::create(out)?.set_len((PAYLOAD_SECTORS << 9) + (EXT4_MIB << 20))?;
    run(
        Command::new("cryptsetup")
            .args(["luksFormat", "--type", "luks1", "--batch-mode"])
            .args([
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--hash",
                "sha256",
            ])
            .args(["--pbkdf-force-iterations", SLOT0_ITERATIONS])
            .args(["--uuid", LUKS_UUID])
            .arg("--volume-key-file")
            .arg(&key_file)
            .arg("--key-file")
            .arg(&pass_file)
            .arg(out),
        "cryptsetup luksFormat",
    )?;
    // The second slot CachyOS's installer adds for GRUB's keyfile.
    let keyfile = work.join("crypto_keyfile.bin");
    std::fs::write(&keyfile, pattern(0x4b46_494c, 64))?;
    run(
        Command::new("cryptsetup")
            .args(["luksAddKey", "--batch-mode"])
            .args(["--pbkdf-force-iterations", SLOT1_ITERATIONS])
            .arg("--key-file")
            .arg(&pass_file)
            .arg(out)
            .arg(&keyfile),
        "cryptsetup luksAddKey",
    )?;
    let dump = run(
        Command::new("cryptsetup").arg("luksDump").arg(out),
        "luksDump",
    )?;
    let offset = dump
        .lines()
        .find_map(|l| l.strip_prefix("Payload offset:"))
        .and_then(|v| v.trim().parse::<u64>().ok());
    if offset != Some(PAYLOAD_SECTORS) {
        bail!("ext4-rootrw-interop: LUKS payload offset {offset:?}, expected {PAYLOAD_SECTORS}");
    }
    let cipher = xts(key);
    let mut input = std::fs::File::open(ext4)?;
    let mut output = std::fs::OpenOptions::new().write(true).open(out)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut sector = 0u128;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n % 512 != 0 {
            bail!("ext4-rootrw-interop: short read of the ext4 image");
        }
        cipher.encrypt_area(&mut buf[..n], 512, sector, get_tweak_default);
        std::io::Seek::seek(
            &mut output,
            std::io::SeekFrom::Start((PAYLOAD_SECTORS << 9) + ((sector as u64) << 9)),
        )?;
        output.write_all(&buf[..n])?;
        sector += (n / 512) as u128;
    }
    Ok(())
}

fn luks_range() -> (u64, u64) {
    let start = (ESP_START + ESP_MIB * 2048) << 9;
    (start, start + (PAYLOAD_SECTORS << 9) + (EXT4_MIB << 20))
}

/// The GPT disk: ESP, then the LUKS partition.
fn build_disk(work: &Path, luks: &Path, out: &Path) -> Result<()> {
    let esp = work.join("esp.fat");
    let _ = std::fs::remove_file(&esp);
    std::fs::File::create(&esp)?.set_len(ESP_MIB << 20)?;
    run(
        Command::new("mkfs.fat")
            .args(["-F", "32", "-i", "CA50EF17", "-n", "EFI"])
            .arg(&esp),
        "mkfs.fat",
    )?;
    let (luks_start, luks_end) = luks_range();
    let luks_sectors = (luks_end - luks_start) >> 9;
    let root_start = luks_start >> 9;
    let total = root_start + luks_sectors + 2048;
    let _ = std::fs::remove_file(out);
    std::fs::File::create(out)?.set_len(total << 9)?;
    let table = format!(
        "label: gpt\nstart={ESP_START}, size={}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"EFI system partition\"\n\
         start={root_start}, size={luks_sectors}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"root\"\n",
        ESP_MIB * 2048
    );
    let mut sfdisk = Command::new("sfdisk")
        .arg("-q")
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawn sfdisk")?;
    sfdisk
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("sfdisk stdin"))?
        .write_all(table.as_bytes())?;
    if !sfdisk.wait()?.success() {
        bail!("ext4-rootrw-interop: sfdisk failed");
    }
    for (src, start) in [(&esp, ESP_START << 9), (&luks.to_path_buf(), luks_start)] {
        let data = std::fs::read(src)?;
        let mut disk = std::fs::OpenOptions::new().write(true).open(out)?;
        std::io::Seek::seek(&mut disk, std::io::SeekFrom::Start(start))?;
        disk.write_all(&data)?;
    }
    Ok(())
}

/// SHA-256 of the disk outside the ext4 payload (GPT, ESP, LUKS header).
fn outside_payload(disk: &Path) -> Result<[u8; 32]> {
    let (luks_start, luks_end) = luks_range();
    let payload = (luks_start + (PAYLOAD_SECTORS << 9), luks_end);
    let data = std::fs::read(disk)?;
    let mut hash = Sha256::new();
    hash.update(&data[..payload.0 as usize]);
    hash.update(&data[payload.1 as usize..]);
    Ok(hash.finalize().into())
}

/// The payload of `disk`, decrypted.
fn decrypt_payload(disk: &Path, key: &[u8; 64], out: &Path) -> Result<()> {
    let (luks_start, luks_end) = luks_range();
    let start = luks_start + (PAYLOAD_SECTORS << 9);
    let mut data = std::fs::read(disk)?[start as usize..luks_end as usize].to_vec();
    xts(key).decrypt_area(&mut data, 512, 0, get_tweak_default);
    std::fs::write(out, data)?;
    Ok(())
}

/// A QEMU `sendkey` name for a passphrase character.
fn key_name(c: char) -> Result<String> {
    Ok(match c {
        'a'..='z' | '0'..='9' => c.to_string(),
        '-' => "minus".into(),
        _ => bail!("ext4-rootrw-interop: no sendkey name for {c:?}"),
    })
}

/// Boot `disk`, type the passphrase at the prompt, and return the serial
/// output once the workload's verdict appears (or the timeout passes).
fn boot(args: &Args, kernel: &Path, disk: &Path, work: &Path, mode: &str) -> Result<String> {
    let cmdline = format!(
        "narf.disks=root-rw root=UUID={LUKS_UUID} rd.luks.uuid={LUKS_UUID} \
         rd.luks.prompt=console rd.luks.timeout=300 narf.ext4_interop={mode}"
    );
    std::env::set_var("NARF_NVME_IMG", disk);
    std::env::set_var("XTASK_QEMU_APPEND", &cmdline);
    // The prompt polls the i8042: route keys there, not to the virtio
    // keyboard (or, below, the USB one).
    std::env::set_var("XTASK_QEMU_NO_VIRTIO_INPUT", "1");
    let monitor = work.join("monitor.sock");
    let _ = std::fs::remove_file(&monitor);
    let mut qemu_args = super::qemu_boot_args(&args.build, kernel)?;
    if let Some(at) = qemu_args.iter().position(|a| a == "usb-kbd,bus=xhci0.0") {
        qemu_args.drain(at - 1..=at);
    }
    let mut cmd = Command::new(args.build.arch.qemu_bin());
    cmd.args(&qemu_args)
        .arg("-monitor")
        .arg(format!("unix:{},server=on,wait=off", monitor.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    println!("ext4-rootrw-interop: boot `{cmdline}`");
    let mut child = cmd.spawn().context("spawn qemu")?;
    let mut stdout = child.stdout.take().ok_or_else(|| anyhow!("qemu stdout"))?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("qemu stdin"))?;
    let serial = Arc::new(Mutex::new(String::new()));
    // 0 running, 1 prompt seen, 2 verdict, 3 panic.
    let state = Arc::new(AtomicU8::new(0));
    let (serial2, state2) = (serial.clone(), state.clone());
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut line = String::new();
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            if let Ok(mut s) = serial2.lock() {
                s.push_str(&text);
            }
            for c in text.chars() {
                if c == '\n' {
                    if line.contains("EXT4-INTEROP:")
                        || line.contains("disks:")
                        || line.contains("root-mount")
                        || line.contains("LUKS")
                        || line.contains("ext4")
                    {
                        println!("  | {line}");
                    }
                    if line.contains("EXT4-INTEROP: PASS")
                        || line.contains("EXT4-INTEROP: FAIL")
                        || line.contains("EXT4-INTEROP: NO-ROOT")
                        || line.contains("EXT4-INTEROP: REFUSED")
                        || line.contains("ROOT MOUNT FAILED")
                    {
                        state2.store(2, Ordering::Release);
                    }
                    if line.contains("panicked at") || line.contains("KERNEL PANIC") {
                        state2.store(3, Ordering::Release);
                    }
                    line.clear();
                } else {
                    line.push(c);
                    // The prompt carries no newline.
                    if line.contains("passphrase (no echo):") && state2.load(Ordering::Acquire) == 0
                    {
                        state2.store(1, Ordering::Release);
                    }
                }
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut typed = false;
    let outcome = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break Err(anyhow!("QEMU exited early ({status})"));
        }
        if Instant::now() >= deadline {
            break Err(anyhow!("no verdict within {} s", args.timeout));
        }
        match state.load(Ordering::Acquire) {
            1 if !typed && args.type_on == TypeOn::Serial => {
                println!("ext4-rootrw-interop: typing the passphrase on the serial line");
                stdin.write_all(PASSPHRASE.as_bytes())?;
                stdin.write_all(b"\r")?;
                stdin.flush()?;
                typed = true;
            }
            1 if !typed => {
                println!("ext4-rootrw-interop: typing the passphrase on the PS/2 keyboard");
                let mut mon =
                    UnixStream::connect(&monitor).context("connect to the QEMU monitor")?;
                for c in PASSPHRASE.chars() {
                    writeln!(mon, "sendkey {} 50", key_name(c)?)?;
                    std::thread::sleep(Duration::from_millis(150));
                }
                writeln!(mon, "sendkey ret 50")?;
                mon.flush()?;
                typed = true;
            }
            2 => break Ok(()),
            3 => break Err(anyhow!("kernel panic")),
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // Let QEMU drain the guest's last writes into the image, then stop it.
    std::thread::sleep(Duration::from_millis(1000));
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let text = serial.lock().map(|s| s.clone()).unwrap_or_default();
    std::fs::write(work.join(format!("serial-{mode}.log")), &text)?;
    outcome.map_err(|e| {
        anyhow!(
            "ext4-rootrw-interop: {e}; serial in {}",
            work.join("serial-root.log").display()
        )
    })?;
    if !typed {
        bail!("ext4-rootrw-interop: the passphrase prompt never appeared");
    }
    Ok(text)
}

/// What the workload must have left, as `(path, content)`.
fn expected_files() -> Vec<(String, Vec<u8>)> {
    let mut big = pattern(5, 1 << 20);
    big[BIG_PATCH.0..BIG_PATCH.0 + BIG_PATCH.1].copy_from_slice(&pattern(7, BIG_PATCH.1));
    let mut log = Vec::new();
    for i in 0..LOG_CHUNKS {
        log.extend_from_slice(&pattern(9 + i, 4096));
    }
    let mut sparse = vec![0u8; ((2 * (SPARSE as usize - 1)) + 1) * 4096];
    for i in 0..SPARSE {
        let at = i as usize * 2 * 4096;
        sparse[at..at + 4096].copy_from_slice(&pattern(1000 + i, 4096));
    }
    let mut files = vec![
        ("etc/hostname".to_string(), HOSTNAME.to_vec()),
        (
            "var/lib/pacman/local/ALPM_DB_VERSION".into(),
            ALPM_DB_VERSION.to_vec(),
        ),
        (
            "var/lib/pacman/local/narf-interop-1.0-1/desc".into(),
            PKG_DESC.to_vec(),
        ),
        ("usr/share/narf/big.bin".into(), big),
        (
            "usr/share/narf/trunc.bin".into(),
            pattern(6, 512 << 10)[..TRUNC_TO].to_vec(),
        ),
        ("var/log/narf.log".into(), log),
        ("var/tmp/sparse".into(), sparse),
    ];
    for i in 0..MANY_INITIAL {
        let name = many_name(i);
        files.push((format!("usr/lib/narf-many/{name}"), name.into_bytes()));
    }
    for i in (0..MANY).filter(|i| i % 3 != 0) {
        files.push((
            format!("usr/lib/narf-many/n{i:05}"),
            format!("n{i:05}\n").into_bytes(),
        ));
    }
    files
}

fn check(plain: &Path, work: &Path) -> Result<()> {
    let fsck = Command::new("e2fsck").args(["-fn"]).arg(plain).output()?;
    if fsck.status.code() != Some(0) {
        bail!(
            "ext4-rootrw-interop: e2fsck -fn exited {:?}:\n{}",
            fsck.status.code(),
            String::from_utf8_lossy(&fsck.stdout)
        );
    }
    let header = run(Command::new("dumpe2fs").arg("-h").arg(plain), "dumpe2fs -h")?;
    let field = |name: &str| {
        header
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_string())
    };
    if field("Filesystem state:").as_deref() != Some("clean") {
        bail!("ext4-rootrw-interop: the remount read-only did not leave the filesystem clean");
    }
    if field("Mount count:").as_deref() != Some("1") {
        bail!("ext4-rootrw-interop: the read-write mount was not counted");
    }
    let rdump = work.join("rdump");
    let _ = std::fs::remove_dir_all(&rdump);
    std::fs::create_dir_all(&rdump)?;
    run(
        Command::new("debugfs")
            .args(["-R", &format!("rdump / {}", rdump.display())])
            .arg(plain),
        "debugfs rdump",
    )?;
    for (path, want) in expected_files() {
        let got = std::fs::read(rdump.join(&path)).with_context(|| format!("/{path} missing"))?;
        if got != want {
            bail!(
                "ext4-rootrw-interop: /{path} differs ({} bytes, expected {})",
                got.len(),
                want.len()
            );
        }
    }
    let names = std::fs::read_dir(rdump.join("usr/lib/narf-many"))?.count();
    let want = MANY_INITIAL as usize + (0..MANY).filter(|i| i % 3 != 0).count();
    if names != want {
        bail!("ext4-rootrw-interop: /usr/lib/narf-many has {names} names, expected {want}");
    }
    for gone in ["usr/share/narf/remove-me", "usr/share/narf/empty-dir"] {
        if rdump.join(gone).exists() {
            bail!("ext4-rootrw-interop: /{gone} should be gone");
        }
    }
    if !rdump.join("srv/narf-new").is_dir() {
        bail!("ext4-rootrw-interop: /srv/narf-new is missing");
    }
    let ex = run(
        Command::new("debugfs")
            .args(["-R", "ex /var/tmp/sparse"])
            .arg(plain),
        "debugfs ex",
    )?;
    let depth = ex.lines().find_map(|l| {
        l.trim()
            .split_once('/')
            .and_then(|(_, d)| d.split_whitespace().next()?.parse::<u32>().ok())
    });
    if depth.is_none_or(|d| d < 2) {
        bail!("ext4-rootrw-interop: /var/tmp/sparse should have an extent tree of depth 2, has {depth:?}");
    }
    Ok(())
}

pub fn run_cmd(args: &Args) -> Result<()> {
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("ext4-rootrw-interop: x86_64 only");
    }
    for t in [
        "mkfs.ext4",
        "e2fsck",
        "debugfs",
        "dumpe2fs",
        "cryptsetup",
        "mkfs.fat",
        "sfdisk",
    ] {
        tool(t)?;
    }
    let root = super::workspace_root()?;
    let work: PathBuf = root.join("target/ext4-rootrw-interop");
    std::fs::create_dir_all(&work)?;
    let kernel = super::cargo_build(&args.build, &root)?.join(&args.build.package);
    if !kernel.exists() {
        bail!("expected kernel at {}", kernel.display());
    }
    let key: [u8; 64] = pattern(0x4c55_4b53, 64).try_into().expect("64 bytes");
    let ext4 = work.join("root.ext4");
    let luks = work.join("root.luks");
    let disk = work.join("disk.img");
    build_ext4(&work, &ext4)?;
    build_luks(&work, &ext4, &key, &luks)?;
    build_disk(&work, &luks, &disk)?;
    let before = outside_payload(&disk)?;
    let serial = boot(args, &kernel, &disk, &work, "root")?;
    if !serial.contains("EXT4-INTEROP: PASS root") {
        bail!(
            "ext4-rootrw-interop: the workload did not pass; serial in {}",
            work.join("serial-root.log").display()
        );
    }
    if outside_payload(&disk)? != before {
        bail!(
            "ext4-rootrw-interop: bytes outside the ext4 payload (GPT, ESP, LUKS header) changed"
        );
    }
    let plain = work.join("after.ext4");
    decrypt_payload(&disk, &key, &plain)?;
    check(&plain, &work)?;
    // The same disk again, and this time NARF is killed with the root still
    // mounted read-write.
    let serial = boot(args, &kernel, &disk, &work, "crash")?;
    if !serial.contains("EXT4-INTEROP: PASS crash") {
        bail!(
            "ext4-rootrw-interop: the crash workload did not get ready; serial in {}",
            work.join("serial-crash.log").display()
        );
    }
    let crashed = work.join("crashed.ext4");
    decrypt_payload(&disk, &key, &crashed)?;
    check_crash(&crashed)?;
    println!("ext4-rootrw-interop: OK");
    Ok(())
}

/// After NARF was killed with the journaled root mounted read-write:
/// - the superblock still says `needs_recovery` (nothing cleared it);
/// - `e2fsck -fy` recovers the journal and repairs nothing (its
///   optimizations aside), then `e2fsck -fn` is clean;
/// - the file written and synced before the kill reads back exactly, and so
///   does the one written without a sync and left for NARF's 5 s commit
///   timer.
fn check_crash(plain: &Path) -> Result<()> {
    let header = run(Command::new("dumpe2fs").arg("-h").arg(plain), "dumpe2fs -h")?;
    if !header
        .lines()
        .any(|l| l.starts_with("Filesystem features:") && l.contains("needs_recovery"))
    {
        bail!("ext4-rootrw-interop: crashed root does not say needs_recovery:\n{header}");
    }
    // `/narf-crash/held`, unlinked while open: on the device, the one
    // orphan recorded, with no link and its size.
    let held = recorded_orphans(plain, &header)?;
    let [held] = held[..] else {
        bail!("ext4-rootrw-interop: the crashed root records orphans {held:?}, not just /narf-crash/held");
    };
    let stat = run(
        Command::new("debugfs")
            .args(["-R", &format!("stat <{held}>")])
            .arg(plain),
        "debugfs stat",
    )?;
    if !stat.contains("Links: 0") || !stat.contains(&format!("Size: {CRASH_HELD_LEN}")) {
        bail!("ext4-rootrw-interop: orphan {held} is not the unlinked /narf-crash/held:\n{stat}");
    }
    let fsck = Command::new("e2fsck").arg("-fy").arg(plain).output()?;
    let text = String::from_utf8_lossy(&fsck.stdout).into_owned();
    if !text.contains(&format!("Clearing orphaned inode {held} ")) {
        bail!("ext4-rootrw-interop: e2fsck did not release orphan {held}:\n{text}");
    }
    let repaired = text
        .lines()
        .any(|l| (l.contains("Fix?") || l.contains("? yes")) && !l.contains("Optimize?"));
    if fsck.status.code() != Some(0) || repaired {
        bail!(
            "ext4-rootrw-interop: e2fsck -fy after the crash exited {:?}:\n{text}",
            fsck.status.code()
        );
    }
    let fsck = Command::new("e2fsck").args(["-fn"]).arg(plain).output()?;
    if fsck.status.code() != Some(0) {
        bail!(
            "ext4-rootrw-interop: e2fsck -fn after recovery exited {:?}:\n{}",
            fsck.status.code(),
            String::from_utf8_lossy(&fsck.stdout)
        );
    }
    let testi = run(
        Command::new("debugfs")
            .args(["-R", &format!("testi <{held}>")])
            .arg(plain),
        "debugfs testi",
    )?;
    if testi.contains("is marked in use") {
        bail!("ext4-rootrw-interop: orphan {held} still in use after e2fsck");
    }
    for (path, seed, len) in [
        ("/narf-crash/synced", CRASH_SYNCED_SEED, CRASH_SYNCED_LEN),
        ("/narf-crash/timer", CRASH_TIMER_SEED, CRASH_TIMER_LEN),
    ] {
        let cat = Command::new("debugfs")
            .args(["-R", &format!("cat {path}")])
            .arg(plain)
            .output()?;
        if cat.stdout != pattern(seed, len) {
            bail!(
                "ext4-rootrw-interop: after the crash {path} is {} bytes, not its {len}",
                cat.stdout.len()
            );
        }
    }
    Ok(())
}

/// The inodes `plain`'s orphan file lists, then the `s_last_orphan` list
/// (`header` is its `dumpe2fs -h`).
fn recorded_orphans(plain: &Path, header: &str) -> Result<Vec<u32>> {
    let field = |name: &str| {
        header
            .lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
    };
    let mut inos = Vec::new();
    if let Some(orphan_file) = field("Orphan file inode:") {
        let bs: usize = field("Block size:").unwrap_or_default().parse()?;
        let cat = Command::new("debugfs")
            .args(["-R", &format!("cat <{orphan_file}>")])
            .arg(plain)
            .output()?;
        for block in cat.stdout.chunks(bs) {
            for e in block[..block.len().saturating_sub(8)].chunks_exact(4) {
                let ino = u32::from_le_bytes(e.try_into()?);
                if ino != 0 {
                    inos.push(ino);
                }
            }
        }
    }
    if let Some(head) = field("First orphan inode:") {
        inos.push(head.parse()?);
    }
    Ok(inos)
}

/// What the guest's `crash` mode writes (`drivers/fs/ext2/src/interop.rs`).
const CRASH_SYNCED_SEED: u32 = 0x5359_4e43;
const CRASH_SYNCED_LEN: usize = 300_000;
const CRASH_TIMER_SEED: u32 = 0x5449_4d52;
const CRASH_TIMER_LEN: usize = 50_000;
const CRASH_HELD_LEN: usize = 70_000;

#[cfg(test)]
mod tests {
    /// The host encrypts what the kernel decrypts: aes-xts-plain64 with the
    /// sector number as the tweak, across a 1 MiB chunk boundary.
    #[test]
    fn xts_round_trip_is_per_sector() {
        let key: [u8; 64] = super::pattern(1, 64).try_into().unwrap();
        let cipher = super::xts(&key);
        let plain = super::pattern(2, 4096);
        let mut whole = plain.clone();
        cipher.encrypt_area(&mut whole, 512, 10, xts_mode::get_tweak_default);
        let mut second = plain[512..1024].to_vec();
        cipher.encrypt_sector(&mut second, xts_mode::get_tweak_default(11));
        assert_eq!(&whole[512..1024], &second[..]);
        cipher.decrypt_area(&mut whole, 512, 10, xts_mode::get_tweak_default);
        assert_eq!(whole, plain);
    }

    #[test]
    fn interop_contract_matches_the_kernel() {
        assert!(super::LUKS_UUID.starts_with("c4c405ee-0000-4a11-9e57-"));
        assert!(super::FS_UUID.starts_with("c4c405ee-0000-4a11-9e57-"));
        assert!(super::PASSPHRASE
            .chars()
            .all(|c| super::key_name(c).is_ok()));
    }
}
