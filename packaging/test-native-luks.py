#!/usr/bin/env python3
"""Boot real cryptsetup LUKS1/LUKS2 fixtures through NARF's native EFI image.

Only regular files in a temporary directory are used. No device mapper,
mounts, loop devices, host disks, or persistent credentials are needed.
Requires a current boot-init kernel ELF and generated initramfs arguments.
"""
import argparse
import hashlib
import json
import os
import pathlib
import selectors
import shutil
import struct
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTER = "4152464e-4c55-4b53-9000-000000000001"
PASS = b"narf-test-passphrase"
PROOF = b"NARF-LUKS-ROOT-PROOF"


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def extract_archive(source, directory):
    data = source.read_bytes()
    offset = 0
    while data[offset:offset + 6] == b"070701":
        size = int(data[offset + 54:offset + 62], 16)
        namesize = int(data[offset + 94:offset + 102], 16)
        name = data[offset + 110:offset + 109 + namesize].decode()
        offset = (offset + 110 + namesize + 3) & ~3
        if name == "TRAILER!!!":
            return
        relative = pathlib.PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("archive path escapes fixture tree")
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data[offset:offset + size])
        path.chmod(0o755)
        offset = (offset + size + 3) & ~3
    raise RuntimeError("archive has no newc trailer")


def make_disk(work, version, plaintext):
    container = work / f"{plaintext.stem}-{version}.luks"
    container_size = plaintext.stat().st_size + 32 * 1024**2
    with container.open("wb") as output:
        output.truncate(container_size)
    volume_key = os.urandom(64)
    keyfile, password = work / "volume.key", work / "password"
    keyfile.write_bytes(volume_key)
    password.write_bytes(PASS)
    run("cryptsetup", "luksFormat", "--type", version, "--batch-mode", "--cipher", "aes-xts-plain64",
        "--key-size", "512", "--hash", "sha256", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
        "--sector-size", "512", "--uuid", OUTER, "--volume-key-file", keyfile, "--key-file", password, container)
    if version == "luks1":
        with container.open("rb") as source:
            header = source.read(112)
        payload = struct.unpack_from(">I", header, 104)[0] * 512
    else:
        metadata = json.loads(subprocess.check_output(["cryptsetup", "luksDump", "--dump-json-metadata", str(container)]))
        payload = int(metadata["segments"]["0"]["offset"])
    with plaintext.open("rb") as source, container.open("r+b") as output:
        output.seek(payload)
        sector = 0
        while block := source.read(512):
            encryptor = Cipher(algorithms.AES(volume_key), modes.XTS(sector.to_bytes(16, "little"))).encryptor()
            output.write(encryptor.update(block) + encryptor.finalize())
            sector += 1
    # A GPT partition is necessary for root-ro/root-rw's identity/designation
    # checks. Its parent guard must remain read-only even when cryptroot is RW.
    disk = work / f"{plaintext.stem}-{version}.img"
    with disk.open("wb") as output:
        output.truncate(container_size + 4 * 1024**2)
    partition = f"label: gpt\nstart=2048, size={container_size // 512}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
    subprocess.run(["sfdisk", str(disk)], input=partition.encode(),
                   check=True, stdout=subprocess.DEVNULL)
    with disk.open("r+b") as output, container.open("rb") as source:
        output.seek(1024**2)
        shutil.copyfileobj(source, output)
    keyfile.unlink()
    password.unlink()
    return {"disk": disk, "key": volume_key, "offset": payload}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=pathlib.Path)
    parser.add_argument("--initramfs", required=True, type=pathlib.Path)
    parser.add_argument("--case", choices=("all", "write"), default="all")
    firmware = os.environ.get("OVMF_CODE") or next((p for p in (
        "/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/x64/OVMF_CODE.fd", "/usr/share/edk2/OvmfX64/OVMF_CODE.fd")
        if pathlib.Path(p).is_file()), "")
    parser.add_argument("--ovmf", default=firmware)
    args = parser.parse_args()
    kernel, archive = args.kernel.resolve(), args.initramfs.resolve()
    if not args.ovmf or not pathlib.Path(args.ovmf).is_file():
        parser.error("set OVMF_CODE or --ovmf to a raw OVMF CODE file")
    report_dir = ROOT / "target/native-luks-tests"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"selection": args.case, "cases": []}
    (report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="narf-luks-") as temporary:
        work = pathlib.Path(temporary)
        work.chmod(0o700)
        tree = work / "root"
        tree.mkdir()
        extract_archive(archive, tree)
        (tree / "luks-proof").write_bytes(PROOF + b"\n")
        run("cc", "-nostdlib", "-static", "-Wl,--build-id=none", "-Wl,-T," + str(ROOT / "userspace/coreutils/cat/cat.ld"),
            "-o", tree / "narf-luks-write",
            ROOT / "packaging/native-luks-write.S")
        plaintext = work / "plain.ext2"
        with plaintext.open("wb") as output:
            output.truncate(32 * 1024**2)
        run("mke2fs", "-q", "-t", "ext2", "-b", "4096", "-d", tree, plaintext)
        disks = {version: make_disk(work, version, plaintext) for version in ("luks1", "luks2")} if args.case == "all" else {}
        command = f"narf.disks=root-ro root=UUID={OUTER} rd.luks.uuid={OUTER} rd.luks.prompt=serial rd.luks.timeout=10 console=ttyS0"
        efi = work / "esp/EFI/BOOT/BOOTX64.EFI"
        efi.parent.mkdir(parents=True)
        run("cargo", "xtask", "efi-image", "--prebuilt", kernel, "--initramfs", archive,
            "--cmdline", command, "--output", efi, cwd=ROOT)

        def boot_case(name, version, interaction):
            disk = disks[version]["disk"]
            before = hashlib.sha256(disk.read_bytes()).hexdigest()
            log_path = report_dir / f"{name}.log"
            case = {"name": name, "passed": False, "log": str(log_path),
                    "image_sha256": hashlib.sha256(efi.read_bytes()).hexdigest()}
            report["cases"].append(case)
            (report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            qemu = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max", "-smp", "2", "-m", "4096M",
                    "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf}",
                    "-drive", f"if=virtio,format=raw,readonly=on,file=fat:{work / 'esp'}",
                    "-drive", f"if=none,id=luks-root,format=raw,snapshot=on,file={disk}",
                    "-device", "virtio-blk-pci,drive=luks-root,disable-legacy=on,disable-modern=off",
                    "-serial", "stdio", "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none"]
            overlay = work / f"{name}.qcow2"
            if interaction == "write":
                run("qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", disk, overlay)
                qemu[qemu.index(f"if=none,id=luks-root,format=raw,snapshot=on,file={disk}")] = \
                    f"if=none,id=luks-root,format=qcow2,file={overlay}"
            process = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       bufsize=0, env=dict(os.environ, TMPDIR=str(work)))
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            received = bytearray()
            cursor = 0
            deadline = time.monotonic() + 180

            def expect(marker):
                nonlocal cursor
                while time.monotonic() < deadline:
                    index = received.find(marker, cursor)
                    if index >= 0:
                        cursor = index + len(marker)
                        return
                    if selector.select(0.1):
                        block = os.read(process.stdout.fileno(), 65536)
                        if not block:
                            break
                        received.extend(block)
                        log_path.write_bytes(received)
                raise RuntimeError(f"{name}: missing {marker!r}; see {log_path}")

            def send(data):
                process.stdin.write(data)
                process.stdin.flush()

            try:
                expect(b"passphrase (serial; no echo):")
                if interaction == "cancel":
                    send(b"\x03")
                    expect(b"encrypted root required; refusing initramfs fallback")
                elif interaction == "timeout":
                    expect(b"encrypted root required; refusing initramfs fallback")
                else:
                    if interaction == "retry":
                        send(b"wrong-passphrase\r")
                        expect(b"passphrase (serial; no echo):")
                    send(PASS + b"\r")
                    expect(b'on cryptroot mounted at "/"')
                    expect(b"login:")
                    send(b"root\r")
                    expect(b"Password:")
                    send(b"narf\r")
                    expect(b"narf>")
                    send(b"cat /luks-proof\r")
                    expect(PROOF)
                    if interaction == "write":
                        expect(b"narf>")
                        # boot-init mounts its baked coreutils over /bin;
                        # execute this fixture from the selected root itself.
                        send(b"/narf-luks-write\r")
                        expect(b"NARF-LUKS-RW-SYNCED")
                if PASS in received or b"wrong-passphrase" in received:
                    raise RuntimeError("credential echoed or logged")
                if interaction in ("cancel", "timeout") and b"login:" in received:
                    raise RuntimeError("encrypted-root failure launched a fallback login")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                selector.close()
                process.stdin.close()
                process.stdout.close()
                log_path.write_bytes(received)
            if hashlib.sha256(disk.read_bytes()).hexdigest() != before:
                raise RuntimeError("root-ro test changed its source disk")
            if interaction == "write":
                changed = work / "changed.img"
                run("qemu-img", "convert", "-O", "raw", overlay, changed)
                decrypted = work / "persisted.btrfs"
                with changed.open("rb") as source, decrypted.open("wb") as output:
                    source.seek(1024**2 + disks[version]["offset"])
                    for sector in range(plain_btrfs.stat().st_size // 512):
                        block = source.read(512)
                        decryptor = Cipher(algorithms.AES(disks[version]["key"]), modes.XTS(sector.to_bytes(16, "little"))).decryptor()
                        output.write(decryptor.update(block) + decryptor.finalize())
                run("btrfs", "check", "--readonly", decrypted)
                restored = work / "restored"
                restored.mkdir()
                run("btrfs", "restore", decrypted, restored)
                if (restored / "luks-rw-proof").read_bytes() != b"NARF-LUKS-PERSISTED\n":
                    raise RuntimeError("fsynced encrypted-root data did not survive host decryption/remount")
            case["passed"] = True
            (report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"native LUKS {name}: passed", flush=True)

        if args.case == "all":
            boot_case("luks1-unlock", "luks1", "unlock")
            boot_case("luks2-retry", "luks2", "retry")
            boot_case("luks2-cancel", "luks2", "cancel")
            boot_case("luks1-timeout", "luks1", "timeout")
        plain_btrfs = work / "plain.btrfs"
        with plain_btrfs.open("wb") as output:
            output.truncate(128 * 1024**2)
        run("mkfs.btrfs", "-q", "-f", "-d", "single", "-m", "single", "--rootdir", tree, plain_btrfs)
        disks["luks2-rw"] = make_disk(work, "luks2", plain_btrfs)
        run("cargo", "xtask", "efi-image", "--prebuilt", kernel, "--initramfs", archive,
            "--cmdline", command.replace("narf.disks=root-ro", "narf.disks=root-rw") + " rootflags=subvolid=5", "--output", efi, cwd=ROOT)
        boot_case("luks2-btrfs-write", "luks2-rw", "write")


if __name__ == "__main__":
    main()
