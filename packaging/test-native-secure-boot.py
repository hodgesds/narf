#!/usr/bin/env python3
"""Exercise native package installation under enforcing Secure Boot OVMF.

Keys are ephemeral test keys, never release keys. No host firmware/ESP changes.
Full serial logs and a JSON report are retained under target/secure-boot-native.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    image = pathlib.Path(sys.argv[1]).resolve()
    for tool in ("openssl", "sbsign", "sbverify", "virt-fw-vars", "qemu-system-x86_64"):
        if not shutil.which(tool):
            raise RuntimeError(f"Secure Boot test requires {tool}")
    pairs = [(os.environ.get("OVMF_SECURE_CODE", ""), os.environ.get("OVMF_SECURE_VARS", ""))]
    for directory in ("/usr/share/OVMF", "/usr/share/edk2/x64", "/usr/share/edk2/OvmfX64"):
        for suffix in ("_4M", ""):
            pairs.append((f"{directory}/OVMF_CODE{suffix}.secboot.fd", f"{directory}/OVMF_VARS{suffix}.fd"))
    code, variables = next(((pathlib.Path(c), pathlib.Path(v)) for c, v in pairs
                            if c and v and pathlib.Path(c).is_file() and pathlib.Path(v).is_file()), (None, None))
    if code is None:
        raise RuntimeError("set OVMF_SECURE_CODE/OVMF_SECURE_VARS to matching raw OVMF files")
    report_dir = ROOT / "target/secure-boot-native"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"image": str(image), "cases": []}
    (report_dir / "report.json").write_text(json.dumps(report))
    with tempfile.TemporaryDirectory(prefix="narf-secure-boot-") as temporary:
        work = pathlib.Path(temporary)
        raw_firmware = []
        for name, source in (("code", code), ("vars", variables)):
            destination = work / f"{name}-raw.fd"
            run("qemu-img", "convert", "-O", "raw", source, destination)
            raw_firmware.append(destination)
        code, variables = raw_firmware
        cert, key = work / "db.crt", work / "db.key"
        run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
            "-subj", "/CN=NARF isolated test key/", "-keyout", key, "-out", cert, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run("bash", ROOT / "packaging/build-release.sh", "--version", "0.0.0-native-secure-boot", "--arch", "x86_64",
            "--skip-build", "--formats", "tar", "--uefi-loader", image,
            "--secure-boot-key", key, "--secure-boot-cert", cert, "--output", work / "packages")
        tree = work / "tree"
        tree.mkdir()
        run("tar", "-xzf", work / "packages/narf-0.0.0-native-secure-boot-x86_64.tar.gz", "-C", tree)
        esp = work / "esp"
        esp.mkdir()
        environment = dict(os.environ, NARF_UEFI_SOURCE_DIR=str(tree / "usr/lib/narf/uefi"),
                           NARF_UEFI_STATE_DIR=str(work / "state"), NARF_UEFI_ALLOW_NON_ESP="1")
        run(tree / "usr/bin/narf-uefi", "install", "--esp", esp, "--no-manager-hooks", env=environment)
        boot = esp / "EFI/BOOT"
        boot.mkdir()
        installed = esp / "EFI/NARF/narf.efi"
        signed = work / "signed.efi"
        shutil.copyfile(installed, signed)
        run("sbverify", "--cert", cert, signed)
        run("virt-fw-vars", "--input", variables, "--output", work / "enrolled.fd", "--enroll-cert", cert,
            "--no-microsoft", "--add-db", "8c8b13fd-3c1f-4dce-92d9-2a76e88d9fe8", cert, "--secure-boot")

        def boot_case(name, candidate, positive=False):
            # Both discovery locations contain the same candidate: firmware
            # cannot fall back to a different valid NARF image in a rejection test.
            shutil.copyfile(candidate, boot / "BOOTX64.EFI")
            shutil.copyfile(candidate, installed)
            vars_file = work / f"{name}-vars.fd"
            shutil.copyfile(work / "enrolled.fd", vars_file)
            log = report_dir / f"{name}.log"
            args = ["qemu-system-x86_64", "-machine", "q35,smm=on", "-global", "driver=cfi.pflash01,property=secure,value=on",
                    "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                    "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}", "-cpu", "max", "-smp", "2", "-m", "4096M",
                    "-drive", f"if=virtio,format=raw,readonly=on,file=fat:{esp}",
                    "-nic", "none", "-serial", "stdio", "-display", "none", "-monitor", "none", "-no-reboot"]
            with log.open("wb") as output:
                process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                try:
                    status = process.wait(timeout=int(os.environ.get("XTASK_BOOT_SMOKE_TIMEOUT_SECS", "180")) if positive else 25)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    status = 124
            text = log.read_text(errors="replace")
            if positive:
                passed = (status == 0 and "boot-smoke: clean exit" in text and
                          "SecureBoot=Some(1) SetupMode=Some(0)" in text and not re.search(r"KERNEL PANIC|panicked at|double fault", text))
            else:
                # A timeout alone proves nothing: require the firmware's
                # explicit authentication refusal and absence of loader entry.
                passed = (bool(re.search(r"Security Violation|Access Denied", text, re.IGNORECASE)) and
                          "NARF native EFI:" not in text and "boot-smoke: clean exit" not in text)
            report["cases"].append({"name": name, "passed": passed, "status": status, "log": str(log)})
            (report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            if not passed:
                print(text[-20000:], file=sys.stderr)
                raise RuntimeError(f"Secure Boot case {name} failed; see {log}")
            print(f"Secure Boot {name}: passed", flush=True)

        boot_case("signed", signed, True)
        boot_case("unsigned", image)
        for part in ("kernel", "initramfs", "cmdline"):
            candidate = work / f"tampered-{part}.efi"
            run("python3", ROOT / "packaging/native-efi.py", signed, "--tamper", part, "--output", candidate)
            boot_case(f"tampered-{part}", candidate)
    print(f"Secure Boot report: {report_dir / 'report.json'}")


if __name__ == "__main__":
    main()
