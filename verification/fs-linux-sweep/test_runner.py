"""Failure-path checks for the diagnostic harness (no QEMU required)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("fs_sweep", Path(__file__).with_name("run.py"))
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)


class ResultValidation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "guest.log"
        self.lines = ["FSMOUNT status=ok device=/dev/vda fs=ext4 existing=0 options=noatime"]
        for name, units in zip(sweep.CASES, sweep.UNITS):
            self.lines.append(f"FSCASE name={name} status=ok errno=0 step=verify units={units} ns=1000")
        self.lines += ["FSSYNC status=ok errno=0 unmount=0 retained_boot_mount=0",
                       "FSDONE cases=11 failed=0", "FS-SWEEP-END", "FSRUN-RC=0"]

    def parse(self, lines=None, code=0, side="linux"):
        self.log.write_text("\n".join(self.lines if lines is None else lines) + "\n")
        return sweep.parse_log(self.log, code, side, "ext4")

    def test_complete_success(self):
        self.assertTrue(self.parse()["passed"])

    def test_timeout_after_workload_is_not_success(self):
        self.assertFalse(self.parse(code=124)["passed"])

    def test_missing_duplicate_or_wrong_case_cannot_pass(self):
        for lines in [self.lines[:3] + self.lines[4:], self.lines + [self.lines[1]],
                      [line.replace("name=stat ", "name=unknown ") for line in self.lines]]:
            with self.subTest(lines=lines):
                self.assertFalse(self.parse(lines)["passed"])

    def test_wrong_units_and_failed_data_check_cannot_pass(self):
        for replacement in ["units=0", "units=1"]:
            self.assertFalse(self.parse([line.replace("units=1048576", replacement) for line in self.lines])["passed"])
        bad = [line.replace("name=stat status=ok errno=0", "name=stat status=error errno=84")
               .replace("failed=0", "failed=1").replace("FSRUN-RC=0", "FSRUN-RC=1") for line in self.lines]
        result = self.parse(bad)
        self.assertTrue(result["complete"])
        self.assertFalse(result["passed"])

    def test_sync_and_guest_status_are_required(self):
        for remove in ["FSSYNC", "FSRUN-RC", "FSDONE", "FS-SWEEP-END"]:
            self.assertFalse(self.parse([line for line in self.lines if not line.startswith(remove)])["passed"])

    def test_narf_requires_verified_boot_mount(self):
        lines = [line.replace("/dev/vda", "/dev/vblk0").replace("existing=0", "existing=1")
                 for line in self.lines]
        self.assertFalse(self.parse(lines, side="narf")["passed"])
        lines.insert(0, '  mnt-mount-ext2: ext on vblk0 mounted at "/mnt"')
        self.assertTrue(self.parse(lines, side="narf")["passed"])

    def test_persistent_data_corruption_and_missing_files_fail(self):
        tree = Path(self.directory.name) / "restored"
        (tree / "lookup").mkdir(parents=True)
        data = bytes((i * 17 + (i >> 8) * 31 + 91) & 255 for i in range(1048576))
        (tree / "seed.bin").write_bytes(data)
        for i in range(64): (tree / "lookup" / f"n{i:04d}").write_bytes(b"x")
        self.assertTrue(sweep.verify_restored(tree, [])["passed"])
        (tree / "seed.bin").write_bytes(b"bad")
        self.assertFalse(sweep.verify_restored(tree, [])["passed"])
        (tree / "seed.bin").unlink()
        self.assertFalse(sweep.verify_restored(tree, [])["passed"])


if __name__ == "__main__":
    unittest.main()
