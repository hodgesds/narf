"""Reject incomplete evidence and exercise reversible host-control helpers."""
import errno
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import controlled_host as host
import measure


class MeasurementValidation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "guest.log"
        self.lines = ["FSBENCH_ENV native=0 no_randomize=1 file_bytes=8388608 random_ops=4096 names=1024"]
        self.lines += [f"FSBENCH name={n} cycles=1000 work={w} unit={u}" for n, (w, u) in measure.CONTRACT.items()]
        self.lines += ["FSBENCH_DONE cases=11", "FSRUN-RC=0"]

    def parse(self, lines=None, code=0):
        self.log.write_text("\n".join(self.lines if lines is None else lines) + "\n")
        return measure.validate_log(self.log, code, "linux")["valid"]

    def test_complete(self):
        self.assertTrue(self.parse())

    def test_missing_duplicate_wrong_contract_and_zero_duration(self):
        for lines in [self.lines[1:], self.lines[:3] + self.lines[4:], self.lines + [self.lines[1]],
                      [s.replace("work=8388608", "work=1") for s in self.lines],
                      [s.replace("cycles=1000", "cycles=0") for s in self.lines],
                      [s.replace("no_randomize=1", "no_randomize=0") for s in self.lines],
                      [s.replace("native=0", "native=1") for s in self.lines]]:
            with self.subTest(lines=lines): self.assertFalse(self.parse(lines))

    def test_failure_after_complete_and_host_timeout(self):
        self.assertFalse(self.parse(self.lines + ["FSBENCH_FAIL step=sync errno=5"]))
        self.assertFalse(self.parse(code=124))
        self.assertFalse(self.parse(self.lines[:-1]))


class HostControls(unittest.TestCase):
    def setUp(self):
        self.state = dict(cpus=[8], frequency_khz=2401000, cgroup="/group",
                          sensors={"cpu": "/sensor", "nvme": "/nvme"},
                          limits={"cpu": 70000, "nvme": 78000}, storage_alarm="/alarm")
        self.values = {str(host.CPU_ROOT / name): value for name, value in {
            "smt/active": "0", "cpufreq/boost": "0", "online": "0-8",
            "cpu8/cache/index3/shared_cpu_list": "8,24",
            "cpu8/cpufreq/scaling_governor": "performance",
            "cpu8/cpufreq/scaling_min_freq": "2401000", "cpu8/cpufreq/scaling_max_freq": "2401000"}.items()}
        self.values.update({"/group/cpuset.cpus.partition": "isolated", "/group/cpuset.cpus.effective": "8",
                            "/sensor": "50000", "/nvme": "45000", "/alarm": "0"})

    def test_reject_drift_thermal_alarm_and_shared_llc(self):
        with patch.object(host, "read", side_effect=lambda p: self.values[str(p)]):
            self.assertEqual(host.verify(self.state), {"cpu": 50000, "nvme": 45000})
            for path, value in [("/sensor", "70000"), ("/alarm", "1"),
                                ("/group/cpuset.cpus.partition", "member"),
                                (str(host.CPU_ROOT / "smt/active"), "1"),
                                (str(host.CPU_ROOT / "cpu8/cpufreq/scaling_max_freq"), "3000000"),
                                (str(host.CPU_ROOT / "online"), "0-31")]:
                old = self.values[path]; self.values[path] = value
                with self.subTest(path=path), self.assertRaises(RuntimeError): host.verify(self.state)
                self.values[path] = old

    def test_busy_llc_cannot_pass_initial_window(self):
        with patch.object(host, "verify", return_value={}), patch.object(host.time, "sleep"), \
             patch.object(host, "cpu_times", side_effect=[{8: (100, 90)}, {8: (200, 180)}]):
            with self.assertRaises(RuntimeError): host.initial_window(self.state, seconds=1)

    def test_restore_frequency_interval_and_governor_preferences(self):
        original = dict(scaling_governor="powersave", scaling_min_freq="416174",
                        scaling_max_freq="5314214", energy_performance_preference="balance_performance")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in original.items(): (root / name).write_text(value)
            (root / "scaling_min_freq").write_text("2401000")
            (root / "scaling_max_freq").write_text("2401000")
            (root / "scaling_governor").write_text("performance")
            host.restore_policy(root, original)
            self.assertEqual({name: host.read(root / name) for name in original}, original)

    def test_partition_removal_retries_transient_busy(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            (group / "cgroup.procs").write_text("")
            with patch.object(Path, "rmdir", side_effect=[OSError(errno.EBUSY, "busy"), None]) as remove, \
                 patch.object(host.time, "sleep"):
                host.remove_partition(group)
                self.assertEqual(remove.call_count, 2)
            (group / "cgroup.procs").write_text("123")
            with self.assertRaises(RuntimeError): host.remove_partition(group)


if __name__ == "__main__": unittest.main()
