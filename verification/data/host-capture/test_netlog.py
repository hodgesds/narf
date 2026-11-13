#!/usr/bin/env python3
"""Run narf-netlog against a fake procfs and a local UDP receiver."""
from pathlib import Path
import os
import socket
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).with_name('narf-netlog').resolve()


class NetLog(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.proc = Path(self.temporary.name) / 'proc'
        files = {
            'sys/kernel/random/boot_id': '9b8af885-bf79-479e-b712-fe4aa8c5f4a3',
            'uptime': '133.09 1148.56',
            'loadavg': '1.00 0.50 0.25 2/600 1500',
            'stat': 'cpu  1 2 3 4\ncpu0 1 2 3 4\nintr 5\n',
            'meminfo': ''.join(f'Line{i}: {i} kB\n' for i in range(8)),
            'narf/nvme_queues': 'nvme1 q1 isr_runs=10 irq_missed=0\n',
            'narf/tasks': 'tid=38 origin=writeback\n',
            '1189/task/1189/comm': 'kwin_wayland',
            '1189/task/1189/stat': '1189 (kwin_wayland) S 1186 0',
            '1189/task/1189/syscall': '271 0x1 0xd 0x7ff 0x0 0x8 0x0 0x7ff 0x409',
            '1189/task/1189/wchan': 'ppoll',
            '1215/task/1220/comm': 'Thread (pooled)',
            '1215/task/1220/stat': '1220 (Thread (pooled)) D 1 0',
            '1215/task/1220/syscall': '74 0x5 0x0 0x0 0x0 0x0 0x0 0x7ff 0x409',
            '1215/task/1220/wchan': 'fsync',
        }
        for relative, text in files.items():
            path = self.proc / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text + ('' if text.endswith('\n') else '\n'))

    def run_netlog(self, rounds, kmsg):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(receiver.close)
        receiver.bind(('127.0.0.1', 0))
        receiver.settimeout(0.5)
        packets, done = [], threading.Event()

        def drain():
            # Read while the script sends: a full socket buffer drops datagrams.
            while True:
                try:
                    packets.append(receiver.recv(65535))
                except socket.timeout:
                    if done.is_set():
                        return

        reader = threading.Thread(target=drain)
        reader.start()
        env = dict(os.environ, NARF_NETLOG_PROC=str(self.proc),
                   NARF_NETLOG_KMSG=kmsg, NARF_NETLOG_ROUNDS=str(rounds),
                   XDG_RUNTIME_DIR=self.temporary.name)
        try:
            subprocess.run(['bash', str(SCRIPT), '127.0.0.1',
                            str(receiver.getsockname()[1]), '0'],
                           env=env, check=True, timeout=60)
        finally:
            done.set()
            reader.join()
        lines = []
        for packet in packets:
            self.assertLessEqual(len(packet), 1300)
            lines += packet.decode().splitlines()
        return lines

    def test_stream_carries_kernel_log_and_thread_waits(self):
        lines = self.run_netlog(2, 'printf "first kernel line\\nsecond\\n"')
        self.assertTrue(lines)
        seqs = [int(line.split()[1]) for line in lines]
        self.assertEqual(seqs, list(range(len(seqs))))
        self.assertTrue(all(line.startswith('9b8af885 ') for line in lines))
        bodies = [line.split(' ', 2)[2] for line in lines]
        self.assertIn('K first kernel line', bodies)
        self.assertIn('K second', bodies)
        self.assertIn('Q nvme1 q1 isr_runs=10 irq_missed=0', bodies)
        self.assertIn('N tid=38 origin=writeback', bodies)
        self.assertIn('T 1215 1220 D Thread (pooled) | 74 0x5 0x0 0x0 0x0 | fsync',
                      bodies)
        # Round one sends every thread; round two only changed ones (none).
        self.assertEqual(sum(b.startswith('T 1189 1189 ') for b in bodies), 1)
        self.assertEqual(sum(b.startswith('H up=133.09') for b in bodies), 2)

    def test_many_lines_split_into_bounded_datagrams(self):
        lines = self.run_netlog(1, 'seq 1 3000')
        kernel = [line.split(' ', 2)[2] for line in lines if ' K ' in line]
        self.assertEqual(kernel, [f'K {i}' for i in range(1, 3001)])


if __name__ == '__main__':
    unittest.main()
