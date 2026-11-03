#!/usr/bin/env python3
"""Black-box checks for the native-boot collector's bounded text stream."""
from pathlib import Path
import os
import re
import select
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name('narf-plasma-capture').read_text()
BEGIN = SOURCE.index('batched_stream() {')
END = SOURCE.index('\nkernel_snapshots()', BEGIN)
# Extract the function without launching any host collection side effects.
FUNCTION = SOURCE[BEGIN:END]
HELPER = None


def command():
    script = FUNCTION + '\nbatched_stream\n'
    return ['bash', '-c', script]


def environment():
    return {**os.environ, 'NARF_CAPTURE_STREAM_HELPER': str(HELPER), 'LC_ALL': 'C.UTF-8'}


def cleanup(proc):
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    for stream in [proc.stdin, proc.stdout, proc.stderr]:
        if stream is not None:
            stream.close()


def visible(proc, size, timeout=7):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) < size and time.monotonic() < deadline:
        if select.select([proc.stdout], [], [], max(0, deadline-time.monotonic()))[0]:
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


class BatchStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global HELPER
        cls.temporary = tempfile.TemporaryDirectory(prefix='narf-capture-test-')
        HELPER = Path(cls.temporary.name) / 'stream-helper'
        source = Path(__file__).with_name('narf-capture-stream.c')
        subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(HELPER)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_empty_stream_exits(self):
        result = subprocess.run(command(), input=b'', capture_output=True, timeout=5, env=environment())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_raw_text_and_unterminated_tail_survive_chunk_boundaries(self):
        # Crosses many buffer boundaries, including inside UTF-8 sequences.
        payload = (b'back\\slash\r\nblank\n\n\0' + '£→🙂'.encode()) * 8193 + b'last line without newline'
        result = subprocess.run(command(), input=payload, capture_output=True, timeout=10,
                                env=environment())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, payload)

    def test_pipe_read_and_write_counts_are_bounded(self):
        # Fits PIPE_BUF, so the parent cannot deadlock while writing before
        # it starts draining stdout on systems with a small pipe capacity.
        payload = (b'log \\ bytes \xc2\xa3\n' * 256)
        proc = subprocess.Popen(command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0, env=environment())
        try:
            proc.stdin.write(payload)
            proc.stdin.flush()
            self.assertEqual(visible(proc, len(payload)), payload)
            accounting = (Path('/proc') / str(proc.pid) / 'io').read_text()
            counts = dict(re.findall(r'^(syscr|syscw): (\d+)$', accounting, re.MULTILINE))
            # Count oracles, not timing benchmarks. Allow short pipe reads
            # and loader work, reject per-byte reads and tiny shell writes.
            self.assertLess(int(counts['syscr']), 512, accounting)
            self.assertLess(int(counts['syscw']), 8, accounting)
            proc.stdin.close()
            proc.stdin = None
            rest, error = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, error)
            self.assertEqual(rest, b'')
        finally:
            cleanup(proc)

    def test_timeout_publishes_partial_before_eof(self):
        proc = subprocess.Popen(command(), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=environment())
        partial = b'partial line \\ with no newline ' + '£'.encode()
        tail = b' then more\nlast fragment'
        try:
            proc.stdin.write(partial)
            proc.stdin.flush()
            received = visible(proc, len(partial))
            self.assertEqual(received, partial, 'partial block stayed buffered in the open producer')
            self.assertIsNone(proc.poll())
            proc.stdin.write(tail)
            proc.stdin.close()
            proc.stdin = None
            rest, error = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, error)
            self.assertEqual(bytes(received) + rest, partial + tail)
        finally:
            cleanup(proc)

    def test_stop_signal_publishes_already_read_partial_buffer(self):
        proc = subprocess.Popen(command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0, env=environment())
        try:
            directory = Path('/proc') / str(proc.pid)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                status = (directory / 'status').read_text()
                caught = int(re.search(r'^SigCgt:\s*([0-9a-f]+)$', status, re.MULTILINE)[1], 16)
                if caught & (1 << (signal.SIGTERM-1)):
                    break
                time.sleep(.005)
            else:
                self.fail('stream helper did not install its stop handler')
            def rchar():
                return int(re.search(r'^rchar: (\d+)$', (directory / 'io').read_text(), re.MULTILINE)[1])
            before = rchar()
            partial = b'buffered bytes before service stop'
            proc.stdin.write(partial)
            proc.stdin.flush()
            deadline = time.monotonic() + 3
            while rchar() < before + len(partial) and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertGreaterEqual(rchar(), before + len(partial))
            proc.send_signal(signal.SIGTERM)
            result, error = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0, error)
            self.assertEqual(result, partial)
        finally:
            cleanup(proc)


if __name__ == '__main__':
    unittest.main()
