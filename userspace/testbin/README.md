# userspace/testbin — testbin

A minimal `no_std` user binary that exists for NARF's user-mode tests:
the verification e2e harness runs it and greps its output. Its `_start`
entry point invokes the kernel through `narf-user-runtime` (`int 0x80`
on x86_64, `svc #0` on aarch64) and links at user virtual address
`0x0000_0080_0000_1000` via the sibling `testbin.ld`.

It drives the probes the harness looks for, printing `<probe>: ok` or
`<probe>: bad` for each: argv, aux, mmap, boot, ring, fs, wr, pid, brk,
clk, sig, and user — plus a framebuffer probe that prints `fb0: ok
<W>x<H>` (or `fb0: skip` / `fb0: bad ...`). It finishes by calling
`exit_task`. The whole program is `src/main.rs`.
