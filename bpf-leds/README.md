# bpf-leds — BPF-to-LED Control

`narf-bpf-leds` lets a BPF program drive an LED — set a brightness, start a
blink, turn it off, or set an RGB color. It supplies a single kfunc,
`narf_led_submit`, that a loaded BPF program may call, giving BPF a controlled
window onto the physical indicators of the machine. The intended use is
expressive status signaling: a program attached somewhere in the kernel can
reflect system state onto an LED without that state having to be plumbed
through native code first.

The crucial property is that the kfunc is safe to call from atomic context. It
does no allocation and never blocks: it only enqueues a command into the LED
engine's lock-free mailbox in `narf-drivers-leds`. A background worker in that
crate later drains the mailbox, resolves the target device, and performs the
real work — the parts that may need to snapshot the LED registry or issue I²C
color writes on real hardware, where sleeping is permitted. That mediation is
exactly what makes it legal for a program running in atomic context to touch an
LED at all; it is the same enqueue-and-defer shape the `struct_ops` committer
and the Frame-mediated probe-read path use, and it is specified in the BPF
atomic-context rules. The kfunc reports success, a retry-worthy failure when
the mailbox is full or contended, or an invalid-argument error for an unknown
action; a bad device index is a harmless no-op resolved later, not an error at
submit time, because the kfunc deliberately does not resolve the device.

Like `narf-bpf-idle`, this crate is a seam: it depends on both `narf-bpf` (for
the `kfunc!` macro that registers the function into the kernel's kfunc link
section so the verifier can resolve it) and `narf-drivers-leds` (for the
mailbox and worker), so neither the BPF subsystem nor the LED subsystem needs
to know about the other. The crate registers a late-stage initcall that starts
the LED engine worker after device discovery, and anchors the kfunc so its
link-section entry is pulled in.

`narf-bpf-leds` is `no_std` and `alloc`-backed, with strict lints. Its non-test
dependencies are `narf-bpf`, `narf-drivers-leds`, and `narf-init`. The
`kernel-test` feature adds the BPF ISA, verifier, and test harness so the
smokes can assemble, verify, and load a program that calls the kfunc.
