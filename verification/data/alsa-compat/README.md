# ALSA application compatibility probe

`alsa_probe.c` links against unmodified upstream alsa-lib 1.2.14. It exercises
card/control discovery, hardware parameter negotiation, software parameters,
poll, write and mmap playback, drain, planar capture, mmap capture, linked
pause/resume, boundary-mode silence, user controls, TLV and control events. The
x86_64 QEMU profile must provide both HDA (card 0) and VirtIO sound (card 1).
Capture uses HDA. The program fails if either expected card is absent.

The explicit hardware-plugin entry points avoid requiring a guest ALSA config
file or plugin loader. Negotiation and PCM operations are normal alsa-lib APIs.
No downloaded source, binary, or library is stored in the repository.

Build alsa-lib from its official release tarball with a temporary prefix:

```sh
./configure --prefix=/tmp/narf-alsa-host --disable-shared --enable-static --disable-python
make -j8
make install
```

Then, from the NARF root:

```sh
gcc -O2 -Wall -static -I/tmp/narf-alsa-host/include \
  verification/data/alsa-compat/alsa_probe.c /tmp/narf-alsa-host/lib/libasound.a \
  -lm -ldl -lpthread -o /tmp/narf-alsa-probe
XTASK_STAGE_BIN=/tmp/narf-alsa-probe:alsa-probe cargo xtask run-interactive \
  --arch=x86_64 --features cgroup-all,container \
  --cmd /alsa-probe --expect alsa-compat-ok
```

The binary is staged at `/alsa-probe` because the guest's built-in `/bin` mount
would hide an initramfs file below `/bin`. This is an optional integration check;
ordinary targeted tests do not download or build alsa-lib.

The persistent kernel tests are tagged `drivers/sound/alsa` and
`syscall_abi/sound`. Their errno and precedence oracles are the local Linux
7.3-rc4 sources under `/usr/src/linux`:

| Contract | Linux source |
| --- | --- |
| PCM state, parameter, transfer ioctl and mmap checks | `sound/core/pcm_native.c` |
| Access checks, zero transfers, null buffers, pointer commits | `sound/core/pcm_lib.c` |
| Mixer locks, TLV, subscriptions, events | `sound/core/control.c` |
| Control-fd PCM enumeration and info | `sound/core/pcm.c` |
| Wire layouts and ioctl request words | `include/uapi/sound/asound.h` |
| Numeric errno values | `include/uapi/asm-generic/errno-base.h`, `errno.h` |

Compile the independent header assertions to verify errno numbers, ioctl words,
structure sizes and offsets directly against that tree:

```sh
gcc -std=c11 -Wall -Werror -I/usr/src/linux/include/uapi \
  verification/data/alsa-compat/uapi_contract.c -o /tmp/narf-alsa-uapi
/tmp/narf-alsa-uapi
```

The sound specification defines hardware capabilities and platform power
responsibilities. This probe validates the implemented PCM/control paths;
audible quality and physical system power transitions require hardware tests.
