# userspace/init — init

The first user process. It prints its startup lines and then parks in a
`sleep(u32::MAX)` loop. That is all it does today: the code notes there
is no real work yet, and the parking loop is a placeholder until a real
`pause()` / signal-wait primitive and child reaping land.

The whole program is `src/main.rs`, a `no_std` binary on `narf-libc`.
