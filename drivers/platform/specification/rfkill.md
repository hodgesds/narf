# rfkill core and `/dev/rfkill`

## 1. Purpose and scope

`rfkill.rs` is the radio registry: Wi-Fi, Bluetooth, WWAN and GPS radios,
plus the soft and hard block state of each. `rfkill_dev.rs` is the Linux
`/dev/rfkill` channel over that registry, as `net/rfkill/core.c` provides
it. NetworkManager, wpa_supplicant, `systemd-rfkill`, the `rfkill` tool and
desktop airplane-mode toggles use the device. `/sys/class/rfkill/rfkill<N>`
is published from the same registry.

## 2. Assumptions

- Vendor laptop drivers (EC, ASUS/HP WMI) register their radios at
  `Stage::Subsys` and report hard blocks from firmware.
- A Wi-Fi stack registers one radio per wiphy with an indexed switch.
- Userspace runs as root for writes; the node is mode 0644.

## 3. Public interface

- `register_radio(name, type, Option<fn(bool) -> bool>) -> idx`. Idempotent
  by name among live radios.
- `register_radio_indexed(name, type, fn(idx, bool) -> bool) -> idx`: one
  switch for several radios. It is told which radio to drive.
- `unregister_radio(idx)` (`rfkill_unregister`): the radio leaves and its
  index is never reused.
- `set_soft_block(idx, blocked)`: runs the switch first and records the
  block only if the switch succeeds. `set_all_soft_blocked` and
  `toggle_all` do the same for every radio, as the airplane key does.
- `set_hard_block(idx, blocked)` / `update_state(idx, state)`: firmware
  reports a hard block. Userspace cannot clear it.
- `radio_state(idx)` is `None` once the radio is unregistered.
- `/dev/rfkill` (misc 10:242), registered with the sysfs publication:
  - Each open gets its own queue, starting with one `RFKILL_OP_ADD` per
    live radio. Every later register, unregister or state change appends
    `ADD`, `DEL` or `CHANGE` to every open queue.
  - `read` returns one `struct rfkill_event_ext` (9 bytes:
    `idx, type, op, soft, hard, hard_block_reasons`, with
    `RFKILL_HARD_BLOCK_SIGNAL` while hard-blocked). It is truncated to the
    caller's count and to `RFKILL_IOCTL_MAX_SIZE`. It blocks on an empty
    queue; `O_NONBLOCK` gets `EAGAIN`. Poll is always writable, and
    readable while events are queued.
  - `write` needs at least 7 bytes. `RFKILL_OP_CHANGE` sets the soft block
    of `idx` if its type matches or is `RFKILL_TYPE_ALL`.
    `RFKILL_OP_CHANGE_ALL` sets it on every radio of the type. Other ops,
    and types beyond `NUM_RFKILL_TYPES`, are `EINVAL`.
  - Ioctls: `RFKILL_IOCTL_NOINPUT` is accepted. `RFKILL_IOCTL_MAX_SIZE`
    sets the read and write size.

## 4. Invariants

- Lock order is registry, then the reader list, then each reader's queue
  and readiness cell. Opening snapshots the `ADD` events and subscribes
  under the registry lock, so no event is lost or doubled.
- An event is emitted only for an actual state change.
- A reader holds at most 1024 queued events; the oldest is dropped
  beyond that.

## 5. Tests

`drivers/platform/rfkill` (`smoke_dev_rfkill_events_and_control`) covers
`/dev/rfkill`. `drivers/platform/wmi1086` covers sysfs.
