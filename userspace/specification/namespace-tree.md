# Namespace tree — Requirements

> Status: **v0.1 requirements**, derived by reading the Linux
> implementation in `/usr/src/linux` (7.0.0-rc7). Every requirement cites
> the function it comes from. Nothing here is invented: where NARF must
> choose, the choice is recorded in §12 as a deliberate deviation with a
> reason, not as a silent difference.

## 1. Purpose

Linux 6.17 added `kernel/nstree.c`. Before it, a namespace could only be
reached through something already using it — a task, an open `/proc/<pid>/ns/*`
fd, a socket. There was no way to ask *what namespaces exist*. The namespace
tree is a registry of every namespace of every flavour, keyed by a globally
unique id, which makes `listns(2)`, nsfs file handles, and mount-namespace
traversal possible.

This document states what NARF must implement to be compatible with that
ABI, and what NARF has today.

## 2. Reference sources

| Area | File |
| --- | --- |
| Tree structure, lookup, traversal, `listns(2)` | `kernel/nstree.c` (792 lines) |
| Tree API and macros | `include/linux/nstree.h` |
| Per-namespace common header, refcounts | `include/linux/ns_common.h`, `kernel/nscommon.c` |
| UAPI: ids, types, `struct ns_id_req`, ioctls | `include/uapi/linux/nsfs.h` |
| nsfs ioctls, file handles, `is_current_namespace` | `fs/nsfs.c` (714 lines) |
| `current_in_namespace` | `include/linux/nsfs.h` |

---

## 3. Identity

### R1 — One id space across all flavours

`__ns_tree_gen_id` (`nstree.c:380`) draws from a single
`atomic64_t namespace_cookie`. The kerneldoc is explicit: *"All namespace
types share the same id space and thus can be compared directly. IOW, when
two ids of two namespaces are equal, they are identical."*

Ids are never reused within a boot. Id `0` is never assigned
(`VFS_WARN_ON_ONCE(!ns->ns_id)` in `__ns_tree_add_raw`) and is the wire
spelling of "unset" throughout the ABI.

**NARF:** satisfied — `NsId` is a `u64` from one `NS_ID_COUNTER`.

### R2 — Initial namespaces have FIXED, UAPI-visible ids

`include/uapi/linux/nsfs.h:71` defines `enum init_ns_id`:

| Namespace | id |
| --- | --- |
| IPC | 1 |
| UTS | 2 |
| USER | 3 |
| PID | 4 |
| CGROUP | 5 |
| TIME | 6 |
| NET | 7 |
| MNT | 8 |

`NS_LAST_INIT_ID = MNT_NS_INIT_ID = 8`. The dynamic counter therefore starts
at `NS_LAST_INIT_ID + 1 = 9` (`nstree.c:382`).

These are UAPI, not implementation detail: `is_ns_init_id(ns)` is
`ns->ns_id <= NS_LAST_INIT_ID` (`ns_common.h:23`) and gates refcount
behaviour, and userspace can hard-code them.

**NARF: satisfied** — it was not. `init_namespaces()` allocated initial ids
from `NS_ID_COUNTER`, which started at 1, so the values depended on boot
ordering and collided with the UAPI constants only by accident. Now a
reserved block, with the dynamic counter starting at 9.

### R3 — Initial namespaces have fixed inode numbers

`enum init_ns_ino` (`nsfs.h:47`): MNT `0xEFFFFFF8` … IPC `0xEFFFFFFF`,
plus the kernel-internal `MNT_NS_ANON_INO = 0xEFFFFFF7`. `is_ns_init_inum`
range-checks against these, and `__ns_common_init` uses the *inum* (not the
id) to decide whether a namespace starts life active.

**NARF: satisfied.** `namespaces::init_ns_ino` plus `ns_inum(id)`, which
derives rather than stores: dynamic inums are offset into the
`PROC_DYNAMIC_FIRST` (`0xF0000000`) range that `proc_alloc_inum` allocates
from, and NARF's ids are already dense and monotonic above the reserved
block, so the offset is unique for the same reason Linux's ida is — without
a second allocator to keep in step with the first.

Needed by R29: `nsfs_encode_fh` puts the inum in the handle, so a handle
could not be faithful without one. `NsFd::stat` reports it as `st_ino`,
which is what `ns_match` compares.

### R4 — `ns_type` values are the `CLONE_NEW*` bits

`enum ns_type` (`nsfs.h:82`): TIME `1<<7`, MNT `1<<17`, CGROUP `1<<25`,
UTS `1<<26`, IPC `1<<27`, USER `1<<28`, PID `1<<29`, NET `1<<30`.
`NS_ALL` is their union (`nstree.c:424`).

**NARF:** satisfied — `namespaces::ns_type`.

---

## 4. Data model

### R5 — Three independent indices per namespace

`struct ns_common` carries three `ns_tree_node`s, and
`__ns_tree_add_raw` (`nstree.c:196`) inserts into all three:

1. **Per-type tree** — one `ns_tree_root` per flavour
   (`mnt_ns_tree`, `net_ns_tree`, … `nstree.c:26–65`).
2. **Unified tree** — `ns_unified_root`, every namespace of every flavour.
3. **Per-owner tree** — rooted in the *owning user namespace's*
   `ns_owner_root`, so "what does this user namespace own" is a subtree
   walk, not a scan.

Each index is an rbtree **plus** a list held in the same sorted order
(`ns_tree_node_add`, `nstree.c:112`: insert into the rbtree, find `rb_prev`,
then `list_add_rcu` after it). The rbtree answers "find id ≥ N" in
O(log n); the list makes "give me the next one" O(1) for traversal.

**NARF: partially satisfied.** One `BTreeMap<NsId, NsTreeEntry>` serves as
the unified index and gives ordered range queries (covering both the rbtree
and list roles). Per-type and per-owner indices do not exist — both are
linear filters over the unified map today. Acceptable at NARF's namespace
counts; must be recorded as a known complexity difference, not a behaviour
difference (§12 D1).

### R6 — The tree holds a NON-owning reference

`ns_tree_remove` is called from each flavour's *free* path — e.g.
`free_user_ns` (`kernel/user_namespace.c:205`), `free_ipcs`
(`ipc/namespace.c:208`), `cleanup_net` (`net/core/net_namespace.c:680`).
Tree membership therefore does not keep a namespace alive; the tree is
emptied as the object dies.

**NARF:** satisfied by the weak-handle conversion —
`NsTreeEntry.object: Weak<dyn NsObject>`. `Weak` is the exact analogue: it
does not extend the lifetime, and it fails to upgrade once the last owner is
gone.

### R7 — Registration happens after the object is constructed

Every caller (`ns_tree_add(ns)` at `user_namespace.c:162`,
`utsname.c:62`, `pid_namespace.c:126`, `cgroup/namespace.c:88`, and
`ns_tree_add_raw` at `fs/namespace.c:3163`, `ipc/namespace.c:90`,
`net/core/net_namespace.c:453`) registers a fully-initialised namespace.
`ns_tree_add` = generate id, then add; `ns_tree_add_raw` = add with an id
generated earlier.

**NARF:** required by construction — there is no `Weak` to store before the
`Arc` exists. This is why every constructor must build the `Arc` first and
register second.

---

## 5. Lifetime

### R8 — Two refcounts: `__ns_ref` and `__ns_ref_active`

`ns_common.h:36`. `__ns_ref` is ordinary lifetime. `__ns_ref_active` is
"is this namespace in active use" — incremented when installed in an
`nsproxy`, decremented when the last active use goes.

`__ns_common_init` (`nscommon.c:56`) starts `__ns_ref` at 1 and
`__ns_ref_active` at **0** for a new namespace, **1** for an initial one.

### R9 — The active count cascades up the owner chain

`__ns_ref_active_put` / `__ns_ref_active_get` (`nscommon.c:164`, `:280`).
Each namespace holds ONE active reference on its owning user namespace.
When a namespace's own active count reaches zero it drops that reference,
which may cascade further up; the walk stops at the first still-active
owner. `ns_owner` (`nscommon.c:93`) returns `NULL` for `init_user_ns`,
which is always active and terminates every chain.

Getting resurrects symmetrically: if `atomic_fetch_add` saw 0, the
namespace was dead and must re-take a reference on its owner, recursively.

### R10 — Initial namespaces are permanently active

Every refcount helper short-circuits on `is_ns_init_id(ns)`
(`ns_common.h:72–112`) and asserts the counts are exactly 1. An initial
namespace is never removed from the tree and never freed.

### R11 — A lookup must not hand out an inactive namespace

`ns_get_unless_inactive` (`ns_common.h:136`):

```c
if (!__ns_ref_active_read(ns)) { VFS_WARN_ON_ONCE(is_ns_init_id(ns)); return NULL; }
if (!__ns_ref_get(ns)) return NULL;
return ns;
```

Every tree read path funnels through it: `lookup_ns_id`, `lookup_ns_id_at`,
`lookup_ns_owner_at`, `legitimize_ns`, `nsfs_fh_to_dentry`. A namespace
found in the tree but no longer active is **skipped**, not reported.

**NARF: satisfied, modulo D2.** `Weak::upgrade()` failing is the analogue of
`__ns_ref_get` failing, and *every* read path now filters
`strong_count() > 0`: `ns_tree_lookup`, `ns_tree_list`, and
`ns_tree_entries_from`. There is no distinct *active* count: NARF has no
`nsproxy`, so "is anything using it" and "is it alive" are the same
question. Recorded as §12 D2.

---

## 6. Concurrency

### R12 — Writers take a seqlock; readers are RCU

`DEFINE_SEQLOCK(ns_tree_lock)` (`nstree.c:11`), with
`write_seqlock` for add/remove and `read_seqlock_excl` for the two
*exclusive* readers that walk rbtree pointers (`lookup_ns_id_at`,
`lookup_ns_owner_at`). All other reads are lock-free under
`rcu_read_lock()`: `rb_find_rcu`, `list_add_rcu`, `list_bidir_del_rcu`,
`list_entry_rcu`, `rcu_dereference`.

`ns_tree_lookup_rcu` and `__ns_tree_adjoined_rcu` both begin with
`RCU_LOCKDEP_WARN(!rcu_read_lock_held(), …)` — calling them outside an RCU
read section is a kernel bug.

**NARF: satisfied.** The tree is `narf_rcu::Atomic<BTreeMap<NsId,
NsTreeEntry>>`. `read_tree` pins and loads — no lock. `mutate_tree` takes a
writer-only `IrqSafeSpinLock<()>` (the seqlock's write side, and nothing
more: it is never held across a read), clones, mutates, and publishes.

### R13 — Lookups retry on a concurrent write

`__ns_tree_lookup_rcu` / `__ns_unified_tree_lookup_rcu` (`nstree.c:310`,
`:325`) loop on `read_seqbegin` / `read_seqretry`, breaking early on a hit.
A miss that raced a write is retried rather than reported as absent.

**NARF: not applicable.** The retry exists because `rb_find_rcu` walks a
tree that a writer is rotating *in place*, so a concurrent insert can make a
present node unreachable mid-descent. A copy-on-write cell publishes a whole
map atomically: a reader either sees the map before the write or the map
after it, never a partial one. There is nothing to retry. This is a
consequence of D3, and the one place where COW is strictly simpler than
in-place RCU.

### R14 — The listing loop drops and re-takes the read lock per element

`do_listns` (`nstree.c:692`) and `do_listns_userns` (`:584`) call
`legitimize_ns` under RCU, then `rcu_read_unlock()` before `put_user`,
then `rcu_read_lock()` again to advance. The reference taken by
`legitimize_ns` is what keeps the cursor valid across the gap; `prev` is
put on the next iteration. This is the requirement that makes paging safe
against concurrent namespace destruction.

**NARF: met differently — see D5.** `listns` copies the filtered entries
into an owned `Vec` under one pin, then releases it and writes to userspace.
Linux cannot do that — `ns_common` is not copyable and the list is
intrusive — so it must keep a reference alive across the `put_user`, which
is what forces the drop-and-retake dance. An owned snapshot of `Weak`
handles has no such constraint: nothing it names can be freed under it,
because it holds no borrows into the tree at all.

What NARF gives up is *freshness*: a namespace created after the snapshot is
taken will not appear in that page. The cursor makes that harmless — the
next call resumes at `last + 1` and picks it up — and Linux has the same
property for anything created behind its walk position.

---

## 7. Lookup and traversal

### R15 — Lookup by id, optionally constrained by type

`ns_tree_lookup_rcu(ns_id, ns_type)` (`nstree.c:345`): a non-zero
`ns_type` selects the per-type tree via `ns_tree_from_type`; zero searches
the unified tree. An unknown type returns `NULL` — *not* an error.

### R16 — Lookup of the first id ≥ N

`lookup_ns_id_at(ns_id, ns_type)` (`nstree.c:624`) and
`lookup_ns_owner_at(ns_id, owner)` (`:462`) both descend the rbtree keeping
the smallest node with `id >= ns_id`. Both end with
`ns_get_unless_inactive`. This is the cursor primitive `listns` pages with.

### R17 — Ordered next/previous traversal

`__ns_tree_adjoined_rcu(ns, ns_tree, previous)` (`nstree.c:365`) follows
the sorted RCU list forward or backward within one type tree, returning
`ERR_PTR(-ENOENT)` at either end. This is what backs
`NS_MNT_GET_NEXT` / `NS_MNT_GET_PREV`.

**NARF: satisfied.** `ns_tree_adjoined(from, ns_type, previous)`. Linux
walks a per-type list so "next" is implicitly "next of this flavour"; NARF
has one map, so the flavour is a filter over a `BTreeMap` range in either
direction. Dead entries are skipped inside, which composes with
`get_sequential_mnt_ns`'s own permission loop rather than duplicating it.

---

## 8. `listns(2)`

Syscall 470 on x86_64 and arm64.
`listns(const struct ns_id_req *req, u64 *ns_ids, size_t nr_ns_ids, unsigned int flags)`.

### R18 — Argument validation, in order

`SYSCALL_DEFINE4(listns)` (`nstree.c:761`):

| Condition | Result |
| --- | --- |
| `flags != 0` | `-EINVAL` |
| `nr_ns_ids > 1000000` | `-EOVERFLOW` |
| `!access_ok(ns_ids, nr_ns_ids * 8)` | `-EFAULT` |

The order is load-bearing — `flags` is rejected before the buffer is even
range-checked.

### R19 — `struct ns_id_req` is an extensible struct

`copy_ns_id_req` (`nstree.c:427`), `NS_ID_REQ_SIZE_VER0 = 32`:

```c
{ __u32 size; __u32 spare; __u64 ns_id; __u32 ns_type; __u32 spare2; __u64 user_ns_id; }
```

| Condition | Result |
| --- | --- |
| `get_user(size)` faults | `-EFAULT` |
| `usize > PAGE_SIZE` | `-E2BIG` |
| `usize < 32` | `-EINVAL` |
| non-zero bytes past byte 32 | `-E2BIG` (via `copy_struct_from_user`) |
| `kreq->spare != 0` | `-EINVAL` |
| `kreq->ns_type & ~NS_ALL` | `-EOPNOTSUPP` |

**E2BIG is decided before EINVAL**, so an oversized `size` reports E2BIG
even though it is also not a known version.

`spare2` is **not** checked. A caller setting it is accepted. (Asymmetric
with `spare`, and it is the kernel's behaviour, so NARF must match it.)

`ns_type & ~NS_ALL` is `-EOPNOTSUPP`, deliberately neither `-EINVAL` nor an
empty result: a caller probing for a flavour this kernel does not know must
be able to distinguish "no such namespace type" from "none exist".

### R20 — Two listing modes

`if (kreq.user_ns_id) return do_listns_userns(&klns); return do_listns(&klns);`

**Owner mode** (`user_ns_id != 0`, `do_listns_userns`, `nstree.c:551`):
- `LISTNS_CURRENT_USER` (`0xffffffffffffffff`) resolves to
  `current_user_ns()` unconditionally — it is never looked up.
- Any other value is `lookup_ns_id(user_ns_id, CLONE_NEWUSER)`; if that
  returns NULL → **`-EINVAL`**. An owner id naming nothing, or naming a
  namespace of another flavour, is an error, not an empty result.
- Iteration walks that user namespace's `ns_owner_root` list.

**Global mode** (`user_ns_id == 0`, `do_listns`, `nstree.c:692`):
- `if (hweight32(kls->ns_type) == 1) ns_type = kls->ns_type; else ns_type = 0;`
  — **exactly one** type bit selects that per-type tree; zero bits *or two
  or more* bits fall back to the unified tree, with the multi-bit mask
  applied per element by `ns_requested`.
- `ns_tree_from_type` returning NULL for a selected single type →
  `-EINVAL`.

### R21 — The cursor

`req->ns_id` is the last id already returned, zero on the first call.
When non-zero the walk starts at `lookup_*_at(last_ns_id + 1, …)`, and
**if that finds nothing the call returns `-ENOENT`** — not an empty
success. That is how a paging loop terminates; returning 0 would be
indistinguishable from "nothing is visible to you" and the caller would
spin.

The lookup applies only what the SELECTED tree carries — the type in
single-type global mode, the owner in owner mode, nothing in unified mode —
never the caller's full mask and never the visibility check. The two halves
pull opposite ways:

- One type bit walks that flavour's tree, so exhausting that flavour IS the
  end of the list, even with higher-id namespaces of other flavours present.
- Zero bits, or two or more, walk the unified tree, so the same situation is
  an empty success.

Deciding it over the fully-filtered candidate set gets the second wrong;
always consulting the unified tree gets the first wrong, and a paging loop
never terminates.

### R22 — Per-element visibility

`legitimize_ns` (`nstree.c:533`) applies, in order:

1. `ns_requested` — the `ns_type` mask (`!kls->ns_type || (kls->ns_type & ns->ns_type)`).
2. `ns_get_unless_inactive` — skip dying namespaces (R11).
3. `may_list_ns`.

A namespace failing any of these is **skipped** (`continue`), never an
error, and does not consume a slot in the output buffer.

`may_list_ns` (`nstree.c:517`):

```c
if (kls->user_ns && kls->userns_capable) return true;
if (is_current_namespace(ns))            return true;
return may_see_all_namespaces();
```

`kls->userns_capable` is set to `may_see_all_namespaces()` and `kls->user_ns`
is set **only in owner mode** (`nstree.c:582`), so in global mode the first
clause never fires and the rule reduces to
"a namespace the caller is in, or full visibility".

### R23 — `may_see_all_namespaces`

`nscommon.c:313`:

```c
return (task_active_pid_ns(current) == &init_pid_ns) &&
       ns_capable_noaudit(init_pid_ns.user_ns, CAP_SYS_ADMIN);
```

Both halves matter. CAP_SYS_ADMIN *inside* a pid namespace is authority over
that namespace, not over the system, so a container root must not be able to
enumerate its host's namespaces.

### R24 — `is_current_namespace`

`fs/nsfs.c:479` dispatches on `ns_type` to
`current_in_namespace(...)`, defined (`include/linux/nsfs.h:38`) as
`__current_namespace_from_type(ns) == ns` — an identity comparison against
the corresponding slot of `current->nsproxy` (with `task_active_pid_ns` for
PID and `current_user_ns()` for USER).

### R25 — Return value

The count of ids written. `put_user` failure mid-loop → `-EFAULT`
(ids already written stay written). The loop stops when `nr_ns_ids`
is exhausted or the list ends.

**NARF status for §8:** satisfied, except R14's incremental locking, which
is D5. R20's `hweight32 == 1` selection and R21's cursor rule are both
`ns_tree_first_at`, which applies only the selected tree's constraint.

---

## 9. nsfs — ioctls and file handles

NARF has no nsfs *filesystem*, but an ns-fd is a real object
(`namespaces::NsFd`), which is all these need: the ioctls answer on the fd
and the handle encodes the namespace, neither of which requires a mount.

### R26 — Simple ioctls (`ns_ioctl`, `fs/nsfs.c`)

| ioctl | Behaviour |
| --- | --- |
| `NS_GET_USERNS` | new fd for the owning user namespace |
| `NS_GET_PARENT` | new fd for the parent; `-EINVAL` if the flavour has no `get_parent` |
| `NS_GET_NSTYPE` | returns the `CLONE_NEW*` value **as the return value** |
| `NS_GET_OWNER_UID` | `-EINVAL` unless USER; writes `from_kuid_munged(current_user_ns(), owner)` |
| `NS_GET_MNTNS_ID` | `-EINVAL` unless MNT, then falls through to `NS_GET_ID` |
| `NS_GET_ID` | writes `ns->ns_id` as `__u64` |
| `NS_GET_{PID,TGID}_{FROM,IN}_PIDNS` | `-EINVAL` unless PID; `-ESRCH` if no such task |

An unrecognised command returns `-ENOIOCTLCMD`, which the VFS translates to
`-ENOTTY`. An unrecognised *extensible* command returns `-ENOTTY` directly.

**NARF: satisfied.** `handlers/nsfs.rs`, dispatched from `sys_ioctl`
because four of these mint a new fd and the fd table belongs to that layer
— the same reason `TIOCGPTPEER` is handled there.

### R27 — Extensible ioctls

`NS_MNT_GET_INFO` / `NS_MNT_GET_NEXT` / `NS_MNT_GET_PREV` carry a size in
`_IOC_SIZE`. `nsfs_ioctl_valid` requires `extensible_ioctl_valid(cmd, …,
MNT_NS_INFO_SIZE_VER0)`; the handler additionally rejects
`usize < MNT_NS_INFO_SIZE_VER0` (16) with `-EINVAL`, and `-EINVAL` for a
non-MNT namespace or a NULL `uinfo` (INFO only).

`struct mnt_ns_info { __u32 size; __u32 nr_mounts; __u64 mnt_ns_id; }`.

**NARF: satisfied.** Every ioctl number and struct layout was computed
against `<linux/ioctl.h>` with `offsetof`, not assembled by hand.

### R28 — Traversal is privileged

`may_use_nsfs_ioctl` (`fs/nsfs.c`) returns `may_see_all_namespaces()`
for `NS_MNT_GET_NEXT` and `NS_MNT_GET_PREV`, and `true` for everything
else. Failure is **`-EPERM`**, checked before the namespace is even fetched
from the inode.

On top of that, `get_sequential_mnt_ns` SKIPS each namespace the caller
lacks `CAP_SYS_ADMIN` in rather than refusing, so an enumerating caller
walks what it may see and ends at `-ENOENT` instead of stopping dead at the
first it may not. The gate is about the system; the per-namespace check is
about each namespace.

**NARF: satisfied**, including the skip loop.

### R29 — nsfs file handles

`struct nsfs_file_handle { __u64 ns_id; __u32 ns_type; __u32 ns_inum; }`,
`FILEID_NSFS`. `nsfs_fh_to_dentry` (`fs/nsfs.c:518`):

- `fh_len < NSFS_FID_SIZE_U32_VER0` → NULL.
- Trailing bytes past the latest known size must be zero.
- `ns_id == 0` → NULL.
- `!fid->ns_inum != !fid->ns_type` → NULL (both set, or both unset).
- `ns_tree_lookup_rcu(ns_id, ns_type)`, then `ns_inum` and `ns_type` must
  match if supplied.
- `ns_get_unless_inactive` — deliberately racy, documented as such: the
  namespace may go inactive right after, and `nsfs_init_inode` will
  resurrect the tree.
- If the caller is **not** in the resolved namespace, `may_see_all_namespaces()`
  is required → otherwise `-EPERM`.
- PID special case: if the caller *is* in it but `child_reaper` is NULL
  (namespace is dying), `-EPERM`.
- An unknown `ns_type` → `-EOPNOTSUPP`.

This is the requirement that makes the id space meaningful across
`name_to_handle_at` / `open_by_handle_at`, and it is why R1's
"equal ids are identical namespaces" must hold.

**NARF: satisfied.** `name_to_handle_at(fd, "", .., AT_EMPTY_PATH)` on an
ns-fd emits a `FILEID_NSFS` handle; `open_by_handle_at` resolves it through
the tree with every cross-check above. The type and inode checks are what
matter: ids are unique within a boot but minted afresh on the next, so a
persisted handle would otherwise resolve silently to an unrelated
namespace.

---

## 10. Registration points per flavour

Every namespace type must register on create and deregister on free.

| Flavour | Create | Free |
| --- | --- | --- |
| USER | `user_namespace.c:162` | `:205` |
| UTS | `utsname.c:62` | `:98` |
| TIME | `time/namespace.c:108` | `:255` |
| PID | `pid_namespace.c:126` | `:152` |
| CGROUP | `cgroup/namespace.c:88` | `:38` |
| MNT | `fs/namespace.c:3163`, `:4298` (raw) | `:4190` |
| IPC | `ipc/namespace.c:90` (raw) | `:208` |
| NET | `net/core/net_namespace.c:453` (raw) | `:680` |

Initial namespaces are registered explicitly at boot:
`user_namespace.c:1412`, `utsname.c:163`, `time/namespace.c:488`,
`pid_namespace.c:478`, `cgroup/cgroup.c:6526`, `fs/namespace.c:6200`,
`ipc/shm.c:152`.

### R30 — Every flavour NARF implements must be in the tree

| Flavour | NARF object | In the tree today |
| --- | --- | --- |
| USER | `namespaces::UserNamespace` | yes |
| UTS | `namespaces::UtsNamespace` | yes |
| IPC | `namespaces::IpcNamespace` | yes |
| NET | `namespaces::NetNamespace` | yes — `initial_net_ns()` |
| PID | `pid_ns::PidNamespace` | yes — `initial_pid_ns()` |
| MNT | `filesystem::MountNamespace` | yes — `initial_mount_ns()` |
| CGROUP | `filesystem::cgroupfs::CgroupNamespace` | yes |
| TIME | none | declared in `NS_ALL`, never registered (D4) |

**Satisfied for every flavour NARF implements.** An id in the tree with no
object behind it cannot answer `NS_GET_*`, cannot be `Weak`-upgraded, and
cannot be told apart from a stale entry, so each initial namespace is now a
real object.

MNT is the one that needed care: the initial mount namespace *borrows* the
global registry (`MountStore::Registry`) rather than snapshotting it. A
snapshot would fork the mount table at boot — a later `mount(2)` through the
registry would be invisible through the namespace object, and the two would
drift with nothing reporting it.

Two further rules fall out of the reserved-id block (R2):

- `ns_tree_remove` ignores a reserved id. Linux says the same thing through
  `__ns_ref_put`, which short-circuits on `is_ns_init_id`: an initial
  namespace is permanently active and never leaves the tree (R10). It also
  closes a footgun — a reserved id names a *slot*, and if a displaced
  object's `Drop` ran after its replacement registered, it would erase the
  live entry.
- `init_namespaces()` states each registration itself rather than relying on
  the constructors, which memoise. Otherwise the initial namespaces could
  never be restored after a tree reset.

---

## 11. Concurrency requirements for NARF

### R31 — The tree must not serialise readers against writers

Linux's split is seqlock-write / RCU-read (R12). NARF's equivalent, using
`narf-rcu`:

- The map lives in `rcu::Atomic<BTreeMap<NsId, NsTreeEntry>>`.
- Readers `rcu::pin()` and `load()` — lock-free, no spinlock, and
  reentrant, which removes the self-deadlock hazard entirely (see R32).
- Writers clone-modify-`store()`; the displaced map is `defer_drop`-ed, so
  a reader holding a `Shared` view of the old map stays valid.
- QSBR is the correct variant: reads happen in syscall (task) context and
  `ReadGuard` is `!Send` and may not cross `.await`, which the syscall
  handlers do not do. Epoch would be needed only if a namespace lookup were
  ever added to an IRQ handler.

Write cost is O(n) per namespace create/destroy rather than Linux's O(log n)
in-place RCU insert. At NARF's namespace counts (tens) and creation rates
(`clone`/`unshare` only) that is the right trade for a lock-free read side —
recorded as §12 D3.

**NARF: satisfied.** `mutate_tree` retires the displaced map and drives no
grace period of its own; the executor drains at its poll boundaries, like
every other RCU consumer.

Getting there required fixing the collector. `narf-rcu`'s per-CPU queue was
a fixed **64-slot array** that, on its 65th entry, incremented
`bucket.overflow` and **dropped the pointer on the floor** — a silent leak
whose only evidence was `overflow_count_this_cpu()`, which nothing read.
Whole-map COW retires once per publish, so ordinary namespace churn reached
it. The first version of this work carried a `narf_rcu::sync()` per tree
mutation to keep the bucket drained, which is a consumer working around its
collector — the kind of local patch that outlives the problem it was for.

The queue is now **intrusive**: a `DeferHdr` is embedded in every
RCU-managed allocation (`DeferNode<T>` = header then value, `#[repr(C)]`),
so enqueue is a two-store splice that is allocation-free, infallible, and
IRQ-safe. That is Linux's `struct rcu_head` model, adopted for Linux's
reason — a retiring context may not be able to allocate, so the node must
already exist. `Shared::as_ref` hands out `&node.value`, keeping the header
away from readers still dereferencing the value during their grace period.

Pinned by `smoke_rcu_retire_far_past_old_bucket_cap_reclaims_all` (retire
256, assert all 256 destructors run — re-introducing the cap makes it fail)
and `smoke_rcu_reader_sees_old_value_across_publish` (a pinned reader keeps
its value across a publish, and the displaced value is reclaimed only after
the reader leaves).

### R32 — No lock may be held across an `Arc`/namespace drop

With the current `IrqSafeSpinLock`, dropping the last `Arc` to a namespace
while holding the tree lock re-enters `ns_tree_remove` on a non-reentrant
lock and self-deadlocks. Today that is a hand-maintained discipline at every
call site — `ns_tree_lookup_object` upgrades under the guard and hands the
`Arc` out to be dropped after it is released.

Under R31 the hazard is structural rather than disciplinary: readers hold no
lock, and reclamation is deferred to a quiescent point by construction. This
is the main reason to adopt `narf-rcu` here rather than a reason of
throughput.

**NARF: satisfied.** `read_tree` takes no lock at all, so a namespace drop
on any read path is now simply impossible to deadlock. The writer lock is
never held across a read, and the only thing published under it is a map of
`Weak` handles — nothing in a retired map can run a namespace destructor.

---

## 12. Deliberate deviations

| # | Deviation | Reason |
| --- | --- | --- |
| D1 | One unified `BTreeMap` instead of three indices (R5) | Per-type and per-owner become linear filters. Behaviour is identical; only complexity differs, at counts where it does not matter. Revisit if a workload creates thousands of namespaces. |
| D2 | No separate active refcount (R8–R11) | NARF has no `nsproxy`, so "installed somewhere" and "alive" are the same predicate. `Weak::upgrade` failing covers every place Linux calls `ns_get_unless_inactive`. The owner-chain cascade (R9) has no observable consequence without the active/alive split. |
| D3 | COW publish instead of in-place RCU insert (R31) | `narf-rcu`'s `Atomic<T>` is a whole-value pointer cell; there is no RCU-safe in-place ordered map. O(n) writes on a rare path buy an O(1) lock-free read path. Retiring one map per publish is safe now that the collector's queue is intrusive and unbounded. |
| D5 | `listns` snapshots rather than streaming (R14) | Linux's drop-and-retake exists because it must hold a live reference across `put_user` into an intrusive list it cannot copy. NARF copies the filtered entries — `Weak` handles — under one pin, so it holds no borrow into the tree and needs no reference at all. Costs freshness within a page, which the cursor makes harmless. |
| D4 | No TIME namespace | NARF has no time namespace at all. `TIME` stays in `NS_ALL` so a filter naming it returns an empty list rather than `-EOPNOTSUPP` — which is what a Linux kernel with `CONFIG_TIME_NS=n` would do for a *type* it knows but has no instances of. |

---

## 13. Work items, in dependency order

1. ~~**R2** — fixed initial ids 1–8; dynamic counter starts at 9.~~ **Done.**
   Was a real ABI bug.
2. ~~**R6/R7** — weak-handle tree; every constructor registers after
   `Arc::new`.~~ **Done.**
3. ~~**R30** — real objects for the initial NET, PID, and MNT namespaces.~~
   **Done.** With MNT borrowing the registry rather than snapshotting it,
   and all four `HeldNs::*Global(NsId)` variants deleted: `setns` decides
   "rejoin the initial namespace" by comparing against the reserved id
   instead of carrying a parallel variant.
4. ~~**R31/R32** — move the tree to `narf-rcu`.~~ **Done.** Required fixing
   a silent leak in the collector first: its per-CPU queue is now intrusive
   (`rcu_head` model) rather than a 64-slot array that discarded on
   overflow. Negative-controlled both ways.
5. ~~**R17** — ordered next/previous traversal API.~~ **Done.**
6. ~~**R20/R21** — `hweight32 == 1` tree selection and the cursor ENOENT
   rule.~~ **Done.**
7. ~~**R26–R29** — nsfs: ioctls and file handles.~~ **Done**, which also
   closed R3 (a handle carries the inode, so there had to be one).

Every requirement in this document is now either satisfied or a recorded
deviation in §12.
