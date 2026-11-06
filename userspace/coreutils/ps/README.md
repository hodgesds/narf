# userspace/coreutils/ps — ps

Reports running tasks by enumerating `/proc`: numeric entries are live
PIDs, and each one's command name comes from `/proc/<pid>/comm`. Output
is a `PID  CMD` header followed by one line per task, the PID
right-justified in a 5-column field. A task whose `comm` cannot be read
is shown as `?`.

There are no options. The whole program is `src/main.rs`, a `no_std`
binary that reads `/proc` through `narf-libc` (`opendir` / `readdir` /
`posix_open` / `posix_read`).
