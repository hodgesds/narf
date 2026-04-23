# userspace — Process model, ELF loader, relibc

User-mode processes in NARF: a thread bundle + per-task cap table +
(optionally) a user PKU domain. ELF loading and relibc integration so
standard Rust binaries run.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 4.
