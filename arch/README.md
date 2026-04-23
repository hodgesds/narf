# arch — Hardware Abstraction Layer

Cross-cutting. Defines the trait surface every subsystem uses to talk to
CPU, MMU, interrupt controller, timer, and cache operations. Per-arch
implementations (x86_64, aarch64) satisfy that trait.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (skeleton of trait + enough to boot) → 2 (complete).
