# interrupts — UIPI + IRQ routing

Configures user-level interrupts (UIPI on x86_64; GICv3 ITS on aarch64),
routes IRQs into the correct driver domain, owns the kernel-side trap
fallback path.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 2.
