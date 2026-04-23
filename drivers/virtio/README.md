# drivers/virtio — VirtIO (first driver)

The first real driver NARF ships. Targets VirtIO 1.2 split virtqueues
to start, then packed. Runs in a dedicated PKS/MTE domain; transport is
the Narf-Ring to the rest of the kernel.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3.
