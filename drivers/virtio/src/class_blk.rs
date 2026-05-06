//! narf-drivers-virtio — Block-device class glue.
//!
//! Spec: `drivers/virtio/specification/spec.md` §3.
//!
//! # Purpose
//!
//! This module implements the "Block Server" that consumes requests from
//! a Narf-Ring and dispatches them to a `VirtioBlkDevice`. It manages
//! the lifecycle of in-flight requests and completion signaling back
//! through the ring.

use crate::blk::VirtioBlkDevice;
use alloc::sync::Arc;
use narf_block::{BlockCompletion, BlockDevice, BlockRequest};
use narf_ipc::{Consumer, Producer};

/// A server task that bridges a Narf-Ring to a VirtIO block device.
#[derive(Debug)]
pub struct VirtioBlkServer<const N: usize> {
    device: Arc<VirtioBlkDevice>,
    rx: Consumer<BlockRequest, N>,
    tx: Producer<BlockCompletion, N>,
}

impl<const N: usize> VirtioBlkServer<N> {
    /// Create a new server.
    pub fn new(
        device: Arc<VirtioBlkDevice>,
        rx: Consumer<BlockRequest, N>,
        tx: Producer<BlockCompletion, N>,
    ) -> Self {
        Self { device, rx, tx }
    }

    /// Run the server loop. This async function never returns unless
    /// the ring is closed.
    pub async fn run(&mut self) {
        loop {
            // 1. Receive a request from the ring.
            let Ok(req) = self.rx.recv().await else {
                // Ring closed, terminate server.
                break;
            };

            // 2. Submit to VirtIO device.
            // In a more complex server, we might spawn a task per request
            // or use a join-set to handle multiple in-flight requests.
            // For Stage 3, we process them sequentially or drive them
            // concurrently in this loop.
            let completion = self.device.submit(req).await;

            // 3. Send completion back.
            if self.tx.send(completion).await.is_err() {
                // Completion ring closed.
                break;
            }
        }
    }

    /// Drive the device's completion polling.
    /// In a real driver, this would be triggered by an IRQ.
    pub fn poll(&self) {
        self.device.poll();
    }
}
