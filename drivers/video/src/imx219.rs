//! Sony IMX219 CMOS Image Sensor driver.
//!
//! An 8-Megapixel, 1/4.0-inch CMOS active pixel type image sensor with a square pixel array.
//! Extremely common on embedded systems and Raspberry Pi Camera Module V2.
//!
//! Reference: `linux/drivers/media/i2c/imx219.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

use crate::{BufferQueue, Camera, CameraError, PixelFormat, Result};

pub const IMX219_I2C_ADDR: u16 = 0x10;
pub const IMX219_CHIP_ID_REG: u16 = 0x0000;
pub const IMX219_CHIP_ID: u16 = 0x0219;

/// Typical supported formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Imx219Format {
    /// 3280x2464 at 21 FPS
    FullResolution,
    /// 1920x1080 at 30 FPS
    FHD,
    /// 1640x1232 at 30 FPS
    Binned,
}

/// The IMX219 sensor state and DMA queue.
#[derive(Debug)]
pub struct Imx219 {
    i2c_bus: u16,
    format: Imx219Format,
    streaming: bool,
    queue: BufferQueue,
}

impl Imx219 {
    pub fn new(i2c_bus: u16) -> Self {
        Self {
            i2c_bus,
            format: Imx219Format::FHD,
            streaming: false,
            queue: BufferQueue::new(),
        }
    }

    pub fn probe(&self) -> bool {
        let _ = writeln!(
            Writer,
            "  imx219: Probing sensor on I2C bus {}",
            self.i2c_bus
        );
        // In a real implementation we would read the chip ID register over I2C here.
        true
    }
}

impl Camera for Imx219 {
    fn buffer_queue(&self) -> &BufferQueue {
        &self.queue
    }

    fn buffer_queue_mut(&mut self) -> &mut BufferQueue {
        &mut self.queue
    }

    fn set_format(&self, fmt: PixelFormat, w: u32, h: u32) -> Result<()> {
        let _ = writeln!(Writer, "  imx219: Set format to {:?} {}x{}", fmt, w, h);
        Ok(())
    }

    fn start_streaming(&self) -> Result<()> {
        let _ = writeln!(Writer, "  imx219: Started MIPI streaming");
        Ok(())
    }

    fn stop_streaming(&self) -> Result<()> {
        let _ = writeln!(Writer, "  imx219: Stopped MIPI streaming");
        Ok(())
    }
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "video-imx219", || {
        let _ = writeln!(Writer, "  video-imx219: Sony IMX219 driver initialized");
        InitResult::Ok
    });
}
