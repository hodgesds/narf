//! Console output in whole lines.
//!
//! `narf_printk` takes finished UTF-8. Writing every `fmt` fragment as its
//! own call would interleave with other CPUs mid-line, so [`print_fmt`]
//! formats into a bounded stack buffer and emits it in as few calls as fit —
//! one for any line shorter than [`LINE`]. A fragment is never split inside a
//! UTF-8 sequence: the kernel rejects (drops) a non-UTF-8 write.

use core::fmt::{self, Write};

use crate::abi;

/// Bytes formatted per console write.
pub const LINE: usize = 256;

/// Emit `s` with one `narf_printk` call. Empty strings are skipped (the
/// kernel rejects a zero-length write).
pub fn write_str(s: &str) {
    if s.is_empty() {
        return;
    }
    // SAFETY: a live `&str` names `len` readable bytes of valid UTF-8, the
    // whole of `narf_printk`'s contract.
    unsafe {
        let _ = abi::narf_printk(s.as_ptr(), s.len());
    }
}

/// A console sink that writes each fragment straight through. Prefer
/// [`printkln!`] for anything a human reads; this exists for callers that
/// already assemble whole lines.
#[derive(Debug, Default, Clone, Copy)]
pub struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Buffers formatted output and flushes it in UTF-8-whole chunks.
struct Line {
    buf: [u8; LINE],
    len: usize,
}

impl Line {
    fn flush(&mut self) {
        if self.len > 0 {
            // SAFETY: only whole `&str` fragments (or char-boundary splits of
            // one) are ever copied in, so the prefix is valid UTF-8.
            let s = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) };
            write_str(s);
            self.len = 0;
        }
    }
}

impl Write for Line {
    fn write_str(&mut self, mut s: &str) -> fmt::Result {
        while !s.is_empty() {
            let room = LINE - self.len;
            if s.len() <= room {
                self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
                self.len += s.len();
                return Ok(());
            }
            if self.len > 0 {
                // Keep fragments whole where possible: flush and retry first.
                self.flush();
                continue;
            }
            // A single fragment longer than the buffer: split it at the last
            // char boundary that fits.
            let mut cut = LINE;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            self.buf[..cut].copy_from_slice(&s.as_bytes()[..cut]);
            self.len = cut;
            self.flush();
            s = &s[cut..];
        }
        Ok(())
    }
}

/// Format `args` and write the result to the console, one call per
/// [`LINE`] bytes.
pub fn print_fmt(args: fmt::Arguments<'_>) {
    let mut line = Line {
        buf: [0; LINE],
        len: 0,
    };
    let _ = line.write_fmt(args);
    line.flush();
}

/// `println!` for modules: format, append `\n`, write as one console line.
#[macro_export]
macro_rules! printkln {
    () => { $crate::console::write_str("\n") };
    ($($arg:tt)*) => {
        $crate::console::print_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}
