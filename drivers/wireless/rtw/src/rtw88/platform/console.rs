//! `narf_console` for the module: `klog!` over `narf_printk`.

/// `narf_console::klog!`: one formatted record on the kernel console.
macro_rules! klog {
    ($($arg:tt)*) => {
        narf_module_rt::console::print_fmt(format_args!($($arg)*))
    };
}
pub(crate) use klog;
