//! `/proc/timer_list` tests: the Linux `print_timer` lines for synthetic
//! timers, and a live sleep the file must name by function, arm site and
//! task.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_time::hrtimer::{CpuBaseStats, TimerSnapshot};
use narf_time::timer::{WheelBaseStats, WheelTimerSnapshot};

use super::{render, ClockBaseView, CpuTimerView, TaskNames, WheelBaseView};

macro_rules! console_log {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, $($arg)*);
    }};
}

static SITE: &core::panic::Location<'static> = core::panic::Location::caller();

fn resolve(addr: usize) -> String {
    match addr {
        0x1000 => String::from("hrtimer_wakeup"),
        0x2000 => String::from("tick_nohz_handler"),
        0x3000 => String::from("process_timeout"),
        a => alloc::format!("{:#x}", a),
    }
}

fn synthetic() -> Vec<CpuTimerView> {
    let sleeper = TimerSnapshot {
        addr: 0xffff_8000_0012_3400,
        function: 0x1000,
        state: 1,
        softexpires: 1_000_000,
        expires: 1_050_000,
        owner_task: 41,
        site: Some(SITE),
    };
    let plain = TimerSnapshot {
        addr: 0xffff_8000_0012_3500,
        function: 0x2000,
        state: 1,
        softexpires: 2_000_000,
        expires: 2_000_000,
        owner_task: 0,
        site: None,
    };
    let mut clock_bases: Vec<ClockBaseView> = (0..8).map(|_| ClockBaseView::default()).collect();
    clock_bases[0] = ClockBaseView {
        offset: 0,
        timers: vec![sleeper, plain],
        queued: 2,
    };
    clock_bases[1].offset = 5_000;
    let wheel_timer = WheelTimerSnapshot {
        addr: 0xffff_8000_0012_3600,
        function: 0x3000,
        flags: 0,
        expires: 110,
        bucket_expiry: 111,
        level: 0,
        owner_task: 7,
        site: Some(SITE),
    };
    let wheel = vec![
        WheelBaseView::default(),
        WheelBaseView {
            stats: WheelBaseStats {
                clk: 100,
                next_expiry: 111,
                nr_expired: 3,
            },
            timers: vec![wheel_timer],
            pending: 1,
        },
        WheelBaseView {
            stats: WheelBaseStats {
                clk: 100,
                next_expiry: u64::MAX,
                nr_expired: 0,
            },
            ..WheelBaseView::default()
        },
    ];
    vec![CpuTimerView {
        cpu: 0,
        stats: CpuBaseStats {
            expires_next: 1_050_000,
            nr_events: 12,
            nr_retries: 1,
            nr_hangs: 0,
            nr_queued: 2,
        },
        clock_bases,
        wheel,
    }]
}

/// Header, `print_cpu` / `print_base` and `print_timer` lines in Linux's
/// shape; a sleeper also names its arm site and task (`comm/pid`).
fn smoke_timer_list_prints_linux_print_timer_lines() -> TestResult {
    let names = TaskNames::from_pairs(&[(41, "narf_igc::spawn_pumps::{{closure}}")]);
    let text = render(100_000, 100, &synthetic(), &resolve, &names);
    let site = alloc::format!("{}:{}:{}", SITE.file(), SITE.line(), SITE.column());
    let want = [
        String::from("Timer List Version: v0.10"),
        String::from("HRTIMER_MAX_CLOCK_BASES: 8"),
        String::from("now at 100000 nsecs"),
        String::from("cpu: 0"),
        String::from(" clock 0:"),
        String::from("  .resolution: 1 nsecs"),
        String::from("active timers:"),
        alloc::format!(
            " #0: <ffff800000123400>, hrtimer_wakeup, S:01, {}, narf_igc::spawn_pumps::{{{{closure}}}}/41",
            site
        ),
        String::from(" # expires at 1000000-1050000 nsecs [in 900000 to 950000 nsecs]"),
        String::from(" #1: <ffff800000123500>, tick_nohz_handler, S:01"),
        String::from(" # expires at 2000000-2000000 nsecs [in 1900000 to 1900000 nsecs]"),
        String::from(" clock 1:"),
        String::from("  .offset:     5000 nsecs"),
        String::from("  .expires_next   : 1050000 nsecs"),
        String::from("  .nr_events      : 12"),
        String::from("  .nr_retries     : 1"),
        String::from("jiffies: 100"),
        String::from(" base 1 BASE_GLOBAL: .clk 100, .next_expiry 111, .nr_expired 3"),
        String::from(" base 2 BASE_DEF: .clk 100, .next_expiry none, .nr_expired 0"),
        alloc::format!(
            " #0: <ffff800000123600>, process_timeout, F:00, L:0, {}, ?/7",
            site
        ),
        String::from(" # expires at 110 (bucket 111) jiffies [in 11 jiffies]"),
    ];
    let lines: Vec<&str> = text.lines().collect();
    for w in &want {
        if !lines.contains(&w.as_str()) {
            console_log!("timer_list: missing line {:?}\n{}", w, text);
            return TestResult::Fail("timer_list: a Linux print_timer line is missing");
        }
    }
    // A non-sleeper prints no owner.
    if lines
        .iter()
        .any(|l| l.starts_with(" #1: ") && l.matches(", ").count() != 2)
    {
        return TestResult::Fail("timer_list: a plain timer printed an owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/timer_list",
    smoke_timer_list_prints_linux_print_timer_lines
);

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

/// A live hrtimer sleep and a live wheel sleep on this CPU appear in the
/// file with their function resolved through kallsyms, their arm site
/// (this file) and the arming task; the file is 0400 like Linux's.
fn smoke_timer_list_names_live_sleepers() -> TestResult {
    super::register();
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    // Far enough out that neither fires while the file is read.
    let mut hr = narf_time::sleep_until(narf_time::Deadline::after_ms(5_000));
    let hr_line = line!() - 1;
    let mut wheel = narf_time::msleep(5_000);
    let wheel_line = line!() - 1;
    if Pin::new(&mut hr).poll(&mut cx).is_ready() || Pin::new(&mut wheel).poll(&mut cx).is_ready() {
        return TestResult::Fail("a 5 s sleep completed at once");
    }
    let body = match super::super::lookup_registry(&["timer_list"]) {
        Some(super::super::ProcNodeSnapshot::File(f)) => {
            if f.perms() != 0o400 {
                return TestResult::Fail("timer_list is not mode 0400");
            }
            f.read()
        }
        _ => return TestResult::Fail("timer_list not registered"),
    };
    drop(hr);
    drop(wheel);
    let Ok(text) = String::from_utf8(body) else {
        return TestResult::Fail("timer_list not utf-8");
    };
    let file = file!();
    let hr_site = alloc::format!("{}:{}:", file, hr_line);
    let wheel_site = alloc::format!("{}:{}:", file, wheel_line);
    let have_symbols = narf_observability::kallsyms::table().is_ok();
    let mut lines = text.lines();
    let mut hr_seen = false;
    let mut wheel_seen = false;
    while let Some(l) = lines.next() {
        if l.contains(&hr_site) {
            if have_symbols && !l.contains("hrtimer_wakeup") {
                console_log!("timer_list: {}", l);
                return TestResult::Fail("hrtimer sleeper not resolved to hrtimer_wakeup");
            }
            if !l.contains(", S:01, ") {
                return TestResult::Fail("hrtimer sleeper not shown as queued");
            }
            match lines.next() {
                Some(e) if e.starts_with(" # expires at ") && e.ends_with(" nsecs]") => {}
                _ => return TestResult::Fail("hrtimer sleeper has no expiry line"),
            }
            hr_seen = true;
        } else if l.contains(&wheel_site) {
            if have_symbols && !l.contains("process_timeout") {
                console_log!("timer_list: {}", l);
                return TestResult::Fail("wheel sleeper not resolved to process_timeout");
            }
            wheel_seen = true;
        }
    }
    if !hr_seen || !wheel_seen {
        console_log!("timer_list:\n{}", text);
        return TestResult::Fail("a live sleeper is missing from /proc/timer_list");
    }
    TestResult::Pass
}
kernel_test_in!("time/timer_list", smoke_timer_list_names_live_sleepers);
