extern crate alloc;

use alloc::vec;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::mqueuefs::{
    self, attributes, open, receive, send, unlink, MqueueAttr, MqueueFs, MqueueOpenOptions,
    O_CREAT, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY,
};
use crate::{FileType, FsInstance, POLL_IN, POLL_OUT};

fn poll_once<F: core::future::Future>(mut future: F) -> Option<F::Output> {
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    unsafe fn no_op(_: *const ()) {}
    fn raw_waker() -> RawWaker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    // SAFETY: the no-op waker never dereferences its null data pointer.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    // SAFETY: `future` is not moved after it is pinned here.
    let pinned = unsafe { Pin::new_unchecked(&mut future) };
    match pinned.poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

fn handle_id(file: &dyn crate::FileOps) -> Result<u64, &'static str> {
    file.mq_queue_id().ok_or("mqueue file omitted handle id")
}

fn options(flags: u32, uid: u32, gid: u32) -> MqueueOpenOptions {
    MqueueOpenOptions {
        flags,
        mode: 0o600,
        umask: 0,
        uid,
        gid,
        attr: None,
    }
}

fn smoke_mqueuefs_mount_and_syscalls_share_queue() -> TestResult {
    mqueuefs::reset_for_test();
    let file = match open(7, "/visible", options(O_CREAT | O_RDWR, 1000, 100)) {
        Ok(file) => file,
        Err(_) => return TestResult::Fail("queue create failed"),
    };
    let fs = MqueueFs::new(7);
    let entries = fs.root().enumerate(0, 8);
    if entries != vec![(alloc::string::String::from("visible"), FileType::File)] {
        return TestResult::Fail("mqueue mount did not expose syscall-created queue");
    }
    let mounted = match fs.root().lookup("visible") {
        Some(file) => file,
        None => return TestResult::Fail("mounted queue lookup failed"),
    };
    if file.ino() != mounted.ino() || mounted.stat().size != 80 {
        return TestResult::Fail("mounted queue did not retain Linux inode metadata");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/mqueuefs",
    smoke_mqueuefs_mount_and_syscalls_share_queue
);

fn smoke_mqueuefs_priority_fifo_and_readiness() -> TestResult {
    mqueuefs::reset_for_test();
    let file = match open(0, "/priority", options(O_CREAT | O_RDWR, 0, 0)) {
        Ok(file) => file,
        Err(_) => return TestResult::Fail("queue create failed"),
    };
    let id = match handle_id(file.as_ref()) {
        Ok(id) => id,
        Err(error) => return TestResult::Fail(error),
    };
    if file.poll_readiness() != POLL_OUT {
        return TestResult::Fail("empty queue readiness was not writable-only");
    }
    if send(id, b"low".to_vec(), 1).is_err()
        || send(id, b"high-first".to_vec(), 9).is_err()
        || send(id, b"high-second".to_vec(), 9).is_err()
    {
        return TestResult::Fail("queue send failed");
    }
    if file.poll_readiness() != (POLL_IN | POLL_OUT) {
        return TestResult::Fail("nonempty queue readiness missing POLLIN/POLLOUT");
    }
    let first = receive(id, 8192);
    let second = receive(id, 8192);
    if first != Ok((b"high-first".to_vec(), 9)) || second != Ok((b"high-second".to_vec(), 9)) {
        return TestResult::Fail("priority/FIFO ordering differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/mqueuefs",
    smoke_mqueuefs_priority_fifo_and_readiness
);

fn smoke_mqueuefs_unlink_keeps_open_description_alive() -> TestResult {
    mqueuefs::reset_for_test();
    let file = match open(0, "/lifetime", options(O_CREAT | O_RDWR, 0, 0)) {
        Ok(file) => file,
        Err(_) => return TestResult::Fail("queue create failed"),
    };
    let id = match handle_id(file.as_ref()) {
        Ok(id) => id,
        Err(error) => return TestResult::Fail(error),
    };
    if unlink(0, "/lifetime", 0).is_err() || send(id, b"alive".to_vec(), 0).is_err() {
        return TestResult::Fail("unlink destroyed an open queue");
    }
    if receive(id, 8192) != Ok((b"alive".to_vec(), 0)) {
        return TestResult::Fail("open queue stopped working after unlink");
    }
    if open(0, "/lifetime", options(O_RDONLY, 0, 0)).is_ok() {
        return TestResult::Fail("unlinked queue name remained visible");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/mqueuefs",
    smoke_mqueuefs_unlink_keeps_open_description_alive
);

fn smoke_mqueuefs_access_flags_attrs_and_status_file() -> TestResult {
    mqueuefs::reset_for_test();
    let writer = match open(
        0,
        "/attrs",
        MqueueOpenOptions {
            flags: O_CREAT | O_WRONLY | O_NONBLOCK,
            mode: 0o666,
            umask: 0o027,
            uid: 42,
            gid: 7,
            attr: Some(MqueueAttr {
                maxmsg: 4,
                msgsize: 128,
                ..MqueueAttr::default()
            }),
        },
    ) {
        Ok(file) => file,
        Err(_) => return TestResult::Fail("queue create failed"),
    };
    let id = match handle_id(writer.as_ref()) {
        Ok(id) => id,
        Err(error) => return TestResult::Fail(error),
    };
    if writer.stat().mode.perms != 0o640 || writer.owners() != (42, 7) {
        return TestResult::Fail("mode/umask/ownership metadata is wrong");
    }
    let attr = match attributes(id) {
        Ok(attr) => attr,
        Err(_) => return TestResult::Fail("mq_getattr backend failed"),
    };
    if attr.flags != i64::from(O_NONBLOCK) || attr.maxmsg != 4 || attr.msgsize != 128 {
        return TestResult::Fail("per-open attrs are wrong");
    }
    if receive(id, 128) != Err(mqueuefs::MqueueError::BadDescriptor) {
        return TestResult::Fail("write-only mqd allowed receive");
    }
    if send(id, b"abc".to_vec(), 0).is_err() {
        return TestResult::Fail("write-only mqd rejected send");
    }
    let mut status = [0u8; 80];
    match poll_once(writer.read(0, &mut status)) {
        Some(Ok(count))
            if core::str::from_utf8(&status[..count]).is_ok_and(|text| {
                text == "QSIZE:3          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n"
            }) =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("queue status file format differs from Linux"),
    }
}
kernel_test_in!(
    "filesystem/mqueuefs",
    smoke_mqueuefs_access_flags_attrs_and_status_file
);
