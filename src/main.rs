//! A simple program that traces using zerosim-trace and outputs the results.

use itertools::Itertools;

use libc::syscall;

const BEGIN_SYSCALL_NR: i64 = 546;
const SNAPSHOT_SYSCALL_NR: i64 = 547;
const SIZE_SYSCALL_NR: i64 = 548;

const PER_CPU_TRACE_BUFFER_SIZE: usize = 1 << 12;

const ZEROSIM_TRACE_TASK_SWITCH: u32 = 0x0000_0001;
const ZEROSIM_TRACE_INTERRUPT: u32 = 0x0000_0002;
const ZEROSIM_TRACE_FAULT: u32 = 0x0000_0003;
const ZEROSIM_TRACE_SYSCALL: u32 = 0x0000_0004;
const ZEROSIM_TRACE_SOFTIRQ: u32 = 0x0000_0005;

const ZEROSIM_TRACE_START: u32 = 0x8000_0000;

#[derive(Copy, Clone)]
#[repr(C)]
struct Trace {
    timestamp: u64,
    id: u32,
    flags: u32,
    pid: u32,
    extra: u32,
}

impl std::fmt::Debug for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ty = self.flags & !ZEROSIM_TRACE_START;
        write!(
            f,
            "{{ {:<15} {:5} ts: {}, flags: {:8b}, id: {}, pid: {}, extra: {} }}",
            if ty == ZEROSIM_TRACE_TASK_SWITCH {
                "TASK_SWITCH"
            } else if ty == ZEROSIM_TRACE_INTERRUPT {
                "INTERRUPT"
            } else if ty == ZEROSIM_TRACE_FAULT {
                "FAULT"
            } else if ty == ZEROSIM_TRACE_SYSCALL {
                "SYSCALL"
            } else if ty == ZEROSIM_TRACE_SOFTIRQ {
                "SOFTIRQ"
            } else {
                "??"
            },
            if self.flags & ZEROSIM_TRACE_START != 0 {
                "START"
            } else {
                ""
            },
            self.timestamp,
            self.flags,
            self.id,
            self.pid,
            self.extra,
        )
    }
}

#[derive(Debug, Clone)]
struct Snapshot {
    pub buffer: Vec<Trace>,
}

fn main() {
    size();

    begin();

    std::thread::sleep(std::time::Duration::from_secs(5));

    let snap = snapshot();

    for (i, cpu) in snap
        .buffer
        .into_iter()
        .chunks(PER_CPU_TRACE_BUFFER_SIZE)
        .into_iter()
        .enumerate()
    {
        for ev in cpu {
            println!("{} {:?}", i, ev);
        }
    }
}

fn size() {
    let ret = unsafe { syscall(SIZE_SYSCALL_NR, PER_CPU_TRACE_BUFFER_SIZE) };
    if ret != 0 {
        unsafe {
            libc::perror(std::ptr::null_mut());
        }
        panic!();
    }
}

fn begin() {
    let ret = unsafe { syscall(BEGIN_SYSCALL_NR) };
    if ret != 0 {
        unsafe {
            libc::perror(std::ptr::null_mut());
        }
        panic!();
    }
}

fn snapshot() -> Snapshot {
    let mut buffer = Vec::with_capacity(PER_CPU_TRACE_BUFFER_SIZE * num_cpus::get());

    let ret = unsafe {
        let ptr = buffer.as_mut_ptr();
        let cap = buffer.capacity();

        syscall(SNAPSHOT_SYSCALL_NR, ptr, cap)
    };
    if ret != 0 {
        unsafe {
            libc::perror(std::ptr::null_mut());
        }
        panic!();
    }

    unsafe {
        buffer.set_len(buffer.capacity());
    }

    Snapshot { buffer }
}
