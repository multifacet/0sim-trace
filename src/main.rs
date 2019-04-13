use libc::syscall;

const BEGIN_SYSCALL_NR: i64 = 546;
const SNAPSHOT_SYSCALL_NR: i64 = 547;
const SIZE_SYSCALL_NR: i64 = 548;

const PER_CPU_TRACE_BUFFER_SIZE: usize = 1_000_000;

const ZEROSIM_TRACE_TASK_SWITCH: u32 = 0x0000_0001;
const ZEROSIM_TRACE_INTERRUPT: u32 = 0x0000_0002;
const ZEROSIM_TRACE_FAULT: u32 = 0x0000_0004;
const ZEROSIM_TRACE_SYSCALL: u32 = 0x0000_0008;
const ZEROSIM_TRACE_START: u32 = 0x0000_0010;

#[derive(Copy, Clone)]
#[repr(C)]
struct Trace {
    timestamp: u64,
    id: u32,
    flags: u32,
}

impl std::fmt::Debug for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{ {:<15} {:5} ts: {}, flags: {:8b}, id: {} }}",
            if self.flags & ZEROSIM_TRACE_TASK_SWITCH != 0 {
                "TASK_SWITCH"
            } else if self.flags & ZEROSIM_TRACE_INTERRUPT != 0 {
                "INTERRUPT"
            } else if self.flags & ZEROSIM_TRACE_FAULT != 0 {
                "FAULT"
            } else if self.flags & ZEROSIM_TRACE_SYSCALL != 0 {
                "SYSCALL"
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

    println!("{:#?}", snap.buffer.iter().take(50).collect::<Vec<_>>());
}

fn size() {
    let ret = unsafe { syscall(SIZE_SYSCALL_NR, 1<<12) };
    if ret != 0 {
        unsafe { libc::perror(std::ptr::null_mut()); }
        panic!();
    }
}

fn begin() {
    let ret = unsafe { syscall(BEGIN_SYSCALL_NR) };
    if ret != 0 {
        unsafe { libc::perror(std::ptr::null_mut()); }
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
        unsafe { libc::perror(std::ptr::null_mut()); }
        panic!();
    }

    unsafe {
        buffer.set_len(buffer.capacity());
    }

    Snapshot { buffer }
}
