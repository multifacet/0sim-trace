//! Safe wrapper around the tracing API.

use failure::Fail;

use itertools::Itertools;

/// Possible errors when using the zerosim tracing API.
#[derive(Debug, Fail)]
enum ZerosimTracingError {
    #[fail(display = "zerosim trace size() failed. Please retry.")]
    SizeFailedTemporarily,

    #[fail(display = "zerosim trace unable to allocate kernel buffers.")]
    KernelBuffersUnallocated,

    #[fail(display = "zerosim trace is already running.")]
    AlreadyRunning,
}

/// A handle on the tracer.
#[derive(Debug)]
pub struct ZerosimTracer {
    size: usize,
}

impl ZerosimTracer {
    /// Initialize the zerosim tracer. The kernel allocates a `size`-sized buffer for each cpu,
    /// `size` is in units of "trace entries".
    pub fn init(size: usize) -> Result<Self, failure::Error> {
        sys::size(size)?;
        Ok(ZerosimTracer { size })
    }

    /// Begin tracing. If `size` is `Some(..)`, the buffers will be resized. This method returns a
    /// `PendingSnapshot`, which can be consumed to capture an actual snapshot.
    pub fn begin(&mut self, size: Option<usize>) -> Result<PendingSnapshot, failure::Error> {
        if let Some(size) = size {
            sys::size(size)?;
            self.size = size;
        }

        sys::begin()?;

        Ok(PendingSnapshot {
            size: self.size,
            captured: false,
        })
    }
}

/// A handle on a pending snapshot. A snapshot is taken when the `snapshot` method is called,
/// consuming this handle. Alternately, if this handle is dropped, a snapshot is taken and
/// discarded.
#[derive(Debug)]
pub struct PendingSnapshot {
    size: usize,
    captured: bool,
}

impl PendingSnapshot {
    /// Capture a snapshot and return it.
    pub fn snapshot(mut self) -> Snapshot {
        self.captured = true;
        Snapshot {
            buffer: unsafe { sys::snapshot(self.size) }
                .drain(..)
                .map(Trace::from_raw)
                .collect(),
            size: self.size,
        }
    }
}

impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        if !self.captured {
            let _ = unsafe { sys::snapshot(self.size) };
        }
    }
}

/// A snapshot produced by zerosim trace.
#[derive(Debug, Clone)]
pub struct Snapshot {
    size: usize,
    buffer: Vec<Trace>,
}

impl Snapshot {
    /// Returns an iterator for each cpu that returns the events on the cpu.
    pub fn cpus(&self) -> itertools::structs::IntoChunks<impl Iterator<Item = &Trace> + '_> {
        self.buffer.iter().chunks(self.size)
    }
}

/// A single event in a snapshot.
#[derive(Debug, Clone, Copy)]
pub struct Trace {
    /// What kind of event was traced.
    event: ZerosimTraceEvent,
    /// The `rdtsc` timestamp of the event.
    timestamp: u64,
    /// The process ID of the process that was running when the event happened.
    pid: u32,
}

impl Trace {
    fn from_raw(raw: sys::Trace) -> Self {
        Trace {
            timestamp: raw.timestamp,
            pid: raw.pid,
            event: {
                let is_start = raw.flags & sys::ZEROSIM_TRACE_START != 0;
                let ty = raw.flags & !sys::ZEROSIM_TRACE_START;

                match (ty, is_start) {
                    (ty, is_start) if ty == sys::ZEROSIM_TRACE_TASK_SWITCH => {
                        assert!(!is_start);
                        ZerosimTraceEvent::TaskSwitch {
                            current_pid: raw.pid as usize,
                            prev_pid: raw.extra as usize,
                        }
                    }
                    (ty, true) if ty == sys::ZEROSIM_TRACE_SYSCALL => {
                        ZerosimTraceEvent::SystemCallStart {
                            num: raw.id as usize,
                        }
                    }
                    (ty, false) if ty == sys::ZEROSIM_TRACE_SYSCALL => {
                        ZerosimTraceEvent::SystemCallEnd {
                            num: raw.id as usize,
                            ret: raw.extra,
                        }
                    }
                    (ty, true) if ty == sys::ZEROSIM_TRACE_INTERRUPT => {
                        ZerosimTraceEvent::IrqStart {
                            num: raw.id as usize,
                        }
                    }
                    (ty, false) if ty == sys::ZEROSIM_TRACE_INTERRUPT => {
                        ZerosimTraceEvent::IrqEnd {
                            num: raw.id as usize,
                        }
                    }
                    (ty, true) if ty == sys::ZEROSIM_TRACE_FAULT => {
                        ZerosimTraceEvent::ExceptionStart {
                            error: raw.id as usize,
                        }
                    }
                    (ty, false) if ty == sys::ZEROSIM_TRACE_FAULT => {
                        ZerosimTraceEvent::ExceptionEnd {
                            error: raw.id as usize,
                            ip: raw.extra,
                        }
                    }
                    (ty, true) if ty == sys::ZEROSIM_TRACE_SOFTIRQ => {
                        ZerosimTraceEvent::SoftIrqStart
                    }
                    (ty, false) if ty == sys::ZEROSIM_TRACE_SOFTIRQ => {
                        ZerosimTraceEvent::SoftIrqEnd
                    }
                    _ => unreachable!(),
                }
            },
        }
    }
}

/// Represents different types of events that could be traced.
#[derive(Debug, Clone, Copy)]
pub enum ZerosimTraceEvent {
    TaskSwitch {
        /// The pid of the task that was switched _to_.
        current_pid: usize,
        /// The pid of the task that was switched _from_.
        prev_pid: usize,
    },

    /// The start of a system call.
    SystemCallStart {
        /// The syscall number.
        num: usize,
    },

    /// The end of a system call.
    SystemCallEnd {
        /// The syscall number.
        num: usize,

        /// The lowest 32 bits of the return value.
        ret: u32,
    },

    /// The start of an interrupt handler.
    IrqStart {
        /// The vector number.
        num: usize,
    },

    /// The start of an interrupt handler.
    IrqEnd {
        /// The vector number.
        num: usize,
    },

    /// The end of an exception handler.
    ExceptionStart {
        /// Error code. Note, this is not the exception number, which unforunately, is a pain to
        /// capture properly.
        error: usize,
    },

    /// The end of an exception handler.
    ExceptionEnd {
        /// Error code. Note, this is not the exception number, which unforunately, is a pain to
        /// capture properly.
        error: usize,

        /// The lowest 32 bits of the instruction pointer where the exception occured.
        ip: u32,
    },

    /// The start of softirq processing.
    SoftIrqStart,

    /// The end of softirq processing.
    SoftIrqEnd,
}

/// The raw interface.
mod sys {
    use libc::syscall;

    use super::ZerosimTracingError;

    pub const BEGIN_SYSCALL_NR: i64 = 546;
    pub const SNAPSHOT_SYSCALL_NR: i64 = 547;
    pub const SIZE_SYSCALL_NR: i64 = 548;

    pub const ZEROSIM_TRACE_TASK_SWITCH: u32 = 0x0000_0001;
    pub const ZEROSIM_TRACE_INTERRUPT: u32 = 0x0000_0002;
    pub const ZEROSIM_TRACE_FAULT: u32 = 0x0000_0003;
    pub const ZEROSIM_TRACE_SYSCALL: u32 = 0x0000_0004;
    pub const ZEROSIM_TRACE_SOFTIRQ: u32 = 0x0000_0005;

    pub const ZEROSIM_TRACE_START: u32 = 0x8000_0000;

    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct Trace {
        pub timestamp: u64,
        pub id: u32,
        pub flags: u32,
        pub pid: u32,
        pub extra: u32,
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

    pub fn size(size: usize) -> Result<(), failure::Error> {
        let ret = unsafe { syscall(SIZE_SYSCALL_NR, size) };

        match ret {
            0 => Ok(()),
            e if e == (-libc::EAGAIN).into() => Err(ZerosimTracingError::SizeFailedTemporarily)?,
            e if e == (-libc::ENOMEM).into() => Err(ZerosimTracingError::KernelBuffersUnallocated)?,
            _ => unreachable!(),
        }
    }

    pub fn begin() -> Result<(), failure::Error> {
        let ret = unsafe { syscall(BEGIN_SYSCALL_NR) };

        match ret {
            0 => Ok(()),
            e if e == (-libc::ENOMEM).into() => Err(ZerosimTracingError::KernelBuffersUnallocated)?,
            e if e == (-libc::EINPROGRESS).into() => Err(ZerosimTracingError::AlreadyRunning)?,
            _ => unreachable!(),
        }
    }

    pub unsafe fn snapshot(size: usize) -> Vec<Trace> {
        let mut buffer = Vec::with_capacity(size * num_cpus::get());

        let ret = {
            let ptr = buffer.as_mut_ptr();
            let cap = buffer.capacity();

            syscall(SNAPSHOT_SYSCALL_NR, ptr, cap)
        };
        if ret != 0 {
            libc::perror(std::ptr::null_mut());
            unreachable!();
        }

        buffer.set_len(buffer.capacity());

        buffer
    }
}
