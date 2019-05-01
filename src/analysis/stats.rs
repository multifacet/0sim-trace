//! Computing stats over snapshots.

use std::collections::{HashMap, HashSet};

use statrs::statistics::OrderStatistics;

use crate::tracing::{Snapshot, Trace, ZerosimTraceEvent};

// Window sizes for moving averages. Small window = high frequency.

const ALPHA_LOW: usize = 50;
const ALPHA_HIGH: usize = 1;

/// This is the threshold for "a lot" of divergence. Specifically if we compute the following:
///
///    | avg_lo - avg_hi | / (avg_lo + avg_hi)
///
/// If this ratio is more than `AVERAGE_DIVERGENCE_THRESH`, then we consider the divergence to be
/// "a lot".
///
/// We use the sum in the demoninator so that changes are normalized to both sums. That is, if one
/// sum becomes very small or very large, we don't want it to be drowned out.
const AVERAGE_DIVERGENCE_THRESH: f64 = 0.30; // 40 %

impl Trace {
    /// Returns true if `other` is the ending event for this beginning event.
    pub fn matches(&self, other: &Trace) -> bool {
        match (self.event, other.event) {
            (
                ZerosimTraceEvent::SystemCallStart { num: num_start },
                ZerosimTraceEvent::SystemCallEnd { num: num_end, .. },
            ) if num_start == num_end => true,

            (
                ZerosimTraceEvent::IrqStart { num: num_start },
                ZerosimTraceEvent::IrqEnd { num: num_end },
            ) if num_start == num_end => true,

            (
                ZerosimTraceEvent::ExceptionStart { error: error_start },
                ZerosimTraceEvent::ExceptionEnd {
                    error: error_end, ..
                },
            ) if error_start == error_end => true,

            (ZerosimTraceEvent::SoftIrqStart, ZerosimTraceEvent::SoftIrqEnd) => true,

            // Subsequent events on the same core should always be matching...
            (ZerosimTraceEvent::VmEnter { .. }, ZerosimTraceEvent::VmExit { .. }) => true,

            _ => false,
        }
    }
}

/// A single event from a snapshot: either an point event or an interval denoted as the start and
/// stop points.
enum Event<'snap> {
    Interval {
        start: &'snap Trace,
        end: &'snap Trace,
    },
    Point(&'snap Trace),
}

/// Stats computed over traces from one CPU.
struct PerCpuStats {
    intervals: HashMap<ZerosimTraceEvent, Vec<f64>>,
    points: HashMap<ZerosimTraceEvent, Vec<u64>>,

    //////////////////
    // Computed stats
    //////////////////

    // (median, p99, count)
    computed: HashMap<ZerosimTraceEvent, (f64, f64, f64)>,
    // Moving average divergence intervals (lo, hi, idx, value)
    divergence: HashMap<ZerosimTraceEvent, Vec<(f64, f64, usize, f64)>>,

    // Earliest and latest timestamps (None if no events)
    earliest: Option<u64>,
    latest: Option<u64>,
}

impl PerCpuStats {
    /// `PerCpuStats` with no stats added.
    pub fn empty() -> Self {
        PerCpuStats {
            intervals: HashMap::new(),
            points: HashMap::new(),

            computed: HashMap::new(),
            divergence: HashMap::new(),

            earliest: None,
            latest: None,
        }
    }

    /// Update the stats.
    pub fn fold_event(mut self, ev: &Event) -> Self {
        let mut intervals = self.intervals;
        let mut points = self.points;
        match ev {
            Event::Interval { start, end } => {
                if !intervals.contains_key(&end.event) {
                    intervals.insert(end.event, vec![]);
                }

                intervals
                    .get_mut(&end.event)
                    .map(|v| v.push((end.timestamp - start.timestamp) as f64));

                if self.earliest.is_none() || self.earliest.unwrap() > start.timestamp {
                    self.earliest = Some(start.timestamp);
                }

                if self.latest.is_none() || self.latest.unwrap() < end.timestamp {
                    self.latest = Some(end.timestamp);
                }
            }
            Event::Point(point) => {
                if !points.contains_key(&point.event) {
                    points.insert(point.event, vec![]);
                }

                points
                    .get_mut(&point.event)
                    .map(|v| v.push(point.timestamp));

                if self.earliest.is_none() || self.earliest.unwrap() > point.timestamp {
                    self.earliest = Some(point.timestamp);
                }

                if self.latest.is_none() || self.latest.unwrap() < point.timestamp {
                    self.latest = Some(point.timestamp);
                }
            }
        }

        Self {
            intervals,
            points,
            ..self
        }
    }

    /// Do any computations that require the whole dataset.
    pub fn finalize(&mut self, filter: Option<usize>) {
        for (ev, intervals) in self.intervals.iter_mut() {
            let median = intervals.clone().percentile(50);
            let p99 = intervals.clone().percentile(99);
            let count = intervals.len();
            if let Some(filter) = filter {
                if count < filter {
                    continue;
                }
            }
            self.computed.insert(*ev, (median, p99, count as f64));

            self.divergence
                .insert(*ev, compute_moving_averages(intervals));
        }

        for (ev, point) in self.points.iter_mut() {
            let count = point.len();
            if let Some(filter) = filter {
                if count < filter {
                    continue;
                }
            }
            self.computed
                .insert(*ev, (std::f64::NAN, std::f64::NAN, count as f64));
        }
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.computed.is_empty()
    }
}

impl std::fmt::Display for PerCpuStats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut computed: Vec<_> = self.computed.iter().collect();
        computed.sort_by_key(|(_, (_, _, count))| *count as usize);

        for (ev, (median, p99, count)) in computed.iter() {
            let ev_name = match ev {
                ZerosimTraceEvent::TaskSwitch { current_pid, .. } => {
                    format!("TASK_SWITCH {:>18}", current_pid)
                }
                ZerosimTraceEvent::SystemCallStart { num }
                | ZerosimTraceEvent::SystemCallEnd { num, .. } => {
                    format!("SYSCALL {:>22}", reference::syscall_name(*num))
                }
                ZerosimTraceEvent::IrqStart { num } | ZerosimTraceEvent::IrqEnd { num } => {
                    format!("IRQ {:>26}", reference::vector_name(*num))
                }
                ZerosimTraceEvent::ExceptionStart { error }
                | ZerosimTraceEvent::ExceptionEnd { error, .. } => format!("FAULT {:>24}", error),
                ZerosimTraceEvent::SoftIrqStart | ZerosimTraceEvent::SoftIrqEnd => {
                    format!("SOFTIRQ")
                }
                ZerosimTraceEvent::VmEnter { vcpu } => format!("VMENTER vcpu{:>18}", vcpu),
                ZerosimTraceEvent::VmExit { reason, .. } => format!(
                    "VMEXIT {:>#23}",
                    reference::vm_exit_reason_name(*reason as usize)
                ),
                ZerosimTraceEvent::Unknown { id, flags, .. } => format!("?? {} {:b}", id, flags),
            };
            let ndiv = self.divergence.get(ev).map(|divs| divs.len()).unwrap_or(0);
            writeln!(
                f,
                "{:5} {:30} {:15} {:15.0} {:15.3} {:15.3} {:7.3} ({:5.3})",
                "",
                ev_name,
                if self.latest.is_some() {
                    self.latest.unwrap() - self.earliest.unwrap()
                } else {
                    0
                },
                count,
                median,
                p99,
                ndiv,
                ndiv as f64 * 100. / count
            )?;

            /* debugging
            let divergences = self.divergence.get(ev).unwrap();
            writeln!(f, "{:?}", divergences)?;
            writeln!(f, "{:?}", self.intervals.get(ev).unwrap())?;
            */
        }

        Ok(())
    }
}

/// Compute two moving averages over the data. Highlight points at which the averages diverage more
/// than a given amount.
///
/// Returns the list of divergence points. Specifically, a list of indices into `data` where the
/// moving averages diverge.
fn compute_moving_averages(data: &[f64]) -> Vec<(f64, f64, usize, f64)> {
    let mut divergence = vec![];

    // We need at least `ALPHA_LOW` elements to compute the average for the low-freq window. So if
    // there is not even that much data, then we cannot really do anything.
    if data.len() < ALPHA_LOW {
        return divergence;
    }

    // Otherwise compute the initial sums
    assert!(ALPHA_HIGH < ALPHA_LOW);

    let mut sum_lo: f64 = data[0..ALPHA_LOW].iter().sum();
    let mut sum_hi: f64 = data[ALPHA_LOW - ALPHA_HIGH..ALPHA_LOW].iter().sum();

    let mut iter = data.iter().enumerate().skip(ALPHA_LOW);
    let mut i = ALPHA_LOW;

    loop {
        // Check if the averages diverge by the threshold amount.
        let avg_lo = sum_lo / (ALPHA_LOW as f64);
        let avg_hi = sum_hi / (ALPHA_HIGH as f64);
        let dev = (avg_lo - avg_hi).abs() / (avg_lo + avg_hi);
        if dev >= AVERAGE_DIVERGENCE_THRESH {
            //println!("{:?} {}", (sum_lo, sum_hi, i, data[i - 1]), dev);
            divergence.push((avg_lo, avg_hi, i, data[i]));
        }

        // Update the sums/iterators.
        if let Some((i_prime, x)) = iter.next() {
            sum_lo += x - data[i_prime - ALPHA_LOW];
            sum_hi += x - data[i_prime - ALPHA_HIGH];
            i = i_prime;
        } else {
            break;
        }
    }

    divergence
}

pub fn stats(snap: Snapshot, sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let filter = sub_m
        .value_of("FILTER")
        .map(|arg| arg.parse::<usize>().unwrap());

    let cores: Option<HashSet<_>> = sub_m
        .values_of("CORE")
        .map(|values| values.map(|arg| arg.parse::<usize>().unwrap()).collect());

    /*
     * We start by finding all of the matching start/stop events and creating a stream of events.
     * We need to be able to handle nested events (e.g. a syscall may have a lot of interrupting
     * events happen during it).
     */

    let mut per_cpu_events = vec![];

    for cpu in snap.cpus().into_iter() {
        let mut events = Vec::new();
        let mut stack = Vec::new();

        for ev in cpu {
            match ev.event {
                // Drop unknown events
                ZerosimTraceEvent::Unknown { .. } => {}

                // Handle point events
                ZerosimTraceEvent::TaskSwitch { .. } => {
                    events.push(Event::Point(ev));
                }

                // Handle start events
                ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::IrqStart { .. }
                | ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::SoftIrqStart
                | ZerosimTraceEvent::VmEnter { .. } => {
                    stack.push(ev);
                }

                // Handle end events
                ZerosimTraceEvent::SystemCallEnd { .. }
                | ZerosimTraceEvent::IrqEnd { .. }
                | ZerosimTraceEvent::ExceptionEnd { .. }
                | ZerosimTraceEvent::SoftIrqEnd
                | ZerosimTraceEvent::VmExit { .. } => {
                    if let Some(top) = stack.last() {
                        if top.matches(ev) {
                            // Match!
                            let top = stack.pop().unwrap();
                            events.push(Event::Interval {
                                start: top,
                                end: ev,
                            });
                        } else {
                            // Just treat it as a point event
                            events.push(Event::Point(ev));
                        }
                    } else {
                        // Just treat it as a point event
                        events.push(Event::Point(ev));
                    }
                }
            }
        }

        // Push any remaining unmatched events
        events.extend(stack.drain(..).map(Event::Point));

        per_cpu_events.push(events);
    }

    /*
     * Compute and print stats over the event streams for each cpu we computed above.
     */
    println!(
        "{:>5} {:30} {:>15} {:>15} {:>15} {:>15} {:>15}",
        "core", "event", "duration (cyc)", "count", "median (cyc)", "p99 (cyc)", "# divergent (%)"
    );
    for (i, cpu) in per_cpu_events
        .into_iter()
        .enumerate()
        .filter(|(i, _)| cores.is_none() || cores.as_ref().unwrap().contains(i))
    {
        let mut stats = cpu
            .iter()
            .fold(PerCpuStats::empty(), PerCpuStats::fold_event);
        stats.finalize(filter);
        if !stats.is_empty() {
            println!("{:5}", i,);
            println!("{}", stats);
        }
    }

    Ok(())
}

/// A bunch of constants representing e.g. syscall numbers, etc.
mod reference {
    pub const LINUX_4_4_SYSCALLS_64_BIT: &[&str] = &[
        "read",
        "write",
        "open",
        "close",
        "stat",
        "fstat",
        "lstat",
        "poll",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "access",
        "pipe",
        "select",
        "sched_yield",
        "mremap",
        "msync",
        "mincore",
        "madvise",
        "shmget",
        "shmat",
        "shmctl",
        "dup",
        "dup2",
        "pause",
        "nanosleep",
        "getitimer",
        "alarm",
        "setitimer",
        "getpid",
        "sendfile",
        "socket",
        "connect",
        "accept",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "shutdown",
        "bind",
        "listen",
        "getsockname",
        "getpeername",
        "socketpair",
        "setsockopt",
        "getsockopt",
        "clone",
        "fork",
        "vfork",
        "execve",
        "exit",
        "wait4",
        "kill",
        "uname",
        "semget",
        "semop",
        "semctl",
        "shmdt",
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
        "fcntl",
        "flock",
        "fsync",
        "fdatasync",
        "truncate",
        "ftruncate",
        "getdents",
        "getcwd",
        "chdir",
        "fchdir",
        "rename",
        "mkdir",
        "rmdir",
        "creat",
        "link",
        "unlink",
        "symlink",
        "readlink",
        "chmod",
        "fchmod",
        "chown",
        "fchown",
        "lchown",
        "umask",
        "gettimeofday",
        "getrlimit",
        "getrusage",
        "sysinfo",
        "times",
        "ptrace",
        "getuid",
        "syslog",
        "getgid",
        "setuid",
        "setgid",
        "geteuid",
        "getegid",
        "setpgid",
        "getppid",
        "getpgrp",
        "setsid",
        "setreuid",
        "setregid",
        "getgroups",
        "setgroups",
        "setresuid",
        "getresuid",
        "setresgid",
        "getresgid",
        "getpgid",
        "setfsuid",
        "setfsgid",
        "getsid",
        "capget",
        "capset",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigsuspend",
        "sigaltstack",
        "utime",
        "mknod",
        "uselib",
        "personality",
        "ustat",
        "statfs",
        "fstatfs",
        "sysfs",
        "getpriority",
        "setpriority",
        "sched_setparam",
        "sched_getparam",
        "sched_setscheduler",
        "sched_getscheduler",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_rr_get_interval",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "vhangup",
        "modify_ldt",
        "pivot_root",
        "_sysctl",
        "prctl",
        "arch_prctl",
        "adjtimex",
        "setrlimit",
        "chroot",
        "sync",
        "acct",
        "settimeofday",
        "mount",
        "umount2",
        "swapon",
        "swapoff",
        "reboot",
        "sethostname",
        "setdomainname",
        "iopl",
        "ioperm",
        "create_module",
        "init_module",
        "delete_module",
        "get_kernel_syms",
        "query_module",
        "quotactl",
        "nfsservctl",
        "getpmsg",
        "putpmsg",
        "afs_syscall",
        "tuxcall",
        "security",
        "gettid",
        "readahead",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "getxattr",
        "lgetxattr",
        "fgetxattr",
        "listxattr",
        "llistxattr",
        "flistxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "tkill",
        "time",
        "futex",
        "sched_setaffinity",
        "sched_getaffinity",
        "set_thread_area",
        "io_setup",
        "io_destroy",
        "io_getevents",
        "io_submit",
        "io_cancel",
        "get_thread_area",
        "lookup_dcookie",
        "epoll_create",
        "epoll_ctl_old",
        "epoll_wait_old",
        "remap_file_pages",
        "getdents64",
        "set_tid_address",
        "restart_syscall",
        "semtimedop",
        "fadvise64",
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        "clock_settime",
        "clock_gettime",
        "clock_getres",
        "clock_nanosleep",
        "exit_group",
        "epoll_wait",
        "epoll_ctl",
        "tgkill",
        "utimes",
        "vserver",
        "mbind",
        "set_mempolicy",
        "get_mempolicy",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "kexec_load",
        "waitid",
        "add_key",
        "request_key",
        "keyctl",
        "ioprio_set",
        "ioprio_get",
        "inotify_init",
        "inotify_add_watch",
        "inotify_rm_watch",
        "migrate_pages",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "newfstatat",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "pselect6",
        "ppoll",
        "unshare",
        "set_robust_list",
        "get_robust_list",
        "splice",
        "tee",
        "sync_file_range",
        "vmsplice",
        "move_pages",
        "utimensat",
        "epoll_pwait",
        "signalfd",
        "timerfd_create",
        "eventfd",
        "fallocate",
        "timerfd_settime",
        "timerfd_gettime",
        "accept4",
        "signalfd4",
        "eventfd2",
        "epoll_create1",
        "dup3",
        "pipe2",
        "inotify_init1",
        "preadv",
        "pwritev",
        "rt_tgsigqueueinfo",
        "perf_event_open",
        "recvmmsg",
        "fanotify_init",
        "fanotify_mark",
        "prlimit64",
        "name_to_handle_at",
        "open_by_handle_at",
        "clock_adjtime",
        "syncfs",
        "sendmmsg",
        "setns",
        "getcpu",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "finit_module",
        "sched_setattr",
        "sched_getattr",
        "renameat2",
        "seccomp",
        "getrandom",
        "memfd_create",
        "kexec_file_load",
        "bpf",
        "execveat",
        "userfaultfd",
        "membarrier",
        "mlock2",
    ];

    pub const LINUX_4_4_SYSCALLS_64_BIT_512_548: &[&str] = &[
        "rt_sigaction",
        "rt_sigreturn",
        "ioctl",
        "readv",
        "writev",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "execve",
        "ptrace",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "sigaltstack",
        "timer_create",
        "mq_notify",
        "kexec_load",
        "waitid",
        "set_robust_list",
        "get_robust_list",
        "vmsplice",
        "move_pages",
        "preadv",
        "pwritev",
        "rt_tgsigqueueinfo",
        "recvmmsg",
        "sendmmsg",
        "process_vm_readv",
        "process_vm_writev",
        "setsockopt",
        "getsockopt",
        "io_setup",
        "io_submit",
        "execveat",
        "zerosim_trace_begin",
        "zerosim_trace_snapshot",
        "zerosim_trace_size",
    ];

    // See Vol 3. Appendix C.
    pub const X86_64_VM_EXIT_REASON: &[&str] = &[
        "Fault/NMI",
        "Ext Int",
        "Triple",
        "INIT",
        "SIPI",
        "SMI",
        "SMI2",
        "Int Win",
        "NMI Win",
        "Task Sw",
        "CPUID",
        "GETSEC",
        "HLT",
        "INVD",
        "INVLPG",
        "RDPMC",
        "RDTSC",
        "RSM",
        "VMCALL",
        "VMCLEAR",
        "VMLAUNCH",
        "VMPTRLD",
        "VMPTRST",
        "VMREAD",
        "VMRESUME",
        "VMWRITE",
        "VMXOFF",
        "VMXON",
        "CR Access",
        "MOV DR",
        "I/O Inst",
        "RDMSR",
        "WRMSR",
        "Enter Fail1",
        "Enter Fail2",
        "RESERVED",
        "MWAIT",
        "Mon Trap",
        "RESERVERD",
        "MONITOR",
        "PAUSE",
        "Enter Fail3",
        "RESERVED",
        "TPR<Thr",
        "APIC Access",
        "Virt EOI",
        "I/GDTR",
        "LD/TR",
        "EPT Vio",
        "EPT Misconf",
        "INVEPT",
        "RDTSCP",
        "Preempt Timer",
        "INVVPID",
        "WBINVD",
        "XSETBV",
        "APIC Wr",
        "RDRAND",
        "INVPCID",
        "VMFUNC",
        "ENCLS",
        "RDSEED",
        "Pg Log Full",
        "XSAVES",
        "XRSTORS",
        "RESERVED",
        "SPP",
    ];

    pub fn syscall_name(rax: usize) -> &'static str {
        if rax < 512 {
            LINUX_4_4_SYSCALLS_64_BIT[rax]
        } else {
            LINUX_4_4_SYSCALLS_64_BIT_512_548[rax - 512]
        }
    }

    pub fn vector_name(vector: usize) -> &'static str {
        if vector < 20 {
            "NMI or fault"
        } else if vector < 32 {
            "Reserved"
        } else if vector < 128 {
            "IRQ"
        } else if vector == 128 {
            "syscall"
        } else if vector < 239 {
            "IRQ"
        } else if vector == 239 {
            "LAPIC timer"
        } else if vector == 240 {
            "LAPIC thermal"
        } else if vector < 251 {
            "Reserved"
        } else if vector < 254 {
            "IPI"
        } else if vector == 254 {
            "LAPIC error"
        } else if vector == 255 {
            "LAPIC spurious"
        } else {
            "??"
        }
    }

    pub fn vm_exit_reason_name(reason: usize) -> &'static str {
        X86_64_VM_EXIT_REASON[reason]
    }
}
