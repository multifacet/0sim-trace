#!/usr/bin/env python3

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.lines as lines
import matplotlib.collections as collect
import numpy as np
import re
import random
import datetime

from sys import argv

RE=r'''(\d+) ([\w?_]+)\s+(\w+)?\s+ts: (\d+), id: (\d+), pid: (\d+), extra: (\d+)'''

FREQ=3.5E3

INTERVAL_HEIGHT=0.15
TASK_HEIGHT=INTERVAL_HEIGHT*2

# The marker event just tells us when we started and stopped recording
MARKER = "RECORD"

LINUX_4_4_SYSCALLS_64_BIT = {
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        4: "stat",
        5: "fstat",
        6: "lstat",
        7: "poll",
        8: "lseek",
        9: "mmap",
        10: "mprotect",
        11: "munmap",
        12: "brk",
        13: "rt_sigaction",
        14: "rt_sigprocmask",
        15: "rt_sigreturn",
        16: "ioctl",
        17: "pread64",
        18: "pwrite64",
        19: "readv",
        20: "writev",
        21: "access",
        22: "pipe",
        23: "select",
        24: "sched_yield",
        25: "mremap",
        26: "msync",
        27: "mincore",
        28: "madvise",
        29: "shmget",
        30: "shmat",
        31: "shmctl",
        32: "dup",
        33: "dup2",
        34: "pause",
        35: "nanosleep",
        36: "getitimer",
        37: "alarm",
        38: "setitimer",
        39: "getpid",
        40: "sendfile",
        41: "socket",
        42: "connect",
        43: "accept",
        44: "sendto",
        45: "recvfrom",
        46: "sendmsg",
        47: "recvmsg",
        48: "shutdown",
        49: "bind",
        50: "listen",
        51: "getsockname",
        52: "getpeername",
        53: "socketpair",
        54: "setsockopt",
        55: "getsockopt",
        56: "clone",
        57: "fork",
        58: "vfork",
        59: "execve",
        60: "exit",
        61: "wait4",
        62: "kill",
        63: "uname",
        64: "semget",
        65: "semop",
        66: "semctl",
        67: "shmdt",
        68: "msgget",
        69: "msgsnd",
        70: "msgrcv",
        71: "msgctl",
        72: "fcntl",
        73: "flock",
        74: "fsync",
        75: "fdatasync",
        76: "truncate",
        77: "ftruncate",
        78: "getdents",
        79: "getcwd",
        80: "chdir",
        81: "fchdir",
        82: "rename",
        83: "mkdir",
        84: "rmdir",
        85: "creat",
        86: "link",
        87: "unlink",
        88: "symlink",
        89: "readlink",
        90: "chmod",
        91: "fchmod",
        92: "chown",
        93: "fchown",
        94: "lchown",
        95: "umask",
        96: "gettimeofday",
        97: "getrlimit",
        98: "getrusage",
        99: "sysinfo",
        100: "times",
        101: "ptrace",
        102: "getuid",
        103: "syslog",
        104: "getgid",
        105: "setuid",
        106: "setgid",
        107: "geteuid",
        108: "getegid",
        109: "setpgid",
        110: "getppid",
        111: "getpgrp",
        112: "setsid",
        113: "setreuid",
        114: "setregid",
        115: "getgroups",
        116: "setgroups",
        117: "setresuid",
        118: "getresuid",
        119: "setresgid",
        120: "getresgid",
        121: "getpgid",
        122: "setfsuid",
        123: "setfsgid",
        124: "getsid",
        125: "capget",
        126: "capset",
        127: "rt_sigpending",
        128: "rt_sigtimedwait",
        129: "rt_sigqueueinfo",
        130: "rt_sigsuspend",
        131: "sigaltstack",
        132: "utime",
        133: "mknod",
        134: "uselib",
        135: "personality",
        136: "ustat",
        137: "statfs",
        138: "fstatfs",
        139: "sysfs",
        140: "getpriority",
        141: "setpriority",
        142: "sched_setparam",
        143: "sched_getparam",
        144: "sched_setscheduler",
        145: "sched_getscheduler",
        146: "sched_get_priority_max",
        147: "sched_get_priority_min",
        148: "sched_rr_get_interval",
        149: "mlock",
        150: "munlock",
        151: "mlockall",
        152: "munlockall",
        153: "vhangup",
        154: "modify_ldt",
        155: "pivot_root",
        156: "_sysctl",
        157: "prctl",
        158: "arch_prctl",
        159: "adjtimex",
        160: "setrlimit",
        161: "chroot",
        162: "sync",
        163: "acct",
        164: "settimeofday",
        165: "mount",
        166: "umount2",
        167: "swapon",
        168: "swapoff",
        169: "reboot",
        170: "sethostname",
        171: "setdomainname",
        172: "iopl",
        173: "ioperm",
        174: "create_module",
        175: "init_module",
        176: "delete_module",
        177: "get_kernel_syms",
        178: "query_module",
        179: "quotactl",
        180: "nfsservctl",
        181: "getpmsg",
        182: "putpmsg",
        183: "afs_syscall",
        184: "tuxcall",
        185: "security",
        186: "gettid",
        187: "readahead",
        188: "setxattr",
        189: "lsetxattr",
        190: "fsetxattr",
        191: "getxattr",
        192: "lgetxattr",
        193: "fgetxattr",
        194: "listxattr",
        195: "llistxattr",
        196: "flistxattr",
        197: "removexattr",
        198: "lremovexattr",
        199: "fremovexattr",
        200: "tkill",
        201: "time",
        202: "futex",
        203: "sched_setaffinity",
        204: "sched_getaffinity",
        205: "set_thread_area",
        206: "io_setup",
        207: "io_destroy",
        208: "io_getevents",
        209: "io_submit",
        210: "io_cancel",
        211: "get_thread_area",
        212: "lookup_dcookie",
        213: "epoll_create",
        214: "epoll_ctl_old",
        215: "epoll_wait_old",
        216: "remap_file_pages",
        217: "getdents64",
        218: "set_tid_address",
        219: "restart_syscall",
        220: "semtimedop",
        221: "fadvise64",
        222: "timer_create",
        223: "timer_settime",
        224: "timer_gettime",
        225: "timer_getoverrun",
        226: "timer_delete",
        227: "clock_settime",
        228: "clock_gettime",
        229: "clock_getres",
        230: "clock_nanosleep",
        231: "exit_group",
        232: "epoll_wait",
        233: "epoll_ctl",
        234: "tgkill",
        235: "utimes",
        236: "vserver",
        237: "mbind",
        238: "set_mempolicy",
        239: "get_mempolicy",
        240: "mq_open",
        241: "mq_unlink",
        242: "mq_timedsend",
        243: "mq_timedreceive",
        244: "mq_notify",
        245: "mq_getsetattr",
        246: "kexec_load",
        247: "waitid",
        248: "add_key",
        249: "request_key",
        250: "keyctl",
        251: "ioprio_set",
        252: "ioprio_get",
        253: "inotify_init",
        254: "inotify_add_watch",
        255: "inotify_rm_watch",
        256: "migrate_pages",
        257: "openat",
        258: "mkdirat",
        259: "mknodat",
        260: "fchownat",
        261: "futimesat",
        262: "newfstatat",
        263: "unlinkat",
        264: "renameat",
        265: "linkat",
        266: "symlinkat",
        267: "readlinkat",
        268: "fchmodat",
        269: "faccessat",
        270: "pselect6",
        271: "ppoll",
        272: "unshare",
        273: "set_robust_list",
        274: "get_robust_list",
        275: "splice",
        276: "tee",
        277: "sync_file_range",
        278: "vmsplice",
        279: "move_pages",
        280: "utimensat",
        281: "epoll_pwait",
        282: "signalfd",
        283: "timerfd_create",
        284: "eventfd",
        285: "fallocate",
        286: "timerfd_settime",
        287: "timerfd_gettime",
        288: "accept4",
        289: "signalfd4",
        290: "eventfd2",
        291: "epoll_create1",
        292: "dup3",
        293: "pipe2",
        294: "inotify_init1",
        295: "preadv",
        296: "pwritev",
        297: "rt_tgsigqueueinfo",
        298: "perf_event_open",
        299: "recvmmsg",
        300: "fanotify_init",
        301: "fanotify_mark",
        302: "prlimit64",
        303: "name_to_handle_at",
        304: "open_by_handle_at",
        305: "clock_adjtime",
        306: "syncfs",
        307: "sendmmsg",
        308: "setns",
        309: "getcpu",
        310: "process_vm_readv",
        311: "process_vm_writev",
        312: "kcmp",
        313: "finit_module",
        314: "sched_setattr",
        315: "sched_getattr",
        316: "renameat2",
        317: "seccomp",
        318: "getrandom",
        319: "memfd_create",
        320: "kexec_file_load",
        321: "bpf",
        322: "execveat",
        323: "userfaultfd",
        324: "membarrier",
        325: "mlock2",
        512: "rt_sigaction",
        513: "rt_sigreturn",
        514: "ioctl",
        515: "readv",
        516: "writev",
        517: "recvfrom",
        518: "sendmsg",
        519: "recvmsg",
        520: "execve",
        521: "ptrace",
        522: "rt_sigpending",
        523: "rt_sigtimedwait",
        524: "rt_sigqueueinfo",
        525: "sigaltstack",
        526: "timer_create",
        527: "mq_notify",
        528: "kexec_load",
        529: "waitid",
        530: "set_robust_list",
        531: "get_robust_list",
        532: "vmsplice",
        533: "move_pages",
        534: "preadv",
        535: "pwritev",
        536: "rt_tgsigqueueinfo",
        537: "recvmmsg",
        538: "sendmmsg",
        539: "process_vm_readv",
        540: "process_vm_writev",
        541: "setsockopt",
        542: "getsockopt",
        543: "io_setup",
        544: "io_submit",
        545: "execveat",
        546: "zerosim_trace_begin",
        547: "zerosim_trace_snapshot",
        548: "zerosim_trace_size",
}

filename = argv[1]

class Event:
    def __init__(self, name, is_start, ts, eid, pid, extra):
        self.name = name
        self.is_start = is_start
        self.ts = ts
        self.eid = eid
        self.pid = pid
        self.extra = extra

    def __repr__(self):
        return "<{} {} {} {} {} {}>".format(self.name, self.is_start,
                self.ts, self.eid, self.pid, self.extra)

class IntervalEvent:
    def __init__(self, name, start_ts, end_ts, eid, pid, extra):
        self.name = name
        self.start_ts = start_ts
        self.end_ts = end_ts
        self.eid = eid
        self.pid = pid
        self.extra = extra

    def __repr__(self):
        return "[{} {} {} {} {} {}]".format(self.name, self.start_ts,
                self.end_ts, self.eid, self.pid, self.extra)

data = {}
min_ts = None
max_ts = None

per_cpu_min_ts = {}

# Keep track of the pids for all events. When the pid changes, we start a new
# interval for a new task.
per_cpu_tasks = {}

# Keep track of time that is not measured.
per_cpu_unmeasured = {}

with open(filename, 'r') as f:
    prev_task = {}
    unmeasured_start = {}

    for line in f.readlines():
        m = re.match(RE, line)

        if m is None:
            print("No match for line: %s" % line)

        core = int(m.group(1))
        event = m.group(2)
        start = m.group(3) is not None
        ts = int(m.group(4)) / FREQ # usec
        eid = int(m.group(5))
        pid = int(m.group(6))
        extra = int(m.group(7))

        if core not in data:
            data[core] = []
            per_cpu_min_ts[core] = None
            per_cpu_tasks[core] = []
            per_cpu_unmeasured[core] = []
            prev_task[core] = None
            unmeasured_start[core] = None

        if not start and ts == 0 and eid == 0 and event != MARKER:
            print("skipping %s" % line)
            continue

        ev = Event(event, start, ts, eid, pid, extra)

        data[core].append(ev)

        # Handle the special marker events
        if ev.name == MARKER and ev.is_start:
            continue
        elif ev.name == MARKER:
            if prev_task[core] is not None:
                per_cpu_tasks[core].append((prev_task[core], data[core][-2].ts))
                prev_task[core] = None
            unmeasured_start[core] = data[core][-2].ts
            continue
        elif unmeasured_start[core] is not None:
            per_cpu_unmeasured[core].append((unmeasured_start[core], ev.ts))
            unmeasured_start[core] = None

        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

        if per_cpu_min_ts[core] is None or ts < per_cpu_min_ts[core]:
            per_cpu_min_ts[core] = ts

        if prev_task[core] is None:
            prev_task[core] = ev
        elif prev_task[core].pid != ev.pid:
            per_cpu_tasks[core].append((prev_task[core], ev.ts))
            prev_task[core] = ev

    for cpu, task in prev_task.items():
        if task is not None:
            per_cpu_tasks[cpu].append((task, max_ts))

# Process to get matching events and start-stop events
for cpu, cpu_data in data.items():
    matched = []

    # stack of pending events
    pending = []

    for ev in cpu_data:
        # handle the special marker events
        if ev.name == MARKER and ev.is_start:
            continue
        elif ev.name == MARKER:
            # recording ended... reset everything
            matched.extend(pending)
            pending = []
            continue

        # handle open events
        if ev.is_start:
            pending.append(ev)
            continue

        # handle close events
        else:
            # if the event matches something on the stack, match it. Otherwise,
            # push a singleton event.
            if len(pending) > 0 \
                    and ev.name == pending[-1].name \
                    and ev.eid == pending[-1].eid \
                    and ev.pid == pending[-1].pid:
                start = pending.pop()
                matched.append(IntervalEvent(ev.name, start.ts, ev.ts, ev.eid, ev.pid, ev.extra))
            else:
                matched.append(ev)

    # Append all pending events as singletons
    matched.extend(pending)

    data[cpu] = matched

print("done processing %s" % datetime.datetime.now())

matplotlib.rcParams['agg.path.chunksize'] = 100000
fig, ax = plt.subplots(figsize=(8, 5))

# Plot all the unmeasured parts

cpu_lines = []

for cpu in data:
    if per_cpu_min_ts[cpu] is None:
        per_cpu_min_ts[cpu] = max_ts

    cpu_lines.append([(0, cpu), (per_cpu_min_ts[cpu] - min_ts, cpu)])
    cpu_lines.append([(per_cpu_unmeasured[cpu][-1][0] - min_ts, cpu), (max_ts - min_ts, cpu)])

for cpu, regions in per_cpu_unmeasured.items():
    for start, end in regions:
        cpu_lines.append([(start - min_ts, cpu), (end - min_ts, cpu)])

ax.add_collection(collect.LineCollection(cpu_lines,
        colors=[(0,0,0,0.2)]*len(data)))

print("done plotting unmeasured time %s" % datetime.datetime.now())

# Plot processes/tasks

task_patches = []

np.random.seed(0)
task_colors = {}

def get_task_color(pid):
    if pid in task_colors:
        return task_colors[pid]
    else:
        task_colors[pid] = np.random.rand(3,)
        return get_task_color(pid)

for cpu, tasks in per_cpu_tasks.items():
    for ev, end_ts in tasks:
        rect = patches.Rectangle(
                (ev.ts - min_ts, cpu - TASK_HEIGHT/2), end_ts - ev.ts, TASK_HEIGHT,
                facecolor=get_task_color(ev.pid), alpha=1)
        task_patches.append(rect)

ax.add_collection(collect.PatchCollection(
    task_patches, match_original=True, hatch='xx', edgecolor='#333333'))

print("done plotting tasks %s" % datetime.datetime.now())

# Plot the actual events

events_patches = []

label_colors = {}

def get_label_color(label):
    if label in label_colors:
        return label_colors[label]
    else:
        label_colors[label] = np.random.rand(3,)
        return get_label_color(label)

plot_map = {}

scattered = []
scattered_events = []

for cpu, cpu_data in data.items():
    for ev in cpu_data:
        if isinstance(ev, IntervalEvent):
            rect = patches.Rectangle(
                    (ev.start_ts - min_ts, cpu - INTERVAL_HEIGHT/2),
                    ev.end_ts - ev.start_ts, INTERVAL_HEIGHT,
                    color=get_label_color(ev.name), fill=True, alpha=1, picker=True)
            plot_map[rect] = (cpu, ev)
            events_patches.append(rect)
        else:
            scattered.append((ev.ts - min_ts, cpu, get_label_color(ev.name)))
            scattered_events.append((cpu, ev))

# draw short event last so they are on top.
# zorder doesn't work for collections of patches.
events_patches.sort(reverse=True, key=lambda p: p.get_width())

ax.add_collection(
        collect.PatchCollection(events_patches, match_original=True, picker=True,
            zorder=3))

xs, ys, cs = zip(*scattered)
ax.scatter(xs, ys, color=cs, marker='.', s=50, zorder=9999, picker=True)

print("done plotting events %s" % datetime.datetime.now())

# Custom legend
legend_elements = [
   lines.Line2D([0], [0], color='k', alpha=0.2, label='Not Measured'),
   lines.Line2D([0], [0], markerfacecolor='k', marker='.', \
           markersize=15, color='w', label='Discrete Event'),
]

for label, color in label_colors.items():
    legend_elements.append(lines.Line2D([0], [0], color=color, lw=4, label=label))

ax.legend(handles=legend_elements, bbox_to_anchor=(0,1.02,1,0.2), loc="lower left",
                mode="expand", borderaxespad=0, ncol=3)

print("done plotting making legend %s" % datetime.datetime.now())

# Annotations on hover
annot = ax.annotate("", xy=(0,0), xytext=(20,20),textcoords="offset points",
                    bbox=dict(boxstyle="round", fc="w"),
                    arrowprops=dict(arrowstyle="->"), zorder=10000)
annot.set_visible(False)

def onpick(event):
    cpu, trace_ev = None, None

    if isinstance(event.artist, collect.PatchCollection):
        # Choose the shortest event, since it is likely the one that was clicked.
        cpu, trace_ev = None, None
        for i in event.ind:
            c, tev = plot_map[events_patches[i]]
            if cpu is None or (tev.end_ts - tev.start_ts) < (trace_ev.end_ts - trace_ev.start_ts):
                cpu, trace_ev = c, tev

    elif isinstance(event.artist, collect.PathCollection):
        cpu, trace_ev = scattered_events[event.ind[0]]
    else:
        print("Unknown artist type: %s" % event.artist)
        return

    ts = None
    text = ""

    if isinstance(trace_ev, IntervalEvent):
        ts = trace_ev.start_ts
        text = "{} id: {}{}\nduration: {:,.3f} us\npid: {}\nextra: {}".format(
                trace_ev.name, trace_ev.eid,
                (" (%s)" % LINUX_4_4_SYSCALLS_64_BIT[trace_ev.eid]) if trace_ev.name == "SYSCALL" else "",
                trace_ev.end_ts - trace_ev.start_ts,
                trace_ev.pid, trace_ev.extra)
    else:
        ts = trace_ev.ts
        text = "{} id: {}{}\npid: {}\nextra: {}".format(
                trace_ev.name, trace_ev.eid,
                (" (%s)" % LINUX_4_4_SYSCALLS_64_BIT[trace_ev.eid]) if trace_ev.name == "SYSCALL" else "",
                trace_ev.pid, trace_ev.extra)

    annot.xy = (ts - min_ts, cpu)
    annot.set_text(text)
    annot.get_bbox_patch().set_facecolor("grey")
    annot.get_bbox_patch().set_alpha(0.6)

    annot.set_visible(True)
    fig.canvas.draw_idle()

fig.canvas.mpl_connect("pick_event", onpick)

# Axes
plt.xlabel("Time Elapsed (usec)")

plt.yticks([c for c in data], ["CPU%d" % c for c in data])

plt.setp(( ax.get_yticklines() +
          list(ax.spines.values())), visible=False)

# Plot
plt.show()
