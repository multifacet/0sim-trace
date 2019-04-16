#!/usr/bin/env python3

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.lines as lines
import numpy as np
import re
import random

from sys import argv

RE=r'''(\d+) { ([\w?_]+)\s+(\w+)?\s+ts: (\d+), flags:\s+(\d+), id: (\d+), pid: (\d+), extra: (\d+) }'''

FREQ=3.5E3

INTERVAL_HEIGHT=0.3

START_MARKER='>'
END_MARKER='<'

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

data = {}
min_ts = None
max_ts = None

per_cpu_min_ts = {}

with open(filename, 'r') as f:
    for line in f.readlines():
        m = re.match(RE, line)

        if m is None:
            print("No match for line: %s" % line)

        core = int(m.group(1))
        event = m.group(2)
        start = m.group(3) is not None
        ts = int(m.group(4)) / FREQ # usec
        flags = int(m.group(5), 2)  # binary
        ev_id = int(m.group(6))
        pid = int(m.group(7))
        extra = int(m.group(8))

        if core not in data:
            data[core] = []
            per_cpu_min_ts[core] = None

        if start == 0 and ts == 0 and flags == 0 and ev_id == 0:
            continue

        data[core].append((event, start, ts, flags, ev_id, pid, extra))

        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

        if per_cpu_min_ts[core] is None or ts < per_cpu_min_ts[core]:
            per_cpu_min_ts[core] = ts

# Process to get matching events
for cpu, cpu_data in data.items():
    matched = []

    # stack of pending events
    pending = []

    for ev in cpu_data:
        # handle open events
        if ev[1]:
            pending.append(ev)
            continue

        # handle close events
        else:
            # if the event matches something on the stack, match it. Otherwise,
            # push a singleton event.
            if len(pending) > 0 \
                    and ev[0] == pending[-1][0] \
                    and ev[4] == pending[-1][4] \
                    and ev[5] == pending[-1][5]:
                start = pending.pop()
                matched.append(("interval", ev[0], start[2], ev[2], ev[3], ev[4], ev[5], ev[6]))
            else:
                matched.append(ev)

    # Append all pending events as singletons
    matched.extend(pending)

    data[cpu] = matched

levels = np.array([-5, 5, -3, 3, -1, 1])
fig, ax = plt.subplots(figsize=(8, 5))

# Create a line for each CPU
for cpu in range(len(data)):
    if per_cpu_min_ts[cpu] is None:
        per_cpu_min_ts[cpu] = max_ts

    ax.text((min_ts - max_ts) * 0.01, cpu, "CPU%d" % cpu, horizontalalignment='right', verticalalignment='center', fontsize=14)
    ax.plot((0, per_cpu_min_ts[cpu] - min_ts), (cpu, cpu), 'k', alpha=0.2, linestyle="dashed")
    ax.plot((per_cpu_min_ts[cpu] - min_ts, max_ts - min_ts), (cpu, cpu), 'k', alpha=0.2)

np.random.seed(0)

label_colors = {}

def get_label_color(label):
    if label in label_colors:
        return label_colors[label]
    else:
        label_colors[label] = np.random.rand(3,)
        return get_label_color(label)

plot_map = {}

# Iterate through releases annotating each one
for cpu, cpu_data in data.items():
    for ev in cpu_data:
        if ev[0] == 'interval':
            # intervals (matched events)
            rect = patches.Rectangle((ev[2] - min_ts, cpu - INTERVAL_HEIGHT/2), ev[3] - ev[2],
                    INTERVAL_HEIGHT, color=get_label_color(ev[1]), fill=True, alpha=0.5, picker=True)
            plot_map[rect] = (cpu, ev)
            ax.add_patch(rect)
        else:
            # point event
            sc = ax.scatter(ev[2] - min_ts, cpu, s=50,
                    c=get_label_color(ev[0]),
                    marker=START_MARKER if ev[1] else END_MARKER,
                    zorder=9999, picker=True)

            plot_map[sc] = (cpu, ev)

# Custom legend
legend_elements = [
                   lines.Line2D([0], [0], color='k', alpha=0.2,
                       linestyle="dashed", label='Not Measured'),
                   lines.Line2D([0], [0], markerfacecolor='k', marker=START_MARKER, \
                       markersize=15, color='w', label='Start'),
                   lines.Line2D([0], [0], markerfacecolor='k', marker=END_MARKER, \
                       markersize=15, color='w', label='End'),
                   ]

for label, color in label_colors.items():
    legend_elements.append(lines.Line2D([0], [0], color=color, lw=4, label=label))

ax.legend(handles=legend_elements, bbox_to_anchor=(0,1.02,1,0.2), loc="lower left",
                mode="expand", borderaxespad=0, ncol=3)

# Annotations on hover
annot = ax.annotate("", xy=(0,0), xytext=(20,20),textcoords="offset points",
                    bbox=dict(boxstyle="round", fc="w"),
                    arrowprops=dict(arrowstyle="->"), zorder=10000)
annot.set_visible(False)

def onpick(event):
    cpu, trace_ev = plot_map[event.artist]

    annot.xy = (trace_ev[2] - min_ts, cpu)

    text = ""

    if trace_ev[0] == "interval":
        text = "{} id: {}{}\nduration: {:,.3f} us\npid: {}\nextra: {}".format(
                trace_ev[1], trace_ev[5],
                (" (%s)" % LINUX_4_4_SYSCALLS_64_BIT[trace_ev[5]]) if trace_ev[1] == "SYSCALL" else "",
                trace_ev[3] - trace_ev[2],
                trace_ev[6], trace_ev[7])
    else:
        text = "{} id: {}{}\npid: {}\nextra: {}".format(
                trace_ev[0], trace_ev[4],
                (" (%s)" % LINUX_4_4_SYSCALLS_64_BIT[trace_ev[5]]) if trace_ev[1] == "SYSCALL" else "",
                trace_ev[5], trace_ev[6])

    annot.set_text(text)
    annot.get_bbox_patch().set_facecolor("grey")
    annot.get_bbox_patch().set_alpha(0.4)

    annot.set_visible(True)
    fig.canvas.draw_idle()

fig.canvas.mpl_connect("pick_event", onpick)

# X axis label
plt.xlabel("Time Elapsed (usec)")

# Remove components for a cleaner look
plt.setp((ax.get_yticklabels() + ax.get_yticklines() +
          list(ax.spines.values())), visible=False)
plt.show()
