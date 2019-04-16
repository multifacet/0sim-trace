# 0sim-trace

This is intended as a debugging tool for the simulator (initially). It is a
very simplified implementation of
[`kutrace`](https://www.youtube.com/watch?v=UYwWollxzAk). Currently, it debugs
_the host_, not the simulated workload.

The kernel-side implementation is in `kernel/zerosim-trace.c` in the `0sim`
repo, with hooks inserted on the x86-64 syscall, interrupt, fault, and
task-switching code paths in the kernel.
