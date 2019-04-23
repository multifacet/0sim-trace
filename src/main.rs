//! A simple program that traces using zerosim-trace and outputs the results.

mod tracing;

use std::fs::File;
use std::io::{BufWriter, Write};

use clap::clap_app;

use tracing::{Snapshot, ZerosimTraceEvent, ZerosimTracer};

fn is_usize(s: String) -> Result<(), String> {
    s.parse::<usize>().map(|_| ()).map_err(|e| format!("{}", e))
}

fn main() -> Result<(), failure::Error> {
    let matches = clap_app! {zerosim_trace =>
        (about: "Takes periodic traces using the 0sim tracing API.")
        (@arg INTERVAL: +required {is_usize}
         "The interval to take snapshots at in milliseconds.")
        (@arg BUFFER_SIZE: +required {is_usize}
         "The number of events to buffer on each CPU per snapshot.")
        (@arg OUTPUT_PREFIX: +required
         "The filename prefix of the output files.")
        (@arg TOTAL: +takes_value {is_usize} -t --total
         "The total amount of time (in msecs) to measure; if omitted, measure until killed by ^C.")
    }
    .get_matches();

    let interval = matches
        .value_of("INTERVAL")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let buffer_size = matches
        .value_of("BUFFER_SIZE")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let prefix = matches.value_of("OUTPUT_PREFIX").unwrap();
    let total = matches
        .value_of("TOTAL")
        .map(|t| t.parse::<usize>().unwrap());

    let mut zs = ZerosimTracer::init(buffer_size)?;

    let done = |i| {
        if let Some(total) = total {
            i * (interval as usize) > total
        } else {
            false
        }
    };

    let mut i = 0;
    while !done(i) {
        let pending = zs.begin(None)?;

        std::thread::sleep(std::time::Duration::from_millis(interval));

        let snap = pending.snapshot()?;

        let prefix = prefix.to_owned();
        let _ = std::thread::spawn(move || process_snapshot(snap, &prefix, i));

        i += 1;
    }

    Ok(())
}

fn process_snapshot(snap: Snapshot, prefix: &str, i: usize) {
    let f = File::create(&format!("{}{:05}", prefix, i)).unwrap();
    let mut buf = BufWriter::new(f);
    for (i, cpu) in snap.cpus().into_iter().enumerate() {
        writeln!(
            buf,
            "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
            i, "RECORD", "START", 0, 0, 0, 0
        )
        .unwrap();

        for ev in cpu {
            let name = match ev.event {
                ZerosimTraceEvent::TaskSwitch { .. } => "TASK_SWITCH",
                ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::SystemCallEnd { .. } => "SYSCALL",
                ZerosimTraceEvent::IrqStart { .. } | ZerosimTraceEvent::IrqEnd { .. } => {
                    "INTERRUPT"
                }
                ZerosimTraceEvent::SoftIrqStart { .. } | ZerosimTraceEvent::SoftIrqEnd { .. } => {
                    "SOFTIRQ"
                }
                ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::ExceptionEnd { .. } => "FAULT",
                ZerosimTraceEvent::Unknown { .. } => "??",
            };

            let start = match ev.event {
                ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::IrqStart { .. }
                | ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::SoftIrqStart => "START",

                ZerosimTraceEvent::TaskSwitch { .. }
                | ZerosimTraceEvent::SystemCallEnd { .. }
                | ZerosimTraceEvent::IrqEnd { .. }
                | ZerosimTraceEvent::ExceptionEnd { .. }
                | ZerosimTraceEvent::SoftIrqEnd
                | ZerosimTraceEvent::Unknown { .. } => "",
            };

            let id = match ev.event {
                ZerosimTraceEvent::TaskSwitch { current_pid, .. } => current_pid,
                ZerosimTraceEvent::SystemCallStart { num }
                | ZerosimTraceEvent::SystemCallEnd { num, .. } => num,
                ZerosimTraceEvent::IrqStart { num } | ZerosimTraceEvent::IrqEnd { num } => num,
                ZerosimTraceEvent::SoftIrqStart { .. } | ZerosimTraceEvent::SoftIrqEnd { .. } => 0,
                ZerosimTraceEvent::ExceptionStart { error }
                | ZerosimTraceEvent::ExceptionEnd { error, .. } => error,
                ZerosimTraceEvent::Unknown { id, .. } => id as usize,
            };

            let extra = match ev.event {
                ZerosimTraceEvent::TaskSwitch { prev_pid, .. } => prev_pid,
                ZerosimTraceEvent::SystemCallEnd { num, .. } => num,
                ZerosimTraceEvent::ExceptionEnd { ip, .. } => ip as usize,
                ZerosimTraceEvent::Unknown { extra, .. } => extra as usize,

                ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::SoftIrqStart { .. }
                | ZerosimTraceEvent::SoftIrqEnd { .. }
                | ZerosimTraceEvent::IrqStart { .. }
                | ZerosimTraceEvent::IrqEnd { .. } => 0,
            };

            writeln!(
                buf,
                "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
                i, name, start, ev.timestamp, id, ev.pid, extra
            )
            .unwrap();
        }

        writeln!(
            buf,
            "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
            i, "RECORD", "", 0, 0, 0, 0
        )
        .unwrap();
    }
}
