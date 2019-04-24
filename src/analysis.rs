//! Various functionalities for analyzing a trace snapshot.

mod stats;

use std::fs::File;
use std::io::{BufWriter, Write};

use clap::clap_app;

use crate::tracing::{Snapshot, ZerosimTraceEvent};

pub fn cli_args() -> clap::App<'static, 'static> {
    (clap_app! {analyze =>
        (about: "Analyze an existing trace.")
        (@arg FILE: +required
         "The file where the snapshot is stored.")
        (@subcommand dump =>
            (about: "Dump the snapshot in a human- (and python-) readable format.")
            (@arg OUTPUT_FILE: +required
             "The name of the file to dump to.")
        )
        (@subcommand stats =>
            (about: "Compute per-cpu stats from the trace snapshot.")
        )
    })
    .setting(clap::AppSettings::SubcommandRequired)
    .setting(clap::AppSettings::DisableVersion)
}

pub fn analyze(matches: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let snap = crate::record::deserialize(matches.value_of("FILE").unwrap())?;

    match matches.subcommand() {
        ("dump", Some(sub_m)) => dump(snap, sub_m),
        ("stats", Some(sub_m)) => stats::stats(snap, sub_m),

        _ => unreachable!(),
    }
}

/// Dump the trace in a human (and python) readable format. This format is not space-efficient, but
/// it is easy to read (as a human) and easy parse (in a script).
pub fn dump(snap: Snapshot, sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let filename = sub_m.value_of("OUTPUT_FILE").unwrap();
    let f = File::create(filename)?;
    let mut buf = BufWriter::new(f);
    for (i, cpu) in snap.cpus().into_iter().enumerate() {
        writeln!(
            buf,
            "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
            i, "RECORD", "START", 0, 0, 0, 0
        )?;

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
            )?;
        }

        writeln!(
            buf,
            "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
            i, "RECORD", "", 0, 0, 0, 0
        )?;
    }

    Ok(())
}
