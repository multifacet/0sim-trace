//! Various functionalities for analyzing a trace snapshot.

mod stats;

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use clap::clap_app;

use crate::tracing::{Snapshot, ZerosimTraceEvent};

pub fn cli_args() -> clap::App<'static, 'static> {
    fn is_usize(s: String) -> Result<(), String> {
        s.parse::<usize>().map(|_| ()).map_err(|e| format!("{}", e))
    }

    (clap_app! {analyze =>
        (about: "Analyze an existing trace.")
        (@arg FILE: +required ...
         "The file where the snapshot is stored.")
        (@subcommand dump =>
            (about: "Dump the snapshot in a human- (and python-) readable format.")
            (@arg OUTPUT_FILE: +required
             "The name of the file to dump to.")
            (@arg CORE: +takes_value ... {is_usize} -C --core
             "If passed, only dump traces for the given core. Can be used multiple times.")
        )
        (@subcommand stats =>
            (about: "Compute per-cpu stats from the trace snapshot.")
            (@arg FILTER: +takes_value {is_usize} -f --filter
             "If passed, filter out all evetns that occur fewer than N times, \
              where N is the value passed.")
            (@arg CORE: +takes_value ... {is_usize} -C --core
             "If passed, only show stats for the given core. Can be used multiple times.")
        )
    })
    .setting(clap::AppSettings::SubcommandRequired)
    .setting(clap::AppSettings::DisableVersion)
}

pub fn analyze(matches: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    for (i, file) in matches.values_of("FILE").unwrap().enumerate() {
        let snap = crate::record::deserialize(file)?;

        match matches.subcommand() {
            ("dump", Some(sub_m)) => dump(snap, sub_m, i == 0)?,
            ("stats", Some(sub_m)) => stats::stats(snap, sub_m)?,

            _ => unreachable!(),
        }
    }

    Ok(())
}

/// Dump the trace in a human (and python) readable format. This format is not space-efficient, but
/// it is easy to read (as a human) and easy parse (in a script).
pub fn dump(
    snap: Snapshot,
    sub_m: &clap::ArgMatches<'_>,
    is_first: bool,
) -> Result<(), failure::Error> {
    let cores: Option<HashSet<_>> = sub_m
        .values_of("CORE")
        .map(|values| values.map(|arg| arg.parse::<usize>().unwrap()).collect());

    let filename = sub_m.value_of("OUTPUT_FILE").unwrap();
    let f = if is_first {
        File::create(filename)?
    } else {
        OpenOptions::new().append(true).open(filename)?
    };
    let mut buf = BufWriter::new(f);
    for (i, cpu) in snap
        .cpus()
        .into_iter()
        .enumerate()
        .filter(|(i, _)| cores.is_none() || cores.as_ref().unwrap().contains(i))
    {
        writeln!(
            buf,
            "{} {:<15} {:5} ts: {}, id: {}, pid: {}, extra: {}",
            i, "RECORD", "START", 0, 0, 0, 0
        )?;

        for ev in cpu {
            let name =
                match ev.event {
                    ZerosimTraceEvent::TaskSwitch { .. } => "TASK_SWITCH",
                    ZerosimTraceEvent::SystemCallStart { .. }
                    | ZerosimTraceEvent::SystemCallEnd { .. } => "SYSCALL",
                    ZerosimTraceEvent::IrqStart { .. } | ZerosimTraceEvent::IrqEnd { .. } => {
                        "INTERRUPT"
                    }
                    ZerosimTraceEvent::SoftIrqStart { .. }
                    | ZerosimTraceEvent::SoftIrqEnd { .. } => "SOFTIRQ",
                    ZerosimTraceEvent::ExceptionStart { .. }
                    | ZerosimTraceEvent::ExceptionEnd { .. } => "FAULT",
                    ZerosimTraceEvent::VmEnter { .. } => "VMENTER",
                    ZerosimTraceEvent::VmExit { .. } => "VMEXIT",
                    ZerosimTraceEvent::VmDelayBegin { .. }
                    | ZerosimTraceEvent::VmDelayEnd { .. } => "VMDELAY",
                    ZerosimTraceEvent::Unknown { .. } => "??",
                };

            let start = match ev.event {
                ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::IrqStart { .. }
                | ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::SoftIrqStart
                | ZerosimTraceEvent::VmEnter { .. }
                | ZerosimTraceEvent::VmDelayBegin { .. } => "START",

                ZerosimTraceEvent::TaskSwitch { .. }
                | ZerosimTraceEvent::SystemCallEnd { .. }
                | ZerosimTraceEvent::IrqEnd { .. }
                | ZerosimTraceEvent::ExceptionEnd { .. }
                | ZerosimTraceEvent::SoftIrqEnd
                | ZerosimTraceEvent::Unknown { .. }
                | ZerosimTraceEvent::VmExit { .. }
                | ZerosimTraceEvent::VmDelayEnd { .. } => "",
            };

            let id = match ev.event {
                ZerosimTraceEvent::TaskSwitch { current_pid, .. } => current_pid,
                ZerosimTraceEvent::SystemCallStart { num }
                | ZerosimTraceEvent::SystemCallEnd { num, .. } => num,
                ZerosimTraceEvent::IrqStart { num } | ZerosimTraceEvent::IrqEnd { num } => num,
                ZerosimTraceEvent::SoftIrqStart { .. }
                | ZerosimTraceEvent::SoftIrqEnd { .. }
                | ZerosimTraceEvent::VmEnter { .. } => 0,
                ZerosimTraceEvent::ExceptionStart { error }
                | ZerosimTraceEvent::ExceptionEnd { error, .. } => error,
                ZerosimTraceEvent::VmExit { reason, .. } => reason as usize,
                ZerosimTraceEvent::Unknown { id, .. } => id as usize,
                ZerosimTraceEvent::VmDelayBegin { vcpu, .. }
                | ZerosimTraceEvent::VmDelayEnd { vcpu, .. } => vcpu as usize,
            };

            let extra = match ev.event {
                ZerosimTraceEvent::TaskSwitch { prev_pid, .. } => prev_pid,
                ZerosimTraceEvent::SystemCallEnd { num, .. } => num,
                ZerosimTraceEvent::ExceptionEnd { ip, .. } => ip as usize,
                ZerosimTraceEvent::Unknown { extra, .. } => extra as usize,
                ZerosimTraceEvent::VmEnter { vcpu } => vcpu,
                ZerosimTraceEvent::VmExit { qual, .. } => qual as usize,
                ZerosimTraceEvent::VmDelayBegin { behind, .. } => behind as usize,

                ZerosimTraceEvent::ExceptionStart { .. }
                | ZerosimTraceEvent::SystemCallStart { .. }
                | ZerosimTraceEvent::SoftIrqStart { .. }
                | ZerosimTraceEvent::SoftIrqEnd { .. }
                | ZerosimTraceEvent::IrqStart { .. }
                | ZerosimTraceEvent::IrqEnd { .. }
                | ZerosimTraceEvent::VmDelayEnd { .. } => 0,
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
