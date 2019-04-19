//! A simple program that traces using zerosim-trace and outputs the results.

mod tracing;

use std::fs::File;
use std::io::{BufWriter, Write};

use clap::clap_app;

use tracing::{Snapshot, ZerosimTracer};

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
    }
    .get_matches();

    let interval = matches
        .value_of("INTERVAL")
        .unwrap()
        .parse::<usize>()
        .unwrap() as u64;
    let buffer_size = matches
        .value_of("BUFFER_SIZE")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let prefix = matches.value_of("OUTPUT_PREFIX").unwrap();

    let mut zs = ZerosimTracer::init(buffer_size)?;

    for i in 0.. {
        let pending = zs.begin(None)?;

        std::thread::sleep(std::time::Duration::from_millis(interval));

        let snap = pending.snapshot();

        let prefix = prefix.to_owned();
        let _ = std::thread::spawn(move || process_snapshot(snap, &prefix, i));
    }

    Ok(())
}

fn process_snapshot(snap: Snapshot, prefix: &str, i: usize) {
    let f = File::create(&format!("{}{}", prefix, i)).unwrap();
    let mut buf = BufWriter::new(f);
    for (i, cpu) in snap.cpus().into_iter().enumerate() {
        for ev in cpu {
            writeln!(buf, "{} {:?}", i, ev).unwrap();
        }
    }
}
