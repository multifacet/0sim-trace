//! Functionality for recording a trace

use std::fs::File;
use std::io::{BufWriter, Write};

use clap::clap_app;

use crate::tracing::{Snapshot, ZerosimTracer};

pub fn cli_args() -> clap::App<'static, 'static> {
    fn is_usize(s: String) -> Result<(), String> {
        s.parse::<usize>().map(|_| ()).map_err(|e| format!("{}", e))
    }

    clap_app! {trace =>
        (about: "Record a trace. Takes periodic traces using the 0sim tracing API.")
        (@arg INTERVAL: +required {is_usize}
         "The interval to take snapshots at in milliseconds.")
        (@arg BUFFER_SIZE: +required {is_usize}
         "The number of events to buffer on each CPU per snapshot.")
        (@arg OUTPUT_PREFIX: +required
         "The filename prefix of the output files.")
        (@arg TOTAL: +takes_value {is_usize} -t --total
         "The total amount of time (in msecs) to measure; if omitted, measure until killed by ^C.")
    }
}

pub fn record(matches: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
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

    let mut handles = if let Some(total) = total {
        Vec::with_capacity(total / (interval as usize))
    } else {
        Vec::new()
    };

    let mut i = 0;
    while !done(i) {
        let pending = zs.begin(None)?;

        std::thread::sleep(std::time::Duration::from_millis(interval));

        let snap = pending.snapshot()?;

        // Process and save the snapshot in another thread.
        let prefix = prefix.to_owned();
        let h = std::thread::spawn(move || serialize(snap, &prefix, i));
        handles.push(h);

        i += 1;
    }

    // Wait for all threads to finish draining
    for h in handles.drain(..) {
        let _ = h.join();
    }

    Ok(())
}

/// Serialize the snapshot to a file with the given name `prefix` and index `i`. The serialized
/// format is a compact binary format.
pub fn serialize(snap: Snapshot, prefix: &str, i: usize) -> Result<(), failure::Error> {
    let f = File::create(&format!("{}{:05}", prefix, i)).unwrap();
    let mut buf = BufWriter::new(f);

    let serialized = bincode::serialize(&snap)?;

    buf.write_all(&serialized)?;

    Ok(())
}

/// Deserialize the snapshot from the given file.
pub fn deserialize<P: AsRef<std::path::Path>>(file: P) -> Result<Snapshot, failure::Error> {
    let buf = std::fs::read(file)?;

    let deserialized = bincode::deserialize(&buf)?;

    Ok(deserialized)
}
