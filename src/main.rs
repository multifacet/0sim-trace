//! A simple program that traces using zerosim-trace and outputs the results.

use tracing::ZerosimTracer;

mod tracing;

const PER_CPU_TRACE_BUFFER_SIZE: usize = 2 << 12;

fn main() -> Result<(), failure::Error> {
    let mut zs = ZerosimTracer::init(PER_CPU_TRACE_BUFFER_SIZE)?;

    let pending = zs.begin(None)?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    let snap = pending.snapshot();

    for (i, cpu) in snap.cpus().into_iter().enumerate() {
        for ev in cpu {
            println!("{} {:?}", i, ev);
        }
    }

    Ok(())
}
