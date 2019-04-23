//! A simple program that traces using zerosim-trace and outputs the results.

mod analysis;
mod record;
mod tracing;

use clap::App;

fn main() -> Result<(), failure::Error> {
    let matches = App::new("zerosim_trace")
        .subcommand(record::cli_args())
        .subcommand(analysis::cli_args())
        .setting(clap::AppSettings::SubcommandRequired)
        .setting(clap::AppSettings::DisableVersion)
        .get_matches();

    match matches.subcommand() {
        ("trace", Some(sub_m)) => record::record(sub_m),
        ("analyze", Some(sub_m)) => analysis::analyze(sub_m),

        _ => unreachable!(),
    }
}
