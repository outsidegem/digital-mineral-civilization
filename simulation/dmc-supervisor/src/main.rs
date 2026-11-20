//! Entry point for the Persistent Simulation Supervisor (M1.2)

mod cli;
mod config;
mod envelope;
mod log;
mod persistence;
mod recovery;
mod resources;
mod runner;
mod uuid_util;

use crate::cli::Cli;
use crate::config::Config;
use clap::Parser;
use std::process;

fn main() {
    let cli = Cli::parse();
    let config = Config::from_cli(cli);
    if let Err(e) = runner::run_supervisor(config) {
        eprintln!("Supervisor fatal error: {e}");
        process::exit(1);
    }
}
