//! DMC Simulator CLI executable.
//!
//! Supported commands:
//!   cargo run -p dmc-simulator -- run foundation
//!   cargo run -p dmc-simulator -- run all
//!
//! Flags:
//!   --json       Emit machine-readable JSON directly to stdout
//!   --help, -h   Display this help message

use std::env;
use std::process;

use dmc_simulator::{execute_all, execute_foundation};

fn print_usage() {
    eprintln!(
        "DMC Simulation Foundation Runtime\n\n\
         Usage:\n\
           dmc-simulator run foundation [--json]\n\
           dmc-simulator run all [--json]\n\
           dmc-simulator --help\n\n\
         Commands:\n\
           run foundation    Executes the deterministic Engineering Department scenario\n\
           run all           Executes foundation and all 9 security regression scenarios\n\n\
         Flags:\n\
           --json            Emit machine-readable JSON output to stdout\n\
           --help, -h        Display this help message\n"
    );
}

/// Parses CLI arguments in any order and dispatches execution.
pub fn parse_and_run(args: &[String]) -> i32 {
    let mut json_mode = false;
    let mut positional = Vec::new();

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--json" => json_mode = true,
            "--help" | "-h" | "help" => {
                print_usage();
                return 0;
            }
            _ => positional.push(arg.as_str()),
        }
    }

    if positional.is_empty() {
        print_usage();
        return 1;
    }

    match positional[0] {
        "run" => {
            if positional.len() < 2 {
                eprintln!("Error: 'run' subcommand requires a target ('foundation' or 'all').\n");
                print_usage();
                return 1;
            }
            match positional[1] {
                "foundation" => execute_foundation(json_mode),
                "all" => execute_all(json_mode),
                other => {
                    eprintln!(
                        "Error: Unknown run target '{other}'. Expected 'foundation' or 'all'.\n"
                    );
                    print_usage();
                    1
                }
            }
        }
        other => {
            eprintln!("Error: Unknown command '{other}'.\n");
            print_usage();
            1
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let exit_code = parse_and_run(&args);
    process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_flags_exit_zero() {
        let args1 = vec!["dmc-simulator".into(), "--help".into()];
        assert_eq!(parse_and_run(&args1), 0);

        let args2 = vec!["dmc-simulator".into(), "-h".into()];
        assert_eq!(parse_and_run(&args2), 0);
    }

    #[test]
    fn test_missing_and_invalid_args_exit_one() {
        let empty = vec!["dmc-simulator".into()];
        assert_eq!(parse_and_run(&empty), 1);

        let run_missing_target = vec!["dmc-simulator".into(), "run".into()];
        assert_eq!(parse_and_run(&run_missing_target), 1);

        let run_invalid_target = vec!["dmc-simulator".into(), "run".into(), "invalid".into()];
        assert_eq!(parse_and_run(&run_invalid_target), 1);

        let unknown_cmd = vec!["dmc-simulator".into(), "deploy".into()];
        assert_eq!(parse_and_run(&unknown_cmd), 1);
    }

    #[test]
    fn test_flag_positional_flexibility() {
        // Flag after target
        let args_normal = vec![
            "dmc-simulator".into(),
            "run".into(),
            "foundation".into(),
            "--json".into(),
        ];
        assert_eq!(parse_and_run(&args_normal), 0);

        // Flag before command
        let args_before = vec![
            "dmc-simulator".into(),
            "--json".into(),
            "run".into(),
            "foundation".into(),
        ];
        assert_eq!(parse_and_run(&args_before), 0);

        // Flag between run and target
        let args_between = vec![
            "dmc-simulator".into(),
            "run".into(),
            "--json".into(),
            "foundation".into(),
        ];
        assert_eq!(parse_and_run(&args_between), 0);
    }
}
