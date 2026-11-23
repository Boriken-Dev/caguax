//! The `caguax` command.

use std::process::ExitCode;

fn main() -> ExitCode {
    caguax::cli::main(std::env::args_os())
}
