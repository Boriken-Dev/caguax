//! Every command in the README's command-line section runs as written, against the README's own
//! configuration.
#![cfg(feature = "cli")]

use std::process::{Command, Stdio};

const README: &str = include_str!("../README.md");

/// The fenced block of `language` that follows the heading `heading`.
fn block(heading: &str, language: &str) -> String {
    let after = README
        .split(&format!("\n{heading}\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("no {heading} section"));
    let fence = format!("```{language}\n");
    let start = after
        .find(&fence)
        .unwrap_or_else(|| panic!("no {language} block under {heading}"))
        + fence.len();
    let end = after[start..].find("```").unwrap() + start;
    after[start..end].to_owned()
}

#[test]
fn the_commands_in_the_readme_run_as_written() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("caguax.cfg"),
        block("## Configuration", "toml"),
    )
    .unwrap();
    let commands = block("## Command line", "sh");
    let mut ran = 0;
    for line in commands.lines().filter(|line| !line.trim().is_empty()) {
        let arguments: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(arguments[0], "caguax", "{line}");
        let output = Command::new(env!("CARGO_BIN_EXE_caguax"))
            .args(&arguments[1..])
            .current_dir(directory.path())
            .env_remove("CAGUAX_CONFIG")
            .env_remove("CAGUAX_LOG")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "`{line}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "`{line}` printed nothing");
        ran += 1;
    }
    assert_eq!(ran, 6);
    assert!(directory.path().join("pki/ca.pem").exists());
}
