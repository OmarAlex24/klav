//! Printing. Results go to stdout; messages and warnings go to stderr so
//! that `--json` output and revealed values can be piped.

use std::io::Write;

use serde::Serialize;

use crate::error::CliResult;

pub(crate) fn json<T: Serialize + ?Sized>(value: &T) -> CliResult<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)
        .map_err(|e| crate::error::CliError::Other(e.to_string()))?;
    writeln!(out)?;
    Ok(())
}

/// `value` as one line of JSON on stdout (what a program reads with one
/// `read_line`).
pub(crate) fn json_line<T: Serialize + ?Sized>(value: &T) -> CliResult<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)
        .map_err(|e| crate::error::CliError::Other(e.to_string()))?;
    writeln!(out)?;
    Ok(())
}

pub(crate) fn line(text: &str) {
    println!("{text}");
}

pub(crate) fn info(text: &str) {
    eprintln!("{text}");
}

pub(crate) fn warn(text: &str) {
    eprintln!("warning: {text}");
}

/// Prints rows as aligned columns.
pub(crate) fn table(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let render = |cells: Vec<String>| {
        let last = cells.len().saturating_sub(1);
        cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c
                } else {
                    format!("{c:<width$}", width = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    line(&render(header.iter().map(|h| (*h).to_owned()).collect()));
    for row in rows {
        line(&render(row.clone()));
    }
}
