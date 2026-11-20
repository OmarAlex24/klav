//! The task file of `klav agent task request` (ADR 0021 §1): TOML or JSON
//! with the keys of [`TaskSpec`]. YAML is not accepted: `serde_yaml` is
//! deprecated and a task file is short and flat.

use std::path::Path;

use klav_core::task::TaskSpec;

use crate::error::{CliResult, usage};

/// The formats a task file may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Toml,
    Json,
}

/// The format of `path`, by extension: `.toml` or `.json`. Anything else is
/// rejected, YAML with its own reason.
fn format(path: &Path) -> CliResult<Format> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("toml") => Ok(Format::Toml),
        Some("json") => Ok(Format::Json),
        Some("yaml" | "yml") => Err(usage(
            "task files are TOML or JSON, not YAML: rename the keys into tarea.toml (task, reason, duration, [[access]] ref, permissions)",
        )),
        _ => Err(usage(format!(
            "{}: a task file ends in .toml or .json",
            path.display()
        ))),
    }
}

/// Parses `text` as a task in `format`, and checks it.
fn parse(text: &str, format: Format, name: &str) -> CliResult<TaskSpec> {
    let spec: TaskSpec = match format {
        Format::Toml => {
            toml::from_str(text).map_err(|e| usage(format!("{name}: invalid task file: {e}")))?
        }
        Format::Json => serde_json::from_str(text)
            .map_err(|e| usage(format!("{name}: invalid task file: {e}")))?,
    };
    spec.validate().map_err(|e| usage(format!("{name}: {e}")))?;
    Ok(spec)
}

/// Reads and checks a task file (`-` reads JSON from stdin).
pub(crate) fn read(path: &Path) -> CliResult<TaskSpec> {
    if path == Path::new("-") {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .map_err(|e| usage(format!("cannot read the task from stdin: {e}")))?;
        return parse(&text, Format::Json, "stdin");
    }
    let format = format(path)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
    parse(&text, format, &path.display().to_string())
}

#[cfg(test)]
mod tests {
    use klav_core::policy::Permission;

    use super::*;

    const TOML: &str = r#"
task = "Descargar las facturas de octubre"
reason = "Conciliar los gastos del mes"
duration = "2h"

[[access]]
ref = "Facturas/AWS"
permissions = ["fill", "totp"]

[[access]]
ref = "Facturas/Telmex"
permissions = ["fill"]
domain = "telmex.com"
"#;

    #[test]
    fn the_adr_example_parses_from_toml_and_json() {
        let spec = parse(TOML, Format::Toml, "tarea.toml").unwrap();
        assert_eq!(spec.task, "Descargar las facturas de octubre");
        assert_eq!(spec.duration, "2h");
        assert_eq!(spec.access.len(), 2);
        assert_eq!(spec.access[0].reference, "Facturas/AWS");
        assert_eq!(
            spec.access[0].permissions,
            vec![Permission::Fill, Permission::Totp]
        );
        assert_eq!(spec.access[1].domain.as_deref(), Some("telmex.com"));
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(parse(&json, Format::Json, "tarea.json").unwrap(), spec);
    }

    #[test]
    fn formats_by_extension() {
        assert_eq!(format(Path::new("tarea.toml")).unwrap(), Format::Toml);
        assert_eq!(format(Path::new("T.JSON")).unwrap(), Format::Json);
        for bad in ["tarea.yaml", "tarea.yml", "tarea", "tarea.txt"] {
            assert!(format(Path::new(bad)).is_err(), "{bad}");
        }
        let yaml = format(Path::new("tarea.yaml"))
            .unwrap_err()
            .message()
            .unwrap();
        assert!(yaml.contains("not YAML"), "{yaml}");
    }

    #[test]
    fn bad_tasks_are_rejected_with_the_reason() {
        let reveal = TOML.replace(r#"["fill", "totp"]"#, r#"["fill", "reveal"]"#);
        let err = parse(&reveal, Format::Toml, "t.toml")
            .unwrap_err()
            .message()
            .unwrap();
        assert!(err.contains("`reveal` never goes in a task"), "{err}");
        for (from, to) in [
            (r#"["fill", "totp"]"#, r#"["delete"]"#),
            (r#"["fill", "totp"]"#, r#"["list"]"#),
            (r#"["fill", "totp"]"#, r#"["create"]"#),
            (r#"["fill", "totp"]"#, r#"["fly"]"#),
            (r#"["fill", "totp"]"#, "[]"),
            (r#"duration = "2h""#, r#"duration = "1m""#),
            (r#"duration = "2h""#, r#"duration = "25h""#),
            (r#"duration = "2h""#, r#"duration = "2 hours""#),
            (
                r#"reason = "Conciliar los gastos del mes""#,
                r#"reason = """#,
            ),
            (
                "[[access]]\nref = \"Facturas/AWS\"",
                "[[access]]\nref = \"Facturas/AWS\"\nfoo = 1",
            ),
        ] {
            let text = TOML.replace(from, to);
            assert_ne!(text, TOML, "{from}");
            assert!(parse(&text, Format::Toml, "t.toml").is_err(), "{to}");
        }
        let long = TOML.replace("Descargar las facturas de octubre", &"x".repeat(121));
        assert!(parse(&long, Format::Toml, "t.toml").is_err());
        let none = "task = \"a\"\nreason = \"b\"\nduration = \"1h\"\naccess = []\n";
        assert!(parse(none, Format::Toml, "t.toml").is_err());
    }
}
