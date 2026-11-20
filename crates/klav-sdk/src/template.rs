//! `{{ klav://… }}` templates (`klav inject`, the `inject_file` tool).

/// A piece of a template.
#[derive(Debug, PartialEq, Eq)]
pub enum Piece<'a> {
    /// Text copied as is.
    Text(&'a str),
    /// A reference to replace by its value.
    Reference(String),
}

/// Whether `value` is a full `klav://` reference.
pub fn is_reference(value: &str) -> bool {
    value.trim().starts_with("klav://")
}

/// Splits `template` into text and `{{ klav://… }}` references. Other
/// `{{ … }}` blocks (other template languages) are left alone.
pub fn parse(template: &str) -> Result<Vec<Piece<'_>>, String> {
    let mut pieces = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let inner = after[..end].trim();
        if is_reference(inner) {
            if start > 0 {
                pieces.push(Piece::Text(&rest[..start]));
            }
            // Names keep their spaces (`{{ klav://Mi bóveda/… }}`); a line
            // break or other control character is a typo, not a name.
            if inner.chars().any(char::is_control) {
                return Err(format!("invalid reference {inner:?} in the template"));
            }
            pieces.push(Piece::Reference(inner.to_owned()));
        } else {
            pieces.push(Piece::Text(&rest[..start + 2 + end + 2]));
        }
        rest = &after[end + 2..];
    }
    if !rest.is_empty() {
        pieces.push(Piece::Text(rest));
    }
    Ok(pieces)
}

/// The references of a template, in order.
pub fn references(pieces: &[Piece<'_>]) -> Vec<String> {
    pieces
        .iter()
        .filter_map(|p| match p {
            Piece::Reference(r) => Some(r.clone()),
            Piece::Text(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_replace_only_klav_references() {
        let pieces = parse("A={{ klav://V/P/I/f }}\nB={{ other }}\nC={{klav://V/P/J/g}}").unwrap();
        assert_eq!(
            pieces,
            vec![
                Piece::Text("A="),
                Piece::Reference("klav://V/P/I/f".into()),
                Piece::Text("\nB={{ other }}"),
                Piece::Text("\nC="),
                Piece::Reference("klav://V/P/J/g".into()),
            ]
        );
        assert_eq!(
            parse("no refs {{").unwrap(),
            vec![Piece::Text("no refs {{")]
        );
        assert!(parse("{{ klav://a\nb/c/d/e }}").is_err());
        assert!(parse("{{ klav://a\tb/c/d/e }}").is_err());
        assert_eq!(references(&pieces).len(), 2);
    }

    #[test]
    fn references_keep_spaces_and_accents() {
        let pieces =
            parse("K={{ klav://Mi bóveda/Café con leche/Banco Azul/password }}\n").unwrap();
        assert_eq!(
            references(&pieces),
            vec!["klav://Mi bóveda/Café con leche/Banco Azul/password".to_owned()]
        );
        // The encoded form older versions showed still works.
        let pieces = parse("K={{ klav://Mi%20b%C3%B3veda/P/Banco%20Azul/password }}").unwrap();
        assert_eq!(
            references(&pieces),
            vec!["klav://Mi%20b%C3%B3veda/P/Banco%20Azul/password".to_owned()]
        );
    }
}
