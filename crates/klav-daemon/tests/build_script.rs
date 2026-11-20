//! The checks `build.rs` makes on `KLAV_BUILD_COMMIT` and
//! `KLAV_BUILD_COMMIT_TIME`, without running a build: the script is
//! compiled here as a module and only its parser is called.

// `main` and its helpers aren't called here, and `println!` is how a build
// script talks to cargo.
#[allow(dead_code, clippy::print_stdout)]
#[path = "../build.rs"]
mod build_script;

use build_script::parse_env;

const COMMIT: &str = "ce4fa50990924bf17d349b752ad8020ff6b3a9ff";

fn time_of(time: &str) -> Result<u64, String> {
    parse_env(Some(COMMIT), Some(time)).map(|identity| identity.expect("both set").time)
}

#[test]
fn the_time_is_decimal_digits_only() {
    for (text, secs) in [
        ("0", 0),
        ("1794593822", 1_794_593_822),
        ("01794593822", 1_794_593_822),
        ("253402300799", 253_402_300_799),
    ] {
        assert_eq!(time_of(text), Ok(secs), "{text}");
    }
    for text in [
        "+1794593822",
        "-1",
        " 1794593822",
        "1794593822 ",
        "1794593822\n",
        "1_794_593_822",
        "0x6af6b11e",
        "1.5",
        "١٧٩٤",
        "99999999999999999999999",
    ] {
        let error = time_of(text).expect_err(text);
        assert!(error.contains("must be Unix seconds"), "{text}: {error}");
    }
    let error = time_of("253402300800").expect_err("past the cap");
    assert!(error.contains("must be at most 253402300799"), "{error}");
}

#[test]
fn the_commit_is_the_full_lowercase_hash() {
    assert_eq!(
        parse_env(Some(COMMIT), Some("1")).map(|i| i.map(|i| i.commit)),
        Ok(Some(COMMIT.to_owned()))
    );
    for commit in [
        &COMMIT[..12],
        &COMMIT.to_uppercase(),
        &format!("{COMMIT}0"),
        &format!("+{}", &COMMIT[1..]),
        "xyz",
    ] {
        let error = parse_env(Some(commit), Some("1")).err().expect(commit);
        assert!(
            error.contains("40-digit lowercase hex"),
            "{commit}: {error}"
        );
    }
}

#[test]
fn both_or_neither_and_empty_is_unset() {
    assert!(matches!(parse_env(None, None), Ok(None)));
    assert!(matches!(parse_env(Some(""), Some("")), Ok(None)));
    for (commit, time) in [
        (Some(COMMIT), None),
        (None, Some("1")),
        (Some(COMMIT), Some("")),
    ] {
        let error = parse_env(commit, time).err().expect("only one set");
        assert!(error.contains("set both"), "{error}");
    }
}
