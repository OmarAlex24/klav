//! `klav-forward`, the sandbox forwarder (ADR 0036 §5, §6).
//!
//! It holds no vault code: it cannot decrypt an item, open a grant or sign
//! as an agent. What it has is the sandbox's one-time package (until its
//! claim), the pin of the proxy and a channel key that never leaves its
//! process.
//!
//! The Klav skill it installs (`skill`, from `skill/SKILL.md` at the root of
//! the repository) is a module of the binary, not of this library:
//! `klav-proxy` links this library, and its image builds from `crates/`
//! alone, so a change to the skill never rebuilds the proxy.

pub mod channel;
pub mod forward;
pub mod http;
pub mod setup;

#[cfg(test)]
mod channel_tests;

#[cfg(test)]
mod test_dir;
#[cfg(test)]
pub(crate) use test_dir::TestDir;

#[cfg(test)]
mod tests {
    /// No vault code (ADR 0036 §5): of Klav's crates, only `klav-core`,
    /// whose own dependencies are no Klav crate.
    #[test]
    fn it_depends_on_no_klav_crate_but_the_core() {
        for (crate_dir, allowed) in [(".", &["klav-core"][..]), ("../klav-core", &[][..])] {
            let manifest = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(crate_dir)
                    .join("Cargo.toml"),
            )
            .expect("manifest");
            let deps = manifest
                .split("\n[")
                .find(|s| s.starts_with("dependencies]"))
                .expect("dependencies");
            let klav: Vec<&str> = deps
                .lines()
                .filter_map(|l| l.split(['=', '.', ' ']).next())
                .filter(|name| name.starts_with("klav-"))
                .collect();
            assert_eq!(klav, allowed, "{crate_dir}");
        }
    }
}
