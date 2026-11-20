//! `klav proxy grant ITEM --preset NAME` (ADR 0036 §7, layer 10): a
//! provider's profile as a starting point. It only fills in the
//! [`ProxyCredentialSpec`] the explicit flags would: each flag the person
//! gives replaces that part of it, the confirmation shows the result
//! before presence, and the grant signs exactly that. Nothing of a format,
//! `klavd` or the server changes: a profile made with a preset is the one
//! the same explicit flags make.

use klav_client::proxy_admin::{MAX_GRANT_METHODS, ProxyCredentialSpec, credential_profile};
use klav_core::ids::ItemId;
use klav_core::policy::Effect;

use super::sandbox::NORTHFLANK_PROFILE;
use crate::cli::ProxyGrantArgs;
use crate::error::{CliResult, usage};

/// A provider's profile for mode (a), the base URL.
#[derive(Debug)]
pub(crate) struct Preset {
    /// Its name on the command line.
    pub(crate) name: &'static str,
    /// The profile it makes.
    pub(crate) profile: &'static str,
    /// Where calls go.
    pub(crate) upstream: &'static str,
    /// The header the value goes in.
    pub(crate) header: &'static str,
    /// Text before the value.
    pub(crate) prefix: &'static str,
    /// Methods that go through.
    pub(crate) methods: &'static [&'static str],
    /// Methods that ask the person first.
    pub(crate) ask_methods: &'static [&'static str],
    /// Path prefixes (`/`: every path).
    pub(crate) path_prefixes: &'static [&'static str],
    /// What the person reads about it before the confirmation.
    pub(crate) note: &'static str,
}

/// Northflank (ADR 0036 §7, with Omar's decision of 2026-11-16): its API
/// token in `Authorization: Bearer`, every path of `api.northflank.com`.
/// `GET`, `POST` and `PATCH` go through and `DELETE` asks: the four
/// methods one credential may carry ([`MAX_GRANT_METHODS`]), so no `PUT`.
/// Role and token changes are not told apart by path.
pub(crate) const NORTHFLANK: Preset = Preset {
    name: "northflank",
    profile: NORTHFLANK_PROFILE,
    upstream: "https://api.northflank.com",
    header: "authorization",
    prefix: "Bearer ",
    methods: &["GET", "POST", "PATCH"],
    ask_methods: &["DELETE"],
    path_prefixes: &["/"],
    note: "The northflank preset: your API token goes in `Authorization: Bearer` to every path of api.northflank.com. GET, POST and PATCH go through; each DELETE asks you first; PUT and every other method are refused. Nothing in it guards role or token changes by path: a POST or PATCH that changes a role or a token goes through like any other call. A flag you add replaces that part of the preset, and the profile below is what you sign.",
};

/// The presets `--preset` takes.
const PRESETS: &[&Preset] = &[&NORTHFLANK];

/// Presets of ADR 0036 §7 whose mode the proxy does not have yet: no
/// partial profile for them.
const NOT_YET: &[(&str, &str)] = &[
    (
        "railway",
        "mode (b), `HTTPS_PROXY` with a CA of the sandbox, which Klav's credential proxy does not have yet",
    ),
    (
        "maple",
        "mode (c), the MCP gateway, which Klav's credential proxy does not have yet",
    ),
];

impl Preset {
    /// The spec the preset makes on its own, with no flag on top.
    fn own_spec(&self) -> ProxyCredentialSpec {
        let list = |l: &[&str]| l.iter().map(|m| (*m).to_owned()).collect();
        ProxyCredentialSpec {
            profile: self.profile.to_owned(),
            upstream: self.upstream.to_owned(),
            header: self.header.to_owned(),
            prefix: self.prefix.to_owned(),
            field: None,
            methods: list(self.methods),
            path_prefixes: list(self.path_prefixes),
            ask: false,
            ask_methods: list(self.ask_methods),
            rate_per_minute: None,
        }
    }
}

/// What the person reads before the profile, derived from the spec that
/// is signed, never from which flags were typed: the preset's full note
/// only when `spec` signs exactly what the preset alone signs; otherwise
/// one line saying the flags changed it, plus the sentence on role and
/// token changes whenever the profile lets `POST` or `PATCH` through or
/// asks for them.
fn note_for(preset: &Preset, spec: &ProxyCredentialSpec) -> String {
    // Any item will do: both sides get the same one.
    let item = ItemId::from_bytes([0; 16]);
    let Ok((profile, rules)) = credential_profile(item, spec) else {
        // The grant refuses this spec right after; say nothing about it.
        return changed_line(preset);
    };
    if credential_profile(item, &preset.own_spec())
        .is_ok_and(|(own_profile, own_rules)| own_profile == profile && own_rules == rules)
    {
        return preset.note.to_owned();
    }
    let reaches = |method: &str| {
        rules.iter().any(|r| {
            matches!(r.effect, Effect::Allow | Effect::Ask)
                && r.scope.methods.iter().any(|m| m.as_str() == method)
        })
    };
    let changes = match (reaches("POST"), reaches("PATCH")) {
        (true, true) => "POST or PATCH",
        (true, false) => "POST",
        (false, true) => "PATCH",
        (false, false) => return changed_line(preset),
    };
    format!(
        "{} Nothing in it tells role or token changes apart: a {changes} that changes a role or a token, on the paths below, is treated like any other call with that method.",
        changed_line(preset)
    )
}

/// The note for a preset the flags changed: it says nothing the flags
/// could have made false.
fn changed_line(preset: &Preset) -> String {
    format!(
        "The {} preset, changed by your flags: the profile below is what you sign.",
        preset.name
    )
}

/// The preset called `name`, or why there is none.
fn preset(name: &str) -> CliResult<&'static Preset> {
    let wanted = name.trim().to_ascii_lowercase();
    if let Some(p) = PRESETS.iter().find(|p| p.name == wanted) {
        return Ok(p);
    }
    if let Some((_, mode)) = NOT_YET.iter().find(|(n, _)| *n == wanted) {
        return Err(usage(format!(
            "the {wanted} preset needs {mode}: nothing was granted. Mode (a), a base URL, is the only one so far"
        )));
    }
    let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
    Err(usage(format!(
        "there is no preset {:?}: the presets are {} (railway and maple come with the proxy's later modes)",
        name,
        names.join(", ")
    )))
}

/// The spec `klav proxy grant` previews and signs: the preset's parts, each
/// replaced by the flag the person gave for it. Without a preset, the flags
/// alone (clap requires `--profile`, `--upstream` and `--header` then).
/// With one, also the note to print before the profile, derived from that
/// final spec.
pub(crate) fn grant_spec(
    args: &ProxyGrantArgs,
) -> CliResult<(ProxyCredentialSpec, Option<String>)> {
    let preset = args.preset.as_deref().map(preset).transpose()?;
    let text = |given: &Option<String>, from: fn(&Preset) -> &'static str, flag: &str| {
        given
            .clone()
            .or_else(|| preset.map(|p| from(p).to_owned()))
            .ok_or_else(|| usage(format!("{flag} is required without --preset")))
    };
    let list = |given: &[String], from: fn(&Preset) -> &'static [&'static str]| {
        if given.is_empty() {
            preset.map_or_else(Vec::new, |p| {
                from(p).iter().map(|m| (*m).to_owned()).collect()
            })
        } else {
            given.to_vec()
        }
    };
    let spec = ProxyCredentialSpec {
        profile: text(&args.profile, |p| p.profile, "--profile")?,
        upstream: text(&args.upstream, |p| p.upstream, "--upstream")?,
        header: text(&args.header, |p| p.header, "--header")?,
        prefix: args
            .prefix
            .clone()
            .or_else(|| preset.map(|p| p.prefix.to_owned()))
            .unwrap_or_default(),
        field: args.field.clone(),
        methods: list(&args.methods, |p| p.methods),
        path_prefixes: list(&args.path_prefixes, |p| p.path_prefixes),
        ask: args.ask,
        ask_methods: list(&args.ask_methods, |p| p.ask_methods),
        rate_per_minute: args.rate,
    };
    let Some(preset) = preset else {
        return Ok((spec, None));
    };
    within_method_limit(&spec, preset)?;
    let note = note_for(preset, &spec);
    Ok((spec, Some(note)))
}

/// A preset plus the flags may name more methods than one credential
/// carries: refused, naming the limit and where each method came from,
/// never cut to fit.
fn within_method_limit(spec: &ProxyCredentialSpec, preset: &Preset) -> CliResult<()> {
    let mut every: Vec<String> = spec
        .methods
        .iter()
        .chain(&spec.ask_methods)
        .map(|m| m.trim().to_ascii_uppercase())
        .collect();
    every.sort();
    every.dedup();
    if every.len() <= MAX_GRANT_METHODS {
        return Ok(());
    }
    Err(usage(format!(
        "with the {name} preset this credential would carry {count} HTTP methods ({list}), and one credential carries at most {MAX_GRANT_METHODS}, so the confirmation can show them all. The preset lets {allowed} through and asks for {asked}; --method replaces the ones that go through and --ask-method the ones that ask. Nothing was granted: name at most {MAX_GRANT_METHODS} in all",
        name = preset.name,
        count = every.len(),
        list = every.join(", "),
        allowed = preset.methods.join(", "),
        asked = preset.ask_methods.join(", "),
    )))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use klav_core::ids::{ItemId, ProjectId, VaultId};
    use klav_core::policy::{Effect, Permission, Policy, Request, Target, evaluate};

    use super::*;
    use crate::cli::{Cli, Command, ProxyCommand};
    use crate::commands::sandbox::NORTHFLANK_LOGIN_CHECK;
    use crate::error::CliError;

    fn args(extra: &[&str]) -> ProxyGrantArgs {
        let mut argv = vec!["klav", "proxy", "grant", "Northflank"];
        argv.extend_from_slice(extra);
        match Cli::try_parse_from(argv).expect("parses").command {
            Command::Proxy(ProxyCommand::Grant(a)) => *a,
            other => panic!("{other:?}"),
        }
    }

    fn spec(extra: &[&str]) -> ProxyCredentialSpec {
        grant_spec(&args(extra)).expect("spec").0
    }

    fn refused(extra: &[&str]) -> String {
        match grant_spec(&args(extra)) {
            Err(CliError::Usage(m)) => m,
            other => panic!("{other:?}"),
        }
    }

    /// The bytes the grant signs for this spec: its profile and rules.
    fn signed(spec: &ProxyCredentialSpec, item: ItemId) -> Vec<u8> {
        let (profile, rules) =
            klav_client::proxy_admin::credential_profile(item, spec).expect("valid");
        serde_json::to_vec(&(profile, rules)).expect("json")
    }

    /// The explicit flags the northflank preset stands for.
    const NORTHFLANK_FLAGS: &[&str] = &[
        "--profile",
        "northflank",
        "--upstream",
        "https://api.northflank.com",
        "--header",
        "authorization",
        "--prefix",
        "Bearer ",
        "--method",
        "GET,POST,PATCH",
        "--ask-method",
        "DELETE",
        "--path-prefix",
        "/",
    ];

    /// Safe with older clients: a profile made with the preset is the
    /// same profile and rules, byte for byte, as the explicit flags make,
    /// so an older `klav`, `klavd`, proxy or server sees nothing new.
    #[test]
    fn the_preset_signs_the_bytes_its_explicit_flags_sign() {
        let item = ItemId::generate();
        assert_eq!(
            signed(&spec(&["--preset", "northflank"]), item),
            signed(&spec(NORTHFLANK_FLAGS), item)
        );
    }

    /// The profile lets `northflank login`'s check through without an
    /// approval step, under the name the setup line uses: both read where
    /// `klav sandbox start` defines them.
    #[test]
    fn the_northflank_preset_lets_the_setup_lines_login_through() {
        let item = ItemId::generate();
        let preset = spec(&["--preset", "northflank"]);
        assert_eq!(preset.profile, NORTHFLANK_PROFILE);
        let (profile, rules) =
            klav_client::proxy_admin::credential_profile(item, &preset).expect("valid");
        let (host, _) = profile.upstream_host().expect("host");
        let policy = Policy {
            rules,
            expires_at: None,
        };
        let decide = |method: &str, path: &str| {
            evaluate(
                &policy,
                &Request {
                    permission: Permission::Proxy,
                    vault: Target {
                        id: VaultId::generate(),
                        name: String::new(),
                    },
                    project: Target {
                        id: ProjectId::generate(),
                        name: String::new(),
                    },
                    tags: Vec::new(),
                    domain: Some(host.clone()),
                    item: Some(item),
                    method: Some(method.to_owned()),
                    path: Some(path.to_owned()),
                    now: 1,
                },
            )
            .effect
        };
        let (method, path) = NORTHFLANK_LOGIN_CHECK;
        assert_eq!(decide(method, path), Effect::Allow, "{method} {path}");
        for method in ["GET", "POST", "PATCH"] {
            assert_eq!(decide(method, "/v1/projects"), Effect::Allow, "{method}");
        }
        assert_eq!(decide("DELETE", "/v1/projects/p"), Effect::Ask);
        assert_eq!(decide("PUT", "/v1/projects/p"), Effect::Deny, "no PUT");
    }

    /// Each flag replaces its part of the preset, and only that part.
    #[test]
    fn a_flag_replaces_its_part_of_the_preset() {
        let s = spec(&[
            "--preset",
            "northflank",
            "--profile",
            "nf",
            "--method",
            "GET",
            "--path-prefix",
            "/v1",
            "--rate",
            "30",
        ]);
        assert_eq!(s.profile, "nf");
        assert_eq!(s.methods, ["GET"]);
        assert_eq!(s.ask_methods, ["DELETE"], "kept from the preset");
        assert_eq!(s.path_prefixes, ["/v1"]);
        assert_eq!(s.upstream, "https://api.northflank.com");
        assert_eq!(s.prefix, "Bearer ");
        assert_eq!(s.rate_per_minute, Some(30));
        assert_eq!(spec(&["--preset", "northflank", "--prefix", ""]).prefix, "");
    }

    /// A fifth method is refused with the limit named, never dropped.
    #[test]
    fn a_fifth_method_is_refused_with_the_limit() {
        let m = refused(&["--preset", "northflank", "--method", "GET,POST,PATCH,PUT"]);
        assert!(
            m.contains("5 HTTP methods (DELETE, GET, PATCH, POST, PUT)"),
            "{m}"
        );
        assert!(m.contains(&format!("at most {MAX_GRANT_METHODS}")), "{m}");
        assert!(m.contains("asks for DELETE"), "{m}");
        let m = refused(&["--preset", "northflank", "--ask-method", "DELETE,PUT"]);
        assert!(m.contains("5 HTTP methods"), "{m}");
        // Four in all is fine: PUT instead of PATCH.
        assert_eq!(
            spec(&["--preset", "northflank", "--method", "GET,POST,PUT"]).methods,
            ["GET", "POST", "PUT"]
        );
    }

    /// Railway and Maple need modes the proxy lacks; an unknown name lists
    /// the presets. Neither makes a profile.
    #[test]
    fn presets_without_their_mode_and_unknown_ones_are_refused() {
        let m = refused(&["--preset", "railway"]);
        assert!(
            m.contains("mode (b)") && m.contains("does not have yet"),
            "{m}"
        );
        let m = refused(&["--preset", "maple"]);
        assert!(
            m.contains("mode (c)") && m.contains("does not have yet"),
            "{m}"
        );
        let m = refused(&["--preset", "heroku"]);
        assert!(m.contains(r#"no preset "heroku""#), "{m}");
        assert!(m.contains("the presets are northflank"), "{m}");
        // Without a preset, the three flags stay required.
        let argv = [
            "klav",
            "proxy",
            "grant",
            "X",
            "--profile",
            "p",
            "--upstream",
            "https://h",
        ];
        assert!(Cli::try_parse_from(argv).is_err());
    }

    /// The note printed for these flags.
    fn note(extra: &[&str]) -> String {
        grant_spec(&args(extra)).expect("spec").1.expect("a preset")
    }

    const ROLES: &str = "that changes a role or a token";

    /// The unchanged preset prints its full note, also when the flags typed
    /// only restate it: what counts is the profile signed.
    #[test]
    fn the_unchanged_preset_prints_its_full_note() {
        let mut restated = vec!["--preset", "northflank"];
        restated.extend_from_slice(NORTHFLANK_FLAGS);
        for flags in [
            &["--preset", "northflank"][..],
            &["--preset", "northflank", "--method", "patch,get,post,get"],
            &restated,
        ] {
            let n = note(flags);
            assert_eq!(n, NORTHFLANK.note, "{flags:?}");
            assert!(n.contains("PUT and every other method are refused"), "{n}");
            assert!(
                n.contains("Nothing in it guards role or token changes by path"),
                "{n}"
            );
        }
        assert!(
            grant_spec(&args(NORTHFLANK_FLAGS))
                .expect("spec")
                .1
                .is_none()
        );
    }

    /// Flags that change the profile get one line instead of the note,
    /// and it never says PUT is refused when PUT goes through.
    #[test]
    fn a_changed_preset_never_claims_what_the_flags_undid() {
        let n = note(&["--preset", "northflank", "--method", "GET,POST,PUT"]);
        assert!(
            n.starts_with(
                "The northflank preset, changed by your flags: the profile below is what you sign."
            ),
            "{n}"
        );
        assert!(!n.contains("PUT") && !n.contains("refused"), "{n}");
        assert!(n.contains(&format!("a POST {ROLES}")), "{n}");
    }

    /// The sentence on role and token changes stays while the profile lets
    /// POST or PATCH through or asks for them, and goes when neither can.
    #[test]
    fn the_role_sentence_follows_post_and_patch() {
        for (flags, which) in [
            (&["--path-prefix", "/v1"][..], "POST or PATCH"),
            (&["--ask"], "POST or PATCH"),
            (&["--rate", "30"], "POST or PATCH"),
            (&["--method", "GET,PATCH"], "PATCH"),
            (&["--method", "GET", "--ask-method", "post"], "POST"),
        ] {
            let mut argv = vec!["--preset", "northflank"];
            argv.extend_from_slice(flags);
            let n = note(&argv);
            assert!(
                n.starts_with("The northflank preset, changed by your flags"),
                "{n}"
            );
            assert!(n.contains(&format!("a {which} {ROLES}")), "{flags:?}: {n}");
        }
        let n = note(&["--preset", "northflank", "--method", "GET"]);
        assert_eq!(
            n,
            "The northflank preset, changed by your flags: the profile below is what you sign."
        );
    }
}
