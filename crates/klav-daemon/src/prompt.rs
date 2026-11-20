//! The texts of the Touch ID prompt.
//!
//! macOS writes the prompt as "<process> is trying to <reason>." (in
//! Spanish, "<process> está intentando <reason>."), in the first of the
//! person's preferred languages. Every reason here is that predicate: it
//! starts in lower case, has no final period, and is written in the same
//! language as the rest of the prompt ([`Lang::current`]).
//!
//! Each one says who asks for what, on which item, without IDs. Names
//! from outside (the agent's name, which it picks itself, and item titles,
//! which can come from an import) go through [`clean`] and between quotes.
//! What the agent writes freely (its `reason`, a task's title, the site it
//! claims) never reaches the prompt. [`Source`] adds which program the
//! request came through, from the kernel's view of the socket's peer.

use std::path::Path;

use klav_client::grant_change::{ChangeLine, ChangeWhat};
use klav_core::policy::{Effect, Permission};

/// Longest name shown, in characters (LocalAuthentication cuts long
/// reasons).
pub(crate) const MAX_NAME: usize = 40;
/// Longest e-mail address shown.
const MAX_EMAIL: usize = 60;
/// Granted projects listed by name before "and N more".
const MAX_PLACES: usize = 2;
/// What widens, listed before "and N more changes" (ADR 0033, amendment of
/// 2026-11-10, F4): the sheet already showed every line.
const MAX_WIDENING: usize = 3;

/// The language of the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Es,
}

impl Lang {
    /// Spanish for any `es` tag (`es`, `es-MX`, `es_419`…), English
    /// otherwise.
    pub(crate) fn from_tag(tag: &str) -> Lang {
        let tag = tag.trim().to_ascii_lowercase();
        match tag.strip_prefix("es") {
            Some(rest) if rest.is_empty() || rest.starts_with(['-', '_']) => Lang::Es,
            _ => Lang::En,
        }
    }

    /// The language macOS shows the prompt in now: the person's first
    /// preferred language. English without one (or off macOS).
    pub(crate) fn current() -> Lang {
        klav_touchid::preferred_language().map_or(Lang::En, |tag| Lang::from_tag(&tag))
    }

    fn quote(self, name: &str) -> String {
        match self {
            Lang::En => format!("“{name}”"),
            Lang::Es => format!("«{name}»"),
        }
    }
}

/// The program a request came through, as the kernel reports the
/// socket's peer. A hint for the person, not a check: any program of the
/// same user can start `klav-native-host` or `klav`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    /// `klav-native-host`: the browser extension.
    Browser,
    /// `klav`: the command line.
    Terminal,
    /// The Mac app (`Klav.app/Contents/MacOS/Klav`).
    App,
}

impl Source {
    /// The source of a peer whose executable is `peer` (symbolic links
    /// resolved). `klavd_dir` is where this `klavd` lives, also resolved.
    /// `None` for anything else.
    pub(crate) fn of_executable(peer: &Path, klavd_dir: Option<&Path>) -> Option<Source> {
        let name = peer.file_name()?.to_str()?;
        let dir = peer.parent()?;
        match name {
            // The host this klavd ships with: next to it, or in the Mac
            // app's helpers.
            "klav-native-host" if klavd_dir == Some(dir) || in_app(dir, "Helpers") => {
                Some(Source::Browser)
            }
            "klav" => Some(Source::Terminal),
            "Klav" if in_app(dir, "MacOS") => Some(Source::App),
            _ => None,
        }
    }

    /// For an unlock: "for your browser".
    fn unlock_for(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Source::Browser, Lang::En) => "for your browser",
            (Source::Terminal, Lang::En) => "for the terminal",
            (Source::App, Lang::En) => "for the Klav app",
            (Source::Browser, Lang::Es) => "para tu navegador",
            (Source::Terminal, Lang::Es) => "para la terminal",
            (Source::App, Lang::Es) => "para la app de Klav",
        }
    }

    /// For a decision: "from your browser".
    pub(crate) fn decided_from(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Source::Browser, Lang::En) => "from your browser",
            (Source::Terminal, Lang::En) => "from the terminal",
            (Source::App, Lang::En) => "from the Klav app",
            (Source::Browser, Lang::Es) => "desde tu navegador",
            (Source::Terminal, Lang::Es) => "desde la terminal",
            (Source::App, Lang::Es) => "desde la app de Klav",
        }
    }
}

/// Whether `dir` is `<something>.app/Contents/<last>`.
fn in_app(dir: &Path, last: &str) -> bool {
    let mut parts = dir.components().rev().map(|c| c.as_os_str().to_str());
    parts.next() == Some(Some(last))
        && parts.next() == Some(Some("Contents"))
        && parts
            .next()
            .flatten()
            .is_some_and(|bundle| bundle.len() > ".app".len() && bundle.ends_with(".app"))
}

/// Who a presence prompt lets use the vault (ADR 0041 §2.4, §3.2). A
/// hint, never proof of which program asks (§1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Who<'a> {
    /// A peer in a terminal session with this controlling terminal.
    Terminal(&'a str),
    /// A peer in a terminal whose device has no name here.
    ATerminal,
    /// A peer with no terminal, keyed by its parent.
    NoTerminal,
    /// The same, when its executable is the browser's host.
    Browser,
    /// A peer keyed by its connection.
    Connection,
    /// The same, when its executable is the browser's host.
    BrowserConnection,
    /// A connection that declared `hold` (§1.2): never named.
    Declared,
}

impl Who<'_> {
    /// "the terminal ttys003", as the subject of "use your vault".
    fn subject(self, lang: Lang) -> String {
        match (self, lang) {
            (Who::Terminal(name), Lang::En) => format!("the terminal {}", clean(name, MAX_NAME)),
            (Who::Terminal(name), Lang::Es) => format!("la terminal {}", clean(name, MAX_NAME)),
            (Who::ATerminal, Lang::En) => "a terminal".into(),
            (Who::ATerminal, Lang::Es) => "una terminal".into(),
            (Who::NoTerminal, Lang::En) => "a program with no terminal".into(),
            (Who::NoTerminal, Lang::Es) => "un programa sin terminal".into(),
            (Who::Browser, Lang::En) => "a browser".into(),
            (Who::Browser, Lang::Es) => "un navegador".into(),
            (Who::Connection, Lang::En) => "this connection".into(),
            (Who::Connection, Lang::Es) => "esta conexión".into(),
            (Who::BrowserConnection, Lang::En) => "this browser connection".into(),
            (Who::BrowserConnection, Lang::Es) => "esta conexión del navegador".into(),
            (Who::Declared, Lang::En) => "the program that asked".into(),
            (Who::Declared, Lang::Es) => "el programa que lo pidió".into(),
        }
    }
}

/// How long a presence prompt says its window lasts (ADR 0041 §2.4): it
/// comes from the window key and the setting, and the window lasts what
/// the prompt said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lasts {
    /// "for 5 minutes".
    FiveMinutes,
    /// "until Klav locks".
    UntilLock,
}

impl Lasts {
    fn words(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Lasts::FiveMinutes, Lang::En) => "for 5 minutes",
            (Lasts::FiveMinutes, Lang::Es) => "durante 5 minutos",
            (Lasts::UntilLock, Lang::En) => "until Klav locks",
            (Lasts::UntilLock, Lang::Es) => "hasta que Klav se bloquee",
        }
    }
}

/// A value handed out with no window (the setting on Always, or a peer
/// with no window): the prompt names the value itself (ADR 0041 §2.4,
/// §3.2). Titles come from the vault and go through [`clean`]; `None` when
/// the item couldn't be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueAsk<'a> {
    /// `view` with `reveal`.
    Show(Option<&'a str>),
    /// `previous_password`.
    Previous(Option<&'a str>),
    /// `totp`.
    Code(Option<&'a str>),
    /// `generated_value`.
    Generated,
    /// `resolve`, with how many references.
    Resolve(usize),
    /// `autofill`.
    Fill(Option<&'a str>),
}

/// What a Touch ID prompt asks for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Prompt<'a> {
    /// The presence gate's window (ADR 0041 §2.4): "let the terminal
    /// ttys003 use your vault for 5 minutes".
    Presence { who: Who<'a>, lasts: Lasts },
    /// `unlock` with the presence gate on: it says the window it opens
    /// (`lasts`), or none (ADR 0041 §2.4, §1.2).
    UnlockPresence {
        email: &'a str,
        who: Who<'a>,
        lasts: Option<Lasts>,
    },
    /// A value with no window (ADR 0041 §2.4), and who asks for it, as the
    /// prompts that open a window name it (Omar's decision C of
    /// 2026-11-19).
    Value { ask: ValueAsk<'a>, who: Who<'a> },
    /// Loosen the presence setting from `from` to `to` (ADR 0041 §2.4): it
    /// names the change, not a window, and opens none.
    PresenceWindow {
        from: crate::uv::Window,
        to: crate::uv::Window,
    },
    /// Unlock the account of `email`.
    Unlock { email: &'a str },
    /// Approve an agent's request (`decide_approval`). `target` is the
    /// item's title, or `vault/project` without an item; `None` when this
    /// device does not have the item.
    Request {
        agent: &'a str,
        permission: Permission,
        target: Option<&'a str>,
    },
    /// Approve an agent or replace its grant, with its projects as
    /// `vault/project`.
    Grant {
        agent: &'a str,
        places: &'a [String],
    },
    /// Approve a task request, with the items left checked.
    Task { agent: &'a str, items: usize },
    /// Add a request's item to the agent's running task.
    AddToTask {
        agent: &'a str,
        item: Option<&'a str>,
    },
    /// Offer an agent a task to change passwords (ADR 0022 §6).
    Offer { agent: &'a str, passwords: usize },
    /// Sign in to `site` (the rpId) with a passkey in the vault (ADR 0020
    /// §8).
    PasskeySignIn { site: &'a str },
    /// Save a new passkey for `site` (the rpId) in the vault.
    PasskeySave { site: &'a str },
    /// Loosen the passkey verification window: fewer prompts from now on
    /// (ADR 0020 §8).
    PasskeyWindow,
    /// Resume an agent, or every agent (`None`), after a pause (ADR 0033
    /// §7, P2).
    Resume { agent: Option<&'a str> },
    /// Make `agent` the account's credential proxy, or use none (ADR 0036
    /// §3). `replaces`: an agent wrote the account's preferences, and this
    /// replaces them whole.
    ProxyUse {
        agent: Option<&'a str>,
        replaces: bool,
    },
    /// Let the credential proxy `agent` use `item` with `host` (and its
    /// `port` when not 443), the value in `header` when not
    /// `authorization` and taken from `field` when not the main secret,
    /// for the methods in `allowed` (and those in `asked`, asking first),
    /// on the path prefixes in `paths`: never cut (`klav-client` caps a
    /// grant to what fits). The item's title can be cut, so its
    /// `Vault/Project` and site come with it. Not shown: the profile's
    /// name, the text before the value and the rate. `words` when this
    /// approves the pending agent: the 6 words of the key klavd fetched.
    /// `first_on_account` adds what older devices lose.
    ProxyGrant {
        agent: &'a str,
        item: ItemShown<'a>,
        host: &'a str,
        port: Option<u16>,
        header: Option<&'a str>,
        field: Option<&'a str>,
        allowed: &'a [String],
        asked: &'a [String],
        paths: &'a [String],
        words: Option<&'a str>,
        first_on_account: bool,
        /// Sandbox issuers that lose a profile: the one this replaces
        /// under another name, or one of an item that dropped out.
        issuers_losing: usize,
        /// Sandbox issuers that keep the profile this writes, under these
        /// rules.
        issuers_keeping: usize,
    },
    /// Take `item` away from the credential proxy `agent`; that many
    /// sandbox issuers lose a profile.
    ProxyRevoke {
        agent: &'a str,
        item: ItemShown<'a>,
        issuers_losing: usize,
    },
    /// Finish an earlier revoke: re-issue the grants of `agents`, which
    /// still hold `item` and could not get its new key then.
    ProxyReissue {
        item: ItemShown<'a>,
        agents: &'a [String],
    },
    /// Let `issuer` start sandboxes through the credential proxy `proxy`,
    /// reached at `address`, with `profiles`, up to `max_live` at once,
    /// each for at most `max_ttl_secs`. `words` when this approves the
    /// pending issuer. Nothing is cut (`klav-client` caps it).
    ProxyIssuerAdd {
        issuer: &'a str,
        proxy: &'a str,
        address: &'a str,
        profiles: &'a [String],
        max_ttl_secs: u64,
        max_live: u32,
        words: Option<&'a str>,
        inject_ask: bool,
        first_on_account: bool,
    },
    /// Stop `issuer` from starting sandboxes through `proxy`.
    ProxyIssuerRemove { issuer: &'a str, proxy: &'a str },
    /// Ask to delete the account (ADR 0037 §1, §7.3).
    DeleteAccount,
    /// Cancel the deletion of the account, which brings the agents back
    /// (ADR 0037 A2).
    CancelDeletion,
    /// Let an active agent do more (ADR 0033, amendment of 2026-11-10, F4):
    /// only what widens, in the sheet's order. Asked only when the change
    /// widens (P8).
    GrantChange {
        agent: &'a str,
        more: &'a [Widening<'a>],
    },
}

/// One thing a grant change lets the agent do that it could not before,
/// from a line of the sheet that widens. No text of the agent's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Widening<'a> {
    /// A project added, as `vault/project`.
    Project(&'a str),
    /// A permission, with its new effect.
    Permission(Permission, Effect),
    /// More sites to fill (or anywhere).
    Sites,
    /// More hours (or always).
    Hours,
    /// No end any more.
    NoExpiry,
    /// It ends later.
    LaterExpiry,
    /// Rules outside the editor's model (only from the CLI).
    Rules,
}

impl<'a> Widening<'a> {
    /// What `line` widens; `None` for a line that does not.
    pub(crate) fn of(line: &'a ChangeLine) -> Option<Widening<'a>> {
        if !line.widens {
            return None;
        }
        Some(match &line.what {
            ChangeWhat::ProjectAdded { project } => Widening::Project(project),
            ChangeWhat::ProjectRemoved { .. } => return None,
            ChangeWhat::Permission {
                permission, after, ..
            } => Widening::Permission(*permission, *after),
            ChangeWhat::FillSites { .. } => Widening::Sites,
            ChangeWhat::Hours { .. } => Widening::Hours,
            ChangeWhat::Expires { after: None, .. } => Widening::NoExpiry,
            ChangeWhat::Expires { after: Some(_), .. } => Widening::LaterExpiry,
            ChangeWhat::Rules => Widening::Rules,
        })
    }

    /// `Personal/Release`, `reveal (ask)`, `more sites`…
    fn show(self, lang: Lang) -> String {
        match (self, lang) {
            (Widening::Project(place), _) => clean(place, MAX_NAME),
            (Widening::Permission(permission, effect), _) => format!(
                "{} ({})",
                permission_word(permission, lang),
                effect_word(effect, lang)
            ),
            (Widening::Sites, Lang::En) => "more sites".into(),
            (Widening::Sites, Lang::Es) => "más sitios".into(),
            (Widening::Hours, Lang::En) => "more hours".into(),
            (Widening::Hours, Lang::Es) => "más horas".into(),
            (Widening::NoExpiry, Lang::En) => "no expiry".into(),
            (Widening::NoExpiry, Lang::Es) => "sin caducidad".into(),
            (Widening::LaterExpiry, Lang::En) => "expires later".into(),
            (Widening::LaterExpiry, Lang::Es) => "caduca más tarde".into(),
            (Widening::Rules, Lang::En) => "other rules".into(),
            (Widening::Rules, Lang::Es) => "otras reglas".into(),
        }
    }
}

/// A permission in the app's words (`Localizable.xcstrings`).
fn permission_word(permission: Permission, lang: Lang) -> &'static str {
    match (permission, lang) {
        (Permission::List, Lang::En) => "list",
        (Permission::Fill, Lang::En) => "fill",
        (Permission::Inject, Lang::En) => "inject",
        (Permission::Totp, Lang::En) => "code",
        (Permission::Reveal, Lang::En) => "reveal",
        (Permission::Create, Lang::En) => "create",
        (Permission::Update, Lang::En) => "edit",
        (Permission::Delete, Lang::En) => "delete",
        (Permission::Passkey, Lang::En) => "passkey",
        (Permission::Rotate, Lang::En) => "change passwords",
        (Permission::Proxy, Lang::En) => "proxy",
        (Permission::List, Lang::Es) => "listar",
        (Permission::Fill, Lang::Es) => "rellenar",
        (Permission::Inject, Lang::Es) => "inyectar",
        (Permission::Totp, Lang::Es) => "código",
        (Permission::Reveal, Lang::Es) => "revelar",
        (Permission::Create, Lang::Es) => "crear",
        (Permission::Update, Lang::Es) => "editar",
        (Permission::Delete, Lang::Es) => "borrar",
        (Permission::Passkey, Lang::Es) => "passkey",
        (Permission::Rotate, Lang::Es) => "cambiar contraseñas",
        (Permission::Proxy, Lang::Es) => "proxy",
    }
}

fn effect_word(effect: Effect, lang: Lang) -> &'static str {
    match (effect, lang) {
        (Effect::Allow, Lang::En) => "allow",
        (Effect::Ask, Lang::En) => "ask",
        (Effect::Deny, Lang::En) => "deny",
        (Effect::Allow, Lang::Es) => "permitir",
        (Effect::Ask, Lang::Es) => "preguntar",
        (Effect::Deny, Lang::Es) => "denegar",
    }
}

/// `Personal/Release, reveal (ask), more sites and 2 more changes`.
fn widening(more: &[Widening<'_>], lang: Lang) -> String {
    let shown: Vec<String> = more
        .iter()
        .take(MAX_WIDENING)
        .map(|w| w.show(lang))
        .collect();
    let rest = more.len().saturating_sub(MAX_WIDENING);
    let shown = shown.join(", ");
    match (lang, rest) {
        (_, 0) => shown,
        (Lang::En, 1) => format!("{shown} and 1 more change"),
        (Lang::En, n) => format!("{shown} and {n} more changes"),
        (Lang::Es, 1) => format!("{shown} y 1 cambio más"),
        (Lang::Es, n) => format!("{shown} y {n} cambios más"),
    }
}

impl Prompt<'_> {
    /// The reason in `lang`, with where the request came from when known.
    pub(crate) fn reason(&self, lang: Lang, source: Option<Source>) -> String {
        let name = |text: &str| name(text, lang);
        let text = match (*self, lang) {
            (Prompt::Presence { who, lasts }, Lang::En) => {
                return format!(
                    "let {} use your vault {}",
                    who.subject(lang),
                    lasts.words(lang)
                );
            }
            (Prompt::Presence { who, lasts }, Lang::Es) => {
                return format!(
                    "dejar que {} use tu bóveda {}",
                    who.subject(lang),
                    lasts.words(lang)
                );
            }
            (Prompt::UnlockPresence { email, who, lasts }, _) => {
                let email = clean(email, MAX_EMAIL);
                return match (who, lasts, lang) {
                    (_, None, Lang::En) => format!("unlock your vault ({email})"),
                    (_, None, Lang::Es) => format!("desbloquear tu bóveda ({email})"),
                    (Who::Declared, Some(lasts), Lang::En) => format!(
                        "unlock your vault and let the program that asked use it {} ({email})",
                        lasts.words(lang)
                    ),
                    (Who::Declared, Some(lasts), Lang::Es) => format!(
                        "desbloquear tu bóveda y dejar que el programa que lo pidió la use {} ({email})",
                        lasts.words(lang)
                    ),
                    (who, Some(lasts), Lang::En) => format!(
                        "unlock your vault for {}, and let it use the vault {} ({email})",
                        who.subject(lang),
                        lasts.words(lang)
                    ),
                    (who, Some(lasts), Lang::Es) => format!(
                        "desbloquear tu bóveda para {} y dejar que la use {} ({email})",
                        who.subject(lang),
                        lasts.words(lang)
                    ),
                };
            }
            (Prompt::Value { ask, who }, _) => return value_for(ask, who, lang),
            (Prompt::PresenceWindow { from, to }, _) => return presence_window(from, to, lang),
            (Prompt::Unlock { email }, _) => {
                let email = clean(email, MAX_EMAIL);
                let what = match lang {
                    Lang::En => "unlock your vault",
                    Lang::Es => "desbloquear tu bóveda",
                };
                return match source {
                    Some(source) => format!("{what} {} ({email})", source.unlock_for(lang)),
                    None => format!("{what} ({email})"),
                };
            }
            (
                Prompt::Request {
                    agent,
                    permission,
                    target,
                },
                _,
            ) => request(lang, &name(agent), permission, target.map(name)),
            (Prompt::Grant { agent, places }, Lang::En) => {
                format!(
                    "give the agent {} access to {}",
                    name(agent),
                    list(places, lang)
                )
            }
            (Prompt::Grant { agent, places }, Lang::Es) => {
                format!(
                    "dar al agente {} acceso a {}",
                    name(agent),
                    list(places, lang)
                )
            }
            (Prompt::Task { agent, items }, Lang::En) => format!(
                "approve the task of {}: {items} {}",
                name(agent),
                if items == 1 { "item" } else { "items" }
            ),
            (Prompt::Task { agent, items }, Lang::Es) => format!(
                "aprobar la tarea de {}: {items} {}",
                name(agent),
                if items == 1 { "elemento" } else { "elementos" }
            ),
            (Prompt::AddToTask { agent, item }, Lang::En) => format!(
                "add {} to the task of {}",
                item.map_or_else(|| "an item".to_owned(), name),
                name(agent)
            ),
            (Prompt::AddToTask { agent, item }, Lang::Es) => format!(
                "añadir {} a la tarea de {}",
                item.map_or_else(|| "un elemento".to_owned(), name),
                name(agent)
            ),
            (Prompt::Offer { agent, passwords }, Lang::En) => format!(
                "offer {} a task to change {passwords} {}",
                name(agent),
                if passwords == 1 {
                    "password"
                } else {
                    "passwords"
                }
            ),
            (Prompt::Offer { agent, passwords }, Lang::Es) => format!(
                "ofrecer a {} una tarea para cambiar {passwords} {}",
                name(agent),
                if passwords == 1 {
                    "contraseña"
                } else {
                    "contraseñas"
                }
            ),
            (Prompt::PasskeySignIn { site }, Lang::En) => {
                format!("sign in to {} with your passkey", name(site))
            }
            (Prompt::PasskeySignIn { site }, Lang::Es) => {
                format!("iniciar sesión en {} con tu passkey", name(site))
            }
            (Prompt::PasskeySave { site }, Lang::En) => {
                format!("save a passkey for {} in Klav", name(site))
            }
            (Prompt::PasskeySave { site }, Lang::Es) => {
                format!("guardar una passkey de {} en Klav", name(site))
            }
            (Prompt::PasskeyWindow, Lang::En) => {
                "let your passkeys sign in without asking every time".to_owned()
            }
            (Prompt::PasskeyWindow, Lang::Es) => {
                "dejar que tus passkeys inicien sesión sin preguntar cada vez".to_owned()
            }
            (Prompt::Resume { agent: Some(agent) }, Lang::En) => {
                format!("let {} use Klav again", name(agent))
            }
            (Prompt::Resume { agent: Some(agent) }, Lang::Es) => {
                format!("dejar que {} vuelva a usar Klav", name(agent))
            }
            (Prompt::Resume { agent: None }, Lang::En) => {
                "let your agents use Klav again".to_owned()
            }
            (Prompt::Resume { agent: None }, Lang::Es) => {
                "dejar que tus agentes vuelvan a usar Klav".to_owned()
            }
            (Prompt::ProxyUse { agent, replaces }, _) => {
                let what = match (agent, lang) {
                    (Some(agent), Lang::En) => {
                        format!("use {} as your credential proxy", name(agent))
                    }
                    (Some(agent), Lang::Es) => {
                        format!("usar {} como tu proxy de credenciales", name(agent))
                    }
                    (None, Lang::En) => "stop using a credential proxy".to_owned(),
                    (None, Lang::Es) => "dejar de usar un proxy de credenciales".to_owned(),
                };
                match (replaces, lang) {
                    (false, _) => what,
                    (true, Lang::En) => {
                        format!("{what}, replacing the account preferences an agent wrote")
                    }
                    (true, Lang::Es) => {
                        format!(
                            "{what} y reemplazar las preferencias de la cuenta que escribió un agente"
                        )
                    }
                }
            }
            (
                Prompt::ProxyGrant {
                    agent,
                    item,
                    host,
                    port,
                    header,
                    field,
                    allowed,
                    asked,
                    paths,
                    words,
                    first_on_account,
                    issuers_losing,
                    issuers_keeping,
                },
                lang,
            ) => proxy_grant(
                lang,
                &name(agent),
                &item.show(lang),
                &ProxyRules {
                    host,
                    port,
                    header,
                    field,
                    allowed,
                    asked,
                    paths,
                },
                words,
                first_on_account,
                (issuers_losing, issuers_keeping),
            ),
            (
                Prompt::ProxyIssuerAdd {
                    issuer,
                    proxy,
                    address,
                    profiles,
                    max_ttl_secs,
                    max_live,
                    words,
                    inject_ask,
                    first_on_account,
                },
                lang,
            ) => issuer_add(
                lang,
                &name(issuer),
                &name(proxy),
                &IssuerLimits {
                    address,
                    profiles,
                    max_ttl_secs,
                    max_live,
                },
                words,
                inject_ask,
                first_on_account,
            ),
            (Prompt::ProxyIssuerRemove { issuer, proxy }, Lang::En) => format!(
                "stop {} from starting sandboxes through your credential proxy {}",
                name(issuer),
                name(proxy)
            ),
            (Prompt::ProxyIssuerRemove { issuer, proxy }, Lang::Es) => format!(
                "impedir que {} cree sandboxes con tu proxy de credenciales {}",
                name(issuer),
                name(proxy)
            ),
            (
                Prompt::ProxyRevoke {
                    agent,
                    item,
                    issuers_losing,
                },
                Lang::En,
            ) => format!(
                "take {} away from your credential proxy {}{}",
                item.show(lang),
                name(agent),
                issuers_lose(lang, issuers_losing)
            ),
            (
                Prompt::ProxyRevoke {
                    agent,
                    item,
                    issuers_losing,
                },
                Lang::Es,
            ) => format!(
                "quitarle {} a tu proxy de credenciales {}{}",
                item.show(lang),
                name(agent),
                issuers_lose(lang, issuers_losing)
            ),
            (Prompt::ProxyReissue { item, agents }, Lang::En) => format!(
                "finish re-issuing {} to {} {}",
                item.show(lang),
                if agents.len() == 1 { "agent" } else { "agents" },
                names(agents, lang)
            ),
            (Prompt::ProxyReissue { item, agents }, Lang::Es) => format!(
                "terminar de darle {} con su clave nueva {} {}",
                item.show(lang),
                if agents.len() == 1 {
                    "al agente"
                } else {
                    "a los agentes"
                },
                names(agents, lang)
            ),
            (Prompt::DeleteAccount, Lang::En) => {
                "confirm it’s you to delete your account".to_owned()
            }
            (Prompt::DeleteAccount, Lang::Es) => {
                "confirmar que eres tú para borrar tu cuenta".to_owned()
            }
            (Prompt::CancelDeletion, Lang::En) => {
                "cancel the deletion of your account and let your agents use Klav again".to_owned()
            }
            (Prompt::CancelDeletion, Lang::Es) => {
                "cancelar el borrado de tu cuenta y dejar que tus agentes vuelvan a usar Klav"
                    .to_owned()
            }
            (Prompt::GrantChange { agent, more }, Lang::En) => {
                format!("let {} do more: {}", name(agent), widening(more, lang))
            }
            (Prompt::GrantChange { agent, more }, Lang::Es) => {
                format!(
                    "dejar que {} haga más: {}",
                    name(agent),
                    widening(more, lang)
                )
            }
        };
        match source {
            Some(source) => format!("{text} ({})", source.decided_from(lang)),
            None => text,
        }
    }
}

/// The value's own text, and who it is for (ADR 0041 §2.4; Omar's decision
/// C of 2026-11-19): "show the code of “GitHub” (for the terminal
/// ttys003)". A fill for a browser keyed by its parent already names it
/// ("in a browser"), so it says no more.
fn value_for(ask: ValueAsk<'_>, who: Who<'_>, lang: Lang) -> String {
    let text = value_ask(ask, lang);
    if matches!((ask, who), (ValueAsk::Fill(_), Who::Browser)) {
        return text;
    }
    match lang {
        Lang::En => format!("{text} (for {})", who.subject(lang)),
        Lang::Es => format!("{text} (para {})", who.subject(lang)),
    }
}

/// The value's own text (ADR 0041 §2.4: "fill “GitHub” in a browser").
fn value_ask(ask: ValueAsk<'_>, lang: Lang) -> String {
    let name = |title: &str| name(title, lang);
    match (ask, lang) {
        (ValueAsk::Show(Some(t)), Lang::En) => format!("show the values of {}", name(t)),
        (ValueAsk::Show(Some(t)), Lang::Es) => format!("mostrar los valores de {}", name(t)),
        (ValueAsk::Previous(Some(t)), Lang::En) => {
            format!("show a previous password of {}", name(t))
        }
        (ValueAsk::Previous(Some(t)), Lang::Es) => {
            format!("mostrar una contraseña anterior de {}", name(t))
        }
        (ValueAsk::Code(Some(t)), Lang::En) => format!("show the code of {}", name(t)),
        (ValueAsk::Code(Some(t)), Lang::Es) => format!("mostrar el código de {}", name(t)),
        (ValueAsk::Fill(Some(t)), Lang::En) => format!("fill {} in a browser", name(t)),
        (ValueAsk::Fill(Some(t)), Lang::Es) => format!("rellenar {} en un navegador", name(t)),
        (ValueAsk::Generated, Lang::En) => "show a password you generated".into(),
        (ValueAsk::Generated, Lang::Es) => "mostrar una contraseña que generaste".into(),
        (ValueAsk::Resolve(1), Lang::En) => "use a value from your vault in a command".into(),
        (ValueAsk::Resolve(1), Lang::Es) => "usar un valor de tu bóveda en un comando".into(),
        (ValueAsk::Resolve(n), Lang::En) => format!("use {n} values from your vault in a command"),
        (ValueAsk::Resolve(n), Lang::Es) => format!("usar {n} valores de tu bóveda en un comando"),
        (
            ValueAsk::Show(None)
            | ValueAsk::Previous(None)
            | ValueAsk::Code(None)
            | ValueAsk::Fill(None),
            Lang::En,
        ) => "show a value from your vault".into(),
        (
            ValueAsk::Show(None)
            | ValueAsk::Previous(None)
            | ValueAsk::Code(None)
            | ValueAsk::Fill(None),
            Lang::Es,
        ) => "mostrar un valor de tu bóveda".into(),
    }
}

/// Loosening the presence setting names the change (ADR 0041 §2.4).
fn presence_window(from: crate::uv::Window, to: crate::uv::Window, lang: Lang) -> String {
    use crate::uv::Window;
    let to_words = match (to, lang) {
        (Window::FiveMinutes, Lang::En) => "every 5 minutes",
        (Window::FiveMinutes, Lang::Es) => "cada 5 minutos",
        (Window::Unlocked, Lang::En) => "once until Klav locks",
        (Window::Unlocked, Lang::Es) => "una vez hasta que Klav se bloquee",
        (Window::Always, Lang::En) => "for every value",
        (Window::Always, Lang::Es) => "en cada valor",
    };
    let from_words = match (from, lang) {
        (Window::FiveMinutes, Lang::En) => "every 5 minutes",
        (Window::FiveMinutes, Lang::Es) => "cada 5 minutos",
        (Window::Unlocked, Lang::En) => "once until Klav locks",
        (Window::Unlocked, Lang::Es) => "una vez hasta que Klav se bloquee",
        (Window::Always, Lang::En) => "for every value",
        (Window::Always, Lang::Es) => "en cada valor",
    };
    match lang {
        Lang::En => format!("ask for your presence {to_words} instead of {from_words}"),
        Lang::Es => format!("pedir tu presencia {to_words} en vez de {from_words}"),
    }
}

/// "let “claude-code” fill “GitHub”". `agent` and `target` are already
/// cleaned and quoted.
fn request(lang: Lang, agent: &str, permission: Permission, target: Option<String>) -> String {
    let target = target.unwrap_or_else(|| {
        match lang {
            Lang::En => "an item",
            Lang::Es => "un elemento",
        }
        .to_owned()
    });
    // Every permission has its words: a new one must get them here.
    match lang {
        Lang::En => match permission {
            Permission::List => format!("let {agent} see the list of {target}"),
            Permission::Fill => format!("let {agent} fill {target}"),
            Permission::Inject => format!("let {agent} use {target} in a command"),
            Permission::Totp => format!("let {agent} get a code for {target}"),
            Permission::Reveal => format!("let {agent} see the value of {target}"),
            Permission::Create => format!("let {agent} create an item in {target}"),
            Permission::Update => format!("let {agent} change {target}"),
            Permission::Delete => format!("let {agent} delete {target}"),
            Permission::Passkey => format!("let {agent} sign in to {target} with your passkey"),
            Permission::Rotate => format!("let {agent} change the password of {target}"),
            Permission::Proxy => format!("let {agent} send a request signed in with {target}"),
        },
        Lang::Es => match permission {
            Permission::List => format!("dejar que {agent} vea la lista de {target}"),
            Permission::Fill => format!("dejar que {agent} rellene {target}"),
            Permission::Inject => format!("dejar que {agent} use {target} en un comando"),
            Permission::Totp => format!("dejar que {agent} obtenga un código de {target}"),
            Permission::Reveal => format!("dejar que {agent} vea el valor de {target}"),
            Permission::Create => format!("dejar que {agent} cree un elemento en {target}"),
            Permission::Update => format!("dejar que {agent} cambie {target}"),
            Permission::Delete => format!("dejar que {agent} borre {target}"),
            Permission::Passkey => {
                format!("dejar que {agent} inicie sesión en {target} con tu passkey")
            }
            Permission::Rotate => format!("dejar que {agent} cambie la contraseña de {target}"),
            Permission::Proxy => {
                format!("dejar que {agent} mande una petición con la sesión de {target}")
            }
        },
    }
}

/// What a proxy grant lets the proxy do with one credential.
struct ProxyRules<'a> {
    host: &'a str,
    port: Option<u16>,
    header: Option<&'a str>,
    field: Option<&'a str>,
    allowed: &'a [String],
    asked: &'a [String],
    paths: &'a [String],
}

/// An item in a proxy dialog: its title, which any caller of klavd can
/// change without presence and which is cut like every name, with its
/// `Vault/Project` (klavd moves no item and renames no vault or project)
/// and the host of its first website.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ItemShown<'a> {
    pub(crate) title: &'a str,
    pub(crate) place: &'a str,
    pub(crate) site: Option<&'a str>,
}

impl ItemShown<'_> {
    /// `“GitHub” (github.com, in “Personal/Dev”)`.
    fn show(&self, lang: Lang) -> String {
        let title = name(self.title, lang);
        let site = self
            .site
            .map(|s| tail(s, MAX_NAME))
            .filter(|s| !s.is_empty());
        let place = (!self.place.trim().is_empty()).then(|| {
            let place = name(self.place, lang);
            match lang {
                Lang::En => format!("in {place}"),
                Lang::Es => format!("en {place}"),
            }
        });
        let parts: Vec<String> = site.into_iter().chain(place).collect();
        if parts.is_empty() {
            title
        } else {
            format!("{title} ({})", parts.join(", "))
        }
    }
}

/// [`clean`], cut from the start when too long (`…mail.example.com`): the
/// end of a host is what names it.
fn tail(text: &str, max: usize) -> String {
    let text = clean(text, usize::MAX);
    let count = text.chars().count();
    if count <= max {
        return text;
    }
    let mut cut = String::from('…');
    cut.extend(text.chars().skip(count - max.saturating_sub(1)));
    cut
}

/// `“a”, “b” and 3 more`: names from outside, quoted.
fn names(list: &[String], lang: Lang) -> String {
    let quoted: Vec<String> = list
        .iter()
        .take(MAX_PLACES)
        .map(|n| name(n, lang))
        .collect();
    let more = list.len().saturating_sub(MAX_PLACES);
    let and = match lang {
        Lang::En => "and",
        Lang::Es => "y",
    };
    match (quoted.as_slice(), more) {
        ([], _) => String::new(),
        ([one], 0) => one.clone(),
        ([a, b], 0) => format!("{a} {and} {b}"),
        (shown, more) => {
            let more = match lang {
                Lang::En => format!("{more} more"),
                Lang::Es => format!("{more} más"),
            };
            format!("{} {and} {more}", shown.join(", "))
        }
    }
}

/// Longest piece of a proxy grant shown: above every cap `klav-client`
/// puts on a grant, so `clean` never cuts one.
const MAX_RULE_PIECE: usize = 128;

/// What a grant or a revoke takes from sandbox issuers (none: nothing).
/// A count, not names: the dialog stays bounded, and the CLI's preview
/// names them and their profiles. It says "a profile" and not which: the
/// count also holds the profiles of items that dropped out of the grant
/// (purged or moved), which are not the one this request names.
fn issuers_lose(lang: Lang, n: usize) -> String {
    match (lang, n) {
        (_, 0) => String::new(),
        (Lang::En, 1) => ". 1 sandbox issuer loses a profile".into(),
        (Lang::En, n) => format!(". {n} sandbox issuers lose a profile"),
        (Lang::Es, 1) => ". 1 emisor de sandboxes pierde un perfil".into(),
        (Lang::Es, n) => format!(". {n} emisores de sandboxes pierden un perfil"),
    }
}

/// `. 2 sandbox issuers keep this profile, with these rules`: said
/// whenever an issuer keeps the profile a grant writes, since a re-grant
/// under the same name keeps them on it whatever its rules become.
fn issuers_keep(lang: Lang, n: usize) -> String {
    match (lang, n) {
        (_, 0) => String::new(),
        (Lang::En, 1) => ". 1 sandbox issuer keeps this profile, with these rules".into(),
        (Lang::En, n) => format!(". {n} sandbox issuers keep this profile, with these rules"),
        (Lang::Es, 1) => ". 1 emisor de sandboxes conserva este perfil, con estas reglas".into(),
        (Lang::Es, n) => {
            format!(". {n} emisores de sandboxes conservan este perfil, con estas reglas")
        }
    }
}

/// The reason for a proxy grant: every host, method and path it signs.
fn proxy_grant(
    lang: Lang,
    agent: &str,
    item: &str,
    rules: &ProxyRules<'_>,
    words: Option<&str>,
    first_on_account: bool,
    (issuers_losing, issuers_keeping): (usize, usize),
) -> String {
    let join = |list: &[String]| {
        list.iter()
            .map(|t| clean(t, MAX_RULE_PIECE))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut host = clean(rules.host, MAX_RULE_PIECE);
    if let Some(port) = rules.port {
        host.push_str(&format!(":{port}"));
    }
    let header = rules.header.map(|h| clean(h, MAX_RULE_PIECE));
    let field = rules.field.map(|f| lang.quote(&clean(f, MAX_RULE_PIECE)));
    let mut how = String::new();
    match lang {
        Lang::En => {
            if let Some(h) = &header {
                how.push_str(&format!(", in header {h}"));
            }
            if let Some(f) = &field {
                how.push_str(&format!(", from field {f}"));
            }
        }
        Lang::Es => {
            if let Some(h) = &header {
                how.push_str(&format!(", en la cabecera {h}"));
            }
            if let Some(f) = &field {
                how.push_str(&format!(", del campo {f}"));
            }
        }
    }
    let mut methods = Vec::new();
    if !rules.allowed.is_empty() {
        methods.push(join(rules.allowed));
    }
    if !rules.asked.is_empty() {
        methods.push(match lang {
            Lang::En => format!("asking you first for {}", join(rules.asked)),
            Lang::Es => format!("preguntándote antes para {}", join(rules.asked)),
        });
    }
    let methods = methods.join("; ");
    let paths = join(rules.paths);
    let words = words.map(|w| clean(w, MAX_RULE_PIECE));
    match lang {
        Lang::En => {
            let who = match &words {
                Some(w) => format!(
                    "approve the pending agent {agent} (words: {w}) as your credential proxy and let it"
                ),
                None => format!("let your credential proxy {agent}"),
            };
            let mut text = format!(
                "{who} use {item} with {host}{how}: {methods}, on {paths}. The agent never sees its value"
            );
            text.push_str(&issuers_lose(lang, issuers_losing));
            text.push_str(&issuers_keep(lang, issuers_keeping));
            if first_on_account {
                text.push_str(". Devices without the latest Klav stop showing agents and requests");
            }
            text
        }
        Lang::Es => {
            let who = match &words {
                Some(w) => format!(
                    "aprobar el agente pendiente {agent} (palabras: {w}) como tu proxy de credenciales y dejar que"
                ),
                None => format!("dejar que tu proxy de credenciales {agent}"),
            };
            let mut text = format!(
                "{who} use {item} con {host}{how}: {methods}, en {paths}. El agente nunca ve su valor"
            );
            text.push_str(&issuers_lose(lang, issuers_losing));
            text.push_str(&issuers_keep(lang, issuers_keeping));
            if first_on_account {
                text.push_str(
                    ". Los dispositivos sin la última versión de Klav dejan de mostrar agentes y solicitudes",
                );
            }
            text
        }
    }
}

/// What an issuer may ask the proxy for.
struct IssuerLimits<'a> {
    address: &'a str,
    profiles: &'a [String],
    max_ttl_secs: u64,
    max_live: u32,
}

/// `8 h`, `90 min`: a TTL as the person typed it.
fn duration(secs: u64) -> String {
    if secs.is_multiple_of(3600) {
        format!("{} h", secs / 3600)
    } else {
        format!("{} min", secs.div_ceil(60))
    }
}

/// The reason for `klav proxy issuer add`: every profile and limit it
/// signs, and the proxy's address.
fn issuer_add(
    lang: Lang,
    issuer: &str,
    proxy: &str,
    limits: &IssuerLimits<'_>,
    words: Option<&str>,
    inject_ask: bool,
    first_on_account: bool,
) -> String {
    let profiles = limits
        .profiles
        .iter()
        .map(|p| clean(p, MAX_RULE_PIECE))
        .collect::<Vec<_>>()
        .join(", ");
    let address = clean(limits.address, MAX_RULE_PIECE * 2);
    let ttl = duration(limits.max_ttl_secs);
    let live = limits.max_live;
    let words = words.map(|w| clean(w, MAX_RULE_PIECE));
    match lang {
        Lang::En => {
            let who = match &words {
                Some(w) => format!("approve the pending agent {issuer} (words: {w}) and let it"),
                None => format!("let {issuer}"),
            };
            let mut text = format!(
                "{who} start sandboxes through your credential proxy {proxy} at {address}: profiles {profiles}, up to {live} at once, each for at most {ttl}"
            );
            if inject_ask {
                text.push_str(". Each `inject` of it will ask you first");
            }
            if first_on_account {
                text.push_str(
                    ". Devices and proxies without the latest Klav stop working with agents",
                );
            }
            text
        }
        Lang::Es => {
            let who = match &words {
                Some(w) => {
                    format!("aprobar el agente pendiente {issuer} (palabras: {w}) y dejar que")
                }
                None => format!("dejar que {issuer}"),
            };
            let mut text = format!(
                "{who} cree sandboxes con tu proxy de credenciales {proxy} en {address}: perfiles {profiles}, hasta {live} a la vez, cada uno por {ttl} como mucho"
            );
            if inject_ask {
                text.push_str(". Cada `inject` suyo te preguntará antes");
            }
            if first_on_account {
                text.push_str(
                    ". Los dispositivos y proxies sin la última versión de Klav dejan de funcionar con agentes",
                );
            }
            text
        }
    }
}

/// A name from outside, cleaned and between quotes.
fn name(text: &str, lang: Lang) -> String {
    let text = clean(text, MAX_NAME);
    if text.is_empty() {
        return match lang {
            Lang::En => "(no name)",
            Lang::Es => "(sin nombre)",
        }
        .to_owned();
    }
    lang.quote(&text)
}

/// "Personal/Release, Work/API and 3 more".
fn list(places: &[String], lang: Lang) -> String {
    let shown: Vec<String> = places
        .iter()
        .take(MAX_PLACES)
        .map(|p| clean(p, MAX_NAME))
        .collect();
    let more = places.len().saturating_sub(MAX_PLACES);
    let and = match lang {
        Lang::En => "and",
        Lang::Es => "y",
    };
    match (shown.as_slice(), more) {
        ([], _) => String::new(),
        ([one], _) => one.clone(),
        ([a, b], 0) => format!("{a} {and} {b}"),
        (shown, more) => {
            let more = match lang {
                Lang::En => format!("{more} more"),
                Lang::Es => format!("{more} más"),
            };
            format!("{} {and} {more}", shown.join(", "))
        }
    }
}

/// Makes text from outside safe to show in a system dialog: control
/// characters become spaces, Unicode format characters (bidi overrides
/// and isolates, zero-width characters, tags…) go away, quotation marks
/// become `'` (so the quotes around the name stay the only ones), runs of
/// white space become one space, and the result is at most `max`
/// characters, ending in `…` when cut.
pub(crate) fn clean(text: &str, max: usize) -> String {
    let spaced: String = text
        .chars()
        .filter(|c| !is_format(*c))
        .map(|c| {
            if c.is_control() {
                ' '
            } else if is_quote(c) {
                '\''
            } else {
                c
            }
        })
        .collect();
    let joined = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max {
        return joined;
    }
    let mut cut: String = joined.chars().take(max.saturating_sub(1)).collect();
    cut.truncate(cut.trim_end().len());
    cut.push('…');
    cut
}

/// The Unicode format characters (general category `Cf`): invisible, and
/// some reorder the text around them.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn is_quote(c: char) -> bool {
    matches!(
        c,
        '"' | '“' | '”' | '„' | '‟' | '«' | '»' | '‹' | '›' | '「' | '」' | '＂'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn request(agent: &str, permission: Permission, target: &str, lang: Lang) -> String {
        Prompt::Request {
            agent,
            permission,
            target: Some(target),
        }
        .reason(lang, None)
    }

    fn line(what: ChangeWhat, widens: bool) -> ChangeLine {
        ChangeLine { what, widens }
    }

    #[test]
    fn a_grant_change_names_only_what_widens() {
        let lines = [
            line(
                ChangeWhat::ProjectAdded {
                    project: "Personal/Release".into(),
                },
                true,
            ),
            line(
                ChangeWhat::ProjectRemoved {
                    project: "Work/API".into(),
                },
                false,
            ),
            line(
                ChangeWhat::Permission {
                    permission: Permission::Fill,
                    before: Effect::Allow,
                    before_default: true,
                    after: Effect::Deny,
                    after_default: false,
                },
                false,
            ),
            line(
                ChangeWhat::Permission {
                    permission: Permission::Reveal,
                    before: Effect::Deny,
                    before_default: true,
                    after: Effect::Ask,
                    after_default: false,
                },
                true,
            ),
        ];
        let more: Vec<Widening<'_>> = lines.iter().filter_map(Widening::of).collect();
        let prompt = Prompt::GrantChange {
            agent: "claude-code",
            more: &more,
        };
        assert_eq!(
            prompt.reason(Lang::En, None),
            "let “claude-code” do more: Personal/Release, reveal (ask)"
        );
        assert_eq!(
            prompt.reason(Lang::Es, None),
            "dejar que «claude-code» haga más: Personal/Release, revelar (preguntar)"
        );
        assert_eq!(
            prompt.reason(Lang::En, Some(Source::Terminal)),
            "let “claude-code” do more: Personal/Release, reveal (ask) (from the terminal)"
        );
        assert_eq!(
            prompt.reason(Lang::Es, Some(Source::App)),
            "dejar que «claude-code» haga más: Personal/Release, revelar (preguntar) (desde la app de Klav)"
        );
    }

    #[test]
    fn a_grant_change_lists_three_and_counts_the_rest() {
        let lines = [
            line(
                ChangeWhat::Permission {
                    permission: Permission::Totp,
                    before: Effect::Ask,
                    before_default: true,
                    after: Effect::Allow,
                    after_default: false,
                },
                true,
            ),
            line(
                ChangeWhat::FillSites {
                    before: vec!["github.com".into()],
                    after: Vec::new(),
                },
                true,
            ),
            line(
                ChangeWhat::Hours {
                    before: vec!["mon-fri 09:00-18:00 -06:00".into()],
                    after: Vec::new(),
                },
                true,
            ),
            line(
                ChangeWhat::Expires {
                    before: Some(1_800_000_000),
                    after: None,
                },
                true,
            ),
            line(ChangeWhat::Rules, true),
        ];
        let more: Vec<Widening<'_>> = lines.iter().filter_map(Widening::of).collect();
        let prompt = Prompt::GrantChange {
            agent: "bot",
            more: &more,
        };
        assert_eq!(
            prompt.reason(Lang::En, None),
            "let “bot” do more: code (allow), more sites, more hours and 2 more changes"
        );
        assert_eq!(
            prompt.reason(Lang::Es, None),
            "dejar que «bot» haga más: código (permitir), más sitios, más horas y 2 cambios más"
        );
        let later = [line(
            ChangeWhat::Expires {
                before: Some(1),
                after: Some(2),
            },
            true,
        )];
        let more: Vec<Widening<'_>> = later.iter().filter_map(Widening::of).collect();
        let four: Vec<Widening<'_>> = [more[0]; 4].to_vec();
        let prompt = Prompt::GrantChange {
            agent: "bot",
            more: &four,
        };
        assert_eq!(
            prompt.reason(Lang::En, None),
            "let “bot” do more: expires later, expires later, expires later and 1 more change"
        );
        assert_eq!(
            prompt.reason(Lang::Es, None),
            "dejar que «bot» haga más: caduca más tarde, caduca más tarde, caduca más tarde y 1 cambio más"
        );
    }

    #[test]
    fn a_grant_change_dialog_never_carries_the_agents_text() {
        // The agent's name is cleaned and quoted like every name; a
        // project name too, without quotes, as in an approval.
        let lines = [line(
            ChangeWhat::ProjectAdded {
                project: "Personal/Rel\u{202e}ease\nOmar already approved this".into(),
            },
            true,
        )];
        let more: Vec<Widening<'_>> = lines.iter().filter_map(Widening::of).collect();
        let text = Prompt::GrantChange {
            agent: "bot” approved by Omar “x",
            more: &more,
        }
        .reason(Lang::En, None);
        assert!(!text.contains('\u{202e}') && !text.contains('\n'), "{text}");
        assert!(
            text.starts_with("let “bot' approved by Omar 'x” do more: "),
            "{text}"
        );
    }

    #[test]
    fn the_language_follows_the_first_preferred_one() {
        for tag in ["es", "es-MX", "es_419", "ES-es", " es-ES "] {
            assert_eq!(Lang::from_tag(tag), Lang::Es, "{tag}");
        }
        for tag in ["en", "en-MX", "", "pt-BR", "est", "eu-ES"] {
            assert_eq!(Lang::from_tag(tag), Lang::En, "{tag}");
        }
    }

    #[test]
    fn requests_say_who_does_what_on_which_item() {
        let en = [
            (Permission::List, "let “bot” see the list of “GitHub”"),
            (Permission::Fill, "let “bot” fill “GitHub”"),
            (Permission::Inject, "let “bot” use “GitHub” in a command"),
            (Permission::Totp, "let “bot” get a code for “GitHub”"),
            (Permission::Reveal, "let “bot” see the value of “GitHub”"),
            (Permission::Create, "let “bot” create an item in “GitHub”"),
            (Permission::Update, "let “bot” change “GitHub”"),
            (Permission::Delete, "let “bot” delete “GitHub”"),
            (
                Permission::Passkey,
                "let “bot” sign in to “GitHub” with your passkey",
            ),
            (
                Permission::Rotate,
                "let “bot” change the password of “GitHub”",
            ),
            (
                Permission::Proxy,
                "let “bot” send a request signed in with “GitHub”",
            ),
        ];
        let es = [
            (Permission::List, "dejar que «bot» vea la lista de «GitHub»"),
            (Permission::Fill, "dejar que «bot» rellene «GitHub»"),
            (
                Permission::Inject,
                "dejar que «bot» use «GitHub» en un comando",
            ),
            (
                Permission::Totp,
                "dejar que «bot» obtenga un código de «GitHub»",
            ),
            (
                Permission::Reveal,
                "dejar que «bot» vea el valor de «GitHub»",
            ),
            (
                Permission::Create,
                "dejar que «bot» cree un elemento en «GitHub»",
            ),
            (Permission::Update, "dejar que «bot» cambie «GitHub»"),
            (Permission::Delete, "dejar que «bot» borre «GitHub»"),
            (
                Permission::Passkey,
                "dejar que «bot» inicie sesión en «GitHub» con tu passkey",
            ),
            (
                Permission::Rotate,
                "dejar que «bot» cambie la contraseña de «GitHub»",
            ),
            (
                Permission::Proxy,
                "dejar que «bot» mande una petición con la sesión de «GitHub»",
            ),
        ];
        for (lang, table) in [(Lang::En, en), (Lang::Es, es)] {
            assert_eq!(table.len(), Permission::ALL.len());
            for (permission, text) in table {
                assert_eq!(request("bot", permission, "GitHub", lang), text);
            }
        }
        assert_eq!(
            request("release-mac", Permission::Inject, "Sparkle EdDSA", Lang::En),
            "let “release-mac” use “Sparkle EdDSA” in a command"
        );
        // An item this device does not have.
        let unknown = Prompt::Request {
            agent: "bot",
            permission: Permission::Fill,
            target: None,
        };
        assert_eq!(unknown.reason(Lang::En, None), "let “bot” fill an item");
        assert_eq!(
            unknown.reason(Lang::Es, None),
            "dejar que «bot» rellene un elemento"
        );
    }

    #[test]
    fn passkey_uses_name_the_site_and_where_the_request_came_from() {
        let site = "example.com";
        let browser = Some(Source::Browser);
        assert_eq!(
            Prompt::PasskeySignIn { site }.reason(Lang::En, browser),
            "sign in to “example.com” with your passkey (from your browser)"
        );
        assert_eq!(
            Prompt::PasskeySignIn { site }.reason(Lang::Es, browser),
            "iniciar sesión en «example.com» con tu passkey (desde tu navegador)"
        );
        assert_eq!(
            Prompt::PasskeySave { site }.reason(Lang::En, browser),
            "save a passkey for “example.com” in Klav (from your browser)"
        );
        assert_eq!(
            Prompt::PasskeySave { site }.reason(Lang::Es, None),
            "guardar una passkey de «example.com» en Klav"
        );
        // Loosening the verification window (ADR 0020 §8).
        assert_eq!(
            Prompt::PasskeyWindow.reason(Lang::En, browser),
            "let your passkeys sign in without asking every time (from your browser)"
        );
        assert_eq!(
            Prompt::PasskeyWindow.reason(Lang::Es, Some(Source::App)),
            "dejar que tus passkeys inicien sesión sin preguntar cada vez (desde la app de Klav)"
        );
    }

    #[test]
    fn grants_tasks_and_offers() {
        let one = ["Personal/Release".to_owned()];
        let two = ["Personal/Release".to_owned(), "Work/API".to_owned()];
        let five: Vec<String> = (1..=5).map(|i| format!("Work/P{i}")).collect();
        let grant = |places: &[String], lang| {
            Prompt::Grant {
                agent: "release-mac",
                places,
            }
            .reason(lang, None)
        };
        assert_eq!(
            grant(&one, Lang::En),
            "give the agent “release-mac” access to Personal/Release"
        );
        assert_eq!(
            grant(&two, Lang::Es),
            "dar al agente «release-mac» acceso a Personal/Release y Work/API"
        );
        assert_eq!(
            grant(&five, Lang::En),
            "give the agent “release-mac” access to Work/P1, Work/P2 and 3 more"
        );
        assert_eq!(
            grant(&five, Lang::Es),
            "dar al agente «release-mac» acceso a Work/P1, Work/P2 y 3 más"
        );

        let task = |items, lang| {
            Prompt::Task {
                agent: "claude-code",
                items,
            }
            .reason(lang, None)
        };
        assert_eq!(
            task(3, Lang::En),
            "approve the task of “claude-code”: 3 items"
        );
        assert_eq!(
            task(1, Lang::En),
            "approve the task of “claude-code”: 1 item"
        );
        assert_eq!(
            task(3, Lang::Es),
            "aprobar la tarea de «claude-code»: 3 elementos"
        );
        assert_eq!(
            task(1, Lang::Es),
            "aprobar la tarea de «claude-code»: 1 elemento"
        );

        let add = |item, lang| {
            Prompt::AddToTask {
                agent: "claude-code",
                item,
            }
            .reason(lang, None)
        };
        assert_eq!(
            add(Some("GitHub"), Lang::En),
            "add “GitHub” to the task of “claude-code”"
        );
        assert_eq!(
            add(Some("GitHub"), Lang::Es),
            "añadir «GitHub» a la tarea de «claude-code»"
        );
        assert_eq!(
            add(None, Lang::En),
            "add an item to the task of “claude-code”"
        );

        let offer = |passwords, lang| {
            Prompt::Offer {
                agent: "claude-code",
                passwords,
            }
            .reason(lang, None)
        };
        assert_eq!(
            offer(4, Lang::En),
            "offer “claude-code” a task to change 4 passwords"
        );
        assert_eq!(
            offer(1, Lang::Es),
            "ofrecer a «claude-code» una tarea para cambiar 1 contraseña"
        );

        // Resuming after a pause (ADR 0033 P2).
        assert_eq!(
            Prompt::Resume {
                agent: Some("claude-code")
            }
            .reason(Lang::En, None),
            "let “claude-code” use Klav again"
        );
        assert_eq!(
            Prompt::Resume { agent: None }.reason(Lang::Es, Some(Source::App)),
            "dejar que tus agentes vuelvan a usar Klav (desde la app de Klav)"
        );

        // The credential proxy (ADR 0036 §14).
        assert_eq!(
            Prompt::ProxyUse {
                agent: Some("klav-proxy"),
                replaces: false,
            }
            .reason(Lang::En, None),
            "use “klav-proxy” as your credential proxy"
        );
        assert_eq!(
            Prompt::ProxyUse {
                agent: Some("klav-proxy"),
                replaces: true,
            }
            .reason(Lang::Es, None),
            "usar «klav-proxy» como tu proxy de credenciales y reemplazar las preferencias de la cuenta que escribió un agente"
        );
        assert_eq!(
            Prompt::ProxyUse {
                agent: None,
                replaces: true,
            }
            .reason(Lang::En, None),
            "stop using a credential proxy, replacing the account preferences an agent wrote"
        );
        let get = ["GET".to_owned()];
        let nf = ItemShown {
            title: "Northflank",
            place: "Personal/Infra",
            site: None,
        };
        let grant = |item, allowed, asked, paths, words, first_on_account| Prompt::ProxyGrant {
            agent: "klav-proxy",
            item,
            host: "api.northflank.com",
            port: None,
            header: None,
            field: None,
            allowed,
            asked,
            paths,
            words,
            first_on_account,
            issuers_losing: 0,
            issuers_keeping: 0,
        };
        let v1 = ["/v1/projects".to_owned()];
        let narrow = grant(nf, &get, &[], &v1, None, false);
        assert_eq!(
            narrow.reason(Lang::Es, Some(Source::Terminal)),
            "dejar que tu proxy de credenciales «klav-proxy» use «Northflank» (en «Personal/Infra») con api.northflank.com: GET, en /v1/projects. El agente nunca ve su valor (desde la terminal)"
        );
        let methods = ["GET".to_owned(), "POST".to_owned()];
        let asked = ["DELETE".to_owned(), "PATCH".to_owned()];
        let paths = ["/v1".to_owned(), "/v2/graphql".to_owned(), "/".to_owned()];
        let wide = grant(nf, &methods, &asked, &paths, None, false);
        assert_eq!(
            wide.reason(Lang::En, None),
            "let your credential proxy “klav-proxy” use “Northflank” (in “Personal/Infra”) with api.northflank.com: GET, POST; asking you first for DELETE, PATCH, on /v1, /v2/graphql, /. The agent never sees its value"
        );
        assert_ne!(narrow.reason(Lang::En, None), wide.reason(Lang::En, None));
        // A login shows its site; a port, header and field that are not
        // the usual ones are shown.
        let gh = ItemShown {
            title: "GitHub",
            place: "Personal/Dev",
            site: Some("github.com"),
        };
        let unusual = Prompt::ProxyGrant {
            agent: "klav-proxy",
            item: gh,
            host: "api.github.com",
            port: Some(8443),
            header: Some("x-api-key"),
            field: Some("token"),
            allowed: &get,
            asked: &[],
            paths: &v1,
            words: None,
            first_on_account: false,
            issuers_losing: 0,
            issuers_keeping: 0,
        };
        assert_eq!(
            unusual.reason(Lang::En, None),
            "let your credential proxy “klav-proxy” use “GitHub” (github.com, in “Personal/Dev”) with api.github.com:8443, in header x-api-key, from field “token”: GET, on /v1/projects. The agent never sees its value"
        );
        assert_eq!(
            unusual.reason(Lang::Es, None),
            "dejar que tu proxy de credenciales «klav-proxy» use «GitHub» (github.com, en «Personal/Dev») con api.github.com:8443, en la cabecera x-api-key, del campo «token»: GET, en /v1/projects. El agente nunca ve su valor"
        );
        // A long site keeps its end, which names it.
        let long = ItemShown {
            title: "SSO",
            place: "Work/IT",
            site: Some("login.microsoftonline.com.attacker-example.net"),
        };
        assert_eq!(
            long.show(Lang::En),
            "“SSO” (…icrosoftonline.com.attacker-example.net, in “Work/IT”)"
        );
        // Approving the pending proxy: the words of the key klavd fetched,
        // and, on the account's first per-item grant, what older devices
        // lose.
        let first = grant(
            nf,
            &get,
            &[],
            &v1,
            Some("acid bird cove dune echo fern"),
            true,
        );
        assert_eq!(
            first.reason(Lang::En, None),
            "approve the pending agent “klav-proxy” (words: acid bird cove dune echo fern) as your credential proxy and let it use “Northflank” (in “Personal/Infra”) with api.northflank.com: GET, on /v1/projects. The agent never sees its value. Devices without the latest Klav stop showing agents and requests"
        );
        assert_eq!(
            first.reason(Lang::Es, None),
            "aprobar el agente pendiente «klav-proxy» (palabras: acid bird cove dune echo fern) como tu proxy de credenciales y dejar que use «Northflank» (en «Personal/Infra») con api.northflank.com: GET, en /v1/projects. El agente nunca ve su valor. Los dispositivos sin la última versión de Klav dejan de mostrar agentes y solicitudes"
        );
        // An issuer: every profile and limit, the address, and the words
        // of a pending one.
        let profiles = ["northflank".to_owned(), "maple".to_owned()];
        let issuer = Prompt::ProxyIssuerAdd {
            issuer: "t3-code",
            proxy: "klav-proxy",
            address: "tls://proxy.example.com:8443",
            profiles: &profiles,
            max_ttl_secs: 8 * 3600,
            max_live: 3,
            words: Some("acid bird cove dune echo fern"),
            inject_ask: true,
            first_on_account: false,
        };
        assert_eq!(
            issuer.reason(Lang::En, None),
            "approve the pending agent “t3-code” (words: acid bird cove dune echo fern) and let it start sandboxes through your credential proxy “klav-proxy” at tls://proxy.example.com:8443: profiles northflank, maple, up to 3 at once, each for at most 8 h. Each `inject` of it will ask you first"
        );
        let narrow = ["maple".to_owned()];
        let active = Prompt::ProxyIssuerAdd {
            issuer: "t3-code",
            proxy: "klav-proxy",
            address: "tls://proxy.example.com:8443",
            profiles: &narrow,
            max_ttl_secs: 90 * 60,
            max_live: 1,
            words: None,
            inject_ask: false,
            first_on_account: true,
        };
        assert_eq!(
            active.reason(Lang::Es, None),
            "dejar que «t3-code» cree sandboxes con tu proxy de credenciales «klav-proxy» en tls://proxy.example.com:8443: perfiles maple, hasta 1 a la vez, cada uno por 90 min como mucho. Los dispositivos y proxies sin la última versión de Klav dejan de funcionar con agentes"
        );
        assert_eq!(
            Prompt::ProxyIssuerRemove {
                issuer: "t3-code",
                proxy: "klav-proxy"
            }
            .reason(Lang::En, None),
            "stop “t3-code” from starting sandboxes through your credential proxy “klav-proxy”"
        );

        // Text from outside is cleaned, never cut.
        let tricky = Prompt::ProxyGrant {
            agent: "klav-proxy",
            item: nf,
            host: "api.\u{202E}evil.com",
            port: None,
            header: None,
            field: None,
            allowed: &get,
            asked: &[],
            paths: &v1,
            words: None,
            first_on_account: false,
            issuers_losing: 0,
            issuers_keeping: 0,
        };
        assert!(!tricky.reason(Lang::En, None).contains('\u{202E}'));
        assert_eq!(
            Prompt::ProxyRevoke {
                agent: "klav-proxy",
                item: nf,
                issuers_losing: 0,
            }
            .reason(Lang::En, None),
            "take “Northflank” (in “Personal/Infra”) away from your credential proxy “klav-proxy”"
        );
        // An issuer that loses the profile is counted.
        assert_eq!(
            Prompt::ProxyRevoke {
                agent: "klav-proxy",
                item: nf,
                issuers_losing: 2,
            }
            .reason(Lang::Es, None),
            "quitarle «Northflank» (en «Personal/Infra») a tu proxy de credenciales «klav-proxy». 2 emisores de sandboxes pierden un perfil"
        );
        // The retry that only re-issues says so.
        let holders = ["ci".to_owned(), "deploy".to_owned()];
        assert_eq!(
            Prompt::ProxyReissue {
                item: nf,
                agents: &holders,
            }
            .reason(Lang::En, None),
            "finish re-issuing “Northflank” (in “Personal/Infra”) to agents “ci” and “deploy”"
        );
        assert_eq!(
            Prompt::ProxyReissue {
                item: nf,
                agents: &holders[..1],
            }
            .reason(Lang::Es, None),
            "terminar de darle «Northflank» (en «Personal/Infra») con su clave nueva al agente «ci»"
        );
    }

    /// The longest issuer dialog: a pending issuer, the account's first,
    /// 6 profiles of 32 characters, a 255-byte address, the inject
    /// sentence and the source.
    #[test]
    fn the_longest_issuer_dialog() {
        let long = |c: char, n: usize| std::iter::repeat_n(c, n).collect::<String>();
        let name = long('n', 64);
        let profiles: Vec<String> = ('a'..='f').map(|c| long(c, 32)).collect();
        let address = format!("tls://{}.example.com:65535", long('h', 255 - 24));
        assert_eq!(address.len(), 255);
        let longest = klav_core::generator::wordlist()
            .iter()
            .max_by_key(|w| w.chars().count())
            .expect("words");
        let words = [*longest; 6].join(" ");
        let prompt = Prompt::ProxyIssuerAdd {
            issuer: &name,
            proxy: &name,
            address: &address,
            profiles: &profiles,
            max_ttl_secs: 23 * 3600 + 59 * 60,
            max_live: 50,
            words: Some(&words),
            inject_ask: true,
            first_on_account: true,
        };
        let en = prompt.reason(Lang::En, Some(Source::Terminal));
        // The longest source in each language.
        let es = prompt.reason(Lang::Es, Some(Source::App));
        // Nothing of what it signs is cut: the whole address and every
        // profile.
        for text in [&en, &es] {
            assert!(text.contains(&address), "{text}");
            assert!(profiles.iter().all(|p| text.contains(p.as_str())));
        }
        assert_eq!(
            (en.chars().count(), es.chars().count()),
            (884, 918),
            "the longest dialog"
        );
    }

    /// The longest grant dialogs, every piece at its cap, with the source.
    /// There are two forms, and each is measured at its own worst case:
    ///
    /// - a pending proxy's first grant shows its words and can be the
    ///   account's first per-item grant, but has no issuers yet (they are
    ///   listed in the proxy's grant, which does not exist);
    /// - a proxy with a grant shows no words and is never the account's
    ///   first (it holds items), but can count issuers that lose a profile
    ///   (from an item that dropped out) and issuers that keep this one.
    ///   Nothing caps how many issuers a proxy has: the bound is the count
    ///   itself, a `usize` printed in decimal, at most 20 digits.
    ///
    /// Touch ID was never seen showing a reason this long (see the PR).
    #[test]
    fn the_longest_grant_dialog() {
        let long = |c: char, n: usize| std::iter::repeat_n(c, n).collect::<String>();
        let name = long('n', 64);
        let title = long('t', 200);
        let place = long('p', 200);
        let site = format!("{}.com", long('s', 60));
        let host = long('h', 64);
        // MAX_GRANT_HEADER_LEN for both.
        let header = long('x', 32);
        let field = long('f', 32);
        // MAX_GRANT_METHODS of the longest a rule takes: a method is any
        // 1 to 16 upper-case letters, not only the usual ones. Some asking.
        let allowed = [long('A', 16), long('B', 16)];
        let asked = [long('C', 16), long('D', 16)];
        // MAX_GRANT_PATHS of MAX_GRANT_PATH_LEN.
        let paths = [long('a', 32), long('b', 32), long('c', 32)];
        // Six times the longest word of the list.
        let longest = klav_core::generator::wordlist()
            .iter()
            .max_by_key(|w| w.chars().count())
            .expect("words");
        let words = [*longest; 6].join(" ");
        let form = |words: Option<&str>, first_on_account: bool, issuers: usize| {
            let prompt = Prompt::ProxyGrant {
                agent: &name,
                item: ItemShown {
                    title: &title,
                    place: &place,
                    site: Some(&site),
                },
                host: &host,
                port: Some(65535),
                header: Some(&header),
                field: Some(&field),
                allowed: &allowed,
                asked: &asked,
                paths: &paths,
                words,
                first_on_account,
                issuers_losing: issuers,
                issuers_keeping: issuers,
            };
            // The longest source in each language.
            (
                prompt
                    .reason(Lang::En, Some(Source::Terminal))
                    .chars()
                    .count(),
                prompt.reason(Lang::Es, Some(Source::App)).chars().count(),
            )
        };
        assert_eq!(form(Some(&words), true, 0), (793, 832), "a pending proxy");
        assert_eq!(form(None, false, usize::MAX), (749, 784), "with issuers");
    }

    /// Each issuer sentence of a grant, in both languages, one and many.
    #[test]
    fn a_grant_counts_the_issuers_that_lose_or_keep_the_profile() {
        let get = ["GET".to_owned()];
        let v1 = ["/v1".to_owned()];
        let nf = ItemShown {
            title: "Northflank",
            place: "Personal/Infra",
            site: None,
        };
        let grant = |losing, keeping| Prompt::ProxyGrant {
            agent: "klav-proxy",
            item: nf,
            host: "api.northflank.com",
            port: None,
            header: None,
            field: None,
            allowed: &get,
            asked: &[],
            paths: &v1,
            words: None,
            first_on_account: false,
            issuers_losing: losing,
            issuers_keeping: keeping,
        };
        let base_en = "let your credential proxy “klav-proxy” use “Northflank” (in “Personal/Infra”) with api.northflank.com: GET, on /v1. The agent never sees its value";
        let base_es = "dejar que tu proxy de credenciales «klav-proxy» use «Northflank» (en «Personal/Infra») con api.northflank.com: GET, en /v1. El agente nunca ve su valor";
        for (losing, keeping, en, es) in [
            (0, 0, "", ""),
            (
                1,
                0,
                ". 1 sandbox issuer loses a profile",
                ". 1 emisor de sandboxes pierde un perfil",
            ),
            (
                3,
                0,
                ". 3 sandbox issuers lose a profile",
                ". 3 emisores de sandboxes pierden un perfil",
            ),
            (
                0,
                1,
                ". 1 sandbox issuer keeps this profile, with these rules",
                ". 1 emisor de sandboxes conserva este perfil, con estas reglas",
            ),
            (
                1,
                2,
                ". 1 sandbox issuer loses a profile. 2 sandbox issuers keep this profile, with these rules",
                ". 1 emisor de sandboxes pierde un perfil. 2 emisores de sandboxes conservan este perfil, con estas reglas",
            ),
        ] {
            let prompt = grant(losing, keeping);
            assert_eq!(prompt.reason(Lang::En, None), format!("{base_en}{en}"));
            assert_eq!(prompt.reason(Lang::Es, None), format!("{base_es}{es}"));
        }
        // A revoke, one issuer.
        let revoke = Prompt::ProxyRevoke {
            agent: "klav-proxy",
            item: nf,
            issuers_losing: 1,
        };
        assert_eq!(
            revoke.reason(Lang::En, None),
            "take “Northflank” (in “Personal/Infra”) away from your credential proxy “klav-proxy”. 1 sandbox issuer loses a profile"
        );
        assert_eq!(
            revoke.reason(Lang::Es, None),
            "quitarle «Northflank» (en «Personal/Infra») a tu proxy de credenciales «klav-proxy». 1 emisor de sandboxes pierde un perfil"
        );
    }

    #[test]
    fn unlock_and_the_source() {
        let unlock = Prompt::Unlock {
            email: "ana@example.com",
        };
        assert_eq!(
            unlock.reason(Lang::En, None),
            "unlock your vault (ana@example.com)"
        );
        assert_eq!(
            unlock.reason(Lang::En, Some(Source::Browser)),
            "unlock your vault for your browser (ana@example.com)"
        );
        assert_eq!(
            unlock.reason(Lang::En, Some(Source::Terminal)),
            "unlock your vault for the terminal (ana@example.com)"
        );
        assert_eq!(
            unlock.reason(Lang::Es, Some(Source::App)),
            "desbloquear tu bóveda para la app de Klav (ana@example.com)"
        );
        assert_eq!(
            unlock.reason(Lang::Es, Some(Source::Browser)),
            "desbloquear tu bóveda para tu navegador (ana@example.com)"
        );
        let fill = Prompt::Request {
            agent: "claude-code",
            permission: Permission::Fill,
            target: Some("GitHub"),
        };
        assert_eq!(
            fill.reason(Lang::En, Some(Source::Browser)),
            "let “claude-code” fill “GitHub” (from your browser)"
        );
        assert_eq!(
            fill.reason(Lang::Es, Some(Source::Terminal)),
            "dejar que «claude-code» rellene «GitHub» (desde la terminal)"
        );
    }

    #[test]
    fn the_source_comes_from_the_executable_path() {
        let cargo = PathBuf::from("/Users/ana/.cargo/bin");
        let app = PathBuf::from("/Applications/Klav.app/Contents/Helpers");
        let of = |peer: &str, klavd: &Path| Source::of_executable(Path::new(peer), Some(klavd));
        // The browser's host next to klavd, or in the app's helpers.
        assert_eq!(
            of("/Users/ana/.cargo/bin/klav-native-host", &cargo),
            Some(Source::Browser)
        );
        assert_eq!(
            of(
                "/Applications/Klav.app/Contents/Helpers/klav-native-host",
                &cargo
            ),
            Some(Source::Browser)
        );
        assert_eq!(
            of(
                "/Applications/Klav.app/Contents/Helpers/klav-native-host",
                &app
            ),
            Some(Source::Browser)
        );
        // The app's klavd runs from its own bundle (Helpers/klavd.app, so
        // the dialog says Klav): the helpers next to that bundle still count.
        let bundled =
            PathBuf::from("/Applications/Klav.app/Contents/Helpers/klavd.app/Contents/MacOS");
        assert_eq!(
            of(
                "/Applications/Klav.app/Contents/Helpers/klav-native-host",
                &bundled
            ),
            Some(Source::Browser)
        );
        assert_eq!(
            of("/Applications/Klav.app/Contents/Helpers/klav", &bundled),
            Some(Source::Terminal)
        );
        assert_eq!(
            of(
                "/Applications/Klav.app/Contents/Helpers/klavd.app/Contents/MacOS/klavd",
                &bundled
            ),
            None
        );
        // A host somewhere else is not claimed.
        assert_eq!(of("/tmp/x/klav-native-host", &cargo), None);
        assert_eq!(
            of("/tmp/.app/Contents/Helpers/klav-native-host", &cargo),
            None
        );
        // The command line, wherever it lives.
        assert_eq!(
            of("/Users/ana/.cargo/bin/klav", &app),
            Some(Source::Terminal)
        );
        assert_eq!(
            of("/Applications/Klav.app/Contents/Helpers/klav", &app),
            Some(Source::Terminal)
        );
        // The Mac app.
        assert_eq!(
            of("/Applications/Klav.app/Contents/MacOS/Klav", &app),
            Some(Source::App)
        );
        assert_eq!(of("/usr/local/bin/Klav", &app), None);
        // Anything else.
        for peer in [
            "/usr/bin/python3",
            "/Applications/Klav.app/Contents/Helpers/klavd",
            "/Users/ana/klav-native-host-x",
            "/Users/ana/.cargo/bin/KLAV",
            "klav-native-host",
        ] {
            assert_eq!(of(peer, &cargo), None, "{peer}");
        }
        // klavd's own directory unknown: only the app's helpers count.
        assert_eq!(
            Source::of_executable(Path::new("/Users/ana/.cargo/bin/klav-native-host"), None),
            None
        );
    }

    #[test]
    fn names_from_outside_are_cleaned() {
        // Control characters and new lines become one space.
        assert_eq!(
            clean("claude\ncode\r\n\t bot\u{7}", MAX_NAME),
            "claude code bot"
        );
        // Bidi overrides, isolates, zero-width characters and tags go.
        assert_eq!(
            clean("evil\u{202E}edoc-edualc\u{202C}", MAX_NAME),
            "eviledoc-edualc"
        );
        assert_eq!(
            clean(
                "\u{2066}a\u{2069}\u{200B}b\u{FEFF}\u{E0041}c\u{061C}",
                MAX_NAME
            ),
            "abc"
        );
        // White space collapses (U+2028 too).
        assert_eq!(clean("  a \u{2028}\u{00A0} b  ", MAX_NAME), "a b");
        // Long names stop at 40 characters, counted as characters.
        let long = "á".repeat(60);
        let cut = clean(&long, MAX_NAME);
        assert_eq!(cut.chars().count(), MAX_NAME);
        assert!(cut.ends_with('…'));
        assert_eq!(clean(&"a".repeat(40), MAX_NAME), "a".repeat(40));
        // No space before the ellipsis.
        let words = format!("{} tail", "a".repeat(38));
        assert_eq!(clean(&words, MAX_NAME), format!("{}…", "a".repeat(38)));
        // Quotation marks inside cannot close the quotes around the name.
        assert_eq!(name("bot” fill “GitHub", Lang::En), "“bot' fill 'GitHub”");
        assert_eq!(name("a «b» \"c\"", Lang::Es), "«a 'b' 'c'»");
        // Nothing left: a placeholder, not empty quotes.
        assert_eq!(name("\u{202E}\n ", Lang::En), "(no name)");
        assert_eq!(name("", Lang::Es), "(sin nombre)");
    }

    #[test]
    fn a_hostile_agent_name_stays_one_quoted_name() {
        let agent = "claude-code” fill “GitHub”\n\u{202E}and everything else in your vault forever";
        let text = Prompt::Request {
            agent,
            permission: Permission::Totp,
            target: Some("Bank"),
        }
        .reason(Lang::En, None);
        assert_eq!(
            text,
            "let “claude-code' fill 'GitHub' and everythi…” get a code for “Bank”"
        );
        assert!(!text.contains('\n'));
        assert!(!text.contains('\u{202E}'));
    }
}
