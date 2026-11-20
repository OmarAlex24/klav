//! Klav core for WebAssembly: what the browser extension must compute
//! exactly as the Rust clients do (ADR 0017 §3).
//!
//! - the site rule ([`klav_core::site`]): which pages a login may be filled
//!   into, and how a page relates to a login (exact, subdomain or parent,
//!   ADR 0025);
//! - the password generator, with the sites' rules (ADR 0022 §1);
//! - reading a one-time code key the person pastes in the popup, as
//!   `klavd` will read it (only what the key says about itself, never the
//!   secret or a code).
//!
//! No vault cryptography lives here or in the extension: the vault stays in
//! `klavd`. Cryptography is never implemented in this crate; it is always
//! delegated to `klav-core`.

use secrecy::ExposeSecret;
use wasm_bindgen::prelude::*;

/// Version of `klav-core` this crate is built against.
#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    klav_core::VERSION.to_owned()
}

/// The page's host if Klav may fill into `url` (`https`, or `http` on this
/// machine); `undefined` otherwise.
#[wasm_bindgen(js_name = fillableHost)]
pub fn fillable_host(url: &str) -> Option<String> {
    klav_core::site::fillable_host(url).ok()
}

/// Whether the page `host` belongs to one of the item's URLs.
#[wasm_bindgen(js_name = hostMatches)]
pub fn host_matches(host: &str, item_urls: Vec<String>) -> bool {
    klav_core::site::host_matches(host, &item_urls)
}

/// How the page `host` relates to the item's URLs (ADR 0025 §3):
/// `"exact"`, `"subdomain"`, `"parent"` (a login saved for a subdomain of
/// the page: only when the person picks it), or `undefined`.
#[wasm_bindgen(js_name = hostRelation)]
pub fn host_relation(host: &str, item_urls: Vec<String>) -> Option<String> {
    use klav_core::site::HostRelation;
    klav_core::site::host_relation(host, &item_urls).map(|r| {
        match r {
            HostRelation::Exact => "exact",
            HostRelation::Subdomain => "subdomain",
            HostRelation::Parent => "parent",
        }
        .to_owned()
    })
}

/// Whether a login with `item_urls` may be filled into the page at `url`.
#[wasm_bindgen(js_name = pageMatches)]
pub fn page_matches(url: &str, item_urls: Vec<String>) -> bool {
    klav_core::site::page_matches(url, &item_urls).unwrap_or(false)
}

/// Checks a one-time code key the person pasted: an `otpauth://` URI or a
/// bare base32 secret, read by [`klav_core::totp::Totp::from_field_value`]
/// exactly as `klavd` reads it on `create`. Returns JSON with what the key
/// says about itself (`{issuer?, account?, digits, period}`), never the
/// secret or a code; an error says why it is not a key.
#[wasm_bindgen(js_name = totpCheck)]
pub fn totp_check(value: &str) -> Result<String, JsError> {
    let totp =
        klav_core::totp::Totp::from_field_value(value).map_err(|e| JsError::new(&e.to_string()))?;
    let mut out = serde_json::json!({ "digits": totp.digits(), "period": totp.period() });
    if let Some(issuer) = totp.issuer().filter(|s| !s.is_empty()) {
        out["issuer"] = issuer.into();
    }
    if let Some(account) = totp.account().filter(|s| !s.is_empty()) {
        out["account"] = account.into();
    }
    Ok(out.to_string())
}

/// Generates a password (ADR 0022 §1). `options` is a JSON
/// `GeneratorOptions` and `site` a JSON `SiteHints` (both may be `{}`).
/// Returns JSON: `{value, kind, bits, strength, rules?, limited,
/// fallback?}`.
#[wasm_bindgen]
pub fn generate(options: &str, site: &str) -> Result<String, JsError> {
    let options: klav_core::generator::GeneratorOptions =
        serde_json::from_str(options).map_err(|e| JsError::new(&e.to_string()))?;
    let site: klav_core::generator::SiteHints =
        serde_json::from_str(site).map_err(|e| JsError::new(&e.to_string()))?;
    let g = klav_core::generator::generate(&options, &site)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let out = serde_json::json!({
        "value": g.value.expose_secret(),
        "kind": g.kind,
        "bits": g.bits,
        "strength": g.strength,
        "rules": g.rules,
        "limited": g.limited,
        "fallback": g.fallback,
    });
    Ok(out.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_call_the_core() {
        assert_eq!(core_version(), klav_core::VERSION);
        assert_eq!(
            fillable_host("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert!(fillable_host("http://github.com/").is_none());
        assert!(page_matches(
            "https://gist.github.com/",
            vec!["github.com".into()]
        ));
        assert!(!page_matches(
            "https://github.com.evil.io/",
            vec!["github.com".into()]
        ));
        assert!(host_matches(
            "github.com",
            vec!["https://github.com".into()]
        ));
        assert_eq!(
            host_relation("1password.com", vec!["my.1password.com".into()]).as_deref(),
            Some("parent")
        );
        assert!(!host_matches(
            "1password.com",
            vec!["my.1password.com".into()]
        ));
        assert_eq!(host_relation("com", vec!["my.1password.com".into()]), None);
        let out: serde_json::Value = serde_json::from_str(&generate("{}", "{}").unwrap()).unwrap();
        assert_eq!(out["value"].as_str().map(str::len), Some(20));
        assert_eq!(out["strength"], "very_strong");
        let pin: serde_json::Value =
            serde_json::from_str(&generate(r#"{"kind":"pin","pin_length":8}"#, "{}").unwrap())
                .unwrap();
        assert_eq!(pin["value"].as_str().map(str::len), Some(8));
        let site: serde_json::Value =
            serde_json::from_str(&generate("{}", r#"{"host":"all.accor.com"}"#).unwrap()).unwrap();
        assert_eq!(site["rules"]["source"], "bundled");
        assert_eq!(site["rules"]["domain"], "accor.com");
    }

    #[test]
    fn totp_check_reads_keys_without_echoing_them() {
        let bare: serde_json::Value =
            serde_json::from_str(&totp_check(" jbsw y3dp ehpk 3pxp ").unwrap()).unwrap();
        assert_eq!(bare, serde_json::json!({"digits": 6, "period": 30}));
        let uri = "otpauth://totp/ACME:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60";
        let out = totp_check(uri).unwrap();
        assert!(!out.contains("JBSWY3DPEHPK3PXP"));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["issuer"], "ACME");
        assert_eq!(parsed["account"], "ana@example.com");
        assert_eq!(parsed["digits"], 8);
        assert_eq!(parsed["period"], 60);
    }
}
