//! Synthetic exports for tests and demos (feature `samples`). Every value
//! is made up; nothing comes from a real account. They are written to
//! `examples/import/` by `cargo run -p klav-import --features samples
//! --example import-samples` and read by the CLI, extension and iOS tests.
//!
//! Together they tell one story: Bitwarden first, then 1Password (one login
//! repeated with a newer password, one new), Google Authenticator in two
//! QR codes (one code joins the GitHub login, one stands alone, one is
//! HOTP) and Chrome (a repeat and a new login).

/// The account name used across the samples.
pub const USER: &str = "ana@example.com";

/// The passkey's private key in the Bitwarden sample: a synthetic P-256
/// key made for these samples with WebCrypto's `exportKey("pkcs8")`, in
/// base64url as Bitwarden exports it. It belongs to no one.
pub const SAMPLE_PASSKEY_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeGMd7qVrKhDv5XxmlAocElMjBvhgODgfDEdnAKElH_ehRANCAATfJ3JJecuIlnArBOh__25xF1O8ODTYr00TEAcEHzkxf2NY6f1MBegXGWha-zYISlnTdh8TOqqfpKrpc4cfFqt9";

/// A Bitwarden `.json` export (unencrypted).
pub fn bitwarden_json() -> String {
    format!(
        r#"{{
  "encrypted": false,
  "folders": [{{"id": "f-work", "name": "Work"}}],
  "items": [
    {{"id": "1", "type": 1, "name": "GitHub", "folderId": "f-work", "notes": null,
      "revisionDate": "2026-01-10T09:00:00.000Z", "deletedDate": null,
      "login": {{"uris": [{{"match": null, "uri": "https://github.com/login"}}],
                "username": "{USER}", "password": "sample-gh-2026", "totp": null}}}},
    {{"id": "2", "type": 1, "name": "Example Bank", "folderId": null,
      "revisionDate": "2026-02-01T12:00:00.000Z", "deletedDate": null,
      "passwordHistory": [{{"lastUsedDate": "2025-06-01T00:00:00.000Z", "password": "sample-bank-2025"}}],
      "login": {{"uris": [{{"match": null, "uri": "https://bank.example.com"}}],
                "username": "{USER}", "password": "sample-bank-2026", "totp": "JBSWY3DPEHPK3PXP"}}}},
    {{"id": "3", "type": 1, "name": "Passkey Shop", "folderId": null,
      "revisionDate": "2026-03-01T12:00:00.000Z", "deletedDate": null,
      "login": {{"uris": [{{"match": null, "uri": "https://shop.example.com"}}],
                "username": "{USER}", "password": "sample-shop-1",
                "fido2Credentials": [{{"credentialId": "b64.c2FtcGxl", "keyType": "public-key", "keyAlgorithm": "ECDSA",
                  "keyCurve": "P-256", "keyValue": "{SAMPLE_PASSKEY_KEY}", "rpId": "shop.example.com",
                  "userHandle": "dQ", "userName": "{USER}", "counter": "0", "discoverable": "true"}}]}}}},
    {{"id": "4", "type": 2, "name": "Wi-Fi at home", "notes": "Network: sample-net / key: sample-wifi-key",
      "secureNote": {{"type": 0}}, "deletedDate": null}},
    {{"id": "5", "type": 3, "name": "Sample Visa", "deletedDate": null,
      "card": {{"cardholderName": "Ana Sample", "brand": "Visa", "number": "4111111111111111",
               "expMonth": "7", "expYear": "2031", "code": "123"}}}},
    {{"id": "6", "type": 1, "name": "Old forum", "deletedDate": "2026-01-01T00:00:00.000Z",
      "login": {{"username": "ana", "password": "sample-trash"}}}}
  ]
}}
"#
    )
}

/// The JSON inside the `.1pux`.
fn onepux_data() -> String {
    format!(
        r#"{{"accounts": [{{"attrs": {{"name": "Ana Sample"}}, "vaults": [
  {{"attrs": {{"uuid": "v1", "name": "Private"}}, "items": [
    {{"uuid": "a1", "categoryUuid": "001", "state": "active", "updatedAt": 1777777777,
     "details": {{"loginFields": [
         {{"value": "{USER}", "name": "email", "fieldType": "E", "designation": "username"}},
         {{"value": "sample-bank-2026b", "name": "password", "fieldType": "P", "designation": "password"}}],
       "sections": [], "passwordHistory": []}},
     "overview": {{"title": "Example Bank", "url": "https://bank.example.com", "tags": ["finance"]}}}},
    {{"uuid": "a2", "categoryUuid": "001", "state": "active", "updatedAt": 1777777777,
     "details": {{"loginFields": [
         {{"value": "{USER}", "name": "email", "fieldType": "E", "designation": "username"}},
         {{"value": "sample-mail-1", "name": "password", "fieldType": "P", "designation": "password"}}],
       "sections": [{{"title": "", "fields": [
         {{"title": "recovery code", "id": "r1", "value": {{"concealed": "sample-recovery-123"}}}}]}}]}},
     "overview": {{"title": "Example Mail", "url": "https://mail.example.com"}}}}
  ]}}
]}}]}}"#
    )
}

/// A 1Password `.1pux` export.
pub fn onepux() -> Vec<u8> {
    zip(&[
        (
            "export.attributes",
            br#"{"version":3,"description":"1Password Unencrypted Export"}"#.to_vec(),
        ),
        ("export.data", onepux_data().into_bytes()),
    ])
}

/// Google Authenticator's export in two QR codes, as links.
pub fn google_links() -> [String; 2] {
    // (secret, name, issuer, algorithm, digits, type)
    let first = migration(
        &[
            (
                b"sample-github-otp!",
                &format!("GitHub:{USER}"),
                "GitHub",
                1,
                1,
                2,
            ),
            (b"sample-discord-otp", USER, "Discord", 1, 1, 2),
        ],
        0,
    );
    let second = migration(
        &[(b"sample-hotp-counter", "legacy", "Legacy VPN", 1, 1, 1)],
        1,
    );
    [first, second]
}

/// A Chrome (or Edge, Brave) CSV export.
pub fn chrome_csv() -> String {
    format!(
        "name,url,username,password,note\n\
         github.com,https://github.com/,{USER},sample-gh-2026,\n\
         news.example.com,https://news.example.com/login,{USER},sample-news-1,\n"
    )
}

/// A Firefox CSV export.
pub fn firefox_csv() -> String {
    format!(
        "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
         \"https://forum.example.com\",\"{USER}\",\"sample-forum-1\",,\"https://forum.example.com\",\"{{1}}\",\"1767225600000\",\"1767225600000\",\"1767225600000\"\n"
    )
}

/// A Safari CSV export.
pub fn safari_csv() -> String {
    format!(
        "Title,URL,Username,Password,Notes,OTPAuth\n\
         shop.example.com ({USER}),https://shop.example.com/,{USER},sample-shop-1,,\n"
    )
}

/// `(secret, name, issuer, algorithm, digits, type)`.
type Account<'a> = (&'a [u8], &'a str, &'a str, u64, u64, u64);

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_bytes(out: &mut Vec<u8>, number: u64, bytes: &[u8]) {
    put_varint(out, number << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_int(out: &mut Vec<u8>, number: u64, v: u64) {
    put_varint(out, number << 3);
    put_varint(out, v);
}

/// Code `index` (from 0) of a two-code export.
fn migration(accounts: &[Account<'_>], index: u64) -> String {
    let mut payload = Vec::new();
    for (secret, name, issuer, algorithm, digits, kind) in accounts {
        let mut p = Vec::new();
        put_bytes(&mut p, 1, secret);
        put_bytes(&mut p, 2, name.as_bytes());
        put_bytes(&mut p, 3, issuer.as_bytes());
        put_int(&mut p, 4, *algorithm);
        put_int(&mut p, 5, *digits);
        put_int(&mut p, 6, *kind);
        put_bytes(&mut payload, 1, &p);
    }
    put_int(&mut payload, 2, 1);
    put_int(&mut payload, 3, 2);
    put_int(&mut payload, 4, index);
    put_int(&mut payload, 5, 424_242);
    let b64 = data_encoding::BASE64.encode(&payload);
    let enc = percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC);
    format!("otpauth-migration://offline?data={enc}")
}

/// A ZIP of stored entries.
pub(crate) fn zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, content) in entries {
        let offset = out.len() as u32;
        let size = (content.len() as u32).to_le_bytes();
        let name_len = (name.len() as u16).to_le_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&size);
        out.extend_from_slice(&size);
        out.extend_from_slice(&name_len);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(content);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&size);
        central.extend_from_slice(&size);
        central.extend_from_slice(&name_len);
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// A PNG of `text` as a QR code (black on white, 6 px per module).
pub fn qr_png(text: &str) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    let code = qrcode::QrCode::new(text.as_bytes()).expect("the link fits in a QR code");
    let modules = code.width();
    let colors = code.to_colors();
    let (scale, quiet) = (6usize, 4usize);
    let side = (modules + 2 * quiet) * scale;
    let mut pixels = vec![255u8; side * side];
    for (i, c) in colors.iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (mx, my) = (i % modules + quiet, i / modules + quiet);
            for y in my * scale..(my + 1) * scale {
                pixels[y * side + mx * scale..y * side + (mx + 1) * scale].fill(0);
            }
        }
    }
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, side as u32, side as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        #[allow(clippy::expect_used)]
        let mut writer = encoder.write_header().expect("PNG header");
        #[allow(clippy::expect_used)]
        writer.write_image_data(&pixels).expect("PNG data");
    }
    out
}
