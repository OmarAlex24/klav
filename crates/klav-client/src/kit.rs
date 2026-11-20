//! The emergency kit (spec §4.2). A plain-text rendering: PDF output is left
//! to graphical clients.

use std::path::Path;

use klav_core::crypto::secret_key::EmergencyKit;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};

/// The kit as text. Contains the Secret Key: write it only to a private
/// file or the user's terminal, never to logs.
pub fn render(kit: &EmergencyKit) -> Zeroizing<String> {
    let secret = kit.secret_key().to_text();
    Zeroizing::new(format!(
        "KLAV EMERGENCY KIT\n\
         ===================\n\
         \n\
         Keep this somewhere safe (printed, or in a place only you can open).\n\
         You need it, together with your master password, to log in on a new\n\
         device. Nobody can recover your account without it, not even the\n\
         server operator.\n\
         \n\
         Server:     {server}\n\
         E-mail:     {email}\n\
         Account ID: {account}\n\
         Secret Key: {secret}\n\
         \n\
         Master password: ______________________________ (write it here if\n\
         you keep this kit offline)\n",
        server = kit.server_url,
        email = kit.email,
        account = kit.account_id,
        secret = secret.expose_secret(),
    ))
}

/// Writes the kit to a **new** file with mode 0600 (never overwrites).
pub fn write_new(kit: &EmergencyKit, path: &Path) -> ClientResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ClientError::Invalid(format!("{} already exists", path.display()))
        } else {
            e.into()
        }
    })?;
    file.write_all(render(kit).as_bytes())?;
    file.sync_all()?;
    Ok(())
}
