//! Secure Enclave checks. The prompt-free ones run everywhere (they are
//! no-ops without the shim); the Touch ID round trip needs a finger and is
//! `#[ignore]`: `cargo test -p klav-touchid -- --ignored`.

#[test]
fn queries_do_not_crash_and_report_consistently() {
    let available = klav_touchid::available();
    if !klav_touchid::compiled_in() {
        assert!(!available);
        assert_eq!(
            klav_touchid::create_key().unwrap_err(),
            klav_touchid::Error::Unavailable
        );
        assert!(klav_touchid::boot_time().is_none());
        return;
    }
    let boot = klav_touchid::boot_time().expect("boot time");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(boot > 1_000_000_000 && boot <= now);
    let _ = klav_touchid::screen_locked();
}

/// What the Touch ID prompt is built from: the Mac's language and the
/// executable of the program on the other end of klavd's socket.
#[test]
fn the_language_and_a_process_path() {
    let pid = i32::try_from(std::process::id()).expect("pid");
    if !klav_touchid::compiled_in() {
        assert!(klav_touchid::preferred_language().is_none());
        assert!(klav_touchid::process_path(pid).is_none());
        return;
    }
    let tag = klav_touchid::preferred_language().expect("a preferred language");
    assert!(
        !tag.is_empty() && tag.len() < 64 && tag.is_ascii(),
        "{tag:?}"
    );
    let own = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .expect("current exe");
    assert_eq!(klav_touchid::process_path(pid), Some(own));
    // A pid with no process.
    assert_eq!(klav_touchid::process_path(-1), None);
}

/// A device's name from its number, from many threads at once (finding 6
/// of the second layer-2 review): each call gets its own device's name,
/// never another call's. `devname(3)`'s static buffer would let them mix.
/// An unknown device number has no name.
#[test]
fn device_names_from_concurrent_calls_never_mix() {
    use std::os::unix::fs::MetadataExt;
    let rdev = |path: &str| {
        u32::try_from(std::fs::metadata(path).expect(path).rdev()).expect("device number")
    };
    let devices = [("null", rdev("/dev/null")), ("zero", rdev("/dev/zero"))];
    if !klav_touchid::compiled_in() {
        assert_eq!(klav_touchid::device_name(devices[0].1), None);
        return;
    }
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let (name, device) = devices[i % 2];
            std::thread::spawn(move || {
                for _ in 0..2_000 {
                    assert_eq!(klav_touchid::device_name(device).as_deref(), Some(name));
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a call got another device's name");
    }
    // A number no device has: nothing, or nothing `klavd` would show.
    let unknown = klav_touchid::device_name(0x7fff_0000 | 0x00ff);
    assert!(
        unknown
            .as_deref()
            .is_none_or(|n| n.starts_with('#') || n == "??"),
        "{unknown:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn creating_and_wrapping_need_no_prompt() {
    if !klav_touchid::available() {
        return; // no Secure Enclave or no enrolled fingers on this Mac
    }
    let key = klav_touchid::create_key().expect("create");
    assert!(!key.handle.is_empty());
    assert_eq!(key.public[0], 0x04);
    let a = klav_touchid::wrap(&key.public).expect("wrap");
    let b = klav_touchid::wrap(&key.public).expect("wrap");
    assert_ne!(a.ephemeral_public, b.ephemeral_public);
    assert_ne!(*a.secret, *b.secret);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a finger on the Touch ID sensor"]
fn touch_id_round_trip() {
    assert!(klav_touchid::available(), "Touch ID not available");
    let key = klav_touchid::create_key().expect("create");
    let wrap = klav_touchid::wrap(&key.public).expect("wrap");
    let secret = klav_touchid::unwrap(&key, &wrap.ephemeral_public, "test the Klav Touch ID shim")
        .expect("unwrap (touch the sensor)");
    assert_eq!(*secret, *wrap.secret);
}

/// Writes to the login keychain: run by hand on a Mac (`--ignored`), never
/// in CI.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "writes to the login keychain"]
fn keychain_round_trip() {
    let (service, account) = ("dev.klav.test", "keychain-round-trip");
    klav_touchid::keychain_store(service, account, b"kag1_test").expect("store");
    assert_eq!(
        klav_touchid::keychain_load(service, account)
            .expect("load")
            .as_slice(),
        b"kag1_test"
    );
    klav_touchid::keychain_delete(service, account).expect("delete");
    assert_eq!(
        klav_touchid::keychain_load(service, account).unwrap_err(),
        klav_touchid::Error::NotFound
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a finger on Touch ID"]
fn presence_prompt() {
    klav_touchid::authenticate("Klav test: touch to approve").expect("authenticate");
}
