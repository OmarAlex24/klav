//! A master password as proof of presence (ADR 0041 §2.3): it counts only
//! when it is the password of the session unlocked in memory, never because
//! the files in the home open with it.

mod common;

use common::ServerProcess;
use klav_client::{ClientError, Home, SignupRequest, signup, unlock_with_password};
use klav_core::crypto::kdf::MasterPassword;
use klav_proto::auth::DeviceKind;

const PERSON: &str = "correct horse battery staple";
const THEIRS: &str = "a password the program chose";

/// The files `unlock_with_password` reads to open an account.
const FILES: [&str; 4] = ["account.json", "secret-key", "session.bin", "cache.bin"];

async fn account(server: &ServerProcess, home: &Home, email: &str, password: &str) {
    signup(
        home,
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(password),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
}

/// Moves `from`'s account files into `to`, keeping `to`'s in `aside`.
fn swap(to: &Home, from: &Home, aside: &std::path::Path) {
    std::fs::create_dir_all(aside).expect("aside");
    for name in FILES {
        std::fs::rename(to.file(name), aside.join(name)).expect("move aside");
        std::fs::copy(from.file(name), to.file(name)).expect("copy in");
    }
}

fn put_back(to: &Home, aside: &std::path::Path) {
    for name in FILES {
        std::fs::rename(aside.join(name), to.file(name)).expect("put back");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_counts_only_for_the_session_in_memory() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let person = Home::at(dir.path().join("person"));
    let scratch = Home::at(dir.path().join("scratch"));
    account(&server, &person, "ana@example.com", PERSON).await;
    account(&server, &scratch, "scratch@example.com", THEIRS).await;

    let session = unlock_with_password(&person, &MasterPassword::new(PERSON)).expect("unlock");
    let check = session.password_check().expect("check");
    check.check(&MasterPassword::new(PERSON)).expect("its own");
    assert!(matches!(
        check.check(&MasterPassword::new(THEIRS)),
        Err(ClientError::WrongCredentials)
    ));

    // A consistent set of files made under another password, in the
    // person's home: the files open with that password…
    let aside = dir.path().join("aside");
    swap(&person, &scratch, &aside);
    unlock_with_password(&person, &MasterPassword::new(THEIRS))
        .expect("the swapped files open with the program's password");
    // …and it still isn't this session's password.
    assert!(matches!(
        check.check(&MasterPassword::new(THEIRS)),
        Err(ClientError::WrongCredentials)
    ));
    // While swapped, the person's own fails too: the Secret Key on disk is
    // the program's. It fails closed.
    assert!(matches!(
        check.check(&MasterPassword::new(PERSON)),
        Err(ClientError::WrongCredentials)
    ));
    // A missing Secret Key is no proof either.
    std::fs::remove_file(person.file("secret-key")).unwrap();
    assert!(matches!(
        check.check(&MasterPassword::new(PERSON)),
        Err(ClientError::WrongCredentials)
    ));
    std::fs::copy(scratch.file("secret-key"), person.file("secret-key")).unwrap();

    // Put back, the person's password works again.
    for name in FILES {
        std::fs::remove_file(person.file(name)).unwrap();
    }
    put_back(&person, &aside);
    check.check(&MasterPassword::new(PERSON)).expect("put back");
    drop(session);
}
