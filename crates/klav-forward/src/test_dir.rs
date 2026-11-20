//! A test directory, shared by the library's tests and the binary's
//! (`skill`, which only the binary compiles).

/// A directory of its own for a test, removed when dropped (also when the
/// test fails).
pub(crate) struct TestDir(std::path::PathBuf);

impl TestDir {
    pub(crate) fn new() -> Self {
        let n: [u8; 8] = klav_core::crypto::random::array();
        let dir = std::env::temp_dir().join(format!(
            "klav-forward-test-{}",
            n.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&dir).expect("test dir");
        Self(dir)
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
