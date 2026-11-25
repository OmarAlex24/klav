//! Reading secrets: a hidden prompt on the controlling terminal, or lines
//! from stdin (`--password-stdin`, `--secret-stdin`). Never from argv.

use std::io::{BufRead, IsTerminal};

use zeroize::Zeroizing;

use crate::error::{CliResult, usage};

/// Ordered access to stdin lines and the TTY.
pub(crate) struct Input {
    password_stdin: bool,
    /// With `--password-stdin` the password is always the first line, even
    /// if another value is read before the password is needed.
    password_line: Option<Zeroizing<String>>,
    password_taken: bool,
    stdin: Option<std::io::StdinLock<'static>>,
}

/// Appends `bytes` to `out`, moving to a larger buffer by hand when it is
/// full: `Vec`'s own growth would free the old buffer without wiping it,
/// leaving copies of the secret behind.
fn push_wiped(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if out.capacity() - out.len() < bytes.len() {
        let wanted = (out.len() + bytes.len()).max(out.capacity() * 2).max(64);
        let mut bigger = Zeroizing::new(Vec::with_capacity(wanted));
        bigger.extend_from_slice(out);
        *out = bigger; // the old buffer is wiped as it drops
    }
    out.extend_from_slice(bytes);
}

/// The next line of `reader` without its `\n` (nor a `\r` before it), as
/// [`BufRead::lines`] gives it but in a buffer that is wiped; `None` at the
/// end.
fn next_line(reader: &mut impl BufRead) -> std::io::Result<Option<Zeroizing<String>>> {
    let mut line = Zeroizing::new(Vec::new());
    let mut ended = false;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let (take, newline) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        push_wiped(&mut line, &buf[..take]);
        reader.consume(take + usize::from(newline));
        if newline {
            ended = true;
            break;
        }
    }
    if line.is_empty() && !ended {
        return Ok(None);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let bytes = std::mem::take(&mut *line);
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stdin is not valid UTF-8",
            ))
        }
    }
}

impl Input {
    pub(crate) fn new(password_stdin: bool) -> Self {
        Self {
            password_stdin,
            password_line: None,
            password_taken: false,
            stdin: None,
        }
    }

    /// The master password comes from stdin (`--password-stdin`).
    pub(crate) fn password_from_stdin(&self) -> bool {
        self.password_stdin
    }

    fn reserve_password(&mut self) -> CliResult<()> {
        if self.password_stdin && !self.password_taken && self.password_line.is_none() {
            let line = self.raw_line("master password")?;
            self.password_line = Some(line);
        }
        Ok(())
    }

    /// The next line of stdin (without the line ending), after the
    /// password line when `--password-stdin` is set.
    pub(crate) fn stdin_line(&mut self, what: &str) -> CliResult<Zeroizing<String>> {
        self.reserve_password()?;
        self.raw_line(what)
    }

    fn raw_line(&mut self, what: &str) -> CliResult<Zeroizing<String>> {
        let stdin = self.stdin.get_or_insert_with(|| std::io::stdin().lock());
        match next_line(stdin)? {
            Some(mut line) => {
                // A second `\r` (`\r\r\n`) went with `trim_end_matches`.
                while line.ends_with('\r') {
                    line.pop();
                }
                Ok(line)
            }
            None => Err(usage(format!("stdin ended before the {what}"))),
        }
    }

    /// The rest of stdin.
    pub(crate) fn stdin_rest(&mut self) -> CliResult<Zeroizing<String>> {
        self.reserve_password()?;
        let stdin = self.stdin.get_or_insert_with(|| std::io::stdin().lock());
        let mut out = Zeroizing::new(Vec::new());
        let mut first = true;
        while let Some(line) = next_line(stdin)? {
            if !first {
                push_wiped(&mut out, b"\n");
            }
            first = false;
            push_wiped(&mut out, line.as_bytes());
        }
        let text = String::from_utf8(std::mem::take(&mut *out))
            .map_err(|_| usage("stdin is not valid UTF-8"))?;
        Ok(Zeroizing::new(text))
    }

    /// Asks on the TTY without echo.
    pub(crate) fn prompt_hidden(&self, prompt: &str) -> CliResult<Zeroizing<String>> {
        if !std::io::stderr().is_terminal() && !std::io::stdin().is_terminal() {
            return Err(usage(format!(
                "no terminal to ask for the {}; pipe it on stdin (see --password-stdin / --secret-stdin)",
                prompt.trim_end_matches(": ")
            )));
        }
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|e| usage(format!("cannot read from the terminal: {e}")))
    }

    /// A value that is not a long-lived secret, typed visibly on the
    /// terminal (an invite code, ADR 0048 §2): it can be pasted and checked
    /// by eye. Never read from a pipe, where it would take a line meant for
    /// the master password; `missing` says how to give it instead.
    pub(crate) fn prompt_visible(
        &mut self,
        prompt: &str,
        missing: &str,
    ) -> CliResult<Zeroizing<String>> {
        if self.password_stdin
            || !std::io::stdin().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            return Err(usage(missing));
        }
        eprint!("{prompt}");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let line = self.raw_line(prompt.trim_end_matches(": "))?;
        Ok(Zeroizing::new(line.trim().to_owned()))
    }

    /// The master password: stdin if `--password-stdin`, else the TTY.
    pub(crate) fn password(&mut self, prompt: &str) -> CliResult<Zeroizing<String>> {
        if self.password_stdin {
            self.password_taken = true;
            match self.password_line.take() {
                Some(line) => Ok(line),
                None => self.raw_line("master password"),
            }
        } else {
            self.prompt_hidden(prompt)
        }
    }

    /// A new master password, asked twice on a TTY.
    pub(crate) fn new_password(&mut self) -> CliResult<Zeroizing<String>> {
        let first = self.password("New master password: ")?;
        if !self.password_stdin {
            let again = self.prompt_hidden("Repeat it: ")?;
            if *first != *again {
                return Err(usage("the passwords do not match"));
            }
        }
        if first.chars().count() < 10 {
            return Err(usage("use a master password of at least 10 characters"));
        }
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_read_as_before_in_buffers_that_grow_by_hand() {
        // A tiny reader buffer forces many reads per line.
        let text = "first\r\nsecond\n\nlast without newline";
        let mut reader = std::io::BufReader::with_capacity(3, text.as_bytes());
        let mut got = Vec::new();
        while let Some(line) = next_line(&mut reader).unwrap() {
            got.push(line.to_string());
        }
        let expected: Vec<String> = text.as_bytes().lines().map(Result::unwrap).collect();
        assert_eq!(got, expected);
        let mut empty = std::io::BufReader::new(&b""[..]);
        assert!(next_line(&mut empty).unwrap().is_none());

        let mut out = Zeroizing::new(Vec::new());
        for _ in 0..100 {
            push_wiped(&mut out, b"0123456789");
        }
        assert_eq!(out.len(), 1000);
        assert!(out.capacity() >= 1000);
    }
}
