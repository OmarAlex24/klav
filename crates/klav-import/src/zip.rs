//! A minimal ZIP reader: finds one entry by name through the central
//! directory and returns its bytes, stored or deflated (ADR 0024). Enough
//! for a `.1pux`, which only needs `export.data`. No ZIP64, no encryption.

use zeroize::Zeroizing;

use crate::ImportError;

const EOCD_SIG: u32 = 0x0605_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

fn bad(what: &str) -> ImportError {
    ImportError::Invalid(format!("damaged .1pux file ({what})"))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The uncompressed bytes of the entry called `name`, at most `limit`,
/// in a buffer wiped on drop. `Ok(None)` if the archive has no such entry;
/// an error if it has two (which one a reader picks differs, so the
/// archive is ambiguous).
pub(crate) fn read_entry(
    archive: &[u8],
    name: &str,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, ImportError> {
    // The end of central directory record is in the last 22 + 65535 bytes.
    let search_from = archive.len().saturating_sub(22 + 0xFFFF);
    let eocd = (search_from..archive.len().saturating_sub(21))
        .rev()
        .find(|&i| u32_at(archive, i) == Some(EOCD_SIG))
        .ok_or_else(|| bad("no central directory"))?;
    let count = usize::from(u16_at(archive, eocd + 10).ok_or_else(|| bad("short record"))?);
    let mut at = u32_at(archive, eocd + 16).ok_or_else(|| bad("short record"))? as usize;
    if at == 0xFFFF_FFFF {
        return Err(bad("ZIP64 is not supported"));
    }
    let mut found: Option<CentralEntry> = None;
    for _ in 0..count {
        if u32_at(archive, at) != Some(CENTRAL_SIG) {
            return Err(bad("central directory"));
        }
        let field = |off: usize| u16_at(archive, at + off).ok_or_else(|| bad("short entry"));
        let entry = CentralEntry {
            flags: field(8)?,
            method: field(10)?,
            compressed: u32_at(archive, at + 20).ok_or_else(|| bad("short entry"))? as usize,
            size: u32_at(archive, at + 24).ok_or_else(|| bad("short entry"))? as usize,
            local: u32_at(archive, at + 42).ok_or_else(|| bad("short entry"))? as usize,
        };
        let name_len = usize::from(field(28)?);
        let extra_len = usize::from(field(30)?);
        let comment_len = usize::from(field(32)?);
        let entry_name = archive
            .get(at + 46..at + 46 + name_len)
            .ok_or_else(|| bad("short entry"))?;
        at += 46 + name_len + extra_len + comment_len;
        if entry_name != name.as_bytes() {
            continue;
        }
        if found.is_some() {
            return Err(bad("two entries with the same name"));
        }
        found = Some(entry);
    }
    found.map(|e| e.read(archive, limit)).transpose()
}

/// What the central directory says of one entry.
struct CentralEntry {
    flags: u16,
    method: u16,
    compressed: usize,
    size: usize,
    local: usize,
}

impl CentralEntry {
    fn read(&self, archive: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>, ImportError> {
        if self.flags & 1 != 0 {
            return Err(bad("encrypted entry"));
        }
        if self.size > limit {
            return Err(ImportError::TooLarge);
        }
        let local = self.local;
        if u32_at(archive, local) != Some(LOCAL_SIG) {
            return Err(bad("local header"));
        }
        let local_name =
            usize::from(u16_at(archive, local + 26).ok_or_else(|| bad("local header"))?);
        let local_extra =
            usize::from(u16_at(archive, local + 28).ok_or_else(|| bad("local header"))?);
        let start = local + 30 + local_name + local_extra;
        let data = archive
            .get(
                start
                    ..start
                        .checked_add(self.compressed)
                        .ok_or_else(|| bad("size"))?,
            )
            .ok_or_else(|| bad("truncated entry"))?;
        match self.method {
            0 if data.len() == self.size => Ok(Zeroizing::new(data.to_vec())),
            0 => Err(bad("size mismatch")),
            8 => inflate(data, self.size),
            _ => Err(bad("unsupported compression")),
        }
    }
}

/// Inflates `data` into a buffer of exactly `size` bytes, allocated once:
/// growing it would free copies of the plaintext without wiping them.
fn inflate(data: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};

    let mut out = Zeroizing::new(vec![0u8; size]);
    let mut state = Box::<DecompressorOxide>::default();
    let (status, _, written) = decompress(
        &mut state,
        data,
        &mut out,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    match status {
        TINFLStatus::Done if written == size => Ok(out),
        // More output than the header said, or less.
        TINFLStatus::Done | TINFLStatus::HasMoreOutput => Err(bad("size mismatch")),
        _ => Err(bad("cannot inflate")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ZIP with the given `(name, content, deflate)` entries, written
    /// the way most archivers do (sizes in the headers, no data descriptor).
    pub(crate) fn build(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, content, deflate) in entries {
            let data = if *deflate {
                miniz_oxide::deflate::compress_to_vec(content, 6)
            } else {
                content.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let mut header = Vec::new();
            header.extend_from_slice(&LOCAL_SIG.to_le_bytes());
            header.extend_from_slice(&[20, 0, 0, 0]);
            header.extend_from_slice(&method.to_le_bytes());
            header.extend_from_slice(&[0; 8]); // time, date, crc (unchecked)
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
            header.extend_from_slice(&(content.len() as u32).to_le_bytes());
            header.extend_from_slice(&(name.len() as u16).to_le_bytes());
            header.extend_from_slice(&[0, 0]);
            header.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&header);
            out.extend_from_slice(&data);
            central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 8]);
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(content.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn stored_and_deflated_entries() {
        let big = "x".repeat(10_000);
        let zip = build(&[
            ("export.attributes", b"{}", false),
            ("export.data", big.as_bytes(), true),
            ("files/a.bin", b"\x00\x01", false),
        ]);
        assert_eq!(
            &read_entry(&zip, "export.data", 1 << 20).unwrap().unwrap()[..],
            big.as_bytes()
        );
        assert_eq!(
            &read_entry(&zip, "export.attributes", 10).unwrap().unwrap()[..],
            b"{}"
        );
        assert_eq!(read_entry(&zip, "missing", 10).unwrap(), None);
        assert_eq!(
            read_entry(&zip, "export.data", 100).err(),
            Some(ImportError::TooLarge)
        );
        assert!(read_entry(b"PK\x03\x04 not a zip", "export.data", 10).is_err());
        let truncated = &zip[..zip.len() - 30];
        assert!(read_entry(truncated, "export.data", 1 << 20).is_err());
    }

    #[test]
    fn refuses_a_second_entry_with_the_same_name() {
        // One reader would take the first and another the last: the
        // preview and what is imported could differ.
        let zip = build(&[
            ("export.data", b"{\"accounts\": []}", true),
            ("export.data", b"{\"accounts\": [{}]}", false),
        ]);
        assert_eq!(
            read_entry(&zip, "export.data", 1 << 20).err(),
            Some(bad("two entries with the same name"))
        );
        // The other entries still read.
        let zip = build(&[
            ("export.data", b"{}", false),
            ("files/a", b"x", false),
            ("files/b", b"y", false),
        ]);
        assert!(read_entry(&zip, "export.data", 10).unwrap().is_some());
    }

    #[test]
    fn the_declared_size_is_the_size() {
        let mut zip = build(&[("export.data", b"hello hello hello", true)]);
        // Shrink the size in the central directory (offset 24 of the
        // record): inflating must not write past it.
        let cd = zip
            .windows(4)
            .position(|w| w == CENTRAL_SIG.to_le_bytes())
            .unwrap();
        zip[cd + 24..cd + 28].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            read_entry(&zip, "export.data", 100).err(),
            Some(bad("size mismatch"))
        );
        zip[cd + 24..cd + 28].copy_from_slice(&50u32.to_le_bytes());
        assert_eq!(
            read_entry(&zip, "export.data", 100).err(),
            Some(bad("size mismatch"))
        );
    }
}
