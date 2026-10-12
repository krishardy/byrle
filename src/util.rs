//! Helpers shared between modules.

pub mod lru;

/// `bytes` in lowercase hex, two digits each.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A zip member's name. zip 9 reads a name that is not UTF-8 as CP437, which maps every
/// byte at or above 0x80 to a character, so the decoding it reports as fallible never fails.
pub fn zip_name<R: std::io::Read>(entry: &zip::read::ZipFile<'_, R>) -> String {
    entry
        .name()
        .expect("zip decodes a name that is not UTF-8 as CP437, which every byte is")
        .into_owned()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_support;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::io::Write;

    /// A member named with byte 0x80, which is not UTF-8, reads as CP437's `Ç`.
    #[test]
    fn a_zip_name_that_is_not_utf8_reads_as_cp437() {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("aZb", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        let mut bytes = writer.finish().unwrap().into_inner();
        let mut patched = 0;
        for at in 0..bytes.len() - 2 {
            if &bytes[at..at + 3] == b"aZb" {
                bytes[at + 1] = 0x80;
                patched += 1;
            }
        }
        assert_eq!(patched, 2, "the local header and the central directory");
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(super::zip_name(&archive.by_index(0).unwrap()), "aÇb");
    }
}
