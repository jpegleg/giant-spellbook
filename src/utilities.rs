use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

#[allow(dead_code)]
pub fn write_and_replace(path: &str, bytes: &[u8]) -> io::Result<()> {
    let p = Path::new(path);
    let tmp_name = format!("{}.tmp", path);
    let mut f = File::create(&tmp_name)?;
    f.write_all(bytes)?;
    f.sync_all()?;

    match fs::rename(&tmp_name, &p) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(&tmp_name);
            Ok(())
        }
    }
}

#[allow(dead_code)]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1F => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04X}", b);
            }
            _ => out.push(b as char),
        }
    }
    out
}
