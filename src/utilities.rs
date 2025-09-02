use std::fs::{self, File, OpenOptions};
use std::io::{self, Write, Read, Seek, SeekFrom};
use std::cmp::min;
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
pub fn json_escape_type1(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[allow(dead_code)]
pub fn json_escape_type2(s: &str) -> String {
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

#[allow(dead_code)]
pub fn json_escape_type3(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[allow(dead_code)]
pub fn trim_file<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    const BUF_SIZE: usize = 256 * 1024;
    let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
    let mut len = f.metadata()?.len();
    if len == 0 {
        return Ok(0);
    }

    let mut buf = vec![0u8; BUF_SIZE];
    let mut new_len: Option<u64> = None;

    let mut offset: i128 = len as i128;
    while offset > 0 {
        let to_read = min(BUF_SIZE as u64, offset as u64) as usize;
        offset -= to_read as i128;

        f.seek(SeekFrom::Start(offset as u64))?;
        f.read_exact(&mut buf[..to_read])?;

        if let Some(last_nz) = buf[..to_read].iter().rposition(|&b| b != 0) {
            new_len = Some(offset as u64 + last_nz as u64 + 1);
            break;
        }
    }

    let target = new_len.unwrap_or(0);
    if target < len {
        f.set_len(target)?;
        len = target;
    }
    Ok(len)
}
