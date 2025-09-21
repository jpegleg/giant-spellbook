use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

const GREY: &str = "\x1b[90m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

pub fn colorless_file_diff<P: AsRef<Path>>(a: P, b: P) -> io::Result<()> {
    let mut ra = BufReader::new(File::open(a)?);
    let mut rb = BufReader::new(File::open(b)?);

    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();

    loop {
        let read_a = read_line_bytes(&mut ra, &mut buf_a)?;
        let read_b = read_line_bytes(&mut rb, &mut buf_b)?;

        if read_a == 0 && read_b == 0 {
            break;
        }

        let mut la = buf_a.clone();
        let mut lb = buf_b.clone();
        strip_line_endings(&mut la);
        strip_line_endings(&mut lb);

        if la == lb {
            continue;
        }

        print_colorless_line(b"- ", &la)?;
        print_colorless_line(b"+ ", &lb)?;
    }

    Ok(())
}

pub fn file_diff<P: AsRef<Path>>(a: P, b: P) -> io::Result<()> {
    let mut ra = BufReader::new(File::open(a)?);
    let mut rb = BufReader::new(File::open(b)?);

    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();

    loop {
        let read_a = read_line_bytes(&mut ra, &mut buf_a)?;
        let read_b = read_line_bytes(&mut rb, &mut buf_b)?;

        if read_a == 0 && read_b == 0 {
            break;
        }

        let mut la = buf_a.clone();
        let mut lb = buf_b.clone();
        strip_line_endings(&mut la);
        strip_line_endings(&mut lb);

        if la == lb {
            continue;
        }

        print_colored_line(b"- ", &la, &lb)?;
        print_colored_line(b"+ ", &lb, &la)?;
    }

    Ok(())
}

fn read_line_bytes<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
    buf.clear();
    r.read_until(b'\n', buf)
}

fn strip_line_endings(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
}

fn print_colored_line(prefix: &[u8], this: &[u8], other: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    out.write_all(prefix)?;
    let mut last_style: Option<&'static str> = None;

    for i in 0..this.len() {
        let style = if i < other.len() && this[i] == other[i] { GREY } else { YELLOW };
        if last_style != Some(style) {
            out.write_all(style.as_bytes())?;
            last_style = Some(style);
        }
        out.write_all(&[this[i]])?;
    }

    if last_style.is_some() {
        out.write_all(RESET.as_bytes())?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

fn print_colorless_line(prefix: &[u8], this: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    out.write_all(prefix)?;

    for i in 0..this.len() {
        out.write_all(&[this[i]])?;
    }

    out.write_all(b"\n")?;
    Ok(())
}
