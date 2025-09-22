use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

const GREY: &str = "\x1b[90m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

#[rustfmt::skip]
static HEX_TABLE: [&str; 256] = [
    "\\x00","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\x07","\\x08","\\x09","\\x0A","\\x0B","\\x0C","\\x0D","\\x0E","\\x0F",
    "\\x10","\\x11","\\x12","\\x13","\\x14","\\x15","\\x16","\\x17","\\x18","\\x19","\\x1A","\\x1B","\\x1C","\\x1D","\\x1E","\\x1F",
    "\\x20","\\x21","\\x22","\\x23","\\x24","\\x25","\\x26","\\x27","\\x28","\\x29","\\x2A","\\x2B","\\x2C","\\x2D","\\x2E","\\x2F",
    "\\x30","\\x31","\\x32","\\x33","\\x34","\\x35","\\x36","\\x37","\\x38","\\x39","\\x3A","\\x3B","\\x3C","\\x3D","\\x3E","\\x3F",
    "\\x40","\\x41","\\x42","\\x43","\\x44","\\x45","\\x46","\\x47","\\x48","\\x49","\\x4A","\\x4B","\\x4C","\\x4D","\\x4E","\\x4F",
    "\\x50","\\x51","\\x52","\\x53","\\x54","\\x55","\\x56","\\x57","\\x58","\\x59","\\x5A","\\x5B","\\x5C","\\x5D","\\x5E","\\x5F",
    "\\x60","\\x61","\\x62","\\x63","\\x64","\\x65","\\x66","\\x67","\\x68","\\x69","\\x6A","\\x6B","\\x6C","\\x6D","\\x6E","\\x6F",
    "\\x70","\\x71","\\x72","\\x73","\\x74","\\x75","\\x76","\\x77","\\x78","\\x79","\\x7A","\\x7B","\\x7C","\\x7D","\\x7E","\\x7F",
    "\\x80","\\x81","\\x82","\\x83","\\x84","\\x85","\\x86","\\x87","\\x88","\\x89","\\x8A","\\x8B","\\x8C","\\x8D","\\x8E","\\x8F",
    "\\x90","\\x91","\\x92","\\x93","\\x94","\\x95","\\x96","\\x97","\\x98","\\x99","\\x9A","\\x9B","\\x9C","\\x9D","\\x9E","\\x9F",
    "\\xA0","\\xA1","\\xA2","\\xA3","\\xA4","\\xA5","\\xA6","\\xA7","\\xA8","\\xA9","\\xAA","\\xAB","\\xAC","\\xAD","\\xAE","\\xAF",
    "\\xB0","\\xB1","\\xB2","\\xB3","\\xB4","\\xB5","\\xB6","\\xB7","\\xB8","\\xB9","\\xBA","\\xBB","\\xBC","\\xBD","\\xBE","\\xBF",
    "\\xC0","\\xC1","\\xC2","\\xC3","\\xC4","\\xC5","\\xC6","\\xC7","\\xC8","\\xC9","\\xCA","\\xCB","\\xCC","\\xCD","\\xCE","\\xCF",
    "\\xD0","\\xD1","\\xD2","\\xD3","\\xD4","\\xD5","\\xD6","\\xD7","\\xD8","\\xD9","\\xDA","\\xDB","\\xDC","\\xDD","\\xDE","\\xDF",
    "\\xE0","\\xE1","\\xE2","\\xE3","\\xE4","\\xE5","\\xE6","\\xE7","\\xE8","\\xE9","\\xEA","\\xEB","\\xEC","\\xED","\\xEE","\\xEF",
    "\\xF0","\\xF1","\\xF2","\\xF3","\\xF4","\\xF5","\\xF6","\\xF7","\\xF8","\\xF9","\\xFA","\\xFB","\\xFC","\\xFD","\\xFE","\\xFF",
];

static UPPER_HEX: [&str; 256] = {
    const fn genhex() -> [&'static str; 256] {
        let mut arr: [&'static str; 256] = [""; 256];
        let mut i = 0;
        while i < 256 {
            arr[i] = HEX_TABLE[i];
            i += 1;
        }
        arr
    }
    genhex()
};

pub fn colorless_file_diff<P: AsRef<Path>>(a: P, b: P) -> io::Result<()> {
    let mut ra = BufReader::new(File::open(a)?);
    let mut rb = BufReader::new(File::open(b)?);
    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();
    let mut line_no: usize = 0;
    let mut off_a_total: usize = 0;
    let mut off_b_total: usize = 0;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    loop {
        buf_a.clear();
        buf_b.clear();

        let ra_n = ra.read_until(b'\n', &mut buf_a)?;
        let rb_n = rb.read_until(b'\n', &mut buf_b)?;

        if ra_n == 0 && rb_n == 0 {
            break;
        }
        line_no += 1;

        let base_a = off_a_total;
        let base_b = off_b_total;
        let mut la = buf_a.clone();
        let mut lb = buf_b.clone();
        strip_line_ending(&mut la);
        strip_line_ending(&mut lb);

        if la != lb {
            let (start_in_line, end_in_line) = diff_span(&la, &lb);
            let (ga_start, ga_end) = (base_a + start_in_line, base_a + end_in_line);
            let (gb_start, gb_end) = (base_b + start_in_line, base_b + end_in_line);
            write!(out, "{}, {}-{} < ", line_no, ga_start, ga_end)?;
            write_colorless(&mut out, &la)?;
            out.write_all(b"\n")?;
            write!(out, "{}, {}-{} > ", line_no, gb_start, gb_end)?;
            write_colorless(&mut out, &lb)?;
            out.write_all(b"\n")?;
        }

        off_a_total = off_a_total.saturating_add(ra_n);
        off_b_total = off_b_total.saturating_add(rb_n);
    }

    Ok(())
}

pub fn file_diff<P: AsRef<Path>>(a: P, b: P) -> io::Result<()> {
    let mut ra = BufReader::new(File::open(a)?);
    let mut rb = BufReader::new(File::open(b)?);
    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();
    let mut line_no: usize = 0;
    let mut off_a_total: usize = 0;
    let mut off_b_total: usize = 0;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    loop {
        buf_a.clear();
        buf_b.clear();

        let ra_n = ra.read_until(b'\n', &mut buf_a)?;
        let rb_n = rb.read_until(b'\n', &mut buf_b)?;

        if ra_n == 0 && rb_n == 0 {
            break;
        }
        line_no += 1;

        let base_a = off_a_total;
        let base_b = off_b_total;
        let mut la = buf_a.clone();
        let mut lb = buf_b.clone();
        strip_line_ending(&mut la);
        strip_line_ending(&mut lb);

        if la != lb {
            let (start_in_line, end_in_line) = diff_span(&la, &lb);
            let (ga_start, ga_end) = (base_a + start_in_line, base_a + end_in_line);
            let (gb_start, gb_end) = (base_b + start_in_line, base_b + end_in_line);
            write!(out, "{}, {}-{} < ", line_no, ga_start, ga_end)?;
            write_colored(&mut out, &la, &lb)?;
            out.write_all(b"\n")?;
            write!(out, "{}, {}-{} > ", line_no, gb_start, gb_end)?;
            write_colored(&mut out, &lb, &la)?;
            out.write_all(b"\n")?;
        }

        off_a_total = off_a_total.saturating_add(ra_n);
        off_b_total = off_b_total.saturating_add(rb_n);
    }

    Ok(())
}

fn strip_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
}

fn diff_span(a: &[u8], b: &[u8]) -> (usize, usize) {
    let min_len = a.len().min(b.len());
    let mut start = 0usize;
    while start < min_len && a[start] == b[start] {
        start += 1;
    }
    if start == a.len() && start == b.len() {
        return (0, 0);
    }
    let mut suf = 0usize;
    let max_back = a.len().saturating_sub(start).min(b.len().saturating_sub(start));
    while suf < max_back && a[a.len() - 1 - suf] == b[b.len() - 1 - suf] {
        suf += 1;
    }
    let end = usize::max(a.len(), b.len()).saturating_sub(1).saturating_sub(suf);
    (start, end)
}

fn write_colored<W: Write>(out: &mut W, this: &[u8], other: &[u8]) -> io::Result<()> {
    let mut last_style: Option<&'static str> = None;

    for i in 0..this.len() {
        let equal = i < other.len() && this[i] == other[i];
        let style = if equal { GREY } else { YELLOW };

        if last_style != Some(style) {
            out.write_all(style.as_bytes())?;
            last_style = Some(style);
        }

        if (0x20..=0x7E).contains(&this[i]) {
            out.write_all(&[this[i]])?;
        } else {
            let hex = UPPER_HEX[this[i] as usize];
            out.write_all(hex.as_bytes())?;
        }
    }

    if last_style.is_some() {
        out.write_all(RESET.as_bytes())?;
    }
    Ok(())
}

fn write_colorless<W: Write>(out: &mut W, this: &[u8]) -> io::Result<()> {
    for i in 0..this.len() {
        if (0x20..=0x7E).contains(&this[i]) {
            out.write_all(&[this[i]])?;
        } else {
            let hex = UPPER_HEX[this[i] as usize];
            out.write_all(hex.as_bytes())?;
        }
    }
    Ok(())
}
