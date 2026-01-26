use std::fs::File;
use std::io::{self, Read};
use rpassword::read_password;
use base64::{Engine as _};

use crate::disassemble;

const RESET: &str = "\x1b[0m";
const OVERLAP: usize = 15;

pub fn color_map() {
    let clr_cor = fg_rgb(255,107,107);
    let clr_trb = fg_rgb(160,216,239);
    let clr_ndi = fg_rgb(108,99,255);
    let clr_wgr = fg_rgb(214,211,209);
    let clr_eco = fg_rgb(163,201,168);
    let clr_ros = fg_rgb(243,161,191);

    println!("Color Map / Legend:");
    println!("  {}██{}  Printable ASCII (green)", clr_eco, RESET);
    println!("  {}██{}  Non-ASCII bytes (light pink)", clr_ros, RESET);
    println!("  {}██{}  ASCII control characters (coral orange)", clr_cor, RESET);
    println!("  {}██{}  Null bytes (light blue)", clr_trb, RESET);
    println!("  {}██{}  ELF/PE/Mach-O magic bytes (purple/indigo)", clr_ndi, RESET);
    println!("  {}██{}  Column separators / structure (grey)", clr_wgr, RESET);
    println!();
    println!("Symbol replacements:");
    println!("  {}◆{}  - ASCII control character (diamond symbol)", clr_cor, RESET);
    println!("  .  - Non-ASCII byte (period symbol)");
    println!("  {}✦{}  - Magic byte (star glyph symbol)", clr_ndi, RESET);
    println!();
    println!("Column meanings:");
    println!("  byte positions as u64 | hex | ascii | disassembly results");
    println!();
    println!("Session commands:");
    println!("  these commands can be typed (will not display) to print additional data");
    println!("  base64 - print the buffer segment as base64");
    println!("  binary - print the buffer segment as binary text");
    println!();
    println!("Tip:");
    println!("  press the enter key to print the next line");
    println!("  enter a number then press enter to jump to that number in the file data buffer");
    println!("  use control + c to end the session, or read through the end of the file");
    println!();

}

pub fn annotated_dump(path: &str) -> io::Result<()> {
    const RESET: &str = "\x1b[0m";
    let clr_cor = fg_rgb(255,107,107);
    let clr_trb = fg_rgb(160,216,239);
    let clr_ndi = fg_rgb(108,99,255);
    let clr_wgr = fg_rgb(214,211,209);
    let clr_eco = fg_rgb(163,201,168);
    let clr_ros = fg_rgb(243,161,191);
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    let hex_w = 64;
    let max_idx = buf.len().saturating_sub(1) as u64;
    let digits = dec_digits(max_idx);
    let dec_range_w = (2 + digits + 1 + digits + 1).max("Byte Range (u64,u64)".len());
    let is_elf = buf.starts_with(&[0x7F, b'E', b'L', b'F']);
    let is_pe  = buf.starts_with(&[0x4D, 0x5A]);
    let is_macho = is_macho_magic_prefix(&buf);
    let mut row = 0usize;

    while row * hex_w < buf.len().max(1) {
        let start = row * hex_w;
        if start >= buf.len() { break; }
        let end = (start + hex_w).min(buf.len());
        let last = end.saturating_sub(1);
        let range_dec = format!("({},{})", start, last);

        let hex_area = build_hex_area_styled(
            &buf[start..end],
            start as u64,
            hex_w,
            &clr_eco, &clr_ros, &clr_cor, &clr_trb, &clr_ndi, &clr_wgr, RESET,
            hex_w, is_elf, is_pe, is_macho,
        );

        let ascii_area = build_ascii_area_styled(
            &buf[start..end],
            start as u64,
            hex_w,
            &clr_eco, &clr_cor, &clr_trb, &clr_ros, &clr_ndi, RESET,
            is_elf, is_pe, is_macho,
        );

        let lookahead_end = (end + OVERLAP).min(buf.len());
        let dis_slice = &buf[start..lookahead_end];
        let base_addr = start as u64;
        let print_limit = end as u64;
        let printme1 = disassemble::intel_dis_segment_bounded(dis_slice, base_addr, print_limit)
            .unwrap_or_else(|_| String::from(""));

        let printme2 = printme1
            .replace(['\n', '\t'], " ")
            .replace("  ", " ");

        print!(" {}|{} ", &clr_wgr, RESET);
        print!("{:>drw$}", range_dec, drw = dec_range_w);
        print!(" {}|{} ", &clr_wgr, RESET);
        print!("{:<hexw$}", hex_area, hexw = hex_w);
        print!(" {}|{} ", &clr_wgr, RESET);
        println!("{}", ascii_area);
        print!(" {}|{} ", &clr_wgr, RESET);
        println!("{}", printme2.trim());

        let jumper = read_password()?;

        match jumper.parse::<String>() {
            Ok(val) if val == "binary" => {
                let out: String = dis_slice
                  .iter()
                  .map(|b| format!("[ {:08b} ]", b))
                  .collect::<Vec<_>>()
                  .join(" ");
                println!("{}\n", out);
            },
            Ok(val) if val == "base64" => {
                let out: String = base64::engine::general_purpose::STANDARD_NO_PAD
                  .encode(dis_slice);
                println!("{}\n", out);
            },

            _ => {
                match jumper.parse::<usize>() {
                  Ok(n) => row = n,
                  Err(_) => row += 1,
               }
            }
        }

    }

    Ok(())
}

fn fg_rgb(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{};{};{}m", r, g, b)
}

fn dec_digits(mut x: u64) -> usize {
    if x == 0 { return 1; }
    let mut d = 0; while x > 0 { x /= 10; d += 1; } d
}

fn visible_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut n = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i+1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' { i += 1; }
            if i < bytes.len() { i += 1; }
        } else {
            n += 1;
            i += 1;
        }
    }
    n
}

fn build_hex_area_styled(
    chunk: &[u8],
    base_off: u64,
    bytes_per_row: usize,
    hex_printable: &str,
    hex_nonascii: &str,
    hex_control: &str,
    hex_null: &str,
    hex_magic: &str,
    group_sep: &str,
    reset: &str,
    target_w: usize,
    is_elf: bool,
    is_pe: bool,
    is_macho: bool,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(target_w + 64);
    let n = chunk.len();
    for i in 0..bytes_per_row {
        if i < n {
            let b = chunk[i];
            let abs = base_off + i as u64;
            let is_magic = (is_elf && abs < 4) || (is_pe && abs < 2) || (is_macho && abs < 4);
            let color = if is_magic {
                hex_magic
            } else if b == 0x00 {
                hex_null
            } else if (0x20..=0x7E).contains(&b) {
                hex_printable
            } else if b < 0x20 || b == 0x7F {
                hex_control
            } else {
                hex_nonascii
            };
            let _ = write!(s, "{}{:02X}{}", color, b, reset);
        } else {
            s.push_str("  ");
        }
        let last = i + 1 == bytes_per_row;
        if !last {
            let at_group = (i + 1) % 8 == 0 && bytes_per_row >= 8;
            if at_group {
                let _ = write!(s, " {}|{} ", group_sep, reset);
            } else {
                s.push(' ');
            }
        }
    }
    let vis = visible_len(&s);
    if vis < target_w {
        s.push_str(&" ".repeat(target_w - vis));
    }
    s
}

fn build_ascii_area_styled(
    chunk: &[u8],
    base_off: u64,
    bytes_per_row: usize,
    ascii_printable: &str,
    ascii_control: &str,
    ascii_null: &str,
    ascii_nonascii: &str,
    ascii_magic: &str,
    reset: &str,
    is_elf: bool,
    is_pe: bool,
    is_macho: bool,
) -> String {
    let mut out = String::with_capacity(bytes_per_row * 6);
    for i in 0..bytes_per_row {
        if i < chunk.len() {
            let b = chunk[i];
            let abs = base_off + i as u64;
            let is_magic = (is_elf && abs < 4) || (is_pe && abs < 2) || (is_macho && abs < 4);
            let (color, ch) = if is_magic {
                (ascii_magic, if (0x20..=0x7E).contains(&b) { b as char } else { '✦' })
            } else if b == 0x00 {
                (ascii_null, '.')
            } else if (0x20..=0x7E).contains(&b) {
                (ascii_printable, b as char)
            } else if b < 0x20 || b == 0x7F {
                (ascii_control, '◆')
            } else {
                (ascii_nonascii, '.')
            };
            out.push_str(color);
            out.push(ch);
            out.push_str(reset);
        } else {
            out.push(' ');
        }
    }
    out
}

fn is_macho_magic_prefix(buf: &[u8]) -> bool {
    if buf.len() < 4 { return false; }
    let head = [buf[0], buf[1], buf[2], buf[3]];
    const MAGICS: [[u8; 4]; 8] = [
        [0xCE, 0xFA, 0xED, 0xFE],
        [0xCF, 0xFA, 0xED, 0xFE],
        [0xFE, 0xED, 0xFA, 0xCE],
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCA, 0xFE, 0xBA, 0xBE],
        [0xBE, 0xBA, 0xFE, 0xCA],
        [0xCA, 0xFE, 0xBA, 0xBF],
        [0xBF, 0xBA, 0xFE, 0xCA],
    ];
    MAGICS.contains(head)
}
