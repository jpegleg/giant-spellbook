use std::error::Error;
use std::cmp::min;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write, BufWriter, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{SecondsFormat, Utc};

#[path = "./utilities.rs"]
mod utilities;
use utilities::*;

const CHUNK_SIZE: usize = 4096;
const BUF_SIZE: usize = 8 * 1024 * 1024;

pub fn gen_entropy(entropy_size: usize, file_path: &str) -> Result<(), Box<dyn Error>> {
    let mut init_seed = [0u8; CHUNK_SIZE];
    let mut entropy_file = File::create(file_path)?;
    while entropy_size > entropy_file.metadata().unwrap().len().try_into().unwrap() {
      if entropy_size > CHUNK_SIZE {
        wormsign::randombytes(&mut init_seed, CHUNK_SIZE);
        entropy_file.write_all(&init_seed)?;
      } else {
        wormsign::randombytes(&mut init_seed, entropy_size);
        entropy_file.write_all(&init_seed)?;
      }
    }
    entropy_file.set_len(entropy_size.try_into().unwrap())?;
    Ok(())
}

pub fn flatten(path: &str) -> Result<(), Box<dyn Error>> {
    let file_path = Path::new(path);
    let tmp_path = file_path.with_extension("tmp");
    let mut contents = String::new();
    File::open(&file_path)?.read_to_string(&mut contents)?;
    let cleaned: String = contents.chars().filter(|c| !c.is_whitespace()).collect();
    let mut tmp_file = File::create(&tmp_path)?;
    tmp_file.write_all(cleaned.as_bytes())?;
    fs::rename(&tmp_path, &file_path)?;
    Ok(())
}

pub fn shift(path: &str, direction: &str, count_str: &str) {
    fn print_json(path: &str, result_msg: &str) {
        let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        println!(
            "{{\n  \"File\": \"{}\",\n  \"Date UTC\": \"{}\",\n  \"Result\": \"{}\"\n}}",
            path, ts, result_msg.replace('"', "\\\"")
        );
    }

    let count: usize = match count_str.parse() {
        Ok(v) => v,
        Err(_) => {
            print_json(
                path,
                &format!("ERROR - Invalid shift count '{}'", count_str),
            );
            return;
        }
    };

    let dir = direction.to_ascii_lowercase();
    if dir != "left" && dir != "right" {
        print_json(
            path,
            &format!("ERROR - Invalid direction '{}', expected 'left' or 'right'", direction),
        );
        return;
    }

    let data = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            print_json(path, &format!("ERROR - Failed to read file: {}", e));
            return;
        }
    };

    let len = data.len();

    if len == 0 {
        if count == 0 {
            print_json(path, &format!("File shifted {} by {}", dir, count));
        } else {
            print_json(path, "ERROR - Byte position was past the end of the file");
        }
        return;
    }

    if count > len {
        print_json(path, "ERROR - Byte position was past the end of the file");
        return;
    }

    if count == 0 || count == len {
        if let Err(e) = write_and_replace(path, &data) {
            print_json(path, &format!("ERROR - {}", e));
            return;
        }
        print_json(path, &format!("File shifted {} by {}", dir, count));
        return;
    }

    let shifted = if dir == "left" {
        let (head, tail) = data.split_at(count);
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(tail);
        out.extend_from_slice(head);
        out
    } else {
        let split = len - count;
        let (head, tail) = data.split_at(split);
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(tail);
        out.extend_from_slice(head);
        out
    };

    if let Err(e) = write_and_replace(path, &shifted) {
        print_json(path, &format!("ERROR - {}", e));
        return;
    }

    print_json(path, &format!("File shifted {} by {}", dir, count));
}

pub fn xor_these(file1: &str, file2: &str) -> io::Result<()> {
    let p1 = Path::new(file1);
    let p2 = Path::new(file2);
    let out_path = "./xor.out";

    let len1 = fs::metadata(p1)?.len();
    let len2 = fs::metadata(p2)?.len();

    let now = chrono::DateTime::<Utc>::from(SystemTime::now())
        .to_rfc3339_opts(SecondsFormat::Millis, true);

    if len1 != len2 {
        eprintln!(
                "{{\n  \"File 1\": \"{}\",\n  \"File 1 length in bytes\": {},\n  \"File 2\": \"{}\",\n  \"File 2 length in bytes\": {},\n  \"Date_UTC\": \"{}\",\n  \"ERROR\": \"Files must be the same length\"\n}}",
            json_escape(file1),
            len1,
            json_escape(file2),
            len2,
            now
        );
        return Ok(());
    }

    let f1 = File::open(p1)?;
    let f2 = File::open(p2)?;
    let mut r1 = BufReader::new(f1);
    let mut r2 = BufReader::new(f2);

    let out_file = File::create(out_path)?;
    let mut w = BufWriter::new(out_file);

    const BUF_SZ: usize = 64 * 1024;
    let mut b1 = vec![0u8; BUF_SZ];
    let mut b2 = vec![0u8; BUF_SZ];

    loop {
        let n1 = r1.read(&mut b1)?;
        let n2 = r2.read(&mut b2)?;
        if n1 == 0 && n2 == 0 {
            break;
        }
        if n1 != n2 {
            eprintln!(
                "{{\n \"File 1\": \"{}\",\n  \"File 1 length in bytes\": {},\n  \"File 2\": \"{}\",\n  \"File 2 length in bytes\": {},\n  \"Date_UTC\": \"{}\",\n  \"ERROR\": \"Files must be the same length\"\n}}",
                json_escape(file1), len1, json_escape(file2), len2, now
            );
            return Ok(());
        }

        for i in 0..n1 {
            b1[i] ^= b2[i];
        }
        w.write_all(&b1[..n1])?;
    }
    w.flush()?;

    println!(
        "{{\n  \"File 1\": \"{}\",\n  \"File 2\": \"{}\",\n  \"Output\": \"{}\",\n  \"Date_UTC\": \"{}\",\n  \"Result\": \"Files XOR'd\"\n}}",
        json_escape(file1),
        json_escape(file2),
        json_escape(out_path),
        now
    );

    Ok(())
}

pub fn precise_bitflip(path: &str, bit_pos_str: &str) -> Result<(), Box<dyn Error>> {
    let bit_pos: u64 = bit_pos_str.parse()?;
    flip_bit_in_file(path, bit_pos)
}

pub fn splitter(path: &str, bit_pos_str: &str) -> Result<(), Box<dyn Error>> {
    let bit_pos: u64 = bit_pos_str.parse()?;
    split_file(path, bit_pos)
}

pub fn bitflip(file_path: &str) -> Result<(), Box<dyn Error>> {
    let mut file_content = Vec::new();
    let mut input_file = File::open(file_path)?;
    input_file.read_to_end(&mut file_content)?;

    for byte in &mut file_content {
      *byte = !*byte;
    }

    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    let mut read_pos = 0;

    while read_pos < file_content.len() {
      let end = (read_pos + CHUNK_SIZE).min(file_content.len());
      let chunk = &file_content[read_pos..end];
      read_pos = end;
      output_file.write_all(chunk)?;
    }
    std::fs::rename(&temp_file_path, file_path)?;
    Ok(())
}

pub fn flip_bit_in_file(path: &str, bit_pos: u64) -> Result<(), Box<dyn Error>> {
    let byte_index = bit_pos / 8;
    let bit_offset = (bit_pos % 8) as u8;
    let mask = 1u8 << bit_offset;

    let original_path = Path::new(path);
    let temp_path = original_path.with_extension("tmp");

    let mut input = File::open(&original_path)?;
    let mut output = File::create(&temp_path)?;

    io::copy(&mut std::io::Write::by_ref(&mut std::io::Read::by_ref(&mut input)).take(byte_index), &mut output)?;

    let mut target_byte = [0u8; 1];
    let read = input.read(&mut target_byte)?;
    if read == 0 {
        return Err(format!("Bit position {} is past end of file", bit_pos).into());
    }
    target_byte[0] ^= mask;
    output.write_all(&target_byte)?;

    io::copy(&mut input, &mut output)?;

    output.flush()?;
    output.sync_all()?;

    match fs::rename(&temp_path, &original_path) {
        Ok(()) => {}
        Err(e) => {
            if original_path.exists() {
                fs::remove_file(&original_path)?;
            }
            fs::rename(&temp_path, &original_path).map_err(|e2| {
                format!("Failed to replace original file: {e}; fallback error: {e2}")
            })?;
        }
    }

    Ok(())
}

pub fn split_file(path: &str, bit_pos: u64) -> Result<(), Box<dyn Error>> {
    let input_path = Path::new(path);

    let mut input = File::open(&input_path)?;
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    let total_bits = (data.len() as u64) * 8;
    if bit_pos > total_bits {
        return Err(format!(
            "Bit position {} is past end of file ({} bits total)",
            bit_pos, total_bits
        ).into());
    }

    let file_name = input_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid UTF-8 in filename")?;
    let dir = input_path.parent().unwrap_or_else(|| Path::new(""));

    let first_path = dir.join(format!("{file_name}__first"));
    let second_path = dir.join(format!("{file_name}__second"));

    let mut first = File::create(&first_path)?;
    let mut second = File::create(&second_path)?;

    let byte_index = (bit_pos / 8) as usize;
    let bit_offset = (bit_pos % 8) as u8;

    if bit_offset == 0 {
        first.write_all(&data[..byte_index])?;
        second.write_all(&data[byte_index..])?;
    } else {
        if byte_index > 0 {
            first.write_all(&data[..byte_index])?;
        }
        let r = bit_offset as u16;
        let low_mask = (1u16 << r) - 1;
        let last_partial = (data[byte_index] as u16) & low_mask;
        first.write_all(&[(last_partial as u8)])?;

        for i in byte_index..data.len() {
            let cur = data[i] as u16;
            let next = if i + 1 < data.len() { data[i + 1] as u16 } else { 0 };
            let out = ((cur >> r) | ((next & low_mask) << (8 - r))) as u8;
            second.write_all(&[out])?;
        }
    }

    first.flush()?;
    second.flush()?;
    first.sync_all()?;
    second.sync_all()?;
    Ok(())
}

pub fn reverse_file_bytes(path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path_str);
    if !path.is_file() {
        return Err(format!("Not a regular file: {}", path.display()).into());
    }

    let meta = fs::metadata(path)?;
    let len = meta.len();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("tmpfile");
    let mut tmp_path = PathBuf::from(dir);
    tmp_path.push(format!("{base}.revtmp.{pid}.{stamp}"));

    let mut infile = File::open(path)?;
    let outfile = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    outfile.set_permissions(meta.permissions())?;
    let mut writer = BufWriter::new(outfile);
    let mut buf = vec![0u8; BUF_SIZE];
    let mut remaining = len;

    while remaining > 0 {
        let to_read = usize::min(BUF_SIZE, remaining as usize);
        let start = remaining - to_read as u64;

        infile.seek(SeekFrom::Start(start))?;
        infile.read_exact(&mut buf[..to_read])?;
        buf[..to_read].reverse();
        writer.write_all(&buf[..to_read])?;

        remaining = start;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;

    drop(writer);
    drop(infile);

    match fs::rename(&tmp_path, path) {
        Ok(_) => {
            println!("{{\"Result\": \"File bytes reversed.\"}}");
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            fs::rename(&tmp_path, path)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e.into())
        }
    }
}

pub fn hexdump_range(path: &str, start: u64, end: u64) -> Result<(), Box<dyn std::error::Error>> {
    if start >= end {
        return Err("start must be less than end".into());
    }

    let p = Path::new(path);
    let mut file = File::open(p)?;
    let file_len = file.metadata()?.len();

    if start >= file_len {
        return Err("start position is beyond end of file".into());
    }

    let to_end = min(end, file_len);
    if to_end <= start {
        return Ok(());
    }

    file.seek(SeekFrom::Start(start))?;

    let mut buf = vec![0u8; 8192];
    let mut remaining = to_end - start;
    let mut current_off = start;

    while remaining > 0 {
        let want = min(buf.len() as u64, remaining) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }

        let mut idx = 0usize;
        while idx < n {
            let line_len = min(16, n - idx);
            let line = &buf[idx..idx + line_len];

            let mut hex_cols = String::with_capacity(16 * 3 + 2);
            for i in 0..16 {
                if i == 8 {
                    hex_cols.push(' ');
                }
                if i < line_len {
                    hex_cols.push_str(&format!("{:02x} ", line[i]));
                } else {
                    hex_cols.push_str("   ");
                }
            }

            let mut ascii = String::with_capacity(16);
            for &b in line {
                let ch = if (0x20..=0x7e).contains(&b) { b as char } else { '.' };
                ascii.push(ch);
            }

            println!("{:016x}  {} |{}|", current_off, hex_cols, ascii);

            current_off += line_len as u64;
            idx += line_len;
        }

        remaining -= n as u64;
    }

    Ok(())
}

pub fn hex_range(path: &str, start: u64, end: u64) -> Result<(), Box<dyn std::error::Error>> {
    if start >= end {
        return Err("start must be less than end".into());
    }

    let p = Path::new(path);
    let mut file = File::open(p)?;
    let file_len = file.metadata()?.len();

    if start >= file_len {
        return Err("start position is beyond end of file".into());
    }

    let to_end = min(end, file_len);
    if to_end <= start {
        return Ok(());
    }

    file.seek(SeekFrom::Start(start))?;

    let mut buf = vec![0u8; 8192];
    let mut remaining = to_end - start;

    while remaining > 0 {
        let want = min(buf.len() as u64, remaining) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }

        let mut idx = 0usize;
        while idx < n {
            let line_len = min(16, n - idx);
            let line = &buf[idx..idx + line_len];

            let mut hex_cols = String::with_capacity(16 * 3 + 2);
            for i in 0..16 {
                if i == 8 {
                    hex_cols.push(' ');
                }
                if i < line_len {
                    hex_cols.push_str(&format!("{:02x} ", line[i]));
                } else {
                    hex_cols.push_str("   ");
                }
            }

            println!("{}", hex_cols);
            idx += line_len;
        }

        remaining -= n as u64;
    }

    Ok(())
}

pub fn serialized_hex_range(path: &str, start: u64, end: u64) -> Result<(), Box<dyn std::error::Error>> {
    if start >= end {
        return Err("start must be less than end".into());
    }

    let p = Path::new(path);
    let mut file = File::open(p)?;
    let file_len = file.metadata()?.len();

    if start >= file_len {
        return Err("start position is beyond end of file".into());
    }

    let to_end = min(end, file_len);
    if to_end <= start {
        return Ok(());
    }

    file.seek(SeekFrom::Start(start))?;

    let mut buf = vec![0u8; 8192];
    let mut remaining = to_end - start;

    while remaining > 0 {
        let want = min(buf.len() as u64, remaining) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }

        let mut idx = 0usize;
        while idx < n {
            let line_len = min(16, n - idx);
            let line = &buf[idx..idx + line_len];

            let mut hex_cols = String::with_capacity(16 * 3 + 2);
            for i in 0..16 {
               if i < line_len {
                    hex_cols.push_str(&format!("{:02x}", line[i]));
                }
            }

            print!("{}", hex_cols);
            idx += line_len;
        }

        remaining -= n as u64;
    }

    Ok(())
}
