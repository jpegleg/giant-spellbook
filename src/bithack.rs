use std::error::Error;
use std::cmp::min;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CHUNK_SIZE: usize = 4096;
const BUF_SIZE: usize = 8 * 1024 * 1024;

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
