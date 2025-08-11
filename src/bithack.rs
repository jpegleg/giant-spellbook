use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

/// CHUNK_SIZE for file operations.
const CHUNK_SIZE: usize = 4096;


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
        return Err(format!("bit position {} is past end of file", bit_pos).into());
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
                format!("failed to replace original file: {e}; fallback error: {e2}")
            })?;
        }
    }

    Ok(())
}

/// Split `path` at `bit_pos` and write `<name>__first` and `<name>__second` in the same directory.
/// Bit indexing is LSB-first within each byte (bit 0 is the least-significant bit of byte 0).
pub fn split_file(path: &str, bit_pos: u64) -> Result<(), Box<dyn Error>> {
    let input_path = Path::new(path);

    let mut input = File::open(&input_path)?;
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    let total_bits = (data.len() as u64) * 8;
    if bit_pos > total_bits {
        return Err(format!(
            "bit position {} is past end of file ({} bits total)",
            bit_pos, total_bits
        ).into());
    }

    let file_name = input_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid UTF-8 in filename")?;
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
