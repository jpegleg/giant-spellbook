use std::fs::File;
use std::io::{self, Read, Write, BufWriter, BufReader};
use std::path::Path;
use base64::{Engine as _};

const CHUNK_SIZE: usize = 4096;

fn base64_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&buffer[..bytes_read]);
        output.write_all(encoded_chunk.as_bytes())?;
    }
    Ok(())
}

fn base64_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let decoded_chunk = base64::engine::general_purpose::STANDARD_NO_PAD.decode(&buffer[..bytes_read])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Base64 decode error: {}", err)))?;
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

fn base58_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = bs58::encode(&buffer[..bytes_read]).into_vec();
        output.write_all(&encoded_chunk)?;
    }
    Ok(())
}

fn base58_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let decoded_chunk = bs58::decode(&buffer[..bytes_read]).into_vec().unwrap();
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

pub fn hexon(file_path: &str, out_path: &str) -> io::Result<()> {
    let file_path = Path::new(file_path);
    let file = File::open(&file_path)?;
    let outfile = File::create(out_path)?;
    let mut output_writer = BufWriter::new(outfile);
    let mut input_reader = BufReader::new(file);
    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = input_reader.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        let hex_string = hex::encode(&buffer[..bytes_read]);
        let _ = output_writer.write_all(hex_string.as_bytes());
    }
    let _ = output_writer.flush();
    Ok(())
}

pub fn hexoff(file_path: &str, out_path: &str) -> io::Result<()> {
    let file_path = Path::new(file_path);
    let file = File::open(&file_path)?;
    let outfile = File::create(out_path)?;
    let mut output_writer = BufWriter::new(outfile);
    let mut input_reader = BufReader::new(file);
    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = input_reader.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        let binary = hex::decode(&buffer[..bytes_read]).unwrap();
        let _ = output_writer.write_all(&binary);
    }
    let _ = output_writer.flush();
    Ok(())
}

pub fn base64_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base64_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded in Base64 and written to file: {}\" }}", file_path);
    Ok(())
}


pub fn base64_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base64_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Base64 data decoded and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn base58_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base58_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded in Base58 and written to file: {}\" }}", file_path);
    Ok(())
}


pub fn base58_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base58_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Base58 data decoded and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn hex_encode_file(file_path: &str) -> io::Result<()> {
    let temp_file_path = format!("{}.tmp", file_path);
    hexon(file_path, &temp_file_path)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded in hex and written to file: {}\" }}", file_path);
    Ok(())
}


pub fn hex_decode_file(file_path: &str) -> io::Result<()> {
    let temp_file_path = format!("{}.tmp", file_path);
    hexoff(file_path, &temp_file_path)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Hex data decoded and written to file: {}\" }}", file_path);
    Ok(())
}
