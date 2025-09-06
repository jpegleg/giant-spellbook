use std::fs::File;
use std::io::{self, Read, Write, BufWriter, BufReader};
use std::path::Path;
use base64::{Engine as _};
use base32::Alphabet;

const CHUNK_SIZE: usize = 4096;

fn base32_rfc4648_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base32::encode(Alphabet::Rfc4648 {padding: true}, &buffer[..bytes_read]);
        output.write_all(encoded_chunk.as_bytes())?;
    }
    Ok(())
}

fn base32_rfc4648_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let segment = str::from_utf8(&&buffer[..bytes_read]).unwrap();
        let decoded_chunk = base32::decode(Alphabet::Rfc4648 {padding: true}, segment).unwrap();
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

fn base32_rfc4648hex_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base32::encode(Alphabet::Rfc4648Hex {padding: true}, &buffer[..bytes_read]);
        output.write_all(encoded_chunk.as_bytes())?;
    }
    Ok(())
}

fn base32_rfc4648hex_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let segment = str::from_utf8(&&buffer[..bytes_read]).unwrap();
        let decoded_chunk = base32::decode(Alphabet::Rfc4648Hex {padding: true}, segment).unwrap();
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

fn base32_z_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base32::encode(Alphabet::Z, &buffer[..bytes_read]);
        output.write_all(encoded_chunk.as_bytes())?;
    }
    Ok(())
}

fn base32_z_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let segment = str::from_utf8(&&buffer[..bytes_read]).unwrap();
        let decoded_chunk = base32::decode(Alphabet::Z, segment).unwrap();
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

fn base32_crockford_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base32::encode(Alphabet::Crockford, &buffer[..bytes_read]);
        output.write_all(encoded_chunk.as_bytes())?;
    }
    Ok(())
}

fn base32_crockford_decode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let segment = str::from_utf8(&&buffer[..bytes_read]).unwrap();
        let decoded_chunk = base32::decode(Alphabet::Crockford, segment).unwrap();
        output.write_all(&decoded_chunk)?;
    }
    Ok(())
}

fn base64_encode<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buffer = [0; CHUNK_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encoded_chunk = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(&buffer[..bytes_read]);
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
        let decoded_chunk = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&buffer[..bytes_read])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("Base64 decode error: {err}")))?;
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
        let decoded_chunk = bs58::decode(&buffer[..bytes_read])
            .into_vec()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("Base58 decode error: {err}")))?;
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
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let bytes_read = input_reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let hex_string = hex::encode(&buffer[..bytes_read]);
        output_writer.write_all(hex_string.as_bytes())?;
    }
    output_writer.flush()?;
    Ok(())
}

pub fn hexoff(file_path: &str, out_path: &str) -> io::Result<()> {
    let file_path = Path::new(file_path);
    let file = File::open(&file_path)?;
    let outfile = File::create(out_path)?;
    let mut output_writer = BufWriter::new(outfile);
    let mut input_reader = BufReader::new(file);
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let bytes_read = input_reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let binary = hex::decode(&buffer[..bytes_read])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("Hex decode error: {err}")))?;
        output_writer.write_all(&binary)?;
    }
    output_writer.flush()?;
    Ok(())
}

pub fn crockford_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_crockford_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded with Crockford base32 and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn crockford_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_crockford_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Crockford base32 data decoded and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn rfc4648_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_rfc4648_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded with RFC-4648 base32 and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn rfc4648_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_rfc4648_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"RFC-4648 base32 data decoded and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn rfc4648hex_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_rfc4648hex_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded with RFC-4648 hex base32 and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn rfc4648hex_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_rfc4648hex_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"RFC-4648 hex base32 data decoded and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn z_encode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_z_encode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Data encoded with z-base32 and written to file: {}\" }}", file_path);
    Ok(())
}

pub fn z_decode_file(file_path: &str) -> io::Result<()> {
    let mut input_file = File::open(file_path)?;
    let temp_file_path = format!("{}.tmp", file_path);
    let mut output_file = File::create(&temp_file_path)?;
    base32_z_decode(&mut input_file, &mut output_file)?;
    std::fs::rename(&temp_file_path, file_path)?;
    println!("{{ \"Result\": \"Z-base32 data decoded and written to file: {}\" }}", file_path);
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

pub fn url_encode_string(input: &str) -> String {
    let out = urlencoding::encode(input);
    format!("{:?}", out)
}

pub fn url_decode_string(input: &str) -> String {
    urlencoding::decode(input).unwrap().to_string()
}
