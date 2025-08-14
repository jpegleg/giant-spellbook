use argon2::Argon2;
use blake2::{Blake2b512, Digest};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_384, Shake256, digest::{Update, ExtendableOutput}};
use chrono::Utc;
use zeroize::Zeroize;
use std::io::{self, Read};
use std::fs::File;
extern crate blake2;
extern crate digest;
extern crate sha2;
extern crate sha3;

pub fn file_all(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  let mut hasher = Shake256::default();
  hasher.update(&data);
  let mut resulto = hasher.finalize_xof();
  let mut shake256 = [0u8; 10];
  let _ = resulto.read(&mut shake256);
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"SHAKE256 10\": \"{:?}\",", shake256);
  let mut hasher = blake3::Hasher::new();
  hasher.update(&data);
  let blake3 = hasher.finalize();
  println!("  \"BLAKE3\": \"{}\",", blake3);
  let mut hasher = Blake2b512::new();
  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();
  println!("  \"BLAKE2B-512\": \"{:x}\",", blake2b512);
  let mut hasher = Sha3_256::new();
  Update::update(&mut hasher, &data);
  let sha3256 = hasher.finalize();
  println!("  \"SHA3-256\": \"{:x}\",", sha3256);
  let mut hasher = Sha3_384::new();
  Update::update(&mut hasher, &data);
  let sha3384 = hasher.finalize();
  println!("  \"SHA3-384\": \"{:x}\",", sha3384);
  let mut hasher = Sha256::new();
  Update::update(&mut hasher, &data);
  let sha2 = hasher.finalize();
  println!("  \"SHA256\": \"{:x}\",", sha2);
  let mut hasher = Sha512::new();
  Update::update(&mut hasher, &data);
  let sha512 = hasher.finalize();
  println!("  \"SHA512\": \"{:x}\"", sha512);
  println!("}}");
  Ok(())
}

pub fn argon2id(input: &[u8], salt: &[u8]) {
  let mut adata = [0u8; 32];
  let _ = Argon2::default().hash_password_into(input, salt, &mut adata);
  println!("{{ \"Argon2id\": \"{:?}\"", adata);
  adata.zeroize();
}

pub fn sha256(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = Sha256::new();
  Update::update(&mut hasher, &data);
  let sha2 = hasher.finalize();
  println!("  \"SHA256\": \"{:x}\"", sha2);
  println!("}}");
  Ok(())
}

pub fn sha512(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = Sha512::new();
  Update::update(&mut hasher, &data);
  let sha2 = hasher.finalize();
  println!("  \"SHA512\": \"{:x}\"", sha2);
  println!("}}");
  Ok(())
}

pub fn sha3_384(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = Sha3_384::new();
  Update::update(&mut hasher, &data);
  let sha3384 = hasher.finalize();
  println!("  \"SHA3-384\": \"{:x}\"", sha3384);
  println!("}}");
  Ok(())
}

pub fn sha3_256(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = Sha3_256::new();
  Update::update(&mut hasher, &data);
  let sha3256 = hasher.finalize();
  println!("  \"SHA3-256\": \"{:x}\"", sha3256);
  println!("}}");
  Ok(())
}

pub fn blake2b512(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = Blake2b512::new();
  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();
  println!("  \"BLAKE2B-512\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}

pub fn blake3(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  let mut hasher = blake3::Hasher::new();
  hasher.update(&data);
  let blake3 = hasher.finalize();
  println!("  \"BLAKE3\": \"{}\"", blake3);
  println!("}}");
  Ok(())
}

pub fn shake256_10(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  let mut hasher = Shake256::default();
  hasher.update(&data);
  let mut resulto = hasher.finalize_xof();
  let mut shake256 = [0u8; 10];
  let _ = resulto.read(&mut shake256);
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"SHAKE256 10\": \"{:?}\"", shake256);
  println!("}}");
  Ok(())
}

pub fn shake256_32(input: &String) -> Result<(), Box<dyn std::error::Error>> {
  let mut file = File::open(&input).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input}: {e}")))?;
  let mut data = Vec::new();
  file.read_to_end(&mut data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input}: {e}")))?;
  println!("{{\n  \"File\": \"{input}\",");
  let chronox: String = Utc::now().to_string();
  let mut hasher = Shake256::default();
  hasher.update(&data);
  let mut resulto = hasher.finalize_xof();
  let mut shake256 = [0u8; 32];
  let _ = resulto.read(&mut shake256);
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"SHAKE256 32\": \"{:?}\"", shake256);
  println!("}}");
  Ok(())
}
