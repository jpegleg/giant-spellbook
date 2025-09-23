use argon2::Argon2;
use blake2::{Blake2b512, Digest};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_384, Shake256, digest::{Update, ExtendableOutput}};
use chrono::Utc;
use zeroize::Zeroize;
use std::io::{self, Read, Seek, SeekFrom};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
extern crate blake2;
extern crate digest;
extern crate sha2;
extern crate sha3;

#[path = "./utilities.rs"]
mod utilities;
use utilities::json_escape;
use utilities::firmware_hex;

const BLOCK: usize = 512;

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

pub fn attest_linux(mode: bool) -> Result<(), Box<dyn std::error::Error>> {
  let mut data = Vec::new();
  let mut mbr_chk = vec![0; BLOCK];
  let mut mbr: File;

  if mode == true {
    if Path::new("/dev/sda").exists() {
      mbr = File::open("/dev/sda")?;
    } else {
      mbr = File::open("/dev/vda")?;
    }
    mbr.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0; BLOCK];
    mbr.read_exact(&mut buf)?;
    mbr_chk = buf.to_vec();

    data.extend(buf);
  };

  let mut kernel_data = Vec::new();
  let mut passwd_data = Vec::new();
  let mut hosts_data = Vec::new();
  let mut resolv_data = Vec::new();
  let mut profile_data = Vec::new();
  let mut crontab_data = Vec::new();
  let mut machine_data = Vec::new();
  let mut disk_data = Vec::new();

  let mut system_name = Vec::new();

  let mut kernel_file = File::open("/vmlinuz").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /vmlinuz: {e}")))?;
  kernel_file.read_to_end(&mut kernel_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /vmlinuz: {e}")))?;
  let mut kernel_hasher = Blake2b512::new();
  Update::update(&mut kernel_hasher, &kernel_data);
  let kernel_chk = kernel_hasher.finalize();

  let mut password_file = File::open("/etc/passwd").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/passwd: {e}")))?;
  password_file.read_to_end(&mut passwd_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/passwd: {e}")))?;
  let mut passwd_hasher = Blake2b512::new();
  Update::update(&mut passwd_hasher, &passwd_data);
  let passwd_chk = passwd_hasher.finalize();

  let mut hosts_file = File::open("/etc/hosts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/hosts: {e}")))?;
  hosts_file.read_to_end(&mut hosts_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/hosts: {e}")))?;
  let mut hosts_hasher = Blake2b512::new();
  Update::update(&mut hosts_hasher, &hosts_data);
  let hosts_chk = hosts_hasher.finalize();

  let mut resolv_file = File::open("/etc/resolv.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/resolv.conf: {e}")))?;
  resolv_file.read_to_end(&mut resolv_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/resolv.conf: {e}")))?;
  let mut resolv_hasher = Blake2b512::new();
  Update::update(&mut resolv_hasher, &resolv_data);
  let resolv_chk = resolv_hasher.finalize();

  let mut profile_file = File::open("/etc/profile").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/profile: {e}")))?;
  profile_file.read_to_end(&mut profile_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/profile: {e}")))?;
  let mut profile_hasher = Blake2b512::new();
  Update::update(&mut profile_hasher, &profile_data);
  let profile_chk = profile_hasher.finalize();

  let mut crontab_file = File::open("/etc/crontab").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/crontab: {e}")))?;
  crontab_file.read_to_end(&mut crontab_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/crontab: {e}")))?;
  let mut cron_hasher = Blake2b512::new();
  Update::update(&mut cron_hasher, &crontab_data);
  let crontab_chk = cron_hasher.finalize();

  let mut disk_file = File::open("/etc/fstab").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/fstab: {e}")))?;
  disk_file.read_to_end(&mut disk_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/fstab: {e}")))?;
  let mut disk_hasher = Blake2b512::new();
  Update::update(&mut disk_hasher, &disk_data);
  let disk_chk = disk_hasher.finalize();

  let mut machine_file = File::open("/etc/machine-id").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/machine-id: {e}")))?;
  machine_file.read_to_end(&mut machine_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/machine-id: {e}")))?;
  let mut machine_hasher = Blake2b512::new();
  Update::update(&mut machine_hasher, &machine_data);
  let machine_chk = machine_hasher.finalize();

  let firmware_chk = firmware_hex().unwrap();

  let mut hasher = Blake2b512::new();
  data.extend(machine_chk);
  data.extend(disk_chk);
  data.extend(profile_chk);
  data.extend(resolv_chk);
  data.extend(firmware_chk.bytes());
  data.extend(hosts_chk);
  data.extend(passwd_chk);
  data.extend(kernel_chk);

  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();

  let mut hostname = File::open("/etc/hostname").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /etc/hostname: {e}")))?;
  hostname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /etc/hostname: {e}")))?;

  let mut sysname = File::open("/proc/version").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /proc/version: {e}")))?;
  sysname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /proc/version: {e}")))?;

  let name_str = String::from_utf8_lossy(&system_name);

  println!("{{");
  println!("  \"System\": \"{}\",", json_escape(&name_str));
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"MBR checked\": \"{mode}\",");
  if mode == true {
      println!("  \"MBR first sector (512 bytes)\": \"{mbr_chk:?}\",");
  };
  println!("  \"Checked components\": [\n    {{ \"/vmlinuz\": \"{kernel_chk:x}\" }},\n    {{ \"/etc/passwd\": \"{passwd_chk:x}\" }},\n    {{ \"/etc/hosts\": \"{hosts_chk:x}\" }},\n    {{ \"/etc/resolv.conf\": \"{resolv_chk:x}\" }},\n    {{ \"/etc/profile\": \"{profile_chk:x}\" }},\n    {{ \"/etc/crontab\": \"{crontab_chk:x}\" }},\n    {{ \"/etc/machine-id\": \"{machine_chk:x}\" }},\n    {{ \"firmware\": \"{firmware_chk}\" }},\n    {{ \"/etc/fstab\": \"{disk_chk:x}\" }}\n  ],");

  println!("  \"BLAKE2B-512 Linux System Attestation\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}

pub fn attest_alpine_lts(mode: bool) -> Result<(), Box<dyn std::error::Error>> {
  let mut data = Vec::new();
  let mut mbr_chk = vec![0; BLOCK];
  let mut mbr: File;

  if mode == true {
    if Path::new("/dev/sda").exists() {
      mbr = File::open("/dev/sda")?;
    } else {
      mbr = File::open("/dev/vda")?;
    }
    mbr.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0; BLOCK];
    mbr.read_exact(&mut buf)?;
    mbr_chk = buf.to_vec();

    data.extend(buf);
  };

  let mut kernel_data = Vec::new();
  let mut passwd_data = Vec::new();
  let mut hosts_data = Vec::new();
  let mut resolv_data = Vec::new();
  let mut profile_data = Vec::new();
  let mut disk_data = Vec::new();

  let mut system_name = Vec::new();

  let mut kernel_file = File::open("/boot/vmlinuz-lts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /vmlinuz: {e}")))?;
  kernel_file.read_to_end(&mut kernel_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /vmlinuz: {e}")))?;
  let mut kernel_hasher = Blake2b512::new();
  Update::update(&mut kernel_hasher, &kernel_data);
  let kernel_chk = kernel_hasher.finalize();

  let mut password_file = File::open("/etc/passwd").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/passwd: {e}")))?;
  password_file.read_to_end(&mut passwd_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/passwd: {e}")))?;
  let mut passwd_hasher = Blake2b512::new();
  Update::update(&mut passwd_hasher, &passwd_data);
  let passwd_chk = passwd_hasher.finalize();

  let mut hosts_file = File::open("/etc/hosts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/hosts: {e}")))?;
  hosts_file.read_to_end(&mut hosts_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/hosts: {e}")))?;
  let mut hosts_hasher = Blake2b512::new();
  Update::update(&mut hosts_hasher, &hosts_data);
  let hosts_chk = hosts_hasher.finalize();

  let mut resolv_file = File::open("/etc/resolv.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/resolv.conf: {e}")))?;
  resolv_file.read_to_end(&mut resolv_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/resolv.conf: {e}")))?;
  let mut resolv_hasher = Blake2b512::new();
  Update::update(&mut resolv_hasher, &resolv_data);
  let resolv_chk = resolv_hasher.finalize();

  let mut profile_file = File::open("/etc/profile").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/profile: {e}")))?;
  profile_file.read_to_end(&mut profile_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/profile: {e}")))?;
  let mut profile_hasher = Blake2b512::new();
  Update::update(&mut profile_hasher, &profile_data);
  let profile_chk = profile_hasher.finalize();

  let mut disk_file = File::open("/etc/fstab").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/fstab: {e}")))?;
  disk_file.read_to_end(&mut disk_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/fstab: {e}")))?;
  let mut disk_hasher = Blake2b512::new();
  Update::update(&mut disk_hasher, &disk_data);
  let disk_chk = disk_hasher.finalize();

  let firmware_chk = firmware_hex().unwrap();

  let mut hasher = Blake2b512::new();
  data.extend(disk_chk);
  data.extend(profile_chk);
  data.extend(resolv_chk);
  data.extend(hosts_chk);
  data.extend(passwd_chk);
  data.extend(kernel_chk);
  data.extend(firmware_chk.bytes());
  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();

  let mut hostname = File::open("/etc/hostname").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /etc/hostname: {e}")))?;
  hostname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /etc/hostname: {e}")))?;

  let mut sysname = File::open("/proc/version").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /proc/version: {e}")))?;
  sysname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /proc/version: {e}")))?;

  let name_str = String::from_utf8_lossy(&system_name);

  println!("{{");
  println!("  \"System\": \"{}\",", json_escape(&name_str));
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"MBR checked\": \"{mode}\",");
  if mode == true {
      println!("  \"MBR first sector (512 bytes)\": \"{mbr_chk:?}\",");
  };
  println!("  \"Checked components\": [\n    {{ \"/boot/vmlinuz-lts\": \"{kernel_chk:x}\" }},\n    {{ \"/etc/passwd\": \"{passwd_chk:x}\" }},\n    {{ \"/etc/hosts\": \"{hosts_chk:x}\" }},\n    {{ \"/etc/resolv.conf\": \"{resolv_chk:x}\" }},\n    {{ \"firmware\": \"{firmware_chk}\" }},\n    {{ \"/etc/profile\": \"{profile_chk:x}\" }},\n    {{ \"/etc/fstab\": \"{disk_chk:x}\" }}\n  ],");

  println!("  \"BLAKE2B-512 Alpine LTS Linux System Attestation\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}

pub fn attest_macos(mode: bool) -> Result<(), Box<dyn std::error::Error>> {
  let mut data = Vec::new();
  let mut mbr_chk = vec![0; BLOCK];

  if mode == true {
    let mut mbr = File::open("/dev/disk0")?;
    mbr.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0; BLOCK];
    mbr.read_exact(&mut buf)?;
    mbr_chk = buf.to_vec();
    data.extend(buf);
  };

  let mut kernel_data = Vec::new();
  let mut passwd_data = Vec::new();
  let mut hosts_data = Vec::new();
  let mut resolv_data = Vec::new();
  let mut profile_data = Vec::new();
  let mut machine_data = Vec::new();

  let mut kernel_file = File::open("/System/Library/Kernels/kernel").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /System/Library/Kernels/kernel: {e}")))?;
  kernel_file.read_to_end(&mut kernel_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /System/Library/Kernels/kernel: {e}")))?;
  let mut kernel_hasher = Blake2b512::new();
  Update::update(&mut kernel_hasher, &kernel_data);
  let kernel_chk = kernel_hasher.finalize();

  let mut password_file = File::open("/etc/passwd").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/passwd: {e}")))?;
  password_file.read_to_end(&mut passwd_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/passwd: {e}")))?;
  let mut passwd_hasher = Blake2b512::new();
  Update::update(&mut passwd_hasher, &passwd_data);
  let passwd_chk = passwd_hasher.finalize();

  let mut hosts_file = File::open("/etc/hosts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/hosts: {e}")))?;
  hosts_file.read_to_end(&mut hosts_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/hosts: {e}")))?;
  let mut hosts_hasher = Blake2b512::new();
  Update::update(&mut hosts_hasher, &hosts_data);
  let hosts_chk = hosts_hasher.finalize();

  let mut resolv_file = File::open("/etc/resolv.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/resolv.conf: {e}")))?;
  resolv_file.read_to_end(&mut resolv_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/resolv.conf: {e}")))?;
  let mut resolv_hasher = Blake2b512::new();
  Update::update(&mut resolv_hasher, &resolv_data);
  let resolv_chk = resolv_hasher.finalize();

  let mut profile_file = File::open("/etc/profile").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/profile: {e}")))?;
  profile_file.read_to_end(&mut profile_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/profile: {e}")))?;
  let mut profile_hasher = Blake2b512::new();
  Update::update(&mut profile_hasher, &profile_data);
  let profile_chk = profile_hasher.finalize();

  let mut machine_file = File::open("/Library/Preferences/SystemConfiguration/preferences.plist").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /Library/Preferences/SystemConfiguration/preferences.plist: {e}")))?;
  machine_file.read_to_end(&mut machine_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /Library/Preferences/SystemConfiguration/preferences.plist: {e}")))?;

  let mut machine_hasher = Blake2b512::new();
  Update::update(&mut machine_hasher, &machine_data);
  let machine_chk = machine_hasher.finalize();

  let firmware_chk = firmware_hex().unwrap();

  let mut hasher = Blake2b512::new();
  data.extend(machine_chk);
  data.extend(profile_chk);
  data.extend(resolv_chk);
  data.extend(hosts_chk);
  data.extend(passwd_chk);
  data.extend(kernel_chk);
  data.extend(firmware_chk.bytes());

  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();

  let checkmac = Command::new("sh")
    .arg("-c")
    .arg("system_profiler SPSoftwareDataType SPHardwareDataType")
    .output()
    .unwrap();

  let sysname = String::from_utf8_lossy(&checkmac.stdout);
  println!("{{");
  println!("  \"System\": \"{}\",", json_escape(&sysname));
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"MBR checked\": \"{mode}\",");
  if mode == true {
      println!("  \"MBR first sector (512 bytes)\": \"{mbr_chk:?}\",");
  };
  println!("  \"Checked components\": [\n    {{ \"/System/Library/Kernels/kernel\": \"{kernel_chk:x}\" }},\n    {{ \"/etc/passwd\": \"{passwd_chk:x}\" }},\n    {{ \"/etc/hosts\": \"{hosts_chk:x}\" }},\n    {{ \"/etc/resolv.conf\": \"{resolv_chk:x}\" }},\n    {{ \"firmware\": \"{firmware_chk}\" }},\n    {{ \"/etc/profile\": \"{profile_chk:x}\" }},\n    {{ \"/Library/Preferences/SystemConfiguration/preferences.plist\": \"{machine_chk:x}\" }}\n  ],");
  println!("  \"BLAKE2B-512 MacOS System Attestation\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}

pub fn attest_openbsd(mode: bool) -> Result<(), Box<dyn std::error::Error>> {
  let mut data = Vec::new();
  let mut mbr_chk = vec![0; BLOCK];

  if mode == true {
    let mut mbr = File::open("/dev/sd0c")?;
    mbr.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0; BLOCK];
    mbr.read_exact(&mut buf)?;
    mbr_chk = buf.to_vec();
    data.extend(buf);
  };

  let mut passwd_data = Vec::new();
  let mut hosts_data = Vec::new();
  let mut resolv_data = Vec::new();
  let mut profile_data = Vec::new();
  let mut machine_data = Vec::new();

  let mut password_file = File::open("/etc/passwd").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/passwd: {e}")))?;
  password_file.read_to_end(&mut passwd_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/passwd: {e}")))?;
  let mut passwd_hasher = Blake2b512::new();
  Update::update(&mut passwd_hasher, &passwd_data);
  let passwd_chk = passwd_hasher.finalize();

  let mut hosts_file = File::open("/etc/hosts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/hosts: {e}")))?;
  hosts_file.read_to_end(&mut hosts_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/hosts: {e}")))?;
  let mut hosts_hasher = Blake2b512::new();
  Update::update(&mut hosts_hasher, &hosts_data);
  let hosts_chk = hosts_hasher.finalize();

  let mut resolv_file = File::open("/etc/resolv.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/resolv.conf: {e}")))?;
  resolv_file.read_to_end(&mut resolv_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/resolv.conf: {e}")))?;
  let mut resolv_hasher = Blake2b512::new();
  Update::update(&mut resolv_hasher, &resolv_data);
  let resolv_chk = resolv_hasher.finalize();

  let mut profile_file = File::open("/etc/ksh.kshrc").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/ksh.kshrc: {e}")))?;
  profile_file.read_to_end(&mut profile_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/ksh.kshrc: {e}")))?;
  let mut profile_hasher = Blake2b512::new();
  Update::update(&mut profile_hasher, &profile_data);
  let profile_chk = profile_hasher.finalize();

  let mut machine_file = File::open("/etc/rc.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/rc.conf: {e}")))?;
  machine_file.read_to_end(&mut machine_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/rc.conf: {e}")))?;

  let mut machine_hasher = Blake2b512::new();
  Update::update(&mut machine_hasher, &machine_data);
  let machine_chk = machine_hasher.finalize();

  let firmware_chk = firmware_hex().unwrap();

  let mut hasher = Blake2b512::new();
  data.extend(machine_chk);
  data.extend(profile_chk);
  data.extend(resolv_chk);
  data.extend(hosts_chk);
  data.extend(passwd_chk);
  data.extend(firmware_chk.bytes());

  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();

  let mut system_name = Vec::new();

  let mut hostname = File::open("/etc/myname").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /etc/myname: {e}")))?;
  hostname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /etc/myname: {e}")))?;

  let name_str = String::from_utf8_lossy(&system_name);

  println!("{{");
  println!("  \"System\": \"{}\",", json_escape(&name_str));
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"MBR checked\": \"{mode}\",");
  if mode == true {
      println!("  \"MBR first sector (512 bytes)\": \"{mbr_chk:?}\",");
  };
  println!("  \"Checked components\": [\n   {{  \"/etc/passwd\": \"{passwd_chk:x}\" }},\n    {{ \"/etc/hosts\": \"{hosts_chk:x}\" }},\n    {{ \"/etc/resolv.conf\": \"{resolv_chk:x}\" }},\n    {{ \"firmware\": \"{firmware_chk}\" }},\n    {{ \"/etc/ksh.kshrc\": \"{profile_chk:x}\" }},\n    {{ \"/etc/rc.conf\": \"{machine_chk:x}\" }}\n  ],");
  println!("  \"BLAKE2B-512 OpenBSD System Attestation\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}

fn parse_boot_image<'a>(cmdline: &'a str) -> Option<&'a str> {
    for tok in cmdline.split_whitespace() {
        if let Some(rest) = tok.strip_prefix("BOOT_IMAGE=") {
            return Some(rest.trim_matches('"'));
        }
    }
    None
}

fn kernel_image_path() -> std::io::Result<PathBuf> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let boot_image = parse_boot_image(&cmdline)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "BOOT_IMAGE not found"))?;

    let file_name = Path::new(boot_image)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid BOOT_IMAGE"))?;

    Ok(PathBuf::from("/boot").join(file_name))
}

pub fn attest_rhel(mode: bool) -> Result<(), Box<dyn std::error::Error>> {
  let mut data = Vec::new();
  let mut mbr_chk = vec![0; BLOCK];
  let mut mbr: File;

  if mode == true {
    if Path::new("/dev/sda").exists() {
      mbr = File::open("/dev/sda")?;
    } else {
      mbr = File::open("/dev/vda")?;
    }
    mbr.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0; BLOCK];
    mbr.read_exact(&mut buf)?;
    mbr_chk = buf.to_vec();

    data.extend(buf);
  };

  let mut kernel_data = Vec::new();
  let mut passwd_data = Vec::new();
  let mut hosts_data = Vec::new();
  let mut resolv_data = Vec::new();
  let mut profile_data = Vec::new();
  let mut disk_data = Vec::new();
  let mut system_name = Vec::new();

  let kern_path = kernel_image_path()?.display().to_string();
  let mut kernel_file = File::open(kern_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file for the kernel: {e}")))?;
  kernel_file.read_to_end(&mut kernel_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read kernel file: {e}")))?;
  let mut kernel_hasher = Blake2b512::new();
  Update::update(&mut kernel_hasher, &kernel_data);
  let kernel_chk = kernel_hasher.finalize();

  let mut password_file = File::open("/etc/passwd").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/passwd: {e}")))?;
  password_file.read_to_end(&mut passwd_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/passwd: {e}")))?;
  let mut passwd_hasher = Blake2b512::new();
  Update::update(&mut passwd_hasher, &passwd_data);
  let passwd_chk = passwd_hasher.finalize();

  let mut hosts_file = File::open("/etc/hosts").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/hosts: {e}")))?;
  hosts_file.read_to_end(&mut hosts_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/hosts: {e}")))?;
  let mut hosts_hasher = Blake2b512::new();
  Update::update(&mut hosts_hasher, &hosts_data);
  let hosts_chk = hosts_hasher.finalize();

  let mut resolv_file = File::open("/etc/resolv.conf").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/resolv.conf: {e}")))?;
  resolv_file.read_to_end(&mut resolv_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/resolv.conf: {e}")))?;
  let mut resolv_hasher = Blake2b512::new();
  Update::update(&mut resolv_hasher, &resolv_data);
  let resolv_chk = resolv_hasher.finalize();

  let mut profile_file = File::open("/etc/profile").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/profile: {e}")))?;
  profile_file.read_to_end(&mut profile_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/profile: {e}")))?;
  let mut profile_hasher = Blake2b512::new();
  Update::update(&mut profile_hasher, &profile_data);
  let profile_chk = profile_hasher.finalize();

  let mut disk_file = File::open("/etc/fstab").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file /etc/fstab: {e}")))?;
  disk_file.read_to_end(&mut disk_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /etc/fstab: {e}")))?;
  let mut disk_hasher = Blake2b512::new();
  Update::update(&mut disk_hasher, &disk_data);
  let disk_chk = disk_hasher.finalize();

  let firmware_chk = firmware_hex().unwrap();

  let mut hasher = Blake2b512::new();
  data.extend(disk_chk);
  data.extend(profile_chk);
  data.extend(resolv_chk);
  data.extend(hosts_chk);
  data.extend(passwd_chk);
  data.extend(kernel_chk);
  data.extend(firmware_chk.bytes());
  Update::update(&mut hasher, &data);
  let blake2b512 = hasher.finalize();

  let mut hostname = File::open("/etc/hostname").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /etc/hostname: {e}")))?;
  hostname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /etc/hostname: {e}")))?;

  let mut sysname = File::open("/proc/version").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open /proc/version: {e}")))?;
  sysname.read_to_end(&mut system_name).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read from /proc/version: {e}")))?;

  let name_str = String::from_utf8_lossy(&system_name);

  println!("{{");
  println!("  \"System\": \"{}\",", json_escape(&name_str));
  let chronox: String = Utc::now().to_string();
  println!("  \"Time\": \"{chronox}\",");
  println!("  \"MBR checked\": \"{mode}\",");
  if mode == true {
      println!("  \"MBR first sector (512 bytes)\": \"{mbr_chk:?}\",");
  };
  println!("  \"Checked components\": [\n    {{ \"kernel\": \"{kernel_chk:x}\" }},\n    {{ \"/etc/passwd\": \"{passwd_chk:x}\" }},\n    {{ \"/etc/hosts\": \"{hosts_chk:x}\" }},\n    {{ \"/etc/resolv.conf\": \"{resolv_chk:x}\" }},\n    {{ \"firmware\": \"{firmware_chk}\" }},\n    {{ \"/etc/profile\": \"{profile_chk:x}\" }},\n    {{ \"/etc/fstab\": \"{disk_chk:x}\" }}\n  ],");

  println!("  \"BLAKE2B-512 RHEL-based Linux System Attestation\": \"{:x}\"", blake2b512);
  println!("}}");
  Ok(())
}
