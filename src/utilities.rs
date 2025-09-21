use std::fs::{self, File, read_dir};
use std::io::{self, Write, Read};
use std::path::{Path, PathBuf};
use chrono::Utc;
use blake2::{Blake2b512, Digest};

#[allow(dead_code)]
pub fn write_and_replace(path: &str, bytes: &[u8]) -> io::Result<()> {
    let p = Path::new(path);
    let tmp_name = format!("{}.tmp", path);
    let mut f = File::create(&tmp_name)?;
    f.write_all(bytes)?;
    f.sync_all()?;

    match fs::rename(&tmp_name, &p) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(&tmp_name);
            Ok(())
        }
    }
}

#[allow(dead_code)]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1F => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04X}", b);
            }
            _ => out.push(b as char),
        }
    }
    out
}

#[allow(dead_code)]
pub fn walk_dir_hash() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return vec![
            PathBuf::from("/lib/firmware/updates"),
            PathBuf::from("/lib/firmware"),
            PathBuf::from("/usr/lib/firmware"),
        ];
    }
    #[cfg(target_os = "openbsd")]
    {
        return vec![PathBuf::from("/etc/firmware")];
    }
    #[cfg(target_os = "macos")]
    {
        return vec![
            PathBuf::from("/usr/standalone/firmware"),
            PathBuf::from("/System/Library/CoreServices/Firmware Updates"),
        ];
    }
    #[allow(unreachable_code)]
    {
        Vec::new()
    }
}

#[allow(dead_code)]
fn hash_dir(dir: &Path, hasher: &mut Blake2b512) -> io::Result<()> {
    let mut entries = match read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|res| res.ok())
            .collect::<Vec<std::fs::DirEntry>>(),
        Err(e) => {
            eprintln!("ERROR: cannot read dir {}: {}", dir.display(), e);
            return Ok(());
        }
    };

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("ERROR: cannot stat {}: {}", path.display(), e);
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            hash_dir(&path, hasher)?;
        } else if meta.is_file() {
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("ERROR: cannot open {}: {}", path.display(), e);
                    continue;
                }
            };
            let mut buf = [0u8; 64 * 1024];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                    }
                    Err(e) => {
                        eprintln!("ERROR: error reading {}: {}", path.display(), e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn firmware_hash() -> io::Result<[u8; 64]> {
    let mut hasher = Blake2b512::new();

    for dir in walk_dir_hash() {
        if dir.exists() {
            hash_dir(&dir, &mut hasher)?;
        }
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest[..]);
    Ok(out)
}

#[allow(dead_code)]
pub fn firmware_hex() -> io::Result<String> {
    let bytes = firmware_hash()?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

#[allow(dead_code)]
fn recursive_hash(dir: &Path) -> io::Result<()> {
    let mut entries = match read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|res| res.ok())
            .collect::<Vec<std::fs::DirEntry>>(),
        Err(_) => {
            return Ok(());
        }
    };

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => {
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            recursive_hash(&path)?;
        } else if meta.is_file() {
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => {
                    continue;
                }
            };
            let mut buf = [0u8; 64 * 1024];
            let mut hasher = blake3::Hasher::new();
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            let blake3 = hasher.finalize();
            let chronix: String = Utc::now().to_string();
            let stringpath = format!("{}", path.display());
            println!("    {{ \"{}\": \"{}\", \"Report time\": \"{chronix}\" }},", json_escape(stringpath), blake3);
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn recursive_hash_dateless(dir: &Path) -> io::Result<()> {
    let mut entries = match read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|res| res.ok())
            .collect::<Vec<std::fs::DirEntry>>(),
        Err(_) => {
            return Ok(());
        }
    };

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => {
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            recursive_hash(&path)?;
        } else if meta.is_file() {
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => {
                    continue;
                }
            };
            let mut buf = [0u8; 64 * 1024];
            let mut hasher = blake3::Hasher::new();
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            let blake3 = hasher.finalize();
            let stringpath = format!("{}", path.display());
            println!("    {{ \"{}\": \"{}\" }},", json_escape(&stringpath), blake3);
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn blake3_hash(target: &str, date: bool) -> io::Result<()> {
    let chronox: String = Utc::now().to_string();
    println!("{{\n  \"Target\": \"{}\",", json_escape(target));
    println!("  \"Report start time\": \"{chronox}\",");
    println!("  \"BLAKE3 hash report\":  [");
    let path = PathBuf::from(&target);
    if date == true {
        let _ = recursive_hash(&path);
    } else {
        let _ = recursive_hash_dateless(&path);
    }
    let chronax: String = Utc::now().to_string();
    println!("    {{ \"Report end time\": \"{chronax}\" }}");
    println!("  ]");
    println!("}}");
    Ok(())
}
