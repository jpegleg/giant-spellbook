use std::process;
use std::env;
use std::error::Error as StdError;
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::io::{self, Write, Read};
use sha3::{Shake256, digest::{Update, ExtendableOutput}};
use chrono::{TimeZone, NaiveDateTime, DateTime, Utc};
use users::{get_user_by_uid, get_group_by_gid};
use rpassword::read_password;
use base64::prelude::*;
use zeroize::Zeroize;

use enchantress::*;
use enchanter::*;
use wormsign::*;

mod encoding;
mod parsers;
mod hunter;
mod bithack;
mod analysis;
mod disassemble;
mod hashfunctions;
mod commander;
mod researcher;
mod seek;
mod tls_debug;

use crate::hunter::Interesting;

/// Forces errors to JSON. This function is a wrapper for STDERR to JSON.
fn print_error_json(msg: &str) {
    eprintln!(r#"{{ "Error": "{}" }}"#, msg);
}

/// This macro rule is used to catch errors and force them to JSON.
/// The json_started variable is manually set when the printing of
/// a JSON body has already begun, so we can complete the printing
/// of a valid JSON body, catching mid-processing issues and ensuring
/// the output is always valid JSON.
macro_rules! try_print_json {
    ($expr:expr, $json_started:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                if $json_started {
                    println!("  \"ERROR\": \"{}\"", e);
                    println!(" }}");
                    println!("}}");
                    return Ok(());
                } else {
                    return Err(Box::new(e) as Box<dyn StdError>);
                }
            }
        }
    };
}


trait StrExt {
    fn remove_last(&self) -> &str;
}

impl StrExt for str {
    fn remove_last(&self) -> &str {
        match self.char_indices().next_back() {
            Some((i, _)) => &self[..i],
            None => self,
        }
    }
}

/// This function is wrapped by the main function for error catching.
/// It handles the input arguments and applies the corresponding functionality.
#[allow(deprecated)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
      eprintln!("{{\n  \"ERROR\": \"Usage: <encrypt, decrypt, encode, decode, generate, sign, verify, analyze, brute, parse, disassemble, seek, tls_debug, hunter, commander, researcher, reverse_bytes, byte_range, bitflip, single_bitflip, split_file, shift, flatten, metadata, hash, derive_key, xor_these> <subcommands>  Try giant-spellbook <option> to print help for each option subcommands.\"\n}}");
      process::exit(1);
    }

    let first_layer = &args[1];

    match first_layer.as_str() {
        "-v" | "--version" => {
          println!("{{\"Version\": \"0.3.7\"}}");
          Ok(())
        },

        "sign" => {
          if args.len() != 6 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} sign <file_to_sign> <signature_file> <public_key_path> <private_key_path>\"\n}}", args[0]);
            process::exit(1);
          }

          let file_path = &args[2];
          let sig_path = &args[3];
          let pub_path = &args[4];
          let key_path = &args[5];

          let mut json_started = false;
          // STDERR on prompt so that output stays valid JSON, useful for redirects etc
          eprintln!("Enter key password then press enter (will not be displayed):");
          std::io::stdout().flush().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to flush stdout: {}", e)))?;
          let password = read_password().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read password: {}", e)))?;
          let keymaterial = derive_key(password.as_bytes(), 32);
          let kbytes = decrypt_key(key_path, &keymaterial)
              .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decrypt key: {}", e)))?;
          let file_path = Path::new(file_path);
          let metadata = try_print_json!(
              file_path.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata: {}", e))),
              json_started
          );
          let mut file = try_print_json!(
              File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
              json_started
          );
          let mut bytes = Vec::new();
          try_print_json!(
              file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
              json_started
          );
          let num_bytes = bytes.len();
          let num_bits = num_bytes * 8;
          let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;
          let file_is_open = match OpenOptions::new().read(true).write(true).open(file_path) {
              Ok(_) => false,
              Err(_) => true,
          };
          let chronox: String = Utc::now().to_string();
          let mut hasher = Shake256::default();
          hasher.update(&bytes);
          let mut resulto = hasher.finalize_xof();
          let mut shake256 = [0u8; 10];
          let _ = resulto.read(&mut shake256);
          json_started = true;
          println!("{{");
          println!("{:?}: {{", file_path);
          println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
          println!("  \"Report time\": \"{}\",", chronox);
          let num_io_blocks = metadata.blocks();
          println!("  \"Number of IO blocks\": \"{}\",", num_io_blocks);
          let blocksize = metadata.blksize();
          println!("  \"Block size\": \"{}\",", blocksize);
          let inode = metadata.ino();
          println!("  \"Inode\": \"{}\",", &inode);
          println!("  \"Total as bytes\": \"{}\",", &num_bytes);
          println!("  \"Total as kilobytes\": \"{}\",", &num_bytes / 1024);
          println!("  \"Total as megabytes\": \"{}\",", &num_bytes / (1024 * 1024));
          println!("  \"Total as bits\": \"{}\",", num_bits);
          println!("  \"Byte distribution\": \"{}\",", byte_distribution);
          let created: DateTime<Utc> = try_print_json!(
              metadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get created timestamp.")).map(DateTime::from),
              json_started
          );
          let modified: DateTime<Utc> = try_print_json!(
              metadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get modified timestamp.")).map(DateTime::from),
              json_started
          );
          let access: DateTime<Utc> = try_print_json!(
              metadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get accessed timestamp.")).map(DateTime::from),
              json_started
          );
          let changed: DateTime<Utc> = {
              let ctime = metadata.ctime();
              let ctimesec = metadata.ctime_nsec() as u32;
              let naive_datetime = try_print_json!(
                  NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid changed timestamp")),
                  json_started
              );
              TimeZone::from_utc_datetime(&Utc, &naive_datetime)
          };
          println!("  \"Created timestamp (UTC)\": \"{}\",", created);
          println!("  \"Modified timestamp (UTC)\": \"{}\",", modified);
          println!("  \"Accessed timestamp (UTC)\": \"{}\",", access);
          println!("  \"Changed timestamp (UTC)\": \"{}\",", changed);
          let permission = metadata.permissions();
          let mode = permission.mode();
          println!("  \"Permissions\": \"{:o}\",", mode);
          let uid = metadata.uid();
          let gid = metadata.gid();
          let owner = match get_user_by_uid(uid) {
              Some(user) => user.name().to_string_lossy().into_owned(),
              None => "-".to_string(),
          };
          let group = match get_group_by_gid(gid) {
              Some(group) => group.name().to_string_lossy().into_owned(),
              None => "-".to_string(),
          };
          println!("  \"Owner\": \"{} (uid: {})\",", owner, uid);
          println!("  \"Group\": \"{} (gid: {})\",", group, gid);
          if file_is_open {
              println!("  \"Open\": \"File is currently open by another program... signing anyway!\",");
          } else {
              println!("  \"Open\": \"File is not open by another program. Signing...\",");
          }
          let keypath = Path::new(&key_path);
          let pubpath = Path::new(&pub_path);
          let kmetadata = try_print_json!(
              keypath.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata for key: {}", e))),
              json_started
          );
          let mut kpubf = try_print_json!(
              File::open(&pubpath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the public key: {}", e))),
              json_started
          );
          let mut pubbytes = Vec::new();
          try_print_json!(
              kpubf.read_to_end(&mut pubbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the public key: {}", e))),
              json_started
          );
          let keys: Keypair = Keypair::loadit(pubbytes, kbytes);
          let msg = &bytes;
          let sig = keys.sign(&msg);
          let spath = Path::new(sig_path);
          let mut sigoutput = try_print_json!(
              File::create(spath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create signature file {}: {}", sig_path, e))),
              json_started
          );
          try_print_json!(
              sigoutput.write_all(&sig).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write signature: {}", e))),
              json_started
          );
          println!("  \"Dilithium signature file\": \"{}\",", sig_path);
          println!("  \"Dilithium signing key\": \"{}\",", key_path);
          let kinode = kmetadata.ino();
          println!("  \"Key Inode\": \"{}\",", &kinode);
          let kcreated: DateTime<Utc> = try_print_json!(
              kmetadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key created timestamp.")).map(DateTime::from),
              json_started
          );
          let kmodified: DateTime<Utc> = try_print_json!(
              kmetadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key modified timestamp.")).map(DateTime::from),
              json_started
          );
          let kaccess: DateTime<Utc> = try_print_json!(
              kmetadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key accessed timestamp.")).map(DateTime::from),
              json_started
          );
          let kchanged: DateTime<Utc> = {
              let ctime = kmetadata.ctime();
              let ctimesec = kmetadata.ctime_nsec() as u32;
              let naive_datetime = try_print_json!(
                  chrono::NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid key changed timestamp")),
                  json_started
              );
              TimeZone::from_utc_datetime(&Utc, &naive_datetime)
          };
          println!("  \"Key Created timestamp (UTC)\": \"{}\",", kcreated);
          println!("  \"Key Modified timestamp (UTC)\": \"{}\",", kmodified);
          println!("  \"Key Accessed timestamp (UTC)\": \"{}\",", kaccess);
          println!("  \"Key Changed timestamp (UTC)\": \"{}\",", kchanged);
          let kpermission = kmetadata.permissions();
          let kmode = kpermission.mode();
          println!("  \"Key Permissions\": \"{:o}\",", kmode);
          let kuid = kmetadata.uid();
          let kgid = kmetadata.gid();
          let kowner = match get_user_by_uid(kuid) {
              Some(user) => user.name().to_string_lossy().into_owned(),
              None => "-".to_string(),
          };
          let kgroup = match get_group_by_gid(kgid) {
              Some(group) => group.name().to_string_lossy().into_owned(),
              None => "-".to_string(),
          };
          println!("  \"Key Owner\": \"{} (uid: {})\",", kowner, uid);
          println!("  \"Key Group\": \"{} (gid: {})\"", kgroup, gid);
          println!(" }}");
          println!("}}");
          Ok(())
        },

        "verify" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} verify <file_to_verify> <signature_file> <public_key_path>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];
          let sig_path = &args[3];
          let pub_path = &args[4];
          let mut bytes = Vec::new();
          let mut kbytes = Vec::new();
          let mut sbytes = Vec::new();
          let file = File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path, e)));
          let pub_key = File::open(&pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key: {}", e)));
          let sig = File::open(&sig_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the signature file: {}", e)));

          let _ = pub_key?.read_to_end(&mut kbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the key: {}", e)));
          let _ = sig?.read_to_end(&mut sbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the signature file: {}", e)));
          let _ = file?.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the file: {}", e)));

          let msg = &bytes;
          let sig_verify = verify(&sbytes, &msg, &kbytes);
          let statusig = sig_verify.is_ok();
          println!("{{\"Verification Result\": \"{}\"}}", statusig);
          Ok(())
        },

        "generate" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} generate <dilithium5key, rng> (then for dilithium5key): <private_key_path> <public_key_path> (or if 'rng'): <size_in_bytes> <file_path>\"\n}}", args[0]);
            process::exit(1);
          }
          let gentype = &args[2];
          let arg1 = &args[3];
          let arg2 = &args[4];

          match gentype.as_str() {
            "dilithium5key" => {
              keygen(arg1, arg2)?;

            },
            "rng" => {
              let rngsize = arg1.parse::<usize>()?;
              let _ = bithack::gen_entropy(rngsize, arg2);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} generate <dilithium5key, rng> (then for dilithium5key): <private_key_path> <public_key_path> (or if 'rng'): <size_in_bytes> <file_path>\"\n}}", args[0]);
              process::exit(1);
            }
          }

          Ok(())
        },

        "encrypt" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} encrypt <aes-ctr aes-gcm chacha> <file_to_encrypt> <output_ciphertext>\"\n}}", args[0]);
            process::exit(1);
          }

          let entype = &args[2];
          let input_file = &args[3];
          let output_file = &args[4];
          match entype.as_str() {
            "aes-ctr" => {
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = enchantress::a2(bpassword, MAGIC);
              enchantress::encrypt_file(input_file, output_file, &key)?;
              let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
              let mut output_file_data = Vec::new();
              out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
              let validate = enchantress::ciphertext_hash(&key, &output_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              println!("{{\"Validation string\": \"{validate_str}\"}}");
              key.zeroize();
            },
            "aes-gcm" => {
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = enchantress::a2(bpassword, MAGIC);
              enchantress::aead_encrypt_file(input_file, output_file, &key)?;
              let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
              let mut output_file_data = Vec::new();
              out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
              let validate = enchantress::ciphertext_hash(&key, &output_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              println!("{{\"Validation string\": \"{validate_str}\"}}");
              key.zeroize();
            },
            "chacha" => {
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = a3(bpassword, TUR);
              enchanter::encrypt_file(input_file, output_file, &key)?;
              let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
              let mut output_file_data = Vec::new();
              out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
              let validate = enchanter::ciphertext_hash(&key, &output_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              println!("{{\"Validation string\": \"{validate_str}\"}}");
              key.zeroize();
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} encrypt <aes-ctr aes-gcm chacha> <file_to_encrypt> <output_ciphertext>\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "decrypt" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} decrypt <aes-ctr aes-gcm chacha> <file_to_decrypt> <output_plaintext>\"\n}}", args[0]);
            process::exit(1);
          }

          let entype = &args[2];
          let input_file = &args[3];
          let output_file = &args[4];
          match entype.as_str() {
            "aes-ctr" => {
              let mut file = File::open(input_file)?;
              let mut nonce = [0u8; 16];
              file.read_exact(&mut nonce)?;
              eprint!("Enter validation string (ciphertext_hash): ");
              std::io::stdout().flush()?;
              let ciphertext_bytes = read_password()?;
              let known_hash = ciphertext_bytes.to_string();
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = enchantress::a2(bpassword, MAGIC);
              let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
              let mut input_file_data = Vec::new();
              in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
              let validate = enchantress::ciphertext_hash(&key, &input_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              let checkme = &validate_str;
              if enchantress::checks(checkme, &known_hash) == true {
                enchantress::decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
                println!("{{\"Result\": \"file decrypted\"}}");
              } else {
                println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
              };
              key.zeroize();
            },
            "aes-gcm" => {
              let mut file = File::open(input_file)?;
              let mut nonce = [0u8; 12];
              file.read_exact(&mut nonce)?;
              eprint!("Enter validation string (ciphertext_hash): ");
              std::io::stdout().flush()?;
              let ciphertext_bytes = read_password()?;
              let known_hash = ciphertext_bytes.to_string();
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = enchantress::a2(bpassword, MAGIC);
              let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
              let mut input_file_data = Vec::new();
              in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
              let validate = enchantress::ciphertext_hash(&key, &input_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              let checkme = &validate_str;
              if enchantress::checks(checkme, &known_hash) == true {
                enchantress::aead_decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
                println!("{{\"Result\": \"file decrypted\"}}");
              } else {
                println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
              };
              key.zeroize();
            },
            "chacha" => {
              let mut file = File::open(input_file)?;
              let mut nonce = [0u8; 16];
              file.read_exact(&mut nonce)?;
              eprint!("Enter validation string (ciphertext_hash): ");
              std::io::stdout().flush()?;
              let ciphertext_bytes = read_password()?;
              let known_hash = ciphertext_bytes.to_string();
              // Hide from STDOUT for output management, use STDERR for password prompt.
              eprint!("Enter password: ");
              std::io::stdout().flush()?;
              let password = read_password()?;
              let bpassword = password.as_bytes();
              let mut key = a3(bpassword, TUR);
              let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
              let mut input_file_data = Vec::new();
              in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
              let validate = enchanter::ciphertext_hash(&key, &input_file_data, 64);
              let validate_str = BASE64_STANDARD.encode(&validate);
              let checkme = &validate_str;
              if enchanter::checks(checkme, &known_hash) == true {
                enchanter::decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
                println!("{{\"Result\": \"file decrypted\"}}");
              } else {
                println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
              };
              key.zeroize();
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} decrypt <aes-ctr aes-gcm chacha> <file_to_decrypt> <output_plaintext>\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },
        
        "encode" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} encode <base64 base58 hex base32_crockford base32_rfc4648 base32_rfc4648hex base32_z> <target_file> OR <url_encode> <string>\"\n}}", args[0]);
            process::exit(1);
          }

          let entype = &args[2];
          let input_file = &args[3];
          match entype.as_str() {
            "url_encode" => {
              let out = encoding::url_encode_string(input_file);
              println!("{out}");
            },
            "base64" => {
              let _ = encoding::base64_encode_file(input_file);
            },
            "base58" => {
              let _ = encoding::base58_encode_file(input_file);
            },
            "hex" => {
              let _ = encoding::hex_encode_file(input_file);
            },
            "base32_crockford" => {
              let _ = encoding::crockford_encode_file(input_file);
            },
            "base32_z" => {
              let _ = encoding::z_encode_file(input_file);
            },
            "base32_rfc4648" => {
              let _ = encoding::rfc4648_encode_file(input_file);
            },
            "base32_rfc4648hex" => {
              let _ = encoding::rfc4648hex_encode_file(input_file);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} encode <base64 base58 hex base32_crockford base32_rfc4648 base32_rfc4648hex base32_z> <file_to_encode> OR <url_encode> <string>\"\n}}", args[0]);
              process::exit(1);
            }
          }

          Ok(())
        },
        
        "decode" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} decode <base64 base58 hex base32_crockford base32_rfc4648 base32_rfc4648hex base32_z> <target_file> OR <url_decode> <string>\"\n}}", args[0]);
            process::exit(1);
          }

          let entype = &args[2];
          let input_file = &args[3];
          match entype.as_str() {
            "url_decode" => {
              let out = encoding::url_decode_string(input_file);
              println!("{out}");
            },
            "base64" => {
              let _ = encoding::base64_decode_file(input_file);
            },
            "base58" => {
              let _ = encoding::base58_decode_file(input_file);
            },
            "hex" => {
              let _ = encoding::hex_decode_file(input_file);
            },
            "base32_crockford" => {
              let _ = encoding::crockford_decode_file(input_file);
            },
            "base32_z" => {
              let _ = encoding::z_decode_file(input_file);
            },
            "base32_rfc4648" => {
              let _ = encoding::rfc4648_decode_file(input_file);
            },
            "base32_rfc4648hex" => {
              let _ = encoding::rfc4648hex_decode_file(input_file);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} decode <base64 base58 hex base32_crockford base32_rf4648 base32_rf4648hex base32_z> <file_to_decode> OR <url_decode> <string>\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "analyze" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} analyze <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];

          let report = analysis::cryptanalyze_file(file_path)?;
          println!("{report}");
          Ok(())
        },

        "tls_debug" => {
          if args.len() > 6 || args.len() < 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} tls_debug <url:port> <trusted_roots PEM> <no_auth, no_auth_extract, auth, auth_extract> <if auth, then this is the client auth PEM>\"\n}}", args[0]);
            process::exit(1);
          }
          let target_arg = &args[2];
          let roots_path = &args[3];
          let auth_bool = &args[4];

          match auth_bool.as_str() {
            "auth" => {
              if args.len() != 6 {
                 eprintln!("{{\n  \"ERROR\": \"Usage: {} tls_debug <url:port> <trusted_roots PEM> <no_auth, no_auth_extract, auth, auth_extract> <if 'auth', then this is the client auth PEM path is required>\"\n}}", args[0]);
                 process::exit(1);
              }
              let auth_path = &args[5];
              let _ = tls_debug::auth_debug(target_arg, roots_path, auth_path);
            },
            "no_auth" => {
              let _ = tls_debug::debug(target_arg, roots_path);
            },
            "no_auth_extract" => {
              let _ = tls_debug::extract_debug(target_arg, roots_path);
            },
            "auth_extract" => {
              if args.len() != 6 {
                 eprintln!("{{\n  \"ERROR\": \"Usage: {} tls_debug <url:port> <trusted_roots PEM> <no_auth, no_auth_extract, auth, auth_extract> <if 'auth', then this is the client auth PEM path is required>\"\n}}", args[0]);
                 process::exit(1);
              }
              let auth_path = &args[5];
              let _ = tls_debug::extract_auth_debug(target_arg, roots_path, auth_path);
            },

            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} tls_debug <url:port> <trusted_roots PEM> <no_auth, no_auth_extract, auth, auth_extract> <if auth, then this is the client auth PEM\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "brute" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} brute <caesar, xor, xor_batch> <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let cipher_type = &args[2];
          let file_path = &args[3];

          match cipher_type.as_str() {
            "xor_batch" => {
              let _ = analysis::xor_batch(file_path);
            },
            "caesar" => {
              let _ = analysis::caesar_analysis(file_path);
            },
            "xor" => {
              let _ = analysis::xor_analysis(file_path);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} brute <caesar, xor, xor_batch> <target_file>\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "parse" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} parse <certs> <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let parse_type = &args[2];
          let file_path = &args[3];

          match parse_type.as_str() {
            "certs" => {
              let report = parsers::describe_certs(file_path)?;
              println!("{report}");
            },
          _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} parse <certs> <target_file>\"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "disassemble" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} disassemble <arm64, x86_64, ebpf> <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let dis_type = &args[2];
          let file_path = &args[3];

          match dis_type.as_str() {
            "ebpf" => {
              let _ = disassemble::bpf_dis_to_string(file_path)?;
              println!("{{\"Disassembly output\": \"./disassembly.txt\"}}");
            },
            "arm64" => {
              let _ = disassemble::arm_dis_to_string(file_path)?;
              println!("{{\"Disassembly output\": \"./disassembly.txt\"}}");
            },
            "x86_64" => {
              let _ = disassemble::intel_dis_to_string(file_path)?;
              println!("{{\"Disassembly output\": \"./disassembly.txt\"}}");
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} disassemble <arm64, x86_64, ebpf> <target_file>\"\n}}", args[0]);
              process::exit(1);
            }
          }

          Ok(())
        },

        "hunter" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} hunter <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];
          let report = hunter::search_patterns(file_path, &Interesting::all())?;
          println!("{report}");
          Ok(())
        },

        "seek" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: echo -e \"pattern\" | {} seek <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];
          let _ = seek::search_in_file(file_path);
          Ok(())
        },

        "commander" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} commander <\"command to iterate>\"> <input_file>\n}}", args[0]);
            process::exit(1);
          }
          let commands = &args[2];
          let inputs = &args[3];
          let _ = commander::run_iter(commands, inputs)?;
          Ok(())
        },

        "researcher" => {
          if args.len() < 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} researcher <help_map, read, read_arm64, read_ebpf> <input_file>\n}}", args[0]);
            process::exit(1);
          }
          if args.len() > 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} researcher <help_map, read, read_arm64, read_ebpf> <input_file>\n}}", args[0]);
            process::exit(1);
          }

          let otype = &args[2];
          match otype.as_str() {
            "help_map" => {
              let _ = researcher::color_map();
            },
            "read" => {
              let input = &args[3];
              let _ = researcher::annotated_dump(input);
            },
            "read_arm64" => {
              let input = &args[3];
              let _ = researcher::arm_annotated_dump(input);
            },
            "read_ebpf" => {
              let input = &args[3];
              let _ = researcher::ebpf_annotated_dump(input);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} researcher <help_map, read, read_arm64, read_ebpf> <target_file>\"\n}}", args[0]);
              process::exit(1);
            }
          }

          Ok(())
        },

        "reverse_bytes" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} reverse_bytes <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];

          let _ = bithack::reverse_file_bytes(file_path);
          Ok(())
        },
        
        "flatten" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} flatten <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];

          let _ = bithack::flatten(file_path);
          Ok(())
        },
        
        "byte_range" => {
          if args.len() != 6 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} byte_range <hexdump, hex, s_hex> <target_file> <starting_byte> <ending_byte> \"\n}}", args[0]);
            process::exit(1);
          }
          let atype = &args[2];
          let file_path = &args[3];
          let starting_bytein = &args[4];
          let ending_bytein = &args[5];
          let starting_byte: u64 = starting_bytein.parse()?;
          let ending_byte: u64 = ending_bytein.parse()?;

          match atype.as_str() {
            "hexdump" => {
              let report = bithack::hexdump_range(file_path, starting_byte, ending_byte)?;
              let printme1 = format!("{report:?}");
              let printme2 = printme1.remove_last();
              print!("{}", printme2.remove_last());
            },
            "hex" => {
              let report = bithack::hex_range(file_path, starting_byte, ending_byte)?;
              let printme1 = format!("{report:?}");
              let printme2 = printme1.remove_last();
              print!("{}", printme2.remove_last());
            },
            "s_hex" => {
              let report = bithack::serialized_hex_range(file_path, starting_byte, ending_byte)?;
              let printme1 = format!("{report:?}");
              let printme2 = printme1.remove_last();
              print!("{}", printme2.remove_last());
            },

            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} byte_range <hexdump, hex, s_hex> <target_file> <starting_byte> <ending_byte> \"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "bitflip" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} bitflip <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let file_path = &args[2];

          let _ = bithack::bitflip(file_path);
          Ok(())
        },

        "single_bitflip" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} single_bitflip <position> <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let position = &args[2];
          let file_path = &args[3];

          let _ = bithack::precise_bitflip(file_path, position);
          Ok(())
        },

        "split_file" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} split_file  <position> <target_file>\"\n}}", args[0]);
            process::exit(1);
          }
          let position = &args[2];
          let file_path = &args[3];

          let _ = bithack::splitter(file_path, position);
          Ok(())
        },

        "shift" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} shift <left right> <byte count> <file>\"\n}}", args[0]);
            process::exit(1);
          }
          let direction = &args[2];
          let shiftcount = &args[3];
          let file = &args[4];

          let _ = bithack::shift(file, direction, shiftcount);
          Ok(())
        },

        "xor_these" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} xor_these  <file1> <file2>\"\n}}", args[0]);
            process::exit(1);
          }
          let file1 = &args[2];
          let file2 = &args[3];

          let _ = bithack::xor_these(file1, file2);
          Ok(())
        },
        "derive_key" => {
          if args.len() != 5 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} derive_key <argon2id> <data_string> <salt_string>\"\n}}", args[0]);
            process::exit(1);
          }
          let hash = &args[2];
          let input = &args[3];
          match hash.as_str() {
            "argon2id" => {
              let salt = &args[4];
              let bsalt = salt.clone().into_bytes();
              let binput = input.clone().into_bytes();
              let _ = hashfunctions::argon2id(&binput, &bsalt);
            },
            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} derive_key <argon2id> <data_string> <salt_string> \"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },

        "hash" => {
          if args.len() != 4 {
            eprintln!("{{\n  \"ERROR\": \"Usage: {} hash <all, sha512, sha256, sha3_256, sha3_384, shake256_10, shake256_32, blake3, blake2b512> <file_to_hash> OR hash <attest, attest_mbr> <linux, alpine, macos> \"\n}}", args[0]);
            process::exit(1);
          }
          let hash = &args[2];
          let input = &args[3];
          match hash.as_str() {
            "attest_mbr" => {
              match input.as_str() {
                  "linux" => {
                    let mbr = true;
                    let _ = hashfunctions::attest_linux(mbr);
                  },
                  "alpine" => {
                    let mbr = true;
                    let _ = hashfunctions::attest_alpine_lts(mbr);
                  },
                  "macos" => {
                    let mbr = true;
                    let _ = hashfunctions::attest_macos(mbr);
                  },

                  _ => {
                    eprintln!("{{\n  \"ERROR\": \"System attestation use: hash attest_mbr <linux, alpine, macos>\"\n}}");
                  }
              }
            },
            "attest" => {
              match input.as_str() {
                  "linux" => {
                    let mbr = false;
                    let _ = hashfunctions::attest_linux(mbr);
                  },
                  "alpine" => {
                    let mbr = false;
                    let _ = hashfunctions::attest_alpine_lts(mbr);
                  },
                  "macos" => {
                    let mbr = false;
                    let _ = hashfunctions::attest_macos(mbr);
                  },

                  _ => {
                    eprintln!("{{\n  \"ERROR\": \"System attestation use: hash attest <linux, alpine, macos>\"\n}}");
                  }
              }
            },
            "all" => hashfunctions::file_all(input)?,
            "sha256" => {
              let _ = hashfunctions::sha256(input);
            },
            "sha512" => {
              let _ = hashfunctions::sha512(input);
            },
            "sha3_256" => {
              let _ = hashfunctions::sha3_256(input);
            },
            "shake256_10" => {
              let _ = hashfunctions::shake256_10(input);
            },
            "shake256_32" => {
              let _ = hashfunctions::shake256_32(input);
            },
            "blake3" => {
              let _ = hashfunctions::blake3(input);
            },
            "blake2b512" => {
              let _ = hashfunctions::blake2b512(input);
            },
            "sha3_384" => {
              let _ = hashfunctions::sha3_384(input);
            },

            _ => {
              eprintln!("{{\n  \"ERROR\": \"Usage: {} hash <all, sha512, sha256, sha3_256, sha3_384, shake256_10, shake256_32, blake3, blake2b512> <file_to_hash> OR hash <attest, attest_mbr> <linux, alpine, macos> \"\n}}", args[0]);
              process::exit(1);
            }
          }
          Ok(())
        },
        
        "metadata" => {
          if args.len() != 3 {
            eprintln!("{{\n  \"ERROR\": \"Usage: metadata <target_file>\"}}");
            process::exit(1);
          }
          let mut json_started = false;
          let file_path = Path::new(&args[2]);
          let metadata = try_print_json!(
            file_path.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata: {}", e))),
            json_started
          );
          let mut file = try_print_json!(
            File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
            json_started
          );
          let mut bytes = Vec::new();
          try_print_json!(
            file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
            json_started
          );
          let num_bytes = bytes.len();
          let num_bits = num_bytes * 8;
          let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;
          let file_is_open = match OpenOptions::new().read(true).write(true).open(file_path) {
            Ok(_) => false,
            Err(_) => true,
          };
          let chronox: String = Utc::now().to_string();
          let mut hasher = Shake256::default();
          hasher.update(&bytes);
          let mut resulto = hasher.finalize_xof();
          let mut shake256 = [0u8; 10];
          let _ = resulto.read(&mut shake256);
          json_started = true;
          println!("{{");
          println!("{:?}: {{", file_path);
          println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
          println!("  \"Report time\": \"{}\",", chronox);
          let num_io_blocks = metadata.blocks();
          println!("  \"Number of IO blocks\": \"{}\",", num_io_blocks);
          let blocksize = metadata.blksize();
          println!("  \"Block size\": \"{}\",", blocksize);
          let inode = metadata.ino();
          println!("  \"Inode\": \"{}\",", &inode);
          println!("  \"Total as bytes\": \"{}\",", &num_bytes);
          println!("  \"Total as kilobytes\": \"{}\",", &num_bytes / 1024);
          println!("  \"Total as megabytes\": \"{}\",", &num_bytes / (1024 * 1024));
          println!("  \"Total as bits\": \"{}\",", num_bits);
          println!("  \"Byte distribution\": \"{}\",", byte_distribution);
          let created: DateTime<Utc> = try_print_json!(
            metadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get created timestamp.")).map(DateTime::from),
            json_started
          );
          let modified: DateTime<Utc> = try_print_json!(
            metadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get modified timestamp.")).map(DateTime::from),
            json_started
          );
          let access: DateTime<Utc> = try_print_json!(
            metadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get accessed timestamp.")).map(DateTime::from),
            json_started
          );
          let changed: DateTime<Utc> = {
            let ctime = metadata.ctime();
            let ctimesec = metadata.ctime_nsec() as u32;
            let naive_datetime = try_print_json!(
              NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid changed timestamp")),
              json_started
            );
            TimeZone::from_utc_datetime(&Utc, &naive_datetime)
          };
          println!("  \"Created timestamp (UTC)\": \"{}\",", created);
          println!("  \"Modified timestamp (UTC)\": \"{}\",", modified);
          println!("  \"Accessed timestamp (UTC)\": \"{}\",", access);
          println!("  \"Changed timestamp (UTC)\": \"{}\",", changed);
          let permission = metadata.permissions();
          let mode = permission.mode();
          println!("  \"Permissions\": \"{:o}\",", mode);
          let uid = metadata.uid();
          let gid = metadata.gid();
          let owner = match get_user_by_uid(uid) {
            Some(user) => user.name().to_string_lossy().into_owned(),
            None => "-".to_string(),
          };
          let group = match get_group_by_gid(gid) {
            Some(group) => group.name().to_string_lossy().into_owned(),
            None => "-".to_string(),
          };
          println!("  \"Owner\": \"{} (uid: {})\",", owner, uid);
          println!("  \"Group\": \"{} (gid: {})\",", group, gid);
          if file_is_open {
            println!("  \"Open\": \"File is currently open by another program.\"");
          } else {
            println!("  \"Open\": \"File is not open by another program.\"");
          }
          println!(" }}");
          println!("}}");
          Ok(())
        },

        _ => {
          eprintln!("{{\n  \"ERROR\": \"Usage: <encrypt, decrypt, encode, decode, generate, sign, verify, analyze, brute, parse, disassemble, seek, tls_debug, hunter, commander, researcher, reverse_bytes, byte_range, bitflip, single_bitflip, split_file, shift, flatten, metadata, hash, derive_key, xor_these> <subcommands>  Try giant-spellbook <option> to print help for each option subcommands.\"\n}}");
          process::exit(1)
       }
    }

}

/// The main function is a wrapper for the run function, for error catching.
fn main() {
    if let Err(e) = run() {
        print_error_json(&e.to_string());
        std::process::exit(1);
    }
}
