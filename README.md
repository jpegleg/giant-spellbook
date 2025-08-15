![cdlogo](https://carefuldata.com/images/cdlogo.png)

# giant-spellbook

This tool is a "multi-tool" of cryptographic operations and binary/file analysis capabilities. It is useful for regular cryptographic operations like hashing files for checksums, encrypting files, creating and verifying Dilithium5-AES signatures. It uses the highest standards for cryptographic operations with the strongest encryption methods, signing, and hashing.

Giant-spellbook can perform different types of crypanalysis and gather numerous statistics on files and binaries as well as perform low level operations on them such as bitflipping and slicing.

There are additional forensics and reverse engineering capabilities, including disassembly and searching for potentially malicious bytes and strings.

The encryption mechanisms use Argon2id for key material generation from an interactive password. There is also a SHA3 integrity mechnism that is required for decryption, the same mechanism used by enchantress and enchanter tools. The validation string that is generated is required for decryption with the tools, in addition to the password used.

The digital signatures are post-quantum-cryptography Dilithium5-AES. The secret key is written as ciphertext, encrypted with AES-256. The decrypted key is only stored in RAM during the original generation of the key and when the key is used for signing.



| operation  | cipher/algos                                         | upstream     |
|------------|------------------------------------------------------|--------------|
| encryption | AES-256 CTR, SHA3 SHAKE256, BASE64, Argon2id         | enchantress  |
| encryption | AES-256 GCM, SHA3 SHAKE256, BASE64, Argon2id         | enchantress  |
| encryption | XChaCha20Poly1305, SHA3 SHAKE256, BASE64, Argon2id   | enchanter    |
| decryption | AES-256 CTR, SHA3 SHAKE256, BASE64, Argon2id         | enchantress  |
| decryption | AES-256 GCM, SHA3 SHAKE256, BASE64, Argon2id         | enchantress  |
| decryption | XChaCha20Poly1305, SHA3 SHAKE256, BASE64, Argon2id   | enchanter    |
| signing    | Dilithium5-AES, AES-256 CTR, Argon2id                | wormsign     |
| key gen    | Dilithium5-AES, AES-256 CTR, Argon2id                | wormsign     |
| verifying  | Dilithium5-AES                                       | wormsign     |

| operation  | hash algo                                            |
|------------|------------------------------------------------------|
| file hash  | BLAKE3                                               |
| file hash  | BLAKE2B512                                           |
| km hash    | Argon2id                                             |
| file hash  | SHA256                                               |
| file hash  | SHA512                                               |
| file hash  | SHA3-256                                             |
| file hash  | SHA3-384                                             |
| file hash  | SHA3 SHAKE256                                        |

| operation  | encoding type                                        |
|------------|------------------------------------------------------|
| encode     | base64                                               |
| encode     | base58                                               |
| encode     | hex                                                  |
| decode     | base64                                               |
| decode     | base58                                               |
| decode     | hex                                                  |

| operation   | action/algos                                                                       |
|-------------|------------------------------------------------------------------------------------|
| metadata    | file data, byte distribution, SHA3 SHAKE256                                        |
| bitflip     | bitwise NOT                                                                        |
| analyze     | file data, Chi, Hamming, Shannon entropy, rolling entropy, XOR, periodicity, ECB   |
| file_split  | split a file at a bit position to two new files                                    |
| bruteforce  | XOR and Caesar English bruteforce decryption                                       |
| parse       | parse PEM and DER x509 certificates inside files                                   |
| disassemble | disassemble machine code to assembly text file                                     |
| hunter      | search file for IoCs and potentially malicious bytes and strings                   |


## Installing

Giant-spellbook can be installed from crates.io:

```
cargo install giant-spellbook
```

Or compiled from source:

```
cargo build --release
sudo cp target/release/giant-spellbook /usr/local/bin/
```

Or installed from a release binary.


## Enchantress, Enchanter, and Wormsign

The giant-spellbook tool includes the libraries of other tools: wormsign, enchanter, and enchantress.

These tools are compatible for the corresponding functionality with giant-spellbook.

See the tools for more details:

https://github.com/jpegleg/enchanter

https://github.com/jpegleg/enchantress

https://github.com/jpegleg/wormsign

These three tools use TOML config files to store information and support modes such as environment variables and password files for use in automation systems.


## Usage Examples

The tool can be used to do many different types of cryptographic operations. We can also analyze files and gather UNIX file data about files.

Run with no arguments to print all of the options:

```
giant-spellbook
{
  "ERROR": "Usage: <encrypt, decrypt, encode, decode, generate, sign, verify, analyze, brute, parse, disassemble, hunter, reverse_bytes, bitflip, single_bitflip, split_file, metadata, hash, derive_key> <subcommands>  Try giant-spellbook <option> to print help for each option subcommands."
}

```

Use the first argument (option) by itself to print the help information for the subcommands (additional arguments):

```
giant-spellbook generate
{
  "ERROR": "Usage: giant-spellbook generate <private_key_path> <public_key_path>"
}
```

Generating a Dilithium5-AES encrypted secret key and public key:

```
giant-spellbook generate example.key example.pub
Enter key password then press enter (will not be displayed):

```

Signing with an encrypted Dilithium5-AES secret key:

```
giant-spellbook sign sample.file sample.sig example.pub example.key
Enter key password then press enter (will not be displayed):

{
"sample.file": {
  "Checksum SHA3 SHAKE256 10": "[158, 108, 141, 164, 236, 55, 153, 9, 114, 102]",
  "Report time": "2025-08-14 00:22:01.746655122 UTC",
  "Number of IO blocks": "8",
  "Block size": "4096",
  "Inode": "165678331",
  "Total as bytes": "17",
  "Total as kilobytes": "0",
  "Total as megabytes": "0",
  "Total as bits": "136",
  "Byte distribution": "0.23529411764705882",
  "Created timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Modified timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Accessed timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Changed timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Permissions": "100644",
  "Owner": "webserveradmin (uid: 1000)",
  "Group": "webserveradmin (gid: 1000)",
  "Open": "File is not open by another program. Signing...",
  "Dilithium signature file": "sample.sig",
  "Dilithium signing key": "example.key",
  "Key Inode": "165678332",
  "Key Created timestamp (UTC)": "2025-08-14 00:21:27.733197521 UTC",
  "Key Modified timestamp (UTC)": "2025-08-14 00:21:29.330167731 UTC",
  "Key Accessed timestamp (UTC)": "2025-08-14 00:22:01.745563032 UTC",
  "Key Changed timestamp (UTC)": "2025-08-14 00:21:29.330167731 UTC",
  "Key Permissions": "100600",
  "Key Owner": "webserveradmin (uid: 1000)",
  "Key Group": "webserveradmin (gid: 1000)"
 }
}

```

Using the quick cryptanalysis and binary analysis against a file:

```
giant-spellbook analyze sample.file
{
  "File": "sample.file",
  "Report time": "2025-08-14 00:22:33.139471580 UTC",
  "Size": 17,
  "Type": "Unknown",
  "Platform_guess": "Unknown",
  "Elf": {
    "is_elf": false,
    "class": 0,
    "endian": "Unknown",
    "os_abi": 0,
    "os_abi_name": "SYSV/Default '0'"
  },
  "PE": {
    "is_pe": false,
    "machine": null,
    "is_dll": false,
    "subsystem": null,
    "kind": ""
  },
  "Mach-O": {
    "is_macho": false,
    "is_fat": false,
    "fat_arch_count": 0,
    "kind": "Unknown"
  },
  "Clibrary": {
    "glibc": [],
    "musl": [],
    "uclibc": [],
    "libc_sonames": [],
    "darwin_libsystem_present": false,
    "darwin_versions": []
  },
  "Printable_ratio": 1.000000,
  "Entropy": 1.734522,
  "Chi_square": 1443.705882,
  "Rolling_entropy": {
    "window": 17,
    "count": 0,
    "min": null,
    "avg": null,
    "max": null
  },
  "ECB": [
    {"block_size": 8, "blocks": 2, "duplicate_blocks": 0, "max_repeat": 1, "score": 0.000000},
    {"block_size": 16, "blocks": 1, "duplicate_blocks": 0, "max_repeat": 1, "score": 0.000000}
  ],
  "Periodicity": {
    "best_lag": 1,
    "correlation": 0.750000
  },
  "Repeating_xor_keysizes": [
    {"keysize": 2, "norm_hamming": 0.000000},
    {"keysize": 3, "norm_hamming": 0.666667},
    {"keysize": 4, "norm_hamming": 3.000000}
  ],
  "Single_byte_xor_probe": {
    "best_key": "0x47",
    "score": 0.564706,
    "printable": 1.000000
  }
}
```

Gathering (UNIX) file data on a target file, including if the file is open and a checksum:

```
giant-spellbook metadata sample.file
{
"sample.file": {
  "Checksum SHA3 SHAKE256 10": "[158, 108, 141, 164, 236, 55, 153, 9, 114, 102]",
  "Report time": "2025-08-14 00:22:38.223722812 UTC",
  "Number of IO blocks": "8",
  "Block size": "4096",
  "Inode": "165678331",
  "Total as bytes": "17",
  "Total as kilobytes": "0",
  "Total as megabytes": "0",
  "Total as bits": "136",
  "Byte distribution": "0.23529411764705882",
  "Created timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Modified timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Accessed timestamp (UTC)": "2025-08-14 00:22:01.745563032 UTC",
  "Changed timestamp (UTC)": "2025-08-14 00:21:06.523593117 UTC",
  "Permissions": "100644",
  "Owner": "webserveradmin (uid: 1000)",
  "Group": "webserveradmin (gid: 1000)",
  "Open": "File is not open by another program."
 }
}

```

Encrypting a file with AES-256 in GCM mode:

```
giant-spellbook encrypt aes-gcm sample.file sample.file.e
Enter password:
{"Validation string": "6ucVEJJkPN2wsjW5b+3RVcq0vkjMBjMpLxhh0ddCU6am9gWv12E0lQjnezTKWFAZBqiLVWvIQAjs5vyM5Unnug=="}
```

Decrypting a file with AES-256 in GCM mode:

```
giant-spellbook decrypt aes-gcm sample.file.e sample.file.out
Enter validation string (ciphertext_hash):
Enter password:
{"Result": "file decrypted"}
```
_Note that the 'validation string' does not need to be treated as a secret. 
Also it can also be recovered with a decryption attempt if you know the password 
and the ciphertext hasn't been tampered with. The purpose of the validation
string is an additional ciphertext integrity mechanism - if the ciphertext
is tampered with, the validation string generated at the time of encryption
will no longer match. Further, if the password is not correct, the validation
string won't match._


Bruteforce recovery of an English language plaintext with single byte XOR:

```
hexdump -C sample.cipher # show the weak ciphertext
00000000  50 6c 6d 77 24 6d 77 24  65 24 70 61 77 70 24 69  |Plmw$mw$e$pawp$i|
00000010  61 77 77 65 63 61 24 70  6c 65 70 24 6c 65 77 24  |awweca$plep$lew$|
00000020  66 61 61 6a 24 61 6a 67  76 7d 74 70 61 60 25 24  |faaj$ajgv}tpa`%$|
00000030  4b 6c 24 77 6a 65 74 25                           |Kl$wjet%|
00000038

giant-spellbook brute xor sample.cipher
{
  "Decryption_successful": true,
  "Xor_key_used": 4,
  "Analysis_duration_seconds": 0.000122,
  "Report_time_UTC": "2025-08-14T14:45:36.934876088+00:00",
  "Input_file": "sample.cipher",
  "Output_file": "sample.cipher__decrypted"
}
cat sample.cipher__decrypted
This is a test message that has been encrypted! Oh snap!
```
_Note that short messages that are only a few words may fail to decrypt with the "brute" functions.
Also the functions may report decryption success when something vaguely like English is found._


Get all hashes for a file:

```
giant-spellbook hash all sample.cipher
{
  "File": "sample.cipher",
  "Time": "2025-08-14 14:47:33.172006443 UTC",
  "SHAKE256 10": "[237, 36, 102, 121, 7, 223, 214, 149, 160, 229]",
  "BLAKE3": "89f4fa67f8b6dd9a6393c368d88895e4c369d4a43604fc1f317c23c326bbd61d",
  "BLAKE2B-512": "e3ad1cf4bef35150e313dd898e3e38fd546a65b6d412908fe881b87af78898cd8615077cb6b5ebb9994661a0b9caddbbb054f9b01dd41670d75026ac3fd6fbe1",
  "SHA3-256": "fc68e832573e55d3d1082d5394b309651903aaf17586c52b1c3ddfd55453bf05",
  "SHA3-384": "a9af170c6c0827b02d4ec0ed05a93107da0a64e84108bea0a4c7a9a43ce1d1e4559ab4de18db8303799a67b7a0ea8965",
  "SHA256": "34188b5eb7402e8161ae08aefbb7f9938ff0bb8b166d3f16aa04a0ade44d0883",
  "SHA512": "3f83fe11ff6b53dd452bea5a6de2e94131252ceb2823b241fb774841ca768c5e62e1704151e5fa0d20fea57093257b4998b5dc46ad49db154e03e2350e1a65cb"
}

```

Get an individual (BLAKE3) hash of a file:


```
giant-spellbook hash blake3 sample.file
{
  "File": "sample.file",
  "Time": "2025-08-14 15:13:03.859480735 UTC",
  "BLAKE3": "0365f8701d5ef9864a0520579d81fe0d1e66b25895b47663723b38cce5d2ea8b"
}

```

Parse all DER and PEM format certificates from a file:

```
giant-spellbook parse certs mystery.file
[
  {
      "version": 3,
      "serial_hex": "00:E2:2F:0E:25:5B:D7:C7:95",
      "signature_algorithm": "1.2.840.113549.1.1.11",
      "issuer": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
      "subject": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
      "validity": {
        "not_before": "Aug 14 16:56:11 2016 +00:00",
        "not_after": "Aug 12 16:56:11 2026 +00:00"
      },
      "spki": {
        "algorithm": "1.2.840.113549.1.1.1",
        "public_key_bits_approx": 2160
      },
      "extensions": {
      "basic_constraints": {
        "ca": true
      },
      "subject_key_identifier": "6C:D3:A5:03:AB:0D:5F:2C:C9:8D:8A:9C:88:A7:88:77:B8:37:FD:9A",
      "authority_key_identifier": "6C:D3:A5:03:AB:0D:5F:2C:C9:8D:8A:9C:88:A7:88:77:B8:37:FD:9A"
      },
      "signature_len": 256
    }
]

```

Disassemble a file:

```
giant-spellbook disassemble /usr/local/bin/kubectl
{"Disassembly output": "./disassembly.asmod"}
head -n10 disassembly.asmod # show first 10 lines
L_0000:
    ; 0000: 457F
    RST 17791
L_0001:
    ; 0001: 464C
    RST 17996
L_0002:
    ; 0002: 0102
    RST 258
L_0003:
```
_Note that the disassembly.asmod output file can be rather large. Also the function writes to that file in pwd, so
previously existing disassembly.asmod files in pwd would be overwritten._

Hunt for IoCs and potentially malicious bytes within a file:

```
giant-spellbook hunter /usr/local/bin/kubectl
{
  "File": "/usr/local/bin/kubectl",
  "Report time": "2025-08-15 20:40:22.693576073 UTC",
  "Matched patterns": [
    {
      "Pattern name": "rar_magic_v4",
      "Byte offset": [48840288]
    },
    {
      "Pattern name": "rar_magic_v5",
      "Byte offset": [48840464]
    },
    {
      "Pattern name": "zip_magic_local",
      "Byte offset": [869315, 20505776, 20536885, 48839272]
    },
    {
      "Pattern name": "zip_magic_central",
      "Byte offset": [868399, 20506127, 20527445]
    },
    {
      "Pattern name": "zip_magic_end",
      "Byte offset": [867683, 20532282]
    },
    {
      "Pattern name": "bin_bash_use",
      "Byte offset": [28183822, 29307524, 29696469]
    },
    {
      "Pattern name": "passwd_access",
      "Byte offset": [28196715]
    }
  ]
}
```
_Note that the 'hunter' is just checking for patterns to aide in research,
it cannot determine if the binary is actually malicious. Essentially all
shell scripts will be flagged for shell use, and files with compressed
data inside might get flagged for having compressed data. These are important
indicators for malware research, but also are used normally._

The hunter includes checks for many known indicators of compromise (IoCs), as well as bytes and strings that are used in malware such as reverse shells, binary packing, covering tracks, and more.
There are many more patterns to check for, but this function has a good start and will continue to be expanded and refined going forward in future releases of giant-spellbook.

Go binaries commonly match a number of patterns like in the example with `kubectl`. While this isn't malicious exactly, Go just commonly has large binaries that include some of these patterns.
While many cases are normal, don't let that get your guard down. The byte offset is provided so that the occurrence of the pattern can be more closely researched if desired.


### File type detections

The file detections are separate from the "hunter" checks. The file detections are in "analyze", see the output "Type" as well as other supporting details in that JSON.

Because there is some variety in PE file usage and little to distinguish between some uses, some UEFI files will be guessed as Windows, such as linux kernel images.

File type detections include:

- "ELF"
- "WASM"
- "Mach-O"
- "PE"
  - "EXE"
  - "DLL"
  - "UEFI"
- "PNG"
- "JPEG"
- "PDF"
- "GIF"
- "XLSX (ZIP+xl/)"
- "DOC (OLE/CFB)"
- "OLE/CFB"
- "PEM"
- "RAR5"
- "RAR4"
- "TAR"
- "7z"
- "ZIP"
- "GZIP"
- "XZ"
- "Python Pickle"
- "ISO-9660 (.iso)"
- "VHDX"
- "VHD"
- "DER"
  - x509
  - PKCS#7
  - PKCS#12

File type detections are not perfect and should be taken as a data point or best guess rather than a conclusion.


## Bitflipping and slicing

There are two features for bitflipping in giant-spellbook. The first one bitflips the whole file and the second one flips a specific bit at a position.

"bitflip" option flips all bits in the given file, overwriting the file

"single_bitflip" flips the bit at the given position in a file, overwriting the file

"split_file" splits the file into two files at the given position, creating new files with __first and __second extensions

"reverse_bytes" reverses all of the bytes of the file, overwriting the file

## Encoding and decoding

The tool can encode and decode files in place. Hex, base64, and base58 encoding options are available.
