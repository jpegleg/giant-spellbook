![cdlogo](https://carefuldata.com/images/cdlogo.png)

# giant-spellbook

This tool is a "multi-tool" of cryptographic operations and binary/file analysis capabilities. It is useful for regular cryptographic operations like hashing files for checksums, encrypting files, creating and verifying Dilithium5-AES signatures. It uses the highest standards for cryptographic operations with the strongest encryption methods, signing, and hashing.

Giant-spellbook can perform different types of cryptanalysis and gather numerous statistics on files and binaries as well as perform low level operations on them such as bitflipping and slicing.

There are additional forensics and reverse engineering capabilities, including disassembly and searching for potentially interesting bytes and strings.

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

| operation     | action/algos                                                                       |
|---------------|------------------------------------------------------------------------------------|
| metadata      | file data, byte distribution, SHA3 SHAKE256                                        |
| bitflip       | bitwise NOT                                                                        |
| analyze       | file data, Chi, Hamming, Shannon entropy, rolling entropy, XOR, periodicity, ECB   |
| file_split    | split a file at a bit position to two new files                                    |
| reverse_bytes | reverse the byte order of a file                                                   |
| bruteforce    | XOR and Caesar English bruteforce decryption                                       |
| parse         | parse PEM and DER x509 certificates inside files                                   |
| disassemble   | disassemble machine code to assembly text file                                     |
| hunter        | search a file for IoCs and potentially interesting bytes and strings               |
| byte_range    | print hex or hex and ascii of a file from a byte position range                    |
| commander     | run a command for each line in a file, supplying the line as STDIN to command      |
| researcher    | interactive disassembly and hexdump of a file with colored byte highlighting       |
| seek          | search for binary or strings from within a file and report byte positions          |

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


## Usage Examples

The tool can be used to do many different types of cryptographic operations. We can also analyze files and gather UNIX file data about files.

Run with no arguments to print all of the options:

```
giant-spellbook
{
  "ERROR": "Usage: <encrypt, decrypt, encode, decode, generate, sign, verify, analyze, brute, parse, disassemble, seek, hunter, commander, researcher, reverse_bytes, byte_range, bitflip, single_bitflip, split_file, metadata, hash, derive_key> <subcommands>  Try giant-spellbook <option> to print help for each option subcommands."
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

Disassemble a file (x86_64):

```
giant-spellbook disassemble x86_64 /usr/local/bin/kubectl
{"Disassembly output": "./disassembly.txt"}
head -n10 disassembly.txt # show first 10 lines
00000000: 7f 45                   jg 0x47
00000002: 4c 46 02 01             add r8b, byte ptr [rcx]
00000006: 01 00                   add dword ptr [rax], eax
00000008: 00 00                   add byte ptr [rax], al
0000000a: 00 00                   add byte ptr [rax], al
0000000c: 00 00                   add byte ptr [rax], al
0000000e: 00 00                   add byte ptr [rax], al
00000010: 02 00                   add al, byte ptr [rax]
00000012: 3e 00 01                add byte ptr ds:[rcx], al
00000015: 00 00                   add byte ptr [rax], al
```
_Note that the disassembly.txt output file can be rather large. Also the function writes to that file in pwd, so
a previously existing disassembly.txt file in pwd would be overwritten._

ARM64 disassembly is supported via the 'arm64' subcommand to 'disassemble'.

Hunt for IoCs and potentially interesting bytes within a file:

```
giant-spellbook hunter /usr/local/bin/kubectl
{
  "File": "/usr/local/bin/kubectl",
  "Report time": "2025-08-16 02:37:54.280406353 UTC",
  "Matched patterns": [
    {
      "Pattern name": "pe_magic",
      "Byte offset": [26532333]
    },
    {
      "Pattern name": "elf_magic",
      "Byte offset": [0]
    },
    {
      "Pattern name": "gzip_magic",
      "Byte offset": [3640018, 3855956, 48839120, 48871360, 48873664, 48879424, 48879744, 48882528, 48882912, 48883712, 48885120, 48886624, 48887136, 48887648, 48890752, 48891296, 48895456, 48899360, 48901376, 48902048, 48902720, 48903392, 48906848, 48908288, 48909760, 48911328, 48912128, 48912928, 48913728, 48915360, 48916192, 48917856, 48919584, 48920448, 48922176, 48923072, 48923968, 48924896, 48925824, 48926752, 48927680, 48929632, 48948256, 48950560, 48951712, 48952896, 48954144, 48961152, 48962688, 48964256, 48965856, 48967488, 48969120, 48970752, 48972384, 48974080, 48975776, 48979168, 48980928, 48982688, 48984512, 48988544, 48996864, 49001376, 49011872, 49014752, 49152288, 49254944]
    },
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
      "Pattern name": "python3_use",
      "Byte offset": [29339887]
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
data inside might get flagged for having compressed data, Linux binaries have
elf magic, windows binaries have pe magic. These are important
indicators for malware research, but also are used normally._

The hunter includes checks for many known indicators of compromise (IoCs), as well as bytes and strings that are used in malware such as reverse shells, binary packing, covering tracks, and more.
There are many more patterns to check for, but this function has a good start and will continue to be expanded and refined going forward in future releases of giant-spellbook.

Go binaries commonly match a number of patterns like in the example with `kubectl`. While this isn't malicious exactly, Go just commonly has large binaries that include some of these patterns within.
While many cases are normal, don't let that get your guard down. The byte offset is provided so that the occurrence of the pattern can be more closely researched if desired.

To review a byte position in a file as hex and ascii:

```
giant-spellbook byte_range hexdump /usr/local/bin/kubectl 29339887 29340000
0000000001bfb0ef  70 79 74 68 6f 6e 33 0a  0a 23 20 43 6f 70 79 72  |python3..# Copyr|
0000000001bfb0ff  69 67 68 74 20 32 30 31  37 20 54 68 65 20 4b 75  |ight 2017 The Ku|
0000000001bfb10f  62 65 72 6e 65 74 65 73  20 41 75 74 68 6f 72 73  |bernetes Authors|
0000000001bfb11f  2e 0a 23 0a 23 20 4c 69  63 65 6e 73 65 64 20 75  |..#.# Licensed u|
0000000001bfb12f  6e 64 65 72 20 74 68 65  20 41 70 61 63 68 65 20  |nder the Apache |
0000000001bfb13f  4c 69 63 65 6e 73 65 2c  20 56 65 72 73 69 6f 6e  |License, Version|
0000000001bfb14f  20 32 2e 30 20 28 74 68  65 20 22 4c 69 63 65 6e  | 2.0 (the "Licen|
0000000001bfb15f  73                                                |s|
```

To review a byte position and only output the hex (with the trailing '()' at the end):

```
giant-spellbook byte_range hex /usr/local/bin/kubectl 29339887 29340000
70 79 74 68 6f 6e 33 0a  0a 23 20 43 6f 70 79 72
69 67 68 74 20 32 30 31  37 20 54 68 65 20 4b 75
62 65 72 6e 65 74 65 73  20 41 75 74 68 6f 72 73
2e 0a 23 0a 23 20 4c 69  63 65 6e 73 65 64 20 75
6e 64 65 72 20 74 68 65  20 41 70 61 63 68 65 20
4c 69 63 65 6e 73 65 2c  20 56 65 72 73 69 6f 6e
20 32 2e 30 20 28 74 68  65 20 22 4c 69 63 65 6e
73
```

There is also a subcommand to print serialized hex with no spaces or newlines, 's_hex':

```
giant-spellbook byte_range s_hex /usr/local/bin/kubectl 29339887 29340000
707974686f6e330a0a2320436f70797269676874203230313720546865204b756265726e6574657320417574686f72732e0a230a23204c6963656e73656420756e6465722074686520417061636865204c6963656e73652c2056657273696f6e20322e30202874686520224c6963656e73
```

If the purpose is to decode back to binary, then the s_hex output is ready to go.


```
giant-spellbook byte_range s_hex /usr/local/bin/kubectl 29339887 29340000 > test2
giant-spellbook decode hex test2
{ "Result": "Hex data decoded and written to file: test2" }
```

If the decode has no output and left a `.tmp` file in pwd, then the decoding failed.

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

If the decode has no output and left a `.tmp` file in pwd, then the decoding failed.

If decoding is successful, JSON will be printed. If decoding fails, check the file for invalid data and try again or use another approach.

## Commander

The 'commander' option enables command execution iteration with detailed logging. There are many potential uses for this, including cryptanalysis and batch processing.

The input file is a line delimited file that can contain any data to send into the given command.

```
giant-spellbook commander /bin/bash maintenance_actions.txt
```

The command can use double quotes so it can contain spaces.

```
giant-spellbook commander "/usr/local/bin/cryptex.sh batch_xor /opt/workspace/ciphertexts/" xor_keys.txt
```


The output is stored in a `results.log` that contains date and time in UTC, the input line number, the command, the exit status of the command, the input, STDOUT, and STDERR.


## Researcher

The 'researcher' option is an interactive hexdump with x86_64 (intel) or ARM64 disassembly. The hexdump has color highlighting to mark ELF, PE, and Mach-O magic, ASCII control characters, and more.

Use the 'help_map' subcommand to print the meanings of the colors and symbols and print out some tips for using this mode.
The 'help_map' has commands and explanations for using 'researcher'. These commands include 'base64' and 'binary' which can
be used to print out additional views of the data in the current buffer.

The interactive session of 'researcher' is a segment-by-segment hexdump and disassembly, activated with the 'read' subcommand targeting a file.

The functionality attempts to ensure that diassembled instructions are not chopped at the end with look-head/over-read.

Pressing enter will move on to the next (64 byte) buffer number. Typing a number and pressing enter will jump to that buffer number in the file. The buffers are 64 bytes, plus the 15 byte lookahead.

Use control + c to exit, or read to the end of the file by pressing the enter key or entering a buffer number past the length of the file.

This 'researcher' option may not work well with all terminals/consoles and all platforms. I noted that some alpine linux consoles needed to run `reset` to get the display back after exiting the 'researcher'.

Use a full color terminal emulator to get the full experience with the byte coloring. I can recommend [WezTerm](https://wezterm.org/).

## Seek

The 'seek' option can find binary segments and strings in files (including binaries). The binary/strings to search for are piped into STDIN. Note the `-e` is important on linux to getting an echo to work for hex escaped binary to be treated as binary.


```
echo -e '\x0f\x05\x00\x00' | giant-spellbook seek /usr/local/bin/kubectl
{
  "File": "/usr/local/bin/kubectl",
  "Input_pattern_hex_encoded": "0f050000",
  "Positions": [1937006,3891372,4036491,4042036,9434822,9907622,11606779,11917851,12595758,21210542,25101129,25101321,25899241,26881545,27464457,27637513,27717993,27726633,31177866,31201788,31414152,31778284,32131924,32443880,32443928,32554448,32656736,32671788,32719612,40064279,40555741,43173492,43324241]
}

```

This can also be used with 'commander', although the file needs to actually contain the binary on each line, not escaped hex like the echo.

```
giant-spellbook commander "giant-spellbook seek /usr/local/bin/kubectl >> kubectl_segments.bin.log" ./find_segments.bin.in

```

The strings don't have to be binary, and neither does the file. Plain text strings and plain text files work as well.

With 'seek', any pattern that is longer than 4096 bytes will be truncated to 4096 bytes when searching for it in the file.

Use caution with sending binary inputs via 'commander' as the `results.log` will become binary as the STDIN that was piped is logged to the file. Redirecting the output within the command is an option for keeping `results.log` as text.

If the STDOUT or STDERR of with 'commander' "command" have binary, then an error message will be logged to the `results.log` as it uses lossy UTF-8 parsing for STDOUT and STDERR and will log the line number and a stream error about invalid UTF-8 if that occurs.

## Project promises

This project will never use AI-slop. All code is reviewed, tested, implemented by a human that is academically trained in cryptography and information security. This repository and the crates.io repository is carefully managed and protected.

This project will never break backwards compatibility in releases regarding the signature validation or decryption.

This project will be maintained as best as is reasonable.
