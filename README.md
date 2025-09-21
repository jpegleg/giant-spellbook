![cdlogo](https://carefuldata.com/images/cdlogo.png)

# giant-spellbook

This tool is a "multi-tool" of cryptographic operations and binary/file analysis capabilities. It is useful for regular cryptographic operations like hashing files for checksums, encrypting files, creating and verifying Dilithium5-AES signatures. It uses the highest standards for cryptographic operations with the strongest encryption methods, signing, and hashing. All encryption code comes from upstream libraries in RustCrypto, leveraging the work of the best available industry standard cryptography.

Giant-spellbook can perform different types of cryptanalysis and gather numerous statistics on files and binaries as well as perform low level operations on them such as bitflipping and slicing.

There are additional forensics and reverse engineering capabilities, including disassembly and searching for potentially interesting bytes and strings.

The main version, currently 0.3.X, includes TLS debugging but does not support compiling for OpenBSD. The 0.2.X versions are still actively developed without the TLS debugging features, and do support OpenBSD. If you want to skip the 'tls_debug' feature, you can install with `cargo install giant-spellbook@0.2.X` where X is the latest minor version instead, or download release binaries and source code from the '0.2.X' branch on github. The 0.1.X versions are "core" functionality only and do not get new feature updates, only maintenance.

The encryption mechanisms use Argon2id for key material generation from an interactive password. There is also a SHA3 integrity mechnism that helps to identify tampering, the same mechanism used by enchantress and enchanter tools. The validation string that is generated is required with the tools, in addition to the password used.

The digital signatures are post-quantum-cryptography Dilithium5-AES. The secret key is written as ciphertext, encrypted with AES-256. The decrypted key is only stored in RAM during the original generation of the key and when the key is used for signing.



| operation  | cipher/algos                                         | upstream     |
|------------|------------------------------------------------------|--------------|
| encryption | AES-256 CTR, SHA3 SHAKE256, base64, Argon2id         | enchantress  |
| encryption | AES-256 GCM, SHA3 SHAKE256, base64, Argon2id         | enchantress  |
| encryption | XChaCha20Poly1305, SHA3 SHAKE256, base64, Argon2id   | enchanter    |
| decryption | AES-256 CTR, SHA3 SHAKE256, base64, Argon2id         | enchantress  |
| decryption | AES-256 GCM, SHA3 SHAKE256, base64, Argon2id         | enchantress  |
| decryption | XChaCha20Poly1305, SHA3 SHAKE256, base64, Argon2id   | enchanter    |
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
| encode     | base32 Crockford                                     |
| encode     | base32 RFC-4648                                      |
| encode     | base32 RFC-4648 hex                                  |
| encode     | z-base32                                             |
| encode     | URL encode                                           |
| encode     | hex                                                  |
| decode     | base64                                               |
| decode     | base58                                               |
| decode     | base32 Crockford                                     |
| decode     | base32 RFC-4648                                      |
| decode     | base32 RFC-4648 hex                                  |
| decode     | z-base32                                             |
| decode     | hex                                                  |
| decode     | URL decode                                           |

| operation     | action/algos                                                                       |
|---------------|------------------------------------------------------------------------------------|
| metadata      | file data, byte distribution, SHA3 SHAKE256                                        |
| bitflip       | bitwise NOT                                                                        |
| analyze       | file data, Chi, Hamming, Shannon entropy, rolling entropy, XOR, periodicity, ECB   |
| split_file    | split a file at a bit position to two new files                                    |
| flatten       | remove spaces, tabs, newlines, and returns from a text file                        |
| reverse_bytes | reverse the byte order of a file                                                   |
| bruteforce    | XOR and Caesar English bruteforce decryption, and single byte XOR batch processing |
| parse         | parse PEM and DER x509 certificates inside files                                   |
| disassemble   | disassemble machine code to assembly text file                                     |
| hunter        | search a file for IoCs and potentially interesting bytes and strings               |
| byte_range    | print hex or hex and ascii of a file from a byte position range                    |
| commander     | run a command for each line in a file, supplying the line as STDIN to command      |
| researcher    | interactive disassembly and hexdump of a file with colored byte highlighting       |
| seek          | search for binary or strings from within a file and report byte positions          |
| shift         | shift the bytes of a file by a given position to the left or right                 |
| xor_these     | bitwise XOR two files of the same length together, output to xor.out               |
| rng           | generate files of a given byte length from system entropy source                   |
| attest        | BLAKE2 system attestation for MacOS, Linux, and Alpine Linux                       |
| diff          | compare two files for differences, color highlighting and option for colorless     |

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
  "ERROR": "Usage: <encrypt, decrypt, encode, decode, generate, sign, verify, analyze, brute, parse, disassemble, seek, tls_debug, hunter, commander, researcher, reverse_bytes, byte_range, bitflip, single_bitflip, split_file, shift, flatten, metadata, hash, derive_key, xor_these> <subcommands>  Try giant-spellbook <option> to print help for each option subcommands."
}

```

Use the first argument (option) by itself to print the help information for the subcommands (additional arguments):

```
{
  "ERROR": "Usage: target/release/giant-spellbook generate <dilithium5key, rng> (then for 'dilithium5key'): <private_key_path> <public_key_path> (or if 'rng'): <size_in_bytes> <file_path>"
}
```

Generating a Dilithium5-AES encrypted secret key and public key:

```
giant-spellbook generate dilithium5key example.key example.pub
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

There is also 'xor_batch' subcommand for 'brute' that will create a directory for every byte and save the xor result of the input to `xor.out` in the corresponding directory.

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


We can create a recursive BLAKE3 hash report of a provided directory:

```
giant-spellbook hash recursive /tmp/project/
{
  "Target": "/tmp/project/",
  "Report start time": "2025-09-20 23:37:48.430713448 UTC",
  "BLAKE3 hash report":  [
    { "/tmp/project/file1.txt": "ee6d6e040d29f982b7a3c232728cc85120ddfb66cdb2251cf5e138c0f76e9bec", "Report time": "2025-09-20 23:37:48.430909965 UTC" },
    { "/tmp/project/file2.txt": "360dd61e30ee7870f72b741957ce509319f5fac8005a3776e9918fbafb2bdce9", "Report time": "2025-09-20 23:37:48.430938499 UTC" },
    { "/tmp/project/file3.txt": "f35adbadca2bd56f69d74fcb51b12b3d229e98e8c7e1e6c9087106e34ed45706", "Report time": "2025-09-20 23:37:48.430960705 UTC" },
    { "/tmp/project/file4.txt": "d45161efc5e6dfda99dfa7c61fad01b490607161d1ab489f51a4698c832ce143", "Report time": "2025-09-20 23:37:48.430980953 UTC" },
    { "/tmp/project/more_things/1.bin": "cebd8842c67ac69c3f0d86f925e6c4ee26e932e59fa2b833317d2e7bc9cffe06", "Report time": "2025-09-20 23:37:48.431141303 UTC" },
    { "/tmp/project/more_things/2.bin": "0e0ecfb3174827728d4ba272b06d86424f996776f6369d8bbc5966bd9441e985", "Report time": "2025-09-20 23:37:48.431172403 UTC" },
    { "/tmp/project/more_things/3.bin": "fc163c079ca5c38841e653a93a2aaa93eb6fb7ddea7b8ab9ee4a1cb7ff3ea5c9", "Report time": "2025-09-20 23:37:48.431197904 UTC" },
    { "/tmp/project/more_things/4.bin": "f6fc1278f88b1e046b6919c6568807f25cc83e34feb4e8fa587aa1e7b58d7515", "Report time": "2025-09-20 23:37:48.431224837 UTC" },
    { "Report end time": "2025-09-20 23:37:48.431246185 UTC" }
  ]
}

```

We can make an attestation of the system, currently with support for GNU/Linux, Alpine Linux, and MacOS systems (OpenBSD support is in 0.2.X):

```
giant-spellbook hash attest_mbr alpine
{
  "System": "firfather1\nLinux version 6.6.94-0-lts (buildozer@build-3-20-x86_64) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1-Alpine SMP PREEMPT_DYNAMIC 2025-06-23 15:38:39\n",
  "Time": "2025-09-13 19:34:31.390010161 UTC",
  "MBR checked": "true",
  "MBR first sector (512 bytes)": "[51, 192, 250, 142, 216, 142, 208, 188, 0, 124, 137, 230, 6, 87, 142, 192, 251, 252, 191, 0, 6, 185, 0, 1, 243, 165, 234, 31, 6, 0, 0, 82, 82, 180, 65, 187, 170, 85, 49, 201, 48, 246, 249, 205, 19, 114, 19, 129, 251, 85, 170, 117, 13, 209, 233, 115, 9, 102, 199, 6, 141, 6, 180, 66, 235, 21, 90, 180, 8, 205, 19, 131, 225, 63, 81, 15, 182, 198, 64, 247, 225, 82, 80, 102, 49, 192, 102, 153, 232, 102, 0, 232, 53, 1, 77, 105, 115, 115, 105, 110, 103, 32, 111, 112, 101, 114, 97, 116, 105, 110, 103, 32, 115, 121, 115, 116, 101, 109, 46, 13, 10, 102, 96, 102, 49, 210, 187, 0, 124, 102, 82, 102, 80, 6, 83, 106, 1, 106, 16, 137, 230, 102, 247, 54, 244, 123, 192, 228, 6, 136, 225, 136, 197, 146, 246, 54, 248, 123, 136, 198, 8, 225, 65, 184, 1, 2, 138, 22, 250, 123, 205, 19, 141, 100, 16, 102, 97, 195, 232, 196, 255, 190, 190, 125, 191, 190, 7, 185, 32, 0, 243, 165, 195, 102, 96, 137, 229, 187, 190, 7, 185, 4, 0, 49, 192, 83, 81, 246, 7, 128, 116, 3, 64, 137, 222, 131, 195, 16, 226, 243, 72, 116, 91, 121, 57, 89, 91, 138, 71, 4, 60, 15, 116, 6, 36, 127, 60, 5, 117, 34, 102, 139, 71, 8, 102, 139, 86,20, 102, 1, 208, 102, 33, 210, 117, 3, 102, 137, 194, 232, 172, 255, 114, 3, 232, 182, 255, 102, 139, 70, 28, 232, 160, 255, 131, 195, 16, 226, 204, 102, 97, 195, 232, 118, 0, 77, 117, 108, 116, 105, 112, 108, 101, 32, 97, 99, 116, 105, 118, 101, 32, 112, 97, 114, 116, 105, 116, 105, 111, 110, 115, 46, 13, 10, 102, 139, 68, 8, 102, 3, 70, 28, 102, 137, 68, 8, 232, 48, 255, 114, 39, 102, 129, 62, 0, 124, 88, 70, 83, 66, 117, 9, 102, 131, 192, 4, 232, 28, 255, 114, 19, 129, 62, 254, 125, 85, 170, 15, 133, 242, 254, 188, 250, 123, 90, 95, 7, 250, 255, 228, 232, 30, 0, 79, 112, 101, 114, 97, 116, 105, 110, 103, 32, 115, 121, 115, 116, 101, 109, 32, 108, 111, 97, 100, 32, 101, 114, 114, 111, 114, 46, 13, 10, 94, 172, 180, 14, 138, 62, 98, 4, 179, 7, 205, 16, 60, 10, 117, 241, 205, 24, 244, 235, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 235, 105, 120, 0, 0, 128, 0, 33, 2, 131, 8, 184, 99, 0, 8, 0, 0, 0, 96, 9, 0, 0, 8, 185, 99, 142, 15, 255, 255, 0, 104, 9, 0, 0, 152, 54, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 170]",
  "Checked components": [
    { "/boot/vmlinuz-lts": "bb46623bfd7b54110c367169736d771ecc159aa3df5f485e6adae24db3f5687fd8219365015b109386f051c710cb1c4b0d8655bbbe841acbc74e79d87a7cce5d" },
    { "/etc/passwd": "6f756583b43c71601b15bcf09074fc580848875ed1738166211e4fb5698b656b8fe0fcc4174e2bc13906acff3a5900883964c74691c65c3f7c5d5c48d3b116d8" },
    { "/etc/hosts": "9538b233ea28fa911603d01b2405f22b2fccda49ccbdf92176c860e5831e62a0cd19f4594ec8c1551de3b85d06d802eb8361cdd244e456ae0038e0bf02e7d175" },
    { "/etc/resolv.conf": "863322b5f877b4f3a5ac7bc94ca12efb2c31265ee4cf33a9c1e3620e8103095381273d7c1a3fbd8b03818b93e92b91e6794c6b1dfffcbe2e35d6b2c6d979ab72" },
    { "firmware": "0c4244d8add8c51106f68563cd8dca8ade46b0a0c118de5b361b99b2ea0e64ba6076dc02ffa97eb6e8d6455b03410b969767bf560587a16575e07fa01efcc822" },
    { "/etc/profile": "ab85c7a9865ed2cb292dad3c2a5ea127010c4d5231f5bc9c62b0819b2346a0c9ffd4ebb21d41cb07e2ff21f28b750c7e99c1ac8510e716f7708a48658f7b933d" },
    { "/etc/fstab": "ec7e1c54da6fe8fb6143c08b0bf62f749448bf3642a2b26dc946db6f4f80ca2c902b3719992226c029388a75459e811c22a87910e036a5e147d061993749071d" }
  ],
  "BLAKE2B-512 Alpine LTS Linux System Attestation": "f5b473605034cb399a8976df581f59003e27ce2015f482daf9c19c7de6a6da649c9ac5e5858d19ccdf5795921c7ebbf30fec4059a9c1259d597fb807f8d61889"
}

```
_Note that attesting the MBR typically requires superuser access. Attestations can be done without checking the MBR with 'attest' instead of 'attest_mbr'._

If a checked file is not present, the 'attest' and 'attest_mbr' functions will have no output. For MacOS the MBR is checked from `/dev/disk0`, while on linux it is checked from `/dev/sda`.
If `/dev/sda` is not found for Alpine Linux, we also look for `/dev/vda`.
If the system doesn't use the target disk names (some don't), then the MBR can't be attested with this 'attest_mbr' function and will need to be checked using another technique.

The hash of the MBR is not printed, but the actual byte array of the first sector is, and the final BLAKE2B-512 includes that data in the hash along with all the other component hashes as input. 
The final BLAKE2B-512 will change if any of the components change (including the MBR if using 'attest_mbr'). While this attestation is not comprehensive, it is useful baseline data,
and can be helpful when doing tasks like confirming maintenance done for the kernel, or doing forensic comparisons of hosts.

The firmware is read recursively from the `/lib/firmware` and `/usr/lib/firmware` locations on linux, and from `/usr/standalone/firmware` and `/System/Library/CoreServices/Firmware Updates` on MacOS. OpenBSD will read firmware from `/etc/firmware`.
_Note that MacOS has some firmware that is protected and cannot be read, so we aren't able to reach all of the firmware on MacOS._

We can compare our attestion or hash JSON reports with 'diff' and 'diff_no_color' functions. Even though this documentation doesn't show it, the 'diff' output highlights the changed bytes on each line:

```
giant-spellbook diff report1.json report2.json
<   "Report start time": "2025-09-21 18:05:17.044768254 UTC",
>   "Report start time": "2025-09-21 18:05:25.879434241 UTC",
<     { "/tmp/date.out": "6b222ca629210426abe31e30ec116658d0ba157da788a564955518c68f99de24" },
>     { "/tmp/date.out": "42c649822f8bc3d7b4c1d00e5333ebe3078a01a231c46651dc7a1226ab74da50" },
<     { "Report end time": "2025-09-21 18:05:17.045187851 UTC" }
>     { "Report end time": "2025-09-21 18:05:25.880034403 UTC" }
```

 We can use the same functions to compare binary files, although the printing may be not as useful. If any output is printed there is a differing line, even if no characters could be printed.

```
giant-spellbook diff /tmp/rng.1 /tmp/rng.2
< ���&̨
> ��bAa
giant-spellbook diff /tmp/sample.1 /tmp/sample.2
<
>
```

_Note: if processing the diff data with a program, use the diff_no_color option instead._


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

Capture detailed TLS information from a website or SSL/TLS endpoint. 

```
giant-spellbook tls_debug https://pq.cloudflareresearch.com:443 /etc/ssl/certs/ca-certificates.crt no_auth
2025-08-29T19:26:04.818Z INFO: Starting TLS handshake run against pq.cloudflareresearch.com:443
2025-08-29T19:26:04.818Z CLIENT: Resolving & connecting to 104.18.31.220:443
2025-08-29T19:26:04.820Z CLIENT: TCP connected
2025-08-29T19:26:04.820Z CLIENT: sent 1476 byte(s) to server ->> hex=16030105bf010005bb03032473165edfa4f229db9fa0312061cb4b84161a6013787a63b1a2caa11447ba31202858058891e557f475e61a29b3c7a94562dbb2d8545e1ee2e4ccfb920cd2cb6b0014130213011303c02cc02bcca9c030c02fcca800ff0100055e000a000a000811ec001d0017001800170000003304ea04e811ec04c0cadaae047556f15931b78b3a84084d770a3256eb1c9735146e151978f6b0e6ccb1deb37157516f87a362989230c0a82f4f571f9d06ccf0b89b94a3389b530ed5380391c98de3a00db1767fc0931a7162b3d243006d95b52f6351a7b2139b629bc9ab44c217a0eba0a8fe55062462736516584e6a575140b32c373b61663178a60ac7caaf04251fbc505015c41e8b744678b1b751608c736156d334777635c1dba216d52b64361406b6118bc8d14cb1c1c76f7420853a614065008f931f62f61b3537751cd9723e562be133bbdaab27e90a7f4369454d3c6b88ea6a88a48c6c279907895ddff6acf395cdb128861d55650d10bcae838eef91afcb316e48b898a29b33d5085056766184bc9293b020287327fa8478c4d447034b5aa4e542ce3a7b4d079af93731496227e4e7066f492568350174f8b4679846190a4751cb7fbda139c12c8b151a0854e208d8764e1893bb7262a2fc5141db9c6c58105e71008def254bb01a5d16d81c722838f1dc2d95884ba3260d80124e7201318ba5255eb734187b68870aa346cc65922c58a73b9db67603cef3aa1687a3f5c4c05467a0b679588e6097fafa0110727b14a1658f9750cbb312d68a54cf906a5ebabd8ce17654150648b041b7a0c8ca4732fef5bff4fc3141328bccb33df01c7556a95464f849b51877f70565e9926088b8be23dc1fd531807b907d94a47a2d7379f4b02cc71541da8b2dfa94ca80130c4f6ab97e26beff7b26f33bbddba57775a0442d1932c0280252b93f48e25b7e7154bfd7be418b584fec18b86ac6e3c4c14013838cc8aa8200cb1e7108ce25c4f74cb731cb9fa640237f492b2bd64c37e7757315c5dcaca16e43734d50c5614ccd5fa32b85c45dccfb11bb53173dc9bbf398157876cb7680312716c7163c05bbdac18a4a73ade63ad157ad6a45b4d4d808e6b97f4dd18558140ba0d86f3c0b04d2746612d324f6f13b8bfa70b9c1c3150a85dd5742d78873807960add37a98f2ab0ae40fa61515203063a1553654cc5831fa3cf842c5e6fcae9b9375ad771b82b4c7c5e7b0c156a9502a989d20be9d6b28e5844a80db2d4b028bf9b69303fb8c55315ca3b98134544e528839e06867e225742f354f195253d09471fdec38c0c2625c568170b903bba2aa22b03971cc3a9f144c268729ccc3870826465824a45ea4711152c57f9100c9e9aca0b4960b580f6c9aac97f62629d5a2e0e98273605c51d74fdbb0b7ba0941bc288dd340b1d3771f0f18574a89311cf6ab68629ecebc8ed8f2752a38137b733925fab2c439cda52b32ecb71efb717e52124339c83749c8169f989898f278fab4aa82fa563d123e2e7064c660317c3a3ed7278cb477919da97f175103f5c526fccaca88f245463339cb33451eaa439044ac037b1ea332af4f846b0431512665529beb145a5b782533213f82a88b668b0ab4bf301684522507ee0c1b7304388eb3200d196effe88820080f4f814769119fd36cc7ff5479e206bf1e072bb73a17dd606c4d5b073574752a46ce04020fc137487178080d757a1d327f5fa08b8dd125177666c7ac51fd201f73911baf98500008858b32690f0262284b30bf42aff21a8c09e0738a1c28595c98b8834b6189abac098296e0d1e5961bdb8488c8e90c80d6d57f82240911ac4d099e0c7ee2614cb1e0889a04c5fec305efbe84f1cf973c828157ae5994765fc4ba6caa31001d0020e2614cb1e0889a04c5fec305efbe84f1cf973c828157ae5994765fc4ba6caa31002b00050403040303002d00020101000b00020100000d0016001405030403060308070806080508040601050104010000001e001c00001970712e636c6f7564666c61726572657365617263682e636f6d0005000501000000000023
2025-08-29T19:26:04.828Z SERVER: read 4096 byte(s) from server <<- hex=16030304ba020004b60303bda68830028774b85ee3c5ff9c6bdc213a6632f2ae3844f43f5cb34cb0a160e3202858058891e557f475e61a29b3c7a94562dbb2d8545e1ee2e4ccfb920cd2cb6b130200046e0033046411ec046083d2039a3b114d3f242b26e3101f28c73409feb6b18e851ad49f349cc760ba99ef7a3fb1094eb4fd25da3e9ef34bff2cf7ab95dce26400ce031057a4b158ac43545532e68348291401a36d34aa48043ed660f173c055b124d968054ae15a9acc0605ed50be1074aa8cce90d6b251c1443cea1c51f722b68fb7bbbf626d07189d3e6659e27d3d326fe2dc4727aad9fbacb884baac062b693f91e45a16345dce6566f2ea3d8425c9f8b0368a3e907da239d57e36cc58c31976f7cc2142083987cdce8d3e5a9f7e4c45327865d9b1b101d00c422669670626a2a4c6766999f5dfb0b8ac1591fcfe02c72d37cc1352db434d63e57e841e6724c62a15bc5b4dd4c073d451b1b43ceb84af387293059b352ee448d87852260ebe1c6a449aa62cc2df855802a5d9e95eda9daa19cf63379004a04e9a8308bde354096b76ea20132496d23d6e5b31e8acfd6b3b704fb24f8c54752dd33501fa04fe447a672bbc51e78f80db41cdb0fb6e3f82482140fd11ac74d9a5f971690fd2bff1bc71e681dd9140b3d0b1ebc19d7f8a415e0e742a558c84eac74da8fdd063652a33b57d732798d37405c2261026508cb4a812fe9f9a85349c0f976012dbd119477d0bdcd796429435a26f4f428b620cfca00d8a092053aed7c5be768459298733dabdf4ec1a1671c99dc810e0c2d2c9dfba743effbf28952ab288e29ff22cc294b648edcfd76056943d7c2adae0a612caf2dfbc9b5f748d95b35fe5bb4da63a80851da216c3ba61af331e933f82211d4366211521ddb6f432c2a4c394f9f566b55a8176268bfd02b9c1c7332b69be7771554baef0e71c78d9e6e0a5d7532b6908dad31944174ed57383cbc1600b2822526e0c9e531595b60e1584fe2cbcbc86f4f66c59bac92e4d5cc75ece6f295d5dba138e2dca1aeed7dd4fb0b9dc4cf3c4d38060bbd0080b9377e5a9eed3e2638478824c81de836e70cfcaf3f209209a55fa8c6d11d78e6d7c70ca2604a122d5453a388967f677f1686f9bdde1c29ac0397a6eda6505c9aba7b6a92ec8cf44a1331fc5a1c71ed03a604e4bb6771c01721bb5dde8c8b8585b7bfcf3f2db6ec526379be5586f090df8104a89f1bc11fc4f115cdf0fa1c92addc900fe3fb602a1e411a991d709fae45d25e9447c26242abdc87fa34c16a19eb1129e69381fbec9cb94fe3be98221c800aa71ef94e68b3e62bbfd5f9cca92b4d3b9e8699ce46168aef20e0c741f5b1c9140434fe9ccc68fd5b582d9444769ceaaf63c921c8e5909b172fde0a2271dde2687470194b1d0ef902cbafd846e7b2ea59c16495febf7a60a7e374feb3f607297d3820aa63dfc3fd774c01b5b06f7d6bf23ecd2110e232394afbbac941e881b427e6a1c8b4274a97a368d8415764008447d5d4f758be9f43f17c2f4656454c881eda55b944e53b4ffe24be0771c43d9d99427e2a4dd09a82c3732793e30350d578588534f8c90542eccdccd513675c81bab39fa9e790901e18695a217cf06003080fa34da4df742e6254ba7c7c5c55410c400ea83fd492695309d8430f728c3159331e265f3f088b73137d1ed472961643e75002b000203041403030001011703030bca7cdda3c79b5b4ab21c7cd655f1957702cff2fd267f988822a803a3fa9c16b368cc71003018cc3053dfc4b8d0d9e3a27d52fc867456ef7fe13abff3539745a70b08a01e42720793bbfe00ef5347948a5172c0e76e1fd3da5fd16ea3171b8acf622b1184bb04bff095a4425543d95f4f77f4b4fee3ea8a8875322e9510853fc6eeef70199ea90c766c738bbbaa08e5cf2672240cd5bd1e56aec1475ca34632a01ff9efc94b4c1ad8cdb7c4ae66cd9e9101061ba84d4cd6502509a10319894a55cb7d73a5ac8858cb1aca98ca2018303f6dd1373d668376b710905cc76043c7f275cf6afa83dec85f9cfb17a052dffdb9b23e5e18d69ef7fabb0af22f2d30aa4cc45bb1bd09896d045a14ef4e72329a47e3ad3d239ee8115a24b2941fc5e0313abf10e79934a1fba0188830adb55e9ce6ce90a66a565d2e395b3f90d9f5481cc0ed35598e9bb92acce147c39844bd5b045e5985b1830ab7b60c583064498a627c6436a7749165f5537c6fbbe33f61febb5d5bf1711bc4c54b243354885dba94c0ba9c0a104053e17975b05341c944f32fd53fed16d3b5c4f42e7a1817940b6d297c66f8c56bcd7f48c7e854b940ea4ba85291194fc518e221598752b11163c726ab772c7523a432f248365c1509a71d85e43a3e52047afedd3a4abcbbdb8738ccce8246fe95facd1bec713626eb317c76f9b4f4afbde0e65857992dbac072c03d79de977125fc9eb0e5d5a13929d4ed11b294657a43e99a76d1c200ef1e6277d082047d65c59ff54a96558d248ad6e1c534d787f46fee10d4818385cd62f7d06220b57de4c1590a509bca5f0781afb65357fba27ab1eb8c74ceb4df08c24f39b01e7256733b895bff4dae61c141057cf424b197228067b4df149bf56a3987e5ea8355e2b85961bfa79192ae19146effbd4ad589feca3ca89b8bb91d7bddc1f845d59c9376ddef4e66c33ed06322b16559c63db4fc874002949709db23967c84b3a702e80fe65256cb66a766913a604e34409a4532d6eb9b34bdf707d5a2d9d221bd0ee0291a3a5a97dfb30a8d1479782c6a0edb6f04b2ffa5513378ef8def4eb52ac9d9231ed37cb3e9041921a3bd4531991dc69bf4be6c0833849522dc5d845e5fd810381c53c9f131848851387144663c31a9c2c2e3e11ef915ffddffc98fbaa950ccc4ef10074d15fac13b7e41727abf7ac9a9232366ec1daf31f01dc92d70a136074fd288d4f4f460fe297fe76f37fb5e34c8942d8219a5c128da6415ee310e233e3599ce0dcf7c9d16d2bb761fafe941aa056d603d23b1262220ef52dbe82af607afe40a68161fdcde51451a4afc44a194453c8eaeccd9c4816fb1eef5094b1f10e7b108c09825e87c0fa9d9026793cf93fa67e882f5f5fd8771d3c574ce976d7c356e232b85771dc74a3b49293be17f2a9a28df6e894b56417ccd8ae01a70639f6cdd9dc6b071ef55363f0b59f1eebe001836c25b9a56870a9eed0a0dafa1f99f545f95cb441c01148b92aa0e8ec41a63dd264a7bf01a37566ca665e1170b1bb677e9b5ed416f5153d2fcb64faf95c19feaee95e3f54a3a5f9209c1697ef99578b3e3b6f6ad572c036cfd15dd2d9c6af77014b0c8a730e1d396652af7fe9658ecca2e24221dbae3c9052998fd6b002d846dda1a69bd4463cf3663f20ec00e03a5edf10f871686731097357208d1f7d9552ce90addf8a4d9436e244f094394070ddbdc598d4221d023ef5515c3442b91cbf4dc6dc52fc6d8201a6452d061e27c8e299aea01458f4814eddc5903e5cb500f2395377c53d70efbccfbe60ae7852d2fa64aa034c7b386ee7542754ee269f6df5f4631619323c2d586b23d3374e353bb2f99c03d4e8bcff724b49e1ea5256c65775c081ee5097219012c9e63ecd69d5c67f55a2723dff1e63f0fb8ad4924cb287af4a27f56c52ce00067677733d90bf8d79d29168fe968f269eeffe27abb75b4fff5a225927ca1671e7cacdc3a1ac7fb1ae0b3b5d20875776a83d04004f1e08e899f71e286786b99a1b427123790e82825514ae4883c667fef4716c13bb9b62faa5bc2c56d55d0e7d9b1cf4eb680d951f083feec99d520aaa724162133a35825c8015fd61adad499030bb912dc00e26f0f4f56a00b11a1bd6a01624724c8969aed3042dc29f62e4c78b20e9cd461ccf9a9301921e2de92128fecbb49ca0f748bfbf6fe32757ced093007d054b3e3cc5224cac6585abc56de5c1dc3f49f2329bc342a41d13302ee8ea196709a7ff99715e403d55c265d5f9f70a6551de57bdc004f3d798346a75dd7c078c8ecdf2235bf947058d596de62cb3a3ad972bc3f57566a195003e997411eca2e65e94e93e0bc9be5843678e9d24096f5fc467c606f7ca34319c998c38d8b609ddebefd9dcd25bac9e8f27d52580674b7ae2726402af58b3260d63c8a11835c86a12908070d16a9884aa96556f11eaa7c39db603a9d879bb608ce9ac269edbffab4239836e0345928afd31ceea501a23c9da06adf49ed1a523ed8dfe4b074b686a8cf7627e6549700b96485ab91689d6281db96cfb37478be0b7d0409a09344b46bed5ca9ffca3cf7b53a2c2e0ce33a3ab218b4880942873fa2d64364d6a0b04112a254846458004d306a694fba5583ca3bc222f679fa384baa6123e6c48b3091882310110d39ddf3afebf1472a2259d10e853ec973a0e08c47434e03db2de0bd18e47c9fac196318a8077caf5ec6557726c9cb3589588fe2f61a997709230e028e4a43997eec778d6bbda4beb25028c8b3ee9a80fd825c144c773e51c4ee603c1305c2e32d25790c92532870d82ea72691142ba97b0c0941704c141ad4cdb76fee0e858b65d4addd2c9ecf05518cd5e37b628d7e2cb21afc6448b0f7ef66cc73264fd2705d07612c20c057a93f2454f502effeda952edb684edb77fada2fabc0aa0de1a91cee453a1f2be50d6667f760ca26afd5d9526abce1c5f3bf4af0c9f786a169da47db0e55ba068c5f9ef7dd4c62e9c84cd99506dc54ed682c7e0a3d6169fe2b2f7bfc8223b7c2d67aeabcbf6119766c1c8baf956ff5ca07b6b006239ef00eef3ad8f86edfaeb03336f74a8a47a12f73e8e35bf0c79843968ead60d63c3eda9a2b0b527ebac33ba01aba49d342914f9f1e1a6bc168d1d41163512e98c4220d07316c9c8e642e5c03f32b044c671d6ab55714344808218da937ba520bad55644739b7770611fa61c18ae923a7b629effeb8c0175ea3d38b072167fa3c0c0e245a19c6c5dae122b1b328c377475914961cb06a767b58b154eb7e49c624828641368c1599b5d85dbf407a15dac38b6e0156c57d1696dd7e5973b80c84774c8eff241ff4176b78a7817f69a5ab6558df3aea6eed7c052c7edf7898d43dbba544bf361061b1d970f2cad1de34784eb5b44a620d43e95d7d78101bc67e4f994159550b2c8c365583054bdde7dc699103197766a230baa6f296b3f93da0820e3f6054b71e3e7cbcabe7f68075e2c13a8a635522d2c0a37a08b8bade1a766956e2455298bca2aae55e0ec704d58f15f34dcf7d0ce2186f9e4ae337c20daca8dd19de14a9ee6da165e7c8540cc813295ea55c2ad2f56e94a6a8d4a06a862144048849a37924d04dd88debb8db3635b8c309b1c8528dd6b923dd162d951090046e22df84b780803268160521577ee90add3377d0d2da11f06c31e36542f1281ed24c174b8668f2dc865d6c66313b36e7b5249223be18c81783790adfd44be0af29e8718e3cdefbf6fdde180c93da79f2a7491de3375c6d91b38b6e63e3954e7650993e729d6426373bcb62847798da331267964a3c565f1c832064d9bc1c5b0061bf70489eae3ac7f34bc1cd48a5ff97a73f98ab0da3ae605cd90e166df53841377449fb0568d33d384c29d63769982a44dcb6fd7437d9a89641c063914ce40134e4c6665c5990efccc6ed0283da99f95fa12998dbed2a51fdb7e653788a66f281fd529fa94465b3865563c24a4d5f6e36383d03281f4cc4612d4f877b037dc4bbd9fe1f8915f4651066b59fb38de1436ea20f6a7ce29f9fd5601dd4
2025-08-29T19:26:04.829Z CLIENT: sent 6 byte(s) to server ->> hex=140303000101
2025-08-29T19:26:04.829Z SERVER: read 148 byte(s) from server <<- hex=0a4398d7258be00be6cf3b3144314247f2f4c80526fee5a609575c23a5002b83b8359df6551a44ce024120580b10cc2da4b88b332bb01726ad1516f8db74a73a32b89c47f809b4077cd674952f273db59a4ece62805ac2d70b558125a318df21baab8371741b231900c74c38fd16464e61b51ec06a524ef3034a8e69bc526b6bbd875e8a6d592d9b847bf3b0f68dfaa5681487456485ab91689d6281db96cfb37478be0b7d0409a09344b46bed5ca9ffca3cf7b53a2c2e0ce33a3ab218b4880942873fa2d64364d6a0b04112a254846458004d306a694fba5583ca3bc222f679fa384baa6123e6c48b3091882310110d39ddf3afebf1472a2259d10e853ec973a0e08c47434e03db2de0bd18e47c9fac196318a8077caf5ec6557726c9cb3589588fe2f61a997709230e028e4a43997eec778d6bbda4beb25028c8b3ee9a80fd825c144c773e51c4ee603c1305c2e32d25790c92532870d82ea72691142ba97b0c0941704c141ad4cdb76fee0e858b65d4addd2c9ecf05518cd5e37b628d7e2cb21afc6448b0f7ef66cc73264fd2705d07612c20c057a93f2454f502effeda952edb684edb77fada2fabc0aa0de1a91cee453a1f2be50d6667f760ca26afd5d9526abce1c5f3bf4af0c9f786a169da47db0e55ba068c5f9ef7dd4c62e9c84cd99506dc54ed682c7e0a3d6169fe2b2f7bfc8223b7c2d67aeabcbf6119766c1c8baf956ff5ca07b6b006239ef00eef3ad8f86edfaeb03336f74a8a47a12f73e8e35bf0c79843968ead60d63c3eda9a2b0b527ebac33ba01aba49d342914f9f1e1a6bc168d1d41163512e98c4220d07316c9c8e642e5c03f32b044c671d6ab55714344808218da937ba520bad55644739b7770611fa61c18ae923a7b629effeb8c0175ea3d38b072167fa3c0c0e245a19c6c5dae122b1b328c377475914961cb06a767b58b154eb7e49c624828641368c1599b5d85dbf407a15dac38b6e0156c57d1696dd7e5973b80c84774c8eff241ff4176b78a7817f69a5ab6558df3aea6eed7c052c7edf7898d43dbba544bf361061b1d970f2cad1de34784eb5b44a620d43e95d7d78101bc67e4f994159550b2c8c365583054bdde7dc699103197766a230baa6f296b3f93da0820e3f6054b71e3e7cbcabe7f68075e2c13a8a635522d2c0a37a08b8bade1a766956e2455298bca2aae55e0ec704d58f15f34dcf7d0ce2186f9e4ae337c20daca8dd19de14a9ee6da165e7c8540cc813295ea55c2ad2f56e94a6a8d4a06a862144048849a37924d04dd88debb8db3635b8c309b1c8528dd6b923dd162d951090046e22df84b780803268160521577ee90add3377d0d2da11f06c31e36542f1281ed24c174b8668f2dc865d6c66313b36e7b5249223be18c81783790adfd44be0af29e8718e3cdefbf6fdde180c93da79f2a7491de3375c6d91b38b6e63e3954e7650993e729d6426373bcb62847798da331267964a3c565f1c832064d9bc1c5b0061bf70489eae3ac7f34bc1cd48a5ff97a73f98ab0da3ae605cd90e166df53841377449fb0568d33d384c29d63769982a44dcb6fd7437d9a89641c063914ce40134e4c6665c5990efccc6ed0283da99f95fa12998dbed2a51fdb7e653788a66f281fd529fa94465b3865563c24a4d5f6e36383d03281f4cc4612d4f877b037dc4bbd9fe1f8915f4651066b59fb38de1436ea20f6a7ce29f9fd5601dd4
2025-08-29T19:26:04.830Z CLIENT: sent 74 byte(s) to server ->> hex=17030300451b61b5b932e9d1dbe4e20d71c4f74fa55109c36864e2d682fc8db9286630a515c5b3791eb8448040cd15d7266fb07b8ea46e1d419068b663a5403e53db18640e95b66f3f3e
2025-08-29T19:26:04.830Z CLIENT: Handshake flight #1 (TLS wrote 1556 byte(s))
2025-08-29T19:26:04.830Z SERVER: Received 4244 byte(s) during handshake
2025-08-29T19:26:04.830Z INFO: Key agreement group: X25519MLKEM768 (IANA 0x11ec)
2025-08-29T19:26:04.830Z INFO: TLS handshake completed
2025-08-29T19:26:04.830Z INFO: Negotiated TLS version: TLSv1_3
2025-08-29T19:26:04.830Z INFO: Cipher suite: TLS13_AES_256_GCM_SHA384
2025-08-29T19:26:04.830Z INFO: ALPN protocol: (none)
2025-08-29T19:26:04.830Z INFO: Server sent 3 certificate(s)
2025-08-29T19:26:04.830Z INFO: Saved server cert chain bundle: ./server-certs_pq.cloudflareresearch.com_2025-08-29T19-26-04.830Z.pem
2025-08-29T19:26:04.830Z INFO: cert[0]: Subject CN="pq.cloudflareresearch.com"; SANs=[DNS:pq.cloudflareresearch.com, DNS:*.pq.cloudflareresearch.com]; notBefore=2025-08-07T08:08:37Z, notAfter=2025-11-05T09:08:34Z
2025-08-29T19:26:04.830Z INFO: cert[1]: Subject CN="WE1"; SANs=[(none)]; notBefore=2023-12-13T09:00:00Z, notAfter=2029-02-20T14:00:00Z
2025-08-29T19:26:04.830Z INFO: cert[2]: Subject CN="GTS Root R4"; SANs=[(none)]; notBefore=2023-11-15T03:43:21Z, notAfter=2028-01-28T00:00:42Z
2025-08-29T19:26:04.831Z INFO: Run complete. Artifacts saved: log: ./tls-handshake_pq.cloudflareresearch.com_2025-08-29T19-26-04.830Z.log, server certs: ./server-certs_pq.cloudflareresearch.com_2025-08-29T19-26-04.830Z.pem
```
_Note that the hex payloads have trailing 0s trimmed from the end. If you have invalid hex, you probably had a zero trimmed off the end. If the server sent only null bytes for some crazy reason, then they would all get trimmed in the log._

The log and server certificates are saved to files with each run.

The timeout for read and write for the 'tls_debug' is set to 20 seconds. The client is RusTLS, and so old and weak protocols are not supported in the 'tls_debug' client.

RusTLS is very correct, but that also makes it less useful for further probing of misconfigured or legacy endpoints. Another function and library is likely to get added to expand debugging.

If the last argument to 'tls_debug' is 'no_auth' regular TLS will be used. If that argument is 'auth', then an additional argument of a path to a PEM bundle for client auth and mTLS is used. The mTLS with RusTLS is perhaps overly picky, again, so there will likely be another function and library added to expand mTLS testing as well.

There is also 'extract_no_auth' and 'extract_auth' for 'tls_debug', which prints the TLS secrets from the debug session (currently secret keys and IVs) and expose them in the log.


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

eBPF disassembly is supported via 'ebpf' subcommand to 'disassemble'.

Hunt for IoCs and potentially interesting bytes within a file:

```
giant-spellbook hunter /usr/local/bin/kubectl
{
  "File": "/usr/local/bin/kubectl",
  "Report time": "2025-09-08 20:14:18.194438574 UTC",
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
    },
    {
      "Pattern name": "ssh_dir_access",
      "Byte offset": [29854439, 29855118, 29976548, 29977236, 30105622, 30106316, 30236938, 30237598, 30376619, 30377279]
    },
    {
      "Pattern name": "kube_dir_access",
      "Byte offset": [28988841, 29182720, 29310379, 29310670, 29323045, 29323143, 29661987, 29662104, 29798246, 29798348, 29799159, 29799261, 29915972, 29916074, 29916935, 29917037, 30044446, 30044548, 30045380, 30045482, 30178273, 30178375, 30179145, 30179243, 30316341, 30316443, 30317236, 30317338, 30423797, 30423895, 30496897, 30496995, 30576821, 30576919, 30649921, 30650019, 30747199, 30747316, 30748674, 30748791, 30944991, 30945108, 30946466, 30946583]
    },
    {
      "Pattern name": "windows_kube_dir_access",
      "Byte offset": [29324031, 29324086, 29663105, 29663169]
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

To review a byte position and only output the hex:

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

If we have a file that needs to be decoded but does have newlines, returns, spaces, or tabs, we can use the 'flatten' option to remove all whitespace from the file, overwriting the file.

```
giant-spellbook flatten ./sample_raw.txt
```

Then we can use the 'decode' mode on it:

```
giant-spellbook decode base32_z ./sample_raw.txt
{ "Result": "Z-base32 data decoded and written to file: ./sample_raw.txt" }
```

The 'encode' functions do not add any whitespace, so 'flatten' isn't required if we made the file with giant-spellbook 'encode'.

Generating a random file of a given length:

```
giant-spellbook generate rng 4096 ./random4096_$(date +%Y%m%d%H%M%S).bin
```

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


## Bitflipping, slicing, shifting, XORing

There are two features for bitflipping in giant-spellbook. The first one bitflips the whole file and the second one flips a specific bit at a position.

"bitflip" option flips all bits in the given file, overwriting the file

"single_bitflip" flips the bit at the given position in a file, overwriting the file

"split_file" splits the file into two files at the given position, creating new files with __first and __second extensions

"reverse_bytes" reverses all of the bytes of the file, overwriting the file

"shift" moves the position of the bytes to the left or the right - moving to the right means bytes from the end to go the start, and moving to the left means bytes from the start go to the end

"xor_these" takes two files of the same length and performs a bitwise XOR of them, output to a new file `xor.out`


## Encoding and decoding

The tool can encode and decode files in place. Hex, base64, base32, and base58 encoding options are available.

If the decode has no output and left a `.tmp` file in pwd, then the decoding failed.

If decoding is successful, JSON will be printed. If decoding fails, check the file for invalid data and try again or use another approach.

There is also URL encoding and decoding that does not operate on files, but a supplied string as a command line argument. The output for URL encoding and decoding is only the result, not JSON.

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

The 'researcher' option is an interactive hexdump with x86_64 (intel), ARM64, or eBPF disassembly. The hexdump has color highlighting to mark ELF, PE, and Mach-O magic, ASCII control characters, and more.

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
giant-spellbook commander "giant-spellbook seek /usr/local/bin/kubectl >> kubectl_segment_$(date +%Y%m%d%H%M%S)_$RANDOM.json" ./find_segments.bin.in

```

The strings don't have to be binary, and neither does the file. Plain text strings and plain text files work as well.

With 'seek', any pattern that is longer than 4096 bytes will be truncated to 4096 bytes when searching for it in the file.

Use caution with sending binary inputs via 'commander' as the `results.log` will become binary as the STDIN that was piped is logged to the file..

If the STDOUT or STDERR of with 'commander' "command" have binary, then an error message will be logged to the `results.log` as it uses lossy UTF-8 parsing for STDOUT and STDERR and will log the line number and a stream error about invalid UTF-8 if that occurs. Redirecting the output of the command to another file or log can be helpful if the output of the command might be binary, as to avoid the stream errors.

## Project promises

This project will never use AI-slop. All code is reviewed, tested, implemented by a human that is academically trained in cryptography and information security. This repository and the crates.io repository is carefully managed and protected.

This project will never break backwards compatibility in releases regarding the signature validation or decryption.

This project will be maintained as best as is reasonable.

## Version use

The `0.1.X` versions are not recommended but if only core functionality is desired, `0.1.9+` can be used. The `0.1.X` versions _do not_ get feature updates.

The `0.2.X` versions _do not_ include network debugging features and do compile on OpenBSD. The `0.2.X` versions _do not_ get _network_ feature updates, but do get other feature updates.

The `0.3.X` versions include network debugging features and _do not_ compile on OpenBSD. The CI build targets for `0.3.X` are Linux (x86_64 musl) and MacOS (x86_64). The `0.3.X` versions get _all feature updates_, and live in the main branch.
