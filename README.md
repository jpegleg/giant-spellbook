![cdlogo](https://carefuldata.com/images/cdlogo.png)

# giant-spellbook

This tool is a "multi-tool" of cryptographic operations and binary/file analysis capabilities. It is useful for regular cryptographic operations like hashing files for checksums, encrypting files, creating and verifying Dilithium5-AES signatures. It uses the highest standards for cryptographic operations with the strongest encryption methods, signing, and hashing only.

Giant-spellbook can gather numerous statistics on files and binaries as well as perform low level operations on them such as bitflipping and slicing.

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

| operation  | action/algos                                         |
|------------|------------------------------------------------------| 
| metadata   | multiple various including SHA3 SHAKE256             | 
| bitflip    | bitwise NOT                                          | 
| analyze    | multiple various including XOR and ECB               |
| file_split | NA                                                   |


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

```
giant-spellbook generate y.key y.pub
Enter key password then press enter (will not be displayed):

giant-spellbook sign sample.file sample.sig y.pub y.key
Enter key password then press enter (will not be displayed):

{
"sample.file": {
  "Checksum SHA3 SHAKE256 10": "[94, 85, 171, 118, 174, 29, 88, 78, 109, 75]",
  "Report time": "2025-08-12 00:01:02.290576508 UTC",
  "Number of IO blocks": "8",
  "Block size": "4096",
  "Inode": "5382881",
  "Total as bytes": "5",
  "Total as kilobytes": "0",
  "Total as megabytes": "0",
  "Total as bits": "40",
  "Byte distribution": "0.6",
  "Created timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Modified timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Accessed timestamp (UTC)": "2025-08-11 14:53:46.045206505 UTC",
  "Changed timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Permissions": "100644",
  "Owner": "unseenwork (uid: 1000)",
  "Group": "unseenwork (gid: 1000)",
  "Open": "File is not open by another program. Signing...",
  "Dilithium signature file": "sample.sig",
  "Dilithium signing key": "y.key",
  "Key Inode": "5389736",
  "Key Created timestamp (UTC)": "2025-08-11 00:35:07.912473575 UTC",
  "Key Modified timestamp (UTC)": "2025-08-11 00:35:08.629502399 UTC",
  "Key Accessed timestamp (UTC)": "2025-08-11 00:35:16.050798747 UTC",
  "Key Changed timestamp (UTC)": "2025-08-11 00:35:08.629502399 UTC",
  "Key Permissions": "100600",
  "Key Owner": "webserveradmin (uid: 1000)",
  "Key Group": "webserveradmin (gid: 1000)"
 }
}

giant-spellbook analyze sample.file
{
  "File": "sample.file",
  "Time": "2025-08-12 00:02:16.598143471 UTC",
  "Size": 5,
  "Type": "ASN1_DER_seq_like",
  "ELF": {"is_elf": false, "class": 0, "data_endian": "Unknown", "os_abi": 0, "glibc_versions": []},
  "PE": {"is_pe": false, "machine": null},
  "Printable_ratio": 1.000000,
  "Entropy": 1.370951,
  "Chi_square": 558.200000,
  "Rolling_entropy": {"window": 5, "count": 0, "min": null, "avg": null, "max": null},
  "ECB": [],
  "Periodicity": {"best_lag": 3, "correlation": 0.500000},
  "Repeating_xor_keysizes": [{"keysize": 2, "norm_hamming": 0.500000}],
  "Single_byte_xor_probe": {"best_key": "0x40", "score": 0.000000, "printable": 1.000000}
}

giant-spellbook metadata sample.file
{
"sample.file": {
  "Checksum SHA3 SHAKE256 10": "[94, 85, 171, 118, 174, 29, 88, 78, 109, 75]",
  "Report time": "2025-08-12 00:02:22.893932822 UTC",
  "Number of IO blocks": "8",
  "Block size": "4096",
  "Inode": "5382881",
  "Total as bytes": "5",
  "Total as kilobytes": "0",
  "Total as megabytes": "0",
  "Total as bits": "40",
  "Byte distribution": "0.6",
  "Created timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Modified timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Accessed timestamp (UTC)": "2025-08-11 14:53:46.045206505 UTC",
  "Changed timestamp (UTC)": "2025-08-11 14:53:43.643190041 UTC",
  "Permissions": "100644",
  "Owner": "unseenwork (uid: 1000)",
  "Group": "unseenwork (gid: 1000)",
  "Open": "File is not open by another program."
 }
}

giant-spellbook encrypt aes-gcm sample.file sample.file.e
Enter password:
{"Validation string": "/VK3HxOSte9rpdAm61rSQ7tSkSD9DHIFJP2kpwwgkm3Qj5C83cmijikYEj3ZvQCHYrlciFDGRRMPQ8JNRLCGrQ=="}
```

## Bitflipping and slicing

There are two features for bitflipping in giant-spellbook. The first one bitflips the whole file and the second one flips a specific bit at a position.

"bitflip" option flips all bits in the given file, overwriting the file

"single_bitflip" flips the bit at the given position in a file, overwriting the file

"split_file" splits the file into two files at the given position, creating new files with __first and __second extensions

## Encoding and decoding

The tool can encode and decode files in place. Hex, base64, and base58 encoding options are available.

