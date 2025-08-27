#[allow(dead_code)]
pub mod misc_bytes {
    // ─────────────────────────────────────────────────────────────────────────────
    // Magic bytes
    // ─────────────────────────────────────────────────────────────────────────────
    pub const PE_MAGIC: &[u8] = b"PE\0\0";
    pub const ELF_MAGIC: &[u8] = b"\x7FELF";
    pub const MACHO_MAGIC_32: &[u8] = &[0xFE, 0xED, 0xFA, 0xCE];
    pub const MACHO_MAGIC_64: &[u8] = &[0xFE, 0xED, 0xFA, 0xCF];
    pub const MACHO_CIGAM_32: &[u8] = &[0xCE, 0xFA, 0xED, 0xFE];
    pub const MACHO_CIGAM_64: &[u8] = &[0xCF, 0xFA, 0xED, 0xFE];
    pub const OLE_CFB: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    pub const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B, 0x08];
    pub const SEVENZ_MAGIC: &[u8] = b"7z\xBC\xAF\x27\x1C";
    pub const RAR_MAGIC_V4: &[u8] = b"Rar!\x1A\x07\x00";
    pub const RAR_MAGIC_V5: &[u8] = b"Rar!\x1A\x07\x01\x00";
    pub const ZIP_MAGIC_LOCAL: &[u8] = &[0x50, 0x4B, 0x03, 0x04];
    pub const ZIP_MAGIC_CENTRAL: &[u8] = &[0x50, 0x4B, 0x01, 0x02];
    pub const ZIP_MAGIC_END: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
    pub const UPX_MAGIC: &[u8] = b"UPX!";
    pub const BASE64_PE_PREFIX: &str = "TVqQAA";
  
    // ─────────────────────────────────────────────────────────────────────────────
    // Packer artifacts
    // ─────────────────────────────────────────────────────────────────────────────
    pub const UPX0: &[u8] = b"UPX0";
    pub const UPX1: &[u8] = b"UPX1";
    pub const ASPACK: &[u8] = b"ASPack";
    pub const MPRESS: &[u8] = b".MPRESS";
    pub const THEMIDA: &[u8] = b"Themida";
    pub const VMPROTECT: &[u8] = b"VMProtect";
    pub const PETITE: &[u8] = b".petite";
    pub const ENIGMA: &[u8] = b".enigma";
    pub const KKRUNCHY: &[u8] = b"kkrunchy";
  
    // ─────────────────────────────────────────────────────────────────────────────
    // Shells
    // ─────────────────────────────────────────────────────────────────────────────
    pub const BIN_SH: &[u8] = b"/bin/sh";
    pub const POWERSHELL: &[u8] = b"pwsh.exe";
    pub const POWERSHELL2: &[u8] = b"pwsh";
    pub const CMD: &[u8] = b"cmd.exe";
    pub const SH: &[u8] = b"/sh ";
    pub const BASH: &[u8] = b"/bash ";
    pub const PYTHON: &[u8] = b"python ";
    pub const PYTHON3: &[u8] = b"python3";
    pub const PERL: &[u8] = b"/bin/perl ";
    pub const BIN_BASH: &[u8] = b"/bin/bash";
    pub const BIN_KSH: &[u8] = b"/bin/ksh";
    pub const BIN_CSH: &[u8] = b"/bin/csh";
    pub const BIN_ZSH: &[u8] = b"/bin/zsh";
    pub const BIN_DASH: &[u8] = b"/bin/dash";
    pub const BIN_ASH: &[u8] = b"/bin/ash";
    pub const BIN_FISH: &[u8] = b"/bin/fish";
  
    // ─────────────────────────────────────────────────────────────────────────────
    // Windows byte strings (null bytes between each)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const W_POWERSHELL_EXE: &[u8] = &[
      b'p',0,b'o',0,b'w',0,b'e',0,b'r',0,b's',0,b'h',0,b'e',0,b'l',0,b'l',0,b'.',0,b'e',0,b'x',0,b'e',0
    ];
    pub const W_IEX: &[u8] = &[b'I',0,b'E',0,b'X',0,b'(',0];
    pub const W_FROMBASE64: &[u8] = &[
      b'F',0,b'r',0,b'o',0,b'm',0,b'B',0,b'a',0,b's',0,b'e',0,b'6',0,b'4',0,b'S',0,b't',0,b'r',0,b'i',0,b'n',0,b'g',0,b'(',0
    ];
    pub const W_CMD_EXE: &[u8] = &[b'c',0,b'm',0,b'd',0,b'.',0,b'e',0,b'x',0,b'e',0];
    pub const W_RUNDLL32: &[u8] = &[
      b'r',0,b'u',0,b'n',0,b'd',0,b'l',0,b'l',0,b'3',0,b'2',0,b'.',0,b'e',0,b'x',0,b'e',0
    ];
    pub const W_MSHTA: &[u8] = &[b'm',0,b's',0,b'h',0,b't',0,b'a',0,b'.',0,b'e',0,b'x',0,b'e',0];
    pub const W_REGSVR32: &[u8] = &[
      b'r',0,b'e',0,b'g',0,b's',0,b'v',0,b'r',0,b'3',0,b'2',0,b'.',0,b'e',0,b'x',0,b'e',0
    ];
    pub const W_WSCRIPT_SHELL: &[u8] = &[
      b'W',0,b'S',0,b'c',0,b'r',0,b'i',0,b'p',0,b't',0,b'.',0,b'S',0,b'h',0,b'e',0,b'l',0,b'l',0
    ];
    pub const W_SCHTASKS: &[u8] = &[
      b's',0,b'c',0,b'h',0,b't',0,b'a',0,b's',0,b'k',0,b's',0,b'.',0,b'e',0,b'x',0,b'e',0
    ];
    pub const W_VSSADMIN_DELETE: &[u8] = &[
      b'v',0,b's',0,b's',0,b'a',0,b'd',0,b'm',0,b'i',0,b'n',0,b' ',0,
      b'd',0,b'e',0,b'l',0,b'e',0,b't',0,b'e',0,b' ',0,
      b's',0,b'h',0,b'a',0,b'd',0,b'o',0,b'w',0,b's',0
    ];
    pub const W_WEVTUTIL_CL: &[u8] = &[
      b'w',0,b'e',0,b'v',0,b't',0,b'u',0,b't',0,b'i',0,b'l',0,b' ',0,b'c',0,b'l',0
    ];
    pub const W_BCDEDIT: &[u8] = &[b'b',0,b'c',0,b'd',0,b'e',0,b'd',0,b'i',0,b't',0];
    pub const W_WBADMIN_DEL_CAT: &[u8] = &[
      b'w',0,b'b',0,b'a',0,b'd',0,b'm',0,b'i',0,b'n',0,b' ',0,
      b'd',0,b'e',0,b'l',0,b'e',0,b't',0,b'e',0,b' ',0,
      b'c',0,b'a',0,b't',0,b'a',0,b'l',0,b'o',0,b'g',0
    ];
    pub const W_RUN_HKCU: &[u8] = &[
      b'H',0,b'K',0,b'C',0,b'U',0,b'\\',0,
      b'S',0,b'o',0,b'f',0,b't',0,b'w',0,b'a',0,b'r',0,b'e',0,b'\\',0,
      b'M',0,b'i',0,b'c',0,b'r',0,b'o',0,b's',0,b'o',0,b'f',0,b't',0,b'\\',0,
      b'W',0,b'i',0,b'n',0,b'd',0,b'o',0,b'w',0,b's',0,b'\\',0,
      b'C',0,b'u',0,b'r',0,b'r',0,b'e',0,b'n',0,b't',0,b'V',0,b'e',0,b'r',0,b's',0,b'i',0,b'o',0,b'n',0,b'\\',0,
      b'R',0,b'u',0,b'n',0
    ];
    pub const W_RUN_HKLM: &[u8] = &[
      b'H',0,b'K',0,b'L',0,b'M',0,b'\\',0,
      b'S',0,b'O',0,b'F',0,b'T',0,b'W',0,b'A',0,b'R',0,b'E',0,b'\\',0,
      b'M',0,b'i',0,b'c',0,b'r',0,b'o',0,b's',0,b'o',0,b'f',0,b't',0,b'\\',0,
      b'W',0,b'i',0,b'n',0,b'd',0,b'o',0,b'w',0,b's',0,b'\\',0,
      b'C',0,b'u',0,b'r',0,b'r',0,b'e',0,b'n',0,b't',0,b'V',0,b'e',0,b'r',0,b's',0,b'i',0,b'o',0,b'n',0,b'\\',0,
      b'R',0,b'u',0,b'n',0
    ];
}
