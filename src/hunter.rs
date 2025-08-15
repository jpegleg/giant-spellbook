use std::error::Error;
use std::fs;
use chrono::Utc;
use std::fmt::Write as _;

const SEVENZ_MAGIC: &[u8] = b"7z\xBC\xAF\x27\x1C";
const RAR_MAGIC_V4: &[u8] = b"Rar!\x1A\x07\x00";
const RAR_MAGIC_V5: &[u8] = b"Rar!\x1A\x07\x01\x00";
const ZIP_MAGIC_LOCAL: &[u8] = &[0x50, 0x4B, 0x03, 0x04];
const ZIP_MAGIC_CENTRAL: &[u8] = &[0x50, 0x4B, 0x01, 0x02];
const ZIP_MAGIC_END: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
const UPX_MAGIC: &[u8] = b"UPX!";
const UPX0: &[u8] = b"UPX0";
const UPX1: &[u8] = b"UPX1";
const ASPACK: &[u8] = b"ASPack";
const MPRESS: &[u8] = b".MPRESS";
const THEMIDA: &[u8] = b"Themida";
const VMPROTECT: &[u8] = b"VMProtect";
const PETITE: &[u8] = b".petite";
const ENIGMA: &[u8] = b".enigma";
const KKRUNCHY: &[u8] = b"kkrunchy";
const BIN_SH: &[u8] = b"/bin/sh";
const BIN_BASH: &[u8] = b"/bin/bash";
const BIN_KSH: &[u8] = b"/bin/ksh";
const BIN_CSH: &[u8] = b"/bin/csh";
const BIN_ZSH: &[u8] = b"/bin/zsh";
const BIN_DASH: &[u8] = b"/bin/dash";
const BIN_ASH: &[u8] = b"/bin/ash";
const BIN_FISH: &[u8] = b"/bin/fish";
const BASE64_PE_PREFIX: &str = "TVqQAA";
const W_POWERSHELL_EXE: &[u8] = &[
    b'p',0,b'o',0,b'w',0,b'e',0,b'r',0,b's',0,b'h',0,b'e',0,b'l',0,b'l',0,b'.',0,b'e',0,b'x',0,b'e',0
];
const W_IEX: &[u8] = &[b'I',0,b'E',0,b'X',0,b'(',0];
const W_FROMBASE64: &[u8] = &[
    b'F',0,b'r',0,b'o',0,b'm',0,b'B',0,b'a',0,b's',0,b'e',0,b'6',0,b'4',0,b'S',0,b't',0,b'r',0,b'i',0,b'n',0,b'g',0,b'(',0
];
const W_CMD_EXE: &[u8] = &[b'c',0,b'm',0,b'd',0,b'.',0,b'e',0,b'x',0,b'e',0];
const W_RUNDLL32: &[u8] = &[
    b'r',0,b'u',0,b'n',0,b'd',0,b'l',0,b'l',0,b'3',0,b'2',0,b'.',0,b'e',0,b'x',0,b'e',0
];
const W_MSHTA: &[u8] = &[b'm',0,b's',0,b'h',0,b't',0,b'a',0,b'.',0,b'e',0,b'x',0,b'e',0];
const W_REGSVR32: &[u8] = &[
    b'r',0,b'e',0,b'g',0,b's',0,b'v',0,b'r',0,b'3',0,b'2',0,b'.',0,b'e',0,b'x',0,b'e',0
];
const W_WSCRIPT_SHELL: &[u8] = &[
    b'W',0,b'S',0,b'c',0,b'r',0,b'i',0,b'p',0,b't',0,b'.',0,b'S',0,b'h',0,b'e',0,b'l',0,b'l',0
];
const W_SCHTASKS: &[u8] = &[
    b's',0,b'c',0,b'h',0,b't',0,b'a',0,b's',0,b'k',0,b's',0,b'.',0,b'e',0,b'x',0,b'e',0
];
const W_VSSADMIN_DELETE: &[u8] = &[
    b'v',0,b's',0,b's',0,b'a',0,b'd',0,b'm',0,b'i',0,b'n',0,b' ',0,
    b'd',0,b'e',0,b'l',0,b'e',0,b't',0,b'e',0,b' ',0,
    b's',0,b'h',0,b'a',0,b'd',0,b'o',0,b'w',0,b's',0
];
const W_WEVTUTIL_CL: &[u8] = &[
    b'w',0,b'e',0,b'v',0,b't',0,b'u',0,b't',0,b'i',0,b'l',0,b' ',0,b'c',0,b'l',0
];
const W_BCDEDIT: &[u8] = &[b'b',0,b'c',0,b'd',0,b'e',0,b'd',0,b'i',0,b't',0];
const W_WBADMIN_DEL_CAT: &[u8] = &[
    b'w',0,b'b',0,b'a',0,b'd',0,b'm',0,b'i',0,b'n',0,b' ',0,
    b'd',0,b'e',0,b'l',0,b'e',0,b't',0,b'e',0,b' ',0,
    b'c',0,b'a',0,b't',0,b'a',0,b'l',0,b'o',0,b'g',0
];
const W_RUN_HKCU: &[u8] = &[
    b'H',0,b'K',0,b'C',0,b'U',0,b'\\',0,
    b'S',0,b'o',0,b'f',0,b't',0,b'w',0,b'a',0,b'r',0,b'e',0,b'\\',0,
    b'M',0,b'i',0,b'c',0,b'r',0,b'o',0,b's',0,b'o',0,b'f',0,b't',0,b'\\',0,
    b'W',0,b'i',0,b'n',0,b'd',0,b'o',0,b'w',0,b's',0,b'\\',0,
    b'C',0,b'u',0,b'r',0,b'r',0,b'e',0,b'n',0,b't',0,b'V',0,b'e',0,b'r',0,b's',0,b'i',0,b'o',0,b'n',0,b'\\',0,
    b'R',0,b'u',0,b'n',0
];
const W_RUN_HKLM: &[u8] = &[
    b'H',0,b'K',0,b'L',0,b'M',0,b'\\',0,
    b'S',0,b'O',0,b'F',0,b'T',0,b'W',0,b'A',0,b'R',0,b'E',0,b'\\',0,
    b'M',0,b'i',0,b'c',0,b'r',0,b'o',0,b's',0,b'o',0,b'f',0,b't',0,b'\\',0,
    b'W',0,b'i',0,b'n',0,b'd',0,b'o',0,b'w',0,b's',0,b'\\',0,
    b'C',0,b'u',0,b'r',0,b'r',0,b'e',0,b'n',0,b't',0,b'V',0,b'e',0,b'r',0,b's',0,b'i',0,b'o',0,b'n',0,b'\\',0,
    b'R',0,b'u',0,b'n',0
];

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Pattern {
    Bytes(&'static [u8]),
    Str(&'static str),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Malicious {
    // --- Reverse shells / remote exec ---
    BashReverse,
    PythonReverse,
    PHPReverse,
    PerlReverse,
    NcReverse,
    NcUse,
    SocatReverse,
    PowershellIEX,
    PowershellEncoded,
    CertutilDownload,
    BitsadminDownload,
    CurlHttp,
    WgetHttp,
    CurlHttps,
    WgetHttps,
    InvokeWebRequest,
    MshtaExec,
    Rundll32Js,
    WmicExec,
    PsexecSvc,
    Smbexec,
    // --- Privilege / policy tamper ---
    SudoersNoPasswd,
    ShadowAccess,
    PasswdAccess,
    SeDebugPrivilege,
    // --- Windows shadow copy & recovery destruction (ransomware TTPs) ---
    VssadminDeleteShadows,
    WmicShadowcopyDelete,
    BcdeditIgnoreAllFailures,
    BcdeditRecoveryDisabled,
    CipherWipe,
    // --- Service/process killing typical before encryption ---
    NetStopSql,
    NetStopVeeam,
    NetStopBackupExec,
    ScStopVss,
    TaskkillBackup,
    // --- Discovery & lateral movement helpers ---
    NltestDomain,
    NetView,
    NetUse,
    AtOrSchtasksExec,
    // --- Persistence (Windows) ---
    SchtasksCreate,
    RunKeyHKCU,
    RunKeyHKLM,
    StartupFolder,
    WMIEventConsumer,
    // --- Persistence (macOS/Linux) ---
    CronReboot,
    SystemdService,
    LaunchAgents,
    RcLocal,
    // --- Stealth / anti-forensics ---
    HistoryClear,
    LogWipeVarLog,
    ChattrImmutable,
    // --- Ransomware ransom-note filename patterns (common) ---
    RansomNoteReadme,
    RansomNoteHowToDecrypt,
    RansomNoteDecryptInstructions,
    RansomNoteRyuk,
    RansomNoteLockBit,
    RansomNoteBlackCat,
    RansomNoteClop,
    RansomNoteConti,
    RansomNoteSodinokibi,
    // --- Ransomware extension/name markers (generic/family hints) ---
    ExtWcry,
    ExtRyuk,
    ExtLockBit,
    ExtBlackCat,
    ExtClop,
    ExtConti,
    ExtSodinokibi,
    // --- Exfil/comms tools often bundled ---
    TorExe,
    RcloneConfig,
    MegaCli,
    // --- Suspicious crypto demands (generic) ---
    MoneroMention,
    BitcoinMention,
    // --- Binary / wide-string markers & packers ---
    SevenZMagic,
    RarMagic,
    ZipMagic,
    UpxMagic,
    UpxSection0,
    UpxSection1,
    AspackMarker,
    MpressMarker,
    ThemidaMarker,
    VmprotectMarker,
    PetiteMarker,
    EnigmaMarker,
    KkrunchyMarker,
    // --- Embedded shell / stager hints (binary) ---
    BinShUse,
    BinBashUse,
    BinKshUse,
    BinCshUse,
    BinZshUse,
    BinFishUse,
    BinDashUse,
    BinAshUse,
    MzBase64Prefix,
    // --- Suspicious Windows strings in UTF-16LE (wide) ---
    WidePowershellExe,
    WideIEXCall,
    WideFromBase64String,
    WideCmdExe,
    WideRundll32,
    WideMshta,
    WideRegsvr32,
    WideWscriptShell,
    WideSchtasks,
    WideVssadminDelete,
    WideWevtutilClear,
    WideBcdedit,
    WideWbadminDeleteCatalog,
    // --- Windows registry run keys (wide) ---
    WideRunKeyHKCU,
    WideRunKeyHKLM,
}

impl Malicious {
    pub fn all() -> Vec<(&'static str, Pattern)> {
        let mut v: Vec<(&'static str, Pattern)> = Vec::new();

        // --- Binary: file format / packers (often used to pack malware) ---
        v.extend([
            ("7z_magic", Pattern::Bytes(SEVENZ_MAGIC)),
            ("rar_magic_v4", Pattern::Bytes(RAR_MAGIC_V4)),
            ("rar_magic_v5", Pattern::Bytes(RAR_MAGIC_V5)),
            ("zip_magic_local", Pattern::Bytes(ZIP_MAGIC_LOCAL)),
            ("zip_magic_central", Pattern::Bytes(ZIP_MAGIC_CENTRAL)),
            ("zip_magic_end", Pattern::Bytes(ZIP_MAGIC_END)),
            ("upx_magic", Pattern::Bytes(UPX_MAGIC)),
            ("upx_section0", Pattern::Bytes(UPX0)),
            ("upx_section1", Pattern::Bytes(UPX1)),
            ("aspack_marker", Pattern::Bytes(ASPACK)),
            ("mpress_marker", Pattern::Bytes(MPRESS)),
            ("themida_marker", Pattern::Bytes(THEMIDA)),
            ("vmprotect_marker", Pattern::Bytes(VMPROTECT)),
            ("petite_marker", Pattern::Bytes(PETITE)),
            ("enigma_marker", Pattern::Bytes(ENIGMA)),
            ("kkrunchy_marker", Pattern::Bytes(KKRUNCHY)),
        ]);
      
        // --- Binary: embedded shell/stager hints ---
        v.extend([
            ("bin_sh_use", Pattern::Bytes(BIN_SH)),
            ("bin_bash_use", Pattern::Bytes(BIN_BASH)),
            ("bin_ksh_use", Pattern::Bytes(BIN_KSH)),
            ("bin_csh_use", Pattern::Bytes(BIN_CSH)),
            ("bin_zsh_use", Pattern::Bytes(BIN_ZSH)),
            ("bin_dash_use", Pattern::Bytes(BIN_DASH)),
            ("bin_ash_use", Pattern::Bytes(BIN_ASH)),
            ("bin_fish_use", Pattern::Bytes(BIN_FISH)),
            ("base64_pe_prefix", Pattern::Str(BASE64_PE_PREFIX)), // ASCII search
        ]);
      
        // --- UTF-16LE (wide) suspicious command markers ---
        v.extend([
            ("wide_powershell_exe", Pattern::Bytes(W_POWERSHELL_EXE)),
            ("wide_IEX_call", Pattern::Bytes(W_IEX)),
            ("wide_from_base64_string", Pattern::Bytes(W_FROMBASE64)),
            ("wide_cmd_exe", Pattern::Bytes(W_CMD_EXE)),
            ("wide_rundll32_exe", Pattern::Bytes(W_RUNDLL32)),
            ("wide_mshta_exe", Pattern::Bytes(W_MSHTA)),
            ("wide_regsvr32_exe", Pattern::Bytes(W_REGSVR32)),
            ("wide_wscript_shell", Pattern::Bytes(W_WSCRIPT_SHELL)),
            ("wide_schtasks_exe", Pattern::Bytes(W_SCHTASKS)),
            ("wide_vssadmin_delete", Pattern::Bytes(W_VSSADMIN_DELETE)),
            ("wide_wevtutil_cl", Pattern::Bytes(W_WEVTUTIL_CL)),
            ("wide_bcdedit", Pattern::Bytes(W_BCDEDIT)),
            ("wide_wbadmin_delete_catalog", Pattern::Bytes(W_WBADMIN_DEL_CAT)),
            ("wide_run_key_hkcu", Pattern::Bytes(W_RUN_HKCU)),
            ("wide_run_key_hklm", Pattern::Bytes(W_RUN_HKLM)),
          
            // ---- Reverse shells / remote exec ----
            ("bash_reverse", Pattern::Str("bash -i >& /dev/tcp/")),
            ("python_reverse", Pattern::Str("import socket,subprocess,os;")),
            ("php_reverse", Pattern::Str("php -r '$sock=fsockopen(")),
            ("perl_reverse", Pattern::Str("perl -e 'use Socket;")),
            ("nc_reverse", Pattern::Str("nc -e /bin/sh")),
            ("nc_use", Pattern::Str(" nc -")),
            ("socat_reverse", Pattern::Str("socat ")),
            ("pwsh_IEX", Pattern::Str("powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command IEX")),
            ("pwsh_encoded", Pattern::Str("powershell -enc ")),
            ("certutil_download", Pattern::Str("certutil -urlcache -split -f")),
            ("bitsadmin_download", Pattern::Str("bitsadmin /transfer")),
            ("curl_http", Pattern::Str("curl http://")),
            ("wget_http", Pattern::Str("wget http://")),
            ("curl_https", Pattern::Str("curl http://")),
            ("wget_https", Pattern::Str("wget http://")),
            ("invoke_web_request", Pattern::Str("Invoke-WebRequest")),
            ("mshta_exec", Pattern::Str("mshta ")),
            ("rundll32_js", Pattern::Str("rundll32.exe javascript:")),
            ("wmic_exec", Pattern::Str("wmic process call create")),
            ("psexec_svc", Pattern::Str("PSEXESVC")),
            ("smbexec", Pattern::Str("smbexec.py")),

            // ---- Privilege / policy tamper ----
            ("sudoers_nopasswd", Pattern::Str("NOPASSWD:ALL")),
            ("shadow_access", Pattern::Str("/etc/shadow")),
            ("passwd_access", Pattern::Str("/etc/passwd")),
            ("se_debug_priv", Pattern::Str("SeDebugPrivilege")),

            // ---- Shadow copy & recovery destruction ----
            ("vssadmin_delete_shadows", Pattern::Str("vssadmin delete shadows /all /quiet")),
            ("wmic_shadowcopy_delete", Pattern::Str("wmic shadowcopy delete")),
            ("bcdedit_ignore_all_failures", Pattern::Str("bcdedit /set {default} bootstatuspolicy ignoreallfailures")),
            ("bcdedit_recovery_disabled", Pattern::Str("bcdedit /set {default} recoveryenabled No")),
            ("cipher_wipe", Pattern::Str("cipher /w:")),

            // ---- Service/process killing typical before encryption ----
            ("net_stop_sql", Pattern::Str("net stop MSSQL")),
            ("net_stop_veeam", Pattern::Str("net stop Veeam")),
            ("net_stop_backup_exec", Pattern::Str("net stop \"Backup Exec\"")),
            ("sc_stop_vss", Pattern::Str("sc stop VSS")),
            ("taskkill_backup", Pattern::Str("taskkill /F /IM backup*")),

            // ---- Discovery & lateral movement ----
            ("nltest_domain", Pattern::Str("nltest /dclist:")),
            ("net_view", Pattern::Str("net view /domain")),
            ("net_use", Pattern::Str("net use \\\\")),
            ("at_or_schtasks_exec", Pattern::Str("schtasks /run /tn")),

            // ---- Persistence (Windows) ----
            ("schtasks_create", Pattern::Str("schtasks /create")),
            ("run_key_hkcu", Pattern::Str("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")),
            ("run_key_hklm", Pattern::Str("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")),
            ("startup_folder", Pattern::Str("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
            ("wmi_event_consumer", Pattern::Str("CommandLineEventConsumer")),

            // ---- Persistence (macOS/Linux) ----
            ("cron_reboot", Pattern::Str("@reboot")),
            ("systemd_service", Pattern::Str("[Unit]\nDescription=")),
            ("launch_agents", Pattern::Str("/Library/LaunchAgents")),
            ("rc_local", Pattern::Str("/etc/rc.local")),

            // ---- Stealth / anti-forensics ----
            ("history_clear", Pattern::Str("history -c")),
            ("log_wipe_var_log", Pattern::Str("> /var/log/")),
            ("chattr_immutable", Pattern::Str("chattr +i")),

            // ---- Ransom notes (filenames / markers seen across families) ----
            ("ransom_readme", Pattern::Str("README.txt")),
            ("ransom_how_to_decrypt", Pattern::Str("HOW_TO_DECRYPT.txt")),
            ("ransom_decrypt_instructions", Pattern::Str("DECRYPT_INSTRUCTIONS.txt")),
            ("ransom_ryuk_note", Pattern::Str("RyukReadMe.txt")),
            ("ransom_lockbit_note", Pattern::Str("Restore-My-Files.txt")),
            ("ransom_blackcat_note", Pattern::Str("RECOVER-")), // often "RECOVER-<id>-FILES.txt"
            ("ransom_clop_note", Pattern::Str("ClopReadMe.txt")),
            ("ransom_conti_note", Pattern::Str("CONTI_README.txt")),
            ("ransom_sodinokibi_note", Pattern::Str("Sodinokibi.com")),

            // ---- Ransomware extension/name hints (generic) ----
            ("ext_wcry", Pattern::Str(".wnry")),
            ("ext_ryuk", Pattern::Str(".ryk")),
            ("ext_lockbit", Pattern::Str(".lockbit")),
            ("ext_blackcat", Pattern::Str(".alphv")),
            ("ext_clop", Pattern::Str(".clop")),
            ("ext_conti", Pattern::Str(".conti ")),
            ("ext_sodinokibi", Pattern::Str(".revil")),

            // ---- Exfil/comms tooling often bundled ----
            ("tor_exe", Pattern::Str("tor.exe")),
            ("rclone_conf", Pattern::Str("rclone.conf")),
            ("mega_cli", Pattern::Str("MEGAcmd")),

            // ---- Crypto demand language (generic) ----
            ("monero_mention", Pattern::Str("monero")),
            ("bitcoin_mention", Pattern::Str("bitcoin")),
        ]);
      v
    }
}

fn find_all_positions(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let n = needle.len();
    if n == 0 || n > haystack.len() {
        return Vec::new();
    }
    let mut positions = Vec::new();
    let limit = haystack.len() - n;
    let first = needle[0];
    let tail = &needle[1..];

    let mut i = 0;
    while i <= limit {
        if haystack[i] == first && (&haystack[i + 1..i + n] == tail) {
            positions.push(i);
        }
        i += 1;
    }
    positions
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1F}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn search_patterns(
    file_path: &str,
    patterns: &[(&'static str, Pattern)],
) -> Result<String, Box<dyn Error>> {
    let data = fs::read(file_path)?;
    let mut matches: Vec<(&'static str, Vec<usize>)> = Vec::new();

    for (name, pat) in patterns {
        let offsets = match *pat {
            Pattern::Bytes(bytes) => find_all_positions(&data, bytes),
            Pattern::Str(s) => find_all_positions(&data, s.as_bytes()),
        };
        if !offsets.is_empty() {
            matches.push((*name, offsets));
        }
    }

    let chronox: String = Utc::now().to_string();
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"File\": \"");
    json.push_str(&escape_json(file_path));
    json.push_str("\",\n");
    json.push_str("  \"Report time\": \"");
    json.push_str(&escape_json(&chronox));
    json.push_str("\",\n");
    json.push_str("  \"Potentially malicious patterns\": ");
    if matches.is_empty() {
        json.push_str("[]\n");
        json.push('}');
        return Ok(json);
    }

    json.push_str("[\n");
    for (i, (name, offsets)) in matches.iter().enumerate() {
        json.push_str("    {\n");
        json.push_str("      \"Pattern name\": \"");
        json.push_str(&escape_json(name));
        json.push_str("\",\n");
        json.push_str("      \"Byte offset\": [");

        for (j, off) in offsets.iter().enumerate() {
            let _ = write!(json, "{}", off);
            if j + 1 != offsets.len() {
                json.push_str(", ");
            }
        }
        json.push_str("]\n");
        json.push_str("    }");
        if i + 1 != matches.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ]\n");
    json.push('}');

    Ok(json)
}
