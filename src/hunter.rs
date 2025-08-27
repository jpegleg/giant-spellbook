use std::error::Error;
use std::fs;
use chrono::Utc;
use std::fmt::Write as _;

mod cve;
mod misc;
use cve::*;
use misc::*;

#[derive(Debug, Clone, Copy)]
pub enum Pattern {
    Bytes(&'static [u8]),
    Str(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub enum Interesting {}

impl Interesting {
    pub fn all() -> Vec<(&'static str, Pattern)> {
        let mut v: Vec<(&'static str, Pattern)> = Vec::new();
        // --- Exploit patterns ---
        v.extend([
            // log4shell exploit patterns
            ("exploiting_CVEs_log4shell_jndi_use", Pattern::Bytes(cve_bytes::CVE_2021_44228_JNDI_PREFIX)),
            ("exploiting_CVEs_log4shell_jndi_ldap", Pattern::Bytes(cve_bytes::CVE_2021_44228_JNDI_LDAP)),
            ("exploiting_CVEs_log4shell_jndi_ldaps", Pattern::Bytes(cve_bytes::CVE_2021_44228_JNDI_LDAPS)),
            ("exploiting_CVEs_log4shell_jndi_rmi", Pattern::Bytes(cve_bytes::CVE_2021_44228_JNDI_RMI)),
            ("exploiting_CVEs_log4shell_jndi_dns", Pattern::Bytes(cve_bytes::CVE_2021_44228_JNDI_DNS)),
            ("exploiting_CVEs_log4shell_jndi_obfuscation_lower", Pattern::Bytes(cve_bytes::CVE_2021_44228_OBF_LOWER)),
            ("exploiting_CVEs_log4shell_jndi_obfuscation_colon", Pattern::Bytes(cve_bytes::CVE_2021_44228_OBF_COLON)),
            ("exploiting_CVEs_log4shell_java_lookup", Pattern::Bytes(cve_bytes::CVE_2021_44228_JAVA_LOOKUP)),
            ("exploiting_CVEs_log4shell_ctx_server", Pattern::Bytes(cve_bytes::CVE_2021_44228_CTX_SERVER)),

            // spring4shell exploit patterns
            ("exploiting_CVEs_spring4shell_class_module", Pattern::Bytes(cve_bytes::CVE_2022_22965_CLASS_MODULE)),
            ("exploiting_CVEs_spring4shell_class_protection_domain", Pattern::Bytes(cve_bytes::CVE_2022_22965_CLASS_PROTDOMAIN)),
            ("exploiting_CVEs_spring4shell_class_pipeline", Pattern::Bytes(cve_bytes::CVE_2022_22965_PIPELINE)),
            ("exploiting_CVEs_spring4shell_tomcat_logs", Pattern::Bytes(cve_bytes::CVE_2022_22965_TOMCAT_LOGS)),
            ("exploiting_CVEs_spring4shell_routing_header", Pattern::Bytes(cve_bytes::CVE_2022_22965_ROUTING_HEADER)),

            // MSDT RCE
            ("exploiting_CVEs_msdt_rce_ms_msdt_scheme_use", Pattern::Bytes(cve_bytes::CVE_2022_30190_MS_MSDT_SCHEME)),
            ("exploiting_CVEs_msdt_rce_ms_msdt_id", Pattern::Bytes(cve_bytes::CVE_2022_30190_MS_MSDT_ID)),
            ("exploiting_CVEs_msdt_rce_pcwdiagnostic", Pattern::Bytes(cve_bytes::CVE_2022_30190_PCWDIAG)),
            ("exploiting_CVEs_msdt_rce_sdiagnhost_exe", Pattern::Bytes(cve_bytes::CVE_2022_30190_SDIAGNHOST)),
            ("exploiting_CVEs_msdt_rce_hcp_scheme", Pattern::Bytes(cve_bytes::CVE_2022_30190_HCP_SCHEME)),

            // Outlook reminder UNC leak
            ("exploiting_CVEs_outlook_pid_rem_file_param", Pattern::Bytes(cve_bytes::CVE_2023_23397_PID_REM_FILE_PARAM)),
            ("exploiting_CVEs_outlook_pid_rem_override", Pattern::Bytes(cve_bytes::CVE_2023_23397_PID_REM_OVERRIDE)),
            ("exploiting_CVEs_outlook_web_dav_unc", Pattern::Bytes(cve_bytes::CVE_2023_23397_WEB_DAV)),

            // Equation Editor MS Office memory corruption
            ("exploiting_CVEs_ms_office_mem_eqnedt_exe", Pattern::Bytes(cve_bytes::CVE_2017_11882_EQNEDT_EXE)),
            ("exploiting_CVEs_ms_office_mem_equation_3", Pattern::Bytes(cve_bytes::CVE_2017_11882_EQUATION_3)),
            ("exploiting_CVEs_ms_office_mem_eqnedt_clsid", Pattern::Bytes(cve_bytes::CVE_2017_11882_EQNEDT_CLSID)),

            // Pulse Secure arbitrary file read
            ("exploiting_CVEs_pulse_secure_dana_na", Pattern::Bytes(cve_bytes::CVE_2019_11510_DANA_NA)),
            ("exploiting_CVEs_pulse_secure_viewcert", Pattern::Bytes(cve_bytes::CVE_2019_11510_VIEWCERT)),
            ("exploiting_CVEs_pulse_secure_portal_welcome", Pattern::Bytes(cve_bytes::CVE_2019_11510_PORTAL_WELCOME)),
            ("exploiting_CVEs_pulse_secure_mention", Pattern::Bytes(cve_bytes::CVE_2019_11510_SSL_VPN)),

            // Citrix ADC/Gateway path traversal
            ("exploiting_CVEs_citrix_vpns_newbm", Pattern::Bytes(cve_bytes::CVE_2019_19781_VPNS_NEWBM)),
            ("exploiting_CVEs_citrix_traversal", Pattern::Bytes(cve_bytes::CVE_2019_19781_TRAVERSAL)),
            ("exploiting_CVEs_citrix_netscaler", Pattern::Bytes(cve_bytes::CVE_2019_19781_NETSCALER)),

            // F5 BIG-IP iControl REST auth bypass RCE
            ("exploiting_CVEs_f5_icontrol_bash", Pattern::Bytes(cve_bytes::CVE_2022_1388_ICONTROL_BASH)),
            ("exploiting_CVEs_f5_x_f5_token", Pattern::Bytes(cve_bytes::CVE_2022_1388_X_F5_TOKEN)),
            ("exploiting_CVEs_f5_x_conn_xf5", Pattern::Bytes(cve_bytes::CVE_2022_1388_CONN_XF5)),
            ("exploiting_CVEs_f5_util_cmdargs", Pattern::Bytes(cve_bytes::CVE_2022_1388_UTIL_CMDARGS)),

            // F5 TMUI directory traversal
            ("exploiting_CVEs_f5_tmui_login", Pattern::Bytes(cve_bytes::CVE_2020_5902_TMUI_LOGIN)),
            ("exploiting_CVEs_f5_tmui_file_read", Pattern::Bytes(cve_bytes::CVE_2020_5902_FILE_READ)),
            ("exploiting_CVEs_dot_dot_semicolon_path", Pattern::Bytes(cve_bytes::CVE_2020_5902_DOT_DOT_SC)),

            // WebLogic console traversal
            ("exploiting_CVEs_weblogic_console", Pattern::Bytes(cve_bytes::CVE_2020_14882_CONSOLE)),

            // Exchange ProxyLogon
            ("exploiting_CVEs_exchange_proxy_x_beresource", Pattern::Bytes(cve_bytes::CVE_2021_26855_X_BERESOURCE)),
            ("exploiting_CVEs_exchange_proxy_x_anon_backend", Pattern::Bytes(cve_bytes::CVE_2021_26855_X_ANON_BACKEND)),
            ("exploiting_CVEs_exchange_proxy_ecp", Pattern::Bytes(cve_bytes::CVE_2021_26855_ECP)),

            // Exchange ProxyShell
            ("exploiting_CVEs_exchange_autodiscover", Pattern::Bytes(cve_bytes::CVE_2021_34473_AUTODISCOVER)),
            ("exploiting_CVEs_exchange_x_anon", Pattern::Bytes(cve_bytes::CVE_2021_34473_X_ANON)),

            // Apache Struts RCE
            ("exploiting_CVEs_apache_struts_ognl_ct", Pattern::Bytes(cve_bytes::CVE_2017_5638_OGNL_CT)),

            // Shellshock
            ("exploiting_CVEs_shellshock", Pattern::Bytes(cve_bytes::CVE_2014_6271_SHELLSHOCK)),

            // xz/libzma backdoor
            ("exploiting_CVEs_xz_backdoor", Pattern::Bytes(cve_bytes::CVE_2024_3094_LZMA_SO_56)),

            // Fortinet FortiOS path traversal
            ("exploiting_CVEs_fortinet_traversal_fgt_lang", Pattern::Bytes(cve_bytes::CVE_2018_13379_FGT_LANG)),
        ]);

        // --- Binary: file format / packers (often used to pack malware) ---
        v.extend([
            ("pe_magic", Pattern::Bytes(misc_bytes::PE_MAGIC)),
            ("elf_magic", Pattern::Bytes(misc_bytes::ELF_MAGIC)),
            ("macho_magic_32", Pattern::Bytes(misc_bytes::MACHO_MAGIC_32)),
            ("macho_magic_64", Pattern::Bytes(misc_bytes::MACHO_MAGIC_64)),
            ("macho_cigam_32", Pattern::Bytes(misc_bytes::MACHO_CIGAM_32)),
            ("macho_cigam_64", Pattern::Bytes(misc_bytes::MACHO_CIGAM_64)),
            ("ole_cfb_magic", Pattern::Bytes(misc_bytes::OLE_CFB)),
            ("gzip_magic", Pattern::Bytes(misc_bytes::GZIP_MAGIC)),
            ("7z_magic", Pattern::Bytes(misc_bytes::SEVENZ_MAGIC)),
            ("rar_magic_v4", Pattern::Bytes(misc_bytes::RAR_MAGIC_V4)),
            ("rar_magic_v5", Pattern::Bytes(misc_bytes::RAR_MAGIC_V5)),
            ("zip_magic_local", Pattern::Bytes(misc_bytes::ZIP_MAGIC_LOCAL)),
            ("zip_magic_central", Pattern::Bytes(misc_bytes::ZIP_MAGIC_CENTRAL)),
            ("zip_magic_end", Pattern::Bytes(misc_bytes::ZIP_MAGIC_END)),
            ("upx_magic", Pattern::Bytes(misc_bytes::UPX_MAGIC)),
            ("upx_section0", Pattern::Bytes(misc_bytes::UPX0)),
            ("upx_section1", Pattern::Bytes(misc_bytes::UPX1)),
            ("aspack_marker", Pattern::Bytes(misc_bytes::ASPACK)),
            ("mpress_marker", Pattern::Bytes(misc_bytes::MPRESS)),
            ("themida_marker", Pattern::Bytes(misc_bytes::THEMIDA)),
            ("vmprotect_marker", Pattern::Bytes(misc_bytes::VMPROTECT)),
            ("petite_marker", Pattern::Bytes(misc_bytes::PETITE)),
            ("enigma_marker", Pattern::Bytes(misc_bytes::ENIGMA)),
            ("kkrunchy_marker", Pattern::Bytes(misc_bytes::KKRUNCHY)),
        ]);

        // --- Binary: embedded shell/stager hints ---
        v.extend([
            ("python_use", Pattern::Bytes(misc_bytes::PYTHON)),
            ("perl_use", Pattern::Bytes(misc_bytes::PERL)),
            ("python3_use", Pattern::Bytes(misc_bytes::PYTHON3)),
            ("powershell_use", Pattern::Bytes(misc_bytes::POWERSHELL)),
            ("powershell_use_(wide)", Pattern::Bytes(misc_bytes::POWERSHELL2)),
            ("cmd_use", Pattern::Bytes(misc_bytes::CMD)),
            ("bash_use", Pattern::Bytes(misc_bytes::BASH)),
            ("sh_use", Pattern::Bytes(misc_bytes::SH)),
            ("bin_sh_use", Pattern::Bytes(misc_bytes::BIN_SH)),
            ("bin_bash_use", Pattern::Bytes(misc_bytes::BIN_BASH)),
            ("bin_ksh_use", Pattern::Bytes(misc_bytes::BIN_KSH)),
            ("bin_csh_use", Pattern::Bytes(misc_bytes::BIN_CSH)),
            ("bin_zsh_use", Pattern::Bytes(misc_bytes::BIN_ZSH)),
            ("bin_dash_use", Pattern::Bytes(misc_bytes::BIN_DASH)),
            ("bin_ash_use", Pattern::Bytes(misc_bytes::BIN_ASH)),
            ("bin_fish_use", Pattern::Bytes(misc_bytes::BIN_FISH)),
            ("base64_pe_prefix", Pattern::Str(misc_bytes::BASE64_PE_PREFIX)),
        ]);

        // --- UTF-16LE (wide) suspicious command markers ---
        v.extend([
            ("wide_powershell_exe", Pattern::Bytes(misc_bytes::W_POWERSHELL_EXE)),
            ("wide_IEX_call", Pattern::Bytes(misc_bytes::W_IEX)),
            ("wide_from_base64_string", Pattern::Bytes(misc_bytes::W_FROMBASE64)),
            ("wide_cmd_exe", Pattern::Bytes(misc_bytes::W_CMD_EXE)),
            ("wide_rundll32_exe", Pattern::Bytes(misc_bytes::W_RUNDLL32)),
            ("wide_mshta_exe", Pattern::Bytes(misc_bytes::W_MSHTA)),
            ("wide_regsvr32_exe", Pattern::Bytes(misc_bytes::W_REGSVR32)),
            ("wide_wscript_shell", Pattern::Bytes(misc_bytes::W_WSCRIPT_SHELL)),
            ("wide_schtasks_exe", Pattern::Bytes(misc_bytes::W_SCHTASKS)),
            ("wide_vssadmin_delete", Pattern::Bytes(misc_bytes::W_VSSADMIN_DELETE)),
            ("wide_wevtutil_cl", Pattern::Bytes(misc_bytes::W_WEVTUTIL_CL)),
            ("wide_bcdedit", Pattern::Bytes(misc_bytes::W_BCDEDIT)),
            ("wide_wbadmin_delete_catalog", Pattern::Bytes(misc_bytes::W_WBADMIN_DEL_CAT)),
            ("wide_run_key_hkcu", Pattern::Bytes(misc_bytes::W_RUN_HKCU)),
            ("wide_run_key_hklm", Pattern::Bytes(misc_bytes::W_RUN_HKLM)),

            // ---- Reverse shells / remote exec ----
            ("bash_reverse_1", Pattern::Str("bash -i >& /dev/tcp/")),
            ("bash_reverse_2", Pattern::Str("bash -l > /dev/tcp")),
            ("bash_reverse_3", Pattern::Str("bash -l >/dev/tcp")),
            ("python_reverse", Pattern::Str("import socket,subprocess,os;")),
            ("php_reverse", Pattern::Str("php -r '$sock=fsockopen(")),
            ("perl_reverse", Pattern::Str("perl -e 'use Socket;")),
            ("nc_reverse", Pattern::Str("nc -e /bin/")),
            ("nc_use", Pattern::Str(" nc -")),
            ("socat_use", Pattern::Str("socat ")),
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
            ("README.txt_reference", Pattern::Str("README.txt")),
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
    json.push_str("  \"Matched patterns\": ");
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
