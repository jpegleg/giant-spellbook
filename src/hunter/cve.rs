#[allow(dead_code)]
pub mod cve_bytes {
    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2021-44228 (Log4Shell / Log4j JNDI)
    // Sources indicate reliable anchors include raw `${jndi:` and common URI schemes.
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2021_44228_JNDI_PREFIX: &[u8] = b"${jndi:";
    pub const CVE_2021_44228_JNDI_LDAP:   &[u8] = b"jndi:ldap";
    pub const CVE_2021_44228_JNDI_LDAPS:  &[u8] = b"jndi:ldaps";
    pub const CVE_2021_44228_JNDI_RMI:    &[u8] = b"jndi:rmi";
    pub const CVE_2021_44228_JNDI_DNS:    &[u8] = b"jndi:dns";
    // Common obfuscation anchors seen in community rules/pocs:
    pub const CVE_2021_44228_OBF_LOWER:   &[u8] = b"${${lower:j}${lower:n}${lower:d}${lower:i}:";
    pub const CVE_2021_44228_OBF_COLON:   &[u8] = b"${::-j}${::-n}${::-d}${::-i}:";
    pub const CVE_2021_44228_JAVA_LOOKUP: &[u8] = b"${java:version}";
    pub const CVE_2021_44228_CTX_SERVER:  &[u8] = b"${ctx:server}";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2022-22965 (Spring4Shell)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2022_22965_CLASS_MODULE:     &[u8] = b"class.module.classLoader";
    pub const CVE_2022_22965_CLASS_PROTDOMAIN: &[u8] = b"class.protectionDomain";
    pub const CVE_2022_22965_PIPELINE:         &[u8] = b"org.apache.catalina.core.StandardContext";
    pub const CVE_2022_22965_TOMCAT_LOGS:      &[u8] = b"tomcat.util.buf.StringCache.byte[]";
    pub const CVE_2022_22965_ROUTING_HEADER:   &[u8] = b"spring.cloud.function.routing-expression";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2022-30190 (Follina / MSDT)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2022_30190_MS_MSDT_SCHEME: &[u8] = b"ms-msdt:";
    pub const CVE_2022_30190_MS_MSDT_ID:     &[u8] = b"ms-msdt:?id=";
    pub const CVE_2022_30190_PCWDIAG:        &[u8] = b"PCWDiagnostic";
    pub const CVE_2022_30190_SDIAGNHOST:     &[u8] = b"sdiagnhost.exe";
    pub const CVE_2022_30190_HCP_SCHEME:     &[u8] = b"hcp://";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2023-23397 (Outlook reminder UNC leak)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2023_23397_PID_REM_FILE_PARAM: &[u8] = b"PidLidReminderFileParameter";
    pub const CVE_2023_23397_PID_REM_OVERRIDE:   &[u8] = b"PidLidReminderOverride";
    pub const CVE_2023_23397_WEB_DAV:            &[u8] = b"\\\\?\\UNC\\";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2017-11882 (Equation Editor / EQNEDT32)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2017_11882_EQNEDT_EXE:  &[u8] = b"EQNEDT32.EXE";
    pub const CVE_2017_11882_EQUATION_3:  &[u8] = b"Equation.3";
    // OLE CLSID commonly tied to Equation Editor objects:
    pub const CVE_2017_11882_EQNEDT_CLSID: &[u8] = b"0002CE02-0000-0000-C000-000000000046";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2019-11510 (Pulse Secure arbitrary file read)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2019_11510_DANA_NA:     &[u8] = b"/dana-na/";
    pub const CVE_2019_11510_VIEWCERT:    &[u8] = b"/dana-cached/hc/hostchecker.dll";
    pub const CVE_2019_11510_PORTAL_WELCOME: &[u8] = b"/dana-na/auth/url_default/welcome.cgi";
    pub const CVE_2019_11510_SSL_VPN:     &[u8] = b"Pulse Secure";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2019-19781 (Citrix ADC/Gateway path traversal)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2019_19781_VPNS_NEWBM:  &[u8] = b"/vpns/portal/scripts/newbm.pl";
    pub const CVE_2019_19781_TRAVERSAL:   &[u8] = b"/vpn/../vpns/";
    pub const CVE_2019_19781_NETSCALER:   &[u8] = b"NSC_USER";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2022-1388 (F5 BIG-IP iControl REST auth bypass → RCE)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2022_1388_ICONTROL_BASH:   &[u8] = b"/mgmt/tm/util/bash";
    pub const CVE_2022_1388_X_F5_TOKEN:      &[u8] = b"X-F5-Auth-Token";
    pub const CVE_2022_1388_CONN_XF5:        &[u8] = b"Connection: X-F5-Auth-Token";
    pub const CVE_2022_1388_UTIL_CMDARGS:    &[u8] = b"\"utilCmdArgs\"";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2020-5902 (F5 TMUI directory traversal → fileRead.jsp)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2020_5902_TMUI_LOGIN:   &[u8] = b"/tmui/login.jsp";
    pub const CVE_2020_5902_FILE_READ:    &[u8] = b"/tmui/locallb/workspace/fileRead.jsp";
    pub const CVE_2020_5902_DOT_DOT_SC:   &[u8] = b"/..;/";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2020-14882 (Oracle WebLogic console traversal)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2020_14882_CONSOLE:     &[u8] = b"/console/css/%252e%252e%252fconsole.portal";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2021-26855 (Exchange ProxyLogon)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2021_26855_X_BERESOURCE:      &[u8] = b"X-BEResource";
    pub const CVE_2021_26855_X_ANON_BACKEND:    &[u8] = b"X-AnonResource-Backend";
    pub const CVE_2021_26855_ECP:               &[u8] = b"/ecp/";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2021-34473 (Exchange ProxyShell – common HTTP anchors)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2021_34473_AUTODISCOVER: &[u8] = b"/autodiscover/autodiscover.json";
    pub const CVE_2021_34473_X_ANON:       &[u8] = b"X-AnonResource";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2014-6271 (Shellshock / Bash env function)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2014_6271_SHELLSHOCK:    &[u8] = b"() { :;};";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2017-5638 (Apache Struts Jakarta Multipart parser RCE)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2017_5638_OGNL_CT:       &[u8] = b"Content-Type: %{(";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2024-3094 (xz/liblzma backdoor)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2024_3094_LZMA_SO_56:    &[u8] = b"liblzma.so.5.6";

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE-2018-13379 (Fortinet FortiOS path traversal)
    // ─────────────────────────────────────────────────────────────────────────────
    pub const CVE_2018_13379_FGT_LANG:     &[u8] = b"/remote/fgt_lang?lang=";

 }
