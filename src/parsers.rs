use std::path::Path;
use std::fs;
use der_parser::oid::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{
    CRLDistributionPoints, DistributionPointName,
    ExtendedKeyUsage, GeneralName, KeyUsage, ParsedExtension,
};
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

#[path = "./utilities.rs"]
mod utilities;
use utilities::json_escape_type3;

/// Extract all PEM and DER format x509 certificates from an input file.
pub fn describe_certs(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = fs::read(Path::new(path))?;
    let mut certs: Vec<X509Certificate<'_>> = Vec::new();
    let pems: Vec<Pem> = Pem::iter_from_buffer(&data)
        .filter_map(|r| r.ok())
        .filter(|pem| pem.label == "CERTIFICATE")
        .collect();

    if !pems.is_empty() {
        for pem in &pems {
            let (_, cert) = X509Certificate::from_der(&pem.contents)?;
            certs.push(cert);
        }
    } else {
        let (_, cert) = X509Certificate::from_der(&data)?;
        certs.push(cert);
    }

    let mut elems = Vec::new();
    for cert in &certs {
        elems.push(cert_to_json_string(cert, 2));
    }
    Ok(json_array(elems, 0))
}


fn cert_to_json_string(cert: &X509Certificate<'_>, indent: usize) -> String {
    let mut props = Vec::new();
    let n = cert.version().0;

    props.push(prop_num(indent + 2, "version", (n + 1) as i64));
    props.push(prop_str(indent + 2, "serial_hex", &colon_hex(cert.raw_serial())));
    props.push(prop_str(
        indent + 2,
        "signature_algorithm",
        &oid_to_name(cert.signature_algorithm.algorithm.clone()),
    ));
    props.push(prop_str(indent + 2, "issuer", &dn_to_string(cert.issuer())));
    props.push(prop_str(indent + 2, "subject", &dn_to_string(cert.subject())));

    let validity_obj = json_object(
        vec![
            prop_str(
                indent + 4,
                "not_before",
                &asn1time_to_string(cert.validity().not_before),
            ),
            prop_str(
                indent + 4,
                "not_after",
                &asn1time_to_string(cert.validity().not_after),
            ),
        ],
        indent + 2,
    );
    props.push(prop_obj(indent + 2, "validity", &validity_obj));

    let spki = &cert.subject_pki;
    let spki_obj = json_object(
        vec![
            prop_str(
                indent + 4,
                "algorithm",
                &oid_to_name(spki.algorithm.algorithm.clone()),
            ),
            prop_num(
                indent + 4,
                "public_key_bits_approx",
                (spki.subject_public_key.data.len() * 8) as i64,
            ),
        ],
        indent + 2,
    );
    props.push(prop_obj(indent + 2, "spki", &spki_obj));

    let mut ext_props: Vec<String> = Vec::new();
    let mut san_dns: Vec<String> = Vec::new();
    let mut san_ip: Vec<String> = Vec::new();
    let mut san_email: Vec<String> = Vec::new();
    let mut san_uri: Vec<String> = Vec::new();
    let mut key_usage: Vec<String> = Vec::new();
    let mut ext_key_usage: Vec<String> = Vec::new();
    let mut basic_ca: Option<bool> = None;
    let mut basic_pathlen: Option<u32> = None;
    let mut ski: Option<String> = None;
    let mut aki: Option<String> = None;
    let mut crl_dps: Vec<String> = Vec::new();
    let mut aia_entries: Vec<(String, String)> = Vec::new();
    let mut unknowns: Vec<(String, bool)> = Vec::new();

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(d) => san_dns.push(d.to_string()),
                        GeneralName::RFC822Name(m) => san_email.push(m.to_string()),
                        GeneralName::URI(u) => san_uri.push(u.to_string()),
                        GeneralName::IPAddress(ip) => {
                            let ip = ip.as_ref();
                            if ip.len() == 4 {
                                san_ip.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                            } else if ip.len() == 16 {
                                if let Ok(arr) = <[u8; 16]>::try_from(ip) {
                                    use std::net::Ipv6Addr;
                                    san_ip.push(Ipv6Addr::from(arr).to_string());
                                } else {
                                    san_ip.push(format!("0x{}", hex::encode_upper(ip)));
                                }
                            } else {
                                san_ip.push(format!("0x{}", hex::encode_upper(ip)));
                            }
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                key_usage = key_usage_to_vec(ku);
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                ext_key_usage = extkey_usage_to_list(eku);
            }
            ParsedExtension::BasicConstraints(bc) => {
                basic_ca = Some(bc.ca);
                basic_pathlen = bc.path_len_constraint;
            }
            ParsedExtension::SubjectKeyIdentifier(s) => {
                ski = Some(colon_hex(s.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                if let Some(kid) = &a.key_identifier {
                    aki = Some(colon_hex(kid.0));
                }
            }
            ParsedExtension::CRLDistributionPoints(cdp) => {
                crl_dps = render_crldp(cdp);
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for ad in &aia.accessdescs {
                    let method = format!("{}", ad.access_method);
                    let location = match &ad.access_location {
                        GeneralName::URI(u) => u.to_string(),
                        other => format!("{:?}", other),
                    };
                    aia_entries.push((method, location));
                }
            }
            _ => {
                unknowns.push((format!("{}", ext.oid), ext.critical));
            }
        }
    }

    if !(san_dns.is_empty() && san_ip.is_empty() && san_email.is_empty() && san_uri.is_empty()) {
        let mut san_fields = Vec::new();
        if !san_dns.is_empty() {
            san_fields.push(prop_array(indent + 4, "dns", &json_array_strs(&san_dns, indent + 4)));
        }
        if !san_ip.is_empty() {
            san_fields.push(prop_array(indent + 4, "ip", &json_array_strs(&san_ip, indent + 4)));
        }
        if !san_email.is_empty() {
            san_fields.push(prop_array(
                indent + 4,
                "email",
                &json_array_strs(&san_email, indent + 4),
            ));
        }
        if !san_uri.is_empty() {
            san_fields.push(prop_array(
                indent + 4,
                "uri",
                &json_array_strs(&san_uri, indent + 4),
            ));
        }
        let san_obj = json_object(san_fields, indent + 2);
        ext_props.push(prop_obj(indent + 2, "subject_alt_name", &san_obj));
    }

    if !key_usage.is_empty() {
        ext_props.push(prop_array(
            indent + 2,
            "key_usage",
            &json_array_strs(&key_usage, indent + 2),
        ));
    }

    if !ext_key_usage.is_empty() {
        ext_props.push(prop_array(
            indent + 2,
            "extended_key_usage",
            &json_array_strs(&ext_key_usage, indent + 2),
        ));
    }

    if basic_ca.is_some() || basic_pathlen.is_some() {
        let mut bc_fields = Vec::new();
        if let Some(ca) = basic_ca {
            bc_fields.push(prop_bool(indent + 4, "ca", ca));
        }
        if let Some(n) = basic_pathlen {
            bc_fields.push(prop_num(indent + 4, "path_len", n as i64));
        }
        let bc_obj = json_object(bc_fields, indent + 2);
        ext_props.push(prop_obj(indent + 2, "basic_constraints", &bc_obj));
    }

    if let Some(s) = ski {
        ext_props.push(prop_str(indent + 2, "subject_key_identifier", &s));
    }
    if let Some(a) = aki {
        ext_props.push(prop_str(indent + 2, "authority_key_identifier", &a));
    }

    if !crl_dps.is_empty() {
        ext_props.push(prop_array(
            indent + 2,
            "crl_distribution_points",
            &json_array_strs(&crl_dps, indent + 2),
        ));
    }

    if !aia_entries.is_empty() {
        let mut aia_objs = Vec::new();
        for (method, location) in &aia_entries {
            let obj = json_object(
                vec![
                    prop_str(2, "method", method),
                    prop_str(2, "location", location),
                ],
               0,
           );
           aia_objs.push(obj);
       }
       let arr = json_array(aia_objs, indent + 2);
       ext_props.push(prop_array(indent + 2, "authority_info_access", &arr));
    }

    if !unknowns.is_empty() {
        let mut unk_objs = Vec::new();
        for (oid, critical) in &unknowns {
            let obj = json_object(
                vec![
                    prop_str(2, "oid", oid),
                    prop_bool(2, "critical", *critical),
                ],
                0,
            );
            unk_objs.push(obj);
        }
        let arr = json_array(unk_objs, indent + 2);
        ext_props.push(prop_array(indent + 2, "unknown", &arr));
    }

    let ext_obj = if ext_props.is_empty() {
        json_object(Vec::new(), indent + 2)
    } else {
        json_object(ext_props, indent + 2)
    };
    props.push(prop_obj(indent + 2, "extensions", &ext_obj));

    props.push(prop_num(
        indent + 2,
        "signature_len",
        cert.signature_value.data.len() as i64,
    ));

    json_object(props, indent)
}

fn dn_to_string(name: &X509Name<'_>) -> String {
    name.to_string_with_registry(oid_registry())
        .unwrap_or_else(|_| name.to_string())
}

fn asn1time_to_string(t: ASN1Time) -> String {
    format!("{}", t)
}

fn oid_to_name(oid: Oid<'_>) -> String {
    format!("{}", oid)
}

fn key_usage_to_vec(ku: &KeyUsage) -> Vec<String> {
    let mut flags = Vec::new();
    if ku.digital_signature() {
        flags.push("Digital Signature".into());
    }
    if ku.non_repudiation() {
        flags.push("Non Repudiation".into());
    }
    if ku.key_encipherment() {
        flags.push("Key Encipherment".into());
    }
    if ku.data_encipherment() {
        flags.push("Data Encipherment".into());
    }
    if ku.key_agreement() {
        flags.push("Key Agreement".into());
    }
    if ku.key_cert_sign() {
        flags.push("Certificate Sign".into());
    }
    if ku.crl_sign() {
        flags.push("CRL Sign".into());
    }
    if ku.encipher_only() {
        flags.push("Encipher Only".into());
    }
    if ku.decipher_only() {
        flags.push("Decipher Only".into());
    }
    flags
}

fn extkey_usage_to_list(eku: &ExtendedKeyUsage) -> Vec<String> {
    let mut v = Vec::new();
    if eku.any {
        v.push("Any Extended Key Usage".into());
    }
    if eku.server_auth {
        v.push("TLS Web Server Authentication".into());
    }
    if eku.client_auth {
        v.push("TLS Web Client Authentication".into());
    }
    if eku.code_signing {
        v.push("Code Signing".into());
    }
    if eku.email_protection {
        v.push("E-mail Protection".into());
    }
    if eku.time_stamping {
        v.push("Time Stamping".into());
    }
    if eku.ocsp_signing {
        v.push("OCSP Signing".into());
    }
    v
}

fn render_crldp(cdp: &CRLDistributionPoints<'_>) -> Vec<String> {
    let mut v = Vec::new();
    for dp in &cdp.points {
        if let Some(n) = &dp.distribution_point {
            match n {
                DistributionPointName::FullName(gns) => {
                    for gn in gns {
                        if let GeneralName::URI(u) = gn {
                            v.push(u.to_string());
                        }
                    }
                }
                DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                    v.push(format!("RelativeName: {:?}", rdn));
                }
            }
        }
    }
    v
}

fn colon_hex(bytes: &[u8]) -> String {
    chunk_hex(&hex::encode_upper(bytes))
}

fn chunk_hex(hexstr: &str) -> String {
    let mut out = String::with_capacity(hexstr.len() + hexstr.len() / 2);
    for (i, c) in hexstr.chars().enumerate() {
        if i != 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c);
    }
    out
}

fn q(s: &str) -> String {
    format!("\"{}\"", json_escape_type3(s))
}

fn indent(n: usize) -> String {
    " ".repeat(n)
}

fn json_object(props: Vec<String>, indent_lv: usize) -> String {
    if props.is_empty() {
        return "{}".to_string();
    }
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&props.join(",\n"));
    s.push('\n');
    s.push_str(&indent(indent_lv));
    s.push('}');
    s
}

fn json_array(elems: Vec<String>, indent_lv: usize) -> String {
    let mut s = String::new();
    s.push_str("[\n");
    for (i, elem) in elems.iter().enumerate() {
        let lines: Vec<&str> = elem.lines().collect();
        for (j, line) in lines.iter().enumerate() {
            s.push_str(&indent(indent_lv + 2));
            s.push_str(line);
            if j + 1 != lines.len() {
                s.push('\n');
            }
        }
        if i + 1 != elems.len() {
            s.push_str(",\n");
        } else {
            s.push('\n');
        }
    }
    s.push_str(&indent(indent_lv));
    s.push(']');
    s
}

fn json_array_strs(items: &[String], indent_lv: usize) -> String {
    let elems: Vec<String> = items.iter().map(|it| q(it)).collect();
    json_array(elems, indent_lv)
}

fn prop_str(indent_lv: usize, key: &str, val: &str) -> String {
    format!("{}{}: {}", indent(indent_lv), q(key), q(val))
}

fn prop_num(indent_lv: usize, key: &str, val: i64) -> String {
    format!("{}{}: {}", indent(indent_lv), q(key), val)
}

fn prop_bool(indent_lv: usize, key: &str, val: bool) -> String {
    format!("{}{}: {}", indent(indent_lv), q(key), if val { "true" } else { "false" })
}

fn prop_obj(indent_lv: usize, key: &str, obj_json: &str) -> String {
    format!("{}{}: {}", indent(indent_lv), q(key), obj_json)
}

fn prop_array(indent_lv: usize, key: &str, arr_json: &str) -> String {
    format!("{}{}: {}", indent(indent_lv), q(key), arr_json)
}
