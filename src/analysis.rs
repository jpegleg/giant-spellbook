use std::{collections::HashMap, fs, path::Path};
use chrono::Utc;
use std::fmt::Write;

const KEY_CURRENT: &[u8] = b"current version ";
const KEY_COMPAT:  &[u8] = b"compatibility version ";
const MUSL_KEY_CURRENT: &[u8] = b"ld-musl-";
const MUSL_KEY_COMPAT: &[u8] =  b"musl libc";

pub fn cryptanalyze_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let p = Path::new(path);
    let data = fs::read(p)?;
    let n = data.len() as f64;

    if data.is_empty() {
        return Ok(format!(
            "{{\n  \"file\": \"{}\",\n  \"size\": 0,\n  \"empty\": true\n}}\n",
            json_escape(&p.display().to_string())
        ));
    }

    let mut counts = [0u64; 256];
    let mut printable = 0u64;
    for &b in &data {
        counts[b as usize] += 1;
        if b == 9 || b == 10 || b == 13 || (32..=126).contains(&b) {
            printable += 1;
        }
    }

    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / n;
            entropy -= p * p.log2();
        }
    }

    let exp = n / 256.0;
    let mut chi2 = 0.0f64;
    for &c in &counts {
        let o = c as f64;
        let d = o - exp;
        chi2 += d * d / exp;
    }

    let (is_elf, elf_class, elf_endian, elf_os_abi) = detect_elf(&data);
    let pe_info = detect_pe(&data);
    let (is_macho, is_fat, fat_arch_count, macho_kind) = detect_macho(&data);
    let is_wasm = detect_wasm(&data);
    let is_png  = data.starts_with(b"\x89PNG\r\n\x1a\n");
    let is_gzip = data.starts_with(b"\x1F\x8B");
    let is_zip  = data.starts_with(b"PK\x03\x04");
    let is_pdf  = data.starts_with(b"%PDF-");
    let is_pem  = data.starts_with(b"-----BEGIN ");
    let is_jpeg = data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
    let is_gif  = data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a");
    let is_ole  = data.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
    let looks_xlsx = is_zip && (memmem(&data, b"[Content_Types].xml").is_some() && memmem(&data, b"xl/").is_some());
    let looks_doc  = is_ole && (memmem(&data, b"WordDocument").is_some() || memmem(&data, b"\x00W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00").is_some());

    let magic = if is_wasm { "WASM" }
        else if is_macho { "Mach-O" }
        else if is_elf { "ELF" }
        else if pe_info.0 { pe_info.4 }
        else if is_png { "PNG" }
        else if is_jpeg { "JPEG" }
        else if is_gif { "GIF" }
        else if is_gzip { "GZIP" }
        else if looks_xlsx { "XLSX (ZIP+xl/)" }
        else if is_zip { "ZIP" }
        else if looks_doc { "DOC (OLE/CFB)" }
        else if is_ole { "OLE/CFB" }
        else if is_pdf { "PDF" }
        else if is_pem { "PEM" }
        else { "Unknown" };

    let platform_guess = if is_wasm { "WebAssembly" }
        else if is_macho { "MacOS" }
        else if pe_info.0 {
            if pe_info.3.map(|s| is_uefi_subsystem(s)).unwrap_or(false) { "UEFI" } else { "Windows" }
        } else if is_elf {
            match elf_os_abi {
                9  => "FreeBSD",
                12 => "OpenBSD",
                2  => "NetBSD",
                3  => "GNU/Linux",
                _  => "ELF-Unknown/Linux",
            }
        } else { "Unknown" };

    let win = 1024usize.min(data.len());
    let step = (win / 2).max(1);
    let (roll_min, roll_avg, roll_max, roll_cnt) = if win >= 64 {
        let mut rmin = f64::INFINITY;
        let mut rmax = 0.0f64;
        let mut racc = 0.0f64;
        let mut rcnt = 0u64;
        let mut i = 0usize;
        while i + win <= data.len() {
            let mut c = [0u64; 256];
            for &b in &data[i..i + win] { c[b as usize] += 1; }
            let mut e = 0.0f64;
            for v in c {
                if v > 0 {
                    let p = (v as f64) / (win as f64);
                    e -= p * p.log2();
                }
            }
            rmin = rmin.min(e);
            rmax = rmax.max(e);
            racc += e;
            rcnt += 1;
            i += step;
        }
        (rmin, racc / (rcnt as f64), rmax, rcnt)
    } else {
        (f64::NAN, f64::NAN, f64::NAN, 0)
    };

    let mut ecb = Vec::new();
    for &bs in &[8usize, 16, 32] {
        if data.len() >= bs {
            let mut map: HashMap<&[u8], u32> = HashMap::new();
            for chunk in data.chunks_exact(bs) { *map.entry(chunk).or_insert(0) += 1; }
            let total_blocks = map.values().sum::<u32>() as u64;
            let dup_blocks = map.values().filter(|&&c| c > 1).count() as u64;
            let max_rep = map.values().copied().max().unwrap_or(1) as u64;
            let score = if total_blocks > 0 { (dup_blocks as f64) / (total_blocks as f64) } else { 0.0 };
            ecb.push((bs as u64, total_blocks, dup_blocks, max_rep, score));
        }
    }

    let max_lag = 64usize.min(data.len().saturating_sub(1));
    let mut best_lag = 0usize;
    let mut best_corr = 0.0f64;
    for lag in 1..=max_lag {
        let mut matches = 0u64;
        for i in lag..data.len() {
            if data[i] == data[i - lag] { matches += 1; }
        }
        let denom = (data.len() - lag) as f64;
        if denom > 0.0 {
            let corr = (matches as f64) / denom;
            if corr > best_corr { best_corr = corr; best_lag = lag; }
        }
    }

    let hamming = |a: &[u8], b: &[u8]| -> u32 {
        let len = a.len().min(b.len());
        let mut dist = 0u32;
        for i in 0..len { dist += (a[i] ^ b[i]).count_ones(); }
        dist + ((a.len() as i32 - b.len() as i32).unsigned_abs() * 8)
    };

    let mut rkx = Vec::new();
    {
        let max_ks = 40usize.min(data.len() / 4).max(2);
        for ks in 2..=max_ks {
            let mut pairs = 0u32;
            let mut acc = 0.0f64;
            let mut off = 0usize;
            while off + 2 * ks <= data.len() && pairs < 8 {
                let d = hamming(&data[off..off + ks], &data[off + ks..off + 2 * ks]) as f64;
                acc += d / (ks as f64);
                pairs += 1;
                off += 2 * ks;
            }
            if pairs > 0 { rkx.push((ks as u64, acc / (pairs as f64))); }
        }
        rkx.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        if rkx.len() > 6 { rkx.truncate(6); }
    }

    let sample = if data.len() > 4096 { &data[..4096] } else { &data[..] };
    let score_english = |buf: &[u8]| -> f64 {
        let mut score = 0.0f64;
        for &b in buf {
            match b {
                9 | 10 | 13 | 32 => { score += 0.2; }
                65..=90 | 97..=122 => {}
                46 | 44 | 59 | 58 | 39 | 34 | 45 => { score += 0.3; }
                0..=8 | 11 | 12 | 14..=31 | 127..=159 => { score += 5.0; }
                _ => { score += 0.8; }
            }
        }
        let spaces = buf.iter().filter(|&&b| b == b' ').count() as f64 / (buf.len() as f64);
        score - spaces
    };
    let mut best_sb_key = 0u8;
    let mut best_sb_score = f64::INFINITY;
    let mut best_sb_printable = 0.0f64;
    {
        let mut xored = vec![0u8; sample.len()];
        for k in 0u16..=255 {
            let key = k as u8;
            for (i, &b) in sample.iter().enumerate() { xored[i] = b ^ key; }
            let sc = score_english(&xored);
            let pr = xored.iter().filter(|&&b| b == 9 || b == 10 || b == 13 || (32..=126).contains(&b)).count() as f64 / (xored.len() as f64);
            if sc < best_sb_score {
                best_sb_score = sc;
                best_sb_key = key;
                best_sb_printable = pr;
            }
        }
    }

    let glibc_versions   = if is_elf { find_glibc_versions(&data) } else { Vec::new() };
    let musl_versions    = if is_elf { find_musl_versions_strict_and_loose(&data) } else { Vec::new() };
    let uclibc_versions  = if is_elf { find_uclibc_versions(&data) } else { Vec::new() };
    let bsd_libc_sonames = if is_elf { find_bsd_libc_sonames(&data) } else { Vec::new() };
    let (darwin_libsystem_present, darwin_versions) = if is_macho { find_darwin_libsystem(&data) } else { (false, Vec::new()) };

    let printable_ratio = (printable as f64) / n;
    let chronox: String = Utc::now().to_string();
    let mut out = String::new();

    writeln!(&mut out, "{{")?;
    writeln!(&mut out, "  \"File\": \"{}\",", json_escape(&p.display().to_string()))?;
    writeln!(&mut out, "  \"Report time\": \"{chronox}\",",)?;
    writeln!(&mut out, "  \"Size\": {},", data.len())?;
    writeln!(&mut out, "  \"Type\": \"{}\",", magic)?;
    writeln!(&mut out, "  \"Platform_guess\": \"{}\",", platform_guess)?;
    writeln!(&mut out, "  \"Elf\": {{")?;
    writeln!(&mut out, "    \"is_elf\": {},", bool_to_json(is_elf))?;
    writeln!(&mut out, "    \"class\": {},", elf_class)?;
    writeln!(&mut out, "    \"endian\": \"{}\",", elf_endian)?;
    writeln!(&mut out, "    \"os_abi\": {},", elf_os_abi)?;
    writeln!(&mut out, "    \"os_abi_name\": \"{}\"", elf_os_abi_name(elf_os_abi))?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"PE\": {{")?;
    writeln!(&mut out, "    \"is_pe\": {},", bool_to_json(pe_info.0))?;
    writeln!(&mut out, "    \"machine\": {},", pe_info.1.map(|m| m.to_string()).unwrap_or_else(|| "null".to_string()))?;
    writeln!(&mut out, "    \"is_dll\": {},", bool_to_json(pe_info.2))?;
    writeln!(&mut out, "    \"subsystem\": {},", pe_info.3.map(|s| s.to_string()).unwrap_or_else(|| "null".to_string()))?;
    writeln!(&mut out, "    \"kind\": \"{}\"", pe_info.4)?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"Mach-O\": {{")?;
    writeln!(&mut out, "    \"is_macho\": {},", bool_to_json(is_macho))?;
    writeln!(&mut out, "    \"is_fat\": {},", bool_to_json(is_fat))?;
    writeln!(&mut out, "    \"fat_arch_count\": {},", fat_arch_count)?;
    writeln!(&mut out, "    \"kind\": \"{}\"", macho_kind)?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"WASM\": {{")?;
    writeln!(&mut out, "    \"is_wasm\": {}", bool_to_json(is_wasm))?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"Clibrary\": {{")?;
    writeln!(&mut out, "    \"glibc\": {},", json_str_array(&glibc_versions))?;
    writeln!(&mut out, "    \"musl\": {},", json_str_array(&musl_versions))?;
    writeln!(&mut out, "    \"uclibc\": {},", json_str_array(&uclibc_versions))?;
    writeln!(&mut out, "    \"libc_sonames\": {},", json_str_array(&bsd_libc_sonames))?;
    writeln!(&mut out, "    \"darwin_libsystem_present\": {},", bool_to_json(darwin_libsystem_present))?;
    writeln!(&mut out, "    \"darwin_versions\": {}", json_str_array(&darwin_versions))?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"Printable_ratio\": {},", f64_json(printable_ratio))?;
    writeln!(&mut out, "  \"Entropy\": {},", f64_json(entropy))?;
    writeln!(&mut out, "  \"Chi_square\": {},", f64_json(chi2))?;
    writeln!(&mut out, "  \"Rolling_entropy\": {{")?;
    writeln!(&mut out, "    \"window\": {},", win)?;
    writeln!(&mut out, "    \"count\": {},", roll_cnt)?;
    writeln!(&mut out, "    \"min\": {},", f64_json(roll_min))?;
    writeln!(&mut out, "    \"avg\": {},", f64_or_null(roll_avg, roll_cnt == 0))?;
    writeln!(&mut out, "    \"max\": {}", f64_json(roll_max))?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"ECB\": [")?;
    for (i, (bs, total, dups, max_rep, score)) in ecb.iter().enumerate() {
        writeln!(
            &mut out,
            "    {{\"block_size\": {}, \"blocks\": {}, \"duplicate_blocks\": {}, \"max_repeat\": {}, \"score\": {}}}{}",
            bs, total, dups, max_rep, f64_json(*score),
            if i + 1 == ecb.len() { "" } else { "," }
        )?;
    }
    writeln!(&mut out, "  ],")?;

    writeln!(&mut out, "  \"Periodicity\": {{")?;
    writeln!(&mut out, "    \"best_lag\": {},", best_lag)?;
    writeln!(&mut out, "    \"correlation\": {}", f64_json(best_corr))?;
    writeln!(&mut out, "  }},")?;

    writeln!(&mut out, "  \"Repeating_xor_keysizes\": [")?;
    for (i, (ks, score)) in rkx.iter().enumerate() {
        writeln!(
            &mut out,
            "    {{\"keysize\": {}, \"norm_hamming\": {}}}{}",
            ks, f64_json(*score),
            if i + 1 == rkx.len() { "" } else { "," }
        )?;
    }
    writeln!(&mut out, "  ],")?;

    writeln!(&mut out, "  \"Single_byte_xor_probe\": {{")?;
    writeln!(&mut out, "    \"best_key\": \"0x{:02X}\",", best_sb_key)?;
    writeln!(&mut out, "    \"score\": {},", f64_json(best_sb_score))?;
    writeln!(&mut out, "    \"printable\": {}", f64_json(best_sb_printable))?;
    writeln!(&mut out, "  }}")?;

    writeln!(&mut out, "}}\n")?;

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }
    fn bool_to_json(b: bool) -> &'static str { if b { "true" } else { "false" } }
    fn f64_json(v: f64) -> String { if v.is_finite() { format!("{:.6}", v) } else { "null".to_string() } }
    fn f64_or_null(v: f64, cond_null: bool) -> String {
        if cond_null || !v.is_finite() { "null".to_string() } else { format!("{:.6}", v) }
    }
    fn json_str_array(items: &[String]) -> String {
        if items.is_empty() { "[]".to_string() } else {
            let mut s = String::from("[");
            for (i, it) in items.iter().enumerate() {
                if i > 0 { s.push(','); }
                s.push('"'); s.push_str(&json_escape(it)); s.push('"');
            }
            s.push(']'); s
        }
    }

    fn elf_os_abi_name(os_abi: u64) -> &'static str {
        match os_abi {
            0 => "SYSV/Default '0'",
            2 => "NetBSD",
            3 => "GNU",
            6 => "Solaris",
            9 => "FreeBSD",
            12 => "OpenBSD",
            _ => "Unknown",
        }
    }

    fn detect_elf(d: &[u8]) -> (bool, u64, &'static str, u64) {
        if d.len() >= 16 && &d[0..4] == b"\x7FELF" {
            let class = match d[4] { 1 => 32, 2 => 64, _ => 0 };
            let data = match d[5] { 1 => "LSB", 2 => "MSB", _ => "Unknown" };
            let os_abi = d[7] as u64;
            (true, class, data, os_abi)
        } else { (false, 0, "Unknown", 0) }
    }

    fn detect_pe(d: &[u8]) -> (bool, Option<u16>, bool, Option<u16>, &'static str) {
        if d.len() < 64 || &d[0..2] != b"MZ" { return (false, None, false, None, ""); }
        if d.len() < 0x40 { return (false, None, false, None, ""); }
        let e_lfanew = u32::from_le_bytes([d[0x3C], d[0x3D], d[0x3E], d[0x3F]]) as usize;
        if e_lfanew + 0x18 >= d.len() { return (false, None, false, None, ""); }
        if &d[e_lfanew..e_lfanew+4] != b"PE\0\0" { return (false, None, false, None, ""); }

        let machine = u16::from_le_bytes([d[e_lfanew+4], d[e_lfanew+5]]);
        let characteristics = u16::from_le_bytes([d[e_lfanew+0x12], d[e_lfanew+0x13]]);
        let is_dll = (characteristics & 0x2000) != 0; // IMAGE_FILE_DLL

        let size_of_optional_header = u16::from_le_bytes([d[e_lfanew+0x14], d[e_lfanew+0x15]]) as usize;
        let opt_off = e_lfanew + 0x18;
        if opt_off + size_of_optional_header > d.len() { return (true, Some(machine), is_dll, None, if is_dll { "PE/DLL" } else { "PE/EXE" }); }
        if opt_off + 2 > d.len() { return (true, Some(machine), is_dll, None, if is_dll { "PE/DLL" } else { "PE/EXE" }); }

        let magic = u16::from_le_bytes([d[opt_off], d[opt_off+1]]);
        let subsystem_off = if magic == 0x10B {
            opt_off + 0x44
        } else if magic == 0x20B {
            opt_off + 0x5C
        } else {
            opt_off + 0x44
        };
        let subsystem = if subsystem_off + 2 <= d.len() {
            Some(u16::from_le_bytes([d[subsystem_off], d[subsystem_off+1]]))
        } else { None };

        let kind = if subsystem.map(|s| is_uefi_subsystem(s)).unwrap_or(false) {
            "PE/UEFI"
        } else if is_dll {
            "PE/DLL"
        } else {
            "PE/EXE"
        };

        (true, Some(machine), is_dll, subsystem, kind)
    }

    fn is_uefi_subsystem(sub: u16) -> bool {
        matches!(sub, 10 | 11 | 12 | 13)
    }

    fn detect_macho(d: &[u8]) -> (bool, bool, u64, &'static str) {
        if d.len() < 4 { return (false, false, 0, "Unknown"); }
        let m_be = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        let m_le = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        const FAT_MAGIC: u32 = 0xCAFEBABE;
        const FAT_CIGAM: u32 = 0xBEBAFECA;
        const FAT_MAGIC_64: u32 = 0xCAFED00D;
        const FAT_CIGAM_64: u32 = 0xD00DCAFE;

        if m_be == FAT_MAGIC || m_be == FAT_MAGIC_64 {
            if d.len() >= 8 {
                let nfat = u32::from_be_bytes([d[4], d[5], d[6], d[7]]) as u64;
                return (true, true, nfat, "Fat/BE");
            }
        }
        if m_be == FAT_CIGAM || m_be == FAT_CIGAM_64 {
            if d.len() >= 8 {
                let nfat = u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as u64;
                return (true, true, nfat, "Fat/LE");
            }
        }
        match (m_be, m_le) {
            (0xFEEDFACE, _) => (true, false, 1, "MH_MAGIC (BE 32)"),
            (0xFEEDFACF, _) => (true, false, 1, "MH_MAGIC_64 (BE 64)"),
            (_, 0xFEEDFACE) => (true, false, 1, "MH_MAGIC (LE 32)"),
            (_, 0xFEEDFACF) => (true, false, 1, "MH_MAGIC_64 (LE 64)"),
            (0xCEFAEDFE, _) => (true, false, 1, "MH_CIGAM (swap 32)"),
            (0xCFFAEDFE, _) => (true, false, 1, "MH_CIGAM_64 (swap 64)"),
            _ => (false, false, 0, "Unknown"),
        }
    }

    fn detect_wasm(d: &[u8]) -> bool {
        d.len() >= 8 && &d[0..4] == b"\0asm" && (d[4] == 0x01 || d[4] == 0x00)
    }

    fn find_glibc_versions(d: &[u8]) -> Vec<String> {
        let needle = b"GLIBC_";
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + needle.len() < d.len() {
            if &d[i..i+needle.len()] == needle {
                let mut j = i + needle.len();
                while j < d.len() && (d[j].is_ascii_digit() || d[j] == b'.') { j += 1; }
                if j > i + needle.len() {
                    out.push(String::from_utf8_lossy(&d[i..j]).to_string());
                    i = j; continue;
                }
            }
            i += 1;
        }
        out.sort(); out.dedup(); out
    }

    fn find_musl_versions_strict_and_loose(d: &[u8]) -> Vec<String> {
        let mut out = Vec::new();

        let keys: [&[u8]; 2] = [MUSL_KEY_CURRENT, MUSL_KEY_COMPAT];

        for &key in &keys {
            let mut pos = 0usize;
            while let Some(idx) = memmem_from(d, key.as_ref(), pos) {
                let start = idx + key.len();
                let end = (start + 64).min(d.len());
                let slice = &d[start..end];
                let mut j = 0usize;
                while j < slice.len() && !slice[j].is_ascii_digit() { j += 1; }
                if j < slice.len() {
                    let mut k = j;
                    while k < slice.len() && (slice[k].is_ascii_digit() || slice[k] == b'.') { k += 1; }
                    out.push(format!("musl_{}", String::from_utf8_lossy(&slice[j..k])));
                } else {
                    out.push("musl".to_string());
                }
                pos = end;
            }
        }

        let mut i = 0usize;
        while i + 4 <= d.len() {
            if (d[i] | 0x20) == b'm' && (d[i+1] | 0x20) == b'u' && (d[i+2] | 0x20) == b's' && (d[i+3] | 0x20) == b'l' {
                let start = i;
                let end = (i + 64).min(d.len());
                let slice = &d[start..end];
                let mut j = 0usize;
                while j < slice.len() && !slice[j].is_ascii_digit() { j += 1; }
                if j < slice.len() {
                    let mut k = j;
                    while k < slice.len() && (slice[k].is_ascii_digit() || slice[k] == b'.') { k += 1; }
                    out.push(format!("musl_{}", String::from_utf8_lossy(&slice[j..k])));
                } else {
                    out.push("musl".to_string());
                }
                i = end; continue;
            }
            i += 1;
        }

        out.sort(); out.dedup(); out
    }

    fn find_uclibc_versions(d: &[u8]) -> Vec<String> {
        let needle = b"uClibc";
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + needle.len() <= d.len() {
            if &d[i..i+needle.len()] == needle {
                let start = i;
                let end = (i + 64).min(d.len());
                let slice = &d[start..end];
                let mut j = needle.len();
                while j < slice.len() && !slice[j].is_ascii_digit() { j += 1; }
                if j < slice.len() {
                    let mut k = j;
                    while k < slice.len() && (slice[k].is_ascii_digit() || slice[k] == b'.') { k += 1; }
                    out.push(format!("uClibc_{}", String::from_utf8_lossy(&slice[j..k])));
                } else {
                    out.push("uClibc".to_string());
                }
                i = end; continue;
            }
            i += 1;
        }
        out.sort(); out.dedup(); out
    }

    fn find_bsd_libc_sonames(d: &[u8]) -> Vec<String> {
        let pat = b"libc.so.";
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + pat.len() < d.len() {
            if &d[i..i+pat.len()] == pat {
                let mut j = i + pat.len();
                let mut seen_digit = false;
                while j < d.len() && (d[j].is_ascii_digit() || d[j] == b'.') {
                    if d[j].is_ascii_digit() { seen_digit = true; }
                    j += 1;
                }
                if seen_digit {
                    out.push(String::from_utf8_lossy(&d[i..j]).to_string());
                    i = j; continue;
                }
            }
            i += 1;
        }
        out.sort(); out.dedup(); out
    }

    fn find_darwin_libsystem(d: &[u8]) -> (bool, Vec<String>) {
        let mut present = false;
        let mut versions = Vec::new();

        let ls = b"libSystem.B.dylib";
        if memmem(d, ls).is_some() { present = true; }

        let keys: [&[u8]; 2] = [KEY_CURRENT, KEY_COMPAT];

        for &key in &keys {
            let mut pos = 0usize;
            while let Some(idx) = memmem_from(d, key, pos) {
                let start = idx + key.len();
                let mut j = start;
                while j < d.len() && (d[j].is_ascii_digit() || d[j] == b'.') { j += 1; }
                if j > start {
                    versions.push(format!(
                        "{}{}",
                        String::from_utf8_lossy(key),
                        String::from_utf8_lossy(&d[start..j])
                    ));
                }
                pos = j;
            }
        }

        versions.sort(); versions.dedup();
        (present, versions)
    }

    fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
        memmem_from(hay, needle, 0)
    }
    fn memmem_from(hay: &[u8], needle: &[u8], mut start: usize) -> Option<usize> {
        if needle.is_empty() { return Some(start.min(hay.len())); }
        while start + needle.len() <= hay.len() {
            if &hay[start..start + needle.len()] == needle { return Some(start); }
            start += 1;
        }
        None
    }

    Ok(out)

}
