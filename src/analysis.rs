use std::{collections::HashMap, fs, path::Path};
use chrono::Utc;

pub fn cryptanalyze_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let p = Path::new(path);
    let data = fs::read(p)?;
    let n = data.len() as f64;

    if data.is_empty() {
        return Ok(format!(
            "{{\"File\": \"{}\", \"Size\": 0, \"Empty\": true}}",
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

    let magic = {
        let d = &data;
        if d.starts_with(b"\x7FELF") { "ELF" }
        else if d.starts_with(b"MZ") { "MZ" }
        else if d.starts_with(b"\x89PNG\r\n\x1a\n") { "PNG" }
        else if d.starts_with(b"\x1F\x8B") { "GZIP" }
        else if d.starts_with(b"PK\x03\x04") { "ZIP" }
        else if d.starts_with(b"%PDF-") { "PDF" }
        else if d.starts_with(b"-----BEGIN ") { "PEM" }
        else if d.len() > 2 && d[0] == 0x30 && (d[1] & 0x20) == 0x20 { "ASN1_DER_seq_like" }
        else { "Unknown" }
    };

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

    let (is_elf, elf_class, elf_data, elf_osabi) = detect_elf(&data);
    let (is_pe, pe_machine) = detect_pe(&data);

    let glibc_versions = if is_elf {
        find_glibc_versions(&data)
    } else {
        Vec::new()
    };

    let printable_ratio = (printable as f64) / n;
    let chronox: String = Utc::now().to_string();
    let mut out = String::new();

    use std::fmt::Write;
    write!(
        &mut out,
        "{{\n  \
            \"File\": \"{}\",\n  \
            \"Time\": \"{chronox}\",\n  \
            \"Size\": {},\n  \
            \"Type\": \"{}\",\n  \
            \"ELF\": {{\"is_elf\": {}, \"class\": {}, \"data_endian\": \"{}\", \"os_abi\": {}, \"glibc_versions\": {}}},\n  \
            \"PE\": {{\"is_pe\": {}, \"machine\": {}}},\n  \
            \"Printable_ratio\": {},\n  \
            \"Entropy\": {},\n  \
            \"Chi_square\": {},\n  \
            \"Rolling_entropy\": {{\"window\": {}, \"count\": {}, \"min\": {}, \"avg\": {}, \"max\": {}}},\n  \
            \"ECB\": {},\n  \
            \"Periodicity\": {{\"best_lag\": {}, \"correlation\": {}}},\n  \
            \"Repeating_xor_keysizes\": {},\n  \
            \"Single_byte_xor_probe\": {{\"best_key\": \"0x{:02X}\", \"score\": {}, \"printable\": {}}}\n\
        }}",
        json_escape(&p.display().to_string()),
        data.len(),
        magic,
        bool_to_json(is_elf),
        elf_class,
        elf_data,
        elf_osabi,
        json_str_array(&glibc_versions),
        bool_to_json(is_pe),
        pe_machine.map(|m| m.to_string()).unwrap_or_else(|| "null".to_string()),
        f64_json(printable_ratio),
        f64_json(entropy),
        f64_json(chi2),
        win,
        roll_cnt,
        f64_json(roll_min),
        f64_or_null(roll_avg, roll_cnt == 0),
        f64_json(roll_max),
        json_ecb(&ecb),
        best_lag,
        f64_json(best_corr),
        json_pairs(&rkx),
        best_sb_key,
        f64_json(best_sb_score),
        f64_json(best_sb_printable),
    )?;

    return Ok(out);

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => {
                    let code = c as u32;
                    out.push_str(&format!("\\u{:04X}", code));
                }
                c => out.push(c),
            }
        }
        out
    }

    fn bool_to_json(b: bool) -> &'static str { if b { "true" } else { "false" } }

    fn f64_json(v: f64) -> String {
        if v.is_finite() { format!("{:.6}", v) } else { "null".to_string() }
    }
    fn f64_or_null(v: f64, cond_null: bool) -> String {
        if cond_null || !v.is_finite() { "null".to_string() } else { format!("{:.6}", v) }
    }

    fn json_str_array(items: &[String]) -> String {
        if items.is_empty() { "[]".to_string() }
        else {
            let mut s = String::from("[");
            for (i, it) in items.iter().enumerate() {
                if i > 0 { s.push(','); }
                s.push('"'); s.push_str(&json_escape(it)); s.push('"');
            }
            s.push(']');
            s
        }
    }

    fn json_ecb(rows: &Vec<(u64,u64,u64,u64,f64)>) -> String {
        let mut s = String::from("[");
        for (i, (bs, total, dups, max_rep, score)) in rows.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&format!(
                "{{\"block_size\": {}, \"blocks\": {}, \"duplicate_blocks\": {}, \"max_repeat\": {}, \"score\": {}}}",
                bs, total, dups, max_rep, f64_json(*score)
            ));
        }
        s.push(']');
        s
    }

    fn json_pairs(rows: &Vec<(u64, f64)>) -> String {
        let mut s = String::from("[");
        for (i, (a, b)) in rows.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&format!("{{\"keysize\": {}, \"norm_hamming\": {}}}", a, f64_json(*b)));
        }
        s.push(']');
        s
    }

    fn detect_elf(d: &[u8]) -> (bool, u64, &'static str, u64) {
        if d.len() >= 16 && &d[0..4] == b"\x7FELF" {
            let class = match d[4] { 1 => 32, 2 => 64, _ => 0 };
            let data = match d[5] { 1 => "LSB", 2 => "MSB", _ => "Unknown" };
            let osabi = d[7] as u64;
            (true, class, data, osabi)
        } else {
            (false, 0, "Unknown", 0)
        }
    }

    fn detect_pe(d: &[u8]) -> (bool, Option<u16>) {
        if d.len() < 64 || &d[0..2] != b"MZ" { return (false, None); }
        if d.len() < 0x40 { return (false, None); }
        let e_lfanew = u32::from_le_bytes([d[0x3C], d[0x3D], d[0x3E], d[0x3F]]) as usize;
        if e_lfanew + 6 >= d.len() { return (false, None); }
        if &d[e_lfanew..e_lfanew+4] != b"PE\0\0" { return (false, None); }
        let machine = u16::from_le_bytes([d[e_lfanew+4], d[e_lfanew+5]]);
        (true, Some(machine))
    }

    fn find_glibc_versions(d: &[u8]) -> Vec<String> {
        let needle = b"GLIBC_";
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + needle.len() < d.len() {
            if &d[i..i+needle.len()] == needle {
                let mut j = i + needle.len();
                while j < d.len() && (d[j] as char).is_ascii_digit() || (j < d.len() && d[j] == b'.') { j += 1; }
                if j > i + needle.len() {
                    let s = String::from_utf8_lossy(&d[i..j]).to_string();
                    out.push(s);
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        out.sort();
        out.dedup();
        out
    }
}
