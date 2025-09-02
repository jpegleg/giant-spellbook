use std::fs::File;
use std::io::{self, Read, BufRead, BufReader};
use std::path::Path;

#[path = "./utilities.rs"]
mod utilities;
use utilities::json_escape_type2;

pub fn search_in_file(path: &str) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = Vec::with_capacity(4096 + 2);
    reader.read_until(b'\n', &mut line)?;
    if line.last().copied() == Some(b'\n') {
        line.pop();
        if line.last().copied() == Some(b'\r') {
            line.pop();
        }
    }

    if line.len() > 4096 {
        line.truncate(4096);
    }

    if line.is_empty() {
        println!(
            "{{\n  \"File\": \"{}\",\n  \"Input_pattern_hex_encoded\": \"\",\n  \"Positions\": []\n}}",
            json_escape_type2(path)
        );
        return Ok(());
    }

    let mut file = File::open(Path::new(path))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let pat = &line;
    let mut positions: Vec<usize> = Vec::new();
    if pat.len() <= data.len() {
        for i in 0..=data.len() - pat.len() {
            if &data[i..i + pat.len()] == pat {
                positions.push(i);
            }
        }
    }

    let hex_pat = hex::encode(pat);
    print!("{{\n  \"File\": \"{}\",\n  \"Input_pattern_hex_encoded\": \"", json_escape_type2(path));
    print!("{}", hex_pat);
    print!("\",\n  \"Positions\": [");
    for (idx, pos) in positions.iter().enumerate() {
        if idx > 0 {
            print!(",");
        }
        print!("{}", pos);
    }
    println!("]\n}}");

    Ok(())
}
