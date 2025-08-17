use dismael::disassemble_to_string;
use std::fs;

pub fn le_dis_to_string(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let binary = fs::read(path)?;
    let machine_code: Vec<u16> = binary
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let assembly_source = disassemble_to_string(&machine_code)?;
    fs::write("disassembly.asmod", assembly_source)?;
    Ok(())
}

pub fn le_dis_segment(segment: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let machine_code: Vec<u16> = segment
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    Ok(disassemble_to_string(&machine_code)?)
}
