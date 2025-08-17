use capstone::arch::x86::{ArchMode, ArchSyntax};
use capstone::prelude::*;
use std::fmt::Write as _;
use std::fs;

pub fn le_dis_to_string(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let asm = capstone_disassemble_to_string(&bytes)?;
    fs::write("disassembly.asmod", asm)?;
    Ok(())
}

pub fn le_dis_segment(segment: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    capstone_disassemble_to_string(segment)
}

fn capstone_disassemble_to_string(code: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut cs = Capstone::new()
        .x86()
        .mode(ArchMode::Mode64)
        .syntax(ArchSyntax::Intel) 
        .build()?;
    cs.set_skipdata(true)?;

    let insns = cs.disasm_all(code, 0x0)?;

    let mut out = String::new();
    format_instructions(&mut out, &insns)?;
    Ok(out)
}

fn format_instructions(out: &mut String, insns: &capstone::Instructions) -> Result<(), std::fmt::Error> {
    for insn in insns.iter() {
        write!(out, "{:08x}: ", insn.address())?;

        let bytes = insn.bytes();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            write!(out, "{:02x}", b)?;
        }

        const BYTES_COL_WIDTH: usize = 24;
        let bytes_str_len = bytes.len().saturating_mul(3).saturating_sub(1);
        if bytes_str_len < BYTES_COL_WIDTH {
            for _ in 0..(BYTES_COL_WIDTH - bytes_str_len) {
                out.push(' ');
            }
        } else {
            out.push(' ');
        }

        let mnemonic = insn.mnemonic().unwrap_or("");
        let op_str = insn.op_str().unwrap_or("");
        if op_str.is_empty() {
            writeln!(out, "{mnemonic}")?;
        } else {
            writeln!(out, "{mnemonic} {op_str}")?;
        }
    }
    Ok(())
}
