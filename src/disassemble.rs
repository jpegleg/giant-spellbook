use capstone::arch::x86::{ArchMode, ArchSyntax};
use capstone::prelude::*;
use std::fmt::Write as _;
use std::fs;

const BYTES_COL_WIDTH: usize = 24;

pub fn le_dis_to_string(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let asm = capstone_disassemble_to_string_with_base_and_limit(&bytes, 0, u64::MAX)?;
    fs::write("disassembly.txt", asm)?;
    Ok(())
}

pub fn le_dis_segment_bounded(
    segment: &[u8],
    base_addr: u64,
    limit_end: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    capstone_disassemble_to_string_with_base_and_limit(segment, base_addr, limit_end)
}

fn capstone_disassemble_to_string_with_base_and_limit(
    code: &[u8],
    base_addr: u64,
    limit_end: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut cs = Capstone::new()
        .x86()
        .mode(ArchMode::Mode64)
        .syntax(ArchSyntax::Intel)
        .build()?;
    cs.set_skipdata(true)?;

    let insns = cs.disasm_all(code, base_addr)?;
    let mut out = String::new();
    format_instructions_bounded(&mut out, &insns, limit_end)?;
    Ok(out)
}

fn format_instructions_bounded(
    out: &mut String,
    insns: &capstone::Instructions,
    limit_end: u64,
) -> Result<(), std::fmt::Error> {
    for insn in insns.iter() {
        let addr = insn.address();
        if addr >= limit_end {
            break;
        }
        write!(out, "{:08x}: ", addr)?;

        let bytes = insn.bytes();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            write!(out, "{:02x}", b)?;
        }

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
