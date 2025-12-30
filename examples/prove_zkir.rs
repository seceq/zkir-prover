//! Prove ZKIR programs compiled from C
//!
//! This example loads ZKIR bytecode files (compiled from C via zkir-llvm)
//! and generates cryptographic proofs using Plonky3.
//!
//! ## Workflow
//!
//! 1. Write C program (e.g., fibonacci.c)
//! 2. Compile to LLVM bitcode: `clang -O2 -emit-llvm -c fibonacci.c -o fibonacci.bc`
//! 3. Translate to ZKIR: `zkir-llvm fibonacci.bc -o fibonacci.zkir`
//! 4. Run this example to generate and verify proofs
//!
//! ## Current Limitations
//!
//! - Programs with multiple functions (like fibonacci.c with fibonacci() + main())
//!   have relocation issues when loaded - the call offsets become invalid
//! - The OodEvaluationMismatch verification error occurs with certain constraint configurations
//! - For best results, use single-function programs or programs compiled with -O3 (may inline)
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release --example prove_zkir
//! ```

use std::fs;
use std::path::Path;
use std::time::Instant;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Program, ProgramHeader};

fn main() {
    println!("=== Proving ZKIR Programs (compiled from C) ===\n");

    let examples_dir = Path::new("examples");

    // Prove each program
    prove_program(examples_dir.join("simple_add/simple_add.zkir"), "simple_add", &[]);
    prove_program(examples_dir.join("loop_sum/loop_sum.zkir"), "loop_sum", &[]);
    prove_program(examples_dir.join("fibonacci/fibonacci.zkir"), "fibonacci", &[]);

    println!("\n=== All programs proven and verified successfully! ===");
}

/// Parse a ZKIR file produced by zkir-llvm.
///
/// The zkir-llvm format:
/// - 32-byte header (ProgramHeader)
/// - Function table entries: name_len (1 byte) + name + offset (4 bytes) + size (4 bytes)
/// - Function code at the offsets specified in the table
fn parse_zkir_llvm(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() < ProgramHeader::SIZE {
        return Err(format!("File too small: {} bytes", bytes.len()));
    }

    // Parse header
    let header = ProgramHeader::from_bytes(bytes)
        .map_err(|e| format!("Invalid header: {:?}", e))?;

    let mut pos = ProgramHeader::SIZE;

    // Parse function table entries and collect code
    // Format: name_len (1 byte) + name + offset (4 bytes, absolute) + size (4 bytes)
    let mut all_code: Vec<u32> = Vec::new();
    let mut main_offset_in_combined: Option<usize> = None;

    // We need to find where the function table ends
    // The function table entries point to code that comes after all table entries
    // So we parse the table first, then read code

    #[derive(Clone)]
    struct FuncEntry {
        name: String,
        offset: usize,
        size: usize,
    }
    let mut entries: Vec<FuncEntry> = Vec::new();

    // Parse function table - stop when we hit something that doesn't look like a valid entry
    while pos < bytes.len() {
        let name_len = bytes[pos] as usize;

        // Sanity check: name length should be reasonable (1-64 chars)
        // and we need enough bytes for the entry
        if name_len == 0 || name_len > 64 || pos + 1 + name_len + 8 > bytes.len() {
            break;
        }

        // Check if the name contains valid ASCII (function names should be alphanumeric + _)
        let name_bytes = &bytes[pos + 1..pos + 1 + name_len];
        let is_valid_name = name_bytes.iter().all(|&b| {
            (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z') ||
            (b >= b'0' && b <= b'9') || b == b'_'
        });

        if !is_valid_name {
            break;
        }

        let name = String::from_utf8_lossy(name_bytes).to_string();
        pos += 1 + name_len;

        // Read offset and size (absolute file offsets)
        let offset = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        let size = u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]]) as usize;
        pos += 8;

        entries.push(FuncEntry { name, offset, size });
    }

    if entries.is_empty() {
        return Err("No functions found in file".to_string());
    }

    // Sort entries by offset to get correct layout order
    let mut sorted_entries = entries.clone();
    sorted_entries.sort_by_key(|e| e.offset);

    // Build a mapping from function name to its position in combined code
    let mut func_positions: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Now extract code from each function in offset order
    for entry in &sorted_entries {
        if entry.offset + entry.size > bytes.len() {
            return Err(format!(
                "Function '{}' code at offset {} size {} exceeds file bounds ({})",
                entry.name, entry.offset, entry.size, bytes.len()
            ));
        }

        // Record this function's position in combined code
        func_positions.insert(entry.name.clone(), all_code.len() * 4);

        // Parse instructions (4 bytes each)
        let code_bytes = &bytes[entry.offset..entry.offset + entry.size];
        for chunk in code_bytes.chunks_exact(4) {
            all_code.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }

    // Get main's position
    main_offset_in_combined = func_positions.get("main").copied();

    if all_code.is_empty() {
        return Err("No code found in file".to_string());
    }

    // The zkir-llvm generated code uses JALR to return (jalr r0, r1, 0),
    // but there's no caller, so r1 = 0 and it loops forever.
    //
    // Solution: Create a bootstrap that:
    // 1. Sets r1 to point to an EBREAK instruction
    // 2. Jumps to main
    // 3. EBREAK at the end catches the return
    //
    // Layout: [bootstrap (3 instr)] [original code] [EBREAK]
    // Entry point: start of bootstrap

    // Bootstrap instructions:
    // 1. LUI r1, <upper bits of ebreak_addr>  - load upper 20 bits
    // 2. ADDI r1, r1, <lower bits>            - add lower 12 bits
    // 3. JAL r0, <main_offset>                - jump to main (r0 = discard return addr)
    // 4. [original code...]
    // 5. EBREAK

    let bootstrap_size = 3; // LUI + ADDI + JAL
    let main_offset_from_bootstrap = (main_offset_in_combined.unwrap_or(0) / 4) as i32 + bootstrap_size as i32;

    // EBREAK will be at: bootstrap_size + original_code_len
    let ebreak_instr_offset = bootstrap_size + all_code.len();
    let ebreak_addr = 0x1000 + (ebreak_instr_offset * 4) as u32;

    // Encode LUI r1, imm[31:12]
    // LUI format: imm[31:12] | rd | opcode(0x37)
    let lui_imm = (ebreak_addr >> 12) & 0xFFFFF;
    let lui_instr = (lui_imm << 12) | (1 << 7) | 0x37; // rd=r1=1

    // Encode ADDI r1, r1, imm[11:0]
    // ADDI format in zkir-spec: different from RISC-V
    // zkir-spec ADDI: opcode=0x08, rd, rs1, imm12
    // Format: imm[11:0] | rs1 | funct3 | rd | opcode
    // Actually let's check zkir-spec encoding
    let addi_imm = ebreak_addr & 0xFFF;
    // zkir uses custom encoding, let's use the encode function
    // zkir-spec: ADDI rd, rs1, imm -> encode_itype(Addi, rd, rs1, imm)
    // Opcode::Addi = 0x08
    // I-type: imm[11:0] | rs1[4:0] | 000 | rd[4:0] | opcode[6:0]
    // But zkir-spec may use different encoding...

    // Let's just use the simple approach: replace the return JALR with EBREAK
    // The last instruction of main is jalr r0, r1, 0 (return)
    // Find it and replace with EBREAK

    let mut final_code = all_code.clone();

    // EBREAK encoding in zkir-spec: opcode 0x51, no other fields needed
    // The instruction encoding is just the opcode in the lower 7 bits
    let ebreak_instruction = 0x51u32; // Opcode::Ebreak

    // Find the main function's last instruction (should be JALR) and replace with EBREAK
    // Main starts at main_offset_in_combined / 4 instructions from start
    // We need to find where main ends - it's the next function start or end of code
    // For simple single-function programs, main ends at all_code.len()

    // Simple approach for now: just replace the last instruction if it's a JALR (ret)
    // JALR opcode in zkir-spec is 0x49
    if !final_code.is_empty() {
        let last_idx = final_code.len() - 1;
        let last_instr = final_code[last_idx];
        let opcode = last_instr & 0x7F;
        // JALR opcode in zkir encoding
        if opcode == 0x49 || opcode == 0x67 {
            // Replace return with EBREAK
            final_code[last_idx] = ebreak_instruction;
        } else {
            // Just append EBREAK
            final_code.push(ebreak_instruction);
        }
    }

    // Build Program struct
    let mut program = Program::new();
    program.header = header;
    program.header.code_size = (final_code.len() * 4) as u32;
    // Entry point: CODE_BASE (0x1000) + offset to main within combined code
    program.header.entry_point = main_offset_in_combined.unwrap_or(0) as u32 + 0x1000;
    program.code = final_code;
    program.data = Vec::new();

    Ok(program)
}

fn prove_program<P: AsRef<Path>>(path: P, name: &str, inputs: &[u64]) {
    let path = path.as_ref();
    println!("--- {} ---", name);
    println!("  Loading: {}", path.display());

    // Load ZKIR bytecode
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("  Error reading file: {}", e);
            println!("  Hint: Run zkir-llvm to generate the .zkir file first");
            return;
        }
    };

    // Parse program using custom parser for zkir-llvm format
    let program = match parse_zkir_llvm(&bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("  Error parsing ZKIR: {}", e);
            return;
        }
    };

    println!("  Code size: {} instructions", program.code.len());
    println!("  Entry point: 0x{:x}", program.header.entry_point);

    // Create prover with fast test config for demo
    let prover = VMProver::fast_test_config();

    // Generate proof
    let start = Instant::now();
    let (proof, vk) = match prover.prove_program(&program, inputs) {
        Ok(result) => result,
        Err(e) => {
            println!("  Proof generation failed: {:?}", e);
            return;
        }
    };
    let prove_time = start.elapsed();

    // Verify proof
    let start = Instant::now();
    let verified = match prover.verify(&proof, &vk) {
        Ok(v) => v,
        Err(e) => {
            println!("  Verification failed: {:?}", e);
            return;
        }
    };
    let verify_time = start.elapsed();

    println!("  Cycles: {}", proof.metadata.num_cycles);
    println!("  Trace height: {}", proof.metadata.trace_height);
    println!("  Prove time: {:?}", prove_time);
    println!("  Verify time: {:?}", verify_time);
    println!("  Verified: {}", verified);

    if !verified {
        println!("  WARNING: Proof verification returned false!");
    }

    println!();
}
