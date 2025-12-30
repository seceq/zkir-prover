//! Verify indicator column indices and values

use zkir_prover::witness::ProgramConfig;
use zkir_prover::constraints::air::ZkIrAir;

#[test]
fn test_indicator_column_indices() {
    let config = ProgramConfig::default();
    let air = ZkIrAir::new(config);

    println!("\n=== DECODED REGISTER COLUMNS ===");
    println!("Decoded rd column: {}", air.col_decoded_rd());
    println!("Decoded rs1 column: {}", air.col_decoded_rs1());
    println!("Decoded rs2 column: {}", air.col_decoded_rs2());

    println!("\n=== RD INDICATOR COLUMNS ===");
    println!("rd_indicator[0]: {}", air.col_rd_indicator(0));
    println!("rd_indicator[3]: {}", air.col_rd_indicator(3));
    println!("rd_indicator[15]: {}", air.col_rd_indicator(15));

    println!("\n=== RS1 INDICATOR COLUMNS ===");
    println!("rs1_indicator[0]: {}", air.col_rs1_indicator(0));
    println!("rs1_indicator[15]: {}", air.col_rs1_indicator(15));

    println!("\n=== RS2 INDICATOR COLUMNS ===");
    println!("rs2_indicator[0]: {}", air.col_rs2_indicator(0));
    println!("rs2_indicator[2]: {}", air.col_rs2_indicator(2));
    println!("rs2_indicator[15]: {}", air.col_rs2_indicator(15));

    // Verify expected values from print_all_columns test
    // Instruction: ADDI R3, R0, 12
    // Expected: rd=3, rs1=0, rs2=0 (unused for ADDI)
    println!("\n=== EXPECTED FOR ADDI R3, R0, 12 ===");
    println!("rd_indicator[3] should be at column {}", air.col_rd_indicator(3));
    println!("rs1_indicator[0] should be at column {}", air.col_rs1_indicator(0));
}
