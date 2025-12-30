#[test]
fn test_column_indices() {
    use zkir_prover::constraints::air::ZkIrAir;
    use zkir_prover::witness::ProgramConfig;

    let config = ProgramConfig {
        limb_bits: 20,
        data_limbs: 2,
        addr_limbs: 2,
    };

    let air = ZkIrAir::new(config);

    eprintln!("Main columns count: {}", air.main_trace_width());
    eprintln!("Aux columns count: {}", air.aux_trace_width());
    eprintln!("Total columns: {}", air.total_width());
    eprintln!();

    eprintln!("col_zero_flag(): {}", air.col_zero_flag());
    eprintln!("col_bitwise_rd_chunk1(1): {}", air.col_bitwise_rd_chunk1(1));
    eprintln!("col_range_chunk1(1): {}", air.col_range_chunk1(1));
    eprintln!("col_rd_indicator(0): {}", air.col_rd_indicator(0));
    eprintln!("col_rd_indicator(3): {}", air.col_rd_indicator(3));
    eprintln!("col_rs1_indicator(0): {}", air.col_rs1_indicator(0));
    eprintln!("col_rs2_indicator(0): {}", air.col_rs2_indicator(0));
    eprintln!();

    eprintln!("col_mem_perm_exec(): {}", air.col_mem_perm_exec());
    eprintln!("col_logup_and(): {}", air.col_logup_and());
}
