//! Witness collector traits and implementations

use super::trace::{
    CryptoType, CryptoWitness, MemoryOp, ProgramConfig, RangeCheckWitness, MainTraceRow, ValueBound,
    MainWitnessBuilder,
};

/// Trait for collecting witness data during VM execution
pub trait WitnessCollector {
    /// Start a new execution cycle
    fn start_cycle(&mut self, cycle: u64, pc: u64);

    /// Record an instruction execution
    fn record_instruction(
        &mut self,
        instruction: u32,
        registers: &[Vec<u32>],
        bounds: &[ValueBound],
    );

    /// Record a memory operation
    fn record_memory(
        &mut self,
        address: Vec<u32>,
        value: Vec<u32>,
        is_write: bool,
        bound: ValueBound,
    );

    /// Record a range check
    fn record_range_check(&mut self, limb: u32);

    /// Record a cryptographic syscall
    fn record_crypto(
        &mut self,
        crypto_type: CryptoType,
        inputs: Vec<u8>,
        outputs: Vec<Vec<u32>>,
        output_bounds: Vec<ValueBound>,
    );

    /// Finalize and return the collected witness
    fn finalize(self) -> MainWitnessBuilder;
}

/// Standard trace collector implementation
pub struct TraceCollector {
    config: ProgramConfig,
    builder: MainWitnessBuilder,
    current_cycle: u64,
    current_pc: u64,
    current_instruction: Option<u32>,
}

impl TraceCollector {
    /// Create a new trace collector
    pub fn new(config: ProgramConfig, program_hash: [u8; 32]) -> Self {
        Self {
            config,
            builder: MainWitnessBuilder::new(config, program_hash),
            current_cycle: 0,
            current_pc: 0,
            current_instruction: None,
        }
    }

    /// Set public inputs
    pub fn set_inputs(&mut self, inputs: Vec<Vec<u32>>) {
        self.builder.set_inputs(inputs);
    }

    /// Set public outputs
    pub fn set_outputs(&mut self, outputs: Vec<Vec<u32>>) {
        self.builder.set_outputs(outputs);
    }

    /// Finalize the current trace row if there is one
    fn finalize_current_row(&mut self, registers: &[Vec<u32>], bounds: &[ValueBound]) {
        if let Some(instruction) = self.current_instruction.take() {
            let row = MainTraceRow::new(
                self.current_cycle,
                self.current_pc,
                instruction,
                registers.to_vec(),
                bounds.to_vec(),
            );
            self.builder.add_trace_row(row);
        }
    }
}

impl WitnessCollector for TraceCollector {
    fn start_cycle(&mut self, cycle: u64, pc: u64) {
        self.current_cycle = cycle;
        self.current_pc = pc;
    }

    fn record_instruction(
        &mut self,
        instruction: u32,
        registers: &[Vec<u32>],
        bounds: &[ValueBound],
    ) {
        // Finalize previous row if exists
        if self.current_instruction.is_some() {
            self.finalize_current_row(registers, bounds);
        }

        // Store current instruction
        self.current_instruction = Some(instruction);

        // Create the trace row
        let row = MainTraceRow::new(
            self.current_cycle,
            self.current_pc,
            instruction,
            registers.to_vec(),
            bounds.to_vec(),
        );
        self.builder.add_trace_row(row);
        self.current_instruction = None;
    }

    fn record_memory(
        &mut self,
        address: Vec<u32>,
        value: Vec<u32>,
        is_write: bool,
        bound: ValueBound,
    ) {
        let op = MemoryOp::new(address, value, self.current_cycle, is_write, bound);
        self.builder.add_memory_op(op);
    }

    fn record_range_check(&mut self, limb: u32) {
        let chunk_bits = self.config.chunk_bits() as usize;
        let check = RangeCheckWitness::new(self.current_cycle, limb, chunk_bits);
        self.builder.add_range_check(check);
    }

    fn record_crypto(
        &mut self,
        crypto_type: CryptoType,
        inputs: Vec<u8>,
        outputs: Vec<Vec<u32>>,
        output_bounds: Vec<ValueBound>,
    ) {
        let op = CryptoWitness {
            cycle: self.current_cycle,
            syscall_type: crypto_type,
            inputs,
            outputs,
            output_bounds,
        };
        self.builder.add_crypto_op(op);
    }

    fn finalize(self) -> MainWitnessBuilder {
        self.builder
    }
}

/// Null collector that doesn't collect anything (for when witness is disabled)
pub struct NullCollector;

impl WitnessCollector for NullCollector {
    fn start_cycle(&mut self, _cycle: u64, _pc: u64) {}
    fn record_instruction(&mut self, _: u32, _: &[Vec<u32>], _: &[ValueBound]) {}
    fn record_memory(&mut self, _: Vec<u32>, _: Vec<u32>, _: bool, _: ValueBound) {}
    fn record_range_check(&mut self, _: u32) {}
    fn record_crypto(&mut self, _: CryptoType, _: Vec<u8>, _: Vec<Vec<u32>>, _: Vec<ValueBound>) {}
    fn finalize(self) -> MainWitnessBuilder {
        // This should never be called for NullCollector
        panic!("Cannot finalize NullCollector - witness collection was disabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_collector_basic() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        // Set up initial state
        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        // Record a cycle
        collector.start_cycle(0, 0x1000);
        collector.record_instruction(0x12345678, &registers, &bounds);

        // Build witness
        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.trace.len(), 1);
        assert_eq!(witness.trace[0].cycle, 0);
        assert_eq!(witness.trace[0].pc, 0x1000);
        assert_eq!(witness.trace[0].instruction, 0x12345678);
    }

    #[test]
    fn test_trace_collector_memory() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        collector.start_cycle(0, 0x1000);

        // Record a memory write
        collector.record_memory(
            vec![0x100, 0x0],
            vec![0x42, 0x0],
            true,
            ValueBound::tight(32),
        );

        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.memory_ops.len(), 1);
        assert_eq!(witness.memory_ops[0].address, vec![0x100, 0x0]);
        assert_eq!(witness.memory_ops[0].value, vec![0x42, 0x0]);
        assert!(witness.memory_ops[0].is_write);
    }

    #[test]
    fn test_trace_collector_range_check() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        collector.start_cycle(0, 0x1000);
        collector.record_range_check(0x12345);

        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.range_checks.len(), 1);
        assert_eq!(witness.range_checks[0].limb, 0x12345);
        assert!(witness.range_checks[0].verify(10));
    }

    #[test]
    fn test_trace_collector_crypto() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        collector.start_cycle(5, 0x2000);

        let inputs = vec![0xAAu8; 32];
        let outputs = vec![vec![0x1234, 0x5678]; 8];
        let bounds = vec![ValueBound::tight(32); 8];

        collector.record_crypto(CryptoType::Sha256, inputs.clone(), outputs.clone(), bounds);

        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.crypto_ops.len(), 1);
        assert_eq!(witness.crypto_ops[0].cycle, 5);
        assert_eq!(witness.crypto_ops[0].syscall_type, CryptoType::Sha256);
        assert_eq!(witness.crypto_ops[0].inputs, inputs);
        assert_eq!(witness.crypto_ops[0].outputs.len(), 8);
    }

    #[test]
    fn test_trace_collector_multiple_cycles() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        // Record multiple cycles
        for i in 0..10 {
            collector.start_cycle(i, 0x1000 + i * 4);
            collector.record_instruction(0x12345678 + i as u32, &registers, &bounds);
        }

        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.trace.len(), 10);
        assert_eq!(witness.cycle_count, 10);  // Fixed: 10 rows (cycles 0-9) = 10 total cycles

        // Verify cycle ordering
        for i in 0..10 {
            assert_eq!(witness.trace[i].cycle, i as u64);
            assert_eq!(witness.trace[i].pc, 0x1000 + i as u64 * 4);
        }
    }

    #[test]
    fn test_trace_collector_with_io() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];
        let mut collector = TraceCollector::new(config, program_hash);

        let inputs = vec![vec![1, 0], vec![2, 0], vec![3, 0]];
        let outputs = vec![vec![42, 0]];

        collector.set_inputs(inputs.clone());
        collector.set_outputs(outputs.clone());

        let builder = collector.finalize();
        let witness = builder.build();

        assert_eq!(witness.public_io.inputs, inputs);
        assert_eq!(witness.public_io.outputs, outputs);
    }
}
