//! Capstone-based translator for ARM+Thumb.

use std::collections::{BTreeMap, VecDeque};

use architecture::Endian;
use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::{arm_insn, arm_op_type};
use error::*;
use il::*;
use translator::{DEFAULT_TRANSLATION_BLOCK_BYTES, Translator, TranslationMemory, BlockTranslationResult};

mod semantics;

/// The ARM translator.
#[derive(Clone, Debug)]
pub struct Arm;

impl Arm {
    pub fn new() -> Arm { Arm }
}

impl Translator for Arm {
    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
        translate_block(bytes, address, Endian::Little, false)
    }

    /// Translates a function
    fn translate_function(
        &self,
        memory: &TranslationMemory,
        function_address: u64)
    -> Result<Function> {

        // Addresses of blocks pending translation
        let mut translation_queue: VecDeque<u64> = VecDeque::new();

        // The results of block translations
        let mut translation_results: BTreeMap<u64, BlockTranslationResult> = BTreeMap::new();

        translation_queue.push_front(function_address);

        // translate all blocks in the function
        while !translation_queue.is_empty() {
            let block_address = translation_queue.pop_front().unwrap();
            let real_address = block_address & !1;

            // TODO: What happens if block is accessed in both ARM+Thumb mode?
            if translation_results.contains_key(&real_address) {
                continue;
            }

            // For Thumb, we need to mask out the LSB
            let block_bytes = memory.get_bytes(real_address, DEFAULT_TRANSLATION_BLOCK_BYTES);
            if block_bytes.len() == 0 {
                let mut control_flow_graph = ControlFlowGraph::new();
                let block_index = control_flow_graph.new_block()?.index();
                control_flow_graph.set_entry(block_index)?;
                control_flow_graph.set_exit(block_index)?;
                translation_results.insert(
                    real_address,
                    BlockTranslationResult::new(
                        vec![(real_address, control_flow_graph)],
                        real_address,
                        0,
                        Vec::new()
                    )
                );
                continue;
            }

            // translate this block
            let block_translation_result = self.translate_block(&block_bytes, block_address)?;

            // enqueue all successors
            for successor in block_translation_result.successors().iter() {
                if !translation_queue.contains(&successor.0) {
                    translation_queue.push_back(successor.0);
                }
            }

            translation_results.insert(real_address, block_translation_result);
        }

        // We now insert all of these blocks into a new control flow graph,
        // keeping track of their new entry and exit indices.

        // A mapping of instruction address to entry/exit vertex indices
        let mut instruction_indices: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

        // A mapping of block address to entry/exit vertex indices;
        let mut block_indices: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

        let mut control_flow_graph = ControlFlowGraph::new();
        for result in &translation_results {
            let block_translation_result = result.1;
            let mut block_entry = 0;
            let mut block_exit = 0;
            let mut previous_exit = None;
            for &(address, ref instruction_graph) in block_translation_result.instructions.iter() {
                // Have we already inserted this instruction?
                let (entry, exit) =
                    if instruction_indices.get(&address).is_some() {
                        instruction_indices[&address]
                    }
                    else {
                        let (entry, exit) = control_flow_graph.insert(instruction_graph)?;
                        instruction_indices.insert(address, (entry, exit));
                        (entry, exit)
                    };
                // Not our first instruction through this block.
                if let Some(previous_exit) = previous_exit {
                    // Check to see if this edge already exists
                    if control_flow_graph.edge(previous_exit, entry).is_none() {
                        control_flow_graph.unconditional_edge(previous_exit, entry)?;
                    }
                }
                // Our first instruction through this block
                else {
                    block_entry = entry;
                }
                block_exit = exit;
                previous_exit = Some(exit);
            }
            block_indices.insert(*result.0, (block_entry, block_exit));
        }

        // Insert the edges
        for result in translation_results {
            let (_, block_exit) = block_indices[&result.0];
            for successor in result.1.successors().iter() {
                println!("{:x?}", successor.0);
                let (block_entry, _) = block_indices[&(successor.0 & !1)];
                // check for duplicate edges
                if control_flow_graph.edge(block_exit, block_entry).is_some() {
                    continue;
                }
                match successor.1 {
                    Some(ref condition) =>
                        control_flow_graph.conditional_edge(block_exit,
                                                            block_entry,
                                                            condition.clone())?,
                    None => control_flow_graph.unconditional_edge(block_exit,
                                                                  block_entry)?
                }
            }
        }

        // One block is the start of our control_flow_graph
        control_flow_graph.set_entry(block_indices[&(function_address & !1)].0)?;

        // merge for the user
        control_flow_graph.merge()?;

        Ok(Function::new(function_address, control_flow_graph))
    }
}

/// The ARMEB translator.
#[derive(Clone, Debug)]
pub struct Armeb;

impl Armeb {
    pub fn new() -> Armeb { Armeb }
}

impl Translator for Armeb {
    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
        translate_block(bytes, address, Endian::Big, false)
    }

    /// Translates a function
    fn translate_function(
        &self,
        memory: &TranslationMemory,
        function_address: u64)
    -> Result<Function> {

        // Addresses of blocks pending translation
        let mut translation_queue: VecDeque<u64> = VecDeque::new();

        // The results of block translations
        let mut translation_results: BTreeMap<u64, BlockTranslationResult> = BTreeMap::new();

        translation_queue.push_front(function_address);

        // translate all blocks in the function
        while !translation_queue.is_empty() {
            let block_address = translation_queue.pop_front().unwrap();

            if translation_results.contains_key(&block_address) {
                continue;
            }

            // For Thumb, we need to mask out the LSB
            let block_bytes = memory.get_bytes(block_address & !1, DEFAULT_TRANSLATION_BLOCK_BYTES);
            if block_bytes.len() == 0 {
                let mut control_flow_graph = ControlFlowGraph::new();
                let block_index = control_flow_graph.new_block()?.index();
                control_flow_graph.set_entry(block_index)?;
                control_flow_graph.set_exit(block_index)?;
                translation_results.insert(
                    block_address,
                    BlockTranslationResult::new(
                        vec![(block_address, control_flow_graph)],
                        block_address,
                        0,
                        Vec::new()
                    )
                );
                continue;
            }

            // translate this block
            let block_translation_result = self.translate_block(&block_bytes, block_address)?;

            // enqueue all successors
            for successor in block_translation_result.successors().iter() {
                if !translation_queue.contains(&successor.0) {
                    translation_queue.push_back(successor.0);
                }
            }

            translation_results.insert(block_address, block_translation_result);
        }

        // We now insert all of these blocks into a new control flow graph,
        // keeping track of their new entry and exit indices.

        // A mapping of instruction address to entry/exit vertex indices
        let mut instruction_indices: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

        // A mapping of block address to entry/exit vertex indices;
        let mut block_indices: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

        let mut control_flow_graph = ControlFlowGraph::new();
        for result in &translation_results {
            let block_translation_result = result.1;
            let mut block_entry = 0;
            let mut block_exit = 0;
            let mut previous_exit = None;
            for &(address, ref instruction_graph) in block_translation_result.instructions.iter() {
                // Have we already inserted this instruction?
                let (entry, exit) =
                    if instruction_indices.get(&address).is_some() {
                        instruction_indices[&address]
                    }
                    else {
                        let (entry, exit) = control_flow_graph.insert(instruction_graph)?;
                        instruction_indices.insert(address, (entry, exit));
                        (entry, exit)
                    };
                // Not our first instruction through this block.
                if let Some(previous_exit) = previous_exit {
                    // Check to see if this edge already exists
                    if control_flow_graph.edge(previous_exit, entry).is_none() {
                        control_flow_graph.unconditional_edge(previous_exit, entry)?;
                    }
                }
                // Our first instruction through this block
                else {
                    block_entry = entry;
                }
                block_exit = exit;
                previous_exit = Some(exit);
            }
            block_indices.insert(*result.0, (block_entry, block_exit));
        }

        // Insert the edges
        for result in translation_results {
            let (_, block_exit) = block_indices[&result.0];
            for successor in result.1.successors().iter() {
                let (block_entry, _) = block_indices[&successor.0];
                // check for duplicate edges
                if control_flow_graph.edge(block_exit, block_entry).is_some() {
                    continue;
                }
                match successor.1 {
                    Some(ref condition) =>
                        control_flow_graph.conditional_edge(block_exit,
                                                            block_entry,
                                                            condition.clone())?,
                    None => control_flow_graph.unconditional_edge(block_exit,
                                                                  block_entry)?
                }
            }
        }

        // One block is the start of our control_flow_graph
        control_flow_graph.set_entry(block_indices[&function_address].0)?;

        // merge for the user
        control_flow_graph.merge()?;

        Ok(Function::new(function_address, control_flow_graph))
    }
}

// Normalize address and extract the LSB as a flag indicating if the address
// means we are decoding a block in Thumb-mode.
fn normalize_address(address: u64) -> (u64, bool) {
    // (address & !1, address & 1 == 1)
    (address, address & 1 == 1)
}


fn translate_block(bytes: &[u8], address: u64, endian: Endian, thumb: bool)
    -> Result<BlockTranslationResult> {

    let (normalized_address, mut is_thumb) = normalize_address(address);
    is_thumb = is_thumb || thumb;

    println!("is_thumb: {}", is_thumb);

    let mode = match (endian, is_thumb) {
        (Endian::Big, true) => capstone::CS_MODE_BIG_ENDIAN | capstone::CS_MODE_THUMB,
        (Endian::Big, false) => capstone::CS_MODE_BIG_ENDIAN,
        (Endian::Little, true) => capstone::CS_MODE_LITTLE_ENDIAN | capstone::CS_MODE_THUMB,
        (Endian::Little, false) => capstone::CS_MODE_LITTLE_ENDIAN,
    };

    let cs = if let Ok(cs) = capstone::Capstone::new(capstone::cs_arch::CS_ARCH_ARM, mode) {
        cs
    } else {
        return Err("Capstone Error".into())
    };

    cs.option(capstone::cs_opt_type::CS_OPT_DETAIL, capstone::cs_opt_value::CS_OPT_ON).unwrap();

    let mut st = semantics::ArmState::new(is_thumb);

    // A vec which holds each lifted instruction in this block.
    let mut block_graphs: Vec<(u64, ControlFlowGraph)> = Vec::new();

    // the length of this block in bytes.
    let mut length: usize = 0;

    // The successors which exit this block.
    let mut successors = Vec::new();

    // Offset in bytes to the next instruction from the address given at entry.
    let mut offset: usize = 0;

    loop {
        // if we read in the maximum number of bytes possible (meaning there are
        // likely more bytes), and we don't have enough bytes to handle a delay
        // slot, return. We always want to have enough bytes to handle a delay
        // slot.
        if offset >= bytes.len() {
            successors.push((address + offset as u64, None));
            break;
        }
        let disassembly_range = (offset)..bytes.len();
        let disassembly_bytes = bytes.get(disassembly_range).unwrap();

        println!("{:x?}", bytes);
        println!("{:x?}", disassembly_bytes);

        let instructions = match cs.disasm(disassembly_bytes, normalized_address + offset as u64, 1) {
            Ok(instructions) => instructions,
            Err(e) => bail!("Capstone Error: {}", e.code() as u32)
        };

        if instructions.count() == 0 {
            return Err("Capstone failed to disassemble any instruction".into());
        }

        let instruction = instructions.get(0).unwrap();

        if let capstone::InstrIdArch::ARM(instruction_id) = instruction.id {
            let mut instruction_graph = ControlFlowGraph::new();

            match instruction_id {
                arm_insn::ARM_INS_ADC  => st.adc(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_ADD  => st.add(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_ADR  => st.adr(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_AND  => st.and(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_ASR  => st.asr(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BFC  => st.bfc(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BFI  => st.bfi(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BIC  => st.bic(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BKPT => st.bkpt(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_B    => st.b(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BX   => st.bx(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BL   => st.bl(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_BLX  => st.blx(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_CLZ  => st.clz(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_MOV  => st.mov(&mut instruction_graph, &instruction),
                arm_insn::ARM_INS_SUB  => st.sub(&mut instruction_graph, &instruction),
                _ => return Err(format!("Unhandled instruction {} at 0x{:x} ({:x?})",
                    instruction.mnemonic,
                    instruction.address,
                    disassembly_bytes
                ).into())
            }?;

            instruction_graph.set_address(Some(instruction.address));
            block_graphs.push((instruction.address, instruction_graph));
            length += instruction.size as usize;

            // TODO: Handle conditional branching
            match instruction_id {
                // capstone::arm_insn::ARM_INS_BL |
                capstone::arm_insn::ARM_INS_B => {
                    let detail = semantics::details(&instruction)?;
                    if detail.operands[0].type_ == arm_op_type::ARM_OP_IMM {
                        if let Some(cond) = semantics::cc_to_expr(&instruction)? {
                            successors.push((detail.operands[0].imm() as u64,
                                            Some(cond.clone())));
                            successors.push((detail.operands[0].imm() as u64,
                                            Some(Expression::cmpeq(cond, expr_const(0, 1))?)))
                        } else {
                            successors.push((detail.operands[0].imm() as u64,
                                            None));
                        }
                    };
                    break;
                },
                /*
                capstone::arm_insn::ARM_INS_BLX => {
                    let detail = semantics::details(&instruction)?;
                    if detail.operands[0].type_ == arm_op_type::ARM_OP_IMM {
                        let thumb_mod = if st.is_thumb() { 0 } else { 1 };
                        successors.push((detail.operands[0].imm() as u64 | thumb_mod, None));
                    }
                    // break;
                },
                */
                capstone::arm_insn::ARM_INS_BX => {
                    let detail = semantics::details(&instruction)?;
                    if detail.operands[0].type_ == arm_op_type::ARM_OP_IMM {
                        let thumb_mod = if st.is_thumb() { 0 } else { 1 };
                        successors.push((detail.operands[0].imm() as u64 | thumb_mod, None));
                    };
                    break;
                },
                capstone::arm_insn::ARM_INS_CBNZ => {
                    let detail = semantics::details(&instruction)?;
                    if detail.operands[1].type_ == arm_op_type::ARM_OP_IMM {
                        let register = st.get_register_expression(&instruction, 0)?;
                        let condition = Expression::cmpneq(register.clone(),
                                                           expr_const(0, register.bits()))?;

                        successors.push((
                            detail.operands[1].imm() as u64,
                            Some(condition.clone())
                        ));
                        successors.push((
                            st.immediate_successor(&instruction),
                            Some(Expression::cmpeq(condition, expr_const(0, 1))?)
                        ));
                    };
                    break; 
                },
                capstone::arm_insn::ARM_INS_CBZ => {
                    let detail = semantics::details(&instruction)?;
                        if detail.operands[1].type_ == arm_op_type::ARM_OP_IMM {
                        let register = st.get_register_expression(&instruction, 0)?;
                        let condition = Expression::cmpeq(register.clone(),
                                                          expr_const(0, register.bits()))?;

                        successors.push((
                            detail.operands[1].imm() as u64,
                            Some(condition.clone())
                        ));
                        successors.push((
                            st.immediate_successor(&instruction),
                            Some(Expression::cmpeq(condition, expr_const(0, 1))?)
                        ));
                    };
                    break; 
                },
                _ => (),
            }
        } else {
            bail!("Not an ARM instruction")
        }

        offset += instruction.size as usize;
    }

    Ok(BlockTranslationResult::new(block_graphs, normalized_address, length, successors))
}

