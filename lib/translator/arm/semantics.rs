use falcon_capstone::capstone;
use falcon_capstone::capstone::cs_arm_op;
use falcon_capstone::capstone_sys::{arm_op_type, arm_reg};
use error::*;
use il::*;
use il::Expression as Expr;


/// Struct for dealing with x86 registers
pub struct ArmRegister {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: arm_reg,
    /// The size of this register in bits
    bits: usize,
}


impl ArmRegister {
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn scalar(&self) -> Scalar {
        scalar(self.name, self.bits)
    }

    pub fn expression(&self) -> Expression {
        expr_scalar(self.name, self.bits)
    }
}



const ARMREGISTERS : &'static [ArmRegister] = &[
    ArmRegister { name: "r0", capstone_reg: arm_reg::ARM_REG_R0, bits: 32},
    ArmRegister { name: "r1", capstone_reg: arm_reg::ARM_REG_R1, bits: 32},
    ArmRegister { name: "r2", capstone_reg: arm_reg::ARM_REG_R2, bits: 32},
    ArmRegister { name: "r3", capstone_reg: arm_reg::ARM_REG_R3, bits: 32},
    ArmRegister { name: "r4", capstone_reg: arm_reg::ARM_REG_R4, bits: 32},
    ArmRegister { name: "r5", capstone_reg: arm_reg::ARM_REG_R5, bits: 32},
    ArmRegister { name: "r6", capstone_reg: arm_reg::ARM_REG_R6, bits: 32},
    ArmRegister { name: "r7", capstone_reg: arm_reg::ARM_REG_R7, bits: 32},
    ArmRegister { name: "r8", capstone_reg: arm_reg::ARM_REG_R8, bits: 32},
    ArmRegister { name: "r9", capstone_reg: arm_reg::ARM_REG_R9, bits: 32},
    ArmRegister { name: "r10", capstone_reg: arm_reg::ARM_REG_R10, bits: 32},
    ArmRegister { name: "r11", capstone_reg: arm_reg::ARM_REG_R11, bits: 32},
    ArmRegister { name: "r12", capstone_reg: arm_reg::ARM_REG_R12, bits: 32},
    ArmRegister { name: "lr", capstone_reg: arm_reg::ARM_REG_LR, bits: 32},
    ArmRegister { name: "pc", capstone_reg: arm_reg::ARM_REG_PC, bits: 32},
    ArmRegister { name: "sp", capstone_reg: arm_reg::ARM_REG_SP, bits: 32}
];


/// Takes a capstone register enum and returns an `X86Register`
pub fn get_register(capstone_id: arm_reg) -> Result<&'static ArmRegister> {
    for register in ARMREGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(&register);
        }
    }
    Err("Could not find register".into())
}

/// Get an operand of many different types.
pub fn get_operand(operand: &cs_arm_op) -> Result<Expression> {
    Ok(match operand.type_ {
        arm_op_type::ARM_OP_REG => get_register(operand.reg())?.expression(),
        arm_op_type::ARM_OP_IMM => expr_const(operand.imm() as u64, 32),
        arm_op_type::ARM_OP_MEM => {
            let expr = get_register(operand.mem().base.into())?.expression();
            let index_reg: arm_reg = operand.mem().index.into();
            let expr = if index_reg != arm_reg::ARM_REG_INVALID {
                if operand.mem().scale == 1 {
                    Expr::add(expr, get_register(index_reg)?.expression())?
                }
                else {
                    Expr::sub(expr, get_register(index_reg)?.expression())?
                }
            }
            else {
                expr
            };
            if operand.mem().disp > 0 {
                Expr::add(expr, expr_const(operand.mem().disp as u64, 32))?
            }
            else {
                expr
            }
        },
        arm_op_type::ARM_OP_FP => bail!("ARM_OP_FP not supported"),
        arm_op_type::ARM_OP_CIMM => bail!("ARM_OP_CIMM not supported"),
        arm_op_type::ARM_OP_PIMM => bail!("ARM_OP_PIMM not supported"),
        arm_op_type::ARM_OP_SETEND => bail!("ARM_OP_SETEND not supported"),
        arm_op_type::ARM_OP_SYSREG => bail!("ARM_OP_SYSREG not supported"),
        arm_op_type::ARM_OP_INVALID => bail!("got operand ARM_OP_INVALID")
    })
}

/// Returns the details section of an x86 capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_arm> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::ARM(x) => Ok(x),
        _ => Err("Could not get instruction details".into())
    }
}


/// Convenience function set set the zf based on result
pub fn set_z(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::cmpeq(result.clone(), expr_const(0, result.bits()))?;
    block.assign(scalar("Z", 1), expr);
    Ok(())
}


/// Convenience function to set the sf based on result
pub fn set_n(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::shr(result.clone(), expr_const((result.bits() - 1) as u64, result.bits()))?;
    let expr = Expr::trun(1, expr)?;
    block.assign(scalar("N", 1), expr);
    Ok(())
}


/// Convenience function to set the of based on result and both operands
pub fn set_v(block: &mut Block, result: Expression, lhs: Expression, rhs: Expression) -> Result<()> {
    let expr = Expr::cmpeq(
        Expr::trun(1, Expr::shr(
            lhs.clone(),
            expr_const(lhs.bits() as u64 - 1, lhs.bits()))?
        )?,
        Expr::trun(1, Expr::shr(
            rhs.clone(),
            expr_const(rhs.bits() as u64 - 1, rhs.bits()))?
        )?
    )?;
    let expr = Expr::and(
        expr.clone(),
        Expr::cmpeq(
            Expr::trun(1, Expr::shr(
                result.clone(),
                expr_const(result.bits() as u64 - 1, result.bits()))?
            )?,
            expr
        )?
    )?;
    block.assign(scalar("V", 1), expr);
    Ok(())
}


/// Convenience function to set the cf based on result and lhs operand
pub fn set_c(block: &mut Block, result: Expression, lhs: Expression) -> Result<()> {
    let expr = Expr::cmpltu(lhs.clone().into(), result.clone().into())?;
    block.assign(scalar("CF", 1), expr);
    Ok(())
}


pub fn adc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_REG);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let lhs = get_register(detail.operands[1].reg())?.expression();
        let rhs = get_operand(&detail.operands[2])?;

        let expr = Expr::add(
            Expr::add(lhs.clone(), rhs.clone())?,
            Expr::zext(lhs.bits(), expr_scalar("C", 1))?
        )?;

        block.assign(dst.clone(), expr);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            set_c(&mut block, dst.clone().into(), lhs.clone())?;
            set_v(&mut block, dst.into(), lhs, rhs)?;
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn add(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_REG);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let lhs = get_register(detail.operands[1].reg())?.expression();
        let rhs = get_operand(&detail.operands[2])?;

        block.assign(dst.clone(), Expr::add(lhs.clone(), rhs.clone())?);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            set_c(&mut block, dst.clone().into(), lhs.clone())?;
            set_v(&mut block, dst.into(), lhs, rhs)?;
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn adr(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_IMM);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let imm = get_operand(&detail.operands[1])?;

        let pc = expr_const(instruction.address + 8, 32);
        let expr = if detail.operands[2].subtracted {
            Expr::sub(pc, imm)?
        }
        else {
            Expr::add(pc, imm)?
        };

        block.assign(dst, expr);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn and(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_REG);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let lhs = get_register(detail.operands[1].reg())?.expression();
        let rhs = get_operand(&detail.operands[2])?;

        block.assign(dst.clone(), Expr::and(lhs.clone(), rhs.clone())?);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            set_c(&mut block, dst.clone().into(), lhs.clone())?;
            set_v(&mut block, dst.into(), lhs, rhs)?;
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn asr(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_REG);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let lhs = get_register(detail.operands[1].reg())?.expression();
        let rhs = get_operand(&detail.operands[2])?;

        // do the shift right
        let expr = Expr::shr(lhs.clone(), rhs.clone())?;

        // Get mask bit
        let mask = Expr::and(
            expr_const(1, 32),
            Expr::shr(
                lhs.clone(),
                Expr::sub(rhs.clone(), expr_const(1, rhs.bits()))?
            )?
        )?;

        // Create the mask
        let mask = Expr::sub(
            expr_const(0, 32),
            Expr::shl(mask, rhs.clone())?
        )?;

        // Shift the mask into place
        let mask = Expr::shl(mask, Expr::sub(expr_const(32, 32), rhs.clone())?)?;

        block.assign(dst.clone(), Expr::or(expr.clone(), mask.clone())?);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            block.assign(scalar("C", 1),
                Expr::shr(
                    lhs.clone(),
                    Expr::sub(rhs.clone(), expr_const(1, 32))?
                )?
            );
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn b(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_IMM);
        let imm = get_operand(&detail.operands[0])?;

        block.branch(Expr::add(
            expr_const(instruction.address as u64 + 8, 32),
            imm
        )?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bfc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        let dst= get_register(detail.operands[0].reg())?.scalar();
        let lsb = get_operand(&detail.operands[1])?;
        let width = get_operand(&detail.operands[2])?;

        let mask = Expr::sub(
            expr_const(0, 32),
            Expr::shl(expr_const(1, 32), width.clone())?
        )?;

        let mask = Expr::shl(mask, lsb.clone())?;

        // invert the mask
        let mask = Expr::xor(expr_const(0xffffffff, 32), mask)?;

        block.assign(dst.clone(), Expr::and(dst.into(), mask)?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bfi(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        let dst= get_register(detail.operands[0].reg())?.scalar();
        let lsb = get_operand(&detail.operands[1])?;
        let width = get_operand(&detail.operands[2])?;

        let mask = Expr::sub(
            expr_const(0, 32),
            Expr::shl(expr_const(1, 32), width.clone())?
        )?;

        let mask = Expr::shl(mask, lsb.clone())?;

        block.assign(dst.clone(), Expr::and(dst.into(), mask)?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bic(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        assert!(detail.operands[0].type_ == arm_op_type::ARM_OP_REG);
        assert!(detail.operands[1].type_ == arm_op_type::ARM_OP_REG);
        let dst = get_register(detail.operands[0].reg())?.scalar();
        let lhs = get_register(detail.operands[1].reg())?.expression();
        let rhs = get_operand(&detail.operands[2])?;

        let rhs = Expr::xor(expr_const(0xffffffff, 32), rhs)?;

        block.assign(dst.clone(), Expr::and(lhs.clone(), rhs.clone())?);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            // TODO: C flag should be handled here
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bkpt(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let imm = get_operand(&detail.operands[0])?;

        block.raise(Expr::cmpeq(expr_scalar("breakpoint", imm.bits()), imm)?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bl(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_operand(&detail.operands[0])?;

        block.assign(
            scalar("lr", 32),
            expr_const(instruction.address as u64 + 4, 32)
        );

        block.branch(dst);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn blx(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_operand(&detail.operands[0])?;

        block.assign(
            scalar("lr", 32),
            expr_const(instruction.address as u64 + 4, 32)
        );

        block.branch(Expr::add(dst, expr_const(1, 32))?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bx(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_operand(&detail.operands[0])?;

        block.branch(Expr::add(dst, expr_const(1, 32))?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}