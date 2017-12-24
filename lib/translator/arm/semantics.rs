use falcon_capstone::capstone;
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


/// Get the expression for a register operand of this instruction
pub fn get_register_expression(instruction: &capstone::Instr, index: usize)
    -> Result<Expression> {

    let detail = details(instruction)?;
    
    assert!(detail.operands[index].type_ == arm_op_type::ARM_OP_REG);
    let capstone_id = detail.operands[index].reg();

    if capstone_id == arm_reg::ARM_REG_PC {
        Ok(expr_const(instruction.address + 8, 32))
    }
    else {
        for register in ARMREGISTERS.iter() {
            if register.capstone_reg == capstone_id {
                return Ok(register.expression());
            }
        }
        Err("Could not find register".into())
    }
}

/// Get the scalar for a register operand of this instruction
pub fn get_register_scalar(instruction: &capstone::Instr, index: usize)
    -> Result<Scalar> {

    let detail = details(instruction)?;
    assert!(detail.operands[index].type_ == arm_op_type::ARM_OP_REG);
    let capstone_id = detail.operands[index].reg();

    for register in ARMREGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(register.scalar());
        }
    }
    Err("Could not find register".into())
}

/// Get the expression for a register by arm_reg
fn register_expression(instruction: &capstone::Instr, id: arm_reg)
    -> Result<Expression> {
    
    if id == arm_reg::ARM_REG_PC {
        Ok(expr_const(instruction.address + 8, 32))
    }
    else {
        for register in ARMREGISTERS.iter() {
            if register.capstone_reg == id {
                return Ok(register.expression())
            }
        }
        Err("Could not find register".into())
    }
}

/// Get an operand of many different types.
pub fn get_operand(instruction: &capstone::Instr, index: usize)
    -> Result<Expression> {
    
    let detail = details(instruction)?;
    let operand = detail.operands[index];

    Ok(match operand.type_ {
        arm_op_type::ARM_OP_REG => get_register_expression(instruction, index)?,
        arm_op_type::ARM_OP_IMM => expr_const(operand.imm() as u64, 32),
        arm_op_type::ARM_OP_MEM => {
            let expr = register_expression(instruction,
                                           operand.mem().base.into())?;
            let index_reg: arm_reg = operand.mem().index.into();
            let expr = if index_reg != arm_reg::ARM_REG_INVALID {
                if operand.mem().scale == 1 {
                    Expr::add(expr, register_expression(instruction, index_reg)?)?
                }
                else {
                    Expr::sub(expr, register_expression(instruction, index_reg)?)?
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
    block.assign(scalar("z", 1), expr);
    Ok(())
}


/// Convenience function to set the sf based on result
pub fn set_n(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::shr(result.clone(), 
                         expr_const((result.bits() - 1) as u64, result.bits()))?;
    let expr = Expr::trun(1, expr)?;
    block.assign(scalar("n", 1), expr);
    Ok(())
}


/// Convenience function to set the of based on result and both operands
pub fn set_v(block: &mut Block, 
             result: Expression,
             lhs: Expression,
             rhs: Expression)
    -> Result<()> {

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
    block.assign(scalar("v", 1), expr);
    Ok(())
}


/// Convenience function to set the cf based on result and lhs operand
pub fn set_c(block: &mut Block, result: Expression, lhs: Expression) -> Result<()> {
    let expr = Expr::cmpltu(result, lhs)?;
    block.assign(scalar("c", 1), expr);
    Ok(())
}


pub fn adc(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

        let expr = Expr::add(
            Expr::add(lhs.clone(), rhs.clone())?,
            Expr::zext(lhs.bits(), expr_scalar("c", 1))?
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


pub fn add(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

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


pub fn adr(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let imm = get_operand(instruction, 1)?;

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


pub fn and(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

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


pub fn asr(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));
        
    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

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


pub fn bfc(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lsb = get_operand(instruction, 2)?;
        let width = get_operand(instruction, 2)?;

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


pub fn bfi(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lsb = get_operand(instruction, 2)?;
        let width = get_operand(instruction, 2)?;

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


pub fn bic(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

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


pub fn bkpt(control_flow_graph: &mut ControlFlowGraph,
            instruction: &capstone::Instr)
    -> Result<()> {

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let imm = get_operand(instruction, 0)?;

        block.raise(Expr::cmpeq(expr_scalar("breakpoint", imm.bits()), imm)?);
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


pub fn bl(control_flow_graph: &mut ControlFlowGraph,
          instruction: &capstone::Instr)
    -> Result<()> {

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_operand(instruction, 0)?;

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


pub fn blx(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_operand(instruction, 0)?;

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


pub fn clz(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let rd = get_register_scalar(instruction, 0)?;
    let rm = get_register_expression(instruction, 1)?;

    let temp = control_flow_graph.temp(rm.bits());

    let head_index = {
        let block = control_flow_graph.new_block()?;
        block.assign(temp.clone(), expr_const(32, temp.bits()));
        block.index()
    };

    let block_index = {
        let block = control_flow_graph.new_block()?;
        block.assign(temp.clone(),
                     Expr::add(temp.clone().into(),
                               expr_const(1, temp.bits()))?);
        block.index()
    };

    let tail_index = {
        let block = control_flow_graph.new_block()?;
        block.assign(rd, Expr::sub(expr_const(32, rm.bits()),
                                   temp.clone().into())?);
        block.index()
    };

    let condition = Expression::trun(1, Expression::or(
        Expression::and(
            Expression::shr(
                rm.clone(),
                Expression::sub(
                    temp.clone().into(),
                    expr_const(1, rm.bits())
                )?,
            )?,
            expr_const(1, rm.bits())
        )?,
        Expression::cmpeq(
            temp.clone().into(),
            expr_const(0, rm.bits())
        )?
    )?)?;

    control_flow_graph.conditional_edge(head_index, tail_index,
        condition.clone())?;
    control_flow_graph.conditional_edge(block_index, tail_index,
        condition.clone())?;
    control_flow_graph.conditional_edge(head_index, block_index,
        Expression::cmpeq(condition.clone(), expr_const(0, 1))?)?;
    control_flow_graph.conditional_edge(block_index, block_index,
        Expression::cmpeq(condition.clone(), expr_const(0, 1))?)?;
        
    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}


pub fn sub(control_flow_graph: &mut ControlFlowGraph,
           instruction: &capstone::Instr)
    -> Result<()> {

    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = get_register_scalar(instruction, 0)?;
        let lhs = get_register_expression(instruction, 1)?;
        let rhs = get_operand(instruction, 2)?;

        block.assign(dst.clone(), Expr::sub(lhs.clone(), rhs.clone())?);

        if detail.update_flags {
            set_n(&mut block, dst.clone().into())?;
            set_z(&mut block, dst.clone().into())?;
            block.assign(scalar("c", 1),
                         Expr::cmpltu(lhs.clone(), dst.clone().into())?);
            set_v(&mut block, dst.into(), lhs, rhs)?;
        }
        
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}