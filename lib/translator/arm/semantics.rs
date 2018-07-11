use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::{arm_cc, arm_insn, arm_op_type, arm_reg, arm_shifter};
use error::*;
use il::*;
use il::Expression as Expr;


#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ArmState {
    Arm,
    Thumb { itstate: arm_cc },
}


impl ArmState {
    pub fn new(is_thumb: bool) -> ArmState {
        if is_thumb {
            ArmState::Thumb { itstate: arm_cc::ARM_CC_AL }
        } else {
            ArmState::Arm
        }
    }

    pub fn is_thumb(&self) -> bool {
        *self != ArmState::Arm
    }

    pub fn immediate_successor(&self, instruction: &capstone::Instr) -> u64 {
        instruction.address + instruction.size as u64
    }
 
    /// Get the expression for a register operand of this instruction
    pub fn get_register_expression(&self, instruction: &capstone::Instr, index: usize)
        -> Result<Expression> {

        let detail = details(instruction)?;

        assert!(detail.operands[index].type_ == arm_op_type::ARM_OP_REG);
        let capstone_id = detail.operands[index].reg();

        if capstone_id == arm_reg::ARM_REG_PC {
            if self.is_thumb() {
                use self::arm_insn::*;
                Ok(match instruction_id(instruction)? {
                    ARM_INS_B | ARM_INS_BL | ARM_INS_CBZ | ARM_INS_CBNZ =>
                        expr_const(instruction.address + 4, 32),
                    _ => expr_const((instruction.address + 4) & !2, 32)
                })
            } else {
                Ok(expr_const(instruction.address + 8, 32))
            }
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
    pub fn get_register_scalar(&self, instruction: &capstone::Instr, index: usize)
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
    fn register_expression(&self, instruction: &capstone::Instr, id: arm_reg)
        -> Result<Expression> {
        
        if id == arm_reg::ARM_REG_PC {
            if self.is_thumb() {
                use self::arm_insn::*;
                Ok(match instruction_id(instruction)? {
                    ARM_INS_B | ARM_INS_BL | ARM_INS_CBZ | ARM_INS_CBNZ =>
                        expr_const(instruction.address + 4, 32),
                    _ => expr_const((instruction.address + 4) & !2, 32)
                })
            } else {
                Ok(expr_const(instruction.address + 8, 32))
            }
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
    pub fn get_operand(&self, instruction: &capstone::Instr, index: usize)
        -> Result<Expression> {
        
        let detail = details(instruction)?;
        let operand = detail.operands[index];

        Ok(match operand.type_ {
            arm_op_type::ARM_OP_REG => self.get_register_expression(instruction, index)?,
            arm_op_type::ARM_OP_IMM => expr_const(operand.imm() as u64, 32),
            arm_op_type::ARM_OP_MEM => {
                let expr = self.register_expression(instruction,
                                                    operand.mem().base.into())?;
                let index_reg: arm_reg = operand.mem().index.into();
                let expr = if index_reg != arm_reg::ARM_REG_INVALID {
                    if operand.mem().scale == 1 {
                        Expr::add(expr, self.register_expression(instruction, index_reg)?)?
                    }
                    else {
                        Expr::sub(expr, self.register_expression(instruction, index_reg)?)?
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

    pub fn get_shifted(&self, instruction: &capstone::Instr, index: usize)
        -> Result<(Expression, Expression)> {
        let detail = details(instruction)?;
        let operand = detail.operands[index];
        let value = self.get_operand(instruction, index)?;

        match operand.shift.type_ {
            arm_shifter::ARM_SFT_ASR => {
                let bits = value.bits();
                let ext = Expr::sext(operand.shift.value as usize + bits, value)?;

                let res = Expr::trun(bits, Expr::shr(ext.clone(), expr_const(operand.shift.value as u64, bits))?)?;
                let carry_out = Expr::trun(1, Expr::shr(ext, expr_const(operand.shift.value as u64 - 1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_ASR_REG => {
                let bits = value.bits();
                let reg = Expr::modu(Expr::or(self.register_expression(instruction, operand.shift.value.into())?,
                                     expr_const(0xff, bits))?,
                                     expr_const(32, bits))?;
                let ext = Expr::sext(bits * 2, value)?; // XXX: Is this okay?

                let res = Expr::trun(bits, Expr::shr(ext.clone(), reg.clone())?)?;
                let carry_out = Expr::trun(1, Expr::shr(ext, Expr::sub(reg, expr_const(1, bits))?)?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_LSL => {
                let bits = value.bits();

                let res = Expr::trun(bits, Expr::shl(value.clone(), expr_const(operand.shift.value as u64, bits))?)?;
                let carry_out = Expr::trun(1, Expr::shr(value, expr_const(bits as u64 - operand.shift.value as u64, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_LSL_REG => {
                let bits = value.bits();
                let reg = Expr::modu(Expr::or(self.register_expression(instruction, operand.shift.value.into())?,
                                     expr_const(0xff, bits))?,
                                     expr_const(32, bits))?;

                let res = Expr::trun(bits, Expr::shl(value.clone(), reg.clone())?)?;
                let carry_out = Expr::trun(1, Expr::shr(value, Expr::sub(expr_const(bits as u64, bits), reg)?)?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_LSR => {
                let bits = value.bits();

                let res = Expr::trun(bits, Expr::shr(value.clone(), expr_const(operand.shift.value as u64, bits))?)?;
                let carry_out = Expr::trun(1, Expr::shr(value, expr_const(operand.shift.value as u64 - 1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_LSR_REG => {
                let bits = value.bits();
                let reg = Expr::modu(Expr::or(self.register_expression(instruction, operand.shift.value.into())?,
                                     expr_const(0xff, bits))?,
                                     expr_const(32, bits))?;

                let res = Expr::trun(bits, Expr::shr(value.clone(), reg.clone())?)?;
                let carry_out = Expr::trun(1, Expr::shr(value, Expr::sub(reg, expr_const(1, bits))?)?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_ROR => {
                let bits = value.bits();

                let m = operand.shift.value as u64 % value.bits() as u64;

                let rs = expr_const(m, bits);
                let ls = expr_const(bits as u64 - m, bits);

                let res = Expr::or(Expr::shr(value.clone(), rs)?, Expr::shl(value, ls)?)?;
                let carry_out = Expr::trun(1, Expr::shr(res.clone(), expr_const(bits as u64 - 1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_ROR_REG => {
                let bits = value.bits();
                let reg = Expr::modu(Expr::or(self.register_expression(instruction, operand.shift.value.into())?,
                                     expr_const(0xff, bits))?,
                                     expr_const(32, bits))?;

                let m = Expr::modu(reg, expr_const(bits as u64, bits))?;

                let rs = m.clone();
                let ls = Expr::sub(expr_const(bits as u64, bits), m)?;

                let res = Expr::or(Expr::shr(value.clone(), rs)?, Expr::shl(value, ls)?)?;
                let carry_out = Expr::trun(1, Expr::shr(res.clone(), expr_const(bits as u64 - 1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_RRX => {
                let bits = value.bits();
                let carry_out = Expr::trun(1, value.clone())?;
                let c_mask = Expr::shl(Expr::zext(bits, expr_scalar("c", 1))?, expr_const(bits as u64 - 1, bits))?;

                let res = Expr::or(c_mask, Expr::shr(value, expr_const(1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_RRX_REG => {
                let bits = value.bits();
                let carry_out = Expr::trun(1, value.clone())?;
                let c_mask = Expr::shl(Expr::zext(bits, expr_scalar("c", 1))?, expr_const(bits as u64 - 1, bits))?;

                let res = Expr::or(c_mask, Expr::shr(value, expr_const(1, bits))?)?;

                Ok((res, carry_out))
            },
            arm_shifter::ARM_SFT_INVALID => Err("Shift type invalid".into()),
        }
    }

    pub fn adc(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = details(instruction)?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let (rhs, _) = self.get_shifted(instruction, 2)?;

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

        and_cc(control_flow_graph, instruction)
    }

    pub fn add(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = try!(details(instruction));

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let (rhs, _) = self.get_shifted(instruction, 2)?;

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

        and_cc(control_flow_graph, instruction)
    }


    pub fn adr(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = try!(details(instruction));

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let imm = self.get_operand(instruction, 1)?;

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

        and_cc(control_flow_graph, instruction)
    }


    pub fn and(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = try!(details(instruction));

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let (rhs, carry) = self.get_shifted(instruction, 2)?;

            block.assign(dst.clone(), Expr::and(lhs.clone(), rhs.clone())?);

            if detail.update_flags {
                set_n(&mut block, dst.clone().into())?;
                set_z(&mut block, dst.clone().into())?;
                block.assign(scalar("c", 1), carry);
                set_v(&mut block, dst.into(), lhs, rhs)?;
            }
            
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        and_cc(control_flow_graph, instruction)
    }


    pub fn asr(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = try!(details(instruction));
            
        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let rhs = self.get_operand(instruction, 2)?;

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

        and_cc(control_flow_graph, instruction)
    }


    pub fn bfc(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lsb = self.get_operand(instruction, 2)?;
            let width = self.get_operand(instruction, 2)?;

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

        and_cc(control_flow_graph, instruction)
    }


    pub fn bfi(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lsb = self.get_operand(instruction, 2)?;
            let width = self.get_operand(instruction, 2)?;

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

        and_cc(control_flow_graph, instruction)
    }


    pub fn bic(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = details(instruction)?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let (rhs, carry) = self.get_shifted(instruction, 2)?;

            let rhs = Expr::xor(expr_const(0xffffffff, 32), rhs)?;

            block.assign(dst.clone(), Expr::and(lhs.clone(), rhs.clone())?);

            if detail.update_flags {
                set_n(&mut block, dst.clone().into())?;
                set_z(&mut block, dst.clone().into())?;
                block.assign(scalar("c", 1), carry);
            }
            
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        and_cc(control_flow_graph, instruction)
    }


    pub fn bkpt(&mut self,
                control_flow_graph: &mut ControlFlowGraph,
                instruction: &capstone::Instr)
        -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            // get operands
            let imm = self.get_operand(instruction, 0)?;

            block.raise(Expr::cmpeq(expr_scalar("breakpoint", imm.bits()), imm)?);
            
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }

    pub fn b(&mut self,
              control_flow_graph: &mut ControlFlowGraph,
              instruction: &capstone::Instr)
        -> Result<()> {
        
        let detail = details(instruction)?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            if detail.operands[0].type_ != arm_op_type::ARM_OP_IMM {
                let dst = self.get_operand(&instruction, 0)?;

                // The correct semantics for this rely on clearing low bits
                // depending on the processor state; however, if we do this,
                // at a later time we will be unable to determine how to
                // disassemble the instructions at dst.
                block.branch(dst);
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        and_cc(control_flow_graph, instruction)
    }

    pub fn bl(&mut self,
              control_flow_graph: &mut ControlFlowGraph,
              instruction: &capstone::Instr)
        -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_operand(instruction, 0)?;

            block.assign(
                scalar("lr", 32),
                expr_const(self.immediate_successor(&instruction), 32)
            );

            block.branch(dst);
            
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn blx(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;
            let mut dst = self.get_operand(&instruction, 0)?;

            /* XXX: Capstone handles calculation of correct IMM address
            let detail = details(instruction)?;
            if detail.operands[0].type_ == arm_op_type::ARM_OP_IMM {
                if self.is_thumb() {
                    dst = Expr::add(expr_const(instruction.address, 32), dst)?;
                } else {
                    // TODO: Align PC prior to add
                    dst = Expr::add(expr_const(instruction.address, 32), dst)?;
                }
            }
            */

            if self.is_thumb() {
                block.assign(
                    scalar("lr", 32),
                    Expr::or(expr_const(self.immediate_successor(&instruction), 32), expr_const(1, 32))?
                );
                block.branch(dst);
            } else {
                block.assign(
                    scalar("lr", 32),
                    expr_const(self.immediate_successor(&instruction), 32)
                );
                block.branch(Expr::or(dst, expr_const(1, 32))?);
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn bx(&mut self,
              control_flow_graph: &mut ControlFlowGraph,
              instruction: &capstone::Instr)
        -> Result<()> {
        
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.get_operand(&instruction, 0)?;

            // The correct semantics for this rely on clearing low bits
            // depending on the processor state; however, if we do this,
            // at a later time we will be unable to determine how to
            // disassemble the instructions at dst.
            block.branch(dst);
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        and_cc(control_flow_graph, instruction)
    }


    pub fn clz(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let rd = self.get_register_scalar(instruction, 0)?;
        let rm = self.get_register_expression(instruction, 1)?;

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


    pub fn sub(&mut self,
               control_flow_graph: &mut ControlFlowGraph,
               instruction: &capstone::Instr)
        -> Result<()> {

        let detail = try!(details(instruction));

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register_scalar(instruction, 0)?;
            let lhs = self.get_register_expression(instruction, 1)?;
            let (rhs, _) = self.get_shifted(instruction, 2)?;

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
}


pub struct ArmRegister {
    name: &'static str,
    capstone_reg: arm_reg,
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


const ARMREGISTERS: &'static [ArmRegister] = &[
    ArmRegister { name: "r0", capstone_reg: arm_reg::ARM_REG_R0, bits: 32 },
    ArmRegister { name: "r1", capstone_reg: arm_reg::ARM_REG_R1, bits: 32 },
    ArmRegister { name: "r2", capstone_reg: arm_reg::ARM_REG_R2, bits: 32 },
    ArmRegister { name: "r3", capstone_reg: arm_reg::ARM_REG_R3, bits: 32 },
    ArmRegister { name: "r4", capstone_reg: arm_reg::ARM_REG_R4, bits: 32 },
    ArmRegister { name: "r5", capstone_reg: arm_reg::ARM_REG_R5, bits: 32 },
    ArmRegister { name: "r6", capstone_reg: arm_reg::ARM_REG_R6, bits: 32 },
    ArmRegister { name: "r7", capstone_reg: arm_reg::ARM_REG_R7, bits: 32 },
    ArmRegister { name: "r8", capstone_reg: arm_reg::ARM_REG_R8, bits: 32 },
    ArmRegister { name: "r9", capstone_reg: arm_reg::ARM_REG_R9, bits: 32 },
    ArmRegister { name: "r10", capstone_reg: arm_reg::ARM_REG_R10, bits: 32 },
    ArmRegister { name: "r11", capstone_reg: arm_reg::ARM_REG_R11, bits: 32 },
    ArmRegister { name: "r12", capstone_reg: arm_reg::ARM_REG_R12, bits: 32 },
    ArmRegister { name: "lr", capstone_reg: arm_reg::ARM_REG_LR, bits: 32 },
    ArmRegister { name: "pc", capstone_reg: arm_reg::ARM_REG_PC, bits: 32 },
    ArmRegister { name: "sp", capstone_reg: arm_reg::ARM_REG_SP, bits: 32 },
];


/// Returns the details section of Arm capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_arm> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::ARM(x) => Ok(x),
        _ => Err("Could not get instruction details".into())
    }
}

pub fn instruction_id(instruction: &capstone::Instr) -> Result<arm_insn> {
    if let capstone::InstrIdArch::ARM(insn) = instruction.id {
        Ok(insn)
    } else {
        Err("Could not get instruction id".into())
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

pub fn cc(control_flow_graph: &mut ControlFlowGraph, condition: Expression) -> Result<()> {
    let head_index = control_flow_graph.new_block()?.index();
    let true_index = control_flow_graph.entry().unwrap();
    let terminating_index = control_flow_graph.exit().unwrap();

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        condition.clone(),
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpeq(condition, expr_const(0, 1))?
    )?;

    // true index will already point to the exit
    control_flow_graph.set_entry(head_index)?;

    Ok(())
}

pub fn cc_eq() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("z", 1), expr_const(1, 1))
}

pub fn cc_ne() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("z", 1), expr_const(0, 1))
}

pub fn cc_cs() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("c", 1), expr_const(1, 1))
}

pub fn cc_cc() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("c", 1), expr_const(0, 1))
}

pub fn cc_mi() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("n", 1), expr_const(1, 1))
}

pub fn cc_pl() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("n", 1), expr_const(0, 1))
}

pub fn cc_vs() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("v", 1), expr_const(1, 1))
}

pub fn cc_vc() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("v", 1), expr_const(0, 1))
}

pub fn cc_hi() -> Result<Expr> {
   Expr::and(
       Expr::cmpeq(expr_scalar("c", 1), expr_const(1, 1))?,
       Expr::cmpeq(expr_scalar("z", 1), expr_const(0, 1))?)
}

pub fn cc_ls() -> Result<Expr> {
   Expr::or(
       Expr::cmpeq(expr_scalar("c", 1), expr_const(0, 1))?,
       Expr::cmpeq(expr_scalar("z", 1), expr_const(1, 1))?)
}

pub fn cc_ge() -> Result<Expr> {
    Expr::cmpeq(expr_scalar("n", 1), expr_scalar("v", 1))
}

pub fn cc_lt() -> Result<Expr> {
    Expr::cmpneq(expr_scalar("n", 1), expr_scalar("v", 1))
}

pub fn cc_gt() -> Result<Expr> {
   Expr::and(
       Expr::cmpeq(expr_scalar("z", 1), expr_const(0, 1))?,
       Expr::cmpeq(expr_scalar("n", 1), expr_scalar("v", 1))?)
}

pub fn cc_le() -> Result<Expr> {
   Expr::or(
       Expr::cmpeq(expr_scalar("z", 1), expr_const(1, 1))?,
       Expr::cmpneq(expr_scalar("n", 1), expr_scalar("v", 1))?)
}

pub fn cc_to_expr(instruction: &capstone::Instr) -> Result<Option<Expr>> {
    let detail = details(&instruction)?;

    match detail.cc {
        arm_cc::ARM_CC_EQ => cc_eq().map(|cc| Some(cc)),
        arm_cc::ARM_CC_NE => cc_ne().map(|cc| Some(cc)),
        arm_cc::ARM_CC_HS => cc_cs().map(|cc| Some(cc)),
        arm_cc::ARM_CC_LO => cc_cc().map(|cc| Some(cc)),
        arm_cc::ARM_CC_MI => cc_mi().map(|cc| Some(cc)),
        arm_cc::ARM_CC_PL => cc_pl().map(|cc| Some(cc)),
        arm_cc::ARM_CC_VS => cc_vs().map(|cc| Some(cc)),
        arm_cc::ARM_CC_VC => cc_vc().map(|cc| Some(cc)),
        arm_cc::ARM_CC_HI => cc_hi().map(|cc| Some(cc)),
        arm_cc::ARM_CC_LS => cc_ls().map(|cc| Some(cc)),
        arm_cc::ARM_CC_GE => cc_ge().map(|cc| Some(cc)),
        arm_cc::ARM_CC_LT => cc_lt().map(|cc| Some(cc)),
        arm_cc::ARM_CC_GT => cc_gt().map(|cc| Some(cc)),
        arm_cc::ARM_CC_LE => cc_le().map(|cc| Some(cc)),
        arm_cc::ARM_CC_AL => Ok(None),
        arm_cc::ARM_CC_INVALID => Err("Invalid condition code.".into()),
    }
}

pub fn and_cc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr)
    -> Result<()> {

    if let Some(cond) = cc_to_expr(instruction)? {
        cc(control_flow_graph, cond)
    } else {
        Ok(())
    }
}
