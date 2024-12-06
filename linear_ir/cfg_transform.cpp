// Copyright (c) 2021-2024, David H. Hovemeyer <david.hovemeyer@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

#include <cassert>
#include "cfg.h"
#include "cfg_transform.h"
#include <unordered_map>
#include <unordered_set>
#include "highlevel_defuse.h"
#include <tuple>
#include "highlevel_codegen.h"

ControlFlowGraphTransform::ControlFlowGraphTransform(std::shared_ptr<ControlFlowGraph> cfg)
  : m_cfg(cfg) {
}

ControlFlowGraphTransform::~ControlFlowGraphTransform() {
}

std::shared_ptr<ControlFlowGraph> ControlFlowGraphTransform::get_orig_cfg() {
  return m_cfg;
}

std::shared_ptr<ControlFlowGraph> ControlFlowGraphTransform::transform_cfg() {
  std::shared_ptr<ControlFlowGraph> result(new ControlFlowGraph());

  // map of basic blocks of original CFG to basic blocks in transformed CFG
  std::map<std::shared_ptr<InstructionSequence>, std::shared_ptr<InstructionSequence>> block_map;

  // iterate over all basic blocks, transforming each one
  for (auto i = m_cfg->bb_begin(); i != m_cfg->bb_end(); i++) {
    std::shared_ptr<InstructionSequence> orig = *i;

    // Transform the instructions
    std::shared_ptr<InstructionSequence> result_bb = transform_basic_block(orig);

    // Set basic block properties (code order, block label, etc.) of result
    // basic block to be the same as the original
    result_bb->set_kind(orig->get_kind());
    result_bb->set_code_order(orig->get_code_order());
    result_bb->set_block_label(orig->get_block_label());

    // Map original block to transformed block
    // (so that we can reconstruct edges)
    block_map[orig] = result_bb;

    // Have CFG formally adopt the basic block
    result->adopt_basic_block(result_bb);
  }

  // add edges to transformed CFG
  for (auto i = m_cfg->bb_begin(); i != m_cfg->bb_end(); i++) {
    std::shared_ptr<InstructionSequence> orig = *i;
    const ControlFlowGraph::EdgeList &outgoing_edges = m_cfg->get_outgoing_edges(orig);
    for (auto j = outgoing_edges.cbegin(); j != outgoing_edges.cend(); j++) {
      Edge *orig_edge = *j;

      std::shared_ptr<InstructionSequence> transformed_source = block_map[orig_edge->get_source()];
      std::shared_ptr<InstructionSequence> transformed_target = block_map[orig_edge->get_target()];

      result->create_edge(transformed_source, transformed_target, orig_edge->get_kind());
    }
  }

  return result;
}

LVN::LVN(std::shared_ptr<ControlFlowGraph> cfg)
    : ControlFlowGraphTransform(cfg) {
}

LVN::~LVN() {}

// helper function determines the value number (if already seen) or generates a new value number
// updates maps accordingly
int determine_value_num(Operand oper, std::unordered_map<int, int>& vreg_to_value, std::unordered_map<int, std::unordered_set<int>>& value_to_vreg, 
  std::unordered_map<int, int>& const_to_value, std::unordered_map<int, int>& value_to_const, int& next_val) {
  int res;
  if (oper.get_kind() == Operand::IMM_IVAL) { // constants
    if (const_to_value.count(oper.get_imm_ival()) == 1) { // already seen constant
      res = const_to_value[oper.get_imm_ival()];
    } else { // new constant
      const_to_value[oper.get_imm_ival()] = next_val;
      value_to_const[next_val] = oper.get_imm_ival();
      res = next_val++;
    }
  } else { // VREGs
    if (vreg_to_value.count(oper.get_base_reg()) == 1) { // already seen this VREG
      res = vreg_to_value[oper.get_base_reg()];
    } else { // first time seeing this VREG
      vreg_to_value[oper.get_base_reg()] = next_val;
      value_to_vreg[next_val].insert(oper.get_base_reg());
      res = next_val++;
    }
  }
  return res;
}

// when moving from one vreg to another, sets destination value number
void set_value_num(Operand oper, std::unordered_map<int, int>& vreg_to_value, std::unordered_map<int, std::unordered_set<int>>& value_to_vreg, 
  std::unordered_map<int, int>& const_to_value, std::unordered_map<int, int>& value_to_const, int next_val) {
  if (vreg_to_value.count(oper.get_base_reg()) == 1) {
    vreg_to_value[oper.get_base_reg()] = next_val;
  } else {
    vreg_to_value[oper.get_base_reg()] = next_val;
    value_to_vreg[next_val].insert(oper.get_base_reg());
  }
}

std::shared_ptr<InstructionSequence> LVN::transform_basic_block(std::shared_ptr<InstructionSequence> orig_bb) {
  // analysis data
  std::unordered_map<int, int> const_to_value;
  std::unordered_map<int, int> value_to_const;
  std::unordered_map<int, int> vreg_to_value;
  std::unordered_map<int, std::unordered_set<int>> value_to_vreg;
  std::unordered_map<std::string, std::unordered_set<int>> lvn_lookup;
  std::unordered_map<int, int> copy_map;
  int next_val = 0;
  std::shared_ptr<InstructionSequence> new_bb = std::make_shared<InstructionSequence>();

  int num_ins = orig_bb->get_length();
  for (int i = 0; i < num_ins; i++) {
    Instruction *orig_ins = orig_bb->get_instruction(i);
    Instruction *dup_ins = orig_ins->duplicate();
    if (HighLevel::is_def(orig_ins)) { // if a register def
      if (orig_ins->get_num_operands() == 3) { // handles computations (LVN key generation and matching)
        // get value number for first operand
        Operand oper1 = orig_ins->get_operand(1);
        int value_num1 =  determine_value_num(oper1, vreg_to_value, value_to_vreg, const_to_value, value_to_const, next_val);
        // get value number for second operand
        Operand oper2 = orig_ins->get_operand(2);
        int value_num2 =  determine_value_num(oper2, vreg_to_value, value_to_vreg, const_to_value, value_to_const, next_val);
        // generate LVN key from operand value numbers and opcode
        std::string lvn_key = std::to_string(orig_ins->get_opcode()) + "_" + std::to_string(value_num1) + "_" + std::to_string(value_num2);
        Operand dest = orig_ins->get_operand(0);

        if (lvn_lookup.count(lvn_key) != 0) { // if we already have the computation done
          HighLevelOpcode mov_opcode = HINS_mov_q;
          int computed_vreg_val = *(lvn_lookup[lvn_key].begin()); // value number we want
          int move_from = *(value_to_vreg[computed_vreg_val].begin()); // (one of) vregs that value is stored in
          // set destination value number
          set_value_num(dest, vreg_to_value, value_to_vreg, const_to_value, value_to_const, computed_vreg_val);
          new_bb->append(new Instruction(mov_opcode, dest, Operand(Operand::VREG, move_from))); // move from previous computation
          copy_map[dest.get_base_reg()] = move_from; // keep track for copy propogation
        } else { // new computation
          // assign new value number, store in LVN lookup, and append original instruction
          int temp = determine_value_num(dest, vreg_to_value, value_to_vreg, const_to_value, value_to_const, next_val);
          lvn_lookup[lvn_key].insert(temp);
          new_bb->append(dup_ins);
        }
      } else if (orig_ins->get_num_operands() == 2) { // move instructions
        Operand source = orig_ins->get_operand(1);
        Operand dest = orig_ins->get_operand(0);

        // don't modify label moves
        if (source.get_kind() == Operand::IMM_LABEL) {
          new_bb->append(dup_ins);
          continue;
        }

        // don't modify extension
        if (orig_ins->get_opcode() == HINS_sconv_lq) {
          new_bb->append(dup_ins);
          continue;
        }

        // get source value number, set destination's value number accordingly
        int value_num1 = determine_value_num(source, vreg_to_value, value_to_vreg, const_to_value, value_to_const, next_val);
        set_value_num(dest, vreg_to_value, value_to_vreg, const_to_value, value_to_const, value_num1);
        new_bb->append(dup_ins);
      } else { // any other def instruction
        new_bb->append(dup_ins);
      }
    } else { // not a def instruction
      new_bb->append(dup_ins);
    }
  }

  // COPY PROPOGATION, starting from modified LVN instruction sequence
  std::shared_ptr<InstructionSequence> copy_prop_bb = std::make_shared<InstructionSequence>();
  for (int i = 0; i < num_ins; i++) {
    Instruction *orig_ins = new_bb->get_instruction(i);
    Instruction *dup_ins = orig_ins->duplicate();
    int num_operands = dup_ins->get_num_operands();
    if (num_operands == 2) {
      Operand source = dup_ins->get_operand(1);
      // if the source vreg has a previously computed copy stored elsewhere; replace with that copy
      if (source.get_kind() == Operand::VREG && copy_map.count(source.get_base_reg()) == 1) {
        dup_ins->set_operand(1, Operand(Operand::VREG, copy_map[source.get_base_reg()]));
      }
    }
    copy_prop_bb->append(dup_ins);
  }
  return copy_prop_bb;
}


DeadStoreElimination::DeadStoreElimination(std::shared_ptr<ControlFlowGraph> cfg)
  : ControlFlowGraphTransform(cfg)
  , m_live_vregs(cfg) {
  m_live_vregs.execute();
}

DeadStoreElimination::~DeadStoreElimination() {}

std::shared_ptr<InstructionSequence> DeadStoreElimination::transform_basic_block(std::shared_ptr<InstructionSequence> orig_bb) {
  std::shared_ptr<InstructionSequence> result_iseq = std::make_shared<InstructionSequence>();
  for (auto i = orig_bb->cbegin(); i != orig_bb->cend(); ++i) {
    Instruction *orig_ins = *i;
    bool preserve_instruction = true;

    if (HighLevel::is_def(orig_ins)) {
      Operand dest = orig_ins->get_operand(0);

      LiveVregs::FactType live_after =
        m_live_vregs.get_fact_after_instruction(orig_bb, orig_ins);
      
      // filter for call instruction, function argument vregs
      if (orig_ins->get_opcode() != HINS_call && dest.get_base_reg() > 6 && !live_after.test(dest.get_base_reg()))
        // destination register is dead immediately after this instruction,
        // so it can be eliminated
        preserve_instruction = false;
    }
    if (preserve_instruction)
      result_iseq->append(orig_ins->duplicate());
  }
  return result_iseq;
}