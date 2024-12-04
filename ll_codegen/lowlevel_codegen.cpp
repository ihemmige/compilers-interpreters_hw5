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
#include <map>
#include "node.h"
#include "instruction.h"
#include "operand.h"
#include "local_storage_allocation.h"
#include "highlevel.h"
#include "lowlevel.h"
#include "highlevel_formatter.h"
#include "exceptions.h"
#include "lowlevel_codegen.h"
#include <unordered_map>

// maps vreg numbers to their corresponding X86 argument registers
const std::unordered_map<int, MachineReg> FUNC_PARAM_MAPPING = {
  {1, MREG_RDI},
  {2, MREG_RSI},
  {3, MREG_RDX},
  {4, MREG_RCX},
  {5, MREG_R8},
  {6, MREG_R9},
};

// This map has some "obvious" translations of high-level opcodes to
// low-level opcodes.
const std::map<HighLevelOpcode, LowLevelOpcode> HL_TO_LL = {
  { HINS_nop, MINS_NOP},
  { HINS_add_b, MINS_ADDB },
  { HINS_add_w, MINS_ADDW },
  { HINS_add_l, MINS_ADDL },
  { HINS_add_q, MINS_ADDQ },
  { HINS_sub_b, MINS_SUBB },
  { HINS_sub_w, MINS_SUBW },
  { HINS_sub_l, MINS_SUBL },
  { HINS_sub_q, MINS_SUBQ },
  { HINS_mul_l, MINS_IMULL },
  { HINS_mul_q, MINS_IMULQ },
  { HINS_mov_b, MINS_MOVB },
  { HINS_mov_w, MINS_MOVW },
  { HINS_mov_l, MINS_MOVL },
  { HINS_mov_q, MINS_MOVQ },
  { HINS_sconv_bw, MINS_MOVSBW },
  { HINS_sconv_bl, MINS_MOVSBL },
  { HINS_sconv_bq, MINS_MOVSBQ },
  { HINS_sconv_wl, MINS_MOVSWL },
  { HINS_sconv_wq, MINS_MOVSWQ },
  { HINS_sconv_lq, MINS_MOVSLQ },
  { HINS_uconv_bw, MINS_MOVZBW },
  { HINS_uconv_bl, MINS_MOVZBL },
  { HINS_uconv_bq, MINS_MOVZBQ },
  { HINS_uconv_wl, MINS_MOVZWL },
  { HINS_uconv_wq, MINS_MOVZWQ },
  { HINS_uconv_lq, MINS_MOVZLQ },
  { HINS_ret, MINS_RET },
  { HINS_jmp, MINS_JMP },
  { HINS_call, MINS_CALL },

  // For comparisons, it is expected that the code generator will first
  // generate a cmpb/cmpw/cmpl/cmpq instruction to compare the operands,
  // and then generate a setXX instruction to put the result of the
  // comparison into the destination operand. These entries indicate
  // the apprpropriate setXX instruction to use.
  { HINS_cmplt_b, MINS_SETL },
  { HINS_cmplt_w, MINS_SETL },
  { HINS_cmplt_l, MINS_SETL },
  { HINS_cmplt_q, MINS_SETL },
  { HINS_cmplte_b, MINS_SETLE },
  { HINS_cmplte_w, MINS_SETLE },
  { HINS_cmplte_l, MINS_SETLE },
  { HINS_cmplte_q, MINS_SETLE },
  { HINS_cmpgt_b, MINS_SETG },
  { HINS_cmpgt_w, MINS_SETG },
  { HINS_cmpgt_l, MINS_SETG },
  { HINS_cmpgt_q, MINS_SETG },
  { HINS_cmpgte_b, MINS_SETGE },
  { HINS_cmpgte_w, MINS_SETGE },
  { HINS_cmpgte_l, MINS_SETGE },
  { HINS_cmpgte_q, MINS_SETGE },
  { HINS_cmpeq_b, MINS_SETE },
  { HINS_cmpeq_w, MINS_SETE },
  { HINS_cmpeq_l, MINS_SETE },
  { HINS_cmpeq_q, MINS_SETE },
  { HINS_cmpneq_b, MINS_SETNE },
  { HINS_cmpneq_w, MINS_SETNE },
  { HINS_cmpneq_l, MINS_SETNE },
  { HINS_cmpneq_q, MINS_SETNE },
};

LowLevelCodeGen::LowLevelCodeGen(const Options &options)
  : m_options(options)
  , m_total_memory_storage(0) {
}

LowLevelCodeGen::~LowLevelCodeGen() {
}

void LowLevelCodeGen::generate(std::shared_ptr<Function> function) {
  // Make the Function object available to member functions
  m_function = function;

  // The translation is done in the translate_hl_to_ll() member function
  std::shared_ptr<InstructionSequence> ll_iseq = translate_hl_to_ll(function->get_hl_iseq());
  m_function->set_ll_iseq(ll_iseq);
}

std::shared_ptr<InstructionSequence> LowLevelCodeGen::translate_hl_to_ll(std::shared_ptr<InstructionSequence> hl_iseq) {
  std::shared_ptr<InstructionSequence> ll_iseq(new InstructionSequence());

  // The high-level InstructionSequence will have a pointer to the Node
  // representing the function definition. Useful information could be stored
  // there (for example, about the amount of memory needed for local storage,
  // maximum number of virtual registers used, etc.)
  Node *funcdef_ast = m_function->get_funcdef_ast();
  assert(funcdef_ast != nullptr);

  // Determine the total number of bytes of memory storage
  // that the function needs. This should include both variables that
  // *must* have storage allocated in memory (e.g., arrays), and also
  // any additional memory that is needed for virtual registers,
  // spilled machine registers, etc.
  int vreg_space = m_function->get_num_vregs() * 8;
  int local_space = m_function->get_total_local_storage();
  m_total_memory_storage = vreg_space + local_space;

  // The function prologue will push %rbp, which should guarantee that the
  // stack pointer (%rsp) will contain an address that is a multiple of 16.
  // If the total memory storage required is not a multiple of 16, add to
  // it so that it is.
  if ((m_total_memory_storage) % 16 != 0)
    m_total_memory_storage += (16 - (m_total_memory_storage % 16));

  // Iterate through high level instructions
  for (auto i = hl_iseq->cbegin(); i != hl_iseq->cend(); ++i) {
    Instruction *hl_ins = *i;

    // If the high-level instruction has a label, define an equivalent
    // label in the low-level instruction sequence
    if (i.has_label())
      ll_iseq->define_label(i.get_label());

    // Translate the high-level instruction into one or more low-level instructions.
    // The first generated low-level instruction is annotated with a textual
    // representation of the high-level instruction.
    unsigned ll_idx = ll_iseq->get_length();
    translate_instruction(hl_ins, ll_iseq);
    HighLevelFormatter hl_formatter;
    ll_iseq->get_instruction(ll_idx)->set_comment(hl_formatter.format_instruction(hl_ins));
  }

  return ll_iseq;
}

// These helper functions are provided to make it easier to handle
// the way that instructions and operands vary based on operand size
// ('b'=1 byte, 'w'=2 bytes, 'l'=4 bytes, 'q'=8 bytes.)

// Check whether hl_opcode matches a range of opcodes, where base
// is a _b variant opcode. Return true if the hl opcode is any variant
// of that base.
bool match_hl(int base, int hl_opcode) {
  return hl_opcode >= base && hl_opcode < (base + 4);
}

// For a low-level instruction with 4 size variants, return the correct
// variant. base_opcode should be the "b" variant, and operand_size
// should be the operand size in bytes (1, 2, 4, or 8.)
LowLevelOpcode select_ll_opcode(LowLevelOpcode base_opcode, int operand_size) {
  int off;

  switch (operand_size) {
  case 1: // 'b' variant
    off = 0; break;
  case 2: // 'w' variant
    off = 1; break;
  case 4: // 'l' variant
    off = 2; break;
  case 8: // 'q' variant
    off = 3; break;
  default:
    assert(false);
    off = 3;
  }

  return LowLevelOpcode(int(base_opcode) + off);
}

// Get the correct Operand::Kind value for a machine register
// of the specified size (1, 2, 4, or 8 bytes.)
Operand::Kind select_mreg_kind(int operand_size) {
  switch (operand_size) {
  case 1:
    return Operand::MREG8;
  case 2:
    return Operand::MREG16;
  case 4:
    return Operand::MREG32;
  case 8:
    return Operand::MREG64;
  default:
    assert(false);
    return Operand::MREG64;
  }
}

void LowLevelCodeGen::translate_instruction(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  HighLevelOpcode hl_opcode = HighLevelOpcode(hl_ins->get_opcode());

  if (hl_opcode == HINS_enter) {
    // Function prologue: this will create an ABI-compliant stack frame.
    // The local variable area is *below* the address in %rbp, and local storage
    // can be accessed at negative offsets from %rbp. For example, the topmost
    // 4 bytes in the local storage area are at -4(%rbp).
    ll_iseq->append(new Instruction(MINS_PUSHQ, Operand(Operand::MREG64, MREG_RBP)));
    ll_iseq->append(new Instruction(MINS_MOVQ, Operand(Operand::MREG64, MREG_RSP), Operand(Operand::MREG64, MREG_RBP)));
    if (m_total_memory_storage > 0)
      ll_iseq->append(new Instruction(MINS_SUBQ, Operand(Operand::IMM_IVAL, m_total_memory_storage), Operand(Operand::MREG64, MREG_RSP)));

    // save callee-saved registers (if any)
    // TODO: if you allocated callee-saved registers as storage for local variables,
    //       emit pushq instructions to save their original values

    return;
  }

  if (hl_opcode == HINS_leave) {
    // Function epilogue: deallocate local storage area and restore original value
    // of %rbp

    // TODO: if you allocated callee-saved registers as storage for local variables,
    //       emit popq instructions to save their original values

    if (m_total_memory_storage > 0)
      ll_iseq->append(new Instruction(MINS_ADDQ, Operand(Operand::IMM_IVAL, m_total_memory_storage), Operand(Operand::MREG64, MREG_RSP)));
    ll_iseq->append(new Instruction(MINS_POPQ, Operand(Operand::MREG64, MREG_RBP)));

    return;
  }

  if (hl_opcode == HINS_ret) {
    ll_iseq->append(new Instruction(MINS_RET));
    return;
  }

  // TODO: handle other high-level instructions
  // Note that you can use the highlevel_opcode_get_source_operand_size() and
  // highlevel_opcode_get_dest_operand_size() functions to determine the
  // size (in bytes, 1, 2, 4, or 8) of either the source operands or
  // destination operand of a high-level instruction. This should be useful
  // for choosing the appropriate low-level instructions and
  // machine register operands.
  if (hl_opcode == HINS_call) {
    Operand func = hl_ins->get_operand(0);
    ll_iseq->append(new Instruction(MINS_CALL, func));
    return;
  }

  if (match_hl(HINS_mov_b, hl_opcode)) {
    handle_move(hl_ins, ll_iseq);
    return;
  }

  if (hl_opcode == HINS_jmp) {
    Operand label = hl_ins->get_operand(0);
    ll_iseq->append(new Instruction(MINS_JMP, label));
    return;
  }

  if (hl_opcode == HINS_cjmp_t || hl_opcode == HINS_cjmp_f) {
    Operand cond = hl_ins->get_operand(0);
    Operand ll_cond = cond.get_kind() == Operand::IMM_IVAL ? Operand(Operand::IMM_IVAL, cond.get_imm_ival()) : generate_stack_oper(cond);
    ll_iseq->append(new Instruction(MINS_CMPL, Operand(Operand::IMM_IVAL, 0), ll_cond));
    // JNE if true, JE if false
    ll_iseq->append(new Instruction(hl_opcode == HINS_cjmp_t ? MINS_JNE : MINS_JE, hl_ins->get_operand(1))); // jump if, label
    return;
  }

  if (match_hl(HINS_cmplte_b, hl_opcode)) { // <=
    handle_comp(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_cmplt_b, hl_opcode)) { // <
    handle_comp(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_cmpgte_b, hl_opcode)) { // >=
    handle_comp(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_cmpgt_b, hl_opcode)) { // >
    handle_comp(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_cmpeq_b, hl_opcode)) { // =
    handle_comp(hl_ins, ll_iseq);
    return;
  }

  if (hl_opcode == HINS_sconv_bl) {
    handle_sconv(hl_ins, ll_iseq);
    return;
  }

  if (hl_opcode == HINS_sconv_lq) {
    handle_sconv(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_add_b, hl_opcode)) {
    handle_arith(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_sub_b, hl_opcode)) {
    handle_arith(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_mul_b, hl_opcode)) {
    handle_arith(hl_ins, ll_iseq);
    return;
  }

  if (match_hl(HINS_div_b, hl_opcode)) {
    handle_div(hl_ins, ll_iseq, false); // false flag, since NOT modulus
    return;
  }

  if (match_hl(HINS_mod_b, hl_opcode)) {
    handle_div(hl_ins, ll_iseq, true); // true flag, since modulus
    return;
  }

  if (match_hl(HINS_neg_b, hl_opcode)) {
    handle_neg(hl_ins, ll_iseq);
    return;
  }

  if (hl_opcode == HINS_localaddr) {
    handle_localaddr(hl_ins, ll_iseq);
    return;
  }

  RuntimeError::raise("high level opcode %d not handled", int(hl_opcode));
}

// given a VREG, generate an operand accessing stack memory
Operand LowLevelCodeGen::generate_stack_oper(Operand oper) {
  int memory_offset = -m_total_memory_storage + (oper.get_base_reg() - 10) * 8;
  return Operand(Operand::MREG64_MEM_OFF, MREG_RBP, memory_offset);
}

// can handle add, sub, mul instructions
void LowLevelCodeGen::handle_arith(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  Operand elem1 = hl_ins->get_operand(1);
  Operand elem2 = hl_ins->get_operand(2);
  Operand res_dest = hl_ins->get_operand(0);
  int operand_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));

  // move element 1 to a temp destination
  if (elem1.get_kind() == Operand::IMM_IVAL) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size),  Operand(Operand::IMM_IVAL, elem1.get_imm_ival()), Operand(select_mreg_kind(operand_size), MREG_R10)));
  } else {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), generate_stack_oper(elem1), Operand(select_mreg_kind(operand_size), MREG_R10)));
  }

  // carry out arithmetic operation with element 2 and store in temp (R10)
  if (elem2.get_kind() == Operand::IMM_IVAL) {
    ll_iseq->append(new Instruction(HL_TO_LL.at(HighLevelOpcode(hl_ins->get_opcode())),  Operand(Operand::IMM_IVAL, elem2.get_imm_ival()), Operand(select_mreg_kind(operand_size), MREG_R10)));
  } else {
    ll_iseq->append(new Instruction(HL_TO_LL.at(HighLevelOpcode(hl_ins->get_opcode())), generate_stack_oper(elem2), Operand(select_mreg_kind(operand_size), MREG_R10)));
  }

  // move from temp (R10) to final destination
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), Operand(select_mreg_kind(operand_size), MREG_R10), generate_stack_oper(res_dest)));
}

// handles move instructions
void LowLevelCodeGen::handle_move(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  int operand_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));
  Operand source = hl_ins->get_operand(1);
  Operand dest = hl_ins->get_operand(0);    
  Operand ll_source;
  Operand ll_dest;

  // modify low-level destination operand based its type
  if (dest.is_memref()) { // move memory address to R11 (temporary)
    ll_iseq->append(new Instruction(MINS_MOVQ, generate_stack_oper(dest), Operand(select_mreg_kind(8), MREG_R11)));
    ll_dest = Operand(Operand::MREG64_MEM, MREG_R11);
  } else if (dest.get_base_reg() == 0) { // return register
    ll_dest = Operand(select_mreg_kind(operand_size), MREG_RAX);
  } else if (dest.get_base_reg() > 0 && dest.get_base_reg() < 7) { // argument registers
    ll_dest = Operand(Operand(select_mreg_kind(operand_size), FUNC_PARAM_MAPPING.at(dest.get_base_reg())));
  } else { // destination is regular VREG
    ll_dest = generate_stack_oper(dest);
  }

  // modify low-level source operand based its type
  if (source.get_kind() == Operand::IMM_IVAL) { // source is immediate integer
    ll_source = Operand(Operand::IMM_IVAL, source.get_imm_ival());
  } else if(source.get_kind() == Operand::IMM_LABEL) { // source is label (ex. string constant)
    ll_source = source;
  } else if (source.is_memref()) { // move memory address to R11 (temporary), dereference R11 and store in R10 (temporary)
    ll_iseq->append(new Instruction(MINS_MOVQ, generate_stack_oper(source), Operand(select_mreg_kind(8), MREG_R11)));
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), Operand(Operand::MREG64_MEM, MREG_R11), Operand(select_mreg_kind(operand_size), MREG_R10)));
    ll_source = Operand(select_mreg_kind(operand_size), MREG_R10);
  } else if (source.get_base_reg() == 0) { // return register
    ll_source = Operand(select_mreg_kind(operand_size), MREG_RAX);
  } else if (source.get_base_reg() > 0 && source.get_base_reg() < 7) { // argument registers
    ll_source = Operand(Operand(select_mreg_kind(operand_size), FUNC_PARAM_MAPPING.at(source.get_base_reg())));
  } else { // source is regular VREG
    ll_source = generate_stack_oper(source);
  }

  // move source to temp if both are memory references
  if (ll_source.is_memref() && ll_dest.is_memref()) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), ll_source, Operand(select_mreg_kind(operand_size), MREG_R10)));
    ll_source = Operand(Operand(select_mreg_kind(operand_size), MREG_R10));
  }
  // move from source to destination
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), ll_source, ll_dest));
}

// handles all comparison instructions
void LowLevelCodeGen::handle_comp(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  int operand_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));
  Operand comp1 = hl_ins->get_operand(1);
  Operand comp2 = hl_ins->get_operand(2);
  Operand comp_res =  hl_ins->get_operand(0);
  Operand ll_comp1 = comp1.get_kind() == Operand::IMM_IVAL ? Operand(Operand::IMM_IVAL, comp1.get_imm_ival()) : generate_stack_oper(comp1);
  Operand ll_comp2 = comp2.get_kind() == Operand::IMM_IVAL ? Operand(Operand::IMM_IVAL, comp2.get_imm_ival()) : generate_stack_oper(comp2);
  Operand ll_comp_res = generate_stack_oper(comp_res);
  LowLevelOpcode comparator = HL_TO_LL.at(HighLevelOpcode(hl_ins->get_opcode()));

  // if both values being compared are memory references, move the first to temporary (R10)
  if (ll_comp1.is_memref() && ll_comp2.is_memref()) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), ll_comp1, Operand(select_mreg_kind(operand_size), MREG_R10)));
    ll_comp1 = Operand(Operand(select_mreg_kind(operand_size), MREG_R10));
  }
  
  // compare, set R10 flag based on comparison, extend the flag to operand size in R11, move from R11 to destination
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_CMPB, operand_size), ll_comp2, ll_comp1));
  ll_iseq->append(new Instruction(comparator, Operand(Operand(select_mreg_kind(1), MREG_R10))));
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVZBW, operand_size) - 1, Operand(Operand(select_mreg_kind(1), MREG_R10)), Operand(Operand(select_mreg_kind(operand_size), MREG_R11))));
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), Operand(Operand(select_mreg_kind(operand_size), MREG_R11)), ll_comp_res));
}

// handles div instruction
void LowLevelCodeGen::handle_div(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq, bool is_mod) {
  Operand elem1 = hl_ins->get_operand(1);
  Operand elem2 = hl_ins->get_operand(2);
  Operand res_dest = hl_ins->get_operand(0);
  int operand_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));

  // move element 1 to RAX
  if (elem1.get_kind() == Operand::IMM_IVAL) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size),  Operand(Operand::IMM_IVAL, elem1.get_imm_ival()), Operand(select_mreg_kind(operand_size), MREG_RAX)));
  } else {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), generate_stack_oper(elem1), Operand(select_mreg_kind(operand_size), MREG_RAX)));
  }

  // CDQ instruction
  ll_iseq->append(new Instruction(MINS_CDQ));

  // move element 2 to r10
  if (elem2.get_kind() == Operand::IMM_IVAL) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size),  Operand(Operand::IMM_IVAL, elem2.get_imm_ival()), Operand(select_mreg_kind(operand_size), MREG_R10)));
  } else {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), generate_stack_oper(elem2), Operand(select_mreg_kind(operand_size), MREG_R10)));
  }

  // carry out IDIV instruction
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_IDIVL, operand_size) - 2, Operand(select_mreg_kind(operand_size), MREG_R10)));

  // move result from RAX (div) or RDX (mod) to final destination
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), Operand(select_mreg_kind(operand_size), is_mod ? MREG_RDX : MREG_RAX), generate_stack_oper(res_dest)));
}

// handles localaddr stack memory access
void LowLevelCodeGen::handle_localaddr(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  int vreg_space = m_function->get_num_vregs() * 8;
  Operand dest = hl_ins->get_operand(0);
  Operand offset = hl_ins->get_operand(1);
  int memory_offset = -m_total_memory_storage + vreg_space + offset.get_imm_ival(); // where local space (not vreg) starts
  // move value at memory to R10, move from R10 to destination
  ll_iseq->append(new Instruction(MINS_LEAQ, Operand(Operand::MREG64_MEM_OFF, MREG_RBP, memory_offset), Operand(select_mreg_kind(8), MREG_R10)));
  ll_iseq->append(new Instruction(MINS_MOVQ, Operand(select_mreg_kind(8), MREG_R10), generate_stack_oper(dest)));
}

// handles negation insturction
void LowLevelCodeGen::handle_neg(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  Operand value = hl_ins->get_operand(1); // value being negated
  Operand res_dest = hl_ins->get_operand(0);
  int operand_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));

  // move the value to temp destination
  if (value.get_kind() == Operand::IMM_IVAL) {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size),  Operand(Operand::IMM_IVAL, value.get_imm_ival()), Operand(select_mreg_kind(operand_size), MREG_R10)));
  } else {
    ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size), generate_stack_oper(value), Operand(select_mreg_kind(operand_size), MREG_R10)));
  }

  // move 0 to destination
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_MOVB, operand_size),  Operand(Operand::IMM_IVAL, 0), generate_stack_oper(res_dest)));

  // subtract from 0 to negate
  ll_iseq->append(new Instruction(select_ll_opcode(MINS_SUBB, operand_size), Operand(select_mreg_kind(operand_size), MREG_R10), generate_stack_oper(res_dest)));
}

// handles signed size conversions
void LowLevelCodeGen::handle_sconv(Instruction *hl_ins, std::shared_ptr<InstructionSequence> ll_iseq) {
  int from_size = highlevel_opcode_get_source_operand_size(HighLevelOpcode(hl_ins->get_opcode()));
  int to_size = highlevel_opcode_get_dest_operand_size(HighLevelOpcode(hl_ins->get_opcode()));
  Operand source = hl_ins->get_operand(1);
  Operand dest = hl_ins->get_operand(0);

  // generate opcodes based on operand sizes and type of conversion
  LowLevelOpcode move1 = select_ll_opcode(MINS_MOVB, from_size);
  LowLevelOpcode move2 = select_ll_opcode(MINS_MOVB, to_size);
  LowLevelOpcode movs = HL_TO_LL.at(HighLevelOpcode(hl_ins->get_opcode()));

  // move to R10, convert in R10, move from R10 to destination
  ll_iseq->append(new Instruction(move1, generate_stack_oper(source), Operand(Operand(select_mreg_kind(from_size), MREG_R10))));
  ll_iseq->append(new Instruction(movs, Operand(Operand(select_mreg_kind(from_size), MREG_R10)), Operand(Operand(select_mreg_kind(to_size), MREG_R10))));
  ll_iseq->append(new Instruction(move2, Operand(Operand(select_mreg_kind(to_size), MREG_R10)), generate_stack_oper(dest)));
}

// TODO: implement other private member functions
