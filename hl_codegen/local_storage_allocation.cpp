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
#include "node.h"
#include "symtab.h"
#include "local_storage_allocation.h"
#include <ast.h>

const int TOK_AMPERSAND = 278;

LocalStorageAllocation::LocalStorageAllocation()
  : m_total_local_storage(0U)
  , m_next_vreg(VREG_FIRST_LOCAL) {
}

LocalStorageAllocation::~LocalStorageAllocation() {
}

void LocalStorageAllocation::allocate_storage(std::shared_ptr<Function> function) {
  // Any member function can use m_function to refer to the
  // Function object.
  m_function = function;

  visit(function->get_funcdef_ast());
}

void LocalStorageAllocation::visit_function_definition(Node *n) {
  SymbolTable* func_table = n->get_kid(1)->get_symbol()->get_func_symtab();
  visit(n->get_kid(3)); // visit statement list

  m_function->get_vreg_alloc()->alloc_local(); // don't allocate vr0
  int num_alloc = VREG_FIRST_ARG;
  // don't allocate argument registers
  while (num_alloc + 1 < VREG_FIRST_LOCAL) {
    num_alloc = m_function->get_vreg_alloc()->alloc_local();
  }

  // make storage decision based on types (and whether address-of is taken)
  for (auto iter = func_table->cbegin(); iter != func_table->cend(); iter++) {
    Symbol *sym = *iter;    
    if (sym->get_type()->is_array() || sym->get_type()->is_struct()) {
      sym->set_align(m_storage_calc.add_field(sym->get_type()));
    } else if (sym->get_address_of()) {
      sym->set_align(m_storage_calc.add_field(sym->get_type()));
    } else {
      sym->set_vreg(m_function->get_vreg_alloc()->alloc_local());
    }
  }

  m_storage_calc.finish();
  n->set_total_local_storage(m_storage_calc.get_size());
  m_function->set_total_local_storage(m_storage_calc.get_size());
}

void LocalStorageAllocation::visit_statement_list(Node *n) {
  // check for address-of operator
  find_address_of(n);
}

// helper function recursively visits nodes, and marks any variables that have address-of taken
void LocalStorageAllocation::find_address_of(Node *n) {
  int tag = n->get_tag();
  if (tag == AST_UNARY_EXPRESSION && n->get_kid(0)->get_tag() == TOK_AMPERSAND) {
    Symbol* var = n->get_kid(1)->get_symbol();
    if (var) { // if the node has a symbol, set its address-of flag
      var->set_address_of();
    }
  } else {
    // recursively visit kids
    for (auto iter = n->cbegin(); iter != n->cend(); iter++) {
      find_address_of(*iter);
    }
  }
}