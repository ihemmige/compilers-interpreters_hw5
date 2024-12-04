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
#include <algorithm>
#include <utility>
#include <map>
#include "grammar_symbols.h"
#include "parse.tab.h"
#include "node.h"
#include "ast.h"
#include "exceptions.h"
#include "semantic_analysis.h"
#include <unordered_set>

SemanticAnalysis::SemanticAnalysis(const Options &options)
  : m_options(options)
  , m_global_symtab(new SymbolTable(nullptr, "global")) {
  m_cur_symtab = m_global_symtab;
  m_all_symtabs.push_back(m_global_symtab);
}

SemanticAnalysis::~SemanticAnalysis() {
  // The semantic analyzer owns the SymbolTables and their Symbols,
  // so delete them. Note that the AST has pointers to Symbol objects,
  // so the SemanticAnalysis object should live at least as long
  // as the AST.
  for (auto i = m_all_symtabs.begin(); i != m_all_symtabs.end(); ++i)
    delete *i;
}

void SemanticAnalysis::visit_struct_type(Node *n) {
  Symbol* visiting_struct = m_cur_symtab->lookup_recursive("struct " + n->get_kid(0)->get_str()); // find struct type in symbol table
  if (!visiting_struct)
    SemanticError::raise(n->get_loc(), "Struct not defined");
  
  // set type to struct type
  std::shared_ptr<Type> struct_type(visiting_struct->get_type()); 
  n->set_type(struct_type);
}

void SemanticAnalysis::visit_union_type(Node *n) {
  RuntimeError::raise("union types aren't supported");
}

void SemanticAnalysis::visit_variable_declaration(Node *n) {
  // determine base type
  visit(n->get_kid(1));
  std::shared_ptr<Type> base = n->get_kid(1)->get_type();
  n->set_type(base);

  // loop and add declarators to symbol table, with base type
  Node* declarator_list = n->get_kid(2);
  for (auto it = declarator_list->cbegin(); it != declarator_list->cend(); it++) {
    Node* declarator = *it;
    declarator->set_type(base);
    visit(declarator);
    m_cur_symtab->add_entry(n->get_loc(), SymbolKind::VARIABLE, declarator->get_str(), declarator->get_type());
  }
}

void SemanticAnalysis::visit_basic_type(Node *n) {
  // constants for categorizing tokens
  std::unordered_set<std::string> possible_types = {"char", "int", "void"};
  std::unordered_set<std::string> special_ints = {"long", "short"};

  std::shared_ptr<Type> node_type;
  std::unordered_set<std::string> types;
  std::unordered_set<std::string> qualifiers;

  // loop through tokens and categorize as types and qualifiers
  for (auto it = n->cbegin(); it != n->cend(); it++) {
    Node* token = *it;
    if (possible_types.count(token->get_str())) {
      types.insert(token->get_str());
    } else {
      qualifiers.insert(token->get_str());
      if (special_ints.count(token->get_str())) { // long/short imply int
        types.insert("int");
      }
    }
  }

  // no explicit int or char
  if (!types.size() && qualifiers.size())
    types.insert("int");

  // must be exactly one type
  if (types.size() != 1)
    SemanticError::raise(n->get_loc(), "Type and qualifiers specifications not valid");

  // char
  if (types.count("char")) {
    node_type = std::make_shared<BasicType>(BasicTypeKind::CHAR, !qualifiers.count("unsigned"));
  } else if (types.count("int")) { // categorize int as long, short, or int
    if (qualifiers.count("long")) {
      node_type = std::make_shared<BasicType>(BasicTypeKind::LONG, !qualifiers.count("unsigned"));
    } else if (qualifiers.count("short")) {
      node_type = std::make_shared<BasicType>(BasicTypeKind::SHORT, !qualifiers.count("unsigned"));
    } else {
      node_type = std::make_shared<BasicType>(BasicTypeKind::INT, !qualifiers.count("unsigned"));
    }
  } else if (types.count("void")) { // void can't have any qualifiers
    if (qualifiers.size() != 0)
      SemanticError::raise(n->get_loc(), "Type and qualifiers specifications not valid");
    node_type = std::make_shared<BasicType>(BasicTypeKind::VOID, true);
  }

  // add volatile
  if (qualifiers.count("volatile")) {
    node_type = std::make_shared<QualifiedType>(node_type, TypeQualifier::VOLATILE);
  }

  // add const
  if (qualifiers.count("const")) {
    node_type = std::make_shared<QualifiedType>(node_type, TypeQualifier::CONST);
  }
  n->set_type(node_type);
}

void SemanticAnalysis::visit_named_declarator(Node *n) {
  n->set_str(n->get_kid(0)->get_str());
}

void SemanticAnalysis::visit_pointer_declarator(Node *n) {
  n->get_kid(0)->set_type(n->get_type());
  visit(n->get_kid(0));
  n->set_str(n->get_kid(0)->get_str());
  // if pointer is an array, then make the Node type both array and pointer
  if (n->get_kid(0)->get_tag() == AST_ARRAY_DECLARATOR) {
    std::shared_ptr<Type> ptr_type = std::make_shared<PointerType>(n->get_kid(0)->get_type()->get_base_type());
    std::shared_ptr<Type> ptr_array = std::make_shared<ArrayType>(ptr_type, std::stoi(n->get_kid(0)->get_kid(1)->get_str()));
    n->override_type(ptr_array);
  } else { // regular pointer
    std::shared_ptr<Type> node_type = std::make_shared<PointerType>(n->get_kid(0)->get_type());
    n->override_type(node_type);
  }
}

void SemanticAnalysis::visit_array_declarator(Node *n) {
  n->get_kid(0)->set_type(n->get_type());
  visit(n->get_kid(0));
  n->set_str(n->get_kid(0)->get_str());
  // set array type based on underlying element types and array size
  std::shared_ptr<Type> array_type = std::make_shared<ArrayType>(n->get_kid(0)->get_type(), std::stoi(n->get_kid(1)->get_str()));
  n->override_type(array_type);
}

void SemanticAnalysis::visit_function_definition(Node *n) {
  visit_function_declaration(n);
  m_cur_symtab = get_symbol_table("function " + n->get_kid(1)->get_str()); // want to visit statements using function's symbol table
  Node* function_statements = n->get_kid(3);
  // visit each statement node
  for (auto it = function_statements->cbegin(); it != function_statements->cend(); it++) {
    visit(*it);
  }
  leave_scope(); // return to enclosing scope
}

void SemanticAnalysis::visit_function_declaration(Node *n) {
  visit(n->get_kid(0));
  const std::string& func_name = n->get_kid(1)->get_str();
  std::shared_ptr<Type> type = n->get_kid(0)->get_type();

  // ensure function hasn't already been declared/defined
  SymbolTable* func_table = get_symbol_table("function " + func_name);
  if (func_table)
    SemanticError::raise(n->get_loc(), "Cannot redeclare a function");
  
  // create symbol table for the function
  enter_scope("function " + func_name);

  // process function's parameters
  Node* params = n->get_kid(2);
  visit_function_parameter_list(params);
  std::unordered_set<std::string> param_set;
  std::shared_ptr<Type> final_type = std::make_shared<FunctionType>(type);
  // add the parameters' types to function's type definition
  for (auto it = params->cbegin(); it != params->cend(); it++) {
    std::string p_name = (*it)->get_kid(1)->get_kid(0)->get_str();
    if (param_set.count(p_name))
      SemanticError::raise(n->get_loc(), "Function cannot have two params with same name");
    param_set.insert(p_name);
    final_type->add_member(Member(p_name, (*it)->get_type()));
  }
  n->set_type(final_type);
  m_cur_symtab->set_fn_type(final_type);

  // return to enclosing scope and add function to that symbol table
  leave_scope();
  m_cur_symtab->add_entry(n->get_loc(), SymbolKind::FUNCTION, func_name, n->get_type()); // symbol table for function
  n->get_kid(1)->set_symbol(m_cur_symtab->lookup_local(func_name)); // link this function node with symbol in enclosing symtab
  n->get_kid(1)->get_symbol()->set_func_symtab(get_symbol_table("function " + func_name)); // link symbol with its function symtab
}

void SemanticAnalysis::visit_function_parameter_list(Node *n) {
  bool func_defined = m_cur_symtab->get_num_entries() != 0;
  unsigned num_params = 0;
  if (func_defined)
    num_params = m_cur_symtab->get_num_parameters();
  
  // if redeclaring, ensure param counts match
  if (func_defined && num_params != std::distance(n->cbegin(), n->cend()))
    SemanticError::raise(n->get_loc(), "Incorrect number of parameters in function redeclaration");

  // iterate through parameters
  for (auto it = n->cbegin(); it != n->cend(); it++) {
    unsigned idx = std::distance(n->cbegin(), it);
    // if already defined, then overrite previous corresponding symbol table entry
    if (func_defined) { 
      Symbol* prev_symbol = m_cur_symtab->get_entry(0);
      num_params--;
      m_cur_symtab->remove_symbol(0);
      visit_function_parameter(*it);
      Symbol* new_symbol = m_cur_symtab->get_entry(idx + num_params - 1);
      if (prev_symbol->get_type()->as_str() != new_symbol->get_type()->as_str()) // ensure type matches w/ old parameter at same position
        SemanticError::raise(n->get_loc(), "Parameter type does not match in function redeclaration");
    } else {
      visit_function_parameter(*it);
    }
  }
}

void SemanticAnalysis::visit_function_parameter(Node *n) {
  visit(n->get_kid(0));
  std::shared_ptr<Type> node_type = n->get_kid(0)->get_type();
  Node* decl = n->get_kid(1); // declarator node
  decl->set_type(node_type);
  // make correct visit based on type of param
  switch (decl->get_tag()) {
    case AST_POINTER_DECLARATOR: {
      visit_pointer_declarator(decl);
      m_cur_symtab->add_entry(n->get_loc(), SymbolKind::VARIABLE, decl->get_str(), decl->get_type());
      n->set_symbol(m_cur_symtab->lookup_local(decl->get_str()));
      break;
    }
    case AST_NAMED_DECLARATOR: {
      visit_named_declarator(decl);
      m_cur_symtab->add_entry(n->get_loc(), SymbolKind::VARIABLE, decl->get_str(), decl->get_type());
      n->set_symbol(m_cur_symtab->lookup_local(decl->get_str()));
      break;
    }
    case AST_ARRAY_DECLARATOR: {
      std::shared_ptr<Type> type = std::make_shared<PointerType>(decl->get_type());
      n->set_type(type);
      decl->override_type(type);
      m_cur_symtab->add_entry(n->get_loc(), SymbolKind::VARIABLE, decl->get_kid(0)->get_kid(0)->get_str(), decl->get_type());
      break;
    }
  }
}

void SemanticAnalysis::visit_statement_list(Node *n) {
  enter_scope("block " + std::to_string(n->get_loc().get_line())); // block is named based on the line it starts
  // visit each statement
  for (auto it = n->cbegin(); it != n->cend(); it++) {
    visit(*it);
  }
  leave_scope(); // return to enclosing scope
}

void SemanticAnalysis::visit_return_expression_statement(Node *n) {
  std::shared_ptr<Type> expected_type = m_cur_symtab->get_fn_type()->get_base_type(); // return type of function whose symbol table we're in
  visit(n->get_kid(0)); // generate the return value
  std::shared_ptr<Type> actual_type = n->get_kid(0)->get_type(); // actual return type
  if (expected_type->as_str() == "int" && actual_type->as_str() == "char") { // can promote char to int
    // THIS ALLOWS CHAR TO INT PROMOTION
  } else if (expected_type->as_str() != actual_type->as_str()) { // ensure return types match
    SemanticError::raise(n->get_loc(), "Return value is wrong type");
  }
  n->set_type(actual_type);
}

void SemanticAnalysis::visit_struct_type_definition(Node *n) {
  const std::string& struct_name = n->get_kid(0)->get_str();
  std::shared_ptr<Type> struct_type = std::make_shared<StructType>(struct_name);
  m_cur_symtab->add_entry(n->get_loc(), SymbolKind::TYPE, "struct " + struct_name, struct_type); // add struct type to symbol table
  enter_scope("struct " + struct_name); // create new symbol table for the struct
  Node* struct_body = n->get_kid(1);

  // iterate through lines struct body
  for (auto it = struct_body->cbegin(); it != struct_body->cend(); it++) {
    Node* member_line = *it;
    visit(member_line);
    Node* declarators = member_line->get_kid(2);
    // iterate through declarators
    for (auto decl = declarators->cbegin(); decl != declarators->cend(); decl++) {
      std::shared_ptr<Type> type = (*decl)->get_type(); 
      struct_type->add_member(Member((*decl)->get_kid(0)->get_str(), type));
    }
  }
  leave_scope(); // return to enclosing symbol table
}

void SemanticAnalysis::visit_binary_expression(Node *n) {
  std::unordered_set<std::string> arithmetic_opers = {"+", "-", "*", "/"};
  // visit the operands, and get their types
  visit(n->get_kid(1));
  visit(n->get_kid(2));
  std::shared_ptr<Type> lhs_type(n->get_kid(1)->get_type());
  std::shared_ptr<Type> rhs_type(n->get_kid(2)->get_type());
  if (lhs_type->is_void() || rhs_type->is_void())
    SemanticError::raise(n->get_loc(), "One or both operands is void");

  const std::string& oper = n->get_kid(0)->get_str();
  std::shared_ptr<Type> result_type;
  if (oper == "=") { // if assignment, ensure type compatibility
    check_assignment(n, lhs_type, rhs_type);
    result_type = lhs_type;
  } else if (arithmetic_opers.count(oper)) { // arithmetic operators
    if ((oper == "+" || oper == "-") && lhs_type->is_pointer() != rhs_type->is_pointer()) { // pointer arithmetic
      result_type = lhs_type->is_pointer() ? lhs_type : rhs_type;
    } else if (!lhs_type->is_pointer() && !rhs_type->is_pointer()) { // regular arithmetic
      bool signedness = (lhs_type->is_signed() || rhs_type->is_signed());
      // check for chars
      if (lhs_type->get_basic_type_kind() == BasicTypeKind::CHAR || rhs_type->get_basic_type_kind() == BasicTypeKind::CHAR)
        SemanticError::raise(n->get_loc(), "Cannot do arithmetic on char");
      // int type size is based on the larger of the two types
      if (lhs_type->get_basic_type_kind() == BasicTypeKind::LONG || rhs_type->get_basic_type_kind() == BasicTypeKind::LONG)
        result_type = std::make_shared<BasicType>(BasicTypeKind::LONG, signedness);
      else if (lhs_type->get_basic_type_kind() == BasicTypeKind::INT || rhs_type->get_basic_type_kind() == BasicTypeKind::INT)
        result_type = std::make_shared<BasicType>(BasicTypeKind::INT, signedness);
      else if (lhs_type->get_basic_type_kind() == BasicTypeKind::SHORT || rhs_type->get_basic_type_kind() == BasicTypeKind::SHORT)
        result_type = std::make_shared<BasicType>(BasicTypeKind::SHORT, signedness);
    } else {
      SemanticError::raise(n->get_loc(), "Cannot do arithmetic with two pointers");
    }
  } else { // logical operators
    if (lhs_type->is_array() || lhs_type->is_struct() || lhs_type->is_function())
      SemanticError::raise(n->get_loc(), "Cannot compare non-numeric value");
    if (rhs_type->is_array() || rhs_type->is_struct() || rhs_type->is_function())
      SemanticError::raise(n->get_loc(), "Cannot compare non-numeric value");
    result_type = std::make_shared<BasicType>(BasicTypeKind::INT, true);
  }
  n->make_literal(); // result of binary expression always literal
  n->set_type(result_type);
}

void SemanticAnalysis::visit_unary_expression(Node *n) {
  visit(n->get_kid(1));
  std::shared_ptr<Type> type = n->get_kid(1)->get_type();
  const std::string& oper = n->get_kid(0)->get_str();

  // ensure the operand is valid based on the unary operator
  if (oper == "*") { // pointer dereference
    if (!type->is_pointer())
      SemanticError::raise(n->get_loc(), "Cannot dereference non-pointer type");
    n->set_type(type->get_base_type());
  } else if (oper == "-") { // unary minus
    if (type->is_array() || type->is_struct() || type->is_function() || type->get_basic_type_kind() == BasicTypeKind::CHAR) {
      SemanticError::raise(n->get_loc(), "Cannot negate this type");
    }
    n->set_type(std::make_shared<BasicType>(type->get_basic_type_kind(), true));
  } else if (oper == "!") { // logical negation
    if (type->is_array() || type->is_struct() || type->is_function() || type->get_basic_type_kind() == BasicTypeKind::CHAR) {
      SemanticError::raise(n->get_loc(), "Cannot logical not this type");
    }
    n->set_type(type);
  } else if (oper == "&") { // address-of
    if (type->is_array() || type->is_function() || n->get_kid(1)->is_literal()) {
      SemanticError::raise(n->get_loc(), "Cannot take address of non-lvalue");
    }
    n->set_type(std::make_shared<PointerType>(type));
  }
}

void SemanticAnalysis::visit_postfix_expression(Node *n) {
  // TODO: implement
}

void SemanticAnalysis::visit_conditional_expression(Node *n) {
  // TODO: implement
}

void SemanticAnalysis::visit_cast_expression(Node *n) {
  // TODO: implement
}

void SemanticAnalysis::visit_function_call_expression(Node *n) {
  const std::string& func_name = n->get_kid(0)->get_kid(0)->get_str();
  Symbol* func_symbol = m_cur_symtab->lookup_recursive(func_name);
  if (!func_symbol) // undefined function
    SemanticError::raise(n->get_loc(), "Called undefined function");

  std::shared_ptr<Type> func_type = func_symbol->get_type();
  std::shared_ptr<Type> func_return_type = func_type->get_base_type();
  n->set_type(func_type);
  visit(n->get_kid(1)); // check args
  Node* args = n->get_kid(1);
  if (func_type->get_num_members() != args->get_num_kids()) // ensure correct number of args
    SemanticError::raise(n->get_loc(), "Incorrect number of arguments passed");

  // iterate through args and ensure their types are compatible w/ function definition
  for (auto it = args->cbegin(); it != args->cend(); it++) {
    unsigned symbol_index = std::distance(args->cbegin(), it);
    check_assignment(n, func_type->get_member(symbol_index).get_type(), (*it)->get_type());
  }
}

void SemanticAnalysis::visit_field_ref_expression(Node *n) {
  visit(n->get_kid(0));
  std::shared_ptr<Type> type;
  if (n->get_kid(0)->get_tag() == AST_VARIABLE_REF) {
    type = m_cur_symtab->lookup_recursive(n->get_kid(0)->get_kid(0)->get_str())->get_type();
  } else {
    type = n->get_kid(0)->get_type();
  }

  if (type->is_pointer())
    SemanticError::raise(n->get_loc(), "Invalid pointer to struct");

  // given the struct type, locate desired member
  const std::string& member_name = n->get_kid(1)->get_str();
  n->set_str(member_name);
  std::shared_ptr<Type> mem_type(type->find_member(member_name)->get_type());
  n->set_type(mem_type);
}

void SemanticAnalysis::visit_indirect_field_ref_expression(Node *n) {
  visit(n->get_kid(0));
  std::shared_ptr<Type> type;
  if (n->get_kid(0)->get_tag() == AST_VARIABLE_REF) {
    Symbol* struct_symbol = m_cur_symtab->lookup_recursive(n->get_kid(0)->get_kid(0)->get_str()); // lookup with struct name
    type = struct_symbol->get_type()->get_base_type();
    if (!struct_symbol->get_type()->is_pointer())
      SemanticError::raise(n->get_loc(), "Invalid pointer to struct");
  } else {
    type = n->get_kid(0)->get_type()->get_base_type();
    if (!n->get_kid(0)->get_type()->is_pointer())
      SemanticError::raise(n->get_loc(), "Invalid pointer to struct");
  }
  // given the struct type, locate desired member
  std::string mem_name = n->get_kid(1)->get_str();
  n->set_str(mem_name);
  std::shared_ptr<Type> mem_type(type->find_member(mem_name)->get_type());
  n->set_type(mem_type);
}

void SemanticAnalysis::visit_array_element_ref_expression(Node *n) {
  visit(n->get_kid(0));
  std::string array_name;
  std::shared_ptr<Type> array_type;
  
  if (n->get_kid(0)->get_tag() == AST_VARIABLE_REF) {
    array_name = n->get_kid(0)->get_kid(0)->get_str();
    Symbol* array_symbol = m_cur_symtab->lookup_recursive(array_name);
    if (!array_symbol)
      SemanticError::raise(n->get_loc(), "Array variable is not defined");
    array_type = array_symbol->get_type();
  } else { // pointer to array
    array_type = n->get_kid(0)->get_type();
    array_name = n->get_kid(0)->get_str();
  }

  // the type is not an array
  if (!(array_type->is_pointer() || array_type->is_array()))
    SemanticError::raise(n->get_loc(), "Cannot index non-array");
  
  // process index
  visit(n->get_kid(1));
  std::shared_ptr<Type> idx_type = n->get_kid(1)->get_type();
  if (!idx_type->is_basic() || idx_type->get_basic_type_kind() == BasicTypeKind::CHAR)
    SemanticError::raise(n->get_loc(), "Index type is invalid");
  
  // determine final type based on array type
  n->set_str(array_name);
  std::shared_ptr<Type> array_elem_type(array_type->get_base_type());
  n->set_type(array_elem_type);
}

void SemanticAnalysis::visit_variable_ref(Node *n) {
  Symbol* symbol = m_cur_symtab->lookup_recursive(n->get_kid(0)->get_str()); // find variable's symbol by name
  if (!symbol) // undefined variable
    SemanticError::raise(n->get_loc(), "Variable not defined");
  n->set_str(n->get_kid(0)->get_str());
  n->set_symbol(symbol);
}

void SemanticAnalysis::visit_literal_value(Node *n) {
  n->make_literal();
  if (n->get_kid(0)->get_tag() == TOK_STR_LIT) { // string -> const char *
    std::shared_ptr<Type> node_type = std::make_shared<BasicType>(BasicTypeKind::CHAR, true);
    node_type = std::make_shared<PointerType>(node_type); // pointer
    node_type = std::make_shared<QualifiedType>(node_type, TypeQualifier::CONST); // qualify as const
    n->set_type(node_type);
  } else { // default to int
    n->set_type(std::make_shared<BasicType>(BasicTypeKind::INT, true));
  }
}

SymbolTable *SemanticAnalysis::enter_scope(const std::string &name) {
  SymbolTable *symtab = new SymbolTable(m_cur_symtab, name);
  m_all_symtabs.push_back(symtab);
  m_cur_symtab = symtab;
  return symtab;
}

void SemanticAnalysis::leave_scope() {
  assert(m_cur_symtab->get_parent() != nullptr);
  m_cur_symtab = m_cur_symtab->get_parent();
}

SymbolTable* SemanticAnalysis::get_symbol_table(const std::string& name) {
  // loop through all symbol tables to find one for a given name
  for (auto& table : m_all_symtabs) {
    if (table->get_name() == name)
      return table;
  }
  return nullptr; // return nullptr if it doesn't exist
}

void SemanticAnalysis::check_assignment(Node* n, std::shared_ptr<Type> lhs, std::shared_ptr<Type> rhs) {
  // lhs not pointer, rhs pointer
  if (!lhs->is_pointer() && rhs->is_pointer()) {
    SemanticError::raise(n->get_loc(), "Cannot assign pointer to non-pointer");
  } 
  
  // lhs is not l-value
  if (n->get_kid(1)->is_literal() || lhs->is_function() || (lhs->is_struct() && !lhs->is_pointer()) || lhs->is_array()) {
    SemanticError::raise(n->get_loc(), "Cannot assign to non-lvalue");
  }
  
  // lhs is const
  if (lhs->is_const() && !lhs->is_pointer()) {
    SemanticError::raise(n->get_loc(), "Cannot assign to const lvalue");
  }

  // find lhs underlying type (in case it's pointer)
  std::shared_ptr<Type> lhs_underlying = lhs;
  while (lhs_underlying->is_pointer()) {
    lhs_underlying = lhs_underlying->get_base_type();
  }

  // find rhs underlying type (in case it's pointer)
  std::shared_ptr<Type> rhs_underlying = rhs;
  while (rhs_underlying->is_pointer()) {
    rhs_underlying = rhs_underlying->get_base_type();
  }

  // if both pointers, check for const, volatile, and type compatability
  if (lhs->is_pointer() && rhs->is_pointer()) {
    if (!lhs_underlying->is_volatile() && rhs_underlying->is_volatile())
      SemanticError::raise(n->get_loc(), "lhs is not volatile");
    if (!lhs_underlying->get_unqualified_type()->is_same(rhs_underlying->get_unqualified_type()))
      SemanticError::raise(n->get_loc(), "lhs type does not match rhs type");
    if (!lhs_underlying->is_const() && rhs_underlying->is_const())
      SemanticError::raise(n->get_loc(), "lhs is not const");
  } else if (lhs->is_struct() != rhs->is_struct()) { // one is struct, other is not
      SemanticError::raise(n->get_loc(), "Mismatched struct types");
  }
}