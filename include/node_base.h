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

#ifndef NODE_BASE_H
#define NODE_BASE_H

#include <memory>
#include "type.h"
#include "symtab.h"
#include "literal_value.h"
#include "has_operand.h"

//! The Node class will inherit from this type, so you can use it
//! to define any attributes and methods that Node objects should have
//! (constant value, results of semantic analysis, code generation info,
//! etc.)
//!
//! Because NodeBase inherits from HasOperand, each Node automatically
//! stores an Operand. This is useful for code generation: when
//! generating code to evaluate an expression, HighLevelCodegen
//! can set the Node's Operation to indicate the location where the
//! result of the evaluation is stored.
class NodeBase : public HasOperand {
private:
  // copy ctor and assignment operator not supported
  NodeBase(const NodeBase &);
  NodeBase &operator=(const NodeBase &);
  std::shared_ptr<Type> m_type;
  Symbol* m_symbol;
  bool literal;
  unsigned m_total_local_storage;
  std::string str_lit_name;

public:
  NodeBase();
  virtual ~NodeBase();

  void set_symbol(Symbol *symbol);
  void set_type(const std::shared_ptr<Type> &type);
  bool has_symbol() const;
  Symbol* get_symbol() const;
  std::shared_ptr<Type> get_type() const;
  void override_type(const std::shared_ptr<Type> &type);
  void make_literal();
  bool is_literal();
  void set_total_local_storage(unsigned size);
  unsigned get_total_local_storage();
  void set_str_lit_name(std::string value);
  std::string get_str_lit_name();
};

#endif // NODE_BASE_H
