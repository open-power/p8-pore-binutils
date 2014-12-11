/* Header file for PORE opcode table.
   Copyright 2011 Free Software Foundation, Inc.
   Written by Alan Modra, IBM

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef PORE_H
#define PORE_H 1

enum pore_reg_index {
  P0    = 0x0,
  P1    = 0x1,
  A0    = 0x2,
  A1    = 0x3,
  CTR   = 0x4,
  D0    = 0x5,
  D1    = 0x6,
  EMR   = 0x7,
  ETR   = 0x9,
  SPRG0 = 0xa,
  PC    = 0xe,
  IFR   = 0xf,
};

struct pore_reg {
  char name[16];
};

/* Describe a PORE instruction operand.  */
struct pore_operand {
  /* Syntax flags.  */
  unsigned int flags;
  /* Operand is a register.  */
#define PORE_REG	  0x1
  /* Operand is an immediate or symbol.  */
#define PORE_IMM	  0x2
  /* Immediate is pc-relative offset.  */
#define PORE_PCREL	  0x4
  /* Immediate is signed.  */
#define PORE_SIGNED	  0x8
  /* Immediate should be disassembled as an address.  */
#define PORE_ADDR	 0x10
  /* Immediate has restricted set of values, for ROL insn.  */
#define PORE_ROTATE	 0x20
  /* Immediate isn't allowed to be zero.  */
#define PORE_NON_ZERO	 0x40
  /* For Imm we have complicated range checks,
     for a Reg it is base for ld, ldandi, std.  */
#define PORE_IMA24	 0x80
  /* Reg is dest for ld, ldandi insns or source for std.  Affects opcode.  */
#define PORE_IMA24_DEST	0x100
  /* Operand is optional syntactic sugar.  */
#define PORE_OPTIONAL	0x200
  /* Operand goes into 64-bit word of large insn.  */
#define PORE_LARGE	0x400

  /* How far the operand is left shifted in the instruction.
     -1 to indicate that this operand has special treatment.  */
  int shift;

  union {
    /* For register operands, a mask of allowable registers.  */
    unsigned int mask;
    /* For immediate operands, the number of bits in the field.  */
    int bits;
  } u;
};

/* Describe a PORE opcode.  */
struct pore_opcode {
  /* Opcode, goes in msb of insn.  */
  unsigned char op;

  /* Mnemonic.  */
  char name[10];

  /* An array of operand codes.  Each code is an index into the
     operand table.  They appear in the order which the operands
     appear in assembly code, and are terminated by a zero.  */
  unsigned char operands[6];
};

#define NUM_PORE_REGS 16
#define NUM_PORE_OPERAND_TYPES 31

extern const struct pore_reg pore_register[NUM_PORE_REGS];
extern const struct pore_reg pore_hw_register[NUM_PORE_REGS];
extern const struct pore_operand pore_operand_types[NUM_PORE_OPERAND_TYPES];
extern const struct pore_opcode pore_opcodes[];
extern const int num_pore_opcodes;
extern const struct pore_opcode pore_hw_opcodes[];
extern const int num_pore_hw_opcodes;

#endif
