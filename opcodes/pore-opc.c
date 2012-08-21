/* PORE/SBE opcode list.
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

#include "opcode/pore.h"

const struct pore_reg pore_register[NUM_PORE_REGS] = {
  { "p0"    },
  { "p1"    },
  { "a0"    },
  { "a1"    },
  { "ctr"   },
  { "d0"    },
  { "d1"    },
  { "emr"   },
  { "?"     },
  { "etr"   },
  { "sprg0" },
  { "?"     },
  { "?"     },
  { "?"     },
  { "pc"    },
  { "ifr"   },
};

const struct pore_reg pore_hw_register[NUM_PORE_REGS] = {
  { "prv_base_addr0"  },
  { "prv_base_addr1"  },
  { "oci_base_addr0"  },
  { "oci_base_addr1"  },
  { "scratch0"        },
  { "scratch1"        },
  { "scratch2"        },
  { "error_mask"      },
  { "?"               },
  { "exe_trigger"     },
  { "data0"           },
  { "?"               },
  { "?"               },
  { "?"               },
  { "pc"              },
  { "ibuf_id"         },
};

#define LI_REG_MASK                                           \
  ((1 << A0) | (1 << A1) | (1 << CTR) | (1 << D0) | (1 << D1))
#define LS_REG_MASK                                           \
  ((1 << P0) | (1 << P1) | (1 << A0) | (1 << A1) | (1 << CTR) \
   | (1 << D0) | (1 << D1))
#define TCOPY_REG_MASK                                        \
  ((1 << P0) | (1 << P1) | (1 << A0) | (1 << A1) | (1 << CTR) \
  | (1 << D0) | (1 << D1) | (1 << SPRG0)		      \
  | (1 << PC) | (1 << EMR) | (1 << ETR))
#define SCOPY_REG_MASK                                        \
  ((1 << P0) | (1 << P1) | (1 << A0) | (1 << A1) | (1 << CTR) \
  | (1 << D0) | (1 << D1) | (1 << SPRG0)                      \
  | (1 << PC) | (1 << IFR) | (1 << EMR) | (1 << ETR))

const struct pore_operand pore_operand_types[NUM_PORE_OPERAND_TYPES] = {
  { 0, 0, {0} },

#define tD01 1
  { PORE_REG, 20, {(1 << D0) | (1 << D1)} },

#define tD01C tD01 + 1
  { PORE_REG, 20, {(1 << D0) | (1 << D1) | (1 << CTR)} },

#define tLI tD01C + 1
  { PORE_REG, 20, {LI_REG_MASK} },

#define tLIA tLI + 1
  { PORE_REG, 20, {(1 << D0) | (1 << D1) | (1 << A0) | (1 << A1)} },

#define tLS tLIA + 1
  { PORE_REG, 20, {LS_REG_MASK} },

#define tCopy tLS + 1
  { PORE_REG, 20, {TCOPY_REG_MASK} },

#define iD01 tCopy + 1
  { PORE_REG | PORE_IMA24_DEST, -1, {(1 << D0) | (1 << D1)} },

#define sD01 iD01 + 1
  { PORE_REG, 16, {(1 << D0) | (1 << D1)} },

#define sCopy sD01 + 1
  { PORE_REG, 16, {SCOPY_REG_MASK} },

#define optD0 sCopy + 1
  { PORE_REG | PORE_OPTIONAL, -1, {1 << D0} },

#define optD1 optD0 + 1
  { PORE_REG | PORE_OPTIONAL, -1, {1 << D1} },

#define optDup optD1 + 1
  { PORE_REG | PORE_OPTIONAL, -1, {-1} },

#define Im20 optDup + 1
  { PORE_IMM | PORE_ADDR | PORE_SIGNED, 0, {20} },

#define Im32 Im20 + 1
  { PORE_IMM | PORE_ADDR | PORE_LARGE, 0, {32} },

#define Im64 Im32 + 1
  { PORE_IMM | PORE_LARGE, 0, {64} },

#define ImPC20 Im64 + 1
  { PORE_IMM | PORE_ADDR | PORE_PCREL | PORE_SIGNED, 0, {20} },

#define ImPC24 ImPC20 + 1
  { PORE_IMM | PORE_ADDR | PORE_PCREL | PORE_SIGNED, 0, {24} },

#define ImU16 ImPC24 + 1
  { PORE_IMM | PORE_LARGE, 32, {16} },

#define ImS16 ImU16 + 1
  { PORE_IMM | PORE_SIGNED, 0, {16} },

#define ImU24 ImS16 + 1
  { PORE_IMM, 0, {24} },

#define ImU24Z ImU24 + 1
  { PORE_IMM | PORE_NON_ZERO, 0, {24} },

#define RotM ImU24Z + 1
  { PORE_IMM | PORE_ROTATE, 0, {16} },

#define ImA24Off RotM + 1
  { PORE_IMM | PORE_IMA24 | PORE_ADDR, 0, {22} },
#define ImA24Base ImA24Off + 1
  { PORE_REG | PORE_IMA24, -1, {(1 << P0) | (1 << P1) | (1 << A0) | (1 << A1)} },

#define ScanUp ImA24Base + 1
  { PORE_IMM, 23, {1} },
#define ScanCap ScanUp + 1
  { PORE_IMM, 22, {1} },
#define ScanLen ScanCap + 1
  { PORE_IMM, 0, {16} },
#define ScanSel ScanLen + 1
  { PORE_IMM | PORE_LARGE, 32, {32} },
#define ScanOff ScanSel + 1
  { PORE_IMM | PORE_ADDR | PORE_PCREL | PORE_SIGNED | PORE_LARGE, 0, {32} },
};

#define ImA24 ImA24Off, ImA24Base
#define ScanOP ScanUp, ScanCap, ScanLen, ScanSel, ScanOff

/* Main PORE opcode table.  These are the instructions that will be
   produced by the disassembler.  The assembler accepts these, plus
   more in pore_hw_opcodes.

   Fields are: opcode, mnemonic, operands.  Must be kept sorted by
   opcode.  In cases where the opcode is duplicated, the disassembler
   will select the first instruction that matches allowed registers in
   the operands.  */

const struct pore_opcode pore_opcodes[] = {
  { 0x01 * 2, "waits",     {ImU24Z}                },
  { 0x01 * 2, "halt",      {}                      },
  { 0x02 * 2, "trap",      {}                      },
  { 0x0f * 2, "nop",       {}                      },
  { 0x10 * 2, "bra",       {ImPC24}                },
  { 0x12 * 2, "braz",      {tD01C,  ImPC20}        },
  { 0x13 * 2, "branz",     {tD01C,  ImPC20}        },
  { 0x14 * 2, "bsr",       {ImPC24}                },
  { 0x15 * 2, "ret",       {}                      },
  { 0x1c * 2, "brad",      {tD01}                  },
  { 0x1d * 2, "bsrd",      {tD01}                  },
  { 0x1f * 2, "loop",      {ImPC24}                },
  { 0x23 * 2, "add",       {tD01,   optD0,  optD1} },
  { 0x24 * 2, "adds",      {tLS,    optDup, ImS16} },
  { 0x25 * 2, "and",       {tD01,   optD0,  optD1} },
  { 0x26 * 2, "or",        {tD01,   optD0,  optD1} },
  { 0x27 * 2, "xor",       {tD01,   optD0,  optD1} },
  { 0x28 * 2, "subs",      {tLS,    optDup, ImS16} },
  { 0x29 * 2, "sub",       {tD01,   optD0,  optD1} },
  { 0x2a * 2, "neg",       {tD01,   sD01}          },
  { 0x2c * 2, "mr",        {tCopy,  sCopy}         },
  { 0x2e * 2, "rols",      {tD01,   sD01,   RotM}  },
  { 0x2f * 2, "rors",      {tD01,   sD01,   RotM}  },
  { 0x30 * 2, "ls",        {tLS,    Im20}          },
  { 0x32 * 2, "ld",        {iD01,   ImA24}         },
  { 0x36 * 2, "ld",        {iD01,   ImA24}         },
  { 0x39 * 2, "std",       {iD01,   ImA24}         },
  { 0x3a * 2, "std",       {iD01,   ImA24}         },
  { 0x4f * 2, "hooki",     {ImU24,  Im64}          },
  { 0x51 * 2, "braia",     {ImU16,  Im32}          },
  { 0x56 * 2, "cmpibraeq", {optD0,  ImPC24, Im64}  },
  { 0x57 * 2, "cmpibrane", {optD0,  ImPC24, Im64}  },
  { 0x58 * 2, "cmpibsreq", {optD0,  ImPC24, Im64}  },
  { 0x59 * 2, "cmpibragt", {optD0,  ImPC24, Im64}  },
  { 0x5A * 2, "cmpibralt", {optD0,  ImPC24, Im64}  },
  { 0x60 * 2, "andi",      {tD01,   sD01,   Im64}  },
  { 0x61 * 2, "ori",       {tD01,   sD01,   Im64}  },
  { 0x62 * 2, "xori",      {tD01,   sD01,   Im64}  },
  { 0x71 * 2, "lia",       {tLIA,   ImU16,  Im32}  },
  { 0x71 * 2, "li",        {tLI,    Im64}          },
  { 0x73 * 2, "ldandi",    {iD01,   ImA24,  Im64}  },
  { 0x74 * 2, "bsi",       {optD0,  ImA24,  Im64}  },
  { 0x75 * 2, "bci",       {optD0,  ImA24,  Im64}  },
  { 0x77 * 2, "ldandi",    {iD01,   ImA24,  Im64}  },
  { 0x78 * 2, "sti",       {ImA24,  Im64}          },
  { 0x78 * 2, "stia",      {ImA24,  ImU16,  Im32}  },
  { 0x7c * 2, "scand",     {ScanOP}                },
};

const int num_pore_opcodes = (sizeof (pore_opcodes)
			      / sizeof (pore_opcodes[0]));


/* Extra mnemonics the assembler accepts with -hardware.  Not used by
   the disassembler so doesn't need to be sorted.  */
const struct pore_opcode pore_hw_opcodes[] = {
  { 0x01 * 2, "wait",     {ImU24}                 },
  { 0x24 * 2, "addi",     {tLS,    ImS16}         },
  { 0x28 * 2, "subi",     {tLS,    ImS16}         },
  { 0x2c * 2, "copy",     {tCopy,  sCopy}         },
  { 0x2e * 2, "rol",      {tD01,   sD01,   RotM}  },
  { 0x2f * 2, "ror",      {tD01,   sD01,   RotM}  },
  { 0x4f * 2, "hook",     {ImU24,  Im64}          },
  { 0x51 * 2, "brai",     {ImU16,  Im32}          },
  { 0x56 * 2, "cmpbra",   {ImPC24, Im64}          },
  { 0x57 * 2, "cmpnbra",  {ImPC24, Im64}          },
  { 0x58 * 2, "cmpbsr",   {ImPC24, Im64}          },
  { 0x59 * 2, "cmpgt",    {optD0,  ImPC24, Im64}  },
  { 0x5A * 2, "cmplt",    {optD0,  ImPC24, Im64}  },
  { 0x30 * 2, "load20",   {tLS,    Im20}          },
  { 0x71 * 2, "load64",   {tLI,    Im64}          },
  { 0x32 * 2, "scr1rd",   {ImA24}                 },
  { 0x36 * 2, "scr2rd",   {ImA24}                 },
  { 0x39 * 2, "scr1wr",   {ImA24}                 },
  { 0x3a * 2, "scr2wr",   {ImA24}                 },
  { 0x73 * 2, "scr1rda",  {ImA24,  Im64}          },
  { 0x77 * 2, "scr2rda",  {ImA24,  Im64}          },
  { 0x78 * 2, "wri",      {ImA24,  Im64}          },
  { 0x74 * 2, "bs",       {ImA24,  Im64}          },
  { 0x75 * 2, "bc",       {ImA24,  Im64}          },
};

const int num_pore_hw_opcodes = (sizeof (pore_hw_opcodes)
				 / sizeof (pore_hw_opcodes[0]));
