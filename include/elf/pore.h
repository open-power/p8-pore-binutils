/* PORE ELF support for BFD.
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

#ifndef _ELF_PORE_H
#define _ELF_PORE_H

#include "elf/reloc-macros.h"

/* Relocations.  */
START_RELOC_NUMBERS (elf_pore_reloc_type)
RELOC_NUMBER (R_PORE_NONE,     0)
RELOC_NUMBER (R_PORE_64,       1)
RELOC_NUMBER (R_PORE_32,       2)
RELOC_NUMBER (R_PORE_16,       3)
RELOC_NUMBER (R_PORE_8,        4)
RELOC_NUMBER (R_PORE_REL64,    5)
RELOC_NUMBER (R_PORE_REL32,    6)
RELOC_NUMBER (R_PORE_REL16,    7)
RELOC_NUMBER (R_PORE_REL8,     8)
RELOC_NUMBER (R_PORE_22,       9)
RELOC_NUMBER (R_PORE_20,      10)
RELOC_NUMBER (R_PORE_PCREL32, 11)
RELOC_NUMBER (R_PORE_PCREL24, 12)
RELOC_NUMBER (R_PORE_PCREL20, 13)
RELOC_NUMBER (R_PORE_FEATURE, 14)
RELOC_NUMBER (R_PORE_PIBMEM,  15)
END_RELOC_NUMBERS (R_PORE_max)

/* R_PORE_FEATURE addend is used currently to enable or disable
   instruction parity generation.  An addend of zero disables parity.
   An addend of one enables parity.  Any other value does nothing.  */
#define PORE_FEATURE_PARITY_OFF 0
#define PORE_FEATURE_PARITY_ON  1

#endif
