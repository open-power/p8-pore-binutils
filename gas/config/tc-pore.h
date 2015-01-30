/* Header file for tc-pore.c.
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

#define IGNORE_NONSTANDARD_ESCAPES
#define TARGET_ARCH bfd_arch_pore
#define TARGET_FORMAT "elf64-pore"
#define TARGET_BYTES_BIG_ENDIAN 1

/* Permit temporary numeric labels.  */
#define LOCAL_LABELS_FB 1

/* "$" or "." is used to refer to the current location.  */
#define DOLLAR_DOT

/* foo-. gets turned into PC relative relocs.  */
#define DIFF_EXPR_OK

/* No need to handle .word strangely.  */
#define WORKING_DOT_WORD

/* This is a big-endian target.  */
#define md_number_to_chars number_to_chars_bigendian

/* Don't pad end of sections.  */
#define SUB_SEGMENT_ALIGN(SEG, FRCHAIN) 0

/* Error if code is misaligned.  */
#define md_frag_check(FRAGP) \
  if ((FRAGP)->has_code							\
      && (((FRAGP)->fr_address + (FRAGP)->insn_addr) & 3) != 0)		\
    as_bad_where ((FRAGP)->fr_file, (FRAGP)->fr_line,			\
		  _("instruction address is not a multiple of 4"));

/* No special alignment handling needed.  */
#define md_section_align(SEGMENT, SIZE)     (SIZE)

/* No relaxation.  */
#define md_convert_frag(B, S, F)            as_fatal (_("convert_frag\n"))
#define md_estimate_size_before_relax(A, B) (as_fatal (_("estimate size\n")),0)

/* All our predefined symbols are set at md_begin.  */
#define md_undefined_symbol(NAME)           0

/* No special operand handling.  */
#define md_operand(X)

/* PC relative relocations are relative to the reloc word.  */
#define md_pcrel_from(FIX) \
  ((FIX)->fx_frag->fr_address + (FIX)->fx_where)

/* No shared lib support, so we don't need to ensure externally
   visible symbols can be overridden.  */
#define EXTERN_FORCE_RELOC 0

/* Values passed to md_apply_fix don't include the symbol value.  */
#define MD_APPLY_SYM_VALUE(FIX) 0
