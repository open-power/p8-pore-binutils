/* Assemble code for PORE/SBE.
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

#include "as.h"
#include "bfd_stdint.h"
#include "opcode/pore.h"
#include "elf/pore.h"

/* Characters which start a comment anywhere.  */
const char comment_chars[] = "#";

/* Characters which start a comment at the beginning of a line.  */
const char line_comment_chars[] = "#";

/* Characters which may be used to separate multiple commands on a
   single line.  */
const char line_separator_chars[] = ";";

/* Characters which are used to indicate an exponent in a floating
   point number.  */
const char EXP_CHARS[] = "eE";

/* Characters which mean that a number is a floating point constant,
   as in 0d1.0.  */
const char FLT_CHARS[] = "dD";

/* Whether gas should accept the hardware mnemonics and registers.  */
static int hardware;

/* The PIB port for PIB memory relocations. */
static int pibmem_port = -1;

const char *md_shortopts = "";

struct option md_longopts[] =
{
  {"hardware", no_argument, &hardware, 1},
};
size_t md_longopts_size = sizeof (md_longopts);

/* Opcode hash table.  */
static struct hash_control *opcode_hash;

/* Whether emitted words should have insn parity bit.  */
static void set_parity (int);

/* Set the PIB port for PIB memory relocatable addresses */
static void set_pibmem_port (int);

/* The target specific pseudo-ops which we support.  */
const pseudo_typeS md_pseudo_table[] =
{
  { "parity", set_parity, PORE_FEATURE_PARITY_ON },
  { "noparity", set_parity, PORE_FEATURE_PARITY_OFF },
  { "pibmem_port", set_pibmem_port, 0},
  { 0, 0, 0 }
};

int
md_parse_option (int c, char *arg ATTRIBUTE_UNUSED)
{
  return c == 0;
}

void
md_show_usage (FILE *stream)
{
  fprintf (stream, _("\
PORE/SBE options:\n\
-hardware               recognize base hardware mnemonics\n"));
}

/* This function is called when the assembler starts up.  It is called
   after the options have been parsed and the output file has been
   opened.  */
void
md_begin (void)
{
  const struct pore_opcode *op;
  int i;

  /* Insert the opcodes into a hash table.  */
  opcode_hash = hash_new ();

  /* Note that hash_insert drops duplicates.  */
  for (op = pore_opcodes; op < pore_opcodes + num_pore_opcodes; op++)
    hash_insert (opcode_hash, op->name, (void *) op);

  if (hardware)
    for (op = pore_hw_opcodes; op < pore_hw_opcodes + num_pore_hw_opcodes; op++)
      hash_insert (opcode_hash, op->name, (void *) op);

  /* Predefine register symbols, both lowercase and uppercase versions.  */
  do
    for (i = 0; i < NUM_PORE_REGS; i++)
        if (strcmp(pore_register[i].name,"?") != 0) 
          {
            local_symbol_make (pore_register[i].name,
                               &bfd_abs_section, i, &zero_address_frag);
          }
  while ((symbols_case_sensitive ^= 1) == 0);

  if (hardware)
    do
      for (i = 0; i < NUM_PORE_REGS; i++)
        if (strcmp(pore_hw_register[i].name,"?") != 0) 
            {
              local_symbol_make (pore_hw_register[i].name,
                                 &bfd_abs_section, i, &zero_address_frag);
            }
    while ((symbols_case_sensitive ^= 1) == 0);
}

/* Print an informative error about the set of registers allowed,
   given by MASK.  */
static void
register_expected (unsigned int mask, char *file, unsigned int line)
{
  char buf[80];
  char *p;
  int i;

  for (p = buf, i = 0; i < NUM_PORE_REGS; i++)
    if ((mask & (1 << i)) != 0)
      {
	unsigned int len = strlen (pore_register[i].name);

	mask -= 1 << i;
	if (p != buf)
	  {
	    *p++ = ',';
	    *p++ = ' ';
	    if (mask == 0)
	      {
		strcpy (p, _("or "));
		p += strlen (p);
	      }
	  }
	memcpy (p, pore_register[i].name, len);
	p += len;
      }
  *p = 0;
  as_bad_where (file, line, _("expected %s"), buf);
}

/* Poke OPERAND having value VAL into INSN.  */
static void
pore_operand_insert (uint32_t *insn,
		     const struct pore_operand *operand,
		     int64_t val,
		     char *file,
		     unsigned int line)
{
  int64_t mask;

  if ((operand->flags & PORE_REG) != 0)
    {
      if ((operand->flags & PORE_OPTIONAL) != 0
	  && operand->u.mask == (unsigned) -1)
	{
	  /* This operand must duplicate the previous operand.
	     We know the previous operand was a reg and where
	     it was stored.  */
	  int prev = (insn[0] >> 20) & 0xf;
	  if (val != prev)
	    {
	      register_expected (1 << prev, file, line);
	      return;
	    }
	}
      else if ((uint64_t) val > NUM_PORE_REGS
	       || (operand->u.mask & (1 << val)) == 0)
	{
	  register_expected (operand->u.mask, file, line);
	  return;
	}
      if ((operand->flags & PORE_OPTIONAL) != 0)
	return;
      if ((operand->flags & PORE_IMA24_DEST) != 0)
	{
	  /* This operand affects the high byte of the opcode.
	     scr1rd 0x32 -> scr2rd 0x36
	     scr1wr 0x39 -> scr2wr 0x3a
	     scr1rda 0x73 -> scr2rda 0x77  */
	  gas_assert (val == D0 || val == D1);
	  gas_assert (insn[0] >> 25 == 0x32
		      || insn[0] >> 25 == 0x39
		      || insn[0] >> 25 == 0x73);
	  if (val == D1)
	    {
	      if (insn[0] >> 25 == 0x39)
		insn[0] ^= 3 << 25;
	      else
		insn[0] ^= 4 << 25;
	    }
	}
      else if ((operand->flags & PORE_IMA24) != 0)
	{
	  gas_assert (val == P0 || val == P1 || val == A0 || val == A1);
	  insn[0] |= (val & 3) << 22;
	}
      else
	insn[0] |= val << operand->shift;
      return;
    }

  gas_assert (operand->flags & PORE_IMM);
  if ((operand->flags & PORE_PCREL) != 0)
    {
      /* PC-relative offsets are in multiples of a 32-bit word.  */
      if ((val & 3) != 0)
	{
	  as_bad_where (file, line, _("offset must be a multiple of 4"));
	  return;
	}
      val >>= 2;
    }
  if (operand->u.bits != 64)
    {
      if ((operand->flags & PORE_IMA24) != 0 && (insn[0] & (2 << 22)) == 0)
	{
	  /* This is an offset for a P0/P1 base IMA24.  Ignore (some)
	     high bits of the offset, and check against a 20-bit range.  */
	  uint64_t max = (1 << 20) - 1;

	  val &= ~(uint64_t) 0x7F000000;
	  if ((uint64_t) val > max)
	    {
	      as_bad_value_out_of_range (_("operand"), val, 0, max,
					 file, line);
	      return;
	    }
	}
      else if ((operand->flags & PORE_SIGNED) != 0)
	{
	  int64_t min, max;
	  min = -1;
	  max = 1;
	  min <<= operand->u.bits - 1;
	  max <<= operand->u.bits - 1;
	  max -= 1;
	  if (val < min || val > max)
	    {
	      as_bad_value_out_of_range (_("operand"), val, min, max,
					 file, line);
	      return;
	    }
	}
      else
	{
	  uint64_t max;
	  max = 1;
	  max <<= operand->u.bits;
	  max -= 1;
	  if ((uint64_t) val > max)
	    {
	      as_bad_value_out_of_range (_("operand"), val, 0, max,
					 file, line);
	      return;
	    }
	}
    }
  /* if ((operand->flags & PORE_ROTATE) != 0)   // check removed since it is supported in new SBE
    {
      if (val != 1 && val != 4 && val != 8 && val != 16 && val != 32)
	{
	  as_bad_where (file, line, _("shift count must be 1, 4, 8, 16 or 32"));
	  return;
	}
    }
  else */ if ((operand->flags & PORE_NON_ZERO) != 0)
    {
      if (val == 0)
	{
	  as_bad_where (file, line, _("non-zero value expected"));
	  return;
	}
    }
  val <<= operand->shift;
  mask = 1;
  mask <<= (operand->u.bits - 1);
  mask = (mask << 1) - 1;
  mask <<= operand->shift;
  if ((operand->flags & PORE_LARGE) != 0)
    {
      insn[1] |= (val & mask) >> 32;
      insn[2] |= val & mask & 0xffffffff;
    }
  else
    insn[0] |= val & mask;
}

/* This struct stores information about instruction operands that we
   can't evaluate immediately.  */
struct pore_fixup
{
  expressionS exp;
  int opindex;
};
#define MAX_INSN_FIXUPS 5

/* This function is called for each instruction to be assembled.  */
void
md_assemble (char *str)
{
  char *s, *f;
  const struct pore_opcode *opcode;
  const unsigned char *opindex;
  uint32_t insn[3];
  struct pore_fixup fixups[MAX_INSN_FIXUPS];
  int insn_size, nfix, i;
  bfd_boolean skip_optional, skip_comma;
  unsigned int addr_mod;

  s = str;
  while (!is_end_of_line[(unsigned char) *s] && *s != ' ')
    s++;
  if (*s != '\0')
    *s++ = '\0';

  opcode = (const struct pore_opcode *) hash_find (opcode_hash, str);
  if (opcode == NULL)
    {
      as_bad (_("unrecognized opcode: `%s'"), str);
      return;
    }

  str = s;
  while (*str == ' ')
    str++;

  /* If this instruction can have optional operands, count commas to
     see whether all operands are supplied.  Optional operands must
     either be all present or all absent.  */
  skip_optional = FALSE;
  for (opindex = opcode->operands; *opindex; opindex++)
    if ((pore_operand_types[*opindex].flags & PORE_OPTIONAL) != 0)
      break;
  if (*opindex)
    {
      unsigned int supplied;
      unsigned int expected;
      unsigned int optional;

      /* Count operands supplied.  */
      supplied = 0;
      s = str;
      if (*s)
	{
	  ++supplied;
	  while ((s = strchr (s, ',')) != NULL)
	    {
	      ++supplied;
	      ++s;
	    }
	}

      /* Count operands in template.  */
      expected = 0;
      optional = 0;
      for (opindex = opcode->operands; *opindex; opindex++)
	{
	  ++expected;
	  if ((pore_operand_types[*opindex].flags & PORE_OPTIONAL) != 0)
	    ++optional;
	}

      if (supplied + optional == expected)
	skip_optional = TRUE;
      else if (supplied != expected)
	{
	  as_bad (_("optional operands must all be present or all absent"));
	  return;
	}
    }

  /* Gather all operands, inserting into insn or creating fixups as
     we go.  */
  insn[0] = opcode->op << 24;
  insn[1] = 0;
  insn[2] = 0;
  nfix = 0;
  skip_comma = FALSE;
  for (opindex = opcode->operands; *opindex; opindex++)
    {
      expressionS exp;
      const struct pore_operand *operand = &pore_operand_types[*opindex];
      char *save;

      if (skip_optional
	  && (operand->flags & PORE_OPTIONAL) != 0)
	continue;

      if (*str != 0 && skip_comma)
	{
	  if (*str != ',')
	    as_bad (_("syntax error at `%c', expecting `,'"), *str);
	  ++str;
	}

      /* Operands are just an expression.  */
      save = input_line_pointer;
      input_line_pointer = str;
      expression (&exp);
      str = input_line_pointer;
      input_line_pointer = save;

      if (exp.X_op == O_illegal)
	as_bad (_("illegal operand"));
      else if (exp.X_op == O_absent)
	as_bad (_("missing operand"));
      else if ((exp.X_op == O_register
		|| exp.X_op == O_constant)
	       && (operand->flags & (PORE_IMM | PORE_IMA24))
		   != (PORE_IMM | PORE_IMA24))
	{
	  pore_operand_insert (insn, operand, exp.X_add_number, NULL, 0);
	  /* Ima24 operands alway come in an offset/base pair, but we
	     want to process the base first because the offset range
	     depends on the base.  We accomplish this by simply poking
	     the offset into FIXUPS and processing it when we have the
	     base.  */
	  if ((operand->flags & (PORE_REG | PORE_IMA24))
	      == (PORE_REG | PORE_IMA24)
	      && (fixups[nfix - 1].exp.X_op == O_register
		  || fixups[nfix - 1].exp.X_op == O_constant))
	    {
	      --nfix;
	      pore_operand_insert (insn,
				   &pore_operand_types[fixups[nfix].opindex],
				   fixups[nfix].exp.X_add_number, NULL, 0);
	    }
	}
      else
	{
	  /* We need to generate a fixup for this expression.  */
	  if (nfix >= MAX_INSN_FIXUPS)
	    as_fatal (_("too many fixups"));
	  fixups[nfix].exp = exp;
	  fixups[nfix].opindex = *opindex;
	  ++nfix;
	}
      skip_comma = TRUE;
    }

  while (*str == ' ')
    ++str;

  if (*str != '\0')
    as_bad (_("junk at end of line: `%s'"), str);

  /* Write out the instruction.  */
  insn_size = (insn[0] & 0x80000000) != 0 ? 12 : 4;
  f = frag_more (insn_size);
  addr_mod = frag_now_fix () & 3;
  if (frag_now->has_code && frag_now->insn_addr != addr_mod)
    as_bad (_("instruction address is not a multiple of 4"));
  frag_now->insn_addr = addr_mod;
  frag_now->has_code = 1;

  md_number_to_chars (f, insn[0], 4);
  if (insn_size == 12)
    {
      md_number_to_chars (f + 4, insn[1], 4);
      md_number_to_chars (f + 8, insn[2], 4);
    }

  dwarf2_emit_insn (insn_size);

  /* Create any fixups we need from our FIXUPS array.  */
  for (i = 0; i < nfix; i++)
    {
      const struct pore_operand *operand;
      int where;
      bfd_reloc_code_real_type fake_rel;

      operand = &pore_operand_types[fixups[i].opindex];
      where = f - frag_now->fr_literal;
      fake_rel = fixups[i].opindex + BFD_RELOC_UNUSED;
      fix_new_exp (frag_now, where, insn_size, &fixups[i].exp,
		   (operand->flags & PORE_PCREL) != 0, fake_rel);
    }
}

/* Apply a fixup.  This function is called after all lines of the
   source file have been seen for each of the fixups created by
   fix_new_exp above, and also for any data fixups that may have been
   created for expressions in data directives.  */
void
md_apply_fix (fixS *fix, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  uint64_t value = *valP;
  char *where;
  bfd_reloc_code_real_type r_type;

  if (fix->fx_addsy != NULL)
    {
      /* Hack around bfd_install_relocation brain damage.  */
      if (fix->fx_pcrel)
	value += fix->fx_frag->fr_address + fix->fx_where;
    }
  else
    fix->fx_done = 1;

  where = fix->fx_frag->fr_literal + fix->fx_where;
  if (fix->fx_subsy != NULL)
    {
      /* We don't support subtracting a symbol.  */
      r_type = BFD_RELOC_UNUSED;
    }
  else if (fix->fx_r_type < BFD_RELOC_UNUSED)
    {
      /* Data fixups.  */
      r_type = fix->fx_r_type;
      switch (r_type)
	{
	case BFD_RELOC_64:
	  if (fix->fx_pcrel)
	    r_type = BFD_RELOC_64_PCREL;
	  /* fall thru */
	case BFD_RELOC_64_PCREL:
	  md_number_to_chars (where, value, 8);
	  break;

	case BFD_RELOC_32:
	case BFD_RELOC_CTOR:
	  if (fix->fx_pcrel)
	    r_type = BFD_RELOC_32_PCREL;
	  /* fall thru */
	case BFD_RELOC_32_PCREL:
	  md_number_to_chars (where, value, 4);
	  break;

	case BFD_RELOC_16:
	  if (fix->fx_pcrel)
	    r_type = BFD_RELOC_16_PCREL;
	  /* fall thru */
	case BFD_RELOC_16_PCREL:
	  md_number_to_chars (where, value, 2);
	  break;

	case BFD_RELOC_8:
	  if (fix->fx_pcrel)
	    r_type = BFD_RELOC_8_PCREL;
	  /* fall thru */
	case BFD_RELOC_8_PCREL:
	  md_number_to_chars (where, value, 1);
	  break;

	case BFD_RELOC_PORE_FEATURE:
	  fix->fx_done = FALSE;
	  break;

	default:
	  r_type = BFD_RELOC_UNUSED;
	}
    }
  else
    {
      /* Insn fixups.  */
      int opindex = fix->fx_r_type - BFD_RELOC_UNUSED;
      const struct pore_operand *operand = &pore_operand_types[opindex];
      uint32_t insn[3];

      /* Fetch the instruction.  */
      insn[0] = bfd_getb32 (where);
      if ((operand->flags & PORE_LARGE) != 0)
	{
	  insn[1] = bfd_getb32 (where + 4);
	  insn[2] = bfd_getb32 (where + 8);
	}

      /* Poke in the fully resolved value.  */
      pore_operand_insert (insn, operand, value, fix->fx_file, fix->fx_line);

      /* Write updated instruction.  */
      bfd_putb32 (insn[0], where);
      if ((operand->flags & PORE_LARGE) != 0)
	{
	  bfd_putb32 (insn[1], where + 4);
	  bfd_putb32 (insn[2], where + 8);
	}

      if (fix->fx_done)
	return;

      /* OK, so it wasn't fully resolved.  We'll need to generate
	 relocations.  Not all fields of an instruction may be
	 relocated, for example, no register select field can be
	 relocated.  */
      r_type = BFD_RELOC_UNUSED;
      if ((operand->flags & PORE_IMM) != 0)
	{
	  if ((operand->flags & PORE_LARGE) != 0)
	    {
	      if (operand->u.bits == 64)
		/* cmpibra, cmpinbra, cmpbsr, andi, ori, xori, li, ldandi,
		   bsi, bci, sti 64-bit immediate.  */
		{
		  r_type = BFD_RELOC_64;
		  fix->fx_where += 4;
		  fix->fx_size = 8;
		}
	      else if (operand->u.bits == 32)
		{
		  if (operand->shift == 0)
		    {
		      if ((operand->flags & PORE_PCREL) != 0)
			{
			  /* scand word_addr_offset.  */
			  r_type = BFD_RELOC_PORE_PCREL32;
			  value += 8;
			}
		      else
			/* la, brai, lia address
			   (high 16 bits not relocated).  */
			r_type = BFD_RELOC_32;
		      fix->fx_where += 8;
		      fix->fx_size = 4;
		    }
		}
	    }
	  else
	    {
	      if (operand->u.bits == 16)
		{
		  if (operand->flags == (PORE_IMM | PORE_SIGNED))
		    {
		      /* adds, subs immediate.  */
		      r_type = BFD_RELOC_16;
		      fix->fx_where += 2;
		      fix->fx_size = 2;
		    }
		}
	      else if (operand->u.bits == 20)
		{
		  if ((operand->flags & PORE_PCREL) != 0)
		    /* braz, branz pc-offset.  */
		    r_type = BFD_RELOC_PORE_PCREL20;
		  else
		    /* ls immediate.  */
		    r_type = BFD_RELOC_20;
		}
	      else if (operand->u.bits == 22)
		{
		  /* ld, std, ldandi, bsi, bci, sti. 
                     
                  Relocations against A0/A1 are currently disallowed. If they
		  were allowed they would use r_type = BFD_RELOC_PORE_22.

                  Relocations against P0/P1 are allowed if the assembly
		  includes the .pibmem_port directive.  The PIB memory
		  port is inserted into the instruction, and any byte offset
		  previously inserted by the assembler is converted into a
		  word offset - which really only affects the assembler
		  listing. The programmer is responsible for the correct
		  contents of P0/P1.
                  */
                    if (insn[0] & 0x00800000) {
                        as_bad_where (fix->fx_file, fix->fx_line, 
                                      _("Relocatable offsets for A0/A1 "
                                        "are currently not supported"));
                    } else if (pibmem_port < 0) {
                        as_bad_where (fix->fx_file, fix->fx_line, 
                                      _("Relocatable offsets for P0/P1 "
                                        "are only allowed when the "
                                        ".pibmem_port directive "
                                        "is used"));
                    } else {
                        bfd_putb32 ((insn[0] & 0xfff00000) | 
                                    (pibmem_port << 16) |
                                    ((insn[0] & 0x7ffff) >> 3), 
                                    where);
                        r_type = BFD_RELOC_PORE_PIBMEM;
                    }
		}
	      else if (operand->u.bits == 24)
		{
		  if ((operand->flags & PORE_PCREL) != 0)
		    /* bra, bsr, loop, cmpibra, cmpinbra, cmpbsr pc-offset.  */
		    r_type = BFD_RELOC_PORE_PCREL24;
		}
	    }
	}
    }

  if (r_type == BFD_RELOC_UNUSED)
    {
      char *file;
      unsigned int line;

      if (fix->fx_subsy != NULL
	  || expr_symbol_where (fix->fx_addsy, &file, &line))
	as_bad_where (fix->fx_file, fix->fx_line, _("unresolved expression"));
      else
	as_bad_where (fix->fx_file, fix->fx_line,
		      _("unsupported relocation against %s"),
		      S_GET_NAME (fix->fx_addsy));
      fix->fx_done = 1;
      return;
    }

  fix->fx_r_type = r_type;
  fix->fx_addnumber = value;
  /* PORE uses RELA relocs.  If we are going to be emitting a reloc
     then the section contents are immaterial, so don't warn if they
     happen to overflow.  Leave such warnings to ld.  */
  if (!fix->fx_done)
    fix->fx_no_overflow = 1;
}

/* Generate a reloc for a fixup.  */
arelent *
tc_gen_reloc (asection *seg ATTRIBUTE_UNUSED, fixS *fix)
{
  arelent *reloc = (arelent *) xmalloc (sizeof (arelent));

  reloc->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fix->fx_addsy);
  reloc->address = fix->fx_frag->fr_address + fix->fx_where;
  reloc->addend = fix->fx_addnumber;
  reloc->howto = bfd_reloc_type_lookup (stdoutput, fix->fx_r_type);
  if (reloc->howto == NULL)
    {
      as_bad_where (fix->fx_file, fix->fx_line,
		    _("reloc %d not supported by object file format"),
		    fix->fx_r_type);
      return NULL;
    }

  return reloc;
}

/* IEEE floats, if a PORE program should ever need such.  */
char *
md_atof (int type, char *litp, int *sizep)
{
  return ieee_md_atof (type, litp, sizep, TRUE);
}

/* Handle .parity/.noparity directives.  This just arranges to emit a
   relocation at the location of the directive.  No attempt is made
   to merge multiple directives since tracking the parity generation
   state is not that simple if using subsections.  */
static void
set_parity (int on)
{
  int where = frag_now_fix_octets ();
  fix_new (frag_now, where, 0, NULL, on, FALSE, BFD_RELOC_PORE_FEATURE);
}

/* Handle the .pibmem_port directive, which sets the PIB port for relocatable
   PIB memory accesses.  This directive can only be used at most once per file
   because its effect is only used during the fixup phase of assembly.

   Arguably this relocation could/should be handled by the linker.  However
   the linker is not otherwise memory-space aware, and we already have the
   notion of memory-space aware assembly (e.g., the BRAA macro) so this
   implementation is consistent with current usage. */
static void
set_pibmem_port (int ignore ATTRIBUTE_UNUSED)
{
    int port;

    port = get_absolute_expression();
    if ((pibmem_port >= 0) && (pibmem_port != port)) {
        as_bad (_("The .pibmem_port directive was used multiple times "
                  "with different arguments"));
    } else if ((port < 0) || (port > 15)) {
        as_bad(_("Illegal port number: must be in the range 0,...,15"));
    } else {
        pibmem_port = port;
        demand_empty_rest_of_line();
    }
}
