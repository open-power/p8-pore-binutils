/* Disassemble PORE/SBE instructions.
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

#include "sysdep.h"
#include "opcode/pore.h"
#include "bfd_stdint.h"
#include "dis-asm.h"

/* Extract the operand value from the PORE instruction.  */

static bfd_boolean
operand_value (const struct pore_operand *operand,
	       const uint32_t *insn,
	       uint64_t *valp)
{
  uint64_t value;

  if ((operand->flags & PORE_LARGE) != 0)
    {
      value = insn[1] & 0xffffffff;
      value <<= 32;
      value |= insn[2] & 0xffffffff;
    }
  else
    value = insn[0] & 0xffffffff;

  if (operand->shift > 0)
    value >>= operand->shift;
  if ((operand->flags & PORE_REG) != 0)
    {
      if (operand->shift < 0)
	{
	  /* This register isn't encoded in the usual 4-bit field.  */
	  if ((operand->flags & PORE_IMA24_DEST) != 0)
	    {
	      /* Extract the register from the opcode.  */
	      if ((value & (1 << 28)) != 0)
		/* scr1wr 0x39, scr2wr 0x3a */
		value = ((value >> 26) & 1) + D0;
	      else
		/* scr1rd 0x32, scr2rd 0x36, scr1rda 0x73, scr2rda 0x77 */
		value = ((value >> 27) & 1) + D0;
	    }
	  else if ((operand->flags & PORE_IMA24) != 0)
	    {
	      value >>= 22;
	      value &= 3;
	      value += P0;
	    }
	  else if (operand->u.mask == (1 << D0))
	    /* Syntactic sugar, optD0.  */
	    value = D0;
	  else if (operand->u.mask == (1 << D1))
	    /* Syntactic sugar, optD1.  */
	    value = D1;
	  else
	    /* Syntactic sugar, optDup.  */
	    value >>= 20;
	}
      value &= 15;
      *valp = value;
      return (operand->u.mask & (1 << value)) != 0;
    }
  else
    {
      uint64_t sign = (uint64_t) 1 << (operand->u.bits - 1);

      value &= (sign << 1) - 1;
      if ((operand->flags & PORE_SIGNED) != 0)
	{
	  value ^= sign;
	  value -= sign;
	}
      *valp = value;
      return (operand->flags & PORE_NON_ZERO) == 0 || value != 0;
    }
}

/* Print the PORE insn at ADDR.  Return the number of bytes in the
   instruction, or -1 on error.  */
int
print_insn_pore (bfd_vma addr, struct disassemble_info *info)
{
  bfd_byte buf[4];
  uint32_t insn[3];
  int status, lo, hi, mid;
  unsigned char op;
  const unsigned char *opindex;

  status = info->read_memory_func (addr, buf, 4, info);
  if (status != 0)
    goto fail;

  insn[0] = bfd_getb32 (buf);
  if ((insn[0] & 0x80000000) != 0)
    {
      status = info->read_memory_func (addr + 4, buf, 4, info);
      if (status != 0)
	goto fail;
      insn[1] = bfd_getb32 (buf);
      status = info->read_memory_func (addr + 8, buf, 4, info);
      if (status != 0)
	goto fail;
      insn[2] = bfd_getb32 (buf);
    }

  lo = 0;
  hi = num_pore_opcodes;
  op = (insn[0] >> 24) & 0xfe;
  while (lo < hi)
    {
      mid = (lo + hi) / 2;
      if (pore_opcodes[mid].op < op)
	lo = mid + 1;
      else if (pore_opcodes[mid].op > op)
	hi = mid;
      else
	break;
    }
  if (lo < hi)
    {
      bfd_boolean invalid;

      while (mid != lo && pore_opcodes[mid - 1].op == op)
	--mid;

      /* Check that all the operands are valid.  We do this to select
	 between la, lia and li, or halt and waits.  */
      do
	{
	  invalid = FALSE;
	  for (opindex = pore_opcodes[mid].operands; *opindex; opindex++)
	    {
	      uint64_t opval;
	      if (!operand_value (&pore_operand_types[*opindex], insn, &opval))
		{
		  invalid = TRUE;
		  break;
		}
	    }
	}
      while (invalid && ++mid < hi && pore_opcodes[mid].op == op);

      /* Print the insn even if we didn't get a register match.  */
      if (invalid)
	--mid;

      if (pore_opcodes[mid].operands[0] != 0)
	(*info->fprintf_func) (info->stream, "%-7s ", pore_opcodes[mid].name);
      else
	(*info->fprintf_func) (info->stream, "%s", pore_opcodes[mid].name);

      for (opindex = pore_opcodes[mid].operands; *opindex; opindex++)
	{
	  uint64_t opval;

	  operand_value (&pore_operand_types[*opindex], insn, &opval);
	  if (opindex != pore_opcodes[mid].operands)
	    (*info->fprintf_func) (info->stream, ",");
	  if ((pore_operand_types[*opindex].flags & PORE_REG) != 0)
	    (*info->fprintf_func) (info->stream, "%s",
				   pore_register[opval].name);
	  else if ((pore_operand_types[*opindex].flags & PORE_ADDR) != 0)
	    {
	      if ((pore_operand_types[*opindex].flags & PORE_PCREL) != 0)
		{
		  /* Display pcrel offset in bytes.  */
		  opval <<= 2;
		  opval += addr;
		}
	      (*info->print_address_func) (opval, info);
	    }
	  else
	    (*info->fprintf_func) (info->stream, "%#llx", (long long) opval);
	}
      return (insn[0] & 0x80000000) != 0 ? 12 : 4;
    }

  (*info->fprintf_func) (info->stream, ".long %#x", insn[0]);
  return 4;

 fail:
  (*info->memory_error_func) (status, addr, info);
  return -1;
}
