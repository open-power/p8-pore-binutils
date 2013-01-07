/* PORE/SBE support for 64-bit ELF.
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
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/pore.h"

#define TARGET_BIG_SYM		bfd_elf64_pore_vec
#define TARGET_BIG_NAME		"elf64-pore"
#define ELF_ARCH		bfd_arch_pore
#define ELF_MACHINE_CODE	EM_PORE
#define ELF_MAXPAGESIZE		0x1000
#define elf_backend_rela_normal			1
#define bfd_elf64_bfd_reloc_type_lookup		pore_elf_reloc_type_lookup
#define bfd_elf64_bfd_reloc_name_lookup		pore_elf_reloc_name_lookup
#define elf_info_to_howto			pore_elf_info_to_howto
#define elf_backend_relocate_section		pore_elf_relocate_section

static reloc_howto_type pore_elf_howto_table[] = {
  /* This reloc does nothing.  */
  HOWTO (R_PORE_NONE,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_PORE_NONE",		/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A standard 64 bit relocation.  */
  HOWTO (R_PORE_64,
	 0,
	 4,
	 64,
	 FALSE,
	 0,
	 complain_overflow_dont,
	 bfd_elf_generic_reloc,
	 "R_PORE_64",
	 FALSE,
	 0,
	 (((bfd_vma) 1 << 63 << 1) - 1),
	 FALSE),

  /* A standard 32 bit relocation.  */
  HOWTO (R_PORE_32,
	 0,
	 2,
	 32,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_32",
	 FALSE,
	 0,
	 0xffffffff,
	 FALSE),

  /* A standard 16 bit relocation.  */
  HOWTO (R_PORE_16,
	 0,
	 1,
	 16,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_16",
	 FALSE,
	 0,
	 0xffff,
	 FALSE),

  /* A standard 8 bit relocation.  */
  HOWTO (R_PORE_8,
	 0,
	 0,
	 8,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_8",
	 FALSE,
	 0,
	 0xff,
	 FALSE),

  /* A standard 64 bit relative relocation.  */
  HOWTO (R_PORE_REL64,
	 0,
	 4,
	 64,
	 TRUE,
	 0,
	 complain_overflow_dont,
	 bfd_elf_generic_reloc,
	 "R_PORE_REL64",
	 FALSE,
	 0,
	 (((bfd_vma) 1 << 63 << 1) - 1),
	 TRUE),

  /* A standard 32 bit relative relocation.  */
  HOWTO (R_PORE_REL32,
	 0,
	 2,
	 32,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_REL32",
	 FALSE,
	 0,
	 0xffffffff,
	 TRUE),

  /* A standard 16 bit relative relocation.  */
  HOWTO (R_PORE_REL16,
	 0,
	 1,
	 16,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_REL16",
	 FALSE,
	 0,
	 0xffff,
	 TRUE),

  /* A standard 8 bit relative relocation.  */
  HOWTO (R_PORE_REL8,
	 0,
	 0,
	 8,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_REL8",
	 FALSE,
	 0,
	 0xff,
	 TRUE),

  /* A 22 bit relocation.  */
  HOWTO (R_PORE_22,
	 0,
	 2,
	 22,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_22",
	 FALSE,
	 0,
	 0x3fffff,
	 FALSE),

  /* A 20 bit relocation.  */
  HOWTO (R_PORE_20,
	 0,
	 2,
	 20,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_20",
	 FALSE,
	 0,
	 0xfffff,
	 FALSE),

  /* A 32-bit pc-relative offset counted in 32-bit words.  */
  HOWTO (R_PORE_PCREL32,
	 2,
	 2,
	 32,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_PCREL32",
	 FALSE,
	 0,
	 0xffffffff,
	 TRUE),

  /* A 24-bit pc-relative offset counted in 32-bit words.  */
  HOWTO (R_PORE_PCREL24,
	 2,
	 2,
	 24,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_PCREL24",
	 FALSE,
	 0,
	 0xffffff,
	 TRUE),

  /* A 20-bit pc-relative offset counted in 32-bit words.  */
  HOWTO (R_PORE_PCREL20,
	 2,
	 2,
	 20,
	 TRUE,
	 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_PORE_PCREL20",
	 FALSE,
	 0,
	 0xfffff,
	 TRUE),

  /* A marker reloc, used to control parity generation.  */
  HOWTO (R_PORE_FEATURE,
	 0,
	 2,
	 32,
	 FALSE,
	 0,
	 complain_overflow_dont,
	 bfd_elf_generic_reloc,
	 "R_PORE_FEATURE",
	 FALSE,
	 0,
	 0,
	 FALSE),

  /* A 16-bit relocation for PIB memory access */
  HOWTO (R_PORE_PIBMEM,
	 3,                    
	 2,
	 16,
	 FALSE,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_PORE_PIBMEM",
	 FALSE,
	 0,
	 0xffff,
	 FALSE),
};

static reloc_howto_type *
pore_elf_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    bfd_reloc_code_real_type code)
{
  enum elf_pore_reloc_type r;

  switch (code)
    {
    default:
      return NULL;

    case BFD_RELOC_NONE:		r = R_PORE_NONE;	break;
    case BFD_RELOC_64:			r = R_PORE_64;		break;
    case BFD_RELOC_32:			r = R_PORE_32;		break;
    case BFD_RELOC_16:			r = R_PORE_16;		break;
    case BFD_RELOC_8:			r = R_PORE_8;		break;
    case BFD_RELOC_64_PCREL:		r = R_PORE_REL64;	break;
    case BFD_RELOC_32_PCREL:		r = R_PORE_REL32;	break;
    case BFD_RELOC_16_PCREL:		r = R_PORE_REL16;	break;
    case BFD_RELOC_8_PCREL:		r = R_PORE_REL8;	break;
    case BFD_RELOC_PORE_22:		r = R_PORE_22;		break;
    case BFD_RELOC_20:			r = R_PORE_20;		break;
    case BFD_RELOC_PORE_PCREL32:	r = R_PORE_PCREL32;	break;
    case BFD_RELOC_PORE_PCREL24:	r = R_PORE_PCREL24;	break;
    case BFD_RELOC_PORE_PCREL20:	r = R_PORE_PCREL20;	break;
    case BFD_RELOC_PORE_FEATURE:	r = R_PORE_FEATURE;	break;
    case BFD_RELOC_PORE_PIBMEM:         r = R_PORE_PIBMEM;	break;
    };

  return pore_elf_howto_table + r;
}

static reloc_howto_type *
pore_elf_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (pore_elf_howto_table) / sizeof (pore_elf_howto_table[0]);
       i++)
    if (strcasecmp (pore_elf_howto_table[i].name, r_name) == 0)
      return pore_elf_howto_table + i;

  return NULL;
}

static void
pore_elf_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED,
			arelent *cache_ptr,
			Elf_Internal_Rela *dst)
{
  unsigned int r;

  r = ELF64_R_TYPE (dst->r_info);
  BFD_ASSERT (r < (unsigned int) R_PORE_max);

  cache_ptr->howto = pore_elf_howto_table + r;
}

/* Calculate even parity for X.  */
static inline unsigned int
parity (unsigned int x)
{
#if (GCC_VERSION > 3004)
  return __builtin_parity (x);
#else
  x ^= x >> 16;
  x ^= x >> 8;
  x ^= x >> 4;
  x &= 0xf;
  return (0x6996 >> x) & 1;
#endif
}

/* Set parity bits for instructions from CONTENTS + START up to but
   not including CONTENTS + END.  PORE/SBE uses odd parity in bit
   1 << 24 calculated over the whole instruction, which is either
   32 or 96 bits wide.  */
static void
calc_parity (bfd_byte *contents, size_t start, size_t end)
{
  bfd_byte *p = contents + start;

  while (p + 4 <= contents + end)
    {
      bfd_byte *next_p;
      unsigned int insn = bfd_getb32 (p) & ~(1 << 24);
      unsigned int par = parity (insn);

      next_p = p + 4;
      if ((insn & 0x80000000) != 0)
	{
	  next_p = p + 12;
	  if (next_p <= contents + end)
	    {
	      par ^= parity (bfd_getb32 (p + 4));
	      par ^= parity (bfd_getb32 (p + 8));
	    }
	  else
	    break;
	}
      insn |= (par ^ 1) << 24;
      bfd_putb32 (insn, p);
      p = next_p;
    }
}

static bfd_boolean
pore_elf_relocate_section (bfd *output_bfd,
			   struct bfd_link_info *info,
			   bfd *input_bfd,
			   asection *input_section,
			   bfd_byte *contents,
			   Elf_Internal_Rela *relocs,
			   Elf_Internal_Sym *local_syms,
			   asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  bfd_vma parity_start;
  bfd_boolean ret = TRUE;

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  /* Default to not generating parity.  */
  parity_start = input_section->size;
  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      const char *sym_name;
      reloc_howto_type *howto;
      bfd_vma relocation;
      enum elf_pore_reloc_type r_type;
      unsigned long r_symndx;
      bfd_reloc_status_type r;
      bfd_boolean unresolved_reloc;
      bfd_boolean warned;

      r_type = ELF64_R_TYPE (rel->r_info);
      if (r_type >= R_PORE_max)
	{
	  (*info->callbacks->einfo)
	    (_("%H: unsupported reloc %d\n"),
	     input_bfd, input_section, rel->r_offset, (int) r_type);
	  ret = FALSE;
	  continue;
	}

      sym = NULL;
      sec = NULL;
      h = NULL;
      unresolved_reloc = FALSE;
      warned = FALSE;
      r_symndx = ELF64_R_SYM (rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  sym_name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, sec);

	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned);

	  sym_name = h->root.root.string;
	}
      howto = pore_elf_howto_table + r_type;

      if (sec != NULL && elf_discarded_section (sec))
	{
	  /* For relocs against symbols from removed linkonce sections,
	     or sections discarded by a linker script, we just want the
	     section contents zeroed.  Avoid any special processing.  */
	  RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					   rel, relend, howto, contents);
	}

      if (info->relocatable)
	continue;

      if (r_type == R_PORE_FEATURE)
	{
	  r = bfd_reloc_ok;
	  if (rel->r_offset > input_section->size)
	    r = bfd_reloc_outofrange;
	  else if (rel->r_addend == PORE_FEATURE_PARITY_ON)
	    parity_start = rel->r_offset;
	  else if (rel->r_addend == PORE_FEATURE_PARITY_OFF)
	    {
	      calc_parity (contents, parity_start, rel->r_offset);
	      parity_start = input_section->size;
	    }
	  else
	    r = bfd_reloc_outofrange;
	}
      else
	{
	  if (unresolved_reloc)
	    {
	      info->callbacks->einfo
		(_("%H: unresolvable %s relocation against symbol `%s'\n"),
		 input_bfd, input_section, rel->r_offset,
		 howto->name, h->root.root.string);
	      ret = FALSE;
	    }

	  r = _bfd_final_link_relocate (howto,
					input_bfd,
					input_section,
					contents,
					rel->r_offset,
					relocation,
					rel->r_addend);
	}

      if (r != bfd_reloc_ok)
	{
	  if (sym_name == NULL)
	    sym_name = "(null)";
	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      if (warned)
		continue;
	      if (((*info->callbacks->reloc_overflow)
		   (info, (h ? &h->root : NULL), sym_name, howto->name,
		    rel->r_addend, input_bfd, input_section, rel->r_offset)))
		continue;
	      break;

	    case bfd_reloc_outofrange:
	      (*info->callbacks->einfo)
		(_("%H: %s reloc against `%s': out of range\n"),
		 input_bfd, input_section, rel->r_offset, howto->name,
		 sym_name);
	      break;

	    default:
	      (*info->callbacks->einfo)
		(_("%H: %s reloc against `%s': error %d\n"),
		 input_bfd, input_section, rel->r_offset, howto->name,
		 sym_name, (int) r);
	    }
	  ret = FALSE;
	}
    }
  calc_parity (contents, parity_start, input_section->size);

  return ret;
}

#include "elf64-target.h"
