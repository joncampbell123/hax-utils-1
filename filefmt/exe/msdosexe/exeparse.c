#ifdef LINUX
# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <endian.h>
# include <stddef.h>
# include <stdio.h>
# include <fcntl.h>

# ifndef O_BINARY
# define O_BINARY 0
# endif
#endif

#include "util/rawint.h"
#include "filefmt/exe/msdosexe/dosexe.h"
#include "filefmt/exe/msdosexe/exerange.h"
#include "filefmt/exe/msdosexe/exeparse.h"

const char		str_ne_header[] = "New Executable header";
const char		str_exe_main_header[] = "EXE main header";
const char		str_exe_header_area[] = "EXE header area";
const char		str_pe_header[] = "Portable Executable header";
const char		str_exe_resident_image[] = "EXE resident image";
const char		str_exe_relocation_table[] = "EXE relocation table";

int msdos_exe_sanity_check() {
	if (sizeof(struct msdos_exe_header) != 0x1C) return -1;
	if (offsetof(struct msdos_exe_header,bytes_in_last_512_page) != 2) return -2;
	if (sizeof(struct msdos_pe_coff_header) != 0x14) return -3;
	return 0;
}

int msdos_exe_header_compute_regions(struct msdos_exe_header_regions *r,struct msdos_exe_header *h,uint32_t file_len) {
	r->header_end = ((unsigned long)r_le16(&h->header_size_in_paragraphs) * 16UL);
	r->image_ofs = ((unsigned long)r_le16(&h->header_size_in_paragraphs) * 16UL);
	r->image_end = (unsigned long)r_le16(&h->total_512_pages) * 512UL;
	if (r_le16(&h->bytes_in_last_512_page) != 0)
		r->image_end += (unsigned long)r_le16(&h->bytes_in_last_512_page) - 512UL;
	if ((int32_t)r->image_end < 0) r->image_end = 0;

	if (h->number_of_relocation_entries != 0 && h->offset_of_relocation_table != 0) {
		r->reloc_entries = r_le16(&h->number_of_relocation_entries);
		r->reloc_ofs = r_le16(&h->offset_of_relocation_table);
		r->reloc_end = r->reloc_ofs + ((unsigned long)r->reloc_entries * 4UL);
	}
	else {
		r->reloc_ofs = r->reloc_end = 0;
		r->reloc_entries = 0;
	}

	return 0;
}

void fprintf_exehdr(FILE *fp,struct msdos_exe_header *x) {
	fprintf(fp,"EXE main header:\n");
	fprintf(fp,"    Bytes in last 512-byte page:                 %u\n",
		r_le16(&x->bytes_in_last_512_page));
	fprintf(fp,"    Total 512-byte pages:                        %u\n",
		r_le16(&x->total_512_pages));
	fprintf(fp,"    Number of relocation entries:                %u\n",
		r_le16(&x->number_of_relocation_entries));
	fprintf(fp,"    Header size in paragraphs:                   %u\n",
		r_le16(&x->header_size_in_paragraphs));
	fprintf(fp,"    Minimum extra memory (in paragraphs):        %u (%lu bytes)\n",
		r_le16(&x->min_memory_paragraphs),
		(unsigned long)r_le16(&x->min_memory_paragraphs) * 16UL);
	fprintf(fp,"    Maximum extra memory (in paragraphs):        %u (%lu bytes)\n",
		r_le16(&x->max_memory_paragraphs),
		(unsigned long)r_le16(&x->max_memory_paragraphs) * 16UL);
	fprintf(fp,"    Initial stack pointer (SS:SP):               0x%04X:%04X from start of img\n",
		r_le16(&x->initial_ss),
		r_le16(&x->initial_sp));
	fprintf(fp,"    Checksum:                                    0x%04X\n",
		r_le16(&x->checksum));
	fprintf(fp,"    Initial instruction pointer (CS:IP):         0x%04X:%04X from start of img\n",
		r_le16(&x->initial_cs),
		r_le16(&x->initial_ip));
	fprintf(fp,"    Offset of relocation table:                  %u\n",
		r_le16(&x->offset_of_relocation_table));
	fprintf(fp,"    Overlay number:                              %u\n",
		r_le16(&x->overlay_number));
}

