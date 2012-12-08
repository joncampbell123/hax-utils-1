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

static const char		str_ne_header[] = "New Executable header";
static const char		str_exe_main_header[] = "EXE main header";
static const char		str_exe_header_area[] = "EXE header area";
static const char		str_pe_header[] = "Portable Executable header";
static const char		str_exe_resident_image[] = "EXE resident image";
static const char		str_exe_relocation_table[] = "EXE relocation table";

static unsigned char		temp[4096];
static int			exe_fd = -1;
static char*			exe_file = NULL;

static int sanity_check() {
	if (sizeof(struct msdos_exe_header) != 0x1C) return -1;
	if (offsetof(struct msdos_exe_header,bytes_in_last_512_page) != 2) return -2;
	if (sizeof(struct msdos_pe_coff_header) != 0x14) return -3;
	return 0;
}

static void help() {
	fprintf(stderr,"info [options] <MS-DOS EXE file>\n");
	fprintf(stderr,"jmc hax-utils-v1 MS-DOS EXE info dumper\n");
}

static int parse_argv(int argc,char **argv) {
	int i,sw=0;
	char *a;

	for (i=1;i < argc;) {
		a = argv[i++];

		if (*a == '-') {
			do { a++; } while (*a == '-');

			if (!strcmp(a,"h") || !strcmp(a,"help")) {
				help();
				return 1;
			}
			else {
				help();
				fprintf(stderr,"Unknown switch %s\n",a);
				return 1;
			}
		}
		else {
			switch (sw++) {
				case 0:
					exe_file = a;
					break;
				default:
					fprintf(stderr,"Excess param\n");
					return 1;
			};
		}
	}

	if (exe_file == NULL) {
		fprintf(stderr,"No EXE file specified\n");
		return 1;
	}

	return 0;
}

/* NTS: This code only cares about showing you there's a PE header. To dump
 *      all PE structures, you should use another version of this code specialized
 *      for it. */
static void pe_examine(int exe_fd,uint32_t ofs) {
	struct msdos_pe_coff_header mainhdr;

	/* +0x00 "PE\0\0" */
	lseek(exe_fd,ofs+4,SEEK_SET);
	read(exe_fd,&mainhdr,sizeof(mainhdr));
	new_exerange(ofs,ofs+sizeof(mainhdr)+4UL-1UL,"PE COFF Main header");
}

int main(int argc,char **argv) {
	struct msdos_exe_header exehdr;
	struct exe_range *rg;
	uint32_t image_len;
	uint32_t file_len;
	int r;

	if (parse_argv(argc,argv))
		return 1;

	if ((exe_fd = open(exe_file,O_RDONLY|O_BINARY)) < 0) {
		fprintf(stderr,"Unable to open EXE file %s\n",exe_file);
		return 1;
	}

	if ((r=sanity_check()) != 0) {
		fprintf(stderr,"SANITY CHECK FAILED: Code %d\n",r);
		return 1;
	}

	/* OK. read the header */
	if (read(exe_fd,&exehdr,sizeof(exehdr)) != sizeof(exehdr)) {
		fprintf(stderr,"Unable to read EXE header\n");
		return 1;
	}

	/* check signature */
	if (r_le16(&exehdr.mz_signature) != MSDOS_EXE_MZ_SIGNATURE) {
		fprintf(stderr,"EXE header not present\n");
		return 1;
	}

	printf("EXE main header:\n");
	printf("    Bytes in last 512-byte page:                 %u\n",
		r_le16(&exehdr.bytes_in_last_512_page));
	printf("    Total 512-byte pages:                        %u\n",
		r_le16(&exehdr.total_512_pages));
	printf("    Number of relocation entries:                %u\n",
		r_le16(&exehdr.number_of_relocation_entries));
	printf("    Header size in paragraphs:                   %u\n",
		r_le16(&exehdr.header_size_in_paragraphs));
	printf("    Minimum extra memory (in paragraphs):        %u (%lu bytes)\n",
		r_le16(&exehdr.min_memory_paragraphs),
		(unsigned long)r_le16(&exehdr.min_memory_paragraphs) * 16UL);
	printf("    Maximum extra memory (in paragraphs):        %u (%lu bytes)\n",
		r_le16(&exehdr.max_memory_paragraphs),
		(unsigned long)r_le16(&exehdr.max_memory_paragraphs) * 16UL);
	printf("    Initial stack pointer (SS:SP):               0x%04X:%04X from start of EXE\n",
		r_le16(&exehdr.initial_ss),
		r_le16(&exehdr.initial_sp));
	printf("    Checksum:                                    0x%04X\n",
		r_le16(&exehdr.checksum));
	printf("    Initial instruction pointer (CS:IP):         0x%04X:%04X from start of EXE\n",
		r_le16(&exehdr.initial_cs),
		r_le16(&exehdr.initial_ip));
	printf("    Offset of relocation table:                  %u\n",
		r_le16(&exehdr.offset_of_relocation_table));
	printf("    Overlay number:                              %u\n",
		r_le16(&exehdr.overlay_number));

	file_len = (uint32_t)lseek(exe_fd,0,SEEK_END);

	image_len = (unsigned long)r_le16(&exehdr.total_512_pages) * 512UL;
	if (image_len == 0UL) image_len = 512UL;
	if (r_le16(&exehdr.bytes_in_last_512_page) != 0)
		image_len += (unsigned long)r_le16(&exehdr.bytes_in_last_512_page) - 512UL;

	new_exerange(0,0x1C - 1UL,str_exe_main_header);
	new_exerange(0,((unsigned long)r_le16(&exehdr.header_size_in_paragraphs) * 16UL) - 1UL,
		str_exe_header_area);

	/* we will compute the length later */
	rg = new_exerange(((unsigned long)r_le16(&exehdr.header_size_in_paragraphs) * 16UL),
		image_len - 1UL,str_exe_resident_image);
	if (rg->end < rg->start) {
		rg->end = rg->start;
		fprintf(stderr,"WARNING: EXE resident image ends before it starts\n");
	}

	if (exehdr.number_of_relocation_entries != 0 && exehdr.offset_of_relocation_table != 0) {
		struct msdos_exe_relocation_entry *table = (struct msdos_exe_relocation_entry*)temp;
		unsigned int c = r_le16(&exehdr.number_of_relocation_entries);
		unsigned int i,rd,cnt=0;

		printf("EXE relocation table:\n");
		lseek(exe_fd,r_le16(&exehdr.offset_of_relocation_table),SEEK_SET);
		new_exerange(r_le16(&exehdr.offset_of_relocation_table),
			(unsigned long)r_le16(&exehdr.offset_of_relocation_table) +
			((unsigned long)r_le16(&exehdr.number_of_relocation_entries) * 4UL) - 1UL,
			str_exe_relocation_table);

		do {
			rd = c;
			if ((rd*sizeof(struct msdos_exe_relocation_entry)) > sizeof(temp))
				rd = sizeof(temp) / sizeof(struct msdos_exe_relocation_entry);
			c -= rd;

			if (read(exe_fd,temp,rd*sizeof(struct msdos_exe_relocation_entry)) !=
				(rd*sizeof(struct msdos_exe_relocation_entry))) {
				fprintf(stderr,"Read error in relocation table\n");
				return 1;
			}

			for (i=0;i < rd;i++,cnt++) {
				if ((cnt%5) == 0) printf("    ");
				printf("+0x%04X:%04X ",
					r_le16(&table[i].segment),
					r_le16(&table[i].offset));
				if ((cnt%5) == 4) printf("\n");
			}
		} while (c != 0);
		if ((cnt%5) != 0) printf("\n");
	}

	/* MS-Windows and other formats extend the EXE format with an offset at 0x3C */
	if (r_le16(&exehdr.header_size_in_paragraphs) >= 4) {
		uint32_t ofs=0;

		lseek(exe_fd,0x3C,SEEK_SET);
		read(exe_fd,&ofs,4);
		ofs = r_le32(&ofs);
		if (ofs >= 0x40) {
			lseek(exe_fd,ofs,SEEK_SET);
			read(exe_fd,temp,4);

			if (!memcmp(temp,"PE\0\0",4)) {
				pe_examine(exe_fd,ofs);
			}
			else if (!memcmp(temp,"NE",2)) {
				new_exerange(ofs,ofs+0x3FUL,str_ne_header);
			}
		}
	}

	/* sort the ranges. we're going to check for overlapping regions (NOTE: This invalidates our rg_* pointers) */
	sort_exeranges();

	/* summary */
	printf("EXE summary:\n");
	print_exeranges(0,file_len-1UL,0,exeranges-1,0);
	close(exe_fd);
	free_exeranges();
	return 0;
}

