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

static unsigned char		temp[4096];
static int			exe_fd = -1;
static char*			exe_file = NULL;

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
	struct msdos_exe_header_regions exehdr_rgn;
	struct msdos_exe_header exehdr;
	uint32_t file_len;
	int r;

	if (parse_argv(argc,argv))
		return 1;

	if ((exe_fd = open(exe_file,O_RDONLY|O_BINARY)) < 0) {
		fprintf(stderr,"Unable to open EXE file %s\n",exe_file);
		return 1;
	}
	file_len = (uint32_t)lseek(exe_fd,0,SEEK_END);
	lseek(exe_fd,0,SEEK_SET);

	if ((r=msdos_exe_sanity_check()) != 0) {
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

	fprintf_exehdr(stdout,&exehdr);
	if (msdos_exe_header_compute_regions(&exehdr_rgn,&exehdr,file_len)) {
		fprintf(stderr,"EXE header parsing failed\n");
		return 1;
	}

	new_exerange(0,0x1C - 1UL,str_exe_main_header);
	if (exehdr_rgn.header_end != 0UL)
		new_exerange(0,exehdr_rgn.header_end - 1UL,str_exe_header_area);

	/* we will compute the length later */
	if (exehdr_rgn.image_end != 0UL) {
		if (exehdr_rgn.image_ofs < exehdr_rgn.image_end)
			new_exerange(exehdr_rgn.image_ofs,exehdr_rgn.image_end - 1UL,str_exe_resident_image);
		else
			fprintf(stderr,"WARNING: Image ends before image start\n");
	}
	else {
		fprintf(stderr,"WARNING: Image end at zero\n");
	}

	if (exehdr_rgn.reloc_ofs != 0UL && exehdr_rgn.reloc_entries != 0) {
		struct msdos_exe_relocation_entry *table = (struct msdos_exe_relocation_entry*)temp;
		unsigned int c = exehdr_rgn.reloc_entries;
		unsigned int i,rd,cnt=0;

		printf("EXE relocation table:\n");
		lseek(exe_fd,exehdr_rgn.reloc_ofs,SEEK_SET);
		new_exerange(exehdr_rgn.reloc_ofs,exehdr_rgn.reloc_end - 1UL,str_exe_relocation_table);

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

