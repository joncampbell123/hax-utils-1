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
	new_exerange(ofs,ofs+0x18UL-1UL,"PE COFF Main header");
}

int main(int argc,char **argv) {
	struct msdos_exe_header_regions exehdr_rgn;
	struct msdos_exe_header exehdr;
	int r;

	if (parse_argv(argc,argv))
		return 1;

	if ((r=msdos_exe_sanity_check()) != 0) {
		fprintf(stderr,"SANITY CHECK FAILED: Code %d\n",r);
		return 1;
	}

	if ((exe_fd = open(exe_file,O_RDONLY|O_BINARY)) < 0) {
		fprintf(stderr,"Unable to open EXE file %s\n",exe_file);
		return 1;
	}

	if ((r=msdos_exe_read_main_header(&exehdr,&exehdr_rgn,exe_fd))) {
		fprintf(stderr,"Unable to read EXE header, code %d\n",r);
		return 1;
	}

	fprintf_exehdr(stdout,&exehdr);
	if (msdos_exe_header_compute_regions(&exehdr_rgn,&exehdr,exehdr_rgn.file_end)) {
		fprintf(stderr,"EXE header parsing failed\n");
		return 1;
	}
	msdos_exe_header_add_regions(&exehdr_rgn);
	msdos_exe_header_dump_entrypoints(stdout,exe_fd,&exehdr_rgn);
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
				new_exerange(0x3C,0x3F,"Extended header pointer");
				pe_examine(exe_fd,ofs);
			}
			else if (!memcmp(temp,"NE",2)) {
				new_exerange(0x3C,0x3F,"Extended header pointer");
				new_exerange(ofs,ofs+0x3FUL,str_ne_header);
			}
		}
	}

	/* we do rudimentary checking for other extensions---check the bytes immediately after the resident image */
	if (exehdr_rgn.image_end != 0 && exehdr_rgn.image_end < exehdr_rgn.file_end) {
		lseek(exe_fd,exehdr_rgn.image_end,SEEK_SET);
		r = read(exe_fd,temp,sizeof(temp));
		if (r < sizeof(temp)) memset(temp+r,0,sizeof(temp)-r);

		if (!memcmp(temp,"ARJ_SFX\0",8)) {
			new_exerange(exehdr_rgn.image_end,exehdr_rgn.image_end+8UL+32UL-1UL,"ARJ self-extracting executable package header");
		}
	}

	/* sort the ranges. we're going to check for overlapping regions (NOTE: This invalidates our rg_* pointers) */
	sort_exeranges();

	/* summary */
	printf("EXE summary:\n");
	print_exeranges(0,exehdr_rgn.file_end-1UL,0,exeranges-1,0);
	close(exe_fd);
	free_exeranges();
	return 0;
}

