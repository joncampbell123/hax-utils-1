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

static int				exe_fd = -1;
static char*				exe_file = NULL;

static struct msdos_exe_header_regions	exehdr_rgn;
static struct msdos_exe_header		exehdr;

static unsigned char*			resident = NULL;
static uint32_t				resident_size = 0;
static unsigned char*			resident_fence = NULL;

static void help() {
	fprintf(stderr,"info [options] <UNREAL.EXE file>\n");
	fprintf(stderr,"jmc hax-utils-v1 Unreal info dumper\n");
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

static unsigned char *ofs2res(uint32_t o,uint32_t sz) {
	if (sz == 0 || resident == NULL)
		return NULL;
	if (o < exehdr_rgn.image_ofs)
		return NULL;
	if (o >= (exehdr_rgn.image_ofs+resident_size))
		return NULL;
	if ((o+sz-1UL) >= (exehdr_rgn.image_ofs+resident_size))
		return NULL;

	return resident + o - exehdr_rgn.image_ofs;
}

int memcmp_ignzero(const unsigned char *target,const unsigned char *src,size_t l) {
	int r = 0;

	while (r == 0 && l-- != 0) {
		if (*src == 0) {
			/* this is a variant of memcpy() where zeros in the source mean to ignore the byte */
			target++;
			src++;
		}
		else {
			r = ((int)(*target++)) - ((int)(*src++));
		}
	}

	return r;
}

int identify_fc_unreal_11() {
	uint32_t entry,cpy;
	unsigned char *p,*seg,*p2;
	static const unsigned char code_at_entry_000E[] =
	/* 000E */{	0x06,				/* PUSH ES */
	/* 000F */	0x0E,				/* PUSH CS */
	/* 0010 */	0x1F,				/* POP DS */
	/* 0011 */	0x8B,0x0E,0x00,0x00,		/* MOV CX,[xxxx]  [0x000C] param at 0x13 */
	/* 0015 */	0x8B,0xF1,			/* MOV SI,CX */
	/* 0017 */	0x4E,				/* DEC SI */
	/* 0018 */	0x89,0xF7,			/* MOV DI,SI */
	/* 001A */	0x8C,0xDB,			/* MOV BX,DS */
	/* 001C */	0x03,0x1E,0x00,0x00,		/* ADD BX,[xxxx]  [0x000A] param at 0x1E */
	/* 0020 */	0x8E,0xC3,			/* MOV ES,BX */
	/* 0022 */	0xFD,				/* STD */
	/* 0023 */	0xF3,0xA4,			/* REP MOVSB */
	/* 0025 */	0x53,				/* PUSH BX */
	/* 0026 */	0xB8,0x00,0x00,			/* MOV AX,xxxx [MOV AX,002B] param at 0x27 */
	/* 0029 */	0x50,				/* PUSH AX */
	/* 002A */	0xCB				/* RETF */
	};

	if (r_le16(&exehdr.initial_ip) != 0x000E)
		return 0;
	if ((p=seg=ofs2res(exehdr_rgn.csip_offset-0x000E,sizeof(code_at_entry_000E))) == NULL) /* CS:IP 0x0E to 0x2A incl. must exist */
		return 0;
	p += 0x000E;
	if (memcmp_ignzero(p,code_at_entry_000E,sizeof(code_at_entry_000E)) != 0)
		return 0;
	if (r_le16r(seg+0x13) != 0x000C)
		return 0;
	if (r_le16r(seg+0x1E) != 0x000A)
		return 0;

	cpy = r_le16r(seg+0x0C);
	entry = (unsigned long)(((r_le16(&exehdr.initial_cs)+r_le16r(seg+0x0A)) << 4UL) +
		(unsigned long)r_le16r(seg+0x27)) + exehdr_rgn.image_ofs;
	fprintf(stdout,"Unreal v1.1 stage #1:\n");
	fprintf(stdout,"    Memcopy byte count:                     %u\n",r_le16r(seg+0x0C));
	fprintf(stdout,"    Segment adjustment:                    +0x%04x\n",r_le16r(seg+0x0A));
	fprintf(stdout,"    New entry point:                        0x%04x:0x%04x (%lu)\n",
		r_le16(&exehdr.initial_cs)+r_le16r(seg+0x0A),
		r_le16r(seg+0x27),
		(unsigned long)entry);

	if (cpy < 16)
		return 0;

	p = seg;
	if ((p2=ofs2res(entry,cpy)) == NULL)
		return 0;

	fprintf(stdout,"     ^ Carrying out memcpy\n");
	memcpy(p2,p,cpy);

	return 1;
}

void identify_fc_unreal() {
	/* Unreal v1.1: entry point code does some memcpy() backwards */
	/* entry point: some segment:0x000E and some params immediatly befor the entrypoint */
	if (identify_fc_unreal_11())
		return; /* got it */
}

int main(int argc,char **argv) {
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

	resident_size = (uint32_t)(exehdr_rgn.image_end - exehdr_rgn.image_ofs);
	if (resident_size >= 0x100 && resident_size <= 0x8000) {
		uint32_t extra = (uint32_t)r_le16(&exehdr.min_memory_paragraphs) << 4UL;

		resident = malloc(resident_size + extra + 2048);
		if (resident == NULL) {
			fprintf(stderr,"Unable to allocate resident copy\n");
			return 1;
		}
		resident_fence = resident + resident_size;

		if (lseek(exe_fd,exehdr_rgn.image_ofs,SEEK_SET) != exehdr_rgn.image_ofs)
			return 1;
		if (read(exe_fd,resident,resident_size) != resident_size)
			return 1;

		fprintf(stderr,"%lu bytes from %lu loaded into memory\n",
			(unsigned long)resident_size,
			(unsigned long)exehdr_rgn.image_ofs);

		memset(resident+resident_size,0,extra);
		resident_size += extra;
		resident_fence = resident + resident_size;
		fprintf(stderr,"%lu extra zero bytes loaded into memory\n",(unsigned long)extra);

		identify_fc_unreal(exe_fd,&exehdr,&exehdr_rgn);
	}

	if (resident) {
		/* DEBUG write resident buffer */
		int fd = open("/tmp/fcunreal.tmp",O_CREAT|O_TRUNC|O_WRONLY,0644);
		if (fd >= 0) {
			lseek(fd,exehdr_rgn.image_ofs,SEEK_SET);
			write(fd,resident,resident_size);
			close(fd);
		}

		free(resident);
		resident_size = 0;
		resident_fence = resident = NULL;
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

