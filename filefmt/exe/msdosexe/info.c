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

/* these typedefs exist solely to remind me that they are little endian,
 * and must be converted to host byte order if the CPU is big endian */
typedef uint16_t	uint16_le_t;
typedef uint32_t	uint32_le_t;
typedef uint64_t	uint64_le_t;

/* these macros are for reading the little Endian values in the header.
 * one is used if you intend to use it on structure fields, the other
 * if you intend to point it at raw buffer data. */
static inline uint16_t r_le16(const uint16_le_t *x) {
	return *((const uint16_t*)x);
}

static inline uint16_t r_le16r(const void *x) {
	return *((const uint16_t*)x);
}

static inline uint32_t r_le32(const uint32_le_t *x) {
	return *((const uint32_t*)x);
}

static inline uint32_t r_le32r(const void *x) {
	return *((const uint32_t*)x);
}

static inline uint64_t r_le64(const uint64_le_t *x) {
	return *((const uint64_t*)x);
}

static inline uint64_t r_le64r(const void *x) {
	return *((const uint64_t*)x);
}

#define MSDOS_EXE_MZ_SIGNATURE	0x5A4D

#pragma pack(push,1)
struct msdos_exe_header {
	uint16_le_t		mz_signature;			/* +0x00 'MZ' 0x4D 0x5A */
	uint16_le_t		bytes_in_last_512_page;		/* +0x02 number of bytes in last 512-byte page or 0 to use the whole page */
	uint16_le_t		total_512_pages;		/* +0x04 total 512-byte pages in executable */
	uint16_le_t		number_of_relocation_entries;	/* +0x06 number of relocation entries */
	uint16_le_t		header_size_in_paragraphs;	/* +0x08 header size in paragraphs (N x 16 = number of bytes) */
	uint16_le_t		min_memory_paragraphs;		/* +0x0A minimum memory allocated in addition to code size (paragraphs) */
	uint16_le_t		max_memory_paragraphs;		/* +0x0C maximum memory allocated in addition to code size (paragraphs) */
	uint16_le_t		initial_ss;			/* +0x0E initial SS segment (relative to start of EXE) */
	uint16_le_t		initial_sp;			/* +0x10 initial SP */
	uint16_le_t		checksum;			/* +0x12 checksum */
	uint16_le_t		initial_ip;			/* +0x14 initial IP */
	uint16_le_t		initial_cs;			/* +0x16 initial CS segment (relative to start of EXE) */
	uint16_le_t		offset_of_relocation_table;	/* +0x18 offset of relocation table (or 0x40 if NE/LE/etc. EXE) */
	uint16_le_t		overlay_number;			/* +0x1A 0=main program */
								/* =0x1C */
};

struct msdos_exe_relocation_entry { /* array at offset_of_relocation_table */
	uint16_le_t		offset;
	uint16_le_t		segment;
};
#pragma pack(pop)

static unsigned char temp[4096];
static char* exe_file = NULL;
static int exe_fd = -1;

static int sanity_check() {
	if (sizeof(struct msdos_exe_header) != 0x1C) return -1;
	if (offsetof(struct msdos_exe_header,bytes_in_last_512_page) != 2) return -2;
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

struct exe_range {
	/* start <= x <= end inclusive */
	uint32_t		start:31;
	uint32_t		alloc_str;
	uint32_t		end;
	char*			str;
};

#define MAX_RANGES		16

static struct exe_range		range[MAX_RANGES];
static int			ranges=0;

static const char		str_exe_main_header[] = "EXE main header";
static const char		str_exe_header_area[] = "EXE header area";
static const char		str_exe_resident_image[] = "EXE resident image";
static const char		str_exe_relocation_table[] = "EXE relocation table";

static struct exe_range *new_range(uint32_t start,uint32_t end,const char *str) {
	struct exe_range *e;

	if (ranges >= MAX_RANGES) {
		fprintf(stderr,"ERROR: Out of ranges\n");
		exit(1);
	}

	e = &range[ranges++];
	e->alloc_str = 0;
	e->start = start;
	e->end = end;
	e->str = (char*)str;
	return e;
}

static void sort_ranges() {
	struct exe_range tmp;
	unsigned int i,c;

	do {
		c=0;
		for (i=0;(i+1) < ranges;i++) {
			if (range[i].start > range[i+1].start) {
				tmp = range[i];
				range[i] = range[i+1];
				range[i+1] = tmp;
				c++;
			}
			else if (range[i].start == range[i+1].start && range[i].end < range[i+1].end) {
				tmp = range[i];
				range[i] = range[i+1];
				range[i+1] = tmp;
				c++;
			}
		}
	} while (c != 0);
}

static void free_ranges() {
	while (ranges > 0) {
		struct exe_range *e = &range[--ranges];
		if (e->alloc_str) {
			free(e->str);
			e->alloc_str=0;
			e->str=NULL;
		}
	}
}

static void print_ranges(uint32_t start,uint32_t end,int first,int last,int indent) {
	struct exe_range *rg;
	int i,j,fi;

	for (i=first;i <= last;) {
		rg = &range[i];

		if (i == first) {
			if (start < rg->start) {
				for (j=0;j < indent;j++) printf("  ");
				printf("  0x%08lX-0x%08lX: [unused]\n",(unsigned long)start,(unsigned long)rg->start-1UL);
			}
		}

		for (j=0;j < indent;j++) printf("  ");
		printf("  0x%08lX-0x%08lX: %s\n",(unsigned long)rg->start,(unsigned long)rg->end,rg->str);

		i++;
		if (i <= last) {
			fi = i;
			while (i <= last && range[i].start >= rg->start && range[i].start <= rg->end) i++;
			if (i != fi) {
				print_ranges(rg->start,rg->end,fi,i-1,indent+1);
			}
		}

		if (i <= last && (rg->end+1UL) != range[i].start) {
			for (j=0;j < indent;j++) printf("  ");
			printf("  0x%08lX-0x%08lX: [unused]\n",(unsigned long)rg->end+1UL,(unsigned long)range[i].start-1UL);
		}

		if ((i-1) == last) {
			if (end > rg->end) {
				for (j=0;j < indent;j++) printf("  ");
				printf("  0x%08lX-0x%08lX: [unused]\n",(unsigned long)rg->end+1UL,(unsigned long)end);
			}
		}
	}
}

int main(int argc,char **argv) {
	struct msdos_exe_header exehdr;
	struct exe_range *rg;
	uint32_t image_len;
	uint32_t file_len;
	int r,i;

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

	new_range(0,0x1C - 1UL,str_exe_main_header);
	new_range(0,
		((unsigned long)r_le16(&exehdr.header_size_in_paragraphs) * 16UL) - 1UL,
		str_exe_header_area);

	/* we will compute the length later */
	rg = new_range(((unsigned long)r_le16(&exehdr.header_size_in_paragraphs) * 16UL),
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
		new_range(r_le16(&exehdr.offset_of_relocation_table),
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

	/* sort the ranges. we're going to check for overlapping regions (NOTE: This invalidates our rg_* pointers) */
	sort_ranges();

	/* if there is extra data at the end, note it */
	if (ranges > 0 && file_len > 0UL) {
		uint32_t start;

		i = ranges - 1;
		start = (rg = &range[i--])->start;
		while (i > 0 && range[i].start == start) rg = &range[i--];
		if ((rg->end+1UL) < file_len) new_range(rg->end+1UL,file_len-1UL,"Non-EXE region");
	}

	/* summary */
	printf("EXE summary:\n");
	print_ranges(0,file_len-1UL,0,ranges-1,0);
	close(exe_fd);
	free_ranges();
	return 0;
}

