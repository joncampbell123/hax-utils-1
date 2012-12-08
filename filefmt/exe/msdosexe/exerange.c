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

struct exe_range		exerange[MAX_EXERANGES];
int				exeranges=0;

struct exe_range *new_exerange(uint32_t start,uint32_t end,const char *str) {
	struct exe_range *e;

	if (exeranges >= MAX_EXERANGES) {
		fprintf(stderr,"ERROR: Out of ranges\n");
		exit(1);
	}

	e = &exerange[exeranges++];
	e->alloc_str = 0;
	e->start = start;
	e->end = end;
	e->str = (char*)str;
	return e;
}

void sort_exeranges() {
	struct exe_range tmp;
	unsigned int i,c;

	do {
		c=0;
		for (i=0;(i+1) < exeranges;i++) {
			if (exerange[i].start > exerange[i+1].start) {
				tmp = exerange[i];
				exerange[i] = exerange[i+1];
				exerange[i+1] = tmp;
				c++;
			}
			else if (exerange[i].start == exerange[i+1].start && exerange[i].end < exerange[i+1].end) {
				tmp = exerange[i];
				exerange[i] = exerange[i+1];
				exerange[i+1] = tmp;
				c++;
			}
		}
	} while (c != 0);
}

void free_exeranges() {
	while (exeranges > 0) {
		struct exe_range *e = &exerange[--exeranges];
		if (e->alloc_str) {
			free(e->str);
			e->alloc_str=0;
			e->str=NULL;
		}
	}
}

void print_exeranges(uint32_t start,uint32_t end,int first,int last,int indent) {
	struct exe_range *rg;
	int i,j,fi;

	for (i=first;i <= last;) {
		rg = &exerange[i];

		if (i == first) {
			if (start < rg->start) {
				for (j=0;j < indent;j++) printf("  ");
				printf("  0x%08lX-0x%08lX: [extra]\n",(unsigned long)start,(unsigned long)rg->start-1UL);
			}
		}

		for (j=0;j < indent;j++) printf("  ");
		printf("  0x%08lX-0x%08lX: %s\n",(unsigned long)rg->start,(unsigned long)rg->end,rg->str);

		i++;
		if (i <= last) {
			fi = i;
			while (i <= last && exerange[i].start >= rg->start && exerange[i].start <= rg->end) i++;
			if (i != fi) {
				print_exeranges(rg->start,rg->end,fi,i-1,indent+1);
			}
		}

		if (i <= last && (rg->end+1UL) != exerange[i].start) {
			for (j=0;j < indent;j++) printf("  ");
			printf("  0x%08lX-0x%08lX: [extra]\n",(unsigned long)rg->end+1UL,(unsigned long)exerange[i].start-1UL);
		}

		if ((i-1) == last) {
			if (end > rg->end) {
				for (j=0;j < indent;j++) printf("  ");
				printf("  0x%08lX-0x%08lX: [extra]\n",(unsigned long)rg->end+1UL,(unsigned long)end);
			}
			else if (end < rg->end)
				printf("     !! ^ This region extends past the parent region\n");
		}
	}
}

