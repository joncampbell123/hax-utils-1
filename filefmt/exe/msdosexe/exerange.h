#ifndef __FILEFMT_EXE_MSDOS_EXERANGE_H
#define __FILEFMT_EXE_MSDOS_EXERANGE_H

#pragma pack(push,1)
struct exe_range {
	/* start <= x <= end inclusive */
	uint32_t		start:31;
	uint32_t		alloc_str:1;
	uint32_t		end;
	char*			str;
};
#pragma pack(pop)

#define MAX_EXERANGES		128

extern struct exe_range		exerange[MAX_EXERANGES];
extern int			exeranges;

void print_exeranges(uint32_t start,uint32_t end,int first,int last,int indent);
struct exe_range *new_exerange(uint32_t start,uint32_t end,const char *str);
void sort_exeranges();
void free_exeranges();

#endif /* __FILEFMT_EXE_MSDOS_EXERANGE_H */

