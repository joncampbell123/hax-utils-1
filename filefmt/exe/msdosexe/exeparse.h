#ifndef __FILEFMT_EXE_MSDOS_EXEPARSE_H
#define __FILEFMT_EXE_MSDOS_EXEPARSE_H

int msdos_exe_sanity_check();
void fprintf_exehdr(FILE *fp,struct msdos_exe_header *x);
int msdos_exe_header_compute_regions(struct msdos_exe_header_regions *r,struct msdos_exe_header *h,uint32_t file_len);

extern const char		str_ne_header[];
extern const char		str_pe_header[];
extern const char		str_exe_main_header[];
extern const char		str_exe_header_area[];
extern const char		str_exe_resident_image[];
extern const char		str_exe_relocation_table[];

#endif /* __FILEFMT_EXE_MSDOS_EXEPARSE_H */

