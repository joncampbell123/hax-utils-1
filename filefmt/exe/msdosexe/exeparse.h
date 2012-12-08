#ifndef __FILEFMT_EXE_MSDOS_EXEPARSE_H
#define __FILEFMT_EXE_MSDOS_EXEPARSE_H

int msdos_exe_sanity_check();
void fprintf_exehdr(FILE *fp,struct msdos_exe_header *x);
void msdos_exe_header_add_regions(struct msdos_exe_header_regions *exehdr_rgn);
int msdos_exe_header_compute_regions(struct msdos_exe_header_regions *r,struct msdos_exe_header *h,uint32_t file_len);
int msdos_exe_read_main_header(struct msdos_exe_header *exehdr,struct msdos_exe_header_regions *exehdr_rgn,int exe_fd);

extern const char		str_ne_header[];
extern const char		str_pe_header[];
extern const char		str_exe_main_header[];
extern const char		str_exe_header_area[];
extern const char		str_exe_resident_image[];
extern const char		str_exe_relocation_table[];

#endif /* __FILEFMT_EXE_MSDOS_EXEPARSE_H */

