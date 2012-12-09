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
#include "filefmt/exe/msdosexe/neexe.h"
#include "filefmt/exe/msdosexe/stubs.h"
#include "filefmt/exe/msdosexe/dosexe.h"
#include "filefmt/exe/msdosexe/exerange.h"
#include "filefmt/exe/msdosexe/exeparse.h"

void identify_msdos_stub(int exe_fd,struct msdos_exe_header *h,struct msdos_exe_header_regions *r) {
	unsigned char *p,*f;
	uint16_le_t t16;
	int w;

	w = (int)(r->image_end - r->image_ofs);
	if (w > sizeof(temp)) w = sizeof(temp);
	if (w < 3) return;

	if (lseek(exe_fd,r->image_ofs,SEEK_SET) != r->image_ofs)
		return;
	if (read(exe_fd,temp,w) != w)
		return;

	p = temp; f = temp + w;
	/* Form E8 xx xx <string> <code>
	 *
	 *    CALL code
	 *    db STRING
	 * code:
	 *    pop dx
	 *    push cs
	 *    pop ds
	 *    mov ah,9
	 *    int 21
	 */
	if (h->initial_ip == 0x0000 && h->initial_cs == 0x0000 && p[0] == 0xE8) {
		static const unsigned char code[] = {0x5A,0x0E,0x1F,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21};
		char *str,*pp,*stro;

		t16 = r_le16r(p+1); p += 3; str = (char*)p;
		if ((p+t16+sizeof(code)) <= f && memcmp(p+t16,code,sizeof(code)) == 0) {
			pp = str;
			while (pp < (char*)(p+t16) && *pp != '$') pp++;
			stro = pp;
			*pp-- = 0;
			while (pp > str && (*pp == 13 || *pp == 10)) *pp-- = 0;

			fprintf(stdout,"EXE stub: Microsoft Stub E8xxxxSTRINGCODE5A0E1FB409CD21B8014CCD21\n");
			fprintf(stdout,"    The stub says: \"%s\"\n",str);

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(p+t16+sizeof(code)-temp))-1UL,"MS-DOS stub");

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(str-(char*)temp))-1UL,"Initial CALL");
			new_exerange(r->image_ofs+((size_t)(str-(char*)temp)),r->image_ofs+((size_t)(stro-(char*)temp)),"Message string");
			new_exerange(r->image_ofs+((size_t)(p+t16-temp)),r->image_ofs+((size_t)(p+t16+sizeof(code)-temp))-1UL,"Stub executable code");
			return;
		}
	}
	/* Form BA xx xx <code> <string>
	 *
	 *    MOV DX,<string address>
	 *    push cs
	 *    pop ds
	 *    mov ah,9
	 *    int 21h
	 *    mov ax,0x4C01
	 *    int 21h
	 *    <some NOPs>
	 * string:
	 *    db STRING
	 */
	if (h->initial_ip == 0x0000 && h->initial_cs == 0x0000 && p[0] == 0xBA) {
		static const unsigned char code[] = {/*BA xx xx*/0x0E,0x1F,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21};
		char *str,*pp,*stro;

		t16 = r_le16r(p+1);
		if (t16 >= (sizeof(code)+3UL) && (p+sizeof(code)+3UL) <= f && (p+t16+3+sizeof(code)) <= f && memcmp(p+3,code,sizeof(code)) == 0) {
			fprintf(stdout,"EXE stub: Microsoft Stub BAxxxx0E1FB409CD21B8014CCD21\n");

			/* now look at the string */
			str = (char*)p + t16;
			pp = str; while ((pp+1) < (char*)f && *pp != '$') pp++;
			stro = pp;
			*pp-- = 0;
			while (pp > str && (*pp == 13 || *pp == 10)) *pp-- = 0;
			fprintf(stdout,"    The stub says: \"%s\"\n",str);

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(stro-(char*)temp)),"MS-DOS stub");

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(p+3+sizeof(code)-temp))-1UL,"Stub executable code");
			new_exerange(r->image_ofs+((size_t)(str-(char*)temp)),r->image_ofs+((size_t)(stro-(char*)temp)),"Message string");
			return;
		}
	}
	/* Form 0E 1F BA xx xx <code> <string>
	 *
	 *    MOV DX,<string address>
	 *    push cs
	 *    pop ds
	 *    mov ah,9
	 *    int 21h
	 *    mov ax,0x4C01
	 *    int 21h
	 *    <some NOPs>
	 * string:
	 *    db STRING
	 */
	if (h->initial_ip == 0x0000 && h->initial_cs == 0x0000 && p[0] == 0x0E && p[1] == 0x1F && p[2] == 0xBA) {
		static const unsigned char code[] = {/*0E 1F BA xx xx*/0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21};
		char *str,*pp,*stro;

		t16 = r_le16r(p+3);
		if (t16 >= (sizeof(code)+5UL) && (p+sizeof(code)+5UL) <= f && (p+t16+5+sizeof(code)) <= f && memcmp(p+5,code,sizeof(code)) == 0) {
			fprintf(stdout,"EXE stub: Microsoft Stub 0E1FBAxxxxB409CD21B8014CCD21\n");

			/* now look at the string */
			str = (char*)p + t16;
			pp = str; while ((pp+1) < (char*)f && *pp != '$') pp++;
			stro = pp;
			*pp-- = 0;
			while (pp > str && (*pp == 13 || *pp == 10)) *pp-- = 0;
			fprintf(stdout,"    The stub says: \"%s\"\n",str);

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(stro-(char*)temp)),"MS-DOS stub");

			new_exerange(r->image_ofs,r->image_ofs+((size_t)(p+5+sizeof(code)-temp))-1UL,"Stub executable code");
			new_exerange(r->image_ofs+((size_t)(str-(char*)temp)),r->image_ofs+((size_t)(stro-(char*)temp)),"Message string");
			return;
		}
	}
}

