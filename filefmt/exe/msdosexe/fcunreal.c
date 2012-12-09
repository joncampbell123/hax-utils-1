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

int identify_fc_unreal_10() {
	/* TODO: This needs more comprehensive identification code */
	static const unsigned char code_at_entry_0006[] = {
		0xBC,0x00,0x00,			/* MOV SP,<xxxx>   [0x74, seems to match EXE header] */
		0xC3				/* RET */
	};
	unsigned char *p,*stk;

	if ((p=ofs2res(exehdr_rgn.csip_offset,sizeof(code_at_entry_0006))) == NULL) /* CS:IP 0x0E to 0x2A incl. must exist */
		return 0;
	if (memcmp_ignzero(p,code_at_entry_0006,sizeof(code_at_entry_0006)) != 0)
		return 0;
	if (r_le16r(p+1) != r_le16(&exehdr.initial_sp))
		return 0;

	new_exerange(exehdr_rgn.csip_offset,
		exehdr_rgn.csip_offset+4UL-1UL,
		"Unreal v1.0 initial stack entry");

	fprintf(stderr,"Unreal header identified\n");

	/* now look at the WORDS on the stack.
	 * [SP] = entry point after "MOV SP,xxxx" RET
	 * [SP+2] = initial DS value 0x0000
	 * [SP+4] = where to jump to after what appears to be initialization code
	 *           and then 286 vs 8086 detection code (PUSH SP, POP AX, compares
	 *           the two values to see if they differ. If they don't, then uses
	 *           SMSW to detect virtual 8086 mode, If either 8086 or vm86 is
	 *           detected, the code returns with BP == 0 else it returns with
	 *           BP == 1) */
	if ((stk=ofs2res(exehdr_rgn.sssp_offset,8)) == NULL)
		return 0;

	fprintf(stdout,"Unreal v1.0 initial stack WORDS:\n");
	fprintf(stdout,"    IP after stack entry:              0x%04x\n",r_le16r(stk));
	fprintf(stdout,"    DS after stack entry:              0x%04x\n",r_le16r(stk+2));
	fprintf(stdout,"    IP after detect/init:              0x%04x\n",r_le16r(stk+4));

	if (r_le16r(stk+2) != 0)
		return 0;
	if (r_le16r(stk) < 0x60)
		return 0;
	if (r_le16r(stk) >= r_le16r(stk+4))
		return 0;
	if (r_le16r(stk+4) < 0xE5)
		return 0;

	new_exerange(exehdr_rgn.csip_offset+r_le16r(stk)-r_le16(&exehdr.initial_ip),
		exehdr_rgn.csip_offset+0xE4-r_le16(&exehdr.initial_ip),
		"Unreal v1.0 detect/init");

	return 1;
}

/* Unreal v1.1: entry point code does some memcpy() backwards */
/* entry point: some segment:0x000E and some params immediatly befor the entrypoint */
int identify_fc_unreal_11() {
	uint32_t entry,cpy;
	unsigned char *p,*seg,*p2;
	static const unsigned char code_at_entry_000E[] = {
	/* 000E */	0x06,				/* PUSH ES */
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
	static const unsigned char code_at_entry_002B[] = {
	/* 002B */	0x2E,0x8B,0x2E,0x08,0x00,	/* MOV BP,WORD PTR CS:[0008] */
	/* 0030 */	0x8C,0xDA,			/* MOV DX,DS */
	/* 0032 */	0x89,0xE8,			/* MOV AX,BP */
	/* 0034 */	0x3D,0x00,0x10,			/* CMP AX,1000 */
	/* 0037 */	0x76,0x03,			/* JBE 003C */
	/* 0039 */	0xB8,0x00,0x10,			/* MOV AX,1000 */
	/* 003C */	0x29,0xC5,			/* SUB BP,AX */
	/* 003E */	0x29,0xC2,			/* SUB DX,AX */
	/* 0040 */	0x29,0xC3,			/* SUB BX,AX */
	/* 0042 */	0x8E,0xDA,			/* MOV DS,DX */
	/* 0044 */	0x8E,0xC3,			/* MOV ES,BX */
	/* 0046 */	0xB1,0x03,			/* MOV CL,03 */
	/* 0048 */	0xD3,0xE0,			/* SHL AX,CL */
	/* 004A */	0x89,0xC1,			/* MOV CX,AX */
	/* 004C */	0xD1,0xE0,			/* SHL AX,1 */
	/* 004E */	0x48,				/* DEC AX */
	/* 004F */	0x48,				/* DEC AX */
	/* 0050 */	0x8B,0xF0,			/* MOV SI,AX */
	/* 0052 */	0x8B,0xF8,			/* MOV DI,AX */
	/* 0054 */	0xF3,0xA5,			/* REP MOVSW */
	/* 0056 */	0x09,0xED,			/* OR BP,BP */
	/* 0058 */	0x75,0xD8,			/* JNZ 0032 */
	/* 005A */	0xFC,				/* CLD */
	/* 005B */	0x8E,0xC2,			/* MOV ES,DX */
	/* 005D */	0x8E,0xDB,			/* MOV DS,BX */
	/* 005F */	0x31,0xF6,			/* XOR SI,SI */
	/* 0061 */	0x31,0xFF,			/* XOR DI,DI */
	/* 0063 */	0xBA,0x10,0x00,			/* MOV DX,0010 */
	/* 0066 */	0xAD,				/* LODSW */
	/* 0067 */	0x89,0xC5,           /* MOV       BP,AX */
	/* 0069 */	0xD1,0xED,          /*  SHR       BP,1 */
	/* 006B */	0x4A,             /* DEC       DX */
	/* 006C */	0x75,0x05,           /* JNZ       0073 */
	/* 006E */	0xAD,             /* LODSW */
	/* 006F */	0x89,0xC5,           /* MOV       BP,AX */
	/* 0071 */	0xB2,0x10,           /* MOV       DL,10 */
	/* 0073 */	0x73,0x03,           /* JNB       0078 */
	/* 0075 */	0xA4,             /* MOVSB */
	/* 0076 */	0xEB,0xF1,          /*  JMP       0069 */
	/* 0078 */	0x31,0xC9,           /* XOR       CX,CX */
	/* 007A */	0xD1,0xED,           /* SHR       BP,1 */
	/* 007C */	0x4A,             /* DEC       DX */
	/* 007D */	0x75,0x05,           /* JNZ       0084 */
	/* 007F */	0xAD,             /* LODSW */
	/* 0080 */	0x89,0xC5,           /* MOV       BP,AX */
	/* 0082 */	0xB2,0x10,           /* MOV       DL,10 */
	/* 0084 */	0x72,0x22,           /* JB        00A8 */
	/* 0086 */	0xD1,0xED,           /* SHR       BP,1 */
	/* 0088 */	0x4A,             /* DEC       DX */
	/* 0089 */	0x75,0x05,           /* JNZ       0090 */
	/* 008B */	0xAD,             /* LODSW */
	/* 008C */	0x89,0xC5,           /* MOV       BP,AX */
	/* 008E */	0xB2,0x10,           /* MOV       DL,10 */
	/* 0090 */	0xD1,0xD1,           /* RCL       CX,1 */
	/* 0092 */	0xD1,0xED,           /* SHR       BP,1 */
	/* 0094 */	0x4A,             /* DEC       DX */
	/* 0095 */	0x75,0x05,           /* JNZ       009C */
	/* 0097 */	0xAD,             /* LODSW */
	/* 0098 */	0x89,0xC5,           /* MOV       BP,AX */
	/* 009A */	0xB2,0x10,           /* MOV       DL,10 */
	/* 009C */	0xD1,0xD1,           /* RCL       CX,1 */
	/* 009E */	0x41,             /* INC       CX */
	/* 009F */	0x41,             /* INC       CX */
	/* 00A0 */	0xAC,             /* LODSB */
	/* 00A1 */	0xB7,0xFF,           /* MOV       BH,FF */
	/* 00A3 */	0x8A,0xD8,           /* MOV       BL,AL */
	/* 00A5 */	0xE9,0x13,0x00,         /* JMP       00BB */
	/* 00A8 */	0xAD,             /* LODSW */
	/* 00A9 */	0x8B,0xD8,           /* MOV       BX,AX */
	/* 00AB */	0xB1,0x03,           /* MOV       CL,03 */
	/* 00AD */	0xD2,0xEF,          /*  SHR       BH,CL */
	/* 00AF */	0x80,0xCF,0xE0,        /*  OR        BH,E0 */
	/* 00B2 */	0x80,0xE4,0x07,        /*  AND       AH,07 */
	/* 00B5 */	0x74,0x0C,           /* JZ        00C3 */
	/* 00B7 */	0x88,0xE1,           /* MOV       CL,AH */
	/* 00B9 */	0x41,            /*  INC       CX */
	/* 00BA */	0x41,             /* INC       CX */
	/* 00BB */	0x26,0x8A,0x01,         /* MOV       AL,BYTE PTR ES:[BX+DI] */
	/* 00BE */	0xAA,             /* STOSB */
	/* 00BF */	0xE2,0xFA,           /* LOOP      00BB */
	/* 00C1 */	0xEB,0xA6,           /* JMP       0069 */
	/* 00C3 */	0xAC,            /*  LODSB */
	/* 00C4 */	0x08,0xC0,           /* OR        AL,AL */
	/* 00C6 */	0x74,0x34,           /* JZ        00FC */
	/* 00C8 */	0x3C,0x01,           /* CMP       AL,01 */
	/* 00CA */	0x74,0x05,           /* JZ        00D1 */
	/* 00CC */	0x88,0xC1,           /* MOV       CL,AL */
	/* 00CE */	0x41,             /* INC       CX */
	/* 00CF */	0xEB,0xEA,           /* JMP       00BB */
	/* 00D1 */	0x89,0xFB,           /* MOV       BX,DI */
	/* 00D3 */	0x83,0xE7,0x0F,         /* AND       DI,0F */
	/* 00D6 */	0x81,0xC7,0x00,0x20,       /* ADD       DI,2000 */
	/* 00DA */	0xB1,0x04,           /* MOV       CL,04 */
	/* 00DC */	0xD3,0xEB,           /* SHR       BX,CL */
	/* 00DE */	0x8C,0xC0,           /* MOV       AX,ES */
	/* 00E0 */	0x01,0xD8,           /* ADD       AX,BX */
	/* 00E2 */	0x2D,0x00,0x02,        /*  SUB       AX,0200 */
	/* 00E5 */	0x8E,0xC0,           /* MOV       ES,AX */
	/* 00E7 */	0x89,0xF3,           /* MOV       BX,SI */
	/* 00E9 */	0x83,0xE6,0x0F,         /* AND       SI,0F */
	/* 00EC */	0xD3,0xEB,           /* SHR       BX,CL */
	/* 00EE */	0x8C,0xD8,           /* MOV       AX,DS */
	/* 00F0 */	0x01,0xD8,           /* ADD       AX,BX */
	/* 00F2 */	0x8E,0xD8,           /* MOV       DS,AX */
	/* 00F4 */	0xE9,0x72,0xFF,         /* JMP       0069 */
	/* 00F7 */	0x2A,0x46,0x41,         /* SUB       AL,BYTE PTR [BP+41] */
	/* 00FA */	0x42,             /* INC       DX */
	/* 00FB */	0x2A,0x0E,0x1F,0xBE,       /* SUB       CL,BYTE PTR [BE1F] */
	/* 00FF */	0x58,             /* POP       AX */
	/* 0100 */	0x01,0x5B,0x83,         /* ADD       WORD PTR [BP+DI-7D],BX */
	/* 0103 */	0xC3,             /* RET */
	/* 0104 */	0x10,0x89,0xDA,0x31,       /* ADC       BYTE PTR [BX+DI+31DA],CL */
	/* 0108 */	0xFF,0xAC,0x08,0xC0,       /* JMP       DWORD PTR [SI-3FF8] */
	/* 010C */	0x74,0x16,           /* JZ        0124 */
	/* 010E */	0xB4,0x00,           /* MOV       AH,00 */
	/* 0110 */	0x01,0xC7,           /* ADD       DI,AX */
	/* 0112 */	0x8B,0xC7,           /* MOV       AX,DI */
	/* 0114 */	0x83,0xE7,0x0F,         /* AND       DI,0F */
	/* 0117 */	0xB1,0x04,           /* MOV       CL,04 */
	/* 0119 */	0xD3,0xE8,           /* SHR       AX,CL */
	/* 011B */	0x01,0xC2,           /* ADD       DX,AX */
	/* 011D */	0x8E,0xC2,           /* MOV       ES,DX */
	/* 011F */	0x26,0x01,0x1D,         /* ADD       WORD PTR ES:[DI],BX */
	/* 0122 */	0xEB,0xE5,           /* JMP       0109 */
	/* 0124 */	0xAD,            /*  LODSW */
	/* 0125 */	0x09,0xC0,           /* OR        AX,AX */
	/* 0127 */	0x75,0x08,          /*  JNZ       0131 */
	/* 0129 */	0x81,0xC2,0xFF,0x0F,       /* ADD       DX,0FFF */
	/* 012D */	0x8E,0xC2,           /* MOV       ES,DX */
	/* 012F */	0xEB,0xD8,           /* JMP       0109 */
	/* 0131 */	0x3D,0x01,0x00,         /* CMP       AX,0001 */
	/* 0134 */	0x75,0xDA,           /* JNZ       0110 */
	/* 0136 */	0x8B,0xC3,           /* MOV       AX,BX */
	/* 0138 */	0x8B,0x3E,0x04,0x00,       /* MOV       DI,WORD PTR [0004] */
	/* 013C */	0x8B,0x36,0x06,0x00,       /* MOV       SI,WORD PTR [0006] */
	/* 0140 */	0x01,0xC6,          /*  ADD       SI,AX */
	/* 0142 */	0x01,0x06,0x02,0x00,       /* ADD       WORD PTR [0002],AX */
	/* 0146 */	0x2D,0x10,0x00,         /* SUB       AX,0010 */
	/* 0149 */	0x8E,0xD8,           /* MOV       DS,AX */
	/* 014B */	0x8E,0xC0,          /*  MOV       ES,AX */
	/* 014D */	0x31,0xDB,          /*  XOR       BX,BX */
	/* 014F */	0xFA,            /*  CLI */
	/* 0150 */	0x8E,0xD6,          /*  MOV       SS,SI */
	/* 0152 */	0x8B,0xE7,          /*  MOV       SP,DI */
	/* 0154 */	0xFB,            /*  STI */
	/* 0155 */	0x2E,0xFF,0x2F         /* JMP       DWORD PTR CS:[BX] */
	/* 0158         0x00,0x01 */
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
	if (r_le16r(seg+0x27) < 0x002B)
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
	fprintf(stdout,"Unreal v1.1 stage #2:\n");
	fprintf(stdout,"    Initial BP/AX?                          0x%04x\n",r_le16r(seg+0x08));

	if (cpy < 16)
		return 0;

	/* the memcpy region the code uses should exist entirely inside the part of
	 * the EXE made resident */
	if ((exehdr_rgn.csip_offset+r_le16r(seg+0x0C)-0x000EUL) > exehdr_rgn.image_end)
		return 0;

	new_exerange(exehdr_rgn.csip_offset-0x000EUL,
		exehdr_rgn.csip_offset+r_le16r(seg+0x27)-0x000EUL-1UL,
		"Unreal v1.1 stage #1");

	new_exerange(exehdr_rgn.csip_offset+r_le16r(seg+0x27)-0x000EUL,
		exehdr_rgn.csip_offset+r_le16r(seg+0x0C)-0x000EUL-1UL,
		"Unreal v1.1 stage #2 <memcpy'd>");

	p = seg;
	if ((p2=ofs2res(entry,cpy)) == NULL)
		return 0;

	fprintf(stdout,"     ^ Carrying out memcpy\n");
	memcpy(p2,p,cpy);

	if ((p=ofs2res(exehdr_rgn.csip_offset+r_le16r(seg+0x27)-0x000EUL,sizeof(code_at_entry_002B))) == NULL)
		return 0;
	if (memcmp(p,code_at_entry_002B,sizeof(code_at_entry_002B)) != 0)
		return 0;
	fprintf(stdout,"     ^ Second part matches\n");

	return 1;
}

/* Other interesting notes:
 *    - Some of the files within are EXE files.
 *    - Most of the EXE files are compressed with LZEXE (LZ91 signature at 0x1C) */
void identify_fc_unreal() {
	struct msdos_exe_fc_unreal_dirent udr;
	uint32_t ofs,max;
	uint32_le_t t32;

	if (!identify_fc_unreal_11() && !identify_fc_unreal_10())
		return; /* got it */

	/* here's the fun part: there is an index at the END of the EXE that can be
	 * used to find the files inside the EXE. */
	if (lseek(exe_fd,exehdr_rgn.file_end-4,SEEK_SET) != (exehdr_rgn.file_end-4))
		return;
	if (read(exe_fd,&t32,4) != 4)
		return;
	if (lseek(exe_fd,t32,SEEK_SET) != t32)
		return;
	if ((t32+12) >= exehdr_rgn.file_end)
		return;

	new_exerange(t32,t32+11,
		"Unreal directory header");
	new_exerange(t32+12,exehdr_rgn.file_end-4-1,
		"Unreal directory");
	new_exerange(exehdr_rgn.file_end-4,exehdr_rgn.file_end-1,
		"Unreal directory pointer");

	/* the directory starts with 3 DWORDS:
	 *
	 * <unknown> 0x00C82FC0
	 * <EXE offset to somewhere inside the resident area? Value is 0x61>
	 * <EXE resident image end>
	 *
	 * then it is followed by an array of msdos_exe_fc_unreal_dirent structs */
	ofs = t32+12;
	max = exehdr_rgn.file_end-4;
	if (lseek(exe_fd,ofs,SEEK_SET) != ofs) return;
	while (ofs < max) {
		if (read(exe_fd,&udr,sizeof(udr)) != sizeof(udr))
			break;

		{
			size_t l;
			struct exe_range *rg = new_exerange(r_le32(&udr.offset),r_le32(&udr.offset)+r_le32(&udr.length)-1UL,NULL);
			l = 15; while (l > 0 && udr.name[l] == 0) l--; l++;
			rg->alloc_str = 1;
			rg->str = malloc(l+1);
			if (rg->str) {
				memcpy(rg->str,udr.name,l);
				rg->str[l] = 0;
			}
		}
	}
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
	if (resident_size >= 0x100 && resident_size <= 0x10000) {
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
#if 0
		/* DEBUG write resident buffer */
		int fd = open("/tmp/fcunreal.tmp",O_CREAT|O_TRUNC|O_WRONLY,0644);
		if (fd >= 0) {
			lseek(fd,exehdr_rgn.image_ofs,SEEK_SET);
			write(fd,resident,resident_size);
			close(fd);
		}
#endif
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

