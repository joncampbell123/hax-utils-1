#ifndef __FILEFMT_EXE_MSDOS_DOSEXE_H
#define __FILEFMT_EXE_MSDOS_DOSEXE_H

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

struct msdos_pe_coff_header { /* does NOT include "PE\0\0" signature */
	uint16_le_t		Machine;			/* +0x00 */
	uint16_le_t		NumberOfSections;		/* +0x02 */
	uint32_le_t		TimeDateStamp;			/* +0x04 */
	uint32_le_t		PointerToSymbolTable;		/* +0x08 */
	uint32_le_t		NumberOfSymbols;		/* +0x0C */
	uint16_le_t		SizeOfOptionalHeader;		/* +0x10 */
	uint16_le_t		Characteristics;		/* +0x12 */
								/* +0x14 */
};

/* information parsed from header */
struct msdos_exe_header_regions {
	uint32_t reloc_ofs,reloc_end;		/* first byte, last byte + 1 */
	uint16_t reloc_entries;	
	uint32_t header_end;
	uint32_t image_ofs;			/* first byte */
	uint32_t image_end;			/* last byte + 1 */
	uint32_t file_end;			/* last byte + 1 */
};
#pragma pack(pop)

#endif /* __FILEFMT_EXE_MSDOS_DOSEXE_H */

