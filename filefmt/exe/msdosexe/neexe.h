#ifndef __FILEFMT_EXE_MSDOS_NEEXE_H
#define __FILEFMT_EXE_MSDOS_NEEXE_H

#pragma pack(push,1)
struct windows_ne_header {
	uint16_le_t		ne_sig;			/* +0x00 "NE" 0x4E 0x45 */
	uint8_t			linker_version;		/* +0x02 linker version */
	uint8_t			linker_revision;	/* +0x03 linker revision */
	uint16_le_t		entry_table_offset;	/* +0x04 offset of entry table relative to header */
	uint16_le_t		entry_table_length;	/* +0x06 length of entry table in bytes */
	uint32_le_t		file_crc_32;		/* +0x08 32-bit CRC of entire file */
	uint16_le_t		exe_flags;		/* +0x0C executable flags */
							/*   bit 0 = SINGLEDATA */
							/*   bit 1 = MULTIPLEDATA  (if bits[1:0] == 0 then NOAUTODATA) */
							/*   bit 11 = first segment contains code that loads the application */
							/*   bit 13 = linker detected errors at link time */
							/*   bit 15 = executable file is a library module */
	uint16_le_t		auto_data_segment;	/* +0x0E number of the automatic data segment (0 if NOAUTODATA, else 1-based segment index) */
	uint16_le_t		initial_local_heap;	/* +0x10 initial size of the dynamic/local heap added to data segment */
	uint16_le_t		initial_stack_size;	/* +0x12 initial size of the stack. Zero if SS != DS */
	uint16_le_t		offset_ip;		/* +0x14 initial IP */
	uint16_le_t		segment_cs;		/* +0x16 initial CS (segment number) */
	uint16_le_t		offset_sp;		/* +0x18 initial SP */
	uint16_le_t		segment_ss;		/* +0x1A initial SS (segment number) */
	uint16_le_t		segment_table_entries;	/* +0x1C number of entries in the segment table */
	uint16_le_t		module_ref_table_entries;/* +0x1E number of entries in the module reference table */
	uint16_le_t		nonresident_table_length;/* +0x20 number of bytes in the non-resident table */
	uint16_le_t		segment_table_offset;	/* +0x22 offset of segment table, relative to header */
	uint16_le_t		resource_table_offset;	/* +0x24 offset of resource table, relative to header */
	uint16_le_t		resident_name_table_offset;/* +0x26 offset of resident name table */
	uint16_le_t		module_ref_table_offset;/* +0x28 offset module reference table offset relative to header */
	uint16_le_t		imported_name_table_offset;/* +0x2A offset of imported names table relative to header */
	uint32_le_t		nonresident_table_offset;/* +0x2C offset of non-resident table, from start of file */
	uint16_le_t		movable_entries;	/* +0x30 number of movable entries in entry table */
	uint16_le_t		sector_align_shift;	/* +0x32 logical sector alignment shift count */
	uint16_le_t		number_of_resource_entries;/* +0x34 number of resource entries */
	uint8_t			executable_type;	/* +0x36 exe type. (2 = Windows, or bit 2 is windows??) */
	uint8_t			exe_additional_info;	/* +0x37 */
	uint16_le_t		offset_fastload_area;	/* +0x38 offset in sectors of fast-load area */
	uint16_le_t		length_fastload_area;	/* +0x3A length in sectors of fast-load area */
	uint16_le_t		reserved3C;		/* +0x3C */
	uint16_le_t		win_expected_version;	/* +0x3E expected version of Windows */
							/* +0x40 */
};

struct windows_ne_segment_table_entry {
	uint16_le_t		offset;		/* offset in sectors */
	uint16_le_t		length;		/* in bytes */
	uint16_le_t		flags;
	uint16_le_t		minimum_alloc;
};
#pragma pack(pop)

#endif /* __FILEFMT_EXE_MSDOS_NEEXE_H */

