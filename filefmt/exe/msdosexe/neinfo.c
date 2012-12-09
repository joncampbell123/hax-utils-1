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

static int			exe_fd = -1;
static char*			exe_file = NULL;

static void help() {
	fprintf(stderr,"neinfo [options] <MS-DOS/Windows NE EXE file>\n");
	fprintf(stderr,"jmc hax-utils-v1 Windows NE EXE info dumper\n");
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

static void dump_ne(int exe_fd,uint32_t hdr_ofs) {
	struct windows_ne_segment_table_entry te;
	struct windows_ne_header ne_mainhdr;
	uint32_t ofs,len;
	unsigned int i;

	if (sizeof(struct windows_ne_header) != 0x40)
		return;
	if (lseek(exe_fd,hdr_ofs,SEEK_SET) != hdr_ofs)
		return;
	if (read(exe_fd,&ne_mainhdr,sizeof(ne_mainhdr)) != sizeof(ne_mainhdr))
		return;

	new_exerange(hdr_ofs,hdr_ofs+0x3F,"NE main header");

	if (r_le16(&ne_mainhdr.entry_table_offset) != 0 && r_le16(&ne_mainhdr.entry_table_length) != 0)
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.entry_table_offset)),
			hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.entry_table_offset))+
			(uint32_t)r_le16(&ne_mainhdr.entry_table_length)-1UL,
			"NE entry table");

	if (r_le16(&ne_mainhdr.segment_table_offset) != 0 && r_le16(&ne_mainhdr.segment_table_entries) != 0)
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.segment_table_offset)),
			hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.segment_table_offset))+
			((uint32_t)r_le16(&ne_mainhdr.segment_table_entries) * 8UL)-1UL,
			"NE segment table");

	if (r_le16(&ne_mainhdr.offset_fastload_area) != 0 && r_le16(&ne_mainhdr.length_fastload_area) != 0 &&
		r_le16(&ne_mainhdr.sector_align_shift) < 16) {
		uint32_t ofs = (uint32_t)r_le16(&ne_mainhdr.offset_fastload_area) <<
			(uint32_t)r_le16(&ne_mainhdr.sector_align_shift);
		uint32_t len = (uint32_t)r_le16(&ne_mainhdr.length_fastload_area) <<
			(uint32_t)r_le16(&ne_mainhdr.sector_align_shift);
		new_exerange(ofs,ofs+len-1UL,"NE fastload area");
	}

	if (r_le32(&ne_mainhdr.nonresident_table_offset) != 0 && r_le16(&ne_mainhdr.nonresident_table_length) != 0)
		new_exerange(r_le32(&ne_mainhdr.nonresident_table_offset),
			r_le32(&ne_mainhdr.nonresident_table_offset)+((uint32_t)r_le16(&ne_mainhdr.nonresident_table_length)),
			"NE nonresident name table");

	if (r_le16(&ne_mainhdr.module_ref_table_offset) != 0 && r_le16(&ne_mainhdr.module_ref_table_entries) != 0)
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.module_ref_table_offset)),
			hdr_ofs-1UL+((uint32_t)r_le16(&ne_mainhdr.module_ref_table_offset))+
			((uint32_t)r_le16(&ne_mainhdr.module_ref_table_entries)) * 2UL,
			"NE module reference table");

	if (r_le16(&ne_mainhdr.resource_table_offset) != 0 && r_le16(&ne_mainhdr.resident_name_table_offset) != 0 &&
		r_le16(&ne_mainhdr.resource_table_offset) < r_le16(&ne_mainhdr.resident_name_table_offset))
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.resource_table_offset)),
			hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.resident_name_table_offset))-1UL,
			"NE resource table");

	if (r_le16(&ne_mainhdr.resident_name_table_offset) != 0 && r_le16(&ne_mainhdr.module_ref_table_offset) != 0 &&
		r_le16(&ne_mainhdr.resident_name_table_offset) < r_le16(&ne_mainhdr.module_ref_table_offset))
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.resident_name_table_offset)),
			hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.module_ref_table_offset))-1UL,
			"NE resident name table");

	if (r_le16(&ne_mainhdr.imported_name_table_offset) != 0 && r_le16(&ne_mainhdr.entry_table_offset) != 0 &&
		r_le16(&ne_mainhdr.imported_name_table_offset) < r_le16(&ne_mainhdr.entry_table_offset))
		new_exerange(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.imported_name_table_offset)),
			hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.entry_table_offset))-1UL,
			"NE imported name table");

	fprintf(stdout,"NE (New Executable) main header (at %lu):\n",(unsigned long)hdr_ofs);
	fprintf(stdout,"    Linker version:                              %u\n",ne_mainhdr.linker_version);
	fprintf(stdout,"    Linker revision:                             %u\n",ne_mainhdr.linker_revision);
	fprintf(stdout,"    Entry table offset:                          %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.entry_table_offset)),
		r_le16(&ne_mainhdr.entry_table_offset));
	fprintf(stdout,"    Entry table length:                          %u\n",
		r_le16(&ne_mainhdr.entry_table_length));
	fprintf(stdout,"    32-bit CRC:                                  0x%08lX\n",
		(unsigned long)r_le32(&ne_mainhdr.file_crc_32));
	fprintf(stdout,"    EXE flags:                                   0x%04X\n",
		r_le16(&ne_mainhdr.exe_flags));
	fprintf(stdout,"    Auto data segment:                           0x%04X\n",
		r_le16(&ne_mainhdr.auto_data_segment));
	fprintf(stdout,"    Initial local heap:                          %u\n",
		r_le16(&ne_mainhdr.initial_local_heap));
	fprintf(stdout,"    Initial stack size:                          %u\n",
		r_le16(&ne_mainhdr.initial_stack_size));
	fprintf(stdout,"    CS:IP:                                       0x%04X:0x%04X\n",
		r_le16(&ne_mainhdr.segment_cs),
		r_le16(&ne_mainhdr.offset_ip));
	fprintf(stdout,"    SS:SP:                                       0x%04X:0x%04X\n",
		r_le16(&ne_mainhdr.segment_ss),
		r_le16(&ne_mainhdr.offset_sp));
	fprintf(stdout,"    Segment table entries:                       %u\n",
		r_le16(&ne_mainhdr.segment_table_entries));
	fprintf(stdout,"    Module reference table entries:              %u\n",
		r_le16(&ne_mainhdr.module_ref_table_entries));
	fprintf(stdout,"    Nonresident table length:                    %u\n",
		r_le16(&ne_mainhdr.nonresident_table_length));
	fprintf(stdout,"    Segment table offset:                        %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.segment_table_offset)),
		r_le16(&ne_mainhdr.segment_table_offset));
	fprintf(stdout,"    Resource table offset:                       %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.resource_table_offset)),
		r_le16(&ne_mainhdr.resource_table_offset));
	fprintf(stdout,"    Resident name table offset:                  %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.resident_name_table_offset)),
		r_le16(&ne_mainhdr.resident_name_table_offset));
	fprintf(stdout,"    Module reference table offset:               %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.module_ref_table_offset)),
		r_le16(&ne_mainhdr.module_ref_table_offset));
	fprintf(stdout,"    Imported name table offset:                  %u (+%u)\n",
		hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.imported_name_table_offset)),
		r_le16(&ne_mainhdr.imported_name_table_offset));
	fprintf(stdout,"    Nonresident table offset:                    %lu\n",
		(unsigned long)r_le32(&ne_mainhdr.nonresident_table_offset));
	fprintf(stdout,"    Movable entries:                             %u\n",
		r_le16(&ne_mainhdr.movable_entries));
	fprintf(stdout,"    Sector align shift:                          %u (%lu bytes)\n",
		r_le16(&ne_mainhdr.sector_align_shift),
		1UL << r_le16(&ne_mainhdr.sector_align_shift));
	fprintf(stdout,"    Number of resource entries:                  %u\n",
		r_le16(&ne_mainhdr.number_of_resource_entries));
	fprintf(stdout,"    EXE type flags:                              0x%02x\n",
		ne_mainhdr.executable_type);
	fprintf(stdout,"    EXE additional info:                         0x%02x\n",
		ne_mainhdr.exe_additional_info);
	fprintf(stdout,"    Fastload area offset:                        %lu\n",
		(unsigned long)r_le16(&ne_mainhdr.offset_fastload_area) <<
		(unsigned long)r_le16(&ne_mainhdr.sector_align_shift));
	fprintf(stdout,"    Fastload area length:                        %lu\n",
		(unsigned long)r_le16(&ne_mainhdr.length_fastload_area) <<
		(unsigned long)r_le16(&ne_mainhdr.sector_align_shift));
	fprintf(stdout,"    Expected Windows version:                    0x%04x (%d.%d)\n",
		r_le16(&ne_mainhdr.win_expected_version),
		r_le16(&ne_mainhdr.win_expected_version) >> 8,
		r_le16(&ne_mainhdr.win_expected_version) & 0xFF);

	if (r_le16(&ne_mainhdr.segment_table_offset) != 0 && r_le16(&ne_mainhdr.segment_table_entries) != 0) {
		fprintf(stdout,"NE (New Executable) segment table:\n");
		for (i=0;i < (unsigned int)r_le16(&ne_mainhdr.segment_table_entries);i++) {
			if (lseek(exe_fd,hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.segment_table_offset))+(i*8UL),SEEK_SET) !=
				(hdr_ofs+((uint32_t)r_le16(&ne_mainhdr.segment_table_offset))+(i*8UL)))
				break;

			if (read(exe_fd,&te,sizeof(te)) != sizeof(te))
				break;

			fprintf(stdout,"    Sector #0x%X flags=0x%04x\n",i+1,r_le16(&te.flags));

			if (r_le16(&te.offset) != 0 && r_le16(&te.length) != 0) {
				ofs = (uint32_t)r_le16(&te.offset) << (uint32_t)r_le16(&ne_mainhdr.sector_align_shift);
				len = (uint32_t)r_le16(&te.length);
				if (len == 0UL) len = 0x10000UL;

				{
					struct exe_range *rg = new_exerange(ofs,ofs+len-1UL,NULL);
					size_t l = sprintf((char*)temp,"NE Segment #0x%X",i+1);

					rg->alloc_str = 1;
					rg->str = malloc(l+1);
					if (rg->str) memcpy(rg->str,temp,l+1);
				}

				fprintf(stdout,"        Offset:                                  %lu\n",(unsigned long)ofs);
				fprintf(stdout,"        Length:                                  %lu\n",(unsigned long)len);

				if (r_le16(&te.flags) & 0x0100) { /* bit 8 is set if relocations follow the segment */
					uint16_t count;

					if (lseek(exe_fd,ofs+len,SEEK_SET) != (ofs+len))
						continue;
					if (read(exe_fd,&count,2) != 2)
						continue;

					{
						struct exe_range *rg = new_exerange(ofs+len,ofs+len+2UL+((unsigned long)count * 8UL)-1UL,NULL);
						size_t l = sprintf((char*)temp,"NE Segment #0x%X relocation data",i+1);

						rg->alloc_str = 1;
						rg->str = malloc(l+1);
						if (rg->str) memcpy(rg->str,temp,l+1);
					}
				}
			}

			fprintf(stdout,"        Minimum allocation:                      %lu\n",
				te.minimum_alloc == 0 ? 65536UL : (unsigned long)r_le16(&te.minimum_alloc));
		}
	}
}

int main(int argc,char **argv) {
	struct msdos_exe_header_regions exehdr_rgn;
	struct msdos_exe_header exehdr;
	uint32_t ofs=0;
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

	/* MS-Windows and other formats extend the EXE format with an offset at 0x3C */
	if (r_le16(&exehdr.header_size_in_paragraphs) >= 4) {
		lseek(exe_fd,0x3C,SEEK_SET);
		read(exe_fd,&ofs,4);
		ofs = r_le32(&ofs);
	}

	if (ofs >= 0x40) {
		lseek(exe_fd,ofs,SEEK_SET);
		read(exe_fd,temp,4);

		if (!memcmp(temp,"NE",2)) {
			/* HACK: More often than not Win16 compiled executables are generated
			 *       with the MS-DOS resident image region containing the NE header
			 *       even if the actual stub is the usual 100-byte "This program
			 *       requires Microsoft Windows" error message. In many cases it
			 *       seems, executables generated by Microsoft's linker seem to
			 *       have the resident image ALMOST cover the entire NE header,
			 *       but not quite, while others have the resident image cover the
			 *       entire Win16 segments, resources and all---which is silly:
			 *       can you imagine DOS loading all that into memory just so the
			 *       stub can say "this program requires Microsoft Windows"?
			 *
			 *       To avoid needless "this region extends past the end" messages,
			 *       we cut the "end of image" offset to just before the NE offset */
			new_exerange(0x3C,0x3F,"Extended header pointer");

			if (exehdr_rgn.image_end > ofs) {
				fprintf(stderr,"Truncating resident image end to exclude NE header (--nonetr to disable)\n");
				exehdr_rgn.image_end = ofs;
			}
		}
		else {
			ofs = 0;
		}
	}
	else {
		ofs = 0;
	}

	msdos_exe_header_add_regions(&exehdr_rgn);
	msdos_exe_header_dump_entrypoints(stdout,exe_fd,&exehdr_rgn);

	if (exehdr_rgn.image_ofs < exehdr_rgn.image_end)
		identify_msdos_stub(exe_fd,&exehdr,&exehdr_rgn);

	if (ofs != 0) dump_ne(exe_fd,ofs);

	/* we do rudimentary checking for other extensions---check the bytes immediately after the resident image */
	if (exehdr_rgn.image_end != 0 && exehdr_rgn.image_end < exehdr_rgn.file_end) {
		lseek(exe_fd,exehdr_rgn.image_end,SEEK_SET);
		r = read(exe_fd,temp,sizeof(temp));
		if (r < sizeof(temp)) memset(temp+r,0,sizeof(temp)-r);

		if (!memcmp(temp,"ARJ_SFX\0",8)) {
			new_exerange(exehdr_rgn.image_end,exehdr_rgn.image_end+8UL+32UL-1UL,"ARJ self-extracting executable package header");
		}
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

