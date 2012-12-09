#ifndef __FILEFMT_EXE_MSDOS_STUBS_H
#define __FILEFMT_EXE_MSDOS_STUBS_H

#include "util/rawint.h"
#include "filefmt/exe/msdosexe/neexe.h"
#include "filefmt/exe/msdosexe/stubs.h"
#include "filefmt/exe/msdosexe/dosexe.h"
#include "filefmt/exe/msdosexe/exerange.h"
#include "filefmt/exe/msdosexe/exeparse.h"

void identify_msdos_stub(int exe_fd,struct msdos_exe_header *h,struct msdos_exe_header_regions *r);

#endif /* __FILEFMT_EXE_MSDOS_STUBS_H */

