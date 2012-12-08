#ifndef __UTIL_RAWINT_H
#define __UTIL_RAWINT_H

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
#endif

/* these typedefs exist solely to remind me that they are little endian,
 * and must be converted to host byte order if the CPU is big endian */
typedef uint16_t	uint16_le_t;
typedef uint32_t	uint32_le_t;
typedef uint64_t	uint64_le_t;

/* these macros are for reading the little Endian values in the header.
 * one is used if you intend to use it on structure fields, the other
 * if you intend to point it at raw buffer data. */
static inline uint16_t r_le16(const uint16_le_t *x) {
	return *((const uint16_t*)x);
}

static inline uint16_t r_le16r(const void *x) {
	return *((const uint16_t*)x);
}

static inline uint32_t r_le32(const uint32_le_t *x) {
	return *((const uint32_t*)x);
}

static inline uint32_t r_le32r(const void *x) {
	return *((const uint32_t*)x);
}

static inline uint64_t r_le64(const uint64_le_t *x) {
	return *((const uint64_t*)x);
}

static inline uint64_t r_le64r(const void *x) {
	return *((const uint64_t*)x);
}

#endif /* __UTIL_RAWINT_H */

