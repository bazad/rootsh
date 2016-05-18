/* kernel_slide.h
 * Brandon Azad
 *
 * Kernel information leak to recover the kernel slide.
 */

#include <stdint.h>

extern uint64_t kernel_slide;

int find_kernel_slide();
