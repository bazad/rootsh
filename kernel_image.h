/* kernel_image.h
 * Brandon Azad
 *
 * Kernel parsing routines to find addresses of symbols and byte sequences.
 */

#include <mach-o/loader.h>
#include <stdlib.h>

int load_kernel();
int find_kernel_symbol(const char * name, uint64_t * addr);
int find_kernel_bytes(const void * value, size_t size, uint64_t * addr);
