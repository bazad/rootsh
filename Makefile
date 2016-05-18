TARGET = rootsh

all: $(TARGET)

CFLAGS = -Wall -Wpedantic -Werror
FRAMEWORKS = -framework IOKit

# Note that in addition to the standard flags we also need
#
#	-m32 -Wl,-pagezero_size,0
#
# We need these flags because we are leveraging the use-after-free to generate
# a kernel NULL-pointer dereference. By mapping the NULL page in user space we
# ensure that when the kernel dereferences the NULL pointer it gets a value
# that we control. OS X does not allow 64-bit processes to map the NULL page;
# however, for legacy support, 32-bit processes can map the NULL page. In order
# to do so we generate a Mach-O executable without an initial __PAGEZERO
# segment protecting NULL. The "-m32" flag compiles the executable as 32-bit,
# while the "-Wl,-pagezero_size,0" flag causes the linker to not insert a
# __PAGEZERO segment in the final Mach-O executable.
$(TARGET): main.c kernel_image.c kernel_rop.c kernel_slide.c
	clang $(CFLAGS) $(FRAMEWORKS) -m32 -Wl,-pagezero_size,0 -O3 $^ -o $@

clean:
	rm -f -- $(TARGET)
