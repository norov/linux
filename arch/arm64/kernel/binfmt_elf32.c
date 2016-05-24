/*
 * Support for AArch32 Linux ELF binaries.
 */

/* AArch32 EABI. */
#define EF_ARM_EABI_MASK		0xff000000

#define compat_start_thread		compat_start_thread
#define COMPAT_SET_PERSONALITY(ex)		\
do {						\
	clear_thread_flag(TIF_32BIT_AARCH64);	\
	set_thread_flag(TIF_32BIT);		\
} while (0)

#define COMPAT_ARCH_DLINFO
#define COMPAT_ELF_HWCAP		(compat_elf_hwcap)
#define COMPAT_ELF_HWCAP2		(compat_elf_hwcap2)

#ifdef __AARCH64EB__
#define COMPAT_ELF_PLATFORM		("v8b")
#else
#define COMPAT_ELF_PLATFORM		("v8l")
#endif

#define compat_arch_setup_additional_pages \
					aarch32_setup_vectors_page
struct linux_binprm;
extern int aarch32_setup_vectors_page(struct linux_binprm *bprm,
				      int uses_interp);

#include "../../../fs/compat_binfmt_elf.c"
