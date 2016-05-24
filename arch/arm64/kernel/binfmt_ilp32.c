/*
 * Support for ILP32 Linux/aarch64 ELF binaries.
 */
#define USE_AARCH64_GREG

#include <linux/elfcore-compat.h>
#include <linux/time.h>

#undef	ELF_CLASS
#define ELF_CLASS	ELFCLASS32

#undef	elfhdr
#undef	elf_phdr
#undef	elf_shdr
#undef	elf_note
#undef	elf_addr_t
#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_shdr	elf32_shdr
#define elf_note	elf32_note
#define elf_addr_t	Elf32_Addr

/*
 * Some data types as stored in coredump.
 */
#define user_long_t		compat_long_t
#define user_siginfo_t		compat_siginfo_t
#define copy_siginfo_to_user	copy_siginfo_to_user32

/*
 * The machine-dependent core note format types are defined in elfcore-compat.h,
 * which requires asm/elf.h to define compat_elf_gregset_t et al.
 */
#define elf_prstatus	compat_elf_prstatus
#define elf_prpsinfo	compat_elf_prpsinfo

/*
 * Compat version of cputime_to_compat_timeval, perhaps this
 * should be an inline in <linux/compat.h>.
 */
static void cputime_to_compat_timeval(const cputime_t cputime,
				      struct compat_timeval *value)
{
	struct timeval tv;

	cputime_to_timeval(cputime, &tv);
	value->tv_sec = tv.tv_sec;
	value->tv_usec = tv.tv_usec;
}

#undef cputime_to_timeval
#define cputime_to_timeval cputime_to_compat_timeval

/* AARCH64 ILP32 EABI. */
#undef elf_check_arch
#define elf_check_arch(x)		(((x)->e_machine == EM_AARCH64)	\
					&& (x)->e_ident[EI_CLASS] == ELFCLASS32)

#undef SET_PERSONALITY
#define SET_PERSONALITY(ex)						\
do {									\
	set_thread_flag(TIF_32BIT_AARCH64);				\
	clear_thread_flag(TIF_32BIT);					\
} while (0)

#undef ARCH_DLINFO
#define ARCH_DLINFO							\
do {									\
	NEW_AUX_ENT(AT_SYSINFO_EHDR,					\
		    (elf_addr_t)(long)current->mm->context.vdso);	\
} while (0)

#undef ELF_PLATFORM
#ifdef __AARCH64EB__
#define ELF_PLATFORM		("aarch64_be:ilp32")
#else
#define ELF_PLATFORM		("aarch64:ilp32")
#endif

#undef ELF_ET_DYN_BASE
#define ELF_ET_DYN_BASE COMPAT_ELF_ET_DYN_BASE

#undef ELF_HWCAP
#undef ELF_HWCAP2
#define ELF_HWCAP			((u32) elf_hwcap)
#define ELF_HWCAP2			((u32) (elf_hwcap >> 32))

/*
 * Rename a few of the symbols that binfmt_elf.c will define.
 * These are all local so the names don't really matter, but it
 * might make some debugging less confusing not to duplicate them.
 */
#define elf_format		compat_elf_format
#define init_elf_binfmt		init_compat_elf_binfmt
#define exit_elf_binfmt		exit_compat_elf_binfmt

#include "../../../fs/binfmt_elf.c"
