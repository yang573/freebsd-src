/*	$NetBSD: subr_asan.c,v 1.10 2019/06/15 06:40:34 maxv Exp $	*/

/*
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Maxime Villard.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/asan.h>

#ifdef KASAN_PANIC
#define REPORT panic
#else
#define REPORT printf
#endif

/* ASAN constants. Part of the compiler ABI. */
#define KASAN_SHADOW_SCALE_SHIFT	3
#define KASAN_SHADOW_SCALE_SIZE		(1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK		(KASAN_SHADOW_SCALE_SIZE - 1)

/* The MD code. */
#include <machine/asan.h>

/* ASAN ABI version. */
#if defined(__clang__) && (__clang_major__ - 0 >= 6)
#define ASAN_ABI_VERSION	8
#elif __GNUC_PREREQ__(7, 1) && !defined(__clang__)
#define ASAN_ABI_VERSION	8
#elif __GNUC_PREREQ__(6, 1) && !defined(__clang__)
#define ASAN_ABI_VERSION	6
#else
#error "Unsupported compiler version"
#endif

#define __RET_ADDR	(unsigned long)__builtin_return_address(0)

/* Global variable descriptor. Part of the compiler ABI.  */
struct __asan_global_source_location {
	const char *filename;
	int line_no;
	int column_no;
};
struct __asan_global {
	const void *beg;			/* address of the global variable */
	size_t size;				/* size of the global variable */
	size_t size_with_redzone;		/* size with the redzone */
	const void *name;			/* name of the variable */
	const void *module_name;		/* name of the module where the var is declared */
	unsigned long has_dynamic_init;		/* the var has dyn initializer (c++) */
	struct __asan_global_source_location *location;
#if ASAN_ABI_VERSION >= 7
	uintptr_t odr_indicator;		/* the address of the ODR indicator symbol */
#endif
};

static bool kasan_enabled __read_mostly = false;

/* -------------------------------------------------------------------------- */

void
kasan_shadow_map(void *addr, size_t size)
{
	size_t sz, npages, i;
	vm_offset_t sva, eva; // start and end of VA

	KASSERT((vm_offset_t)addr % KASAN_SHADOW_SCALE_SIZE == 0,
			("kasan_shadow_map: Address %p is incorrectly aligned", addr));

	sz = roundup(size, KASAN_SHADOW_SCALE_SIZE) / KASAN_SHADOW_SCALE_SIZE;

	sva = (vm_offset_t)kasan_md_addr_to_shad(addr);
	eva = (vm_offset_t)kasan_md_addr_to_shad(addr) + sz;

	sva = rounddown(sva, PAGE_SIZE);
	eva = rounddown(eva, PAGE_SIZE);

	npages = (eva - sva) / PAGE_SIZE;

	KASSERT(sva >= KASAN_MIN_ADDRESS,
			("kasan_shadow_map: Start virtual address %jx is invalid", sva));
	KASSERT(eva < KASAN_MAX_ADDRESS,
			("kasan_shadow_map: End virtual address %jx is invalid", eva));

	for (i = 0; i < npages; i++) {
		kasan_md_shadow_map_page(sva + (i * PAGE_SIZE));
	}

	return;
}

void
kasan_early_init(void)
{
	kasan_md_early_init();
	return;
}

void
kasan_init(void)
{
	/* MD initialization */
	/* XXX: Currently a no-op */
	kasan_md_init();

	/* Officially enabled */
	kasan_enabled = true;

	return;
}

/* Enum to translate redzone values during kasan_report */
static inline const char *
kasan_code_name(uint8_t code)
{
	switch (code) {
	case KASAN_GENERIC_REDZONE:
		return "GenericRedZone";
	case KASAN_MALLOC_REDZONE:
		return "MallocRedZone";
	case KASAN_KMEM_REDZONE:
		return "KmemRedZone";
	case KASAN_POOL_REDZONE:
		return "PoolRedZone";
	case KASAN_POOL_FREED:
		return "PoolUseAfterFree";
	case 1 ... 7:
		return "RedZonePartial";
	case KASAN_STACK_LEFT:
		return "StackLeft";
	case KASAN_STACK_RIGHT:
		return "StackRight";
	case KASAN_STACK_PARTIAL:
		return "StackPartial";
	case KASAN_USE_AFTER_SCOPE:
		return "UseAfterScope";
	default:
		return "Unknown";
	}
}

static void
kasan_report(unsigned long addr, size_t size, bool write, unsigned long pc,
    uint8_t code)
{
	return;
}

static __always_inline void
kasan_shadow_1byte_markvalid(unsigned long addr)
{
	return;
}

static __always_inline void
kasan_shadow_Nbyte_markvalid(const void *addr, size_t size)
{
	return;
}

static __always_inline void
kasan_shadow_Nbyte_fill(const void *addr, size_t size, uint8_t code)
{
	return;
}

void
kasan_add_redzone(size_t *size)
{
	return;
}

/*
 * In an area of size 'sz_with_redz', mark the 'size' first bytes as valid,
 * and the rest as invalid. There are generally two use cases:
 *
 *  o kasan_mark(addr, origsize, size, code), with origsize < size. This marks
 *    the redzone at the end of the buffer as invalid.
 *
 *  o kasan_mark(addr, size, size, 0). This marks the entire buffer as valid.
 */
void
kasan_mark(const void *addr, size_t size, size_t sz_with_redz, uint8_t code)
{
	return;
}

/* -------------------------------------------------------------------------- */
/* Code that performs the shadow memory checks */

#define ADDR_CROSSES_SCALE_BOUNDARY(addr, size) 		\
	(addr >> KASAN_SHADOW_SCALE_SHIFT) !=			\
	    ((addr + size - 1) >> KASAN_SHADOW_SCALE_SHIFT)

static __always_inline bool
kasan_shadow_1byte_isvalid(unsigned long addr, uint8_t *code)
{
	return true;
}

static __always_inline bool
kasan_shadow_2byte_isvalid(unsigned long addr, uint8_t *code)
{
	return true;
}

static __always_inline bool
kasan_shadow_4byte_isvalid(unsigned long addr, uint8_t *code)
{
	return true;
}

static __always_inline bool
kasan_shadow_8byte_isvalid(unsigned long addr, uint8_t *code)
{
	return true;
}

static __always_inline bool
kasan_shadow_Nbyte_isvalid(unsigned long addr, size_t size, uint8_t *code)
{
	return true;
}

static __always_inline void
kasan_shadow_check(unsigned long addr, size_t size, bool write,
    unsigned long retaddr)
{
	return;
}

/* -------------------------------------------------------------------------- */
/* ASAN ABI functions */

void __asan_register_globals(struct __asan_global *, size_t);
void __asan_unregister_globals(struct __asan_global *, size_t);

void
__asan_register_globals(struct __asan_global *globals, size_t n)
{
	/* never called */
}

void
__asan_unregister_globals(struct __asan_global *globals, size_t n)
{
	/* never called */
}

#define ASAN_LOAD_STORE(size)					\
	void __asan_load##size(unsigned long);			\
	void __asan_load##size(unsigned long addr)		\
	{							\
	} 							\
	void __asan_load##size##_noabort(unsigned long);	\
	void __asan_load##size##_noabort(unsigned long addr)	\
	{							\
	}							\
	void __asan_store##size(unsigned long);			\
	void __asan_store##size(unsigned long addr)		\
	{							\
	}							\
	void __asan_store##size##_noabort(unsigned long);	\
	void __asan_store##size##_noabort(unsigned long addr)	\
	{							\
	}							\

ASAN_LOAD_STORE(1);
ASAN_LOAD_STORE(2);
ASAN_LOAD_STORE(4);
ASAN_LOAD_STORE(8);
ASAN_LOAD_STORE(16);

void __asan_loadN(unsigned long, size_t);
void __asan_loadN_noabort(unsigned long, size_t);
void __asan_storeN(unsigned long, size_t);
void __asan_storeN_noabort(unsigned long, size_t);
void __asan_handle_no_return(void);

void
__asan_loadN(unsigned long addr, size_t size)
{
	/* nothing */
}

void
__asan_loadN_noabort(unsigned long addr, size_t size)
{
	/* nothing */
}


void
__asan_storeN(unsigned long addr, size_t size)
{
	/* nothing */
}

void
__asan_storeN_noabort(unsigned long addr, size_t size)
{
	/* nothing */
}

void
__asan_handle_no_return(void)
{
	/* nothing */
}

void __asan_report_load1_noabort(unsigned long);
void __asan_report_load2_noabort(unsigned long);
void __asan_report_load4_noabort(unsigned long);
void __asan_report_load8_noabort(unsigned long);
void __asan_report_load16_noabort(unsigned long);

void __asan_report_load1_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_load2_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_load4_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_load8_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_load16_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_store1_noabort(unsigned long);
void __asan_report_store2_noabort(unsigned long);
void __asan_report_store4_noabort(unsigned long);
void __asan_report_store8_noabort(unsigned long);
void __asan_report_store16_noabort(unsigned long);

void __asan_report_store1_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_store2_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_store4_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_store8_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_store16_noabort(unsigned long addr)
{
	/* nothing */
}

void __asan_report_load_n_noabort(unsigned long, size_t);
void __asan_report_store_n_noabort(unsigned long, size_t);

void
__asan_report_load_n_noabort(unsigned long addr, size_t size)
{
	//kasan_shadow_check(addr, size, false, __RET_ADDR);
}

void
__asan_report_store_n_noabort(unsigned long addr, size_t size)
{
	//kasan_shadow_check(addr, size, true, __RET_ADDR);
}

void __asan_set_shadow_00(void *, size_t);
void __asan_set_shadow_f1(void *, size_t);
void __asan_set_shadow_f2(void *, size_t);
void __asan_set_shadow_f3(void *, size_t);
void __asan_set_shadow_f5(void *, size_t);
void __asan_set_shadow_f8(void *, size_t);

void __asan_set_shadow_00(void *addr, size_t size)
{
	/* nothing */
}

void __asan_set_shadow_f1(void *addr, size_t size)
{
	/* nothing */
}

void __asan_set_shadow_f2(void *addr, size_t size)
{
	/* nothing */
}

void __asan_set_shadow_f3(void *addr, size_t size)
{
	/* nothing */
}

void __asan_set_shadow_f5(void *addr, size_t size)
{
	/* nothing */
}

void __asan_set_shadow_f8(void *addr, size_t size)
{
	/* nothing */
}

void __asan_poison_stack_memory(const void *, size_t);
void __asan_unpoison_stack_memory(const void *, size_t);

void __asan_poison_stack_memory(const void *addr, size_t size)
{
	/* nothing */
}

void __asan_unpoison_stack_memory(const void *addr, size_t size)
{
	/* nothing */
}

