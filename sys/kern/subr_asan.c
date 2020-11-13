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
kasan_early_init(void *stack)
{
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
	size_t i, n, redz;
	int8_t *shad;

	/* XXX: Work around importing DMAP memory */
	if (__predict_false(kasan_md_unsupported((vm_offset_t)addr)))
		return;

	KASSERT((vm_offset_t)addr % KASAN_SHADOW_SCALE_SIZE == 0,
			("kasan_mark: Address %p is incorrectly aligned", addr));
	redz = sz_with_redz - roundup(size, KASAN_SHADOW_SCALE_SIZE);
	KASSERT(redz % KASAN_SHADOW_SCALE_SIZE == 0,
			("kasan_mark: Redzone size (%zx) must be a multiple of %ld", redz,
			 KASAN_SHADOW_SCALE_SIZE));
	shad = kasan_md_addr_to_shad(addr);

	/* Chunks of 8 bytes, valid. */
	n = size / KASAN_SHADOW_SCALE_SIZE;
	for (i = 0; i < n; i++) {
		*shad++ = 0;
	}

	/* Possibly one chunk, mid. */
	if ((size & KASAN_SHADOW_MASK) != 0) {
		*shad++ = (size & KASAN_SHADOW_MASK);
	}

	/* Chunks of 8 bytes, invalid. */
	n = redz / KASAN_SHADOW_SCALE_SIZE;
	for (i = 0; i < n; i++) {
		*shad++ = code;
	}
}

