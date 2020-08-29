/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _MACHINE_ASAN_H_
#define	_MACHINE_ASAN_H_

#ifndef KASAN_SHADOW_SCALE_SHIFT
#error "Only include this from kern/subr_asan.c"
#endif

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <machine/vmparam.h>

static inline int8_t *
kasan_md_addr_to_shad(const void *addr)
{

	return ((int8_t *)(((vm_offset_t)addr - VM_MIN_KERNEL_ADDRESS) >>
	    KASAN_SHADOW_SCALE_SHIFT) + KASAN_MIN_ADDRESS);
}

static inline bool
kasan_md_unsupported(vm_offset_t addr)
{

	/* Ignore these for now */
	if (addr >= KERNBASE)
		return (true);

	return ((addr < VM_MIN_KERNEL_ADDRESS) ||
	    (addr >= VM_MAX_KERNEL_ADDRESS));
}

static inline void
kasan_md_init(void)
{
	return;
}

extern u_int64_t KASANPDphys;

static inline void
kasan_md_shadow_map_page(vm_offset_t va)
{
	return;
}

#endif
