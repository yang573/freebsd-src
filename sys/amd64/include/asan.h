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

//static bool __md_early __read_mostly = true;
//static uint8_t __md_earlypages[8 * PAGE_SIZE] __aligned(PAGE_SIZE);
//static size_t __md_earlytaken = 0;
static uint8_t __md_earlypage[PAGE_SIZE] __aligned(PAGE_SIZE);

extern int nkasanpt;		/* Number of kasan shadow map page tables */
extern u_int64_t KASANPTphys;	/* phys addr of kasan level 1 */
extern u_int64_t KASANPDphys;	/* phys addr of kasan level 2 */

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

// Map only the current stack with zero pages?
static inline void
kasan_md_early_init(void)
{
	vm_paddr_t pa = (vm_paddr_t)(&__md_earlypage[0]);
	pa -= KERNBASE;

	pt_entry_t *pt_p = (pt_entry_t *)KASANPTphys;
	for (int i = 0; i < nkasanpt; i++)
		pt_p[i] = pa | X86_PG_V;

	//__md_early = false;

	return;
}

static inline void
kasan_md_init(void)
{
	// XXX: Is this needed, or does pmap_growkernel() call map for us?
	//kasan_shadow_map();

	return;
}

static inline void
kasan_md_shadow_map_page(vm_offset_t va)
{
	vm_paddr_t paddr;
	vm_page_t nkpg;
	pd_entry_t *pde;
	pt_entry_t *pte;
	int idx;

	idx = (va - KASAN_MIN_ADDRESS) >> PDRSHIFT;
	pde = (pd_entry_t *)PHYS_TO_DMAP(KASANPDphys);
	if (pde[idx] == 0) {
		nkpg = vm_page_alloc(NULL, 0,
			VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ |
			VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		if (nkpg == NULL)
			panic("kasan_grow_shadow_map: "
				"no memory to grow PD shadow map");
		if ((nkpg->flags & PG_ZERO) == 0)
			pmap_zero_page(nkpg);
		paddr = VM_PAGE_TO_PHYS(nkpg);
		pde[idx] = paddr | X86_PG_RW | X86_PG_V;
	}

	//printf("DEBUG: %s() pde: %p idx: %d pde[idx] 0x%lx\n", __func__, pde, idx, pde[idx]);

	pte = (pt_entry_t *)PHYS_TO_DMAP(pde[idx] & PG_FRAME);
	idx = pmap_pte_index(va);
	//printf("DEBUG: %s() pte: %p idx: %d pte[idx] 0x%lx\n", __func__, pte, idx, pte[idx]);
	if (pte[idx] != 0) {
		//printf("DEBUG: %s() pte: %p idx: %d pte[idx] 0x%lx\n", __func__, pte, idx, pte[idx]);
		return;
	}

	nkpg = vm_page_alloc(NULL, 0,
		VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED |
		VM_ALLOC_ZERO);
	if (nkpg == NULL)
		panic("kasan_md_shadow_map_page: "
			"no memory to grow PT table shadow map");
	if ((nkpg->flags & PG_ZERO) == 0)
		pmap_zero_page(nkpg);
	paddr = VM_PAGE_TO_PHYS(nkpg);
	pte[idx] = paddr | X86_PG_RW | X86_PG_V | X86_PG_G;

	//printf("DEBUG: %s() post-alloc pte: %p idx: %d pte[idx] %lx\n", __func__, pte, idx, pte[idx]);

	__builtin_memset((void *)va, 0xFF, PAGE_SIZE);

	return;
}

#endif
