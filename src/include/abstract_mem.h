/*
 *
 *
 * Copyright © Linux box Corporation, 2012
 * Author: Adam C. Emerson <aemerson@linuxbox.com>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file   abstract_mem.h
 * @author Adam C. Emerson <aemerson@linuxbox.com>
 * @brief  Abstract memory shims to allow swapping out allocators
 *
 * This file's purpose is to allow us to easily replace the memory
 * allocator used by Ganesha.  Further, it provides a pool abstraction
 * that may be implemented in terms of the normal allocator that may
 * be expanded at a later date.  These are intended to be thin
 * wrappers, but conditionally compiled trace information could be
 * added.
 */

#ifndef ABSTRACT_MEM_H
#define ABSTRACT_MEM_H

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/**
 * @page GeneralAllocator General Allocator Shim
 *
 * These functions provide an interface akin to the standard libc
 * allocation functions.  Currently they call the functions malloc,
 * free, and so forth, with changes in functionality being provided by
 * linking in alternate allocator libraries (tcmalloc and jemalloc, at
 * present.)  So long as the interface remains the same, these
 * functions can be switched out using ifdef for versions that do more
 * memory tracking or that call allocators with other names.
 */

#define gsh_malloc(n) ({ \
		void *p_ = malloc(n); \
		if (p_ == NULL) { \
			abort(); \
		} \
		p_; \
	})

#define gsh_malloc_aligned(a, n) ({ \
		void *p_; \
		if (posix_memalign(&p_, a, n) != 0) { \
			abort(); \
		} \
		p_; \
	})

#define gsh_calloc(n, s) ({ \
		void *p_ = calloc(n, s); \
		if (p_ == NULL) { \
			abort(); \
		} \
		p_; \
	})

#define gsh_realloc(p, n) ({ \
		void *p2_ = realloc(p, n); \
		if (n != 0 && p2_ == NULL) { \
			abort(); \
		} \
		p2_; \
	})

#define gsh_strdup(s) ({ \
		size_t n_ = strlen(s)+1; \
		char *p_ = (char *) gsh_malloc(n_); \
		memcpy(p_, s, n_); \
		p_; \
	})

#define gsh_strldup(s, l, n) ({ \
		char *p_ = (char *) gsh_malloc(l+1); \
		memcpy(p_, s, l); \
		p_[l] = '\0'; \
		*n = l + 1; \
		p_; \
	})

#define gsh_memdup(s, l) ({ \
		void *p_ = gsh_malloc(l); \
		memcpy(p_, s, l); \
		p_; \
	})

/**
 * @brief Free a block of memory
 *
 * This function frees a block of memory allocated with gsh_malloc,
 * gsh_malloc_aligned, gsh_calloc, gsh_realloc, or gsh_strdup.
 *
 * @param[in] p Block of memory to free.
 */
static inline void
gsh_free(void *p)
{
	free(p);
}

/**
 * @brief Free a block of memory with size
 *
 * This function exists to be passed to TIRPC when setting
 * allocators.  It should not be used by anyone else.  New shim layers
 * should not redefine it.
 *
 * @param[in] p  Block of memory to free.
 * @param[in] n  Size of block (unused)
 */
static inline void
gsh_free_size(void *p, size_t n __attribute__ ((unused)))
{
	free(p);
}

/**
 * @page PoolAllocator Pool allocator shim
 *
 * These functions provide an abstract interface to memory pools.
 * Since multiple implementations of pooling may be useful within a
 * single running image, the underlying substrate can be changed using
 * by passing a constant (specifying an allocator) and parameters to
 * pool_init.
 *
 * By design, things are separated out so one can add a new pool
 * substrate without editing this file.  One can create, for example,
 * static_pool.h, define a function vector and a parameter structure,
 * and any functions wishing to use the static_pool could include it.
 */

typedef struct pool pool_t;

struct pool_substrate_vector {
		void *unused;
};

/**
 * @brief Type representing a pool
 *
 * This type represents a memory pool.  it should be treated, by all
 * callers, as a completely abstract type.  The pointer should only be
 * stored or passed to pool functions.  The pointer should never be
 * referenced.  No assumptions about the size of the pointed-to type
 * should be made.
 */

struct pool {
	char *name; /*< The name of the pool */
	size_t object_size; /*< The size of the objects created */
	struct pool_substrate_vector *unused;
};

/**
 * @brief Create an object pool
 *
 * This function creates a new object pool, given a name, object size,
 * constructor and destructor.
 *
 * This particular implementation throws the name away, but other
 * implementations that do tracking or keep counts of allocated or
 * de-allocated objects will likely wish to use it in log messages.
 *
 * @param[in] name             The name of this pool
 * @param[in] object_size      The size of objects to allocate
 * @param[in] substrate        The function vector specifying the
 *                             substrate to use for this pool
 * @param[in] substrate_params The substrate-specific parameters for
 *                             this pool
 * @param[in] constructor      Function to be called on each new
 *                             object
 * @param[in] destructor       Function to be called on each object
 *                             before destruction
 *
 * @return A pointer to the pool object.  This pointer must not be
 *         dereferenced.  It may be stored or supplied as an argument
 *         to the other pool functions.  It must not be supplied as an
 *         argument to gsh_free, rather it must be disposed of with
 *         pool_destroy.  NULL is returned on error.
 */

static inline pool_t *
pool_init(const char *name, const size_t object_size,
	  const void *substrate,
	  const void *substrate_params,
	  const void *constructor,
	  const void *destructor)
{
	pool_t *pool = (pool_t *) gsh_calloc(1, sizeof(pool_t));

	pool->object_size = object_size;

	if (name)
		pool->name = gsh_strdup(name);
	else
		pool->name = NULL;

	return pool;
}

/**
 * @brief Destroy a memory pool
 *
 * This function destroys a memory pool.  All objects must be returned
 * to the pool before this function is called.
 *
 * @param[in] pool The pool to be destroyed.
 */

static inline void
pool_destroy(pool_t *pool)
{
	free(pool->name);
	free(pool);
}

#define pool_alloc(pool, unused_) gsh_calloc(1, (pool)->object_size)
#define pool_free(pool, object) free(object)

static const struct pool_substrate_vector pool_basic_substrate[] = {
	{
		.unused = NULL,
	}
};


#endif /* ABSTRACT_MEM_H */
