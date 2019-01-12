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
#include <abstract_atomic.h>
#include "log.h"
#include "gsh_list.h"
#include "common_utils.h"

#define gsh_malloc(n) ({ \
	void *p_ = malloc(n); \
	if (p_ == NULL) { \
		abort(); \
	} \
	p_; \
	})

#define gsh_malloc_aligned(a, n) ({ \
	void *p_; \
	if (posix_memalign(&p_, a, n) != 0) \
		abort(); \
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
	char *p_ = strdup(s); \
	if (p_ == NULL) { \
		abort(); \
	} \
	p_; \
	})

#define gsh_strldup(s, len, n) ({ \
	char *p_ = (char *) gsh_malloc(len+1); \
	memcpy(p_, s, len); \
	p_[len] = '\0'; \
	*n = len + 1; \
	p_; \
	})

#define gsh_free(p) free(p)

/**
 * @brief Type representing a pool
 *
 * This type represents a memory pool.  it should be treated, by all
 * callers, as a completely abstract type.  The pointer should only be
 * stored or passed to pool functions.  The pointer should never be
 * referenced.  No assumptions about the size of the pointed-to type
 * should be made.
 *
 * This allows for flexible growth in the future.
 */

typedef struct pool {
	char *name; /*< The name of the pool */
	size_t object_size; /*< The size of the objects created */
	int64_t cnt;  /* < counter to keep track of allocations */
	struct glist_head mpool_next;	/*< list pointer for pools */
} pool_t;

extern struct glist_head mpool_list; /* head of pool list */
extern pthread_rwlock_t mpool_lock;

/**
 * @brief Create a basic object pool
 *
 * This function creates a new object pool, given a name, object size,
 * constructor and destructor.
 *
 * This particular implementation throws the name away, but other
 * implementations that do tracking or keep counts of allocated or
 * de-allocated objects will likely wish to use it in log messages.
 *
 * This initializer function is expected to abort if it fails.
 *
 * @param[in] name             The name of this pool
 * @param[in] object_size      The size of objects to allocate
 * @param[in] file             Calling source file
 * @param[in] line             Calling source line
 * @param[in] function         Calling source function
 *
 * @return A pointer to the pool object.  This pointer must not be
 *         dereferenced.  It may be stored or supplied as an argument
 *         to the other pool functions.  It must not be supplied as an
 *         argument to gsh_free, rather it must be disposed of with
 *         pool_destroy.
 */

static inline pool_t *
pool_basic_init(const char *name, size_t object_size)
{
	pool_t *pool = (pool_t *) gsh_calloc(1, sizeof(pool_t));

	pool->object_size = object_size;

	if (name)
		pool->name = gsh_strdup(name);
	else
		pool->name = NULL;

	PTHREAD_RWLOCK_wrlock(&mpool_lock);
	glist_add_tail(&mpool_list, &pool->mpool_next);
	PTHREAD_RWLOCK_unlock(&mpool_lock);
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
	PTHREAD_RWLOCK_wrlock(&mpool_lock);
	glist_del(&pool->mpool_next);
	PTHREAD_RWLOCK_unlock(&mpool_lock);
	gsh_free(pool->name);
	gsh_free(pool);
}

/**
 * @brief Allocate an object from a pool
 *
 * This function allocates a single object from the pool and returns a
 * pointer to it.  If a constructor was specified at pool creation, it
 * is called on that pointer.  This function must be thread safe.  If
 * the underlying pool abstraction requires a lock, this function must
 * take and release it.
 *
 * This function returns void pointers.  Programmers who wish for more
 * type safety can easily create static inline wrappers (alloc_client
 * or similar) to return pointers of a specific type (and omitting the
 * pool parameter).
 *
 * This function aborts if no memory is available.
 *
 * @param[in] pool       The pool from which to allocate
 * @param[in] file       Calling source file
 * @param[in] line       Calling source line
 * @param[in] function   Calling source function
 *
 * @return A pointer to the allocated pool item.
 */

static inline void *
pool_alloc(pool_t *pool)
{
	void *ptr;

	ptr = gsh_calloc(1, pool->object_size);
	(void)atomic_inc_int64_t(&pool->cnt);
	return ptr;
}


/**
 * @brief Return an entry to a pool
 *
 * This function returns a single object to the pool.  If a destructor
 * was defined at pool creation time, it is called before the object
 * is freed.  This function must be thread-safe.  If the underlying
 * pool abstract requires a lock, this function must take and release
 * it.
 *
 * @param[in] pool   Pool to which to return the object
 * @param[in] object Object to return.  This is a void pointer.
 *                   Programmers wishing more type safety could create
 *                   a static inline wrapper taking an object of a
 *                   specific type (and omitting the pool parameter.)
 */

static inline void
pool_free(pool_t *pool, void *object)
{
	if (object) {
		gsh_free(object);
		(void)atomic_dec_int64_t(&pool->cnt);
	}
}

#endif /* ABSTRACT_MEM_H */
