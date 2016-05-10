/*
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

#include "config.h"
#include "log.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "gsh_intrinsic.h"
#include "gsh_types.h"
#include "common_utils.h"
#include "avltree.h"
#include "ng_cache.h"
#include "abstract_mem.h"
#include "abstract_atomic.h"

struct ng_cache_info {
	struct gsh_buffdesc ng_group;
	struct gsh_buffdesc ng_host;
	struct avltree_node ng_node;
};

#define ng_cache_size 1009	/* prime number */

static struct avltree_node *ng_cache[ng_cache_size];
static struct avltree ng_pos_tree;
static struct avltree ng_neg_tree;

pthread_rwlock_t ng_lock = PTHREAD_RWLOCK_INITIALIZER;

/* XOR version of djb2 hash with group and host
 *
 * We could have a better hash function by using only a few characters
 * after @. Domians are usually same!
 */
static inline int ng_hash_key(struct ng_cache_info *info)
{
	unsigned long hash = 5381;
	char *str;
	int c;

	str = info->ng_group.addr;
	while ((c = *str++) != 0)
		hash = ((hash << 5) + hash) ^ c;

	str = info->ng_host.addr;
	while ((c = *str++) != 0)
		hash = ((hash << 5) + hash) ^ c;

	return hash % ng_cache_size;
}

/**
 * @brief Compare two buffers
 *
 * Handle the case where one buffer is a left sub-buffer of another
 * buffer by counting the longer one as larger.
 *
 * @param[in] buff1 A buffer
 * @param[in] buffa Another buffer
 *
 * @retval -1 if buff1 is less than buffa
 * @retval 0 if buff1 and buffa are equal
 * @retval 1 if buff1 is greater than buffa
 */
/* @todo: malahal comapre lengths first, also remove conditionals */
static inline int buffdesc_comparator(const struct gsh_buffdesc *buffa,
				      const struct gsh_buffdesc *buff1)
{
	int mr = memcmp(buff1->addr, buffa->addr, MIN(buff1->len,
						      buffa->len));
	if (unlikely(mr == 0)) {
		if (buff1->len < buffa->len)
			return -1;
		else if (buff1->len > buffa->len)
			return 1;
		else
			return 0;
	} else {
		return mr;
	}
}

/**
 * @brief Comparison for netgroup and host entry
 *
 * @param[in] node1 A node
 * @param[in] nodea Another node
 *
 * @retval -1 if node1 is less than nodea
 * @retval 0 if node1 and nodea are equal
 * @retval 1 if node1 is greater than nodea
 */
static int ng_comparator(const struct avltree_node *node1,
			 const struct avltree_node *node2)
{
	int rc;
	struct ng_cache_info *info1;
	struct ng_cache_info *info2;

	info1 = avltree_container_of(node1, struct ng_cache_info, ng_node);
	info2 = avltree_container_of(node2, struct ng_cache_info, ng_node);

	rc = buffdesc_comparator(&info1->ng_host, &info2->ng_host);
	if (rc == 0)
		rc = buffdesc_comparator(&info1->ng_group, &info2->ng_group);

	return rc;
}


/**
 * @brief Initialize the netgroups cache
 */
void ng_cache_init(void)
{
	avltree_init(&ng_pos_tree, ng_comparator, 0);
	avltree_init(&ng_neg_tree, ng_comparator, 0);
	memset(ng_cache, 0, ng_cache_size * sizeof(struct avltree_node *));
}

/* Remove given cache info (group, host) from the AVL trees
 *
 * @note The caller must hold ng_lock
 */
static void ng_remove(struct ng_cache_info *info, bool negative)
{
	if (negative) {
		avltree_remove(&info->ng_node, &ng_neg_tree);
	} else {
		ng_cache[ng_hash_key(info)] = NULL;
		avltree_remove(&info->ng_node, &ng_pos_tree);
	}
	gsh_free(info->ng_group.addr);
	gsh_free(info->ng_host.addr);
	gsh_free(info);
}

/**
 * @brief Add a netgroup entry to the cache
 *
 * @note The caller must hold ng_lock for write.
 *
 */
static void ng_add(const char *group, const char *host, bool negative)
{
	struct ng_cache_info *info;

	info = gsh_malloc(sizeof(struct ng_cache_info));
	if (info == NULL)
		LogFatal(COMPONENT_IDMAPPER, "memory alloc failed");

	info->ng_group.addr = gsh_strdup(group);
	info->ng_group.len = strlen(group)+1;
	info->ng_host.addr = gsh_strdup(host);
	info->ng_host.len = strlen(host)+1;
	if (info->ng_group.addr == NULL || info->ng_host.addr == NULL)
		LogFatal(COMPONENT_IDMAPPER, "memory alloc failed");

	if (negative) {
		(void)avltree_insert(&info->ng_node, &ng_neg_tree);
	} else {
		(void)avltree_insert(&info->ng_node, &ng_pos_tree);
		ng_cache[ng_hash_key(info)] = &info->ng_node;
	}
}


static bool ng_lookup(const char *group, const char *host, bool negative)
{
	struct ng_cache_info prototype = {
		.ng_group.addr = (char *)group,
		.ng_group.len = strlen(group)+1,
		.ng_host.addr = (char *)host,
		.ng_host.len = strlen(host)+1
	};

	void **cache_slot;
	struct avltree_node *found_node;

	if (negative) {
		found_node = avltree_lookup(&prototype.ng_node, &ng_neg_tree);
		return found_node;
	}

	/* Positive lookups are stored in the cache */
	cache_slot = (void **)&ng_cache[ng_hash_key(&prototype)];
	found_node = atomic_fetch_voidptr(cache_slot);
	if (found_node && ng_comparator(found_node, &prototype.ng_node) == 0)
		return true;

	/* cache miss, search AVL tree */
	found_node = avltree_lookup(&prototype.ng_node, &ng_pos_tree);
	if (found_node)
		atomic_store_voidptr(cache_slot, found_node);

	if (unlikely(!found_node))
		return false;

	atomic_store_voidptr(cache_slot, found_node);

	return true;
}

bool ng_innetgr(const char *group, const char *host)
{
	int rc;

	/* Check positive lookup and then negative lookup.  If absent in
	 * both, then do a real innetgr call and cache the result.
	 */
	PTHREAD_RWLOCK_rdlock(&ng_lock);
	if (ng_lookup(group, host, false)) { /* positive lookup */
		PTHREAD_RWLOCK_unlock(&ng_lock);
		return true;
	}

	if (ng_lookup(group, host, true)) { /* negative lookup */
		PTHREAD_RWLOCK_unlock(&ng_lock);
		return false;
	}
	PTHREAD_RWLOCK_unlock(&ng_lock);

	rc = innetgr(group, host, NULL, NULL);

	PTHREAD_RWLOCK_wrlock(&ng_lock);
	if (rc)
		ng_add(group, host, false);	/* positive lookup */
	else
		ng_add(group, host, true);	/* negative lookup */
	PTHREAD_RWLOCK_unlock(&ng_lock);

	return rc;
}


/**
 * @brief Wipe out the netgroup cache
 */
void ng_cache_purge(void)
{
	struct avltree_node *node;
	struct ng_cache_info *info;

	PTHREAD_RWLOCK_wrlock(&ng_lock);

	while ((node = avltree_first(&ng_pos_tree))) {
		info = avltree_container_of(node, struct ng_cache_info,
					    ng_node);
		ng_remove(info, false);
	}

	while ((node = avltree_first(&ng_neg_tree))) {
		info = avltree_container_of(node, struct ng_cache_info,
					    ng_node);
		ng_remove(info, true);
	}

	assert(avltree_first(&ng_pos_tree) == NULL);
	assert(avltree_first(&ng_neg_tree) == NULL);

	PTHREAD_RWLOCK_unlock(&ng_lock);
}
