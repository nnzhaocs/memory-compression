/*
 * kcmask.c - kcmask driver file
 *
 * kcmask is a backend for frontswap that takes pages that are in the process
 * of being swapped out and attempts to compress and store them in a
 * RAM-based memory pool.  This can result in a significant I/O reduction on
 * the swap device and, in the case where decompressing from RAM is faster
 * than reading from the swap device, can also improve workload performance.
 *
 * Copyright (C) 2012  Seth Jennings <sjenning@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/frontswap.h>
#include <linux/rbtree.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/zpool.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>
//NANNAN
#include <unistd.h>
/*********************************
* statistics
**********************************/

#define RESERVED_MEMORY_OFFSET  0x100000000     /* Offset is 4GB */

///* Total bytes used by the compressed storage */
//static u64 kcmask_pool_total_size;
///* The number of compressed pages currently stored in kcmask */
//static atomic_t kcmask_stored_pages = ATOMIC_INIT(0);
//
///*
// * The statistics below are not protected from concurrent access for
// * performance reasons so they may not be a 100% accurate.  However,
// * they do provide useful information on roughly how many times a
// * certain event is occurring.
//*/
//
///* Pool limit was hit (see kcmask_max_pool_percent) */
//static u64 kcmask_pool_limit_hit;
///* Pages written back when pool limit was reached */
//static u64 kcmask_written_back_pages;
///* Store failed due to a reclaim failure after pool limit was reached */
//static u64 kcmask_reject_reclaim_fail;
///* Compressed page was too big for the allocator to (optimally) store */
//static u64 kcmask_reject_compress_poor;
///* Store failed because underlying allocator could not get memory */
//static u64 kcmask_reject_alloc_fail;
///* Store failed because the entry metadata could not be allocated (rare) */
//static u64 kcmask_reject_kmemcache_fail;
///* Duplicate store was encountered (rare) */
//static u64 kcmask_duplicate_entry;

/*********************************
* tunables
**********************************/

///* Enable/disable kcmask (disabled by default) */
//static bool kcmask_enabled;
//module_param_named(enabled, kcmask_enabled, bool, 0644);
//
///* Crypto compressor to use */
//#define kcmask_COMPRESSOR_DEFAULT "lzo"
//static char kcmask_compressor[CRYPTO_MAX_ALG_NAME] = kcmask_COMPRESSOR_DEFAULT;
//static struct kparam_string kcmask_compressor_kparam = {
//	.string =	kcmask_compressor,
//	.maxlen =	sizeof(kcmask_compressor),
//};
//static int kcmask_compressor_param_set(const char *,
//				      const struct kernel_param *);
//static struct kernel_param_ops kcmask_compressor_param_ops = {
//	.set =		kcmask_compressor_param_set,
//	.get =		param_get_string,
//};
//module_param_cb(compressor, &kcmask_compressor_param_ops,
//		&kcmask_compressor_kparam, 0644);
//
///* Compressed storage zpool to use */
//#define kcmask_ZPOOL_DEFAULT "zbud"
//static char kcmask_zpool_type[32 /* arbitrary */] = kcmask_ZPOOL_DEFAULT;
//static struct kparam_string kcmask_zpool_kparam = {
//	.string =	kcmask_zpool_type,
//	.maxlen =	sizeof(kcmask_zpool_type),
//};
//static int kcmask_zpool_param_set(const char *, const struct kernel_param *);
//static struct kernel_param_ops kcmask_zpool_param_ops = {
//	.set =	kcmask_zpool_param_set,
//	.get =	param_get_string,
//};
//module_param_cb(zpool, &kcmask_zpool_param_ops, &kcmask_zpool_kparam, 0644);
//
///* The maximum percentage of memory that the compressed pool can occupy */
//static unsigned int kcmask_max_pool_percent = 20;
//module_param_named(max_pool_percent, kcmask_max_pool_percent, uint, 0644);

/*********************************
* data structures
**********************************/

//struct kcmask_pool {
//	struct zpool *zpool;
//	struct crypto_comp * __percpu *tfm;
//	struct kref kref;
//	struct list_head list;
//	struct rcu_head rcu_head;
//	struct notifier_block notifier;
//	char tfm_name[CRYPTO_MAX_ALG_NAME];
//};

/*
 * struct kcmask_entry
 *
 * This structure contains the metadata for tracking a single compressed
 * page within kcmask.
 *
 * rbnode - links the entry into red-black tree for the appropriate swap type
 * offset - the swap offset for the entry.  Index into the red-black tree.
 * refcount - the number of outstanding reference to the entry. This is needed
 *            to protect against premature freeing of the entry by code
 *            concurrent calls to load, invalidate, and writeback.  The lock
 *            for the kcmask_tree structure that contains the entry must
 *            be held while changing the refcount.  Since the lock must
 *            be held, there is no reason to also make refcount atomic.
 * length - the length in bytes of the compressed page data.  Needed during
 *          decompression
 * pool - the kcmask_pool the entry's data is in
 * handle - zpool allocation handle that stores the compressed page data
 */
//struct kcmask_entry {
//	struct rb_node rbnode;
//	pgoff_t offset;
//	int refcount;
//	unsigned int length;
//	struct kcmask_pool *pool;
//	unsigned long handle;
//};
//
//struct kcmask_header {
//	swp_entry_t swpentry;
//};

/*
 * The tree lock in the kcmask_tree struct protects a few things:
 * - the rbtree
 * - the refcount field of each entry in the tree
 */
//struct kcmask_tree {
//	struct rb_root rbroot;
//	spinlock_t lock;
//};
//
//static struct kcmask_tree *kcmask_trees[MAX_SWAPFILES];

/* RCU-protected iteration */
//static LIST_HEAD(kcmask_pools);
/* protects kcmask_pools list modification */
//static DEFINE_SPINLOCK(kcmask_pools_lock);

/* used by param callback function */
//static bool kcmask_init_started;

/*********************************
* helpers and fwd declarations
**********************************/

//#define kcmask_pool_debug(msg, p)				\
//	pr_debug("%s pool %s/%s\n", msg, (p)->tfm_name,		\
//		 zpool_get_type((p)->zpool))
//
//static int kcmask_writeback_entry(struct zpool *pool, unsigned long handle);
//static int kcmask_pool_get(struct kcmask_pool *pool);
//static void kcmask_pool_put(struct kcmask_pool *pool);
//
//static const struct zpool_ops kcmask_zpool_ops = {
//	.evict = kcmask_writeback_entry
//};
//
//static bool kcmask_is_full(void)
//{
//	return totalram_pages * kcmask_max_pool_percent / 100 <
//		DIV_ROUND_UP(kcmask_pool_total_size, PAGE_SIZE);
//}
//
//static void kcmask_update_total_size(void)
//{
//	struct kcmask_pool *pool;
//	u64 total = 0;
//
//	rcu_read_lock();
//
//	list_for_each_entry_rcu(pool, &kcmask_pools, list)
//		total += zpool_get_total_size(pool->zpool);
//
//	rcu_read_unlock();
//
//	kcmask_pool_total_size = total;
//}

/*********************************
* kcmask entry functions
**********************************/
//static struct kmem_cache *kcmask_entry_cache;
//
//static int __init kcmask_entry_cache_create(void)
//{
//	kcmask_entry_cache = KMEM_CACHE(kcmask_entry, 0);
//	return kcmask_entry_cache == NULL;
//}
//
//static void __init kcmask_entry_cache_destroy(void)
//{
//	kmem_cache_destroy(kcmask_entry_cache);
//}
//
//static struct kcmask_entry *kcmask_entry_cache_alloc(gfp_t gfp)
//{
//	struct kcmask_entry *entry;
//	entry = kmem_cache_alloc(kcmask_entry_cache, gfp);
//	if (!entry)
//		return NULL;
//	entry->refcount = 1;
//	RB_CLEAR_NODE(&entry->rbnode);
//	return entry;
//}
//
//static void kcmask_entry_cache_free(struct kcmask_entry *entry)
//{
//	kmem_cache_free(kcmask_entry_cache, entry);
//}

/*********************************
* rbtree functions
**********************************/
//static struct kcmask_entry *kcmask_rb_search(struct rb_root *root, pgoff_t offset)
//{
//	struct rb_node *node = root->rb_node;
//	struct kcmask_entry *entry;
//
//	while (node) {
//		entry = rb_entry(node, struct kcmask_entry, rbnode);
//		if (entry->offset > offset)
//			node = node->rb_left;
//		else if (entry->offset < offset)
//			node = node->rb_right;
//		else
//			return entry;
//	}
//	return NULL;
//}

/*
 * In the case that a entry with the same offset is found, a pointer to
 * the existing entry is stored in dupentry and the function returns -EEXIST
 */
//static int kcmask_rb_insert(struct rb_root *root, struct kcmask_entry *entry,
//			struct kcmask_entry **dupentry)
//{
//	struct rb_node **link = &root->rb_node, *parent = NULL;
//	struct kcmask_entry *myentry;
//
//	while (*link) {
//		parent = *link;
//		myentry = rb_entry(parent, struct kcmask_entry, rbnode);
//		if (myentry->offset > entry->offset)
//			link = &(*link)->rb_left;
//		else if (myentry->offset < entry->offset)
//			link = &(*link)->rb_right;
//		else {
//			*dupentry = myentry;
//			return -EEXIST;
//		}
//	}
//	rb_link_node(&entry->rbnode, parent, link);
//	rb_insert_color(&entry->rbnode, root);
//	return 0;
//}
//
//static void kcmask_rb_erase(struct rb_root *root, struct kcmask_entry *entry)
//{
//	if (!RB_EMPTY_NODE(&entry->rbnode)) {
//		rb_erase(&entry->rbnode, root);
//		RB_CLEAR_NODE(&entry->rbnode);
//	}
//}

/*
 * Carries out the common pattern of freeing and entry's zpool allocation,
 * freeing the entry itself, and decrementing the number of stored pages.
 */
//static void kcmask_free_entry(struct kcmask_entry *entry)
//{
//	zpool_free(entry->pool->zpool, entry->handle);
//	kcmask_pool_put(entry->pool);
//	kcmask_entry_cache_free(entry);
//	atomic_dec(&kcmask_stored_pages);
//	kcmask_update_total_size();
//}

/* caller must hold the tree lock */
//static void kcmask_entry_get(struct kcmask_entry *entry)
//{
//	entry->refcount++;
//}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
//static void kcmask_entry_put(struct kcmask_tree *tree,
//			struct kcmask_entry *entry)
//{
//	int refcount = --entry->refcount;
//
//	BUG_ON(refcount < 0);
//	if (refcount == 0) {
//		kcmask_rb_erase(&tree->rbroot, entry);
//		kcmask_free_entry(entry);
//	}
//}
//
///* caller must hold the tree lock */
//static struct kcmask_entry *kcmask_entry_find_get(struct rb_root *root,
//				pgoff_t offset)
//{
//	struct kcmask_entry *entry = NULL;
//
//	entry = kcmask_rb_search(root, offset);
//	if (entry)
//		kcmask_entry_get(entry);
//
//	return entry;
//}

/*********************************
* per-cpu code
**********************************/
//static DEFINE_PER_CPU(u8 *, kcmask_dstmem);
//
//static int __kcmask_cpu_dstmem_notifier(unsigned long action, unsigned long cpu)
//{
//	u8 *dst;
//
//	switch (action) {
//	case CPU_UP_PREPARE:
//		dst = kmalloc_node(PAGE_SIZE * 2, GFP_KERNEL, cpu_to_node(cpu));
//		if (!dst) {
//			pr_err("can't allocate compressor buffer\n");
//			return NOTIFY_BAD;
//		}
//		per_cpu(kcmask_dstmem, cpu) = dst;
//		break;
//	case CPU_DEAD:
//	case CPU_UP_CANCELED:
//		dst = per_cpu(kcmask_dstmem, cpu);
//		kfree(dst);
//		per_cpu(kcmask_dstmem, cpu) = NULL;
//		break;
//	default:
//		break;
//	}
//	return NOTIFY_OK;
//}
//
//static int kcmask_cpu_dstmem_notifier(struct notifier_block *nb,
//				     unsigned long action, void *pcpu)
//{
//	return __kcmask_cpu_dstmem_notifier(action, (unsigned long)pcpu);
//}
//
//static struct notifier_block kcmask_dstmem_notifier = {
//	.notifier_call =	kcmask_cpu_dstmem_notifier,
//};
//
//static int __init kcmask_cpu_dstmem_init(void)
//{
//	unsigned long cpu;
//
//	cpu_notifier_register_begin();
//	for_each_online_cpu(cpu)
//		if (__kcmask_cpu_dstmem_notifier(CPU_UP_PREPARE, cpu) ==
//		    NOTIFY_BAD)
//			goto cleanup;
//	__register_cpu_notifier(&kcmask_dstmem_notifier);
//	cpu_notifier_register_done();
//	return 0;
//
//cleanup:
//	for_each_online_cpu(cpu)
//		__kcmask_cpu_dstmem_notifier(CPU_UP_CANCELED, cpu);
//	cpu_notifier_register_done();
//	return -ENOMEM;
//}
//
//static void kcmask_cpu_dstmem_destroy(void)
//{
//	unsigned long cpu;
//
//	cpu_notifier_register_begin();
//	for_each_online_cpu(cpu)
//		__kcmask_cpu_dstmem_notifier(CPU_UP_CANCELED, cpu);
//	__unregister_cpu_notifier(&kcmask_dstmem_notifier);
//	cpu_notifier_register_done();
//}
//
//static int __kcmask_cpu_comp_notifier(struct kcmask_pool *pool,
//				     unsigned long action, unsigned long cpu)
//{
//	struct crypto_comp *tfm;
//
//	switch (action) {
//	case CPU_UP_PREPARE:
//		if (WARN_ON(*per_cpu_ptr(pool->tfm, cpu)))
//			break;
//		tfm = crypto_alloc_comp(pool->tfm_name, 0, 0);
//		if (IS_ERR_OR_NULL(tfm)) {
//			pr_err("could not alloc crypto comp %s : %ld\n",
//			       pool->tfm_name, PTR_ERR(tfm));
//			return NOTIFY_BAD;
//		}
//		*per_cpu_ptr(pool->tfm, cpu) = tfm;
//		break;
//	case CPU_DEAD:
//	case CPU_UP_CANCELED:
//		tfm = *per_cpu_ptr(pool->tfm, cpu);
//		if (!IS_ERR_OR_NULL(tfm))
//			crypto_free_comp(tfm);
//		*per_cpu_ptr(pool->tfm, cpu) = NULL;
//		break;
//	default:
//		break;
//	}
//	return NOTIFY_OK;
//}
//
//static int kcmask_cpu_comp_notifier(struct notifier_block *nb,
//				   unsigned long action, void *pcpu)
//{
//	unsigned long cpu = (unsigned long)pcpu;
//	struct kcmask_pool *pool = container_of(nb, typeof(*pool), notifier);
//
//	return __kcmask_cpu_comp_notifier(pool, action, cpu);
//}
//
//static int kcmask_cpu_comp_init(struct kcmask_pool *pool)
//{
//	unsigned long cpu;
//
//	memset(&pool->notifier, 0, sizeof(pool->notifier));
//	pool->notifier.notifier_call = kcmask_cpu_comp_notifier;
//
//	cpu_notifier_register_begin();
//	for_each_online_cpu(cpu)
//		if (__kcmask_cpu_comp_notifier(pool, CPU_UP_PREPARE, cpu) ==
//		    NOTIFY_BAD)
//			goto cleanup;
//	__register_cpu_notifier(&pool->notifier);
//	cpu_notifier_register_done();
//	return 0;
//
//cleanup:
//	for_each_online_cpu(cpu)
//		__kcmask_cpu_comp_notifier(pool, CPU_UP_CANCELED, cpu);
//	cpu_notifier_register_done();
//	return -ENOMEM;
//}
//
//static void kcmask_cpu_comp_destroy(struct kcmask_pool *pool)
//{
//	unsigned long cpu;
//
//	cpu_notifier_register_begin();
//	for_each_online_cpu(cpu)
//		__kcmask_cpu_comp_notifier(pool, CPU_UP_CANCELED, cpu);
//	__unregister_cpu_notifier(&pool->notifier);
//	cpu_notifier_register_done();
//}

/*********************************
* pool functions
**********************************/

//static struct kcmask_pool *__kcmask_pool_current(void)
//{
//	struct kcmask_pool *pool;
//
//	pool = list_first_or_null_rcu(&kcmask_pools, typeof(*pool), list);
//	WARN_ON(!pool);
//
//	return pool;
//}
//
//static struct kcmask_pool *kcmask_pool_current(void)
//{
//	assert_spin_locked(&kcmask_pools_lock);
//
//	return __kcmask_pool_current();
//}
//
//static struct kcmask_pool *kcmask_pool_current_get(void)
//{
//	struct kcmask_pool *pool;
//
//	rcu_read_lock();
//
//	pool = __kcmask_pool_current();
//	if (!pool || !kcmask_pool_get(pool))
//		pool = NULL;
//
//	rcu_read_unlock();
//
//	return pool;
//}
//
//static struct kcmask_pool *kcmask_pool_last_get(void)
//{
//	struct kcmask_pool *pool, *last = NULL;
//
//	rcu_read_lock();
//
//	list_for_each_entry_rcu(pool, &kcmask_pools, list)
//		last = pool;
//	if (!WARN_ON(!last) && !kcmask_pool_get(last))
//		last = NULL;
//
//	rcu_read_unlock();
//
//	return last;
//}
//
//static struct kcmask_pool *kcmask_pool_find_get(char *type, char *compressor)
//{
//	struct kcmask_pool *pool;
//
//	assert_spin_locked(&kcmask_pools_lock);
//
//	list_for_each_entry_rcu(pool, &kcmask_pools, list) {
//		if (strncmp(pool->tfm_name, compressor, sizeof(pool->tfm_name)))
//			continue;
//		if (strncmp(zpool_get_type(pool->zpool), type,
//			    sizeof(kcmask_zpool_type)))
//			continue;
//		/* if we can't get it, it's about to be destroyed */
//		if (!kcmask_pool_get(pool))
//			continue;
//		return pool;
//	}
//
//	return NULL;
//}
//
//static struct kcmask_pool *kcmask_pool_create(char *type, char *compressor)
//{
//	struct kcmask_pool *pool;
//	gfp_t gfp = __GFP_NORETRY | __GFP_NOWARN;
//
//	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
//	if (!pool) {
//		pr_err("pool alloc failed\n");
//		return NULL;
//	}
//
//	pool->zpool = zpool_create_pool(type, "kcmask", gfp, &kcmask_zpool_ops);
//	if (!pool->zpool) {
//		pr_err("%s zpool not available\n", type);
//		goto error;
//	}
//	pr_debug("using %s zpool\n", zpool_get_type(pool->zpool));
//
//	strlcpy(pool->tfm_name, compressor, sizeof(pool->tfm_name));
//	pool->tfm = alloc_percpu(struct crypto_comp *);
//	if (!pool->tfm) {
//		pr_err("percpu alloc failed\n");
//		goto error;
//	}
//
//	if (kcmask_cpu_comp_init(pool))
//		goto error;
//	pr_debug("using %s compressor\n", pool->tfm_name);
//
//	/* being the current pool takes 1 ref; this func expects the
//	 * caller to always add the new pool as the current pool
//	 */
//	kref_init(&pool->kref);
//	INIT_LIST_HEAD(&pool->list);
//
//	kcmask_pool_debug("created", pool);
//
//	return pool;
//
//error:
//	free_percpu(pool->tfm);
//	if (pool->zpool)
//		zpool_destroy_pool(pool->zpool);
//	kfree(pool);
//	return NULL;
//}
//
//static struct kcmask_pool *__kcmask_pool_create_fallback(void)
//{
//	if (!crypto_has_comp(kcmask_compressor, 0, 0)) {
//		pr_err("compressor %s not available, using default %s\n",
//		       kcmask_compressor, kcmask_COMPRESSOR_DEFAULT);
//		strncpy(kcmask_compressor, kcmask_COMPRESSOR_DEFAULT,
//			sizeof(kcmask_compressor));
//	}
//	if (!zpool_has_pool(kcmask_zpool_type)) {
//		pr_err("zpool %s not available, using default %s\n",
//		       kcmask_zpool_type, kcmask_ZPOOL_DEFAULT);
//		strncpy(kcmask_zpool_type, kcmask_ZPOOL_DEFAULT,
//			sizeof(kcmask_zpool_type));
//	}
//
//	return kcmask_pool_create(kcmask_zpool_type, kcmask_compressor);
//}
//
//static void kcmask_pool_destroy(struct kcmask_pool *pool)
//{
//	kcmask_pool_debug("destroying", pool);
//
//	kcmask_cpu_comp_destroy(pool);
//	free_percpu(pool->tfm);
//	zpool_destroy_pool(pool->zpool);
//	kfree(pool);
//}
//
//static int __must_check kcmask_pool_get(struct kcmask_pool *pool)
//{
//	return kref_get_unless_zero(&pool->kref);
//}
//
//static void __kcmask_pool_release(struct rcu_head *head)
//{
//	struct kcmask_pool *pool = container_of(head, typeof(*pool), rcu_head);
//
//	/* nobody should have been able to get a kref... */
//	WARN_ON(kref_get_unless_zero(&pool->kref));
//
//	/* pool is now off kcmask_pools list and has no references. */
//	kcmask_pool_destroy(pool);
//}
//
//static void __kcmask_pool_empty(struct kref *kref)
//{
//	struct kcmask_pool *pool;
//
//	pool = container_of(kref, typeof(*pool), kref);
//
//	spin_lock(&kcmask_pools_lock);
//
//	WARN_ON(pool == kcmask_pool_current());
//
//	list_del_rcu(&pool->list);
//	call_rcu(&pool->rcu_head, __kcmask_pool_release);
//
//	spin_unlock(&kcmask_pools_lock);
//}
//
//static void kcmask_pool_put(struct kcmask_pool *pool)
//{
//	kref_put(&pool->kref, __kcmask_pool_empty);
//}

/*********************************
* param callbacks
**********************************/

//static int __kcmask_param_set(const char *val, const struct kernel_param *kp,
//			     char *type, char *compressor)
//{
//	struct kcmask_pool *pool, *put_pool = NULL;
//	char str[kp->str->maxlen], *s;
//	int ret;
//
//	/*
//	 * kp is either kcmask_zpool_kparam or kcmask_compressor_kparam, defined
//	 * at the top of this file, so maxlen is CRYPTO_MAX_ALG_NAME (64) or
//	 * 32 (arbitrary).
//	 */
//	strlcpy(str, val, kp->str->maxlen);
//	s = strim(str);
//
//	/* if this is load-time (pre-init) param setting,
//	 * don't create a pool; that's done during init.
//	 */
//	if (!kcmask_init_started)
//		return param_set_copystring(s, kp);
//
//	/* no change required */
//	if (!strncmp(kp->str->string, s, kp->str->maxlen))
//		return 0;
//
//	if (!type) {
//		type = s;
//		if (!zpool_has_pool(type)) {
//			pr_err("zpool %s not available\n", type);
//			return -ENOENT;
//		}
//	} else if (!compressor) {
//		compressor = s;
//		if (!crypto_has_comp(compressor, 0, 0)) {
//			pr_err("compressor %s not available\n", compressor);
//			return -ENOENT;
//		}
//	}
//
//	spin_lock(&kcmask_pools_lock);
//
//	pool = kcmask_pool_find_get(type, compressor);
//	if (pool) {
//		kcmask_pool_debug("using existing", pool);
//		list_del_rcu(&pool->list);
//	} else {
//		spin_unlock(&kcmask_pools_lock);
//		pool = kcmask_pool_create(type, compressor);
//		spin_lock(&kcmask_pools_lock);
//	}
//
//	if (pool)
//		ret = param_set_copystring(s, kp);
//	else
//		ret = -EINVAL;
//
//	if (!ret) {
//		put_pool = kcmask_pool_current();
//		list_add_rcu(&pool->list, &kcmask_pools);
//	} else if (pool) {
//		/* add the possibly pre-existing pool to the end of the pools
//		 * list; if it's new (and empty) then it'll be removed and
//		 * destroyed by the put after we drop the lock
//		 */
//		list_add_tail_rcu(&pool->list, &kcmask_pools);
//		put_pool = pool;
//	}
//
//	spin_unlock(&kcmask_pools_lock);
//
//	/* drop the ref from either the old current pool,
//	 * or the new pool we failed to add
//	 */
//	if (put_pool)
//		kcmask_pool_put(put_pool);
//
//	return ret;
//}
//
//static int kcmask_compressor_param_set(const char *val,
//				      const struct kernel_param *kp)
//{
//	return __kcmask_param_set(val, kp, kcmask_zpool_type, NULL);
//}
//
//static int kcmask_zpool_param_set(const char *val,
//				 const struct kernel_param *kp)
//{
//	return __kcmask_param_set(val, kp, NULL, kcmask_compressor);
//}

/*********************************
* writeback code
**********************************/
/* return enum for kcmask_get_swap_cache_page */
//enum kcmask_get_swap_ret {
//	kcmask_SWAPCACHE_NEW,
//	kcmask_SWAPCACHE_EXIST,
//	kcmask_SWAPCACHE_FAIL,
//};

/*
 * kcmask_get_swap_cache_page
 *
 * This is an adaption of read_swap_cache_async()
 *
 * This function tries to find a page with the given swap entry
 * in the swapper_space address space (the swap cache).  If the page
 * is found, it is returned in retpage.  Otherwise, a page is allocated,
 * added to the swap cache, and returned in retpage.
 *
 * If success, the swap cache page is returned in retpage
 * Returns kcmask_SWAPCACHE_EXIST if page was already in the swap cache
 * Returns kcmask_SWAPCACHE_NEW if the new page needs to be populated,
 *     the new page is added to swapcache and locked
 * Returns kcmask_SWAPCACHE_FAIL on error
 */
//static int kcmask_get_swap_cache_page(swp_entry_t entry,
//				struct page **retpage)
//{
//	bool page_was_allocated;
//
//	*retpage = __read_swap_cache_async(entry, GFP_KERNEL,
//			NULL, 0, &page_was_allocated);
//	if (page_was_allocated)
//		return kcmask_SWAPCACHE_NEW;
//	if (!*retpage)
//		return kcmask_SWAPCACHE_FAIL;
//	return kcmask_SWAPCACHE_EXIST;
//}

/*
 * Attempts to free an entry by adding a page to the swap cache,
 * decompressing the entry data into the page, and issuing a
 * bio write to write the page back to the swap device.
 *
 * This can be thought of as a "resumed writeback" of the page
 * to the swap device.  We are basically resuming the same swap
 * writeback path that was intercepted with the frontswap_store()
 * in the first place.  After the page has been decompressed into
 * the swap cache, the compressed version stored by kcmask can be
 * freed.
 */
//static int kcmask_writeback_entry(struct zpool *pool, unsigned long handle)
//{
//	struct kcmask_header *zhdr;
//	swp_entry_t swpentry;
//	struct kcmask_tree *tree;
//	pgoff_t offset;
//	struct kcmask_entry *entry;
//	struct page *page;
//	struct crypto_comp *tfm;
//	u8 *src, *dst;
//	unsigned int dlen;
//	int ret;
//	struct writeback_control wbc = {
//		.sync_mode = WB_SYNC_NONE,
//	};
//
//	/* extract swpentry from data */
//	zhdr = zpool_map_handle(pool, handle, ZPOOL_MM_RO);
//	swpentry = zhdr->swpentry; /* here */
//	zpool_unmap_handle(pool, handle);
//	tree = kcmask_trees[swp_type(swpentry)];
//	offset = swp_offset(swpentry);
//
//	/* find and ref kcmask entry */
//	spin_lock(&tree->lock);
//	entry = kcmask_entry_find_get(&tree->rbroot, offset);
//	if (!entry) {
//		/* entry was invalidated */
//		spin_unlock(&tree->lock);
//		return 0;
//	}
//	spin_unlock(&tree->lock);
//	BUG_ON(offset != entry->offset);
//
//	/* try to allocate swap cache page */
//	switch (kcmask_get_swap_cache_page(swpentry, &page)) {
//	case kcmask_SWAPCACHE_FAIL: /* no memory or invalidate happened */
//		ret = -ENOMEM;
//		goto fail;
//
//	case kcmask_SWAPCACHE_EXIST:
//		/* page is already in the swap cache, ignore for now */
//		page_cache_release(page);
//		ret = -EEXIST;
//		goto fail;
//
//	case kcmask_SWAPCACHE_NEW: /* page is locked */
//		/* decompress */
//		dlen = PAGE_SIZE;
//		src = (u8 *)zpool_map_handle(entry->pool->zpool, entry->handle,
//				ZPOOL_MM_RO) + sizeof(struct kcmask_header);
//		dst = kmap_atomic(page);
//		tfm = *get_cpu_ptr(entry->pool->tfm);
//		ret = crypto_comp_decompress(tfm, src, entry->length,
//					     dst, &dlen);
//		put_cpu_ptr(entry->pool->tfm);
//		kunmap_atomic(dst);
//		zpool_unmap_handle(entry->pool->zpool, entry->handle);
//		BUG_ON(ret);
//		BUG_ON(dlen != PAGE_SIZE);
//
//		/* page is up to date */
//		SetPageUptodate(page);
//	}
//
//	/* move it to the tail of the inactive list after end_writeback */
//	SetPageReclaim(page);
//
//	/* start writeback */
//	__swap_writepage(page, &wbc, end_swap_bio_write);
//	page_cache_release(page);
//	kcmask_written_back_pages++;
//
//	spin_lock(&tree->lock);
//	/* drop local reference */
//	kcmask_entry_put(tree, entry);
//
//	/*
//	* There are two possible situations for entry here:
//	* (1) refcount is 1(normal case),  entry is valid and on the tree
//	* (2) refcount is 0, entry is freed and not on the tree
//	*     because invalidate happened during writeback
//	*  search the tree and free the entry if find entry
//	*/
//	if (entry == kcmask_rb_search(&tree->rbroot, offset))
//		kcmask_entry_put(tree, entry);
//	spin_unlock(&tree->lock);
//
//	goto end;
//
//	/*
//	* if we get here due to kcmask_SWAPCACHE_EXIST
//	* a load may happening concurrently
//	* it is safe and okay to not free the entry
//	* if we free the entry in the following put
//	* it it either okay to return !0
//	*/
//fail:
//	spin_lock(&tree->lock);
//	kcmask_entry_put(tree, entry);
//	spin_unlock(&tree->lock);
//
//end:
//	return ret;
//}

//static int kcmask_shrink(void)
//{
////	struct kcmask_pool *pool;
////	int ret;
////
////	pool = kcmask_pool_last_get();
////	if (!pool)
////		return -ENOENT;
////
////	ret = zpool_shrink(pool->zpool, 1, NULL);
////
////	kcmask_pool_put(pool);
////
////	return ret;
//}

/*********************************
* frontswap hooks
**********************************/
/* attempts to compress and store an single page */
static int kcmask_frontswap_store(unsigned type, pgoff_t offset,
				struct page *page)
{
	int fd, ret = -1;
//	char *reserved_memory;
	unsigned int dlen = PAGE_SIZE

//	fd = open("/dev/mem", O_RDWR | O_SYNC);
	/* Returns a pointer to the 4GB point in /dev/mem - the start of my reserved memory. Only mapping 4096 bytes. */
//	reserved_memory = (char *) mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, RESERVED_MEMORY_OFFSET);
//	if (reserved_memory == MAP_FAILED){
//		pr_err("Failed to creating mapping. ERRNO:%s\n", strerror(errno));
//		return -1;
//	}
	u8 *reserved_memory;
	reserved_memory = ioremap_nocache(RESERVED_MEMORY_OFFSET, dlen);

	src = kmap_atomic(page);
	memcpy(reserved_memory, src, dlen);
	kunmap_atomic(src);

	sector_t sector = swap_page_sector(page);
	ret = syscall(333, sector);
	return ret; //if == 0, meaning that we can successfully write to frontswap and there is no need to write to swap device.

//	struct kcmask_tree *tree = kcmask_trees[type];
//	struct kcmask_entry *entry, *dupentry;
//	struct crypto_comp *tfm;
//	int ret;
//	unsigned int dlen = PAGE_SIZE, len;
//	unsigned long handle;
//	char *buf;
//	u8 *src, *dst;
//	struct kcmask_header *zhdr;

//	if (!kcmask_enabled || !tree) {
//		ret = -ENODEV;
//		goto reject;
//	}

//	/* reclaim space if needed */
//	if (kcmask_is_full()) {
//		kcmask_pool_limit_hit++;
//		if (kcmask_shrink()) {
//			kcmask_reject_reclaim_fail++;
//			ret = -ENOMEM;
//			goto reject;
//		}
//	}

//	/* allocate entry */
//	entry = kcmask_entry_cache_alloc(GFP_KERNEL);
//	if (!entry) {
//		kcmask_reject_kmemcache_fail++;
//		ret = -ENOMEM;
//		goto reject;
//	}

//	/* if entry is successfully added, it keeps the reference */
//	entry->pool = kcmask_pool_current_get();
//	if (!entry->pool) {
//		ret = -EINVAL;
//		goto freepage;
//	}

	/* compress */
//	dst = get_cpu_var(kcmask_dstmem);
//	tfm = *get_cpu_ptr(entry->pool->tfm);
//	src = kmap_atomic(page);
//	ret = crypto_comp_compress(tfm, src, PAGE_SIZE, dst, &dlen);
//	kunmap_atomic(src);
//	put_cpu_ptr(entry->pool->tfm);
//	if (ret) {
//		ret = -EINVAL;
//		goto put_dstmem;
//	}

	/* store */
//	len = dlen + sizeof(struct kcmask_header);
//	ret = zpool_malloc(entry->pool->zpool, len,
//			   __GFP_NORETRY | __GFP_NOWARN, &handle);
//	if (ret == -ENOSPC) {
//		kcmask_reject_compress_poor++;
//		goto put_dstmem;
//	}
//	if (ret) {
//		kcmask_reject_alloc_fail++;
//		goto put_dstmem;
//	}
//	zhdr = zpool_map_handle(entry->pool->zpool, handle, ZPOOL_MM_RW);
//	zhdr->swpentry = swp_entry(type, offset);
//	buf = (u8 *)(zhdr + 1);
//	memcpy(buf, dst, dlen);
//	zpool_unmap_handle(entry->pool->zpool, handle);
//	put_cpu_var(kcmask_dstmem);

//	/* populate entry */
//	entry->offset = offset;
//	entry->handle = handle;
//	entry->length = dlen;

	/* map */
//	spin_lock(&tree->lock);
//	do {
//		ret = kcmask_rb_insert(&tree->rbroot, entry, &dupentry);
//		if (ret == -EEXIST) {
//			kcmask_duplicate_entry++;
//			/* remove from rbtree */
//			kcmask_rb_erase(&tree->rbroot, dupentry);
//			kcmask_entry_put(tree, dupentry);
//		}
//	} while (ret == -EEXIST);
//	spin_unlock(&tree->lock);
//
//	/* update stats */
//	atomic_inc(&kcmask_stored_pages);
//	kcmask_update_total_size();
//
//	return 0;
//
//put_dstmem:
//	put_cpu_var(kcmask_dstmem);
//	kcmask_pool_put(entry->pool);
//freepage:
//	kcmask_entry_cache_free(entry);
//reject:
//	return ret;
}

/*
 * returns 0 if the page was successfully decompressed
 * return -1 on entry not found or error
*/
static int kcmask_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
//	struct kcmask_tree *tree = kcmask_trees[type];
//	struct kcmask_entry *entry;
//	struct crypto_comp *tfm;
//	u8 *src, *dst;
//	unsigned int dlen;
//	int ret;
//
//	/* find */
//	spin_lock(&tree->lock);
//	entry = kcmask_entry_find_get(&tree->rbroot, offset);
//	if (!entry) {
//		/* entry was written back */
//		spin_unlock(&tree->lock);
//		return -1;
//	}
//	spin_unlock(&tree->lock);
//
//	/* decompress */
//	dlen = PAGE_SIZE;
//	src = (u8 *)zpool_map_handle(entry->pool->zpool, entry->handle,
//			ZPOOL_MM_RO) + sizeof(struct kcmask_header);
//	dst = kmap_atomic(page);
//	tfm = *get_cpu_ptr(entry->pool->tfm);
//	ret = crypto_comp_decompress(tfm, src, entry->length, dst, &dlen);
//	put_cpu_ptr(entry->pool->tfm);
//	kunmap_atomic(dst);
//	zpool_unmap_handle(entry->pool->zpool, entry->handle);
//	BUG_ON(ret);
//
//	spin_lock(&tree->lock);
//	kcmask_entry_put(tree, entry);
//	spin_unlock(&tree->lock);

	return 0; //meaning that we can successfully read from frontswap and there is no need to read from swap device.
}

/* frees an entry in kcmask */
static void kcmask_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	return;
//	struct kcmask_tree *tree = kcmask_trees[type];
//	struct kcmask_entry *entry;
//
//	/* find */
//	spin_lock(&tree->lock);
//	entry = kcmask_rb_search(&tree->rbroot, offset);
//	if (!entry) {
//		/* entry was written back */
//		spin_unlock(&tree->lock);
//		return;
//	}
//
//	/* remove from rbtree */
//	kcmask_rb_erase(&tree->rbroot, entry);
//
//	/* drop the initial reference from entry creation */
//	kcmask_entry_put(tree, entry);
//
//	spin_unlock(&tree->lock);
}

/* frees all kcmask entries for the given swap type */
static void kcmask_frontswap_invalidate_area(unsigned type)
{
	return;
//	struct kcmask_tree *tree = kcmask_trees[type];
//	struct kcmask_entry *entry, *n;
//
//	if (!tree)
//		return;
//
//	/* walk the tree and free everything */
//	spin_lock(&tree->lock);
//	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode)
//		kcmask_free_entry(entry);
//	tree->rbroot = RB_ROOT;
//	spin_unlock(&tree->lock);
//	kfree(tree);
//	kcmask_trees[type] = NULL;
}

static void kcmask_frontswap_init(unsigned type)
{
//	struct kcmask_tree *tree;
//
//	tree = kzalloc(sizeof(struct kcmask_tree), GFP_KERNEL);
//	if (!tree) {
//		pr_err("alloc failed, kcmask disabled for swap type %d\n", type);
//		return;
//	}
//
//	tree->rbroot = RB_ROOT;
//	spin_lock_init(&tree->lock);
//	kcmask_trees[type] = tree;

	pr_info("init front swap: Doing nothing\n"）
}

/*********************************
 kcmask ops:
 Only store and load are implemented
**********************************/

static struct frontswap_ops kcmask_frontswap_ops = {
	.store = kcmask_frontswap_store,
	.load = kcmask_frontswap_load,
	.invalidate_page = kcmask_frontswap_invalidate_page,
	.invalidate_area = kcmask_frontswap_invalidate_area,
	.init = kcmask_frontswap_init
};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *kcmask_debugfs_root;

static int __init kcmask_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	kcmask_debugfs_root = debugfs_create_dir("kcmask", NULL);
	if (!kcmask_debugfs_root)
		return -ENOMEM;

	debugfs_create_u64("pool_limit_hit", S_IRUGO,
			kcmask_debugfs_root, &kcmask_pool_limit_hit);
	debugfs_create_u64("reject_reclaim_fail", S_IRUGO,
			kcmask_debugfs_root, &kcmask_reject_reclaim_fail);
	debugfs_create_u64("reject_alloc_fail", S_IRUGO,
			kcmask_debugfs_root, &kcmask_reject_alloc_fail);
	debugfs_create_u64("reject_kmemcache_fail", S_IRUGO,
			kcmask_debugfs_root, &kcmask_reject_kmemcache_fail);
	debugfs_create_u64("reject_compress_poor", S_IRUGO,
			kcmask_debugfs_root, &kcmask_reject_compress_poor);
	debugfs_create_u64("written_back_pages", S_IRUGO,
			kcmask_debugfs_root, &kcmask_written_back_pages);
	debugfs_create_u64("duplicate_entry", S_IRUGO,
			kcmask_debugfs_root, &kcmask_duplicate_entry);
	debugfs_create_u64("pool_total_size", S_IRUGO,
			kcmask_debugfs_root, &kcmask_pool_total_size);
	debugfs_create_atomic_t("stored_pages", S_IRUGO,
			kcmask_debugfs_root, &kcmask_stored_pages);

	return 0;
}

static void __exit kcmask_debugfs_exit(void)
{
	debugfs_remove_recursive(kcmask_debugfs_root);
}
#else
static int __init kcmask_debugfs_init(void)
{
	return 0;
}

static void __exit kcmask_debugfs_exit(void) { }
#endif

/*********************************
* module init and exit
**********************************/
static int __init init_kcmask(void)
{
//	struct kcmask_pool *pool;
//
//	kcmask_init_started = true;
//
//	if (kcmask_entry_cache_create()) {
//		pr_err("entry cache creation failed\n");
//		goto cache_fail;
//	}
//
//	if (kcmask_cpu_dstmem_init()) {
//		pr_err("dstmem alloc failed\n");
//		goto dstmem_fail;
//	}
//
//	pool = __kcmask_pool_create_fallback();
//	if (!pool) {
//		pr_err("pool creation failed\n");
//		goto pool_fail;
//	}
//	pr_info("loaded using pool %s/%s\n", pool->tfm_name,
//		zpool_get_type(pool->zpool));
//
//	list_add(&pool->list, &kcmask_pools);
//
//	/* Tell the kernel you have reserved this resource, thus preventing other driver to do the same */
//	request_mem_region(2000*1024*1024, size, "who r u");
//    /* get the virtual address of the physical address */
//	virt_addr =  ioremap_nocache(2000*1024*1024, size);
	//TODO exit
//    /* Tell kernel that you are done with the resource */
//    release_mem_region(2000*1024*1024, size);
//   /* unmap io memory */
//    iounmap(virt_addr);

	pr_info("start register front swap ops\n"）
	frontswap_register_ops(&kcmask_frontswap_ops);
	if (kcmask_debugfs_init())
		pr_warn("debugfs initialization failed\n");
	return 0;
//
//pool_fail:
//	kcmask_cpu_dstmem_destroy();
//dstmem_fail:
//	kcmask_entry_cache_destroy();
//cache_fail:
//	return -ENOMEM;
}
/* must be late so crypto has time to come up */
late_initcall(init_kcmask);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nannan Zhao <znannan1@vt.edu>");
MODULE_DESCRIPTION("Kernel support for CMASK");
