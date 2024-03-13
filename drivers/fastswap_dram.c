#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include "fastswap_dram.h"
#include <linux/crypto.h> 
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/cpumask.h>

#include <linux/mm_types.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/crc16.h>

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 32) /* must match what server is allocating */

static void *drambuf;
static struct zswap_tree *zswap_trees;//rb tree数组,只一个swap area,申请一个
static struct compress_sum *sum;
static struct compress_sum_read *sum_read;

struct compress_sum{
	long sum_compress_len;
	long compress_pages;
	long uncompress_pages;
	spinlock_t lock;
};

struct compress_sum_read{
	long sum_compress_len;
	long compress_pages;
	long uncompress_pages;
	spinlock_t lock;
};


struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;//用concurrent load时,保护entry不被过早释放
	unsigned int length;//+++
	// bool IsCompress;//+++
	u16 crc;;//++++
	// struct zswap_pool *pool;
	// unsigned long handle;
};


struct zswap_tree {//包含rb树root
	struct rb_root rbroot;
	spinlock_t lock;
};

/*********************************
* zswap entry functions
**********************************/
static struct kmem_cache *zswap_entry_cache;

static int __init zswap_entry_cache_create(void)
{
	zswap_entry_cache = KMEM_CACHE(zswap_entry, 0);
	return zswap_entry_cache == NULL;
}

static void __init zswap_entry_cache_destroy(void)
{
	kmem_cache_destroy(zswap_entry_cache);
}

static struct zswap_entry *zswap_entry_cache_alloc(gfp_t gfp)
{
	struct zswap_entry *entry;
	entry = kmem_cache_alloc(zswap_entry_cache, gfp);
	if (!entry)
		return NULL;
	entry->refcount = 1;
	RB_CLEAR_NODE(&entry->rbnode);
	return entry;
}

static void zswap_entry_cache_free(struct zswap_entry *entry)
{
	kmem_cache_free(zswap_entry_cache, entry);
}

//******** rb tree操作 **************

static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
{
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,//如果rb树上发现重复的entry,dupenry指向重复的entry
			struct zswap_entry **dupentry)
{//zswap_entry
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct zswap_entry *myentry;

	while (*link) {
		parent = *link;//entry是带插入rb tree的entry, link是指向rb tree的节点的指针
		myentry = rb_entry(parent, struct zswap_entry, rbnode);//#define rb_entry(ptr, type, member) container_of(ptr, type, member)
		if (myentry->offset > entry->offset)//如果新节点的offset小于父亲节点的offset
			link = &(*link)->rb_left;
		else if (myentry->offset < entry->offset)//如果新节点的offset大于父亲节点的offset
			link = &(*link)->rb_right;
		else {//如果新节点的offset等于父亲节点的offset
			*dupentry = myentry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);//插入 把新节点指向其父亲节点
	rb_insert_color(&entry->rbnode, root);//rb树颜色的调整
	return 0;
}

static struct zswap_entry *zswap_rb_search(struct rb_root *root, pgoff_t offset)
{
	struct rb_node *node = root->rb_node;
	struct zswap_entry *entry;

	while (node) {
		entry = rb_entry(node, struct zswap_entry, rbnode);
		if (entry->offset > offset)
			node = node->rb_left;
		else if (entry->offset < offset)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset)//根据offset查entry
{
	struct zswap_entry *entry;

	entry = zswap_rb_search(root, offset);
	// if (entry) 
	// 	entry->refcount++;//用于设置refcount++

	return entry;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
//TODO 使用了refcount 最后也没有使用
static void zswap_entry_put(struct zswap_tree *tree, 
			struct zswap_entry *entry)
{
	// int refcount = --entry->refcount;
	// BUG_ON(refcount < 0);
	// if (refcount == 0) {
	// 	zswap_rb_erase(&tree->rbroot, entry);
	// 	zswap_free_entry(entry);
	// }
  zswap_rb_erase(&tree->rbroot, entry);
  kfree(entry);
}
//
static void zswap_frontswap_invalidate_area(void)
{
	struct zswap_tree *tree = zswap_trees;
	struct zswap_entry *entry, *n;

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode){//先序遍历
    	kfree(entry);
    // atomic_dec(&zswap_stored_pages);
 	}
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees = NULL;
}


static int compress(void* src,unsigned int *dlen, void *dst){
  int ret;
  struct crypto_comp *tfm;
  char alg[] = "lzo";
  tfm = crypto_alloc_comp(alg,0,0);
  if (IS_ERR_OR_NULL(tfm)) {
		pr_err("could not alloc crypto comp");
		return -ENOMEM;
	}
  ret = crypto_comp_compress(tfm, src, PAGE_SIZE, dst, dlen);

  //TODO: 这里不一定合理 参见cpuhp_setup_state_multi
  crypto_free_comp(tfm);//释放crypto_comp对象
  return ret;
}

static int decompress(void* src,int slen, void *dst, unsigned int *dlen){
  int ret;
  struct crypto_comp *tfm;
  char alg[] = "lzo";
  tfm = crypto_alloc_comp(alg,0,0);
  if (IS_ERR_OR_NULL(tfm)) {
		pr_err("could not alloc crypto comp");
		return -ENOMEM;
	}
  ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);

  crypto_free_comp(tfm);//释放crypto_comp对象
  return ret;
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
	void *page_vaddr;//page映射地址
	void *buf;//压缩后缓存
	unsigned int dlen;
	struct zswap_entry *entry, *dupentry;
	u16 crc;
	struct zswap_tree *tree = zswap_trees;
	int ret;
	int compress_ret;

	buf = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
	page_vaddr = kmap_atomic(page);

	crc = crc16(0x0000 ,(u8 *)page_vaddr, PAGE_SIZE);

	//******** 压缩 **************
	compress_ret = compress(page_vaddr, &dlen, buf);

	kunmap_atomic(page_vaddr);

	entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL);
	RB_CLEAR_NODE(&entry->rbnode);

	//在zswap entry cache中分配entry
	// entry = zswap_entry_cache_alloc(GFP_KERNEL);

	entry->offset = roffset;
	entry->crc = crc;

	
	if(dlen < PAGE_SIZE){
		memcpy(drambuf + roffset ,buf, dlen);
		entry->length = dlen;

		spin_lock(&sum_read->lock);
		sum->compress_pages++;
		sum->sum_compress_len += dlen;
		spin_unlock(&sum_read->lock);

		pr_info("[write compres] cpuid: %d roffset: %llx | compress ret: %d len:%lu --> %u crc: %hx",smp_processor_id(), roffset, compress_ret, PAGE_SIZE, dlen, entry->crc);
	}
	else{//不能压缩到4KB以下
		// memcpy(drambuf + roffset, page_vaddr, PAGE_SIZE);
		copy_page((void *) (drambuf + roffset), page_vaddr);
		entry->length = PAGE_SIZE;

		spin_lock(&sum->lock);
		sum->uncompress_pages++;
		spin_unlock(&sum->lock);
		
		
		pr_info("[write] cpuid: %d roffset: %llx | compress ret: %d len: %lu --> %u crc: %hx",smp_processor_id(), roffset, compress_ret, PAGE_SIZE, dlen, entry->crc);

	}
	kfree(buf);

	
	//******** 插入rb tree **************
	spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {//重复的entry 应该删除重复的entry(dupentry) 保证rb tree上node唯一
			pr_info("[Write_duplicate] offset: %lx", entry->offset);
			// zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
			kfree(dupentry);//释放dupentry

			//******** swap entry cache中释放 **************
			// zswap_entry_cache_free(dupentry);
			// zswap_entry_put(tree, dupentry)
		}
	} while (ret == -EEXIST);

	spin_unlock(&tree->lock);
	

	return 0;
}
EXPORT_SYMBOL(sswap_rdma_write);

int sswap_rdma_poll_load(int cpu)
{
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

int sswap_rdma_read_async(struct page *page, u64 roffset)
{
	void *page_vaddr;
	struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树
	struct zswap_entry *entry;
	void *buf;
	unsigned int dlen;
	u16 crc;
	int decompress_ret = 0;

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageUptodate(page), page);

	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, roffset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
  	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		pr_info("rb treee not found roffset: %llx", roffset);
		BUG();
		return -1;
	}
	spin_unlock(&tree->lock);//unlock

	buf = kmalloc(2 * PAGE_SIZE, GFP_KERNEL);
	page_vaddr = kmap_atomic(page);

	if(entry->length < PAGE_SIZE){
		memcpy(buf ,drambuf + roffset, entry->length);
		decompress_ret = decompress(buf, entry->length, page_vaddr, &dlen);
		if(dlen != PAGE_SIZE){
			pr_info("decompress wrong roffset: %llx len: %u ", roffset, entry->length);
		}

		spin_lock(&sum->lock);
		sum_read->compress_pages++;
		sum_read->sum_compress_len += entry->length;
		spin_unlock(&sum->lock);

	}
	else{
		copy_page(page_vaddr, (void *) (drambuf + roffset));
		dlen = PAGE_SIZE;

		spin_lock(&sum->lock);
		sum_read->uncompress_pages++;
		spin_unlock(&sum->lock);
	}
	kfree(buf);

	crc = crc16(0x0000 ,(u8 *)page_vaddr, PAGE_SIZE);//无论是否是解压缩的
	
	if(entry->length < PAGE_SIZE){
		pr_info("++[read decompress] cpuid: %d roffset: %llx | decompress ret: %d len:%u --> %u crc: %hx --> %hx",smp_processor_id(),roffset, decompress_ret, entry->length, dlen, entry->crc, crc);
	}
	else{
		pr_info("**[read] cpuid: %d roffset: %llx len:%u crc: %hx --> %hx",smp_processor_id(),roffset, entry->length, entry->crc, crc);
	}


	if(entry->crc != crc){
		pr_info("!!!crc wrong roffset: %llx", roffset);
	}
	kunmap_atomic(page_vaddr);

	// //读完删除rb tree上 entry
 	// spin_lock(&tree->lock);
	// zswap_entry_put(tree, entry);//ref-- 如果ref为0 1.删除rb tree上entry 2.释放zpool数据 
	// spin_unlock(&tree->lock);

	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
	return sswap_rdma_read_async(page, roffset);
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	long sum_page;
	long long sum_len;

	vfree(drambuf);
	zswap_frontswap_invalidate_area();//释放rbtree

	sum_page = sum->compress_pages + sum->uncompress_pages;
	sum_len = sum->sum_compress_len + (sum->uncompress_pages * 4096);
	pr_info("[write] sum len: %ld --> %lld num: %ld", sum_page * 4096, sum_len, sum_page);
	pr_info("[write] compress num: %ld len: %ld | uncompress num: %ld len: %ld * 4096", sum->compress_pages, sum->sum_compress_len, sum->uncompress_pages, sum->uncompress_pages);
	

	sum_page = sum_read->compress_pages + sum_read->uncompress_pages;
	sum_len = sum_read->sum_compress_len + (sum_read->uncompress_pages * 4096);
	pr_info("[read] sum len: %ld --> %lld num: %ld",sum_page * 4096, sum_len, sum_page);
	pr_info("[read] compress num: %ld len: %ld | uncompress num: %ld len: %ld * 4096", sum_read->compress_pages, sum_read->sum_compress_len, sum_read->uncompress_pages, sum_read->uncompress_pages);

	kfree(sum);
	kfree(sum_read);

	//******** 释放swap entry cache *************
	zswap_entry_cache_destroy();

	pr_info("******* exit ********");

}

static int __init sswap_dram_init_module(void)
{
	struct zswap_tree *tree;//

	pr_info("start: %s\n", __FUNCTION__);
	pr_info("will use new DRAM backend");

	//******** 分配drambuf **************
	drambuf = vzalloc(REMOTE_BUF_SIZE);//同vmalloc
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

	pr_info("DRAM backend is ready for reqs\n");

	//******** 初始化rb tree **************
	tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);//为swap(rb) tree分配空间,包含一个rbroot和lock

	if (!tree) {
	pr_err("alloc failed, zswap disabled for swap type \n");
		BUG();
	}

	tree->rbroot = RB_ROOT;//为NULL #define RB_ROOT	(struct rb_root) { NULL, }
	spin_lock_init(&tree->lock);
	zswap_trees = tree;

	// //******** 初始化zswap entry cache **************
	// zswap_entry_cache_create();

	//******** 初始化统计的lock **************
	
	sum = kzalloc(sizeof(struct compress_sum), GFP_KERNEL);
	spin_lock_init(&sum->lock);
	sum->compress_pages = 0;
	sum->sum_compress_len = 0;
	sum->uncompress_pages = 0;

	sum_read = kzalloc(sizeof(struct compress_sum_read), GFP_KERNEL);
	spin_lock_init(&sum_read->lock);
	sum_read->compress_pages = 0;
	sum_read->sum_compress_len = 0;
	sum_read->uncompress_pages = 0;
	

	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
