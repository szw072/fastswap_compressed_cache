#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "fastswap_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/crc16.h>

#include <linux/rbtree.h>
#include <linux/lzo.h>
#include <linux/lz4.h>


static struct sswap_rdma_ctrl *gctrl;
static int serverport;
static int numqueues;
static int numcpus;
static char serverip[INET_ADDRSTRLEN];
static char clientip[INET_ADDRSTRLEN];
static struct kmem_cache *req_cache;
module_param_named(sport, serverport, int, 0644);

// modified by ysjing
// module_param_named(nq, numqueues, int, 0644);
module_param_named(nc, numcpus, int, 0644);//numqueues = numcpus * 3 = 60;

module_param_string(sip, serverip, INET_ADDRSTRLEN, 0644);
module_param_string(cip, clientip, INET_ADDRSTRLEN, 0644);

static void *drambuf;
static struct swap_trend trend_history;
static struct time_log decomrpess_time_history;
static struct time_log rdma_time_history;
static struct compress_data example_compress_data;

// TODO: destroy ctrl

#define CONNECTION_TIMEOUT_MS 60000
// #define QP_QUEUE_DEPTH 256
#define QP_QUEUE_DEPTH 15000
// #define QP_QUEUE_DEPTH 40000
/* we don't really use recv wrs, so any small number should do */
#define QP_MAX_RECV_WR 4
/* we mainly do send wrs */
#define QP_MAX_SEND_WR	(4096)
#define CQ_NUM_CQES	(QP_MAX_SEND_WR)
#define POLL_BATCH_HIGH (QP_MAX_SEND_WR / 4)
#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 20) /* must match what server is allocating */

struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;//用concurrent load时,保护entry不被过早释放
	size_t length;//+++
  u16 crc_uncompress, crc_compress;//++++
  bool compressed;
  bool cached;//是否缓存 +++
};
struct zswap_tree {//包含rb树root
	struct rb_root rbroot;
	spinlock_t lock;
};


static struct zswap_tree *zswap_trees;//rb tree数组,只一个swap area,申请一个


// static atomic_t local_stored_pages = ATOMIC_INIT(0);//未压缩成功存到本地dram数量
static atomic_t zswap_stored_pages = ATOMIC_INIT(0);//存到页面数量
static atomic64_t total_pages = ATOMIC_INIT(0);//存到页面数量
static atomic64_t cachehit_pages = ATOMIC_INIT(0);//存到页面数量



/*********************************
* declaration
**********************************/

int get_prev_index(int index);

static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset);

static inline int rdma_read_page(struct rdma_queue *q, struct page *page,
			     u64 roffset);

static inline int poll_target(struct rdma_queue *q, int target);

inline static int get_req_for_page(struct rdma_req **req, struct ib_device *dev,
				struct page *page, enum dma_data_direction dir);

static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc);

inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 roffset, enum ib_wr_opcode op);

inline static void sswap_rdma_wait_completion(struct ib_cq *cq,
					      struct rdma_req *qe);

static void sswap_rdma_read_done_syn(struct ib_cq *cq, struct ib_wc *wc);

static inline int drain_queue(struct rdma_queue *q);

int compress_lz4(const char *src, char *dst, int inputSize, int maxOutputSize);

/*********************************
* compress functions
**********************************/


void init_example_compressed_data(void){
  pr_info("init example compress data");
  example_compress_data.src = (u8 *)kmalloc(2 * PAGE_SIZE, GFP_KERNEL); //
  example_compress_data.dst = (u8 *)kmalloc(2 * PAGE_SIZE, GFP_KERNEL);
  get_random_bytes(example_compress_data.src, PAGE_SIZE); //
  memset(example_compress_data.src, 7, PAGE_SIZE / 2);
  example_compress_data.compresslen = compress_lz4(example_compress_data.src, example_compress_data.dst, PAGE_SIZE, 2 * PAGE_SIZE);
}

void destroy_example_compressed_data(void){
  pr_info("destroy example compress data");
  kfree(example_compress_data.src);
  kfree(example_compress_data.dst);
}


int compress_lz4(const char *src, char *dst, int inputSize, int maxOutputSize){
  void *wrkmem_lz4;
  int wlen;

  wrkmem_lz4 = kmalloc(LZ4_MEM_COMPRESS, GFP_KERNEL);

  wlen =  LZ4_compress_default(src, dst, inputSize, maxOutputSize, wrkmem_lz4);

  kfree(wrkmem_lz4);
  return wlen;
}

size_t compress_lzo(const char *src, char *dst, int inputSize, int maxOutputSize){
  void *wrkmem_lzo;
  size_t wlen;

  wrkmem_lzo = kmalloc(LZO1X_1_MEM_COMPRESS, GFP_KERNEL);

  lzo1x_1_compress(src, inputSize, dst, &wlen, wrkmem_lzo);

  kfree(wrkmem_lzo);
  return wlen;
}


/*********************************
* monitor decompress functions
**********************************/

void init_decomrpess_time_history(int times) {
	//设置trend表大小为32 init_swap_trend(32)
	// decomrpess_time_history.history = (s64* ) kzalloc(size * sizeof(s64), GFP_KERNEL);
	atomic_set(&decomrpess_time_history.sample_times, times);//100次中采样次数
	atomic_set(&decomrpess_time_history.count, 0);
	atomic_set(&decomrpess_time_history.sample_count, 0);
	
	printk("decompress time history initiated for sample_times: %d/100\n", atomic_read(&decomrpess_time_history.sample_times));
}


void test_decompress_entry_page(struct zswap_entry *entry){
  void *dst, *src;
  int decompresslen;

  if(entry == NULL){
    return;
  }

  src = example_compress_data.dst;
  dst = example_compress_data.src;
  
  decompresslen =  LZ4_decompress_safe(src, dst, entry->length, PAGE_SIZE);
  if(decompresslen != PAGE_SIZE){
      pr_info("decompress wrong !");
  }
}

//
struct zswap_entry* get_last_trend_entry(void){
	long offset;
	int prev_index;
  // 非空获取最新的访问offset
  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry = NULL;
  
	if(atomic_read(&trend_history.size)) {
		prev_index = get_prev_index(atomic_read(&trend_history.head));
    offset = trend_history.history[prev_index].offset;
    //******** 查rb tree得dlen **************
    spin_lock(&tree->lock);//lock 防止数据读写冲突
    entry = zswap_entry_find_get(&tree->rbroot, offset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
    if (!entry) {
      /* entry was written back */
      spin_unlock(&tree->lock);
      pr_info("rb treee not found");
      BUG();
    }
    spin_unlock(&tree->lock);//unlock
    // test_decompress_entry_page(entry);
  }
  return entry;
}


s64 count_decompress_time(void){
  ktime_t start, diff;
  struct zswap_entry *entry = NULL;

  /* 1. 获取当前时间 */
  start = ktime_get();

  entry = get_last_trend_entry();
  test_decompress_entry_page(entry);

  /* 2. 计算时间差，单位纳秒 */
  diff = ktime_sub(ktime_get(), start);
  // printk("2diff time = %lldns\n", ktime_to_ns(diff));
  return ktime_to_ns(diff);
}

s64 count_decompress_entry_time(struct zswap_entry *entry){
  ktime_t start, diff;

  /* 1. 获取当前时间 */
  start = ktime_get();

  test_decompress_entry_page(entry);

  /* 2. 计算时间差，单位纳秒 */
  diff = ktime_sub(ktime_get(), start);
  // printk("2diff time = %lldns\n", ktime_to_ns(diff));
  return ktime_to_ns(diff);
}

void log_decompress_time(struct zswap_entry *entry){
  s64 time;
  int sample_times;
  
  sample_times = atomic_read(&decomrpess_time_history.sample_times);
  if(atomic_read(&decomrpess_time_history.count) % 100 == 0){
    atomic_set(&decomrpess_time_history.count, 0);
    atomic_set(&decomrpess_time_history.sample_count, 0);
    atomic64_set(&decomrpess_time_history.total_time, 0);
  }

  if(atomic_read(&decomrpess_time_history.count) < 10){
    time = count_decompress_entry_time(entry);
    atomic64_set(&decomrpess_time_history.total_time, atomic64_read(&decomrpess_time_history.total_time) + time);
  }

  if(atomic_read(&decomrpess_time_history.count) == 9){
    atomic64_set(&decomrpess_time_history.average_time, atomic64_read(&decomrpess_time_history.total_time) / sample_times);
    // pr_info("decompress sample time: %ld", atomic64_read(&decomrpess_time_history.average_time));
  }
  atomic_inc(&decomrpess_time_history.count);
}

/*********************************
* monitor rdma functions
**********************************/

void init_rdma_time_history(int times) {
	//设置trend表大小为32 init_swap_trend(32)
	// decomrpess_time_history.history = (s64* ) kzalloc(size * sizeof(s64), GFP_KERNEL);
	atomic_set(&rdma_time_history.sample_times, times);//100次中采样次数
	atomic_set(&rdma_time_history.count, 0);
	atomic_set(&rdma_time_history.sample_count, 0);
	
	printk("rdma time history initiated for sample_times: %d/100\n", atomic_read(&decomrpess_time_history.sample_times));
}

void test_rdma_entry_page(struct zswap_entry *entry){
  struct rdma_queue *q;
  int ret;
  struct page *page = NULL;
  struct rdma_req *req;
  struct ib_device *dev;
  struct ib_sge sge = {};
  int inflight;
  u64 roffset;

  // roffset  = 0x0000;
  roffset = entry->offset;

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  
  dev = q->ctrl->rdev->dev;
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }

  page = alloc_pages(GFP_KERNEL, get_order(PAGE_SIZE));

  if (!page) {
    printk(KERN_ERR "Failed to allocate %lu bytes of memory\n", PAGE_SIZE);
    goto out;
  }

  get_req_for_page(&req, dev, page, DMA_TO_DEVICE);

  req->cqe.done = sswap_rdma_read_done_syn;
  req->len = PAGE_SIZE;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);

  // drain_queue(q);

  sswap_rdma_wait_completion(q->cq, req);

  kmem_cache_free(req_cache, req);
  // kfree(req);
out:
  return;
}



s64 count_rdma_entry_time(struct zswap_entry *entry){
    ktime_t start, diff;
    /* 1. 获取当前时间 */
    start = ktime_get();

    test_rdma_entry_page(entry);

    /* 2. 计算时间差，单位纳秒 */
    diff = ktime_sub(ktime_get(), start);
    // printk("2diff time = %lldns\n", ktime_to_ns(diff));
    return ktime_to_ns(diff);
}



void log_rdma_time(struct zswap_entry *entry){
  s64 time;
  int sample_times;
  
  sample_times = atomic_read(&rdma_time_history.sample_times);
  if(atomic_read(&rdma_time_history.count) % 100 == 0){
    atomic_set(&rdma_time_history.count, 0);
    atomic_set(&rdma_time_history.sample_count, 0);
    atomic64_set(&rdma_time_history.total_time, 0);
  }

  if(atomic_read(&rdma_time_history.count) < 10){
    time = count_rdma_entry_time(entry);
    atomic64_set(&rdma_time_history.total_time, atomic64_read(&rdma_time_history.total_time) + time);
  }

  if(atomic_read(&rdma_time_history.count) == 9){
    atomic64_set(&rdma_time_history.average_time, atomic64_read(&rdma_time_history.total_time) / sample_times);
    // pr_info("rdma sample time: %ld", atomic64_read(&rdma_time_history.average_time));
  }
  atomic_inc(&rdma_time_history.count);
}


/*********************************
* lzo decompress functions
**********************************/

static void decompress_rdma_read_lzo(struct rdma_req *req){
  u16 crc_r, crc_r_decompress;
  void *dst;
  int ret;
  size_t page_len = PAGE_SIZE;

  dst = kmap_atomic(req->page);
  crc_r = crc16(0x0000 ,req->src, req->len);

  // pr_info("--> jump tp decompress_buf_read_alloc_free()");

  //判断是否压缩
  if(req->len == 4096){
    if(req->crc_uncompress != crc_r){
      pr_err("[!!!] uncompress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), req->roffset, req->crc_uncompress, crc_r);
      goto out;
    }
    memcpy(dst, req->src, req->len);
    // pr_info("[done] uncompress cpuid: %d offset: %llx crc: %hx",smp_processor_id(), req->roffset, crc_r);
  }
  else{
    if(req->crc_compress != crc_r){
      pr_err("[!!!] compress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), req->roffset, req->crc_compress, crc_r);
      goto out;
    }
      
    // decompress_ret = crypto_comp_decompress(tfm, req->src, req->len, dst, &slen);
    
    ret = lzo1x_decompress_safe(req->src, req->len, dst, &page_len); 


    if(ret != 0){
      pr_err("[done back] decompress wrong!!! ret: %d", ret);
      goto out;
    }
    crc_r_decompress = crc16(0x0000, dst, page_len);
    // pr_info("[*read done] decompress cpuid: %d offset: %llx len: %zu --> %zu ret: %d", smp_processor_id(), req->roffset, req->len, page_len, ret);
    // pr_info("[----------] crc: %hx --> %hx | %hx --> %hx", req->crc_uncompress, req->crc_compress, crc_r, crc_r_decompress);
  }
out:
  kunmap_atomic(dst);
  // kfree(req->src);//先不释放
  // pr_info("<-- jump back");
}


/*********************************
* rb tree functions 
**********************************/
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
		// entry->refcount++;//用于设置refcount++

	return entry;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
//TODO 使用了refcount 最后也没有使用
// static void zswap_entry_put(struct zswap_tree *tree, 
// 			struct zswap_entry *entry)
// {
// 	// int refcount = --entry->refcount;
// 	// BUG_ON(refcount < 0);
// 	// if (refcount == 0) {
// 	// 	zswap_rb_erase(&tree->rbroot, entry);
// 	// 	zswap_free_entry(entry);
// 	// }
//   zswap_rb_erase(&tree->rbroot, entry);
//   kfree(entry);
// }
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
    atomic_dec(&zswap_stored_pages);
  }
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees = NULL;
}


void init_rbtree(void){
  struct zswap_tree *tree;//
  // int i;

  tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);//为swap(rb) tree分配空间,包含一个rbroot和lock

  if (!tree) {
    pr_err("alloc failed, zswap disabled for swap type \n");
    BUG();
    return;
  }

  tree->rbroot = RB_ROOT;//为NULL #define RB_ROOT	(struct rb_root) { NULL, }
  spin_lock_init(&tree->lock);
  zswap_trees = tree;
}

static void sswap_rdma_addone(struct ib_device *dev)
{
  pr_info("sswap_rdma_addone() = %s\n", dev->name);
}

static void sswap_rdma_removeone(struct ib_device *ib_device, void *client_data)
{
  pr_info("sswap_rdma_removeone()\n");
}

static struct ib_client sswap_rdma_ib_client = {
  .name   = "sswap_rdma",
  .add    = sswap_rdma_addone,
  .remove = sswap_rdma_removeone
};

static struct sswap_rdma_dev *sswap_rdma_get_device(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;

  if (!q->ctrl->rdev) {
    rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
    if (!rdev) {
      pr_err("no memory\n");
      goto out_err;
    }

    rdev->dev = q->cm_id->device;

    pr_info("selecting device %s\n", rdev->dev->name);

    rdev->pd = ib_alloc_pd(rdev->dev, 0);
    if (IS_ERR(rdev->pd)) {
      pr_err("ib_alloc_pd\n");
      goto out_free_dev;
    }

    if (!(rdev->dev->attrs.device_cap_flags &
          IB_DEVICE_MEM_MGT_EXTENSIONS)) {
      pr_err("memory registrations not supported\n");
      goto out_free_pd;
    }

    q->ctrl->rdev = rdev;
  }

  return q->ctrl->rdev;

out_free_pd:
  ib_dealloc_pd(rdev->pd);
out_free_dev:
  kfree(rdev);
out_err:
  return NULL;
}

static void sswap_rdma_qp_event(struct ib_event *e, void *c)
{
  pr_info("sswap_rdma_qp_event\n");
}

static int sswap_rdma_create_qp(struct rdma_queue *queue)
{
  struct sswap_rdma_dev *rdev = queue->ctrl->rdev;
  struct ib_qp_init_attr init_attr;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  memset(&init_attr, 0, sizeof(init_attr));
  init_attr.event_handler = sswap_rdma_qp_event;
  init_attr.cap.max_send_wr = QP_MAX_SEND_WR;
  init_attr.cap.max_recv_wr = QP_MAX_RECV_WR;
  init_attr.cap.max_recv_sge = 1;
  init_attr.cap.max_send_sge = 1;
  init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
  init_attr.qp_type = IB_QPT_RC;
  init_attr.send_cq = queue->cq;
  init_attr.recv_cq = queue->cq;
  /* just to check if we are compiling against the right headers */
  init_attr.create_flags = IB_QP_EXP_CREATE_ATOMIC_BE_REPLY & 0;

  ret = rdma_create_qp(queue->cm_id, rdev->pd, &init_attr);
  if (ret) {
    pr_err("rdma_create_qp failed: %d\n", ret);
    return ret;
  }

  queue->qp = queue->cm_id->qp;
  return ret;
}

static void sswap_rdma_destroy_queue_ib(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev;
  struct ib_device *ibdev;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = q->ctrl->rdev;
  ibdev = rdev->dev;
  //rdma_destroy_qp(q->ctrl->cm_id);
  ib_free_cq(q->cq);
}

static int sswap_rdma_create_queue_ib(struct rdma_queue *q)
{
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  int ret;
  int comp_vector = 0;

  pr_info("start: %s\n", __FUNCTION__);

  if (q->qp_type == QP_READ_ASYNC)
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_SOFTIRQ);
  else
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_DIRECT);

  if (IS_ERR(q->cq)) {
    ret = PTR_ERR(q->cq);
    goto out_err;
  }

  ret = sswap_rdma_create_qp(q);
  if (ret)
    goto out_destroy_ib_cq;

  return 0;

out_destroy_ib_cq:
  ib_free_cq(q->cq);
out_err:
  return ret;
}

static int sswap_rdma_addr_resolved(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = sswap_rdma_get_device(q);
  if (!rdev) {
    pr_err("no device found\n");
    return -ENODEV;
  }

  ret = sswap_rdma_create_queue_ib(q);
  if (ret) {
    return ret;
  }

  ret = rdma_resolve_route(q->cm_id, CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_route failed\n");
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_route_resolved(struct rdma_queue *q,
    struct rdma_conn_param *conn_params)
{
  struct rdma_conn_param param = {};
  int ret;

  param.qp_num = q->qp->qp_num;
  param.flow_control = 1;
  param.responder_resources = 16;
  param.initiator_depth = 16;
  param.retry_count = 7;
  param.rnr_retry_count = 7;
  param.private_data = NULL;
  param.private_data_len = 0;

  pr_info("max_qp_rd_atom=%d max_qp_init_rd_atom=%d\n",
      q->ctrl->rdev->dev->attrs.max_qp_rd_atom,
      q->ctrl->rdev->dev->attrs.max_qp_init_rd_atom);

  ret = rdma_connect(q->cm_id, &param);
  if (ret) {
    pr_err("rdma_connect failed (%d)\n", ret);
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_conn_established(struct rdma_queue *q)
{
  pr_info("connection established\n");
  return 0;
}

static int sswap_rdma_cm_handler(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *ev)
{
  struct rdma_queue *queue = cm_id->context;
  int cm_error = 0;

  pr_info("cm_handler msg: %s (%d) status %d id %p\n", rdma_event_msg(ev->event),
    ev->event, ev->status, cm_id);

  switch (ev->event) {
  case RDMA_CM_EVENT_ADDR_RESOLVED:
    cm_error = sswap_rdma_addr_resolved(queue);
    break;
  case RDMA_CM_EVENT_ROUTE_RESOLVED:
    cm_error = sswap_rdma_route_resolved(queue, &ev->param.conn);
    break;
  case RDMA_CM_EVENT_ESTABLISHED:
    queue->cm_error = sswap_rdma_conn_established(queue);
    /* complete cm_done regardless of success/failure */
    complete(&queue->cm_done);
    return 0;
  case RDMA_CM_EVENT_REJECTED:
    pr_err("connection rejected\n");
    break;
  case RDMA_CM_EVENT_ADDR_ERROR:
  case RDMA_CM_EVENT_ROUTE_ERROR:
  case RDMA_CM_EVENT_CONNECT_ERROR:
  case RDMA_CM_EVENT_UNREACHABLE:
    pr_err("CM error event %d\n", ev->event);
    cm_error = -ECONNRESET;
    break;
  case RDMA_CM_EVENT_DISCONNECTED:
  case RDMA_CM_EVENT_ADDR_CHANGE:
  case RDMA_CM_EVENT_TIMEWAIT_EXIT:
    pr_err("CM connection closed %d\n", ev->event);
    break;
  case RDMA_CM_EVENT_DEVICE_REMOVAL:
    /* device removal is handled via the ib_client API */
    break;
  default:
    pr_err("CM unexpected event: %d\n", ev->event);
    break;
  }

  if (cm_error) {
    queue->cm_error = cm_error;
    complete(&queue->cm_done);
  }

  return 0;
}

inline static int sswap_rdma_wait_for_cm(struct rdma_queue *queue)
{
  wait_for_completion_interruptible_timeout(&queue->cm_done,
    msecs_to_jiffies(CONNECTION_TIMEOUT_MS) + 1);
  return queue->cm_error;
}

static int sswap_rdma_init_queue(struct sswap_rdma_ctrl *ctrl,
    int idx)
{
  struct rdma_queue *queue;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  queue = &ctrl->queues[idx];
  queue->ctrl = ctrl;
  init_completion(&queue->cm_done);
  atomic_set(&queue->pending, 0);
  spin_lock_init(&queue->cq_lock);
  queue->qp_type = get_queue_type(idx);

  queue->cm_id = rdma_create_id(&init_net, sswap_rdma_cm_handler, queue,
      RDMA_PS_TCP, IB_QPT_RC);
  if (IS_ERR(queue->cm_id)) {
    pr_err("failed to create cm id: %ld\n", PTR_ERR(queue->cm_id));
    return -ENODEV;
  }

  queue->cm_error = -ETIMEDOUT;

  ret = rdma_resolve_addr(queue->cm_id, &ctrl->srcaddr, &ctrl->addr,
      CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_addr failed: %d\n", ret);
    goto out_destroy_cm_id;
  }

  ret = sswap_rdma_wait_for_cm(queue);
  if (ret) {
    pr_err("sswap_rdma_wait_for_cm failed\n");
    goto out_destroy_cm_id;
  }

  return 0;

out_destroy_cm_id:
  rdma_destroy_id(queue->cm_id);
  return ret;
}

static void sswap_rdma_stop_queue(struct rdma_queue *q)
{
  rdma_disconnect(q->cm_id);
}

static void sswap_rdma_free_queue(struct rdma_queue *q)
{
  rdma_destroy_qp(q->cm_id);
  ib_free_cq(q->cq);
  rdma_destroy_id(q->cm_id);
}

static int sswap_rdma_init_queues(struct sswap_rdma_ctrl *ctrl)
{
  int ret, i;
  for (i = 0; i < numqueues; ++i) {
    ret = sswap_rdma_init_queue(ctrl, i);
    if (ret) {
      pr_err("failed to initialized queue: %d\n", i);
      goto out_free_queues;
    }
  }

  return 0;

out_free_queues:
  for (i--; i >= 0; i--) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }

  return ret;
}

static void sswap_rdma_stopandfree_queues(struct sswap_rdma_ctrl *ctrl)
{
  int i;
  for (i = 0; i < numqueues; ++i) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }
}

static int sswap_rdma_parse_ipaddr(struct sockaddr_in *saddr, char *ip)
{
  u8 *addr = (u8 *)&saddr->sin_addr.s_addr;
  size_t buflen = strlen(ip);

  pr_info("start: %s\n", __FUNCTION__);

  if (buflen > INET_ADDRSTRLEN)
    return -EINVAL;
  if (in4_pton(ip, buflen, addr, '\0', NULL) == 0)
    return -EINVAL;
  saddr->sin_family = AF_INET;
  return 0;
}

static int sswap_rdma_create_ctrl(struct sswap_rdma_ctrl **c)
{
  int ret;
  struct sswap_rdma_ctrl *ctrl;
  pr_info("will try to connect to %s:%d\n", serverip, serverport);

  *c = kzalloc(sizeof(struct sswap_rdma_ctrl), GFP_KERNEL);
  if (!*c) {
    pr_err("no mem for ctrl\n");
    return -ENOMEM;
  }
  ctrl = *c;

  ctrl->queues = kzalloc(sizeof(struct rdma_queue) * numqueues, GFP_KERNEL);
  ret = sswap_rdma_parse_ipaddr(&(ctrl->addr_in), serverip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  ctrl->addr_in.sin_port = cpu_to_be16(serverport);

  ret = sswap_rdma_parse_ipaddr(&(ctrl->srcaddr_in), clientip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  /* no need to set the port on the srcaddr */

  return sswap_rdma_init_queues(ctrl);
}




static void sswap_rdma_write_done_compress(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  // size_t page_len = PAGE_SIZE;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  // ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);// 修改接口后这里 req->dma 是page kmap到的内核虚拟地址 
  ib_dma_unmap_single(ibdev, req->dma, req->len, DMA_TO_DEVICE);

  // pr_info("[write done] cpuid: %d offset: %llx len: %zu --> %zu crc: %hx --> %hx", smp_processor_id(), req->roffset, page_len, req->len, req->crc_uncompress, req->crc_compress);

  complete(&req->done);//添加写同步


  atomic_dec(&q->pending);
  kfree(req->src);//释放write buf
  kmem_cache_free(req_cache, req);
  // kfree(req);
}

static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_FROM_DEVICE);

  SetPageUptodate(req->page);
  unlock_page(req->page);
  complete(&req->done);
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
  // kfree(req);
}

static void sswap_rdma_read_done_syn(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_FROM_DEVICE);

  SetPageUptodate(req->page);
  unlock_page(req->page);
  complete(&req->done);
  atomic_dec(&q->pending);
}


static void sswap_rdma_read_done_compress(struct ib_cq *cq, struct ib_wc *wc) {
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;



  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_single(ibdev, req->dma, req->len, DMA_FROM_DEVICE);
  decompress_rdma_read_lzo(req);


  complete(&req->done);
  atomic_dec(&q->pending);
  
  SetPageUptodate(req->page);//
  unlock_page(req->page);//
  kfree(req->src);//
  kmem_cache_free(req_cache, req);//
  // kfree(req);
}



inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 roffset, enum ib_wr_opcode op)
{
  const struct ib_send_wr *bad_wr;
  struct ib_rdma_wr rdma_wr = {};
  int ret;

  BUG_ON(qe->dma == 0);

  sge->addr = qe->dma;
  // sge->length = PAGE_SIZE;
  sge->length = qe->len;//按照rdma_req设置长度
  sge->lkey = q->ctrl->rdev->pd->local_dma_lkey;

  /* TODO: add a chain of WR, we already have a list so should be easy
   * to just post requests in batches */
  rdma_wr.wr.next    = NULL;
  rdma_wr.wr.wr_cqe  = &qe->cqe;
  rdma_wr.wr.sg_list = sge;
  rdma_wr.wr.num_sge = 1;
  rdma_wr.wr.opcode  = op;
  rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
  rdma_wr.remote_addr = q->ctrl->servermr.baseaddr + roffset;
  rdma_wr.rkey = q->ctrl->servermr.key;

  atomic_inc(&q->pending);
  ret = ib_post_send(q->qp, &rdma_wr.wr, &bad_wr);
  if (unlikely(ret)) {
    pr_err("ib_post_send failed: %d\n", ret);
  }

  return ret;
}

static void sswap_rdma_recv_remotemr_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *qe =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct sswap_rdma_ctrl *ctrl = q->ctrl;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_recv_done status is not success\n");
    return;
  }
  ib_dma_unmap_single(ibdev, qe->dma, sizeof(struct sswap_rdma_memregion),
		      DMA_FROM_DEVICE);
  pr_info("servermr baseaddr=%llx, key=%u\n", ctrl->servermr.baseaddr,
	  ctrl->servermr.key);
  complete_all(&qe->done);
}

static int sswap_rdma_post_recv(struct rdma_queue *q, struct rdma_req *qe,
  size_t bufsize)
{
  const struct ib_recv_wr *bad_wr;
  struct ib_recv_wr wr = {};
  struct ib_sge sge;
  int ret;

  sge.addr = qe->dma;
  sge.length = bufsize;
  sge.lkey = q->ctrl->rdev->pd->local_dma_lkey;

  wr.next    = NULL;
  wr.wr_cqe  = &qe->cqe;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  ret = ib_post_recv(q->qp, &wr, &bad_wr);
  if (ret) {
    pr_err("ib_post_recv failed: %d\n", ret);
  }
  return ret;
}

/* allocates a sswap rdma request, creates a dma mapping for it in
 * req->dma, and synchronizes the dma mapping in the direction of
 * the dma map.
 * Don't touch the page with cpu after creating the request for it!
 * Deallocates the request if there was an error */
inline static int get_req_for_page(struct rdma_req **req, struct ib_device *dev,
				struct page *page, enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  // *req = kmalloc(sizeof(struct rdma_req), GFP_KERNEL);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  (*req)->page = page;
  init_completion(&(*req)->done);

  (*req)->dma = ib_dma_map_page(dev, page, 0, PAGE_SIZE, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    // kfree(req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, PAGE_SIZE, dir);
out:
  return ret;
}

/* the buffer needs to come from kernel (not high memory) */
inline static int get_req_for_buf(struct rdma_req **req, struct ib_device *dev,
				void *buf, size_t size,
				enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  // *req = kmalloc(sizeof(struct rdma_req), GFP_KERNEL);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  init_completion(&(*req)->done);//+++++

  (*req)->dma = ib_dma_map_single(dev, buf, size, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    // kfree(req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, size, dir);
out:
  return ret;
}

inline static void sswap_rdma_wait_completion(struct ib_cq *cq,
					      struct rdma_req *qe)
{
  ndelay(1000);
  while (!completion_done(&qe->done)) {
    ndelay(250);
    ib_process_cq_direct(cq, 1);
  }
}

/* polls queue until we reach target completed wrs or qp is empty */
static inline int poll_target(struct rdma_queue *q, int target)
{
  unsigned long flags;
  int completed = 0;

  while (completed < target && atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    completed += ib_process_cq_direct(q->cq, target - completed);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return completed;
}

static inline int drain_queue(struct rdma_queue *q)
{
  unsigned long flags;

  while (atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    ib_process_cq_direct(q->cq, 16);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return 1;
}



// static inline int rdma_write_queue_add_compress(struct rdma_queue *q, struct page *page,
// 				  u64 roffset)
// {
//   struct rdma_req *req;
//   struct ib_device *dev = q->ctrl->rdev->dev;
//   struct ib_sge sge = {};
//   int ret, inflight;
//   void *src;
//   size_t page_len = PAGE_SIZE, wlen;
//   void *buf_write, *compress_buf = NULL, *uncompress_buf = NULL;
//   u16 crc_uncompress, crc_compress;

//   struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
//   struct zswap_entry *entry = NULL, *dupentry;

//   void *wrkmem;
//   entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL); //申请插入rbtree 的swap entry
//   if(entry == NULL){
//     pr_err("kmalloc wrong!!!");
//     BUG();
//   }
//   wrkmem = kmalloc(LZO1X_1_MEM_COMPRESS, GFP_KERNEL);


//   while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
//     BUG_ON(inflight > QP_MAX_SEND_WR);
//     poll_target(q, 2048);
//     pr_info_ratelimited("back pressure writes");
//   }

//   src = kmap_atomic(page);
//   uncompress_buf = kmalloc(page_len, GFP_KERNEL);//作未压缩page内容的rdma写buf
//   if(uncompress_buf == NULL){
//     pr_err("kmalloc wrong!!!");
//     BUG();
//   }
//   compress_buf = kmalloc(2 *  page_len, GFP_KERNEL);//压缩目的地址
//   if(compress_buf == NULL){
//     pr_err("kmalloc wrong!!!");
//     BUG();
//   }
//   crc_uncompress = crc16(0x0000, src, page_len);

//   //******** 压缩 **************
//   ret = lzo1x_1_compress(src, page_len, compress_buf, &wlen, wrkmem);

//   if(wlen >= 4096){//不能压缩 使用原page
//     crc_compress = crc_uncompress;//不能压缩crc_compress使用crc_uncompress
//     kfree(compress_buf);
//     memcpy(uncompress_buf, src, PAGE_SIZE);//uncompress_buf必须done之后才能释放 所以不能使用src
//     buf_write = uncompress_buf;
//     wlen = page_len;
//     entry->compressed = false;
//   }
//   else{//能压缩 使用压缩后数据
//     crc_compress = crc16(0x0000, compress_buf, wlen);
//     kfree(uncompress_buf);
//     buf_write = compress_buf;
//     entry->compressed = true;
//   }
//   kunmap_atomic(src);

// //   pr_info("[write] cpuid: %d offset: %llx len: %zu --> %zu crc: %hx --> %hx ret: %d", smp_processor_id(), roffset, page_len, wlen, crc_uncompress, crc_compress, ret);

//   ret = get_req_for_buf(&req, dev, buf_write, wlen, DMA_TO_DEVICE);//设置req中地址dma 长度len

//   if (unlikely(ret))
//     return ret;
//   req->len = wlen;//+++ 用于post请求设置sge
//   req->src = buf_write;
//   req->crc_compress = crc_compress;
//   req->crc_uncompress = crc_uncompress;
//   req->roffset = roffset;
//   req->cqe.done = sswap_rdma_write_done_compress;//添加同步操作
//   ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);

//   // sswap_rdma_wait_completion(q->cq, req);//+++++++同步 等待写完成

//   //TODO 这里可能有问题 rb tree插入在post请求之后执行 可能存在写未完成 rb tree已经插入 导致读的时候rb tree可以找到entry 但是write还处于inflight状态
//   //  但是应该问题不大 因为不在done中unlock page应该不会发起读请求
//   //******** 插入rb tree **************

//   RB_CLEAR_NODE(&entry->rbnode);
//   entry->offset = req->roffset;
//   entry->length = req->len;
//   entry->crc_compress = req->crc_compress;//+++ 用于读校验
//   entry->crc_uncompress = req->crc_uncompress;//+++ 用于读校验

//   spin_lock(&tree->lock);
// 	do {
// 		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
// 		if (ret == -EEXIST) {//重复的entry 应该删除重复的entry(dupentry)
//       // pr_info("[write_duplicate] offset: %lx", entry->offset);
// 			// zswap_duplicate_entry++;
// 			/* remove from rbtree */
// 			zswap_rb_erase(&tree->rbroot, dupentry);
//       kfree(dupentry);//释放entry
// 			// zswap_entry_put(tree, dupentry)
// 		}
// 	} while (ret == -EEXIST);
//   spin_unlock(&tree->lock);

//   kfree(wrkmem);
//   return ret;
// }


int dram_read_compress(struct rdma_queue *q, struct page *page, u64 roffset, struct zswap_entry *entry){
  void *page_vaddr, *src;
  int ret = 0;
  int decompresslen;

  
	page_vaddr = kmap_atomic(page);
  src = drambuf + roffset;

  if(entry->length == PAGE_SIZE){
    memcpy(page_vaddr, src, PAGE_SIZE);
  } else {
    decompresslen =  LZ4_decompress_safe(src, page_vaddr, entry->length, PAGE_SIZE);
    // ret = lzo1x_decompress_safe(src, entry->length, page_vaddr, &page_len); 
    if(decompresslen != PAGE_SIZE){
      pr_info("decompress wrong !");
    }
  }

	kunmap_atomic(page_vaddr);

  //******** 更新 + unlock page **************
  SetPageUptodate(page);
  unlock_page(page);

  return ret;
}


int dram_read(struct rdma_queue *q, struct page *page, u64 roffset){
  void *page_vaddr;

	page_vaddr = kmap_atomic(page);
	copy_page(page_vaddr, (void *) (drambuf + roffset));
	kunmap_atomic(page_vaddr);

  //******** 更新 + unlock page **************
  SetPageUptodate(page);
  unlock_page(page);

  return 0;
}

/*********************************
* trend functions 
**********************************/



int get_prev_index(int index){
    return ((index > 0) ? (index-1) : (atomic_read(&trend_history.max_size) - 1));
}

void inc_head(void) {
    int current_head = atomic_read(&trend_history.head);
    int max_size = atomic_read(&trend_history.max_size);
    atomic_set(&trend_history.head, (( current_head + 1 ) % max_size));
}

void inc_size(void) {
    int current_size = atomic_read(&trend_history.size);
    int max_size = atomic_read(&trend_history.max_size);
    
    if(current_size < max_size) 
        atomic_inc(&trend_history.size);
}


void init_swap_trend(int size) {
	//设置trend表大小为32 init_swap_trend(32)
	trend_history.history = (struct swap_entry *) kzalloc(size * sizeof(struct swap_entry), GFP_KERNEL);
	atomic_set(&trend_history.head, 0);
	atomic_set(&trend_history.size, 0);
	atomic_set(&trend_history.max_size , size);
	
	// init_stat();
	printk("swap_trend history initiated for size: %d, head at: %d, curresnt_size: %d\n", atomic_read(&trend_history.max_size), atomic_read(&trend_history.head), atomic_read(&trend_history.size));
}

void log_swap_trend(unsigned long offset) {
	
	long offset_delta;
	int prev_index;
	struct swap_entry se;
	if(atomic_read(&trend_history.size)) {
		prev_index = get_prev_index(atomic_read(&trend_history.head));
		offset_delta = offset - trend_history.history[prev_index].offset;
		
		//printk("prev_index:%ld, offset_delta:%ld\n", prev_index, offset_delta);
		
		se.delta = offset_delta;
		se.offset = offset;
	}
	else {//第一个entry没有prev
	    se.delta = 0;
	    se.offset = offset;
	}
	//循环链表 最大为 trend_history.max_size head为新插入新元素
	trend_history.history[atomic_read(&trend_history.head)] = se;
	inc_head();
	inc_size();//最大到maxsize
}

int find_trend_in_region(int size, long *major_delta, int *major_count) {
    int maj_index = get_prev_index(atomic_read(&trend_history.head)), count, i, j;
    long candidate;
    
    for (i = get_prev_index(maj_index), j = 1, count = 1; j < size; i = get_prev_index(i), j++) {
        if (trend_history.history[maj_index].delta == trend_history.history[i].delta)
            count++;
        else
            count--;
        if (count == 0) {
            maj_index = i;
            count = 1;
        }
    }
    
    candidate = trend_history.history[maj_index].delta;
    for (i = get_prev_index(atomic_read(&trend_history.head)), j = 0, count = 0; j < size; i = get_prev_index(i), j++) {
        if(trend_history.history[i].delta == candidate)
            count++;
    }
    
    //printk("majority index: %d, candidate: %ld, count:%d\n", maj_index, candidate, count);
    *major_delta = candidate;
    *major_count = count;
    return count > (size/2);//计数是否大于一半
}

int find_trend (int *depth, long *major_delta, int *major_count) {
    int has_trend = 0, size = (int) atomic_read(&trend_history.max_size)/4, max_size;
	max_size = size * 4;
	
	while(has_trend == 0 && size <= max_size) {
		//1/4 1/2 1
		has_trend = find_trend_in_region(size, major_delta, major_count);
		//printk( "at size: %d, trend found? %s\n", size, (has_trend == 0) ? "false" : "true" );
		size *= 2;
	}
	*depth = size;
	return has_trend;
}




/*********************************
* prefetch buffer functions
**********************************/

// 32MB
// unsigned long buffer_size = 8000;//32MB
// unsigned long buffer_size = 50000;//200MB
unsigned long buffer_size = 100000;//400MB
unsigned long is_prefetch_buffer_active = 0;

struct local_buf {
	atomic_t head;
	atomic_t tail;
	atomic_t size;//当前buffer的大小
	// swp_entry_t *offset_list;
	// struct page **page_data;
  struct zswap_entry **page_list;//缓存的page rbtree entry
	spinlock_t buffer_lock;
};

//local buffer （demand读 + prefetch读）
static struct local_buf local_buffer;


void activate_prefetch_buffer(unsigned long val){
    is_prefetch_buffer_active = val;
    printk("prefetch buffer: %s\n", (is_prefetch_buffer_active != 0) ? "active" : "inactive" );
}

unsigned long get_prefetch_buffer_status(void) {
    return is_prefetch_buffer_active;
}


static int get_buffer_head(void){
	return atomic_read(&local_buffer.head);
}

static int get_buffer_tail(void){
	return atomic_read(&local_buffer.tail);
}

static int get_buffer_size(void){
    return atomic_read(&local_buffer.size);
}
// head元素出栈
static void inc_buffer_head(void){
	atomic_set(&local_buffer.head, (atomic_read(&local_buffer.head) + 1) % buffer_size);
	// atomic_dec(&local_buffer.size);
	return;
}

// 在tail入栈 环形缓冲区
static void inc_buffer_tail(void){
	atomic_set(&local_buffer.tail, (atomic_read(&local_buffer.tail) + 1) % buffer_size);
	// atomic_inc(&local_buffer.size);
    	return;
}

static void inc_buffer_size(void) {
	atomic_inc(&local_buffer.size);
}

static void dec_buffer_size(void) {
        atomic_dec(&local_buffer.size);
}

static int is_buffer_full(void){
	//当前buffer 大小是否满了
	return (buffer_size <= atomic_read(&local_buffer.size));
}




//这里不是LRU缓存 简单的循环队列缓存
void add_page_to_buffer(struct zswap_entry* entry){
	int tail, head, error=0;
  struct zswap_entry* page_entry;
  // struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个

	spin_lock_irq(&local_buffer.buffer_lock);
	//buffer满了 尝试释放 head_page 
	while(is_buffer_full() && error == 0){
//		printk("%s: buffer is full for entry: %ld, head at: %d, tail at: %d\n", __func__, entry.val, get_buffer_head(), get_buffer_tail());
		head = get_buffer_head();
    
    //删除缓存 entry字段设成false
    page_entry = local_buffer.page_list[head];
    page_entry->cached = false;

    //******** 从rb tree中删除 **************
    // zswap_rb_erase(&tree->rbroot, page_entry);
    // pr_info("** delete from page list %lx", entry->offset);
		inc_buffer_head();
    dec_buffer_size();
	}
	//尾部添加page
	// local_buffer.offset_list[tail] = entry;
	// local_buffer.page_data[tail] = page;
	tail = get_buffer_tail();
  entry->cached = true;
  local_buffer.page_list[tail] = entry;
	inc_buffer_tail();
	inc_buffer_size();//增加buffer大小
	spin_unlock_irq(&local_buffer.buffer_lock);  
}

void read_page_readahead(u64 offset){
  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry;

  int has_trend = 0, depth, major_count;
  long major_delta;
  u64 startoffset = offset;

  //******** 查rb tree得dlen **************
	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, offset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
  if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
    pr_info("rb treee not found");
    BUG();
	}
	spin_unlock(&tree->lock);//unlock
  
  //******** 当前读 **************
  add_page_to_buffer(entry);
  
  //******** prefetch **************
  has_trend = find_trend(&depth, &major_delta, &major_count);
  if(has_trend){
    int count = 0;
    int mask = major_delta == 0 ? 0 : depth/major_delta;
    // if(major_delta != 4096 && major_delta != -4096){
    //   pr_info("offset: %llu found trend begin prefetch depth: %d major_delta: %ld  major_count %d",offset, depth, major_delta, major_count);
    // }
    for(offset = startoffset + major_delta; count < mask; offset+= major_delta, count++){
      spin_lock(&tree->lock);//lock 防止数据读写冲突
      entry = zswap_entry_find_get(&tree->rbroot, offset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
      if (!entry) {
        break;;
      }
      spin_unlock(&tree->lock);//unlock
      //******** prefetch **************
      add_page_to_buffer(entry);
    }
  }
}

void prefetch_buffer_init(unsigned long _size){	
	printk("%s: initiating prefetch buffer with size %ld!\n",__func__, _size);
	if (!_size || _size <= 0) {
		printk("%s: invalid buffer size\n",__func__);
		return;
	}

	buffer_size = _size;
	//kzalloc分配内存空间
	// local_buffer.offset_list = (swp_entry_t *) kzalloc(buffer_size * sizeof(swp_entry_t), GFP_KERNEL);
	// local_buffer.page_data = (struct page **) kzalloc(buffer_size * sizeof(struct page *), GFP_KERNEL);
  local_buffer.page_list = (struct zswap_entry **) kzalloc(buffer_size * sizeof(struct zswap_entry *), GFP_KERNEL);
	atomic_set(&local_buffer.head, 0);
	atomic_set(&local_buffer.tail, 0);
	atomic_set(&local_buffer.size, 0);
	
	printk("%s: prefetch buffer initiated with size: %d, head at: %d, tail at: %d\n", __func__, get_buffer_size(), get_buffer_head(), get_buffer_tail());
	return;
}


static inline int rdma_read_page(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  // pr_info("[read] roffset: %llx", roffset);
  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }

  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->len = PAGE_SIZE;
  req->cqe.done = sswap_rdma_read_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);
  return ret;
}

int rdma_read_compress(struct rdma_queue *q, struct page *page, u64 roffset,
              struct zswap_entry *entry){
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;
  void *buf_read;

  // pr_info("[begin_read] roffset: %llx", roffset);//读输出roffset
  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }

  buf_read = kmalloc(PAGE_SIZE, GFP_KERNEL);//作为read buf
  if(buf_read == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  ret = get_req_for_buf(&req, dev, buf_read, entry->length, DMA_FROM_DEVICE);

  // ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;
  req->len = entry->length;//+++ 用于unmap
  req->roffset = roffset;//+++++
  req->page = page;//+++
  req->src = buf_read;//+++
  req->crc_compress = entry->crc_compress;//+++ 用于解压缩校验
  req->crc_uncompress = entry->crc_uncompress;//+++ 用于解压缩校验
  req->cqe.done = sswap_rdma_read_done_compress;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);
  
  // sswap_rdma_wait_completion(q->cq, req);//等待read done完成 这里解压缩移到read_done中 不需要同步

  return ret;
}

bool is_buffer_faster(void){
  if(atomic64_read(&decomrpess_time_history.average_time) <= atomic64_read(&rdma_time_history.average_time)){
    return true;
  }
  return false;
}

static inline int begin_read(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  int ret = 0;
  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry;

  //******** 查rb tree得dlen **************
	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, roffset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
  if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
    pr_info("rb treee not found");
    BUG();
		return -1;
	}
	spin_unlock(&tree->lock);//unlock
  // pr_info("found rbtree entry roffest: %lx, length: %d --> %zu crc: %hx --> %hx", entry->offset, 4096, entry->length, entry->crc_uncompress, entry->crc_compress);

  // log_decompress_time(entry);
  // log_rdma_time(entry);

  //******** 检查缓存 **************
  //1.缓存命中 2.读local buffer更快（考虑解压缩开销，相比rdma读）
  if((entry != NULL && entry->cached == true) && is_buffer_faster()){//缓存在local
    //******** dram读 **************
    // pr_info("cache hit %lx", entry->offset);
    atomic64_inc(&cachehit_pages);
    ret = dram_read_compress(q, page, roffset, entry);//rdma读请求后 接dram读
    // ret = dram_read(q, page, roffset);//rdma读请求后 接dram读
  } else {
    //******** rdma读 **************
    ret = rdma_read_page(q, page, roffset);

    //******** 同步操作 等待read done完成 再释放page **************
    // sswap_rdma_wait_completion(q->cq, req);//等待read done完成
    // kmem_cache_free(req_cache, req);//read_done中 移到在外面释放 wait_completion需要使用
  }
  //******** 记录trend **************
  log_swap_trend(roffset);
  
  //******** 添加到缓存 + prefetch **************
  read_page_readahead(roffset);

  atomic64_inc(&total_pages);
  return ret;
}

int dram_write(struct page *page, u64 roffset)
{
	void *page_vaddr;
	page_vaddr = kmap_atomic(page);


	copy_page((void *) (drambuf + roffset), page_vaddr);
	kunmap_atomic(page_vaddr);
	return 0;
}

int dram_write_compress(struct page *page, u64 roffset)
{
  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry = NULL, *dupentry;


	void *page_vaddr, *compress_buf, *src;
  void *wrkmem;
  int ret;
  size_t page_len = PAGE_SIZE, wlen;
  u16 crc_uncompress, crc_compress;

  entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL); //申请插入rbtree 的swap entry
  if(entry == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  wrkmem = kmalloc(LZO1X_1_MEM_COMPRESS, GFP_KERNEL);
	page_vaddr = kmap_atomic(page);

  crc_uncompress = crc16(0x0000, page_vaddr, page_len);

  compress_buf = kmalloc(2 * PAGE_SIZE, GFP_KERNEL);//作未压缩page内容的rdma写buf
  wlen = compress_lz4(page_vaddr, compress_buf, PAGE_SIZE, 2 * PAGE_SIZE);
  // ret = lzo1x_1_compress(page_vaddr, page_len, compress_buf, &wlen, wrkmem);

  if(wlen >= 4096){//不能压缩 使用原page
    crc_compress = crc_uncompress;//不能压缩crc_compress使用crc_uncompress
    src = page_vaddr;
    wlen = page_len;
    entry->compressed = false;
  }
  else{//能压缩 使用压缩后数据
    crc_compress = crc16(0x0000, compress_buf, wlen);
    src = compress_buf;
    entry->compressed = true;
  }

	// copy_page((void *) (drambuf + roffset), page_vaddr);
  memcpy((void *) (drambuf + roffset), src, wlen);

	kunmap_atomic(page_vaddr);
  kfree(wrkmem);
  kfree(compress_buf);

  //******** 插入rb tree **************

  RB_CLEAR_NODE(&entry->rbnode);
  entry->offset = roffset;
  entry->length = wlen;
  entry->crc_compress = crc_compress;//+++ 用于读校验
  entry->crc_uncompress = crc_uncompress;//+++ 用于读校验
  // entry->compressed = true;

  spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {//重复的entry 应该删除重复的entry(dupentry)
      // pr_info("[write_duplicate] offset: %lx", entry->offset);
			// zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
      kfree(dupentry);//释放entry
			// zswap_entry_put(tree, dupentry)
		}
	} while (ret == -EEXIST);
  spin_unlock(&tree->lock);

  //******** 加入local buffer **************
  add_page_to_buffer(entry);

	return ret;
}

static void sswap_rdma_write_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);

  complete(&req->done);//++++ 保证写完成再读

  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
  // kfree(req);
}

static inline int rdma_write_page(struct rdma_queue *q, struct page *page,
				  u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }

  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->cqe.done = sswap_rdma_write_done;
  req->len = PAGE_SIZE;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);

  return ret;
}

static inline int begin_write(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  int ret;
  //******** rdma写 **************
  ret = rdma_write_page(q, page, roffset);
  BUG_ON(ret);
  drain_queue(q);

  //******** dram写 **************
  ret = dram_write_compress(page, roffset);//写缓存 + 插入rbtree
  return ret;
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);
  ret = begin_write(q, page, roffset);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_write);

static int sswap_rdma_recv_remotemr(struct sswap_rdma_ctrl *ctrl)
{
  struct rdma_req *qe;
  int ret;
  struct ib_device *dev;

  pr_info("start: %s\n", __FUNCTION__);
  dev = ctrl->rdev->dev;

  ret = get_req_for_buf(&qe, dev, &(ctrl->servermr), sizeof(ctrl->servermr),
			DMA_FROM_DEVICE);
  if (unlikely(ret))
    goto out;

  qe->cqe.done = sswap_rdma_recv_remotemr_done;

  ret = sswap_rdma_post_recv(&(ctrl->queues[0]), qe, sizeof(struct sswap_rdma_memregion));

  if (unlikely(ret))
    goto out_free_qe;

  /* this delay doesn't really matter, only happens once */
  sswap_rdma_wait_completion(ctrl->queues[0].cq, qe);

out_free_qe:
  kmem_cache_free(req_cache, qe);
  // kfree(qe);
out:
  return ret;
}

/* page is unlocked when the wr is done.
 * posts an RDMA read on this cpu's qp */
int sswap_rdma_read_async(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_poll_load(int cpu)
{
  struct rdma_queue *q = sswap_rdma_get_queue(cpu, QP_READ_SYNC);
  return drain_queue(q);
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

/* idx is absolute id (i.e. > than number of cpus) */
inline enum qp_type get_queue_type(unsigned int idx)
{
  // numcpus = 8
  if (idx < numcpus)
    return QP_READ_SYNC;
  else if (idx < numcpus * 2)
    return QP_READ_ASYNC;
  else if (idx < numcpus * 3)
    return QP_WRITE_SYNC;

  BUG();
  return QP_READ_SYNC;
}

inline struct rdma_queue *sswap_rdma_get_queue(unsigned int cpuid,
					       enum qp_type type)
{
  BUG_ON(gctrl == NULL);

  switch (type) {
    case QP_READ_SYNC:
      return &gctrl->queues[cpuid];
    case QP_READ_ASYNC:
      return &gctrl->queues[cpuid + numcpus];
    case QP_WRITE_SYNC:
      return &gctrl->queues[cpuid + numcpus * 2];
    default:
      BUG();
  };
}

static int __init sswap_rdma_init_module(void)
{
  int ret;

  pr_info("start: %s\n", __FUNCTION__);
  pr_info("* RDMA BACKEND *");

  // modified by ysjing
  // numcpus = num_online_cpus()
  numqueues = numcpus * 3;

  req_cache = kmem_cache_create("sswap_req_cache", sizeof(struct rdma_req), 0,
                      SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);

  if (!req_cache) {
    pr_err("no memory for cache allocation\n");
    return -ENOMEM;
  }

  ib_register_client(&sswap_rdma_ib_client);
  ret = sswap_rdma_create_ctrl(&gctrl);
  if (ret) {
    pr_err("could not create ctrl\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  ret = sswap_rdma_recv_remotemr(gctrl);
  if (ret) {
    pr_err("could not setup remote memory region\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  init_rbtree();


  //******** 申请dram内存 **************
  drambuf = vzalloc(REMOTE_BUF_SIZE);//30GB
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

  //******** 初始化缓存 **************
  prefetch_buffer_init(buffer_size);
//******** 初始化trend history **************
  init_swap_trend(32);
//******** 初始化decomrpess time history **************
  //100次 采样10次
  init_decomrpess_time_history(10);

  init_rdma_time_history(10);

  init_example_compressed_data();

  pr_info("ctrl is ready for reqs\n");
  return 0;
}


static void __exit sswap_rdma_cleanup_module(void)
{
  pr_info("rdma sample time: %ld", atomic64_read(&rdma_time_history.average_time));
  pr_info("decompress sample time: %ld", atomic64_read(&decomrpess_time_history.average_time));
  pr_info("[cache] total: %ld  cache hit: %ld", atomic64_read(&total_pages),  atomic64_read(&cachehit_pages));
  pr_info("[trend] head: %d size: %d maxsize: %d", atomic_read(&trend_history.head), atomic_read(&trend_history.size), atomic_read(&trend_history.max_size));
  pr_info("[prefetch buf] head: %d tail: %d size: %d", atomic_read(&local_buffer.head), atomic_read(&local_buffer.tail), atomic_read(&local_buffer.size));
  
  sswap_rdma_stopandfree_queues(gctrl);
  ib_unregister_client(&sswap_rdma_ib_client);
  kfree(gctrl);
  gctrl = NULL;
  if (req_cache) {
    kmem_cache_destroy(req_cache);
  }
  zswap_frontswap_invalidate_area();
  //drambuf 和 缓存list
  vfree(drambuf);

  //******** 释放free_prefetchbuf和trend_history **************
  pr_info("free trend history");
  kfree(trend_history.history);
  pr_info("free prefetch buffer");
  kfree(local_buffer.page_list);//其中entry为rbtree entry已经释放

  destroy_example_compressed_data();


  pr_info("fsswap_rdma_cleanup_module");
}

module_init(sswap_rdma_init_module);
module_exit(sswap_rdma_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experiments");
