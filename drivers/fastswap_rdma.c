#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "fastswap_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h>

#include <linux/rbtree.h>
#include <linux/crypto.h>
// #include <rdma/ib_verbs.h>


#define ONLINE_CPU 20
struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;
	unsigned int length;
	// struct zswap_pool *pool;
	// unsigned long handle;
};

struct zswap_header {
	swp_entry_t swpentry;
};

struct zswap_tree {//包含rb树root
	struct rb_root rbroot;
	spinlock_t lock;
};

static atomic_t zswap_stored_pages = ATOMIC_INIT(0);//存到页面数量

static struct zswap_tree *zswap_trees;//rb tree数组,只一个swap area,申请一个

u8* zswap_dstmem[ONLINE_CPU];//用于缓存压缩后数据,每cpu分配一个

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
module_param_named(nc, numcpus, int, 0644);

module_param_string(sip, serverip, INET_ADDRSTRLEN, 0644);
module_param_string(cip, clientip, INET_ADDRSTRLEN, 0644);

// todo: destroy ctrl

#define CONNECTION_TIMEOUT_MS 60000
#define QP_QUEUE_DEPTH 256
/* we don't really use recv wrs, so any small number should do */
#define QP_MAX_RECV_WR 4
/* we mainly do send wrs */
#define QP_MAX_SEND_WR	(4096)
#define CQ_NUM_CQES	(QP_MAX_SEND_WR)
#define POLL_BATCH_HIGH (QP_MAX_SEND_WR / 4)

static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,//如果rb树上发现重复的entry,dupenry指向重复的entry
			struct zswap_entry **dupentry)
{//
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
	// 	zswap_entry_get(entry);//用于设置refcount++

	return entry;
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
    atomic_dec(&zswap_stored_pages);
  }
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees = NULL;
}

// static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
// {
// 	if (!RB_EMPTY_NODE(&entry->rbnode)) {
// 		rb_erase(&entry->rbnode, root);
// 		RB_CLEAR_NODE(&entry->rbnode);
// 	}
// }

// static void zswap_entry_put(struct zswap_tree *tree,
// 			struct zswap_entry *entry)
// {
// 	int refcount = --entry->refcount;

// 	BUG_ON(refcount < 0);
// 	if (refcount == 0) {
// 		zswap_rb_erase(&tree->rbroot, entry);
// 		zswap_free_entry(entry);
// 	}
// }

// static void zswap_entry_put(struct zswap_tree *tree,
// 			struct zswap_entry *entry)
// {
// 	int refcount = --entry->refcount;

// 	BUG_ON(refcount < 0);
// 	if (refcount == 0) {
// 		zswap_rb_erase(&tree->rbroot, entry);
// 		zswap_free_entry(entry);
// 	}
// } 


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

  ret = sswap_rdma_wait_for_cm(queue);//阻塞等待cm建链完成
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

  *c = kzalloc(sizeof(struct sswap_rdma_ctrl), GFP_KERNEL);//为gctrl分配空间
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

static void __exit sswap_rdma_cleanup_module(void)
{
  int i;
  sswap_rdma_stopandfree_queues(gctrl);
  ib_unregister_client(&sswap_rdma_ib_client);
  kfree(gctrl);
  gctrl = NULL;
  if (req_cache) {
    kmem_cache_destroy(req_cache);
  }

  //释放申请压缩页面缓存区
  for(i = 0; i < ONLINE_CPU; i++){
    kfree(zswap_dstmem[i]);
  }
  pr_info("dstmem is free\n");

  //释放掉rbtree的entry
  zswap_frontswap_invalidate_area();
  pr_info("rbtree is free\n");
  pr_info("zswap_stored_pages: %d",atomic_read(&zswap_stored_pages));
  pr_info("###########################################################\
  #######################################");
  pr_info("###########################################################\
  #######################################");
    pr_info("###########################################################\
  #######################################");
}

static void sswap_rdma_write_done_compress(struct ib_cq *cq, struct ib_wc *wc)//压缩写的 req->cqe.done
{//TODO 有些不需要删除
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);//通过wc的wr_cqe 得到struct rdma_req变量的地址
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  ib_dma_unmap_page(ibdev, req->dma, req->len, DMA_TO_DEVICE);//unmap 长度(*req)->len

  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
}

static void sswap_rdma_write_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req = //得到发出rdma请求的req 从而得到应unmap的地址 req->dma
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);

  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);//写完释放
}

static void sswap_rdma_read_done_compress(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  int ret;
  void* src;
  unsigned int dlen = PAGE_SIZE;

  struct crypto_comp *tfm;
  char alg[] = "lzo";
  u8* dst;


  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);


  //这里解压缩
  src = req->src;//这里即使rdma读到的临时缓存地址 req->src = (void *)src = (u8 *)kmalloc(PAGE_SIZE, GFP_KERNEL);
  dst = kmap_atomic(req->page);//映射page到内核虚拟地址空间作为解压缩dst
  
  pr_info("[decompress] cpuid: %d roffset: %llx src: %p dst: %p",smp_processor_id(),req->roffset, (void *)src, (void *)dst);
  
  tfm = crypto_alloc_comp(alg,0,0);
  if (IS_ERR_OR_NULL(tfm)) {
		pr_err("could not alloc crypto comp");
		BUG();
	}

  ret = crypto_comp_decompress(tfm, src, req->len, dst, &dlen);

  pr_info("[decompress] length %d --> %d", (int)req->len, dlen);

  //TODO: 这里不一定合理 参见cpuhp_setup_state_multi
  crypto_free_comp(tfm);//释放crypto_comp对象
  kunmap_atomic(dst);//释放


  ib_dma_unmap_page(ibdev, req->dma, req->len, DMA_FROM_DEVICE);

  SetPageUptodate(req->page);
  unlock_page(req->page);
  complete(&req->done);//没有wait地方
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);//读完释放
  
  kfree(src);//释放读的缓存
}

static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req = container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_FROM_DEVICE);

  SetPageUptodate(req->page);
  unlock_page(req->page);
  complete(&req->done);
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);//读完释放
}

inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 roffset, enum ib_wr_opcode op)
{//TODO: 改了bad_wr类型 避免编译问题 可能有问题
  // const struct ib_send_wr *bad_wr;
  struct ib_send_wr *bad_wr;
  struct ib_rdma_wr rdma_wr = {};
  int ret;

  BUG_ON(qe->dma == 0);

  sge->addr = qe->dma;

  sge->length = qe->len;//+++根据len设置 PAGE_SIZE或dlen

  sge->lkey = q->ctrl->rdev->pd->local_dma_lkey;

  /* Todo: add a chain of WR, we already have a list so should be easy
   * to just post requests in batches */
  rdma_wr.wr.next    = NULL;
  rdma_wr.wr.wr_cqe  = &qe->cqe;//保证可以通过wc找到qe container_of(wc->wr_cqe, struct rdma_req, cqe);
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
  // const struct ib_recv_wr *bad_wr;
  struct ib_recv_wr *bad_wr;
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
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  (*req)->page = page;
  init_completion(&(*req)->done);

  (*req)->len = PAGE_SIZE;//和get_req_for_buf相同 设置长度 方便sswap_rdma_post_rdma 设置wr长度

  (*req)->dma = ib_dma_map_page(dev, page, 0, PAGE_SIZE, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, PAGE_SIZE, dir);
out:
  return ret;
}

/* the buffer needs to come from kernel (not high memory) */
inline static int get_req_for_buf(struct rdma_req **req, struct ib_device *dev,//为申请rdma_req空间,需要使用**改变指针变量值,使用*req传递的指针的形参
				void *buf, size_t size,
				enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);//
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  init_completion(&(*req)->done);

  (*req)->len = size;//rdma_req增加len成员,方便handle done处理

  (*req)->dma = ib_dma_map_single(dev, buf, size, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
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
static inline int write_queue_add_compress(struct rdma_queue *q, u8* src, size_t size, u64 roffset){
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;


  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }
  ret = get_req_for_buf(&req, dev, src, size, DMA_TO_DEVICE);//设置req中地址dma 长度len
  if (unlikely(ret))
    return ret;
  
  req->cqe.done = sswap_rdma_write_done_compress;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);//写入remote地址任是roffset
  
  return ret;
}


static inline int write_queue_add(struct rdma_queue *q, struct page *page,
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
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);

  return ret;
}

static inline int begin_read_compress(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树
	struct zswap_entry *entry;

	u8 *src;//src待压缩数据 申请作为远端读的缓存

  //#查rb tree得dlen
	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, roffset);//根据roffset在rb树上查找到entry 包含len
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
    pr_info("rbtree entry not found");
    BUG();
		return -1;
	}
	spin_unlock(&tree->lock);//unlock
  pr_info("cpuid: %d roffest: %llx, found rbtree entry length: %d",smp_processor_id(), roffset, entry->length);
  //读压缩数据
  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }
  src = (u8 *)kmalloc(PAGE_SIZE, GFP_KERNEL);//申请临时缓存src用于map
  ret = get_req_for_buf(&req, dev, src, entry->length, DMA_TO_DEVICE);//设置req中地址dma 长度len
  if (unlikely(ret))
    return ret;
  //TODO: 可能有问题 转换成无类型指针 存地址
  req->src = (void *)src;
  req->page = page;//存在req用于解压缩
  req->roffset = roffset;
  req->cqe.done = sswap_rdma_read_done_compress;//使用done_compress,接受到read结果后,进行解压缩
  
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);
  return ret;
  
}
static inline int begin_read(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

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

  req->cqe.done = sswap_rdma_read_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);//post一个读后返回,接收到后使用sswap_rdma_read_done处理
  return ret;
}

int sswap_rdma_write(unsigned type, struct page *page, u64 roffset)
{
  int ret;
  struct rdma_queue *q;
  
  //
  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
	struct zswap_entry *entry, *dupentry;
	struct crypto_comp *tfm;
  char alg[] = "lzo";
 	u8 *src, *dst;//usgined char 
	unsigned int dlen;

 
  if(page == NULL){
    pr_err("write page NULL");
    BUG();
  }
	// char *buf;

  //
	// struct swp_entry_t *zhdr = kmalloc(sizeof(swp_entry_t), GFP_KERNEL) alloc后需要free
  //
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);
 
  //压缩
 
  dst = zswap_dstmem[smp_processor_id()];//当前cpuid对应的压缩页面缓存
  // dst = (u8 *)kmalloc(PAGE_SIZE, GFP_KERNEL);

  src = (u8 *)kmap_atomic(page);//映射到内核的虚拟地址


  // pr_info("current CPUID %d current src: %p current dst: %p",smp_processor_id(),(void *)src, (void *)dst);
  tfm = crypto_alloc_comp(alg,0,0);
  if (IS_ERR_OR_NULL(tfm)) {
		pr_err("could not alloc crypto comp");
		return -ENOMEM;
	}

  ret = crypto_comp_compress(tfm, src, PAGE_SIZE, dst, &dlen);
  if(dlen > 100){
    pr_info("cpuid: %d roffset: %llx length: %d --> %u",smp_processor_id(), roffset, PAGE_SIZE, dlen);
  }

  //TODO: 这里不一定合理 参见cpuhp_setup_state_multi
  crypto_free_comp(tfm);//释放crypto_comp对象
  
  kunmap_atomic(src);
  // zhdr = swp_entry(type, offset);

  //TODO这里检测一下 dst虽然是u8* 但是应该没有关系 存的是地址 解释成什么类型不重要

  //##写入远端 dst为压缩后的目的地址 作为写入remote的src 长度为dlen
  ret = write_queue_add_compress(q, dst, dlen, roffset);


  //##存zswap_entry到rb tree
  // ret = write_queue_add(q, page, roffset);
  //TODO 1.设置rb tree 存压缩后的元数据(dlen)用于 拉回本地后解压缩  2.后续释放操作 3.更新计数stored_pages 4.entry使用完释放
  entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL); //申请插入rbtree 的swap entry
  entry->offset = roffset;
  entry->length = dlen;

  spin_lock(&tree->lock);
  //TODO: 没有处理重复问题
  zswap_rb_insert(&tree->rbroot, entry, &dupentry);//插入rb tree
  spin_unlock(&tree->lock);
  atomic_inc(&zswap_stored_pages);//增加计数
  
  BUG_ON(ret);
  drain_queue(q);
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

  ret = get_req_for_buf(&qe, dev, &(ctrl->servermr), sizeof(ctrl->servermr),//直接使用&即为内核虚拟地址 转换成void*类型
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
  VM_BUG_ON_PAGE(PageUptodate(page), page);//VM_BUG_ON_PAGE防止出现负面影响

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  // ret = begin_read(q, page, roffset);
  ret = begin_read_compress(q, page, roffset);//1.根据roffset查rb tree 2.读 3.解压缩 4.返回page
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
  // ret = begin_read(q, page, roffset);
  ret = begin_read_compress(q, page, roffset);
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
void sswap_rdma_init_compress(void){
  //初始化rb tree
  struct zswap_tree *tree;//
  int i;

  tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);//为swap(rb) tree分配空间,包含一个rbroot和lock

  if (!tree) {
    pr_err("alloc failed, zswap disabled for swap type \n");
    return;
  }

  tree->rbroot = RB_ROOT;//为NULL #define RB_ROOT	(struct rb_root) { NULL, }
  spin_lock_init(&tree->lock);
  zswap_trees = tree;

  //初始化dstmem 压缩内存临时缓存
  for(i = 0; i < ONLINE_CPU; i++){
    zswap_dstmem[i] = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
    if (!zswap_dstmem[i]) {
		  pr_err("can't allocate compressor buffer\n");
	  	BUG();
  	}
  }
  pr_info("zswap_dstmem alloc done");
}

static int __init sswap_rdma_init_module(void)
{
  int ret;

  pr_info("start: %s\n", __FUNCTION__);
  pr_info("* RDMA BACKEND *");

  // modified by ysjing
  // numcpus = num_online_cpus(
  numqueues = numcpus * 3;

  req_cache = kmem_cache_create("sswap_req_cache", sizeof(struct rdma_req), 0,//rdma_req大小的缓存 
                      SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);//搭配kmem_cache_alloc使用

  // req_cache_compress = kmem_cache_create("sswap_req_cache_compress", sizeof(struct rdma_req), 0,
  //                     SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);
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

  pr_info("ctrl is ready for reqs\n");
  sswap_rdma_init_compress();//初始化rb tree和dstmem
  pr_info("###########################################################\
#######################################");
  pr_info("###########################################################\
#######################################");
    pr_info("###########################################################\
#######################################");
  return 0;
  
}

module_init(sswap_rdma_init_module);
module_exit(sswap_rdma_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experiments");
