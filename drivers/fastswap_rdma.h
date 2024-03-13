#if !defined(_SSWAP_RDMA_H)
#define _SSWAP_RDMA_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

enum qp_type {
  QP_READ_SYNC,
  QP_READ_ASYNC,
  QP_WRITE_SYNC
};

struct sswap_rdma_dev {
  struct ib_device *dev;
  struct ib_pd *pd;
};

struct rdma_req_compress {//信息:1.cqe设置完成done函数 2.dma地址 3.page
  struct completion done;
  struct list_head list;
  struct ib_cqe cqe;
  // u64 dma;
  // struct page *page;
};

struct rdma_req {//信息:1.cqe设置完成done函数 2.dma地址 3.page
  struct completion done;
  struct list_head list;
  struct ib_cqe cqe;
  u64 dma;
  struct page *page;
  size_t len;//+++
  void* src;//+++用于存读时的缓存位置 用于解压缩
  u64 roffset;//+++
  u16 crc; //+++用于crc校验
};

struct sswap_rdma_ctrl;

struct rdma_queue {
  struct ib_qp *qp;
  struct ib_cq *cq;
  spinlock_t cq_lock;
  enum qp_type qp_type;

  struct sswap_rdma_ctrl *ctrl;

  struct rdma_cm_id *cm_id;
  int cm_error;
  struct completion cm_done;

  atomic_t pending;
};

struct sswap_rdma_memregion {
    u64 baseaddr;//64bit baseaddr
    u32 key;
};

struct sswap_rdma_ctrl {
  struct sswap_rdma_dev *rdev; // TODO: move this to queue
  struct rdma_queue *queues;
  struct sswap_rdma_memregion servermr;

  union {
    struct sockaddr addr;
    struct sockaddr_in addr_in;
  };

  union {
    struct sockaddr srcaddr;
    struct sockaddr_in srcaddr_in;
  };
};

struct rdma_queue *sswap_rdma_get_queue(unsigned int idx, enum qp_type type);
enum qp_type get_queue_type(unsigned int idx);
int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);//
int sswap_rdma_poll_load(int cpu);

void sswap_rdma_init(unsigned type);


#endif
