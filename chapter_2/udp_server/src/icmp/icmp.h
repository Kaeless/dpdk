#ifndef __ICMP_H__
#define __ICMP_H__

#include "init/dpdk_init.h"

/* ---- 函数声明 ---- */
uint16_t ng_checksum(uint16_t *addr, int count);

struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
    uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb);

#endif /* __ICMP_H__ */
