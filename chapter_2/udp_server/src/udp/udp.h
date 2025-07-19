#ifndef __UDP_H__
#define __UDP_H__

#include "init/dpdk_init.h"


/**
 * @brief 发送UDP数据包
 * 
 * @param mbuf_pool 
 * @param data 
 * @param length 
 * @param src_addr 
 * @param dst_addr 
 * @return struct rte_mbuf* 
 */
static struct rte_mbuf * send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, 
    uint16_t length,struct ether_addr src_addr,struct ether_addr dst_addr);

#endif