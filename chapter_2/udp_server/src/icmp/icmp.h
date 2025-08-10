#ifndef __ICMP_H__
#define __ICMP_H__

#include "init/dpdk_init.h"


/**
 * @brief 封装ICMP数据包并发送
 * 
 * @param mbuf_pool 
 * @param src_mac 
 * @param dst_mac 
 * @param sip 
 * @param dip 
 * @param icmp_ident 
 * @param icmp_seq_nb 
 * @return struct rte_mbuf* 
 */
struct rte_mbuf* send_icmp(struct rte_mempool *mbuf_pool,uint8_t* src_mac,uint8_t* dst_mac,
    uint32_t sip,uint32_t dip,rte_be16_t icmp_ident,rte_be16_t icmp_seq_nb);


#endif