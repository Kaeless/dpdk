#ifndef __MULTI_THREAD_H__
#define __MULTI_THREAD_H__

#include "init/dpdk_init.h"
#include "arp/arp.h"
#include "udp/udp.h"
#include "icmp/icmp.h"

struct offload{

    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;
    
    int protocol;

    unsigned char* data;
    uint32_t length;
};

void arp_process(struct rte_mempool *mbuf_pool,struct rte_mbuf *mbuf,struct inout_ring *ring);
int pkt_process(void *arg);
#endif