#ifndef __MULTI_THREAD_H__
#define __MULTI_THREAD_H__

#include "init/dpdk_init.h"
#include "arp/arp.h"
#include "udp/udp.h"
#include "icmp/icmp.h"


void arp_process(struct rte_mempool *mbuf_pool,struct rte_mbuf *mbuf,struct inout_ring *ring);
int pkt_process(void *arg);
#endif