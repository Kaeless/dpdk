#ifndef __PKT_PROCESS_H__
#define __PKT_PROCESS_H__

#include "init/dpdk_init.h"
#include "arp/arp.h"
#include "icmp/icmp.h"
#include "udp/udp.h"

/* ---- 包处理主循环 (运行在 worker lcore) ---- */
int pkt_process(void *arg);

#endif /* __PKT_PROCESS_H__ */
