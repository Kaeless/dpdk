#ifndef __UDP_H__
#define __UDP_H__

#include "init/dpdk_init.h"

/* ---- 函数声明 ---- */

/* 基础 UDP 包编码/发送 (使用全局 gSrcMac/gDstMac/gSrcIp/gDstIp/gSrcPort/gDstPort) */
int  ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len);
struct rte_mbuf *ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length);

/* 带参数的 UDP 包编码/发送 (UDP app 使用) */
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    unsigned char *data, uint16_t total_len);

struct rte_mbuf *ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    uint8_t *data, uint16_t length);

#endif /* __UDP_H__ */
