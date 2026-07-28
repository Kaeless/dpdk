#include "udp.h"

/* ---- 基础 UDP 包编码 (使用全局地址/端口) ---- */
int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len)
{
    /* 1. 以太网头 */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->dst_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* 2. IP 头 */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = gSrcIp;
    ip->dst_addr        = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* 3. UDP 头 */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg +
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t *)(udp + 1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    struct in_addr addr;
    addr.s_addr = gSrcIp;
    struct in_addr dst_addr;
    dst_addr.s_addr = gDstIp;
    UDP_LOG_INFO("udp_encode --> src: %s:%d, dst: %s:%d",
        inet_ntoa(addr), ntohs(gSrcPort),
        inet_ntoa(dst_addr), ntohs(gDstPort));

    return 0;
}

/* ---- 构造基础 UDP mbuf ---- */
struct rte_mbuf *ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length)
{
    const unsigned total_len = length + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len  = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}

/* ---- UDP App 包编码 (带完整参数) ---- */
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    unsigned char *data, uint16_t total_len)
{
    /* 1. 以太网头 */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* 2. IP 头 */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = sip;
    ip->dst_addr        = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* 3. UDP 头 */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg +
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = sport;
    udp->dst_port = dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t *)(udp + 1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return 0;
}

/* ---- 构造带参数的 UDP mbuf ---- */
struct rte_mbuf *ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    uint8_t *data, uint16_t length)
{
    const unsigned total_len = length + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len  = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
        data, total_len);

    return mbuf;
}
