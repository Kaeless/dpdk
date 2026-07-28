#include "arp.h"

static struct arp_table *arpt = NULL;

struct arp_table *arp_table_instance(void)
{
    if (arpt == NULL) {
        arpt = rte_malloc("arp table", sizeof(struct arp_table), 0);
        if (arpt == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }
    return arpt;
}

uint8_t *ng_get_dst_macaddr(uint32_t dip)
{
    struct arp_entry *iter;
    struct arp_table *table = arp_table_instance();

    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (dip == iter->ip)
            return iter->hwaddr;
    }
    return NULL;
}

/* ---- 编码 ARP 包 ---- */
static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac,
    uint32_t sip, uint32_t dip)
{
    /* 1. 以太网头 */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    /* 2. ARP 头 */
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen     = RTE_ETHER_ADDR_LEN;
    arp->arp_plen     = sizeof(uint32_t);
    arp->arp_opcode   = htons(opcode);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

/* ---- 构造 ARP mbuf ---- */
struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode,
    uint8_t *dst_mac, uint32_t sip, uint32_t dip)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len  = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;
}

/* ---- ARP 定时器回调: 周期性扫描局域网 ---- */
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    int i;
    for (i = 1; i <= 254; i++) {
        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

        struct in_addr addr;
        addr.s_addr = dstip;
        printf("arp ---> src: %s \n", inet_ntoa(addr));

        struct rte_mbuf *arpbuf = NULL;
        uint8_t *dstmac = ng_get_dst_macaddr(dstip);
        if (dstmac == NULL) {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST,
                gDefaultArpMac, gLocalIp, dstip);
        } else {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST,
                dstmac, gLocalIp, dstip);
        }

        rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
    }
}
