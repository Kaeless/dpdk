#include "pkt_process.h"

/* ---- 前向声明 UDP app 内部函数 ---- */
static int udp_process_pkt(struct rte_mbuf *udpmbuf);
static int udp_out(struct rte_mempool *mbuf_pool);

/* ---- pkt_process: 工作线程主循环 ---- */
int pkt_process(void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in,
            (void **)mbufs, BURST_SIZE, NULL);

        unsigned i;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i],
                struct rte_ether_hdr *);

            /* ---- ARP 处理 ---- */
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i],
                    struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

                struct in_addr addr;
                addr.s_addr = ahdr->arp_data.arp_tip;
                struct in_addr local_addr;
                local_addr.s_addr = gLocalIp;
                UDP_LOG_INFO("arp ---> src: %s  local: %s",
                    inet_ntoa(addr), inet_ntoa(local_addr));

                if (ahdr->arp_data.arp_tip == gLocalIp) {
                    if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                        UDP_LOG_INFO("arp --> request");

                        struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool,
                            RTE_ARP_OP_REPLY,
                            ahdr->arp_data.arp_sha.addr_bytes,
                            ahdr->arp_data.arp_tip,
                            ahdr->arp_data.arp_sip);

                        rte_ring_mp_enqueue_burst(ring->out,
                            (void **)&arpbuf, 1, NULL);

                    } else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
                        UDP_LOG_INFO("arp --> reply");

                        struct arp_table *table = arp_table_instance();
                        uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);

                        if (hwaddr == NULL) {
                            struct arp_entry *entry = rte_malloc("arp_entry",
                                sizeof(struct arp_entry), 0);
                            if (entry) {
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = ahdr->arp_data.arp_sip;
                                rte_memcpy(entry->hwaddr,
                                    ahdr->arp_data.arp_sha.addr_bytes,
                                    RTE_ETHER_ADDR_LEN);
                                entry->type = 0;

                                LL_ADD(entry, table->entries);
                                table->count++;
                            }
                        }

                        /* 打印 ARP 表 */
                        struct arp_entry *iter;
                        for (iter = table->entries; iter != NULL; iter = iter->next) {
                            struct in_addr a;
                            a.s_addr = iter->ip;
                            UDP_LOG_INFO("arp table --> mac: %s ip: %s",
                                format_ethaddr((struct rte_ether_addr *)iter->hwaddr),
                                inet_ntoa(a));
                        }

                        rte_pktmbuf_free(mbufs[i]);
                    }

                    continue;
                }
            }

            /* ---- IPv4 包处理 ---- */
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i],
                struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

            if (iphdr->next_proto_id == IPPROTO_UDP) {
                udp_process_pkt(mbufs[i]);
            }

            /* ---- ICMP 处理 ---- */
            if (iphdr->next_proto_id == IPPROTO_ICMP) {
                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                struct in_addr dst_addr;
                dst_addr.s_addr = iphdr->dst_addr;

                if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
                    UDP_LOG_INFO("icmp ---> src: %s  local: %s , type : %d",
                        inet_ntoa(addr), inet_ntoa(dst_addr), icmphdr->icmp_type);

                    struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool,
                        ehdr->src_addr.addr_bytes,
                        iphdr->dst_addr, iphdr->src_addr,
                        icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

                    rte_ring_mp_enqueue_burst(ring->out,
                        (void **)&txbuf, 1, NULL);
                    rte_pktmbuf_free(mbufs[i]);
                }
            }
        }

        /* UDP app 出队发送 */
        udp_out(mbuf_pool);
    }

    return 0;
}

/* ---- UDP 收包处理: 将数据入队到对应 socket 的 recv ring ---- */
static int udp_process_pkt(struct rte_mbuf *udpmbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf,
        struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    UDP_LOG_INFO("udp_process ---> src: %s:%d",
        inet_ntoa(addr), ntohs(udphdr->src_port));

    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr,
        udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -3;
    }

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -1;
    }

    ol->dip      = iphdr->dst_addr;
    ol->sip      = iphdr->src_addr;
    ol->sport    = udphdr->src_port;
    ol->dport    = udphdr->dst_port;
    ol->protocol = IPPROTO_UDP;
    ol->length   = ntohs(udphdr->dgram_len);

    ol->data = rte_malloc("unsigned char*",
        ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) {
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -2;
    }
    rte_memcpy(ol->data, (unsigned char *)(udphdr + 1),
        ol->length - sizeof(struct rte_udp_hdr));

    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);

    return 0;
}

/* ---- UDP 发包处理: 遍历所有 socket，发送 sndbuf 中的数据 ---- */
static int udp_out(struct rte_mempool *mbuf_pool)
{
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        struct offload *ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
        if (nb_snd < 0) continue;

        struct in_addr addr;
        addr.s_addr = ol->dip;
        UDP_LOG_INFO("udp_out ---> src: %s:%d",
            inet_ntoa(addr), ntohs(ol->dport));

        uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
        if (dstmac == NULL) {
            /* ARP 未解析: 先发 ARP 请求，数据重新入队 */
            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool,
                RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            /* ARP 已解析: 构造并发送 UDP 包 */
            struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool,
                ol->sip, ol->dip, ol->sport, ol->dport,
                host->localmac, dstmac, ol->data, ol->length);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
        }
    }

    return 0;
}
