#include "init/dpdk_init.h"
#include "arp/arp.h"
#include "icmp/icmp.h"
#include "udp/udp.h"
#include "pkt_process/pkt_process.h"

/*
 * =====================================================
 *  UDP Server — DPDK 用户态协议栈
 * =====================================================
 *
 *  模块结构:
 *    init/        - DPDK 初始化、全局状态、ring buffer
 *    arp/         - ARP 表管理、ARP 包构造/发送、定时器
 *    icmp/        - ICMP 校验和、ICMP Echo Reply
 *    udp/         - UDP 包编码/构造
 *    pkt_process/ - 工作线程: ARP/ICMP/UDP 收包分发
 *    udp_server.c - Socket API (nsocket/nbind/nrecvfrom/nsendto/nclose)
 *                   + UDP Echo Server + main
 *
 *  Socket API:
 *    1. nsocket   → socket
 *    2. nbind     → bind
 *    3. nrecvfrom → recvfrom
 *    4. nsendto   → sendto
 *    5. nclose    → close
 *
 *  数据流:
 *    RX: NIC → ring->in → pkt_process() → host->rcvbuf → nrecvfrom()
 *    TX: nsendto() → host->sndbuf → udp_out() → ring->out → NIC
 */

/* ======== Socket API 实现 ======== */

/*
 * nsocket — 创建用户态 socket
 * @domain:   AF_INET
 * @type:     SOCK_DGRAM / SOCK_STREAM
 * @protocol: 0 表示自动选择
 * return:    fd (>=3)，失败返回 -1
 */
static int nsocket(__attribute__((unused)) int domain, int type,
    __attribute__((unused)) int protocol)
{
    int fd = get_fd_frombitmap();

    struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) {
        return -1;
    }
    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    if (type == SOCK_DGRAM)
        host->protocol = IPPROTO_UDP;

    host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE,
        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->rcvbuf == NULL) {
        rte_free(host);
        return -1;
    }

    host->sndbuf = rte_ring_create("send buffer", RING_SIZE,
        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sndbuf == NULL) {
        rte_ring_free(host->rcvbuf);
        rte_free(host);
        return -1;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    LL_ADD(host, lhost);

    return fd;
}

/*
 * nbind — 绑定 socket 到本地地址
 * @sockfd:  socket fd
 * @addr:    struct sockaddr_in *
 * @addrlen: 地址长度
 * return:   0 成功, -1 失败
 */
static int nbind(int sockfd, const struct sockaddr *addr,
    __attribute__((unused)) socklen_t addrlen)
{
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;
}

/*
 * nrecvfrom — 接收 UDP 数据 (阻塞)
 * @sockfd:   socket fd
 * @buf:      用户缓冲区
 * @len:      缓冲区大小
 * @flags:    标志位 (保留)
 * @src_addr: [出] 发送方地址
 * @addrlen:  [入/出] 地址长度
 * return:    实际接收字节数
 */
static ssize_t nrecvfrom(int sockfd, void *buf, size_t len,
    __attribute__((unused)) int flags,
    struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addrlen)
{
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    struct offload *ol = NULL;
    unsigned char *ptr = NULL;

    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;

    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->length) {
        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char *", ol->length - len, 0);
        rte_memcpy(ptr, ol->data + len, ol->length - len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->rcvbuf, ol);

        return len;
    } else {
        rte_memcpy(buf, ol->data, ol->length);

        rte_free(ol->data);
        rte_free(ol);

        return ol->length;
    }
}

/*
 * nsendto — 发送 UDP 数据
 * @sockfd:   socket fd
 * @buf:      待发送数据
 * @len:      数据长度
 * @flags:    标志位 (保留)
 * @dest_addr: 目标地址
 * @addrlen:  地址长度
 * return:    实际发送字节数
 */
static ssize_t nsendto(int sockfd, const void *buf, size_t len,
    __attribute__((unused)) int flags,
    const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addrlen)
{
    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) return -1;

    ol->dip      = daddr->sin_addr.s_addr;
    ol->dport    = daddr->sin_port;
    ol->sip      = host->localip;
    ol->sport    = host->localport;
    ol->length   = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    UDP_LOG_INFO("nsendto ---> src: %s:%d", inet_ntoa(addr), ntohs(ol->dport));

    ol->data = rte_malloc("unsigned char *", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }
    rte_memcpy(ol->data, buf, len);

    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}

/*
 * nclose — 关闭 socket，释放资源
 * @fd: socket fd
 */
static int nclose(int fd)
{
    struct localhost *host = get_hostinfo_fromfd(fd);
    if (host == NULL) return -1;

    LL_REMOVE(host, lhost);

    if (host->rcvbuf) {
        rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
        rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    return 0;
}

/* ======== UDP Echo Server ======== */

/*
 * udp_server_entry — UDP Echo Server 入口 (运行在独立 lcore)
 * 监听端口 8888，将收到的数据原样回显
 */
static int udp_server_entry(__attribute__((unused)) void *arg)
{
    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        UDP_LOG_ERR("sockfd failed");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port        = htons(app_get_port());
    localaddr.sin_family      = AF_INET;
    localaddr.sin_addr.s_addr = gLocalIp;

    nbind(connfd, (struct sockaddr *)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    socklen_t addrlen = sizeof(clientaddr);
    while (1) {
        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
            (struct sockaddr *)&clientaddr, &addrlen) < 0) {
            continue;
        } else {
            UDP_LOG_INFO("recv from %s:%d, data:%s",
                inet_ntoa(clientaddr.sin_addr),
                ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0,
                (struct sockaddr *)&clientaddr, sizeof(clientaddr));
        }
    }

    nclose(connfd);

    return 0;
}

/* ======== main ======== */

int main(int argc, char *argv[])
{
    /* ---- 1. DPDK EAL 初始化 ---- */
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    /* ---- 1.2 日志系统初始化 (输出到 log/ 目录) ---- */
    udp_log_init("log");

    /* ---- 1.5 解析应用层参数 (--local-ip, --local-port) ---- */
    /*
     * DPDK EAL 使用 -- 作为分隔符：-- 之前是 EAL 参数，之后是应用参数。
     * 这里找到 -- 的位置，只把后面的参数传给 app_parse_args。
     */
#if ARGV_PARSER
    int app_argc = 0;
    char **app_argv = NULL;
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            app_argc = argc - i - 1;
            app_argv = &argv[i + 1];
            break;
        }
    }
    if (app_argv == NULL) {
        /* 没有 --，说明所有未知参数都可能被 EAL 跳过，尝试直接解析 */
        app_argc = argc;
        app_argv = argv;
    }
    app_parse_args(app_argc, app_argv);
#endif

    /* ---- 2. 内存池创建 ---- */
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool",
        NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    /* ---- 3. 端口初始化 ---- */
    ng_init_port(mbuf_pool);

    /* ---- 4. 获取本机 MAC 地址 ---- */
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

    /* ---- 5. ARP 定时器初始化 ---- */
#if ENABLE_ARP_TIMER
    rte_timer_subsystem_init();

    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    /* hz * 10 = 10 秒一次，调试期间避免 ARP 定时器频繁耗尽 mbuf pool */
    rte_timer_reset(&arp_timer, hz * 10, PERIODICAL, lcore_id,
        arp_request_timer_cb, mbuf_pool);
#endif

    /* ---- 6. Ring buffer 初始化 ---- */
    struct inout_ring *ring = ringInstance();
    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if (ring->in == NULL) {
        ring->in = rte_ring_create("in ring", RING_SIZE,
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    if (ring->out == NULL) {
        ring->out = rte_ring_create("out ring", RING_SIZE,
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    /* ---- 7. 启动 Worker 线程 ---- */
    /* pkt_process 线程 — 跳过主 lcore */
    unsigned lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

    /* UDP Echo Server 线程 */
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

    /* ---- 8. 主循环: RX (含 ARP 直接处理) / TX + 定时器 ---- */
    while (1) {
        /* RX: 从网卡收包 → ARP 在 main 中直接处理 → 其余入队 ring->in */
        struct rte_mbuf *rx[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (num_recvd > 0) {
            unsigned i;
            for (i = 0; i < num_recvd; i++) {
                struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(rx[i],
                    struct rte_ether_hdr *);

#if ENABLE_ARP
                /* ARP 包直接在 main 中处理 */
                if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                    struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(rx[i],
                        struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

                    struct in_addr addr;
                    addr.s_addr = ahdr->arp_data.arp_tip;
                    struct in_addr local_addr;
                    local_addr.s_addr = gLocalIp;
                    UDP_LOG_INFO("arp ---> src: %s  local: %s",
                        inet_ntoa(addr), inet_ntoa(local_addr));

                    if (ahdr->arp_data.arp_tip == gLocalIp) {

                        if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                            UDP_LOG_INFO("arp --> request, sending reply");

                            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool,
                                RTE_ARP_OP_REPLY,
                                ahdr->arp_data.arp_sha.addr_bytes,
                                gLocalIp,
                                ahdr->arp_data.arp_sip);

                            rte_ring_sp_enqueue_burst(ring->out,
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
                                    entry->type = ARP_ENTRY_STATUS_DYNAMIC;

                                    LL_ADD(entry, table->entries);
                                    table->count++;
                                }
                            }

                            /* 打印 ARP 表 */
                            struct arp_entry *iter;
                            for (iter = table->entries; iter != NULL; iter = iter->next) {
                                struct in_addr a;
                                a.s_addr = iter->ip;
                                UDP_LOG_INFO("arp entry --> mac: %s ip: %s",
                                    format_ethaddr((struct rte_ether_addr *)iter->hwaddr),
                                    inet_ntoa(a));
                            }
                        }
                    }

                    rte_pktmbuf_free(rx[i]);
                    continue;
                }
#endif
                /* 非 ARP 包（或 ARP 未启用时所有包）入队 ring->in */
                rte_ring_sp_enqueue_burst(ring->in, (void **)&rx[i], 1, NULL);
            }
        }
        /* TX: 从 ring->out 出队 → 发送到网卡 */
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out,
            (void **)tx, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

            unsigned i;
            for (i = 0; i < nb_tx; i++) {
                rte_pktmbuf_free(tx[i]);
            }
        }

        /* 驱动 ARP 定时器 */
        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t diff_tsc;

        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
}
    return 0;
}

