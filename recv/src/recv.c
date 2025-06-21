#include <include/recv.h>

/* 信号处理函数 */
static void sig_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\n收到退出信号 %d，准备退出...\n", signum);
        force_quit = 1;
    }
}

/* 初始化以太网端口 */
static int port_init(uint16_t port) {
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t q;
    int retval;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    /* 配置以太网端口 */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    /* 设置接收队列 */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* 设置发送队列 */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    /* 启动以太网端口 */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* 显示MAC地址 */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("端口 %u MAC 地址: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
           (unsigned)port,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* 启用混杂模式 */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/* 创建新连接 */
static struct tcp_connection *create_connection(uint32_t src_ip, uint16_t src_port,
        uint32_t dst_ip, uint16_t dst_port) {
    struct tcp_connection *conn;

    conn = rte_zmalloc("TCP_CONN", sizeof(*conn), 0);
    if (conn == NULL)
        return NULL;

    conn->src_ip = src_ip;
    conn->dst_ip = dst_ip;
    conn->src_port = src_port;
    conn->dst_port = dst_port;
    conn->state = CONN_LISTEN;
    conn->rx_seq = 0;
    conn->tx_seq = rte_rand(); /* 随机初始序列号 */

    rte_spinlock_lock(&conn_lock);
    TAILQ_INSERT_TAIL(&conn_list, conn, next);
    rte_spinlock_unlock(&conn_lock);

    return conn;
}

/* 查找连接 */
static struct tcp_connection *find_connection(uint32_t src_ip, uint16_t src_port,
        uint32_t dst_ip, uint16_t dst_port) {
    struct conn_hash_key key;
    uint32_t hash_key;
    int ret;

    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;

    ret = rte_hash_lookup_data(conn_hash, &key, (void **)&hash_key);
    if (ret >= 0) {
        return (struct tcp_connection *)hash_key;
    }

    return NULL;
}

/* 处理TCP SYN包 */
static void handle_tcp_syn(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph) {
    struct tcp_connection *conn;
    struct rte_mbuf *tx_buf;
    struct ether_hdr *eth;
    struct ipv4_hdr *tx_ip;
    struct tcp_hdr *tx_tcp;
    uint16_t ip_hdr_len;
    uint16_t tcp_data_off;
    uint16_t payload_len;
    uint16_t total_len;
    uint8_t *tcp_options;
    uint16_t options_len;

    ip_hdr_len = iph->version_ihl & 0x0F;
    ip_hdr_len <<= 2; /* 转换为字节 */

    tcp_data_off = tcph->data_off & 0xF0;
    tcp_data_off >>= 2; /* 转换为字节 */

    payload_len = ntohs(iph->total_length) - ip_hdr_len - tcp_data_off;
    total_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

    /* 创建新连接 */
    conn = create_connection(iph->dst_addr, ntohs(tcph->dst_port),
                            iph->src_addr, ntohs(tcph->src_port));
    if (conn == NULL) {
        rte_pktmbuf_free(m);
        return;
    }

    conn->rx_seq = ntohl(tcph->seq_num);
    conn->tx_seq++; /* SYN占一个序列号 */
    conn->state = CONN_SYN_RCVD;

    /* 分配发送缓冲区 */
    tx_buf = rte_pktmbuf_alloc(mbuf_pool);
    if (tx_buf == NULL) {
        rte_pktmbuf_free(m);
        return;
    }

    tx_buf->data_len = total_len;
    tx_buf->pkt_len = total_len;

    /* 构建以太网头部 */
    eth = rte_pktmbuf_mtod(tx_buf, struct ether_hdr *);
    rte_eth_macaddr_get(0, &eth->s_addr); /* 获取本地MAC */
    eth->d_addr = ((struct ether_hdr *)rte_pktmbuf_mtod(m, struct ether_hdr *))->s_addr;
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    /* 构建IP头部 */
    tx_ip = (struct ipv4_hdr *)(eth + 1);
    tx_ip->version_ihl = 0x45; /* IPv4, 头部长度5 */
    tx_ip->type_of_service = 0;
    tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    tx_ip->packet_id = 0;
    tx_ip->fragment_offset = 0;
    tx_ip->time_to_live = 64;
    tx_ip->next_proto_id = IPPROTO_TCP;
    tx_ip->src_addr = iph->dst_addr;
    tx_ip->dst_addr = iph->src_addr;
    tx_ip->hdr_checksum = 0;
    tx_ip->hdr_checksum = rte_ipv4_hdr_checksum(tx_ip);

    /* 构建TCP头部 */
    tx_tcp = (struct tcp_hdr *)(tx_ip + 1);
    tx_tcp->src_port = tcph->dst_port;
    tx_tcp->dst_port = tcph->src_port;
    tx_tcp->seq_num = rte_cpu_to_be_32(conn->tx_seq);
    tx_tcp->ack_num = rte_cpu_to_be_32(conn->rx_seq + 1);
    tx_tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
    tx_tcp->tcp_flags = TCP_SYN | TCP_ACK;
    tx_tcp->rx_win = rte_cpu_to_be_16(65535);
    tx_tcp->cksum = 0;
    tx_tcp->tcp_urp = 0;

    /* 计算TCP校验和 */
    tx_tcp->cksum = rte_tcp_cksum(tx_ip, tx_tcp);

    /* 发送SYN+ACK */
    rte_eth_tx_burst(0, 0, &tx_buf, 1);
    rte_pktmbuf_free(m);
}

/* 处理TCP ACK包 */
static void handle_tcp_ack(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph) {
    struct tcp_connection *conn;
    uint16_t ip_hdr_len;
    uint16_t tcp_data_off;
    uint16_t payload_len;

    ip_hdr_len = iph->version_ihl & 0x0F;
    ip_hdr_len <<= 2; /* 转换为字节 */

    tcp_data_off = tcph->data_off & 0xF0;
    tcp_data_off >>= 2; /* 转换为字节 */

    payload_len = ntohs(iph->total_length) - ip_hdr_len - tcp_data_off;

    /* 查找连接 */
    conn = find_connection(iph->dst_addr, ntohs(tcph->dst_port),
                          iph->src_addr, ntohs(tcph->src_port));
    if (conn == NULL) {
        rte_pktmbuf_free(m);
        return;
    }

    if (conn->state == CONN_SYN_RCVD) {
        /* 连接建立完成 */
        conn->state = CONN_ESTABLISHED;
        printf("TCP连接已建立: %x:%d -> %x:%d\n",
               conn->src_ip, conn->src_port, conn->dst_ip, conn->dst_port);
    }

    /* 处理数据 */
    if (payload_len > 0) {
        conn->rx_bytes += payload_len;
        printf("收到数据: %u 字节, 累计: %u 字节\n", payload_len, conn->rx_bytes);

        /* 这里可以添加应用层协议处理逻辑 */
    }

    /* 发送ACK */
    struct rte_mbuf *tx_buf = rte_pktmbuf_alloc(mbuf_pool);
    if (tx_buf != NULL) {
        struct ether_hdr *eth = rte_pktmbuf_mtod(tx_buf, struct ether_hdr *);
        struct ipv4_hdr *tx_ip = (struct ipv4_hdr *)(eth + 1);
        struct tcp_hdr *tx_tcp = (struct tcp_hdr *)(tx_ip + 1);
        uint16_t total_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

        tx_buf->data_len = total_len;
        tx_buf->pkt_len = total_len;

        /* 构建以太网头部 */
        rte_eth_macaddr_get(0, &eth->s_addr);
        eth->d_addr = ((struct ether_hdr *)rte_pktmbuf_mtod(m, struct ether_hdr *))->s_addr;
        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

        /* 构建IP头部 */
        tx_ip->version_ihl = 0x45;
        tx_ip->type_of_service = 0;
        tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
        tx_ip->packet_id = 0;
        tx_ip->fragment_offset = 0;
        tx_ip->time_to_live = 64;
        tx_ip->next_proto_id = IPPROTO_TCP;
        tx_ip->src_addr = iph->dst_addr;
        tx_ip->dst_addr = iph->src_addr;
        tx_ip->hdr_checksum = 0;
        tx_ip->hdr_checksum = rte_ipv4_hdr_checksum(tx_ip);

        /* 构建TCP头部 */
        tx_tcp->src_port = tcph->dst_port;
        tx_tcp->dst_port = tcph->src_port;
        tx_tcp->seq_num = rte_cpu_to_be_32(conn->tx_seq);
        tx_tcp->ack_num = rte_cpu_to_be_32(ntohl(tcph->seq_num) + payload_len);
        tx_tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
        tx_tcp->tcp_flags = TCP_ACK;
        tx_tcp->rx_win = rte_cpu_to_be_16(65535);
        tx_tcp->cksum = 0;
        tx_tcp->tcp_urp = 0;

        /* 计算TCP校验和 */
        tx_tcp->cksum = rte_tcp_cksum(tx_ip, tx_tcp);

        /* 发送ACK */
        rte_eth_tx_burst(0, 0, &tx_buf, 1);
    }

    rte_pktmbuf_free(m);
}

/* 处理TCP FIN包 */
static void handle_tcp_fin(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph) {
    struct tcp_connection *conn;
    uint16_t ip_hdr_len;
    uint16_t tcp_data_off;

    ip_hdr_len = iph->version_ihl & 0x0F;
    ip_hdr_len <<= 2; /* 转换为字节 */

    tcp_data_off = tcph->data_off & 0xF0;
    tcp_data_off >>= 2; /* 转换为字节 */

    /* 查找连接 */
    conn = find_connection(iph->dst_addr, ntohs(tcph->dst_port),
                          iph->src_addr, ntohs(tcph->src_port));
    if (conn == NULL) {
        rte_pktmbuf_free(m);
        return;
    }

    if (conn->state == CONN_ESTABLISHED) {
        conn->state = CONN_CLOSE_WAIT;

        /* 发送ACK */
        struct rte_mbuf *tx_buf = rte_pktmbuf_alloc(mbuf_pool);
        if (tx_buf != NULL) {
            struct ether_hdr *eth = rte_pktmbuf_mtod(tx_buf, struct ether_hdr *);
            struct ipv4_hdr *tx_ip = (struct ipv4_hdr *)(eth + 1);
            struct tcp_hdr *tx_tcp = (struct tcp_hdr *)(tx_ip + 1);
            uint16_t total_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

            tx_buf->data_len = total_len;
            tx_buf->pkt_len = total_len;

            /* 构建以太网头部 */
            rte_eth_macaddr_get(0, &eth->s_addr);
            eth->d_addr = ((struct ether_hdr *)rte_pktmbuf_mtod(m, struct ether_hdr *))->s_addr;
            eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

            /* 构建IP头部 */
            tx_ip->version_ihl = 0x45;
            tx_ip->type_of_service = 0;
            tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
            tx_ip->packet_id = 0;
            tx_ip->fragment_offset = 0;
            tx_ip->time_to_live = 64;
            tx_ip->next_proto_id = IPPROTO_TCP;
            tx_ip->src_addr = iph->dst_addr;
            tx_ip->dst_addr = iph->src_addr;
            tx_ip->hdr_checksum = 0;
            tx_ip->hdr_checksum = rte_ipv4_hdr_checksum(tx_ip);

            /* 构建TCP头部 */
            tx_tcp->src_port = tcph->dst_port;
            tx_tcp->dst_port = tcph->src_port;
            tx_tcp->seq_num = rte_cpu_to_be_32(conn->tx_seq);
            tx_tcp->ack_num = rte_cpu_to_be_32(ntohl(tcph->seq_num) + 1);
            tx_tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
            tx_tcp->tcp_flags = TCP_ACK;
            tx_tcp->rx_win = rte_cpu_to_be_16(65535);
            tx_tcp->cksum = 0;
            tx_tcp->tcp_urp = 0;

            /* 计算TCP校验和 */
            tx_tcp->cksum = rte_tcp_cksum(tx_ip, tx_tcp);

            /* 发送ACK */
            rte_eth_tx_burst(0, 0, &tx_buf, 1);
        }

        /* 发送FIN+ACK */
        tx_buf = rte_pktmbuf_alloc(mbuf_pool);
        if (tx_buf != NULL) {
            struct ether_hdr *eth = rte_pktmbuf_mtod(tx_buf, struct ether_hdr *);
            struct ipv4_hdr *tx_ip = (struct ipv4_hdr *)(eth + 1);
            struct tcp_hdr *tx_tcp = (struct tcp_hdr *)(tx_ip + 1);
            uint16_t total_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

            tx_buf->data_len = total_len;
            tx_buf->pkt_len = total_len;

            /* 构建以太网头部 */
            rte_eth_macaddr_get(0, &eth->s_addr);
            eth->d_addr = ((struct ether_hdr *)rte_pktmbuf_mtod(m, struct ether_hdr *))->s_addr;
            eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

            /* 构建IP头部 */
            tx_ip->version_ihl = 0x45;
            tx_ip->type_of_service = 0;
            tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
            tx_ip->packet_id = 0;
            tx_ip->fragment_offset = 0;
            tx_ip->time_to_live = 64;
            tx_ip->next_proto_id = IPPROTO_TCP;
            tx_ip->src_addr = iph->dst_addr;
            tx_ip->dst_addr = iph->src_addr;
            tx_ip->hdr_checksum = 0;
            tx_ip->hdr_checksum = rte_ipv4_hdr_checksum(tx_ip);

            /* 构建TCP头部 */
            tx_tcp->src_port = tcph->dst_port;
            tx_tcp->dst_port = tcph->src_port;
            tx_tcp->seq_num = rte_cpu_to_be_32(conn->tx_seq + 1);
            tx_tcp->ack_num = rte_cpu_to_be_32(ntohl(tcph->seq_num) + 1);
            tx_tcp->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
            tx_tcp->tcp_flags = TCP_FIN | TCP_ACK;
            tx_tcp->rx_win = rte_cpu_to_be_16(65535);
            tx_tcp->cksum = 0;
            tx_tcp->tcp_urp = 0;

            /* 计算TCP校验和 */
            tx_tcp->cksum = rte_tcp_cksum(tx_ip, tx_tcp);

            /* 发送FIN+ACK */
            rte_eth_tx_burst(0, 0, &tx_buf, 1);
            conn->state = CONN_LAST_ACK;
        }
    }

    rte_pktmbuf_free(m);
}

/* 处理数据包 */
static void process_packet(struct rte_mbuf *m) {
    struct ether_hdr *eth;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;
    uint16_t eth_type;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth->ether_type);

    if (eth_type != ETHER_TYPE_IPv4) {
        rte_pktmbuf_free(m);
        return;
    }

    iph = (struct ipv4_hdr *)(eth + 1);
    if (iph->next_proto_id != IPPROTO_TCP) {
        rte_pktmbuf_free(m);
        return;
    }

    tcph = (struct tcp_hdr *)(iph + 1);
    if (ntohs(tcph->dst_port) != SERVER_PORT) {
        rte_pktmbuf_free(m);
        return;
    }

    /* 处理TCP包 */
    if (tcph->tcp_flags & TCP_SYN) {
        if (!(tcph->tcp_flags & TCP_ACK)) {
            /* SYN包 */
            handle_tcp_syn(m, iph, tcph);
        } else {
            /* SYN+ACK包（理论上不应该收到） */
            rte_pktmbuf_free(m);
        }
    } else if (tcph->tcp_flags & TCP_ACK) {
        /* ACK包 */
        handle_tcp_ack(m, iph, tcph);
    } else if (tcph->tcp_flags & TCP_FIN) {
        /* FIN包 */
        handle_tcp_fin(m, iph, tcph);
    } else {
        rte_pktmbuf_free(m);
    }
}

/* 主处理循环 */
static void main_loop(void) {
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t nb_rx, i;
    unsigned lcore_id;

    lcore_id = rte_lcore_id();
    printf("核心 %u 开始接收数据包...\n", lcore_id);

    while (!force_quit) {
        nb_rx = rte_eth_rx_burst(0, 0, pkts_burst, BURST_SIZE);
        if (unlikely(nb_rx == 0))
            continue;

        for (i = 0; i < nb_rx; i++) {
            process_packet(pkts_burst[i]);
        }
    }
}

/* 解析服务器IP地址参数 */
static int parse_ip_addr(const char *arg) {
    struct in_addr in;
    int r = inet_pton(AF_INET, arg, &in);
    if (r <= 0) {
        printf("无效的IP地址: %s\n", arg);
        return -1;
    }
    server_ip = rte_be_to_cpu_32(in.s_addr);
    return 0;
}

/* 解析命令行参数 */
static int parse_args(int argc, char **argv) {
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];

    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "i:",
                   lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'i':
            ret = parse_ip_addr(optarg);
            if (ret < 0)
                return ret;
            break;
        default:
            printf("使用方法: %s [EAL选项] -- -i <服务器IP>\n", prgname);
            return -1;
        }
    }

    if (server_ip == 0) {
        printf("错误: 必须指定服务器IP地址 (-i <IP>)\n");
        return -1;
    }

    return 0;
}

