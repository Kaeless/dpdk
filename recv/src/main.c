#pragma once
#include <include/recv.h>


int main(int argc, char *argv[]) {
    int ret;
    unsigned nb_ports;
    uint16_t portid;
    struct rte_hash_parameters hash_params = {0};

    /* 初始化DPDK环境抽象层(EAL) */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL初始化失败，返回代码=%d\n", ret);
    argc -= ret;
    argv += ret;

    /* 解析应用参数 */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "参数解析失败\n");

    /* 设置信号处理 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 获取可用端口数量 */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "没有检测到支持DPDK的以太网设备\n");

    printf("检测到 %u 个支持DPDK的以太网设备\n", nb_ports);

    /* 初始化端口配置 */
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    /* 创建mbuf内存池 */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "无法创建mbuf池\n");

    /* 初始化所有端口 */
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid) != 0)
            rte_exit(EXIT_FAILURE, "无法初始化端口 %"PRIu16 "\n", portid);
    }

    /* 初始化连接哈希表 */
    hash_params.name = "TCP_CONN_HASH";
    hash_params.entries = MAX_CONNECTIONS;
    hash_params.key_len = sizeof(struct conn_hash_key);
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;

    conn_hash = rte_hash_create(&hash_params);
    if (conn_hash == NULL)
        rte_exit(EXIT_FAILURE, "无法创建连接哈希表\n");

    /* 初始化连接列表 */
    TAILQ_INIT(&conn_list);

    printf("TCP服务器启动,监听IP: %s, 端口: %d\n",
           inet_ntoa(*(struct in_addr *)&server_ip), SERVER_PORT);

    /* 进入主循环 */
    main_loop();

    printf("清理并退出...\n");

    /* 关闭所有端口 */
    RTE_ETH_FOREACH_DEV(portid) {
        printf("关闭端口 %d...\n", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }

    /* 释放连接资源 */
    struct tcp_connection *conn, *tmp;
    TAILQ_FOREACH_SAFE(conn, &conn_list, next, tmp) {
        TAILQ_REMOVE(&conn_list, conn, next);
        rte_free(conn);
    }

    /* 释放哈希表 */
    rte_hash_free(conn_hash);

    /* 完成EAL清理 */
    rte_eal_cleanup();

    return 0;
}