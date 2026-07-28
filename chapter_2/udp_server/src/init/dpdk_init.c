#include "dpdk_init.h"

/* ---- 全局变量定义 ---- */
int      gDpdkPortId = 0;
uint32_t gLocalIp = 0;  /* 由 --local-ip 参数设置，默认 192.168.0.115 */
uint32_t gSrcIp;
uint32_t gDstIp;
uint8_t  gSrcMac[RTE_ETHER_ADDR_LEN];
uint8_t  gDstMac[RTE_ETHER_ADDR_LEN];
uint16_t gSrcPort;
uint16_t gDstPort;
uint8_t  gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct localhost *lhost = NULL;

/* ---- ringInstance 单例 ---- */
static struct inout_ring *rInst = NULL;

struct inout_ring *ringInstance(void)
{
    if (rInst == NULL) {
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }
    return rInst;
}

/* ---- 端口初始化 ---- */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.mtu = 0}
};

void ng_init_port(struct rte_mempool *mbuf_pool)
{
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024,
        rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024,
        rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

/* ---- MAC 地址打印 ---- */
void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

/* ---- FD 分配 (从 3 开始, 0/1/2 为标准 stdin/stdout/stderr) ---- */
int get_fd_frombitmap(void)
{
    return DEFAULT_FD_NUM;
}

/* ---- localhost 链表查找 ---- */
struct localhost *get_hostinfo_fromfd(int sockfd)
{
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (sockfd == host->fd)
            return host;
    }
    return NULL;
}

struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto)
{
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol)
            return host;
    }
    return NULL;
}

/* ---- 应用层命令行解析 (rte_eal_init 之后调用) ---- */
/*
 * 支持的参数:
 *   --local-ip=<a.b.c.d>   设置本地 IP 地址 (默认 192.168.100.1)
 *   --local-port=<port>     设置监听端口 (默认 8888)
 */
#define DEFAULT_LOCAL_IP   MAKE_IPV4_ADDR(192, 168, 100, 1)
#define DEFAULT_LOCAL_PORT 8888

static uint16_t gAppPort = 0;  /* 0 表示使用默认值 */

void app_parse_args(int argc, char *argv[])
{
    int i;
    for (i = 0; i < argc; i++) {
        /* 支持 --local-ip=X 和 --local-ip X 两种格式 */
        const char *ip_str = NULL;
        if (strncmp(argv[i], "--local-ip=", 11) == 0) {
            ip_str = argv[i] + 11;                   /* --local-ip=1.2.3.4 */
        } else if (strcmp(argv[i], "--local-ip") == 0 && i + 1 < argc) {
            ip_str = argv[++i];                       /* --local-ip 1.2.3.4 */
        }
        if (ip_str != NULL) {
            struct in_addr addr;
            if (inet_aton(ip_str, &addr) != 0) {
                gLocalIp = addr.s_addr;
                printf("应用参数: local-ip = %s (0x%08x)\n", ip_str, gLocalIp);
            } else {
                printf("无效 IP 地址: %s，使用默认值\n", ip_str);
            }
            continue;
        }

        /* 支持 --local-port=X 和 --local-port X 两种格式 */
        const char *port_str = NULL;
        if (strncmp(argv[i], "--local-port=", 13) == 0) {
            port_str = argv[i] + 13;                  /* --local-port=8888 */
        } else if (strcmp(argv[i], "--local-port") == 0 && i + 1 < argc) {
            port_str = argv[++i];                      /* --local-port 8888 */
        }
        if (port_str != NULL) {
            int port = atoi(port_str);
            if (port > 0 && port <= 65535) {
                gAppPort = (uint16_t)port;
                printf("应用参数: local-port = %d\n", port);
            }
        }
    }

    /* 如果未设置，使用默认值 */
    if (gLocalIp == 0) {
        gLocalIp = DEFAULT_LOCAL_IP;
        struct in_addr addr;
        addr.s_addr = gLocalIp;
        printf("未指定 --local-ip，使用默认: %s\n", inet_ntoa(addr));
    }
    if (gAppPort == 0) {
        gAppPort = DEFAULT_LOCAL_PORT;
    }
}

/* 获取应用层设置的端口 (供 udp_server_entry 使用) */
uint16_t app_get_port(void)
{
    return gAppPort ? gAppPort : DEFAULT_LOCAL_PORT;
}
