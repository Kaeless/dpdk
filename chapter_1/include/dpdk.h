#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_spinlock.h>

#define MAX_PORTS 16
#define MAX_LCORES 32
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define SERVER_PORT 8080
#define MAX_CONNECTIONS 4096
#define LISTEN_BACKLOG 128

/* 连接状态定义 */
enum conn_state {
    CONN_CLOSED,
    CONN_LISTEN,
    CONN_SYN_RCVD,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT_1,
    CONN_FIN_WAIT_2,
    CONN_CLOSE_WAIT,
    CONN_LAST_ACK,
    CONN_TIME_WAIT
};

/* TCP连接结构 */
struct tcp_connection {
    uint32_t src_ip;            /* 客户端IP */
    uint32_t dst_ip;            /* 服务器IP */
    uint16_t src_port;          /* 客户端端口 */
    uint16_t dst_port;          /* 服务器端口 */
    enum conn_state state;      /* 连接状态 */
    uint32_t rx_seq;            /* 接收序列号 */
    uint32_t tx_seq;            /* 发送序列号 */
    struct rte_mbuf *rx_buffer; /* 接收缓冲区 */
    uint32_t rx_bytes;          /* 接收字节数 */
    TAILQ_ENTRY(tcp_connection) next; /* 用于连接列表 */
};

/* 哈希表键结构 */
struct conn_hash_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

/* 全局变量 */
static volatile int force_quit = 0;
static struct rte_eth_conf port_conf;
static struct rte_mempool *mbuf_pool;
static struct rte_hash *conn_hash;
static TAILQ_HEAD(, tcp_connection) conn_list;
static rte_spinlock_t conn_lock = RTE_SPINLOCK_INITIALIZER;
static uint32_t server_ip;