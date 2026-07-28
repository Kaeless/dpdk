#ifndef __DPDK_INIT_H__
#define __DPDK_INIT_H__

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_ring.h>

/* DPDK 21.11+ 协议头需要显式包含 */
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_arp.h>
#include <rte_udp.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "log/udp_log.h"

/* ---- 常量定义 ---- */
#define NUM_MBUFS            (4096 - 1)
#define BURST_SIZE           32
#define RING_SIZE            1024
#define TIMER_RESOLUTION_CYCLES 120000000000ULL

#define MAKE_IPV4_ADDR(a, b, c, d)  (a + (b<<8) + (c<<16) + (d<<24))

#define UDP_APP_RECV_BUFFER_SIZE    128
#define DEFAULT_FD_NUM              3

/* ---- 调试定义 ---- */
#define ENABLE_ARP_TIMER        0
#define ENABLE_ARP              1
#define ARGV_PARSER             1

/* ---- 全局端口 ID ---- */
extern int gDpdkPortId;

/* ---- 本地 IP 和 MAC ---- */
extern uint32_t gLocalIp;
extern uint32_t gSrcIp;
extern uint32_t gDstIp;
extern uint8_t  gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint8_t  gDstMac[RTE_ETHER_ADDR_LEN];
extern uint16_t gSrcPort;
extern uint16_t gDstPort;
extern uint8_t  gDefaultArpMac[RTE_ETHER_ADDR_LEN];

/* ---- Ring buffer 结构 ---- */
struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};

/* ---- localhost: 用户态 socket 抽象 ---- */
struct localhost {
    int fd;

    uint32_t localip;
    uint8_t  localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t protocol;

    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    struct localhost *prev;
    struct localhost *next;

    pthread_cond_t  cond;
    pthread_mutex_t mutex;
};

/* localhost 链表头 */
extern struct localhost *lhost;

/* ---- offload: UDP 数据在 socket 层传递的载体 ---- */
struct offload {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    int      protocol;

    unsigned char *data;
    uint16_t length;
};

/* ---- 函数声明 ---- */

/* 端口初始化 */
void ng_init_port(struct rte_mempool *mbuf_pool);

/* MAC 地址格式化 (返回静态缓冲区指针, 类似 inet_ntoa) */
const char *format_ethaddr(const struct rte_ether_addr *eth_addr);

/* Ring buffer 单例 */
struct inout_ring *ringInstance(void);

/* localhost 查找 */
struct localhost *get_hostinfo_fromfd(int sockfd);
struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto);

/* FD 分配 */
int get_fd_frombitmap(void);

/* 解析应用层命令行参数 (在 rte_eal_init 之后调用) */
void app_parse_args(int argc, char *argv[]);

/* 获取应用层设置的端口 */
uint16_t app_get_port(void);

#endif /* __DPDK_INIT_H__ */
