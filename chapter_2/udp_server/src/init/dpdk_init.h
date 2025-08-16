
#ifndef __DPDK_INIT_H__
#define __DPDK_INIT_H__

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <rte_ether.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#define NUM_MBUFS (4096 - 1)
#define BUFFER_SIZE 2048
#define RING_SIZE 1024
#define BURST_SIZE 32
#define DEFAULT_FD 3

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define ENABLE_PRINT 1

extern struct localhost *lhost;
extern int gDpdkPortId;
extern uint32_t gLocalIp;
extern struct rte_ether_addr gLocalMac[RTE_ETHER_ADDR_LEN];

struct inout_ring{
    struct rte_ring* in_ring;
    struct rte_ring* out_ring;
};

static struct inout_ring* rInst = NULL;


static struct inout_ring* ringInstance(void){
    if(rInst == NULL){
        rInst = rte_malloc("in/out ring",sizeof(struct inout_ring),0);
        memset(rInst,0,sizeof(struct inout_ring));
    }
    return rInst;
}

/**
 * @brief 包括Mac地址 IP地址 端口号
 * 
 */
static struct ether_addr{
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint32_t ip;
    uint16_t port;
};


struct localhost{

    int fd;

    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint32_t localip;
    uint16_t localport;

    int protocol;
    
    struct rte_ring *sendbuf;
    struct rte_ring *recvbuf;

    //多个连接的localhost
    struct localhost *prev;
    struct localhost *next;
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};

void dpdk_init_port(struct rte_mempool* mbuf_pool);

void print_ether_addr(const char* what,const struct rte_ether_addr* eth_addr);


#endif