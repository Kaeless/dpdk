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

#define BURST_SIZE 32

#define ENABLE_SEND 1
#define ENABLE_ARP 1
#define ENABLE_ICMP 1
#define ENABLE_PRINT 1

static int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};

void ng_init_port(struct rte_mempool* mbuf_pool);

void print_ether_addr(const char* what,const struct rte_ether_addr* eth_addr);
