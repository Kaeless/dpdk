#ifndef __ARP_H__
#define __ARP_H__

#include "init/dpdk_init.h"

/* ---- ARP 条目类型 ---- */
#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

/* ---- 双向链表宏 ---- */
#define LL_ADD(item, list) do {         \
    item->prev = NULL;                  \
    item->next = list;                  \
    if (list != NULL) list->prev = item;\
    list = item;                        \
} while(0)

#define LL_REMOVE(item, list) do {                          \
    if (item->prev != NULL) item->prev->next = item->next;  \
    if (item->next != NULL) item->next->prev = item->prev;  \
    if (list == item) list = item->next;                    \
    item->prev = item->next = NULL;                         \
} while(0)

/* ---- ARP 表条目 ---- */
struct arp_entry {
    uint32_t ip;
    uint8_t  hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t  type;

    struct arp_entry *next;
    struct arp_entry *prev;
};

struct arp_table {
    struct arp_entry *entries;
    int count;
};

/* ---- 函数声明 ---- */
struct arp_table *arp_table_instance(void);
uint8_t *ng_get_dst_macaddr(uint32_t dip);

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode,
    uint8_t *dst_mac, uint32_t sip, uint32_t dip);

void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg);

#endif /* __ARP_H__ */
