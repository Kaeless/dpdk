#ifndef __ARP_H__
#define __ARP_H__

#include "../init/dpdk_init.h"


#define LL_ADD(item, list) do { \
	item->prev = NULL; \
	item->next = list; \
	if (list != NULL) list->prev = item; \
	list = item; \
}while (0)

#define LL_REMOVE(item, list) do { \
    if (item->next != NULL) item->prev->next = item->next; \
    if (item->prev != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL; \
}while (0) 

struct arp_entry;
struct arp_entry {
	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
	uint8_t status;

	struct arp_entry* next;
	struct arp_entry* prev;
};

struct arp_table {
	struct arp_entry* entries;
	int count;
};

static struct arp_table* arpt = NULL;

static struct arp_table* arp_table_instance(void) {
	if (arpt == NULL) {
		arpt = rte_malloc("arp table", sizeof(struct arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct arp_table));
	}
	return arpt;
}

static uint8_t* ng_get_dst_macaddr(uint32_t dip) {
	struct arp_entry* iter;
	struct arp_table* table = arp_table_instance();
	for (iter = table->entries; iter != NULL; iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}
	return NULL;
}

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t arp_opcode, uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = rte_cpu_to_be_16(arp_opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return 0;

}

static struct rte_mbuf* ng_send_arp(struct rte_mempool *mbuf_pool,uint16_t arp_opcode, uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data,arp_opcode,src_mac,dst_mac,sip,dip);

	return mbuf;
}
#endif