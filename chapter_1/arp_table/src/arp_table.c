#include "arp.h"

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#define ARP_ENTRY_STATUS_DYNAMIC 0
#define ARP_ENTRY_STATUS_STATIC 1

#define ENABLE_DEBUG 1

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 1, 120);
static struct rte_ether_addr gSrcMac[RTE_ETHER_ADDR_LEN];

/* arp table timer callback */
static void
arp_table_timer_cb(__attribute__((unused)) struct rte_timer *tim,void *arg) 
{
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

	unsigned lcore_id = rte_lcore_id();
	struct rte_ether_addr broadcast_addr = {{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}};
	struct rte_mbuf* arpbuf = NULL;

	//掩码默认为255.255.255.0
	for(int i = 1;i<254;i++){
		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i<<24));
		uint8_t* dstmac = ng_get_dst_macaddr(dstip);

		struct in_addr addr;
		addr.s_addr = gLocalIp;
		printf("arp send src_ip:%s ",inet_ntoa(addr));
		addr.s_addr = dstip;
		printf("dst_ip:%s \n",inet_ntoa(addr));


		
		if(dstmac == NULL){
			arpbuf = ng_send_arp(mbuf_pool,RTE_ARP_OP_REQUEST,gSrcMac->addr_bytes, broadcast_addr.addr_bytes, 
				gLocalIp,dstip);
		}
		else{
			arpbuf = ng_send_arp(mbuf_pool,RTE_ARP_OP_REQUEST,gSrcMac->addr_bytes, dstmac, 
				gLocalIp, dstip);
		}
		rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		rte_pktmbuf_free(arpbuf);
	}
	printf("%s() on lcore %u\n", __func__, lcore_id);

}


int main(int argc, char *argv[]){
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
		
	}
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
	ng_init_port(mbuf_pool);
	
	if(rte_eth_macaddr_get(gDpdkPortId,gSrcMac)<0){
		rte_exit(EXIT_FAILURE, "Could not get NIC mac address\n");
	}
	print_ether_addr("dpdk NIC src_mac:",gSrcMac);
	//init complete


	//启动定时器
	static uint64_t timer_resolution_cycles;
	static struct rte_timer timer0;
	uint64_t hz;
	unsigned lcore_id;

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	rte_timer_init(&timer0);

	hz = rte_get_timer_hz();
	timer_resolution_cycles = hz * 10; /* around 1min */

	/* load timer0, every second, on main lcore, reloaded automatically */
	lcore_id = rte_lcore_id();
	rte_timer_reset(&timer0, hz, PERIODICAL, lcore_id, arp_table_timer_cb, mbuf_pool);

	while(1){
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {
		struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
#if ENABLE_ARP

		if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {

			struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
				struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
			
			struct in_addr addr;
			addr.s_addr = ahdr->arp_data.arp_tip;
			printf("arp ---> src: %s ", inet_ntoa(addr));

			addr.s_addr = gLocalIp;
			printf(" local: %s \n", inet_ntoa(addr));

			if (ahdr->arp_data.arp_tip == gLocalIp) {
			if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){
				struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool,RTE_ARP_OP_REPLY,gSrcMac->addr_bytes, ahdr->arp_data.arp_sha.addr_bytes, 
					ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

				rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
				rte_pktmbuf_free(arpbuf);

				rte_pktmbuf_free(mbufs[i]);				
			}
			else if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){
				printf("arp --> reply\n");
				struct arp_table* table = arp_table_instance();
				uint8_t* hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
				if(hwaddr == NULL){
					struct arp_entry* entry = rte_malloc("arp entry",sizeof(struct arp_entry),0);

					if(entry){
						memset(entry,0,sizeof(struct arp_entry));
						entry->ip = ahdr->arp_data.arp_sip;
						rte_memcpy(entry->hwaddr,ahdr->arp_data.arp_sha.addr_bytes,RTE_ETHER_ADDR_LEN);
						entry->status = ARP_ENTRY_STATUS_DYNAMIC;

						LL_ADD(entry,table->entries);
						table->count++;
					}
					}
#if ENABLE_DEBUG
					struct arp_entry* iter;
					for (iter = table->entries; iter != NULL; iter = iter->next) {
						print_ether_addr("arp entry --> mac:",(struct rte_ether_addr*)iter->hwaddr);
						struct in_addr addr;
						addr.s_addr = iter->ip;
						printf("ip addr : %s\n",inet_ntoa(addr));
#endif
				}
				}
			}
			continue;
		} 
#endif		
		}
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > timer_resolution_cycles) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

	}
	return 0;
}