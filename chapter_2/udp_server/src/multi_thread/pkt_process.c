#include "multi_thread.h"


int pkt_process(void *arg){

    struct rte_mempool *mbuf_pool =(struct rte_mempool *) arg;
    struct inout_ring *ring = ringInstance();

    while(1){

        struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in_ring, (void**)mbufs, BURST_SIZE, NULL);

        unsigned i = 0;
        for(int i=0;i<num_recvd;i++){
            struct rte_ether_hdr *ehdr= rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr*);

            if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
                arp_process(mbuf_pool,mbufs[i],ring);
            }
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) continue;

            //ip packet process
            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr*,sizeof(struct rte_ether_hdr));

            if(iphdr->next_proto_id == IPPROTO_ICMP){
                icmp_process(mbuf_pool,mbufs[i],ring,ehdr,iphdr);
            }
            else if(iphdr->next_proto_id == IPPROTO_UDP){
                udp_process(mbufs[i],iphdr);
            }
            else if(iphdr->next_proto_id == IPPROTO_TCP){
                continue;
            }
        }
    }
}

void arp_process(struct rte_mempool *mbuf_pool,struct rte_mbuf *mbuf,struct inout_ring *ring){
    struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbuf, 
            struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

#if ENABLE_PRINT
        struct in_addr addr;
        addr.s_addr = ahdr->arp_data.arp_tip;
        printf("arp ---> src: %s ", inet_ntoa(addr));

        addr.s_addr = gLocalIp;
        printf(" local: %s \n", inet_ntoa(addr));
#endif

    if(ahdr->arp_data.arp_tip == gLocalIp){
        if(ahdr->arp_opcode == RTE_ARP_OP_REQUEST){
            struct rte_mbuf *arpbuf = send_arp(mbuf_pool,RTE_ARP_OP_REPLY,gLocalMac, ahdr->arp_data.arp_sha.addr_bytes, 
                ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

            rte_ring_mp_enqueue_burst(ring->out_ring, (void**)&arpbuf, 1, NULL);
        }
        else if(ahdr->arp_opcode == RTE_ARP_OP_REPLY){
            //add arp reply to arp table

            struct arp_table* table = arp_table_instance();
            uint8_t* hwaddr = get_dst_macaddr(ahdr->arp_data.arp_sip);
            if(hwaddr == NULL){
                struct arp_entry* entry = rte_malloc("arp entry",sizeof(struct arp_entry),0);

                if(entry){
                    memset(entry,0,sizeof(struct arp_entry));
                    entry->ip = ahdr->arp_data.arp_sip;
                    rte_memcpy(entry->hwaddr,ahdr->arp_data.arp_sha.addr_bytes,RTE_ETHER_ADDR_LEN);
                    entry->type = ARP_ENTRY_STATUS_DYNAMIC;

                    LL_ADD(entry,table->entries);
                    table->count++;
                }
                }
#if ENABLE_PRINT
                struct arp_entry* iter;
                for (iter = table->entries; iter != NULL; iter = iter->next) {
                    print_ether_addr("arp entry --> mac:",(struct rte_ether_addr*)iter->hwaddr);
                    struct in_addr addr;
                    addr.s_addr = iter->ip;
                    printf("ip addr : %s\n",inet_ntoa(addr));
                }   
#endif

        }
        rte_pktmbuf_free(mbuf);
    }
}


void icmp_process(struct rte_mempool *mbuf_pool,struct rte_mbuf *mbuf,struct inout_ring *ring,struct rte_ether_hdr *ehdr,struct rte_ipv4_hdr *iphdr){
        struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

#if ENABLE_PRINT        
        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("icmp ---> src: %s ", inet_ntoa(addr));
#endif 
        
        if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            addr.s_addr = iphdr->dst_addr;

#if ENABLE_PRINT
            printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
#endif        

            struct rte_mbuf *txbuf = send_icmp(mbuf_pool, gLocalMac,ehdr->s_addr.addr_bytes,
                iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

            rte_ring_mp_enqueue_burst(ring->out_ring, (void**)&txbuf, 1, NULL);
            rte_pktmbuf_free(mbuf);
        }
}

void udp_process(struct rte_mbuf *mbuf,struct rte_ipv4_hdr *iphdr){
        struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

        uint16_t length = ntohs(udphdr->dgram_len);
        *((char*)udphdr + length) = '\0';

#if ENABLE_PRINT
        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

        addr.s_addr = iphdr->dst_addr;
        printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
            (char *)(udphdr+1));
#endif

        
        
        rte_pktmbuf_free(mbuf);    
}