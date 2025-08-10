#include "init/dpdk_init.h"
#include "arp/arp.h"
#include "icmp/icmp.h"
#include "udp/udp.h"
#include "multi_thread/multi_thread.h"

/*
    实现五个udp api
    1.socket --> nsocket
    2.bind --> nbind
    3.recvfrom --> nrecvfrom
    4.sendto --> nsendto
    5.close --> nclose
*/





static int udp_server_entry(void){
    int connfd = socket(AF_INET,SOCK_DGRAM,0);
    if(connfd == -1){
        rte_exit(EXIT_FAILURE,"sockfd failed\n");
    }

    struct sockaddr_in localaddr;
    memset(&localaddr,0,sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8888);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(connfd,&localaddr,sizeof(localaddr));


    struct sockaddr_in clientaddr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE] = {0};
    while(1){
        if(recvfrom(connfd,buffer,BUFFER_SIZE,0,&clientaddr,&addr_len)<0){
            continue;
        }
        else{
            printf("recv from %s:%d, data:%s\n",inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port),buffer);
            sendto(connfd,buffer,strlen(buffer),0,&clientaddr,sizeof(clientaddr));
        }
    }
    close(connfd);
    return 0;
}


int main(int argc,char* argv[]){

    //dpdk eal init
    if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
    
    //memory buffer init
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
	dpdk_init_port(mbuf_pool);
	
    //get mac addr
	if(rte_eth_macaddr_get(gDpdkPortId,gLocalMac)<0){
		rte_exit(EXIT_FAILURE, "Could not get NIC mac address\n");
	}
    print_ether_addr("dpdk NIC src_mac:",gLocalMac);

    //ring buffer init
    struct inout_ring *ring = ringInstance();
    if(ring == NULL){
        rte_exit(EXIT_FAILURE,"ring buffer init failed\n");
    }
    if(ring->in_ring == NULL){
        ring->in_ring = rte_ring_create("in ring",RING_SIZE,rte_socket_id(),0);
    }
    if(ring->out_ring == NULL){
        ring->out_ring = rte_ring_create("out ring",RING_SIZE,rte_socket_id(),0);
    }


    //arp timer init
	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz*10, PERIODICAL, lcore_id, arp_table_timer_cb, mbuf_pool);


    //DPDK multi_thread
    //packet process thread
    // lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    // rte_eal_remote_launch(pkt_process, mbuf_pool, rte_get_next_lcore(lcore_id,1,0));

    //udp server thread
    // lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    // rte_eal_remote_launch(udp_server_entry, mbuf_pool, rte_get_next_lcore(lcore_id,1,0));

    print_ether_addr("dpdk NIC src_mac:",gLocalMac);

    while(1){
        //rx
        struct rte_mbuf *rx[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId,0,rx,BURST_SIZE);
        if(num_recvd > BURST_SIZE){
            rte_exit(EXIT_FAILURE,"Error receiving from eth\n");
        }
        else if(num_recvd > 0){
            rte_ring_sp_enqueue_burst(ring->in_ring,(void**)rx,num_recvd,NULL);
        }

        //tx
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned num_send = rte_ring_sc_dequeue_burst(ring->out_ring,(void**)tx,BURST_SIZE,NULL);
        if(num_send > 0){
            rte_eth_tx_burst(gDpdkPortId,0,&tx,num_send);
        }
        unsigned i = 0;
        for (i = 0;i < num_send;i ++) {
            rte_pktmbuf_free(tx[i]);
        }
        //timer

    }

    return 0;
}