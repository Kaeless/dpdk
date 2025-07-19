#include "multi_thread.h"

int pkt_process(void *arg){

    struct rte_mempool *mbuf_pool =(struct rte_mempool *) arg;
    struct inout_ring *ring = ringInstance();

    while(1){

    }
}