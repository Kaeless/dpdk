#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <rte_ether.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

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

