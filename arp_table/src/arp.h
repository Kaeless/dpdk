

#ifndef __ARP_H__
#define __ARP_H__

#include <init/dpdk_init.h>

struct arp_entry{
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t status;

    arp_entry* next;
}arp_entry;


struct arp_table{

};

#endif