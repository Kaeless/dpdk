#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <rte_ether.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#define BUFFER_SIZE 2048



int udp_server_entry(int argc,char* argv[]){
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

    return udp_server_entry(argc,argv);
}