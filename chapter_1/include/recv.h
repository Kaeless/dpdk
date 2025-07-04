#include <dpdk.h>

/* 信号处理函数 */
void sig_handler(int signum);

/* 初始化以太网端口 */
int port_init(uint16_t port);

/* 创建新连接 */
struct tcp_connection *create_connection(uint32_t src_ip, uint16_t src_port,
        uint32_t dst_ip, uint16_t dst_port);

/* 查找连接 */
struct tcp_connection *find_connection(uint32_t src_ip, uint16_t src_port,
        uint32_t dst_ip, uint16_t dst_port);

/* 处理TCP SYN包 */
void handle_tcp_syn(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph);

/* 处理TCP ACK包 */
void handle_tcp_ack(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph);

/* 处理TCP FIN包 */
void handle_tcp_fin(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *tcph);

/* 处理数据包 */
void process_packet(struct rte_mbuf *m);

/* 主处理循环 */
void main_loop(void);

/* 解析服务器IP地址参数 */
int parse_ip_addr(const char *arg);

/* 解析命令行参数 */
int parse_args(int argc, char **argv);