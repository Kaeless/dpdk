# 07_udp — DPDK UDP 协议栈 (对比测试)

## 概述

本示例包含两个独立程序：
- **udp.c** (dpdk_udp) — 基于 DPDK 的用户态 UDP 服务器（与 06_netarch 架构相同）
- **unix_udp.c** — 标准 POSIX socket 实现的 UDP Echo Server（用于对比测试）

**构建目标**: `dpdk_udp`

编译运行



## 架构

```
┌─────────────────────────────────────────────────────────┐
│ udp.c (DPDK 用户态 UDP 协议栈)                          │
│                                                         │
│ 与 06_netarch 完全相同：                                 │
│   - 多线程 (main + worker + UDP app)                    │
│   - Ring buffer 通信                                     │
│   - ARP 表 + ICMP 支持                                  │
│   - nsocket/nbind/nrecvfrom/nsendto 用户态 socket API    │
│                                                         │
│ udp_server_entry() @ lcore 2:                           │
│   - 监听 UDP 端口 8889                                   │
│   - 收到数据后回显 (echo)                                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ unix_udp.c (标准 POSIX UDP Echo Server)                 │
│                                                         │
│ main():                                                 │
│   socket(AF_INET, SOCK_DGRAM, 0)                       │
│   bind(8889, 192.168.0.116)                            │
│   while(1): recvfrom() → printf() → sendto() (echo)    │
│   close()                                               │
└─────────────────────────────────────────────────────────┘
```

## 数据流 (udp.c — DPDK 版本)

```
(同 06_netarch)
RX: 网卡 → ring->in → pkt_process() → udp_process() → rcvbuf → nrecvfrom() → app
TX: app → nsendto() → sndbuf → udp_out() → ring->out → 网卡
```

## 数据流 (unix_udp.c — 标准版本)

```
内核网络栈 → recvfrom() → printf 打印 → sendto() → 内核网络栈
```

## 函数详解 (unix_udp.c)

### `main(int argc, char *argv[])`
标准 POSIX UDP Echo Server。

**流程:**
1. `socket(AF_INET, SOCK_DGRAM, 0)` — 创建 UDP 套接字
2. `bind(connfd, ..., 8889)` — 绑定 192.168.0.116:8889
3. 循环 `recvfrom()` 接收数据，`sendto()` 回显
4. `close(connfd)` — 清理

**与 udp.c 区别:**
- 走标准内核 TCP/IP 协议栈而非 DPDK 用户态协议栈
- 使用标准 POSIX socket API 而非自定义的 nsocket/nbind 等 hook

## 关键对比

| 特性 | udp.c | unix_udp.c |
|------|-------|------------|
| 协议栈 | 用户态 (DPDK) | 内核态 (POSIX) |
| 数据路径 | 绕过内核 | 经过内核 |
| 收包方式 | rte_eth_rx_burst | recvfrom |
| 发包方式 | rte_eth_tx_burst | sendto |
| 阻塞机制 | pthread_cond_wait | 内核阻塞 |
| 多线程 | 3 个 lcore | 1 个线程 |

## 编译宏 (udp.c)

与 06_netarch 完全相同 (`ENABLE_RINGBUFFER`, `ENABLE_MULTHREAD`, `ENABLE_UDP_APP` 等)。
