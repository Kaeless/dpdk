# ============================================================
# DPDK 开发容器 — Ubuntu 22.04 + libdpdk-dev + PCAP PMD
# ============================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends \
    # 编译工具
    build-essential pkg-config make gcc \
    # DPDK 库
    libdpdk-dev \
    # PCAP PMD 依赖 (不需真实网卡就能测试)
    libpcap-dev \
    # 调试工具
    iproute2 netcat-openbsd tcpdump iputils-ping \
    vim less \
    && apt clean && rm -rf /var/lib/apt/lists/*

# 确认 DPDK 版本
RUN pkg-config --modversion libdpdk

WORKDIR /app
COPY . /app/

# 编译
RUN cd /app && make clean && make

# 启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
