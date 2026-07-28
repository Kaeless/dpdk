# ============================================================
# DPDK UDP Server Makefile — Ubuntu 22.04 / DPDK 21.11+
# ============================================================
#
# 依赖: sudo apt install libdpdk-dev
# 使用 pkg-config 管理编译/链接参数

APP     := dpdk_udp
BUILD   := build

# ---- 源文件 (按模块组织) ----
SRCS := src/udp_server.c              \
        src/init/dpdk_init.c          \
        src/arp/arp.c                 \
        src/icmp/icmp.c               \
        src/udp/udp.c                 \
        src/pkt_process/pkt_process.c

OBJS := $(SRCS:%.c=$(BUILD)/%.o)
DEPS := $(OBJS:.o=.d)

# ---- 编译工具链 ----
CC      := gcc
PKG_CFG := pkg-config

# ---- 编译选项 ----
CFLAGS  := -Wall -Wextra -O3 -march=native
CFLAGS  += $(shell $(PKG_CFG) --cflags libdpdk)
CFLAGS  += -Isrc
CFLAGS  += -Wno-address-of-packed-member

# ---- 链接选项 ----
LDFLAGS := $(shell $(PKG_CFG) --libs libdpdk)
LDFLAGS += -lpthread

# ---- 构建规则 ----
.PHONY: all clean check

all: $(BUILD)/$(APP)

# 链接
$(BUILD)/$(APP): $(OBJS)
	@mkdir -p $(dir $@)
	@echo "  LINK    $@"
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# 编译
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(CC) $(CFLAGS) -MMD -c $< -o $@

# 自动依赖
-include $(DEPS)

# ---- 清理 ----
clean:
	rm -rf $(BUILD)
	@echo "已清理"

# ---- 环境检查 ----
check:
	@echo "=== 环境检查 ==="
	@echo -n "DPDK 版本:      "; $(PKG_CFG) --modversion libdpdk 2>/dev/null || echo "未安装"
	@echo -n "GCC 版本:       "; $(CC) --version | head -1
	@echo -n "Hugepages:      "; grep HugePages_Total /proc/meminfo 2>/dev/null || echo "N/A"
	@echo "=================="
