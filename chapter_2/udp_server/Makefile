# 必须先定义DPDK的安装路径
ifeq ($(RTE_SDK),)
$(error "请设置RTE_SDK环境变量指向DPDK安装目录，或在Makefile中直接定义")
endif

# DPDK目标平台（19.11版本仍支持linuxapp）
RTE_TARGET ?= x86_64-native-linuxapp-gcc

# 引入DPDK变量定义
include $(RTE_SDK)/mk/rte.vars.mk

# 源文件目录
SRC_DIR = ../src
BUILD_DIR = build

# DPDK约定：指定可执行文件名和源文件
APP = udp_server
# SRCS-y := $(shell find $(SRC_DIR) -name "*.c")  # 用SRCS-y而非SRCS

SRCS-y := src/udp_server.c \
			src/arp/arp.c \
			src/icmp/icmp.c \
			src/init/dpdk_init.c \
			src/multi_thread/pkt_process.c \
			src/udp/udp.c \

# 编译选项
CFLAGS += -I$(SRC_DIR) -Wall -O3 -Wno-unused-function
LDFLAGS += -lpthread

# 指定输出目录（可选）
RTE_OUTPUT := $(BUILD_DIR)

# DPDK应用程序编译规则（必须放在最后）
include $(RTE_SDK)/mk/rte.extapp.mk

# 删除以下内容
clean:
	rm -rf $(BUILD_DIR)
	@echo "已清理所有生成文件"

# 伪目标
.PHONY: all clean