#!/bin/bash
#===============================================================================
# DPDK UDP Server — PCI 直通模式启动脚本
#
# 用法:
#   ./start_pci.sh                    使用默认配置启动
#   ./start_pci.sh -i enp2s0 -a 192.168.100.1 -p 8888
#   ./start_pci.sh --stop             停止服务并恢复网卡到内核
#   ./start_pci.sh --status           查看当前状态
#===============================================================================

set -euo pipefail

# ---- 默认配置 ----
NIC_NAME="ens160"               # 目标网卡接口名
LOCAL_IP="192.168.76.200"        # DPDK 服务端 IP
LOCAL_PORT="8888"               # 监听端口
DPDK_DRIVER="vfio-pci"          # DPDK 用户态驱动: vfio-pci | uio_pci_generic
LCORES="0-2"                    # DPDK lcore 范围
MEMORY_MB="256"                 # hugepage 内存 (MB)
APP_NAME="dpdk_udp"             # 进程名 (用于 kill)
LOG_FILE="/tmp/dpdk_udp.log"    # 日志文件
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# ---- 颜色输出 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---- 用法 ----
usage() {
    cat <<EOF
用法: $0 [选项]

启动:
  $0                                  默认配置启动
  $0 -i <网卡> -a <IP> -p <端口>      自定义配置启动

停止:
  $0 --stop                           停止服务并恢复网卡

状态:
  $0 --status                         查看当前状态

选项:
  -i, --iface    NAME    目标网卡接口名              (默认: ${NIC_NAME})
  -a, --ip       IP      DPDK 服务端 IP               (默认: ${LOCAL_IP})
  -p, --port     PORT    监听端口                     (默认: ${LOCAL_PORT})
  -d, --driver   DRIVER  DPDK 驱动: vfio-pci|uio_pci_generic (默认: ${DPDK_DRIVER})
  -l, --lcores   RANGE   lcore 范围                   (默认: ${LCORES})
  -m, --memory   MB      hugepage 内存 (MB)           (默认: ${MEMORY_MB})
  -h, --help             显示此帮助
EOF
    exit 0
}

# ---- 状态检查 ----
do_status() {
    echo "=========================================="
    echo "  DPDK UDP Server — PCI 直通模式 状态"
    echo "=========================================="
    echo ""

    # 进程状态
    if pgrep -f "${APP_NAME}" > /dev/null 2>&1; then
        info "进程运行中:"
        ps aux | grep "${APP_NAME}" | grep -v grep
    else
        warn "进程未运行"
    fi
    echo ""

    # 网卡绑定状态
    if command -v dpdk-devbind.py &> /dev/null; then
        info "网卡 DPDK 绑定状态:"
        dpdk-devbind.py --status 2>/dev/null | head -20 || true
    else
        warn "dpdk-devbind.py 未找到，无法查询绑定状态"
    fi
    echo ""

    # hugepage
    info "Hugepage 使用情况:"
    grep HugePages /proc/meminfo 2>/dev/null || true
}

# ---- 获取网卡 PCI 地址 ----
get_pci_addr() {
    local iface="$1"
    local pci

    # 通过 sysfs 获取 PCI 地址
    if [ -L "/sys/class/net/${iface}" ]; then
        pci=$(basename "$(readlink -f "/sys/class/net/${iface}/device")" 2>/dev/null)
        if [ -n "$pci" ] && [ "$pci" != "device" ]; then
            echo "$pci"
            return 0
        fi
    fi

    # fallback: 通过 ethtool 获取
    if command -v ethtool &> /dev/null; then
        pci=$(ethtool -i "$iface" 2>/dev/null | awk -F': ' '/bus-info/ {print $2}')
        if [ -n "$pci" ] && [ "$pci" != "0000:00:00.0" ]; then
            echo "$pci"
            return 0
        fi
    fi

    return 1
}

# ---- 获取网卡当前内核驱动 ----
get_kernel_driver() {
    local iface="$1"

    if [ -L "/sys/class/net/${iface}/device/driver" ]; then
        basename "$(readlink -f "/sys/class/net/${iface}/device/driver")" 2>/dev/null
        return 0
    fi
    return 1
}

# ---- 停止服务 ----
do_stop() {
    info "正在停止 DPDK UDP Server..."

    # 杀进程
    if pgrep -f "${APP_NAME}" > /dev/null 2>&1; then
        sudo kill $(pgrep -f "${APP_NAME}") 2>/dev/null || true
        sleep 1
        info "进程已停止"
    else
        info "未找到运行中的进程"
    fi

    # 恢复网卡到内核 (如果已知 PCI 地址和原始驱动)
    local pci
    pci=$(get_pci_addr "${NIC_NAME}") || true
    if [ -n "$pci" ]; then
        # 判断当前是否绑定在 DPDK 驱动上
        local cur_driver
        cur_driver=$(dpdk-devbind.py --status 2>/dev/null | grep "$pci" | grep -oP 'drv=\K[^\s]+' || true)
        if [ "$cur_driver" = "$DPDK_DRIVER" ] || [ "$cur_driver" = "igb_uio" ] || [ "$cur_driver" = "uio_pci_generic" ]; then
            warn "网卡 $pci 当前绑定于 DPDK 驱动 ($cur_driver)，尝试解绑..."
            sudo dpdk-devbind.py -u "$pci" 2>/dev/null || true

            # 尝试恢复原始内核驱动
            local orig_driver=""
            # 根据网卡型号猜测
            local vendor
            vendor=$(lspci -ns "$pci" | cut -d' ' -f3 | cut -d: -f1)
            case "$vendor" in
                8086) orig_driver="ixgbe"  ;;  # Intel
                15b3) orig_driver="mlx5_core" ;;  # Mellanox
                14e4) orig_driver="bnxt_en"    ;;  # Broadcom
                19a2) orig_driver="enic"       ;;  # Cisco
            esac

            if [ -n "$orig_driver" ]; then
                sudo modprobe "$orig_driver" 2>/dev/null || true
                sudo dpdk-devbind.py -b "$orig_driver" "$pci" 2>/dev/null || true
                info "已尝试恢复网卡 $pci 到驱动 $orig_driver"
            else
                warn "无法确定原始驱动，请手动恢复: dpdk-devbind.py -b <driver> $pci"
            fi
        fi
    fi

    # 清理 hugepage
    sudo rm -f /dev/hugepages/rtemap_* /dev/hugepages/udp_* 2>/dev/null || true
    sudo rm -rf /var/run/dpdk/ 2>/dev/null || true
    info "清理完成"
}

# ---- 启动服务 ----
do_start() {
    echo "=========================================="
    echo "  DPDK UDP Server — PCI 直通模式"
    echo "=========================================="
    echo ""
    echo "  网卡:     ${NIC_NAME}"
    echo "  IP:       ${LOCAL_IP}"
    echo "  端口:     ${LOCAL_PORT}"
    echo "  DPDK驱动: ${DPDK_DRIVER}"
    echo "  lcore:    ${LCORES}"
    echo "  内存:     ${MEMORY_MB} MB"
    echo ""

    # 1. 检查网卡是否存在
    if [ ! -d "/sys/class/net/${NIC_NAME}" ]; then
        error "网卡 ${NIC_NAME} 不存在"
    fi
    info "网卡 ${NIC_NAME} 已找到"

    # 2. 获取 PCI 地址
    PCI_ADDR=$(get_pci_addr "${NIC_NAME}")
    if [ -z "${PCI_ADDR}" ]; then
        error "无法获取 ${NIC_NAME} 的 PCI 地址"
    fi
    info "PCI 地址: ${PCI_ADDR}"

    # 3. 保存原始内核驱动 (用于恢复)
    ORIG_DRIVER=$(get_kernel_driver "${NIC_NAME}" || echo "unknown")
    info "原始内核驱动: ${ORIG_DRIVER}"

    # 4. 检查 hugepages
    local nr_huge
    nr_huge=$(grep HugePages_Free /proc/meminfo | awk '{print $2}')
    local need_huge=$((MEMORY_MB / 2))
    if [ "$nr_huge" -lt "$need_huge" ]; then
        warn "空闲 hugepage 不足 (${nr_huge} < ${need_huge})，尝试分配..."
        sudo sh -c "echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
        sudo chmod 777 /dev/hugepages 2>/dev/null || true
    fi
    info "hugepage 空闲: $(grep HugePages_Free /proc/meminfo | awk '{print $2}')"

    # 5. 加载 DPDK 驱动
    if ! lsmod | grep -q "^${DPDK_DRIVER}"; then
        info "加载内核模块: ${DPDK_DRIVER}"
        sudo modprobe "${DPDK_DRIVER}" || error "无法加载 ${DPDK_DRIVER}"
    fi

    # 6. 检查当前绑定状态，避免重复绑定
    local cur_bind
    cur_bind=$(dpdk-devbind.py --status 2>/dev/null | grep "$PCI_ADDR" | grep -oP 'drv=\K[^\s]+' || true)
    if [ "$cur_bind" = "${DPDK_DRIVER}" ]; then
        info "网卡 ${PCI_ADDR} 已绑定于 ${DPDK_DRIVER}，跳过绑定"
    else
        # 7. 停掉网卡
        info "停用内核网卡: ${NIC_NAME}"
        sudo ip link set "${NIC_NAME}" down 2>/dev/null || true

        # 8. 绑定到 DPDK 驱动
        info "绑定 ${PCI_ADDR} -> ${DPDK_DRIVER}"
        sudo dpdk-devbind.py -b "${DPDK_DRIVER}" "${PCI_ADDR}" || \
            error "绑定失败，请检查网卡是否被占用或驱动是否支持"
    fi

    # 9. 编译 (如果需要)
    if [ ! -f "${BUILD_DIR}/dpdk_udp" ]; then
        info "未找到可执行文件，开始编译..."
        make -C "${SCRIPT_DIR}" clean && make -C "${SCRIPT_DIR}"
    fi

    # 10. 清理残留文件
    sudo rm -f /dev/hugepages/rtemap_* /dev/hugepages/udp_* 2>/dev/null || true
    sudo rm -rf /var/run/dpdk/ 2>/dev/null || true

    # 11. 启动 DPDK UDP Server
    info "启动 DPDK UDP Server..."
    sudo "${BUILD_DIR}/dpdk_udp" \
        -l "${LCORES}" -n 4 -m "${MEMORY_MB}" \
        --file-prefix=udp_srv \
        -a "${PCI_ADDR}" \
        -- \
        --local-ip "${LOCAL_IP}" \
        --local-port "${LOCAL_PORT}" \
        > "${LOG_FILE}" 2>&1 &

    sleep 2

    # 12. 验证启动
    if pgrep -f "${APP_NAME}" > /dev/null 2>&1; then
        info "DPDK UDP Server 启动成功 (PID: $(pgrep -f ${APP_NAME} | head -1))"
        info "日志: ${LOG_FILE}"
        echo ""
        info "=========================================="
        info "  从对端机器测试:"
        info "    ping -c 2 ${LOCAL_IP}"
        info "    echo 'HELLO' | nc -u -p 9999 ${LOCAL_IP} ${LOCAL_PORT}"
        info "=========================================="
        echo ""
        info "停止服务并恢复网卡: $0 --stop"
    else
        error "启动失败，请查看日志: ${LOG_FILE}"
    fi
}

# ---- 参数解析 ----
ACTION="start"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stop)
            ACTION="stop"; shift ;;
        --status)
            ACTION="status"; shift ;;
        -i|--iface)
            NIC_NAME="$2"; shift 2 ;;
        -a|--ip)
            LOCAL_IP="$2"; shift 2 ;;
        -p|--port)
            LOCAL_PORT="$2"; shift 2 ;;
        -d|--driver)
            DPDK_DRIVER="$2"; shift 2 ;;
        -l|--lcores)
            LCORES="$2"; shift 2 ;;
        -m|--memory)
            MEMORY_MB="$2"; shift 2 ;;
        -h|--help)
            usage ;;
        *)
            error "未知参数: $1 (使用 -h 查看帮助)" ;;
    esac
done

# ---- 执行 ----
case "$ACTION" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
esac
