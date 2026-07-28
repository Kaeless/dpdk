#ifndef __UDP_LOG_H__
#define __UDP_LOG_H__

#include <rte_log.h>

/*
 * =====================================================
 *  UDP Server — DPDK 原生日志系统封装
 * =====================================================
 *
 *  使用 DPDK 内置的 RTE_LOG 替代 printf，支持:
 *    - 日志级别过滤 (EMERG / ALERT / CRIT / ERR / WARNING / NOTICE / INFO / DEBUG)
 *    - 自动时间戳和日志级别前缀
 *    - 输出重定向到文件 (通过 rte_openlog_stream)
 *
 *  用法:
 *    UDP_LOG_INFO("recv from %s:%d, data:%s", ip, port, buf);
 *    UDP_LOG_ERR("socket creation failed");
 *    UDP_LOG_DEBUG("arp reply from %s", ip);
 */

/* ---- 自定义日志类型 ---- */
#define RTE_LOGTYPE_UDP_SERVER RTE_LOGTYPE_USER1

/* ---- 便捷宏 ---- */
/* 通用日志宏 (自动追加换行) */
#define UDP_LOG(level, fmt, args...) \
    RTE_LOG(level, UDP_SERVER, "udp_server: " fmt "\n", ##args)

/* 按级别分类的便捷宏 */
#define UDP_LOG_EMERG(fmt, args...)   UDP_LOG(EMERG, fmt, ##args)
#define UDP_LOG_ALERT(fmt, args...)   UDP_LOG(ALERT, fmt, ##args)
#define UDP_LOG_CRIT(fmt, args...)    UDP_LOG(CRIT, fmt, ##args)
#define UDP_LOG_ERR(fmt, args...)     UDP_LOG(ERR, fmt, ##args)
#define UDP_LOG_WARNING(fmt, args...) UDP_LOG(WARNING, fmt, ##args)
#define UDP_LOG_NOTICE(fmt, args...)  UDP_LOG(NOTICE, fmt, ##args)
#define UDP_LOG_INFO(fmt, args...)    UDP_LOG(INFO, fmt, ##args)
#define UDP_LOG_DEBUG(fmt, args...)   UDP_LOG(DEBUG, fmt, ##args)

/*
 * udp_log_init — 初始化 DPDK 日志系统
 * @log_dir: 日志文件输出目录 (例如 "log")
 * return:   0 成功, -1 失败
 *
 * 功能:
 *   1. 注册 UDP_SERVER 自定义日志类型
 *   2. 设置全局日志级别为 INFO
 *   3. 创建日志目录 (如不存在)
 *   4. 将 DPDK 日志输出重定向到 log_dir/udp_server.log
 */
int udp_log_init(const char *log_dir);

#endif /* __UDP_LOG_H__ */
