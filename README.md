# dpdk
dpdk实战学习,实现udp recv send\arp\icmp等协议栈

## 关于在ubuntu 22.04虚拟机上配置dpdk的流程

1.配置双网卡：网卡1用于绑定dpdk进行通信，网卡2用于与宿主机进行ssh通信

2.打开对应的vmx文件，修改网卡1（ethernet0.virtualDev = "vmxnet3"），增加ethernet0.wakeOnPcktRcv = "TRUE"

3.保存后打开虚拟机，执行以下指令：

