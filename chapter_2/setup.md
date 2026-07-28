## 配置命令
'''
sudo nmcli con mod "Wired connection 2" ipv4.method manual \
    ipv4.addresses 192.168.76.200/20 \
    ipv4.gateway 192.168.64.254 \
    ipv4.dns "223.5.5.5 119.29.29.29"
'''

sudo nmcli con up "Wired connection 2"
