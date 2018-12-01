#!/usr/bin/env bash

# 清空原有规则
iptables -F
iptables -X
iptables -Z

# 设置默认规则
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# 端口重定向
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 8888

# 开启转发
echo "1" > /proc/sys/net/ipv4/ip_forward

# 重启网卡
/etc/init.d/networking restart

# 重设DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
