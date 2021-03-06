#!/usr/bin/env bash

# 清空原有规则
iptables -F
iptables -X
iptables -Z

# 设置默认规则
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# 允许相关流量进入防火墙
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 实现内部接口与外部接口之间的数据转发
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 网络地址翻译
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT

# 允许路由与内网通信
iptables -A INPUT -i eth1 -j ACCEPT

# 开启转发
echo "1" > /proc/sys/net/ipv4/ip_forward

# 重启网卡
/etc/init.d/networking restart

# 重设DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
