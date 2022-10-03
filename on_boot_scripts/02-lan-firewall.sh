#!/bin/sh

# (Default) Deny incoming traffic
iptables -P INPUT DROP
# iptables -A INPUT -i eth0 -j DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established sessions to receive incoming traffic
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Block incoming traffic from the modem (static) IP address
## which interface is WAN on udmpro?
# iptables -I INPUT -i eth0 -s 192.168.100.1 -j DROP
iptables -I INPUT -s 192.168.100.1 -j DROP

# Allow LAN traffic
## default network/subnet
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
## primary network/subnet
iptables -A INPUT -s 192.168.2.0/24 -j ACCEPT
## guest network/subnet
iptables -A INPUT -s 192.168.3.0/24 -j ACCEPT

# Rate limiting connections
iptables -A INPUT -m state --state NEW -m limit --limit 100/min --limit-burst 10 -j ACCEPT

# iptables --new-chain RATE-LIMIT
# iptables --append RATE-LIMIT --match hashlimit --hashlimit-upto 5/sec --hashlimit-burst 10 --hashlimit-name conn_rate_limit --jump ACCEPT
# iptables --append RATE-LIMIT --jump DROP

# Rate limiting ICMP echo
# iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT --match limit --limit 10/minute