#!/bin/sh

########## Networking ##########

# increase the maximum length of processor input queues
echo "net.core.netdev_max_backlog = 250000" | sudo tee -a /etc/sysctl.conf > /dev/null

# enable BPF JIT hardening for all users
# this trades off performance, but can mitigate JIT spraying
echo "net.core.bpf_jit_harden = 2" | sudo tee -a /etc/sysctl.conf > /dev/null

# increase TCP max buffer size setable using setsockopt()
echo "net.core.rmem_max = 8388608" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.core.wmem_max = 8388608" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.core.rmem_default = 8388608" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.core.wmem_default = 8388608" | sudo tee -a /etc/sysctl.conf > /dev/null
#net.core.optmem_max = 40960

########## IPv4 Networking ##########

# enable BBR congestion control
## NOT AVAILABLE ON UDM-PRO
# net.ipv4.tcp_congestion_control = bbr

# Configure SYNCookies (protects against SYN floods)
echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_synack_retries = 5" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_max_syn_backlog = 2048" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_syn_retries = 5" | sudo tee -a /etc/sysctl.conf > /dev/null

# Enable packet spoof protection (via source address verification)
## enable reverse path source validation (BCP38)
## refer to RFC1812, RFC2827, and BCP38 (http://www.bcp38.info)
echo "net.ipv4.conf.default.rp_filter=1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.conf > /dev/null

# do not send redirects
echo "net.ipv4.conf.default.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# do not accept packets with SRR option
echo "net.ipv4.conf.default.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# disable sending and receiving of shared media redirects
# this setting overwrites net.ipv4.conf.all.secure_redirects
# refer to RFC1620
echo "net.ipv4.conf.default.shared_media = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.shared_media = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# always use the best local address for announcing local IP via ARP
echo "net.ipv4.conf.default.arp_announce = 2" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.arp_announce = 2" | sudo tee -a /etc/sysctl.conf > /dev/null

# reply only if the target IP address is local address configured on the incoming interface
echo "net.ipv4.conf.default.arp_ignore = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.arp_ignore = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# drop Gratuitous ARP frames to prevent ARP poisoning
# this can cause issues when ARP proxies are used in the network
echo "net.ipv4.conf.default.drop_gratuitous_arp = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.drop_gratuitous_arp = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# mitigate TIME-WAIT Assassination hazards in TCP
# refer to RFC1337
echo "net.ipv4.tcp_rfc1337 = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# enabling SACK can increase the throughput
# but SACK is commonly exploited and rarely used
echo "net.ipv4.tcp_sack = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_dsack = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_fack = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# disable TCP window scaling
# this makes the host less susceptible to TCP RST DoS attacks
echo "net.ipv4.tcp_window_scaling = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# divide socket buffer evenly between TCP window size and application
echo "net.ipv4.tcp_adv_win_scale = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# increase system IP port limits
echo "net.ipv4.ip_local_port_range = 1024 65535" | sudo tee -a /etc/sysctl.conf > /dev/null

# SSR could impact TCP's performance on a fixed-speed network (e.g., wired)
#   but it could be helpful on a variable-speed network (e.g., LTE)
# uncomment this if you are on a fixed-speed network
echo "net.ipv4.tcp_slow_start_after_idle = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# TCP timestamps could provide protection against wrapped sequence numbers,
#   but the host's uptime can be calculated precisely from its timestamps
# it is also possible to differentiate operating systems based on their use of timestamps
# - 0: disable TCP timestamps
# - 1: enable timestamps as defined in RFC1323 and use random offset for
#        each connection rather than only using the current time
# - 2: enable timestamps without random offsets
echo "net.ipv4.tcp_timestamps = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# enabling MTU probing helps mitigating PMTU blackhole issues
# this may not be desirable on congested networks
echo "net.ipv4.tcp_mtu_probing = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_base_mss = 1024" | sudo tee -a /etc/sysctl.conf > /dev/null

# increase memory thresholds to prevent packet dropping
# net.ipv4.tcp_rmem = 1024 2048 4096  # 87380 8388608
echo "net.ipv4.tcp_rmem = 1024 2048 4096" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_wmem = 1024 2048 4096" | sudo tee -a /etc/sysctl.conf > /dev/null

# ICMP rate-limiting
echo "net.ipv4.icmp_ratelimit 100" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.icmp_ratemask 88089" | sudo tee -a /etc/sysctl.conf > /dev/null

########## IPv6 Networking ##########

# disallow IPv6 packet forwarding
echo "net.ipv6.conf.default.forwarding = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.forwarding = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# number of Router Solicitations to send until assuming no routers are present
echo "net.ipv6.conf.default.router_solicitations = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.router_solicitations = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# do not accept Router Preference from RA
echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.accept_ra_rtr_pref = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# learn prefix information in router advertisement
echo "net.ipv6.conf.default.accept_ra_pinfo = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.accept_ra_pinfo = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# setting controls whether the system will accept Hop Limit settings from a router advertisement
echo "net.ipv6.conf.default.accept_ra_defrtr = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.accept_ra_defrtr = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# router advertisements can cause the system to assign a global unicast address to an interface
echo "net.ipv6.conf.default.autoconf = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.autoconf = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# number of neighbor solicitations to send out per address
echo "net.ipv6.conf.default.dad_transmits = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.dad_transmits = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# number of global unicast IPv6 addresses can be assigned to each interface
echo "net.ipv6.conf.default.max_addresses = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.max_addresses = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# enable IPv6 Privacy Extensions (RFC3041) and prefer the temporary address
echo "net.ipv6.conf.default.use_tempaddr = 2" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.use_tempaddr = 2" | sudo tee -a /etc/sysctl.conf > /dev/null

# ignore IPv6 ICMP redirect messages
echo "net.ipv6.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# do not accept packets with SRR option
echo "net.ipv6.conf.default.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# ignore all ICMPv6 echo requests
#net.ipv6.icmp.echo_ignore_all = 1
#net.ipv6.icmp.echo_ignore_anycast = 1
#net.ipv6.icmp.echo_ignore_multicast = 1


########## ICMP Networking ##########

# Ignore ICMP redirects from non-GW hosts
echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.secure_redirects=1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.default.secure_redirects=1" | sudo tee -a /etc/sysctl.conf > /dev/null

# Ignore bogus ICMP errors
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" | sudo tee -a /etc/sysctl.conf > /dev/null

# Ignore ICMP broadcasts to avoid participating in Smurf attacks
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" | sudo tee -a /etc/sysctl.conf > /dev/null

# Do not accept ICMP redirects (prevent MITM attacks)
echo "net.ipv4.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null

# Log Martian Packets
## spoofed, source-routed, and redirect packets
echo "net.ipv4.conf.all.log_martians=1" | sudo tee -a /etc/sysctl.conf > /dev/null


########## File System ##########

# disallow core dumping by SUID/SGID programs
echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# protect the creation of hard links
# one of the following conditions must be fulfilled
#   - the user can only link to files that he or she owns
#   - the user must first have read and write access to a file, that he/she wants to link to
echo "fs.protected_hardlinks = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# protect the creation of symbolic links
# one of the following conditions must be fulfilled
#   - the process following the symbolic link is the owner of the symbolic link
#   - the owner of the directory is also the owner of the symbolic link
echo "fs.protected_symlinks = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# enable extended FIFO protection
echo "fs.protected_fifos = 2" | sudo tee -a /etc/sysctl.conf > /dev/null

# similar to protected_fifos, but it avoids writes to an attacker-controlled regular file
echo "fs.protected_regular = 2" | sudo tee -a /etc/sysctl.conf > /dev/null


########## Kernel ##########

# enable ASLR
# turn on protection and randomize stack, vdso page and mmap + randomize brk base address
echo "kernel.randomize_va_space=2" | sudo tee -a /etc/sysctl.conf > /dev/null

# controls the System Request debugging functionality of the kernel
echo "kernel.sysrq = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# restrict access to kernel address
# kernel pointers printed using %pK will be replaced with 0’s regardless of privileges
echo "kernel.kptr_restrict = 2" | sudo tee -a /etc/sysctl.conf > /dev/null

# Reboot the machine soon after a kernel panic.
echo "kernel.panic=10" | sudo tee -a /etc/sysctl.conf > /dev/null

# Ptrace protection using Yama
#   - 1: only a parent process can be debugged
#   - 2: only admins canuse ptrace (CAP_SYS_PTRACE capability required)
#   - 3: disables ptrace completely, reboot is required to re-enable ptrace
# echo "kernel.yama.ptrace_scope = 3" | sudo tee -a /etc/sysctl.conf > /dev/null

# restrict kernel logs to root only
echo "kernel.dmesg_restrict = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# restrict BPF JIT compiler to root only
# echo "kernel.unprivileged_bpf_disabled = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# disables kexec as it can be used to livepatch the running kernel
# echo "kernel.kexec_load_disabled = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# disable unprivileged user namespaces to decrease attack surface
# echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a /etc/sysctl.conf > /dev/null

# allow for more PIDs
# this value can be up to:
#   - 32768 (2^15) on a 32-bit system
#   - 4194304 (2^22) on a 64-bit system
# kernel.pid_max = 4194304

# restrict perf subsystem usage
# echo "kernel.perf_event_paranoid = 3" | sudo tee -a /etc/sysctl.conf > /dev/null
# echo "kernel.perf_cpu_time_max_percent = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
# echo "kernel.perf_event_max_sample_rate = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# prevent unprivileged attackers from loading vulnerable line disciplines with the TIOCSETD ioctl
echo "dev.tty.ldisc_autoload = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
