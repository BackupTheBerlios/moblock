#
# MoBlock.sh - MoBlock start script
# ---------------------------------

# Be sure needed modules are loaded
# Change ipt_NFQUEUE in ip_queue if you want to use the old interface

modprobe ipt_NFQUEUE
modprobe ipt_state

# Filter all traffic, edit for your needs

iptables -A INPUT -p all -m state --state NEW -j NFQUEUE
iptables -A OUTPUT -p all -m state --state NEW -j NFQUEUE

# Loopback traffic fix, see readme

iptables -I INPUT -p all -i lo -j ACCEPT
iptables -I OUTPUT -p all -o lo -j ACCEPT

# Here you can change block list and log files
./MoBlock /etc/guarding.p2p ./MoBlock.log

# On exit delete the rules we added

iptables -D INPUT -p all -m state --state NEW -j NFQUEUE
iptables -D OUTPUT -p all -m state --state NEW -j NFQUEUE
iptables -D INPUT -p all -i lo -j ACCEPT
iptables -D OUTPUT -p all -o lo -j ACCEPT
