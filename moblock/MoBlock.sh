#
# MoBlock.sh - MoBlock start script
# ---------------------------------

# Be sure needed modules are loaded

modprobe ip_queue
modprobe ipt_state

# Filter all traffic, edit for your needs

iptables -A INPUT -p all -m state --state NEW -j QUEUE
iptables -A OUTPUT -p all -m state --state NEW -j QUEUE

# Loopback traffic fix, see readme

iptables -I INPUT -p all -i lo -j ACCEPT
iptables -I OUTPUT -p all -o lo -j ACCEPT

# Here you can change block list and log files
./MoBlock /etc/guarding.p2p ./MoBlock.log

# On exit delete the rules we added

iptables -D INPUT -p all -m state --state NEW -j QUEUE
iptables -D OUTPUT -p all -m state --state NEW -j QUEUE
iptables -D INPUT -p all -i lo -j ACCEPT
