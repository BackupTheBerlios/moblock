modprobe ip_queue
modprobe ipt_state
iptables -A INPUT -p udp -m state --state NEW -j QUEUE
iptables -A OUTPUT -p udp -m state --state NEW -j QUEUE
iptables -A INPUT -p tcp -m state --state NEW -j QUEUE
iptables -A OUTPUT -p tcp -m state --state NEW -j QUEUE
iptables -I INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -I INPUT -p udp -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT

# Here you can change block list and log files
./MoBlock /etc/guarding.p2p ./MoBlock.log

iptables -D INPUT -p udp -m state --state NEW -j QUEUE
iptables -D OUTPUT -p udp -m state --state NEW -j QUEUE
iptables -D INPUT -p tcp -m state --state NEW -j QUEUE
iptables -D OUTPUT -p tcp -m state --state NEW -j QUEUE
iptables -D INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -D INPUT -p udp -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
