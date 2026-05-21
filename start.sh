sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -P FORWARD ACCEPT
