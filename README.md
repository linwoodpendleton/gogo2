# gogo2  自用的防CC防火墙.
使用方法  
其他人勿用.
我占用备份一下

apt-get install libnetfilter-queue-dev libpcap-dev libuv1-dev libglib2.0 make  gcc autoconf libtool -y  
  
  
git clone --recursive https://github.com/maxmind/libmaxminddb  
cd libmaxminddb  
./bootstrap  
./configure  
make  
make check  
make install  
ldconfig  
  
  
gcc CCFW.c -o CCFW  -lpcap -lnetfilter_queue -luv $(pkg-config --cflags --libs glib-2.0) -lmaxminddb -lpthread  
/usr/sbin/iptables -F  
/usr/sbin/iptables -X  
/usr/sbin/iptables -N NFQUEUE_CHAIN  
  
/usr/sbin/iptables -D NFQUEUE_CHAIN -p tcp --sport 80 -j NFQUEUE --queue-num 0  
/usr/sbin/iptables -D NFQUEUE_CHAIN -p tcp --sport 443 -j NFQUEUE --queue-num 0  
  
/usr/sbin/iptables -I INPUT 1 -j NFQUEUE_CHAIN  
  
  
  
/usr/sbin/iptables -D NFQUEUE_CHAIN -p tcp --sport 80 -j NFQUEUE --queue-num 0  
/usr/sbin/iptables -D NFQUEUE_CHAIN -p tcp --sport 443 -j NFQUEUE --queue-num 0  
  
-i 入方向  
-o 出方向  
有docker 的情况  
iptables -A FORWARD -i docker0 -o eth0 -j ACCEPT  
iptables -A FORWARD -i eth0 -o docker0 -j ACCEPT  
  
  
/usr/sbin/iptables -I FORWARD  -p tcp --dport 80 -j NFQUEUE --queue-num 0  
/usr/sbin/iptables -I FORWARD  -p tcp --dport 443 -j NFQUEUE --queue-num 0  
  
/usr/sbin/iptables -I INPUT  -p tcp --dport 80 -j NFQUEUE --queue-num 0  
/usr/sbin/iptables -I INPUT  -p tcp --dport 443 -j NFQUEUE --queue-num 0  
  
/usr/sbin/iptables -D OUTPUT 1 -j NFQUEUE_CHAIN  
  
  
apt-get install ipset  
ipset create blockip hash:ip  timeout 86400  
  
  
iptables  -I INPUT -p tcp -m set --match-set blockip src --dport 80 -j REJECT --reject-with tcp-reset  
iptables  -I INPUT -p tcp -m set --match-set blockip src --dport 443 -j REJECT --reject-with tcp-reset  
  
  
iptables  -I INPUT -p tcp -m set --match-set blockip src --dport 80 -j DROP  
iptables  -I INPUT -p tcp -m set --match-set blockip src --dport 443 -j DROP  
  
  
iptables -t nat -A POSTROUTING ! -o docker0 -s 172.17.0.0/16 -j MASQUERADE  
iptables -t nat -A POSTROUTING -s 172.17.0.2 -p tcp --dport 443 -j MASQUERADE  
iptables -t nat -A POSTROUTING -s 172.17.0.2 -p tcp --dport 80 -j MASQUERADE  
  
  
iptables -t nat -A DOCKER -i docker0 -j RETURN  
iptables -t nat -A DOCKER ! -i docker0 -p tcp --dport 443 -j DNAT --to-destination 172.17.0.2:443  
iptables -t nat -A DOCKER ! -i docker0 -p tcp --dport 80 -j DNAT --to-destination 172.17.0.2:80  
  
  
iptables -t nat -A DOCKER -i docker0 -j RETURN  
iptables -t nat -A DOCKER ! -i docker0 -p tcp --dport 443 -j DNAT --to-destination 172.17.0.2:443  
iptables -t nat -A DOCKER ! -i docker0 -p tcp --dport 80 -j DNAT --to-destination 172.17.0.2:80  
  
iptables -A INPUT -p tcp --dport 80 -j drop  
iptables -A INPUT -p tcp --dport 443 -j drop  
  



