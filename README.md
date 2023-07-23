# gogo2  自用的防CC防火墙.
使用方法  
其他人勿用.
我占用备份一下
iptables -F  
iptables -X  
iptables -N NFQUEUE_CHAIN  
  
iptables -A NFQUEUE_CHAIN -p tcp --sport 80 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --sport 443 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --sport 6080 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --dport 6080 -j NFQUEUE --queue-num 0  


iptables -A NFQUEUE_CHAIN -p tcp --sport 60443 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --dport 60443 -j NFQUEUE --queue-num 0  
iptables -D INPUT 1 -j NFQUEUE_CHAIN  
iptables -I OUTPUT 1 -j NFQUEUE_CHAIN  


apt-get install libnetfilter-queue-dev  

apt-get install libpcap-dev libuv1-dev

apt-get install libglib2.0-dev。
apt-get install libnetfilter-queue-dev   
apt-get install libpcap-dev libuv1-dev  
apt-get install libglib2.0-dev  
git clone --recursive https://github.com/maxmind/libmaxminddb  
cd libmaxminddb  
./bootstrap  
./configure  
make  
make check  
make install  
ldconfig  
gcc test.c -o test -lpcap -lnetfilter_queue -luv $(pkg-config --cflags --libs glib-2.0) -libmaxminddb  


./test -t 600 -u 86400 -w /home/whitelist.txt

ipset create blockip hash:ip

iptables -I INPUT -m set --match-set blockip src -j DROP

iptables -t nat -I PREROUTING -p tcp --dport 80 -m set --match-set blockip src -j REDIRECT --to-port 6080  
iptables -t nat -I PREROUTING -p tcp --dport 443 -m set --match-set blockip src -j REDIRECT --to-port 60443  
iptables -t nat -D PREROUTING -p tcp --dport 80 -m set --match-set blockip src -j DNAT --to-destination 127.0.0.1:6080  
iptables -t nat -D PREROUTING -p tcp --dport 443 -m set --match-set blockip src -j DNAT --to-destination 127.0.0.1:60443  


iptables -D INPUT -m set --match-set blockip src -j DROP  


