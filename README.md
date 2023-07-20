# gogo2  
使用方法  
  

iptables -F  
iptables -X  
iptables -N NFQUEUE_CHAIN  
  
iptables -A NFQUEUE_CHAIN -p tcp --sport 80 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --sport 443 -j NFQUEUE --queue-num 0  
iptables -D INPUT 1 -j NFQUEUE_CHAIN  
iptables -I OUTPUT 1 -j NFQUEUE_CHAIN  


apt-get install libnetfilter-queue-dev  
apt-get install libpcap-dev libuv1-dev
apt-get install libglib2.0-dev
gcc test.c -o test -lpcap -lnetfilter_queue -luv $(pkg-config --cflags --libs glib-2.0)

./test -t 600 -u 86400 -w /home/whitelist.txt

ipset create blockip hash:ip
iptables -I INPUT -m set --match-set blockip src -j DROP
