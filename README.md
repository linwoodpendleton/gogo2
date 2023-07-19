# gogo2  
使用方法  
apt-get install libnetfilter-queue-dev  
apt-get install libpcap-dev libuv1-dev  
gcc test.c -o test -lpcap -lnetfilter_queue -luv  
iptables -F  
iptables -X  
iptables -N NFQUEUE_CHAIN  
  
iptables -A NFQUEUE_CHAIN -p tcp --sport 80 -j NFQUEUE --queue-num 0  
iptables -A NFQUEUE_CHAIN -p tcp --sport 443 -j NFQUEUE --queue-num 0  
iptables -I INPUT 1 -j NFQUEUE_CHAIN  
iptables -I OUTPUT 1 -j NFQUEUE_CHAIN  
./test  


没有任何参数.懂代码的自行修改
