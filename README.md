# gogo2  
使用方法  
apt-get install libnetfilter-queue-dev  
apt-get install libpcap-dev libuv1-dev  
gcc test.c -o test -lpcap -lnetfilter_queue -luv  
iptables -F  
iptables -X  
/usr/sbin/iptables -I OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0     
/usr/sbin/iptables -I OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 0     
./test  


没有任何参数.懂代码的自行修改
