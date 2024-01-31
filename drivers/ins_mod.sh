echo -e "before\n"

lsmod | grep fast
sudo insmod fastswap_rdma.ko sport=50000 sip=10.10.10.9 cip=10.10.10.10 nc=8
sudo insmod fastswap.ko

echo -e "after\n"
lsmod | grep fast