echo -e "before\n"

lsmod | grep fast
sudo insmod fastswap_dram.ko
sudo insmod fastswap.ko

echo -e "after\n"
lsmod | grep fast