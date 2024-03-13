echo -e "before\n"

lsmod | grep fast

sudo rmmod fastswap.ko
sudo rmmod fastswap_dram.ko

echo -e "after\n"
lsmod | grep fast