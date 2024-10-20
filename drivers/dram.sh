echo -e "before\n"
lsmod | grep fast


sudo rmmod fastswap.ko
sudo rmmod fastswap_dram.ko

echo -e "after\n"
lsmod | grep fast


sudo insmod fastswap_dram.ko
sudo insmod fastswap.ko


echo -e "after\n"
lsmod | grep fast