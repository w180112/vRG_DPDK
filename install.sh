export RTE_SDK=./src/lib/dpdk-stable-18.11.2/
export RTE_TARGET=x86_64-native-linuxapp-gcc
cd ./src
cd ./lib/dpdk-stable-18.11.2 && make install T=x86_64-native-linuxapp-gcc
cd ../..
make
cd ..