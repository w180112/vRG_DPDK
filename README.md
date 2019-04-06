PPPoE client Implementation using DPDK.

System required : Intel DPDK, Linux kernel > 3.10, at least 4G ram, 4 cpu cores.

------------------------------------How to Use------------------------------------

Type "make" to compile

Then 

	./pppoeclient "user id" "password" "dpdk eal options"

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to lan and the second is used to receive packets from/send packets to wan.

Type "make clean" to remove the binary file

Note : 

	This is previous version that just tested on experiment environment, so it may contain several bugs.

Test environment : 

	1.CentOS 7.5 KVM with Mellanox CX3 and Intel X520 NIC SR-I/OV virtual function driver
	2.AMD Ryzen 2700, 32GB ram
	3.test connection with CHT(Chunghwa Telecom Co., Ltd.) BRAS PPPoE server
	4.Intel DPDK 18.11

TODO : 

	1.Control plane timer
	2.VLAN support
	3.some LCP exception
