PPPoE client Implementation using DPDK.

required : Intel DPDK, Linux.

------------------------------------How to Use------------------------------------

Type "make" to compile

Then ./build/pppoeclient "user id" "password" "dpdk eal options"

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to lan and the second is used to receive packets from/send packets to wan.

Type "make clean" to remove the binary file

Note : This is previous version that just tested on experiment environment, so it may contain several bugs.

Test environment : 

	1.CentOS 7.5 KVM with Mellanox CX3 SR-I/OV virtual function driver / Intel X520 NIC
	2.AMD Ryzen 2700, 32GB ram
	3.test connection with CASA vBNG 

TODO : 
	1.Control plane timer
	2.VLAN support
	3.some LCP exception
