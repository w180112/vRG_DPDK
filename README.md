PPPoE client Implementation using DPDK.

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, we design a system that make PPPoE client can be used in virtualization and high speed network.

System required: Intel DPDK, Linux kernel > 3.10, at least 4G ram, 4 cpu cores.

------------------------------------How to Use------------------------------------

Type "make" to compile

Then 

	./pppoeclient <user id> <password> <dpdk eal options>
	e.g. ./pppoeclient asdf zxcv -l 0-3 -n 4

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to lan and the second is used to receive packets from/send packets to wan.

Type "make clean" to remove the binary file

Note : 

	We only support PAP authentication so far.

Test environment : 

	1.CentOS 7.5 KVM with Mellanox CX3 and Intel X520 NIC SR-I/OV virtual function driver
	2.AMD Ryzen 2700, 32GB ram
	3.Successfully test connection with CHT(Chunghwa Telecom Co., Ltd.) BRAS PPPoE server and Spirent test center
	4.Intel DPDK 18.11

TODO : 

	1.Control plane timer
	2.VLAN support
	3.some LCP exception
