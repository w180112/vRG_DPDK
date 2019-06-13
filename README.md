PPPoE client Implementation using DPDK
======================================

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, we design a system that make PPPoE client can be used in virtualization and high speed network.

System required:
================

Intel DPDK 18.11, Linux kernel > 3.10, at least 4G ram, 6 cpu cores.

How to use:
===========

Git clone this repository

	# git clone https://github.com/w180112/PPPoE_Client_DPDK.git

Type 

	# cd PPPoE_Client_DPDK/src

and 

	# make 

to compile

Then 

	# ./pppoeclient <user id> <password> <dpdk eal options>

e.g. 

	# ./pppoeclient asdf zxcv -l 0-5 -n 4

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to LAN port and the second is used to receive packets from/send packets to WAN port.

To remove the binary file 

	# make clean 

Note: 
=====
	1.We only support 3 LCP options, PAP authentication, Magic Number, Max receive unit so far.
	2.User can now set the default gateway address 192.168.0.1 to end device after PPPoE link established.
	3.The master branch contains NAT feature. If you don't want any NAT translation, switch to non_nat branch by typing git checkout non_nat.
	4.User can assign how many sessions will be established, we support maximum 3 sessions so far. Default is 1 session.
	5.Data plant now only support 1 session and will increase in the future.

Test environment: 
=================

	1.CentOS 7.5 KVM with Mellanox CX4 Lx and Intel X520 NIC SR-I/OV virtual function driver
	2.AMD Ryzen 2700, 32GB ram
	3.Successfully test connection with CHT(Chunghwa Telecom Co., Ltd.) BRAS PPPoE server and Spirent test center
	4.Intel DPDK 18.11 and GCC compiler

TODO: 
=====

	1.VLAN support
	2.Some LCP exception
	3.Multiple users/devices data plane support
	4.Command line interface

ChangeLogs:
===========

2019/06/13
----------

1. Add log system at ./pppoeclient.log
2. Add debug message system
3. Add multiple user connection
4. Fix upstream and downstream bugs

2019/06/05
----------

1. Support Unix SIGINT signal
2. Bugs fix
