# PPPoE client and NAT implementation using DPDK

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://travis-ci.com/w180112/vRG.svg?branch=master)](https://travis-ci.com/w180112/vRG)

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE client, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, a vRG system that make PPPoE client and NAT can be used in virtualization is purposed. By the powerful DPDK, all packets can be forwarded in high speed network.

## System required:

Intel DPDK 20.11, Linux kernel > 4.18, at least 4G ram, 10 cpu cores.

## How to use:

Git clone this repository

	# git clone https://github.com/w180112/vRG.git

Type

	# cd vRG

For first time build, please use boot.sh

	# ./boot.sh

to compile

For second time build, please use install.sh

	# ./install.sh

to compile

Then

	# ./src/vrg <dpdk eal options>

e.g.

	# ./src/vrg -l 0-8 -n 4

In this project 2 DPDK ethernet ports are needed, the first is used to receive packets from/send packets to LAN port and the second is used to receive packets from/send packets to WAN port.

After Sessions established, there is a CLI. User can input "?" command to show available commands.

To remove the binary files

	# ./uninstall.sh

For hugepages, NIC binding and other system configuration, please refer to Intel DPDK documentation: [DPDK doc](http://doc.dpdk.org/guides/linux_gsg/)

## Note:

1. The vRG system only support 3 LCP options, PAP authentication, Magic Number, Max receive unit so far.
2. User can now set the default gateway address 192.168.2.1 to end device after PPPoE link established.
3. The master branch contains NAT feature. If you don't want any NAT translation, switch to non_nat branch by typing git checkout non_nat.
4. User can assign how many sessions will be established, the maximum support sessions are 4094, but only 2 sessions have been tested so far.
5. In data plane, user 1 uses single tag vlan 1, user 2 uses single tag vlan 2. All data plane packets received at gateway should include a single tag vlan. If you don't need to run in VLAN environment, just switch to non_vlan branch.
6. Each user's account and password are stored in ***pap-setup*** file.

## Test environment:

1. CentOS 8.1 with Mellanox CX4 Lx virtual function and Ubuntu 20.04 with Intel X710 NIC SR-I/OV virtual function
2. AMD EPYC 7401P with ECC RAM server / Dell R630, E5 2670v3 with ECC RAM server
3. Successfully test control plane and data plane with CHT(Chunghwa Telecom Co., Ltd.) BRAS, open source RP-PPPoE and Spirent test center PPPoE server
4. Intel DPDK 19.11 and GCC version 8.3 compiler

## Example usage:

![image](https://github.com/w180112/vRG/blob/master/topo.png)

## TODO:

1. Some LCP exception
2. Add disconnect and connnect commands
3. Support Intel 700 series NIC to make uplink checksum offload and support DPDK flow API
