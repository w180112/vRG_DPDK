# PPPoE client Implementation using DPDK

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://travis-ci.org/w180112/PPPoE_Client_DPDK.svg?branch=master)](https://travis-ci.org/w180112/PPPoE_Client_DPDK)

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, we design a system that make PPPoE client can be used in virtualization and high speed network.

## System required:

Intel DPDK 18.11.2, Linux kernel > 3.10, at least 4G ram, 9 cpu cores.

## How to use:

Git clone this repository

	# git clone https://github.com/w180112/PPPoE_Client_DPDK.git

Type

	# cd PPPoE_Client_DPDK

For first time build, please use boot.sh

	# ./boot.sh

to compile

For second time build, please use install.sh

	# ./install.sh

to compile

Then

	# ./src/pppoeclient <dpdk eal options>

e.g.

	# ./src/pppoeclient -l 0-8 -n 4

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to LAN port and the second is used to receive packets from/send packets to WAN port.

After Sessions established, there is a CLI. User can input "?" command to show available commands.

To remove the binary files

	# ./uninstall.sh

## Note:

1. We only support 3 LCP options, PAP authentication, Magic Number, Max receive unit so far.
2. User can now set the default gateway address 192.168.2.1 to end device after PPPoE link established.
3. The master branch contains NAT feature. If you don't want any NAT translation, switch to non_nat branch by typing git checkout non_nat.
4. User can assign how many sessions will be established, we have test upto maximum 2 sessions so far.
5. In data plane, user 1 uses single tag vlan 1, user 2 uses single tag vlan 2. All data plane packets received at gateway should include the single tag vlan. If you don't need to run in VLAN environment, just switch to non_vlan branch.
6. Each user's account and password are stored in ***pap-setup*** file.

## Test environment:

1. CentOS 7.6 and Ubuntu 18.04 KVM with Mellanox CX4 Lx and Intel X520 NIC SR-I/OV virtual function driver
2. AMD Ryzen 2700, 32GB ram desktop / Dell R630, E5 2630v3, 32GB ram
3. Successfully test control plane and data plane with CHT(Chunghwa Telecom Co., Ltd.) BRAS PPPoE server and Spirent test center
4. Intel DPDK 18.11.2 and GCC compiler

## TODO:

1. Some LCP exception
2. Add disconnect and connnect commands
3. Support Intel 700 series NIC to make uplink checksum offload and support DPDK flow API
