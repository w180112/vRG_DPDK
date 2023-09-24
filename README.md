# Virtualized residential gateway (vRG) implementation using DPDK

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![vRG ci](https://github.com/w180112/vRG_DPDK/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/w180112/vRG_DPDK/actions/workflows/ci.yml)

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE client, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, a vRG system that make PPPoE client and NAT can be used in virtualization is purposed. By the powerful DPDK, all packets can be forwarded in high speed network.

## System required:

Intel DPDK 22.11, at least 2G ram, 8 cpu cores.

Package required: make gcc pip3 pyelftools pkg-config meson libnuma-dev autoconf libconfig-dev

## How to use:

In this project 2 DPDK ethernet ports are needed, the first is used to receive packets from/send packets to LAN port and the second is used to receive packets from/send packets to WAN port.

Git clone this repository

	# git clone https://github.com/w180112/vRG_DPDK.git

Type

	# cd vRG
	# git submodule update --init --recursive

For first time build, please use boot.sh to build DPDK library, libutil and vRG

	# ./boot.sh

For just vRG build, please use install.sh

	# ./install.sh

Then

	# vrg <dpdk eal options>

e.g.

	# vrg -l 0-7 -n 4

For using vRG in Docker,

	# mount -t hugetlbfs -o pagesize=1G none /dev/hugepages1G
	# docker run -it --net=host --privileged -v /sys/bus/pci/devices:/sys/bus/pci/devices -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev $DOCKER_IMAGE  bash

Execute following command in Docker container

	# /vrg/lib/dpdk/usertools/dpdk-hugepages.py --setup 1G

After vRG system started, there is a CLI. User can input "?" command to show available commands.

Use command ***connect*** or ***disconnect*** to determine which user start/stop a PPPoE connection, e.g.: to start all subscribers PPPoE connection defined in ***vRG-setup*** file.

	vRG> connect all

To start specific subscriber 1 PPPoE connection.

	vRG> connect 1

To disconnect all subscribers PPPoE connection.

	vRG> disconnect all

To start specific subscriber 1 DHCP server.

	vRG> dhcp-server start 1

To stop all subscribers DHCP server.

	vRG> dhcp-server stop all

To remove the binary files

	# ./uninstall.sh

For hugepages, NIC binding and other system configuration, please refer to Intel DPDK documentation: [DPDK doc](http://doc.dpdk.org/guides/linux_gsg/)

## Note:

1. The vRG system only support 3 LCP options, PAP authentication, Magic Number, Max receive unit so far.
2. Users behind vRG should use DHCP to get IP address or set the default gateway address 192.168.2.1 to their end device.
3. The default gateway ip address can be configured in ***config.cfg***.
4. Administrator can assign how many subscriber PPPoE sessions will be established, the maximum support sessions are 4094, but only 20 sessions have been tested so far. 
5. In default configurationin ***config.cfg*** file, there are only 20 vRG subscriber PPPoE sessions. You can just modify the value ***UserCount*** in this file. For example, there will be 4 subscriber PPPoE connection while the value is changed to 4.
6. In data plane, default subscriber 1 uses single tag vlan 2, subscriber 2 uses single tag vlan 3. All data plane packets received at vRG system should include a single tag vlan. If you don't need to run vRG system in VLAN environment, config ***NonVlanMode*** in ***config.cfg*** file to 1(Note: non-vlan mode only support 1 subscriber PPPoE connection at the same time).
7. All DPDK EAL lcores should be on same CPU socket.

## Test environment:

1. Ubuntu 22.04 with Mellanox CX4 Lx virtual function and RHEL 9.2 with Intel X710 NIC SR-I/OV virtual function
2. Xeon Platinum 8124 / Xeon Gold 6268 with ECC RAM server
3. Successfully test control plane and data plane with CHT(Chunghwa Telecom Co., Ltd.) BRAS, open source RP-PPPoE and Spirent test center PPPoE server
4. Intel DPDK 22.11

## Example use case:

![image](https://github.com/w180112/vRG/blob/master/topo.png)

## TODO:

1. Some LCP exception
