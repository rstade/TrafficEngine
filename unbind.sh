#!/bin/bash
bricksDir=~/work/NetBricks
sudo ip link set enp7s0f0 down
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --bind ixgbe 07:00.0
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --status
nmcli dev set enp7s0f0 managed no
sudo ip addr add 192.168.222.2/24 dev enp7s0f0
sudo ip link set enp7s0f0 up
ip addr show dev enp7s0f0

